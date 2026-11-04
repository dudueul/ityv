//! Leaked encodings, deterministic keys and signatures.
//!
//! Every value the generator makes lives for the whole run (`'static`), so
//! the borrowed encoding types of `ityv-encoding` can point at each other
//! freely. Keys are named by a label; the label and the generator seed fix
//! both halves of the key. Signatures draw their hedged ML-DSA randomness
//! from `ityv-cunit`'s SHA3 counter-mode generator, seeded from the key
//! label, the purpose and the object hash, so the same input always gives
//! the same bytes.

use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};

use ityv_crypto::{
    HybridSignature, HybridSigningKey, Purpose, RecordPurpose, Sha3Hasher, object_hash,
    sign_ed25519_half, sign_hybrid,
};
use ityv_cunit::DeviceRng;
use ityv_encoding::{
    Encode, HYBRID_SIG_LEN, HYBRID_VK_LEN, Hash512, SchemaId, Writer, encode_object, schema_version,
};

/// The generator seed. Changing it changes every key and every signature.
pub const SEED: &[u8] = b"ityv-sim:v1:fixed-seed";

/// Leaks `value` for the rest of the run.
pub fn leak<T>(value: T) -> &'static T {
    Box::leak(Box::new(value))
}

/// Leaks `values` as a slice.
pub fn leak_slice<T>(values: Vec<T>) -> &'static [T] {
    Box::leak(values.into_boxed_slice())
}

/// Leaks a string's bytes.
pub fn text(value: &str) -> &'static [u8] {
    leak_slice(value.as_bytes().to_vec())
}

/// Leaks a string.
pub fn leak_str(value: String) -> &'static str {
    Box::leak(value.into_boxed_str())
}

/// A complete object of `schema` at the version `ityv-encoding` encodes
/// it at (`schema_version`), leaked.
pub fn object<T: Encode>(schema: SchemaId, value: &T) -> &'static [u8] {
    let mut buf = vec![0u8; 16 + value.encoded_len()];
    let len = encode_object(schema, schema_version(schema), value, &mut buf).unwrap();
    buf.truncate(len);
    leak_slice(buf)
}

/// A field group's encoding without an object header, leaked.
pub fn group<T: Encode>(value: &T) -> &'static [u8] {
    let mut out = vec![0u8; value.encoded_len()];
    let mut w = Writer::new(&mut out);
    value.encode(&mut w).unwrap();
    leak_slice(out)
}

/// `SHA3-512("ityv-sim:" ‖ label ‖ 0x00 ‖ SEED ‖ parts…)`, each part
/// length-prefixed.
pub fn digest(label: &str, parts: &[&[u8]]) -> [u8; 64] {
    let mut h = Sha3Hasher::new();
    h.absorb(b"ityv-sim:");
    h.absorb(label.as_bytes());
    h.absorb(&[0x00]);
    h.absorb(SEED);
    for p in parts {
        h.absorb(&(p.len() as u64).to_be_bytes());
        h.absorb(p);
    }
    h.finish()
}

/// A hash value derived from `label` and `parts` (for document hashes the
/// simulated election only refers to).
pub fn hash_of(label: &str, parts: &[&[u8]]) -> Hash512 {
    Hash512(digest(label, parts))
}

/// A generator for one operation, seeded from `label` and `parts`.
pub fn rng(label: &str, parts: &[&[u8]]) -> DeviceRng {
    let d = digest(label, parts);
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&d[..32]);
    DeviceRng::for_signing(&seed)
}

type KeyCache = Mutex<BTreeMap<String, (&'static HybridSigningKey, &'static [u8; HYBRID_VK_LEN])>>;

fn keys() -> &'static KeyCache {
    static KEYS: OnceLock<KeyCache> = OnceLock::new();
    KEYS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn key_pair(label: &str) -> (&'static HybridSigningKey, &'static [u8; HYBRID_VK_LEN]) {
    if let Some(k) = keys().lock().unwrap().get(label) {
        return *k;
    }
    let d = digest("key", &[label.as_bytes()]);
    let mut ml = [0u8; 32];
    let mut ed = [0u8; 32];
    ml.copy_from_slice(&d[..32]);
    ed.copy_from_slice(&d[32..]);
    let key = leak(HybridSigningKey::from_seeds(ml, ed));
    let vk = key.verifying_key();
    let mut out = [0u8; HYBRID_VK_LEN];
    let (a, b) = out.split_at_mut(vk.mldsa87().len());
    a.copy_from_slice(vk.mldsa87());
    b.copy_from_slice(vk.ed25519());
    let pair = (key, leak(out));
    keys().lock().unwrap().insert(label.to_owned(), pair);
    pair
}

/// The signing key named `label`.
pub fn signing(label: &str) -> &'static HybridSigningKey {
    key_pair(label).0
}

/// The registered (verifying) key bytes of the key named `label`.
pub fn registered(label: &str) -> &'static [u8; HYBRID_VK_LEN] {
    key_pair(label).1
}

/// The Ed25519 half of key `label`'s verifying key (an observer token's
/// check key).
pub fn ed25519_half(label: &str) -> &'static [u8; 32] {
    let vk = registered(label);
    let mut out = [0u8; 32];
    out.copy_from_slice(&vk[HYBRID_VK_LEN - 32..]);
    leak(out)
}

/// Key `label`'s hybrid signature over `object` under `purpose`.
pub fn hybrid(label: &str, purpose: &[u8], object: &[u8]) -> &'static HybridSignature {
    hybrid_variant(label, purpose, object, 0)
}

/// As [`hybrid`], with randomness variant `variant`: another signature
/// over the same object.
pub fn hybrid_variant(
    label: &str,
    purpose: &[u8],
    object: &[u8],
    variant: u64,
) -> &'static HybridSignature {
    let p = Purpose::new(purpose).unwrap();
    let hash = object_hash(object);
    let mut r = rng(
        "sig",
        &[
            label.as_bytes(),
            purpose,
            hash.as_bytes(),
            &variant.to_be_bytes(),
        ],
    );
    leak(sign_hybrid(signing(label), &p, object, &mut r).unwrap())
}

/// The bytes of a hybrid signature.
pub fn signature_bytes(signature: &HybridSignature) -> &'static [u8; HYBRID_SIG_LEN] {
    let mut out = [0u8; HYBRID_SIG_LEN];
    let (ml, ed) = out.split_at_mut(signature.mldsa87().len());
    ml.copy_from_slice(signature.mldsa87());
    ed.copy_from_slice(signature.ed25519());
    leak(out)
}

/// Key `label`'s hybrid signature over `object` under `purpose`, as bytes.
pub fn sign(label: &str, purpose: &[u8], object: &[u8]) -> &'static [u8; HYBRID_SIG_LEN] {
    signature_bytes(hybrid(label, purpose, object))
}

/// As [`sign`], randomness variant `variant`.
pub fn sign_variant(
    label: &str,
    purpose: &[u8],
    object: &[u8],
    variant: u64,
) -> &'static [u8; HYBRID_SIG_LEN] {
    signature_bytes(hybrid_variant(label, purpose, object, variant))
}

/// Key `label`'s Ed25519 record signature over `message`.
pub fn record_sig(label: &str, purpose: RecordPurpose, message: &[u8]) -> &'static [u8; 64] {
    leak(
        *sign_ed25519_half(signing(label), purpose, message)
            .unwrap()
            .as_bytes(),
    )
}

/// The SHA3-512 of `bytes`, hexadecimal (a bundle's identity in
/// `index.json`).
pub fn sha3_hex(bytes: &[u8]) -> String {
    let mut h = Sha3Hasher::new();
    h.absorb(bytes);
    hex(&h.finish())
}

/// Lower-case hexadecimal.
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// A small deterministic stream of numbers for shaping a simulated day
/// (arrivals, choices). Not used for any cryptographic value.
pub struct Dice {
    key: [u8; 64],
    counter: u64,
}

impl Dice {
    /// A stream named by `label` and `parts`.
    pub fn new(label: &str, parts: &[&[u8]]) -> Self {
        Self {
            key: digest(label, parts),
            counter: 0,
        }
    }

    /// The next 64-bit value.
    pub fn next_u64(&mut self) -> u64 {
        let mut h = Sha3Hasher::new();
        h.absorb(&self.key);
        h.absorb(&self.counter.to_be_bytes());
        self.counter += 1;
        let d = h.finish();
        u64::from_be_bytes(d[..8].try_into().unwrap())
    }

    /// A value in `0..n` (`n > 0`).
    pub fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }

    /// `true` with probability `per_mille / 1000`.
    pub fn chance(&mut self, per_mille: u64) -> bool {
        self.below(1000) < per_mille
    }

    /// An index drawn with the given weights (not all zero).
    pub fn weighted(&mut self, weights: &[u64]) -> usize {
        let total: u64 = weights.iter().sum();
        let mut x = self.below(total);
        for (i, w) in weights.iter().enumerate() {
            if x < *w {
                return i;
            }
            x -= w;
        }
        weights.len() - 1
    }
}
