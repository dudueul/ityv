//! Shared helpers for the integration tests. Test code is outside the TCB.
//!
//! This module is compiled into every test binary and each binary uses a
//! different subset of it, so `dead_code` is allowed here and nowhere else.
#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::missing_panics_doc
)]

use ityv_crypto::{HybridSigningKey, PURPOSE_CHECKPOINT, sign_hybrid};
use ityv_encoding::{
    CheckpointBody, CheckpointParts, Decode, ElectionId, Encode, Error as EncodingError, Hash512,
    Ident, KeysetId, LedgerFrame, LedgerId, Reader, SCHEMA_CHECKPOINT_BODY, SCHEMA_LEDGER_FRAME,
    SCHEMA_VERSION_1, SchemaId, Seq, TimeBucket, TreeSize, Writer, encode_object,
};
use ityv_ledger::{
    SCHEMA_SIGNED_CHECKPOINT, SignedCheckpoint, SignedCheckpointParts, WitnessSignatureEntry,
};
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;
use std::string::String;
use std::vec::Vec;

pub(crate) const ELECTION: &[u8] = b"KR-2030-PRES";
pub(crate) const LEDGER: &[u8] = b"LEDGER-MAIN";
pub(crate) const KEYSET: &[u8] = b"WITNESS-KEYSET-1";

/// A deterministic CSPRNG for reproducible tests.
pub(crate) fn rng(seed: u64) -> ChaCha20Rng {
    ChaCha20Rng::seed_from_u64(seed)
}

/// Encodes a value into a freshly sized vector and checks the declared length.
pub(crate) fn encode_to_vec<T: Encode>(value: &T) -> Vec<u8> {
    let len = value.encoded_len();
    let mut out = std::vec![0u8; len];
    let mut writer = Writer::new(&mut out);
    value
        .encode(&mut writer)
        .unwrap_or_else(|e| panic!("encoding must succeed: {e}"));
    assert_eq!(writer.finish(), len, "encoded_len must match bytes written");
    out
}

/// Decodes a value that must consume the whole input.
pub(crate) fn decode_exact<'a, T: Decode<'a>>(bytes: &'a [u8]) -> Result<T, EncodingError> {
    let mut reader = Reader::new(bytes);
    let value = T::decode(&mut reader)?;
    reader.finish()?;
    Ok(value)
}

/// Encodes a complete object (header plus body).
pub(crate) fn object_to_vec<T: Encode>(schema: SchemaId, value: &T) -> Vec<u8> {
    let mut out = std::vec![0u8; value.encoded_len() + 16];
    let n = encode_object(schema, SCHEMA_VERSION_1, value, &mut out).unwrap();
    out.truncate(n);
    out
}

/// Formats a byte slice as lowercase hex.
pub(crate) fn hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Parses hex into bytes.
pub(crate) fn unhex(text: &str) -> Vec<u8> {
    let digits: Vec<u8> = text.trim().bytes().collect();
    digits
        .chunks(2)
        .map(|pair| {
            let s = core::str::from_utf8(pair).unwrap();
            u8::from_str_radix(s, 16).unwrap()
        })
        .collect()
}

/// Parses hex into a digest.
pub(crate) fn unhex_hash(text: &str) -> Hash512 {
    let bytes = unhex(text);
    Hash512(bytes.as_slice().try_into().unwrap())
}

/// Parses a comma-separated hex list into digests.
pub(crate) fn unhex_hashes(text: &str) -> Vec<Hash512> {
    if text.trim().is_empty() {
        return Vec::new();
    }
    text.split(',').map(unhex_hash).collect()
}

/// The leaf input `L_i`: 64 bytes of value `i`.
pub(crate) fn leaf_input(i: u8) -> Hash512 {
    Hash512([i; 64])
}

/// Leaf inputs `L_0 .. L_{n-1}`.
pub(crate) fn leaves(n: usize) -> Vec<Hash512> {
    (0..n).map(|i| leaf_input(i as u8)).collect()
}

/// Pseudo-random leaf inputs.
pub(crate) fn random_leaves(seed: u64, n: usize) -> Vec<Hash512> {
    use rand_chacha::rand_core::Rng;
    let mut r = rng(seed);
    (0..n)
        .map(|_| {
            let mut h = [0u8; 64];
            r.fill_bytes(&mut h);
            Hash512(h)
        })
        .collect()
}

/// Loads `name = value` lines from a vectors file.
pub(crate) fn load_vectors(file: &str) -> std::collections::BTreeMap<String, String> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("vectors")
        .join(file);
    let text = std::fs::read_to_string(&path).unwrap();
    text.lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .map(|l| {
            let (k, v) = l.split_once(" = ").unwrap();
            (k.to_string(), v.to_string())
        })
        .collect()
}

pub(crate) fn election() -> ElectionId<'static> {
    ElectionId::new(ELECTION).unwrap()
}

/// Encodes a frame object.
pub(crate) fn frame_object(
    election_id: &[u8],
    seq: u64,
    prev_hash: Hash512,
    event_schema: u32,
    event_hash: Hash512,
) -> Vec<u8> {
    let frame = LedgerFrame::new(
        ElectionId::new(election_id).unwrap(),
        Seq::new(seq).unwrap(),
        prev_hash,
        SchemaId::new(event_schema),
        event_hash,
    );
    object_to_vec(SCHEMA_LEDGER_FRAME, &frame)
}

/// A chain of `n` valid frame objects for the fixed election, with event
/// hashes `L_1 .. L_n`.
pub(crate) fn frame_chain(n: usize) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut prev = Hash512::ZERO;
    for i in 1..=n {
        let bytes = frame_object(ELECTION, i as u64, prev, 0x0005, leaf_input(i as u8));
        prev = ityv_crypto::object_hash(&bytes);
        out.push(bytes);
    }
    out
}

/// A checkpoint body with the fixed identifiers.
#[allow(clippy::too_many_arguments)]
pub(crate) fn body_parts(
    seq: u64,
    tree_size: u64,
    root_hash: Hash512,
    previous: Hash512,
    box_close_root: Hash512,
    dispute_root: Hash512,
    genesis_hash: Hash512,
    bucket: u64,
) -> CheckpointParts<'static> {
    CheckpointParts {
        election_id: election(),
        ledger_id: LedgerId::new(LEDGER).unwrap(),
        keyset_id: KeysetId::new(KEYSET).unwrap(),
        checkpoint_seq: Seq::new(seq).unwrap(),
        tree_size: TreeSize::new(tree_size),
        root_hash,
        previous_checkpoint_hash: previous,
        box_close_root,
        dispute_root,
        genesis_hash,
        time_bucket: TimeBucket::new(bucket),
    }
}

/// Encodes a checkpoint body object.
pub(crate) fn body_object(parts: &CheckpointParts<'_>) -> Vec<u8> {
    let body = CheckpointBody::new(parts).unwrap();
    object_to_vec(SCHEMA_CHECKPOINT_BODY, &body)
}

/// Decodes a checkpoint body object.
pub(crate) fn decode_body(bytes: &[u8]) -> CheckpointBody<'_> {
    ityv_encoding::decode_object(SCHEMA_CHECKPOINT_BODY, SCHEMA_VERSION_1, bytes).unwrap()
}

/// A fixture witness: identifier, attributes and signing key.
pub(crate) struct Witness {
    pub(crate) id: String,
    pub(crate) org: String,
    pub(crate) provider: String,
    pub(crate) region: String,
    pub(crate) key: HybridSigningKey,
}

/// `n` witnesses `W00..`, with orgs `ORG<i>`, providers `P<i mod 5>`,
/// regions `R<i mod 4>`, keys from a seeded RNG.
pub(crate) fn witnesses(n: usize) -> Vec<Witness> {
    let mut r = rng(0x77_69_74);
    (0..n)
        .map(|i| Witness {
            id: std::format!("W{i:02}"),
            org: std::format!("ORG{i}"),
            provider: std::format!("P{}", i % 5),
            region: std::format!("R{}", i % 4),
            key: HybridSigningKey::generate(&mut r),
        })
        .collect()
}

/// Roster entries for `witnesses`, in identifier order (the fixture ids are
/// already ascending).
pub(crate) fn roster_entries(ws: &[Witness]) -> Vec<ityv_ledger::WitnessEntry<'_>> {
    ws.iter()
        .map(|w| ityv_ledger::WitnessEntry {
            id: Ident::new(w.id.as_bytes(), 64).unwrap(),
            org: Ident::new(w.org.as_bytes(), 64).unwrap(),
            provider: Ident::new(w.provider.as_bytes(), 64).unwrap(),
            region: Ident::new(w.region.as_bytes(), 64).unwrap(),
            key: w.key.verifying_key(),
        })
        .collect()
}

/// Signs `body_bytes` with the given witnesses (by index) and encodes the
/// `SignedCheckpoint` object.
pub(crate) fn signed_checkpoint_object(
    ws: &[Witness],
    signers: &[usize],
    body_bytes: &[u8],
) -> Vec<u8> {
    let mut r = rng(0x73_69_67);
    let sigs: Vec<(usize, ityv_crypto::HybridSignature)> = signers
        .iter()
        .map(|&i| {
            (
                i,
                sign_hybrid(&ws[i].key, &PURPOSE_CHECKPOINT, body_bytes, &mut r).unwrap(),
            )
        })
        .collect();
    let entries: Vec<WitnessSignatureEntry<'_>> = sigs
        .iter()
        .map(|(i, sig)| WitnessSignatureEntry {
            witness_id: Ident::new(ws[*i].id.as_bytes(), 64).unwrap(),
            signature: sig,
        })
        .collect();
    let parts = SignedCheckpointParts::new(body_bytes, &entries).unwrap();
    object_to_vec(SCHEMA_SIGNED_CHECKPOINT, &parts)
}

/// Decodes a `SignedCheckpoint` object.
pub(crate) fn decode_signed(bytes: &[u8]) -> SignedCheckpoint<'_> {
    ityv_encoding::decode_object(SCHEMA_SIGNED_CHECKPOINT, SCHEMA_VERSION_1, bytes).unwrap()
}
