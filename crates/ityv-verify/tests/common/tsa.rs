//! Real RFC 3161 timestamp tokens for the verifier's tests, made by OpenSSL
//! (3.0 or later, on `PATH`) at test time, as `ityv-tsa`'s
//! `tests/vectors/make.sh` makes its vectors.
//!
//! OpenSSL 3 is required, not optional: the tokens need its `ts`
//! `ess_cert_id_alg` (an ESS v2 binding; `LibreSSL`, the `openssl` of macOS,
//! has no such option and would bind with ESS v1, which the test pins
//! refuse). The first use checks `openssl version` and fails every test
//! that needs a token, with that message, when it is missing or another
//! implementation: no test is skipped. Every integration test of this
//! crate builds the test genesis, whose authorities these are.
//!
//! Five throwaway authorities' RSA-2048 keys are generated once per test
//! process. Each certificate is self-signed with `openssl ca -selfsign`,
//! valid from 2024-01-01 (the tests' election epoch is day 20 000,
//! 2024-10-04) to 2036, with the profile `ityv-tsa` requires (`CA:FALSE`,
//! critical key usage digitalSignature+nonRepudiation, critical EKU
//! timeStamping). A token is made by `openssl ts -query`/`-reply` over the
//! 64-octet object hash of the stamped event (imprint SHA-512, `certReq`,
//! no nonce), so its whole structure, ESS v2 binding and signature come
//! from OpenSSL. OpenSSL stamps the current time; the tests need tokens at
//! chosen buckets, so the helper then writes the wanted `genTime` (same
//! length), recomputes the `messageDigest` attribute with `openssl dgst
//! -sha256` and signs the signed attributes again with `openssl dgst
//! -sha256 -sign` (as `forge.py` does for its timed vectors). RSA PKCS#1
//! v1.5 signatures have the modulus length, so no length changes.
//!
//! No private key is committed or left behind: a key lives in memory and is
//! written to a fresh directory under the system temporary directory only
//! for the one OpenSSL call that needs it, and the directory is removed
//! when the call ends, by a guard that also runs if the call panics. The
//! directory's name has a random part and is created only if nothing is at
//! that path (not an existing directory, not a symbolic link), so no other
//! user of the temporary directory can have it read or written there.
//!
//! The authorities (indices of [`signer`]):
//!
//! * 0: `TSA-GOV-1` (operator `MOIS-GPKI`, government), its first
//!   certificate; tokens state an accuracy of one second, as the genesis
//!   declares for the authority;
//! * 1: `TSA-GOV-1`'s second certificate and key (a rotation: the genesis
//!   pins both);
//! * 2: `TSA-FREE-1` (operator `FREE-TSA`, not government); tokens state no
//!   accuracy, and the genesis declares two seconds for it;
//! * 3: `TSA-GOV-2` (operator `MOIS-GPKI` again, government), so that two
//!   authorities of one operator count once; tokens state three seconds,
//!   more than the one second the genesis declares;
//! * 4: an authority no genesis pins.
//!
//! Every pin carries its certificate (ADR-0039 2: the genesis compares
//! the signer keys).
// Test helper: outside the TCB. It expresses "this must hold" with
// unwrap/expect/panic/indexing and small arithmetic, so those lints are
// relaxed for this file only (CONSTITUTION.md §1.1).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::missing_panics_doc,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    dead_code,
    unreachable_pub
)]

use core::sync::atomic::{AtomicU64, Ordering};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::string::String;
use std::sync::{Mutex, OnceLock};
use std::vec::Vec;

use ityv_encoding::{
    AuthorityId, ElectionId, Hash512, OrgId, PolicyAccuracy, SCHEMA_TIMESTAMP_RECORD,
    SCHEMA_VERSION_1, SchemaId, TimestampAuthorityEntry, TimestampAuthorityKind, TimestampPins,
    TimestampRecord, TimestampRecordParts,
};
use ityv_tsa::{DigestSet, PinnedTsa, SignatureSet};

use super::{leak, leak_slice, object};

/// The tests' election epoch, day 20 000 (2024-10-04), as Unix seconds.
pub const EPOCH_SECONDS: u64 = 20_000 * 86_400;

/// The policy every authority uses: 1.2.3.4.1.
pub const POLICY: [u8; 6] = [0x06, 0x04, 0x2A, 0x03, 0x04, 0x01];

/// Signers: (authority, operator, government, certificate name, the
/// accuracy its tokens state in seconds).
const SIGNERS: [(&str, &str, bool, &str, Option<u32>); 5] = [
    ("TSA-GOV-1", "MOIS-GPKI", true, "gov-1a", Some(1)),
    ("TSA-GOV-1", "MOIS-GPKI", true, "gov-1b", Some(1)),
    ("TSA-FREE-1", "FREE-TSA", false, "free-1", None),
    ("TSA-GOV-2", "MOIS-GPKI", true, "gov-2", Some(3)),
    ("TSA-ROGUE", "ROGUE", false, "rogue", Some(1)),
];

/// The government authority's first certificate.
pub const GOV: usize = 0;
/// The government authority's second certificate.
pub const GOV_ROTATED: usize = 1;
/// The non-government authority.
pub const FREE: usize = 2;
/// A second government authority of the same operator.
pub const GOV_SAME_OPERATOR: usize = 3;
/// An authority no genesis pins.
pub const ROGUE: usize = 4;

/// One throwaway authority key and its certificate.
pub struct Signer {
    /// The authority identifier the genesis gives it.
    pub authority: &'static str,
    /// Its operator.
    pub operator: &'static str,
    /// Whether the government runs it.
    pub government: bool,
    /// The accuracy its tokens state, in seconds.
    pub accuracy: Option<u32>,
    key_pem: String,
    cert_pem: String,
    /// The certificate, DER.
    pub cert: &'static [u8],
    /// Its pin bytes (certificate SHA-256, SHA-256 and SHA-512 digests,
    /// RSA PKCS#1 v1.5 SHA-256, the one policy, the certificate).
    pub pin: &'static [u8],
}

fn run(dir: &Path, args: &[&str], stdin: Option<&[u8]>) -> Vec<u8> {
    let mut child = Command::new("openssl")
        .args(args)
        .current_dir(dir)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the verifier's timestamp tests need `openssl` (3.0 or later) on PATH");
    if let Some(input) = stdin {
        use std::io::Write as _;
        child.stdin.take().unwrap().write_all(input).unwrap();
    }
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "openssl {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}

/// A fresh directory, removed when dropped, also while a panic unwinds.
struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        // Nothing to report from a destructor; a leftover directory is
        // the one thing this guard exists to prevent.
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A new directory under the system temporary directory, with a name no
/// one can predict, made only if nothing is at that path yet.
fn scratch() -> Scratch {
    use core::hash::{BuildHasher as _, Hasher as _};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    // `RandomState` is keyed from the operating system's randomness.
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u64(n);
    let random = hasher.finish();
    let dir: PathBuf = std::env::temp_dir().join(std::format!(
        "ityv-verify-tsa-{}-{n}-{random:016x}",
        std::process::id()
    ));
    // `create_dir` fails if anything, a symbolic link included, is there.
    std::fs::create_dir(&dir)
        .unwrap_or_else(|e| panic!("a fresh scratch directory {}: {e}", dir.display()));
    let guard = Scratch(dir);
    let kind = std::fs::symlink_metadata(&guard.0).unwrap().file_type();
    assert!(
        kind.is_dir() && !kind.is_symlink(),
        "{} is not a directory of ours",
        guard.0.display()
    );
    guard
}

/// Runs `f` in a fresh directory that is removed afterwards, also if `f`
/// panics.
pub fn in_scratch<T>(f: impl FnOnce(&Path) -> T) -> T {
    let dir = scratch();
    f(&dir.0)
}

/// Fails, with a message, unless `openssl` on `PATH` is OpenSSL 3 or
/// later (module documentation).
fn require_openssl_3() {
    let out = Command::new("openssl")
        .arg("version")
        .output()
        .expect("the verifier's timestamp tests need `openssl` (OpenSSL 3.0 or later) on PATH");
    let version = String::from_utf8_lossy(&out.stdout);
    let major = version
        .strip_prefix("OpenSSL ")
        .and_then(|rest| rest.split('.').next())
        .and_then(|major| major.parse::<u32>().ok());
    assert!(
        out.status.success() && major.is_some_and(|m| m >= 3),
        "the verifier's timestamp tests need OpenSSL 3.0 or later as `openssl` on PATH \
         (ESS v2 bindings, `ts` option `ess_cert_id_alg`); found: {}",
        version.trim()
    );
}

/// The bytes of a pin of `cert` (DER) with the given masks, the tests'
/// policy and the certificate copy.
pub fn pin_of(cert: &'static [u8], digests: u8, signatures: u8) -> &'static [u8] {
    let hash: [u8; 32] = in_scratch(|dir| run(dir, &["dgst", "-sha256", "-binary"], Some(cert)))
        .try_into()
        .unwrap();
    let pin = PinnedTsa::new(
        hash,
        DigestSet::from_bits(digests).unwrap(),
        SignatureSet::from_bits(signatures).unwrap(),
        false,
        &POLICY,
        Some(cert),
    )
    .unwrap();
    let mut bytes = std::vec![0u8; pin.encoded_len()];
    let len = pin.encode(&mut bytes).unwrap();
    bytes.truncate(len);
    leak_slice(bytes)
}

/// The digests every test pin allows: SHA-256 (the signer's) and SHA-512
/// (the imprint's).
pub const DIGESTS: u8 = 0x01 | 0x04;

/// The signature algorithm every test pin allows: RSA PKCS#1 v1.5 SHA-256.
pub const SIGNATURES: u8 = 0x01;

/// A certificate configuration for `openssl ca`, with the profile
/// `ityv-tsa` requires, under the common name `name`.
fn ca_config(name: &str) -> String {
    std::format!(
        "[ ca ]\ndefault_ca = d\n[ d ]\ndatabase = index.txt\nnew_certs_dir = .\n\
         serial = serial\ndefault_md = sha256\npolicy = p\nx509_extensions = ext\n\
         unique_subject = no\n[ p ]\ncommonName = supplied\n[ req ]\n\
         distinguished_name = dn\nprompt = no\n[ dn ]\nC = KR\nO = ityv test\n\
         CN = ityv verify test TSA {name}\n[ ext ]\n\
         basicConstraints = critical, CA:FALSE\n\
         keyUsage = critical, digitalSignature, nonRepudiation\n\
         extendedKeyUsage = critical, timeStamping\nsubjectKeyIdentifier = hash\n"
    )
}

/// A self-signed certificate (DER) over the key `k.pem` in `dir`, under
/// the common name `name` and serial `serial`.
fn self_signed(dir: &Path, name: &str, serial: usize) -> (Vec<u8>, String) {
    self_signed_until(dir, name, serial, "20361231000000Z")
}

/// As [`self_signed`], valid until `end` (`YYYYMMDDhhmmssZ`).
fn self_signed_until(dir: &Path, name: &str, serial: usize, end: &str) -> (Vec<u8>, String) {
    std::fs::write(dir.join("ca.cnf"), ca_config(name)).unwrap();
    std::fs::write(dir.join("index.txt"), "").unwrap();
    std::fs::write(dir.join("serial"), std::format!("{serial:02X}\n")).unwrap();
    run(
        dir,
        &[
            "req", "-new", "-config", "ca.cnf", "-key", "k.pem", "-out", "r.csr",
        ],
        None,
    );
    run(
        dir,
        &[
            "ca",
            "-batch",
            "-selfsign",
            "-config",
            "ca.cnf",
            "-keyfile",
            "k.pem",
            "-in",
            "r.csr",
            "-startdate",
            "20240101000000Z",
            "-enddate",
            end,
            "-notext",
            "-out",
            "c.pem",
        ],
        None,
    );
    (
        run(dir, &["x509", "-in", "c.pem", "-outform", "DER"], None),
        std::fs::read_to_string(dir.join("c.pem")).unwrap(),
    )
}

/// A second certificate over signer `index`'s key (another name and
/// serial): its pin bytes, as [`Signer::pin`] but for that certificate.
/// One key under two certificates is one signer (ADR-0039 2).
pub fn recertified(index: usize) -> &'static [u8] {
    recertified_until(index, "20361231000000Z")
}

/// As [`recertified`], the certificate valid until `end`
/// (`YYYYMMDDhhmmssZ`): the pin of signer `index`'s key under a
/// certificate that may end before the election.
pub fn recertified_until(index: usize, end: &str) -> &'static [u8] {
    let signer = signer(index);
    in_scratch(|dir| {
        std::fs::write(dir.join("k.pem"), &signer.key_pem).unwrap();
        let (cert, _) = self_signed_until(dir, "recertified", 0x40 + index, end);
        pin_of(leak_slice(cert), DIGESTS, SIGNATURES)
    })
}

fn make_signer(index: usize) -> Signer {
    let (authority, operator, government, name, accuracy) = SIGNERS[index];
    in_scratch(|dir| {
        run(
            dir,
            &[
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out",
                "k.pem",
            ],
            None,
        );
        let (cert, cert_pem) = self_signed(dir, name, index + 1);
        let cert = leak_slice(cert);
        Signer {
            authority,
            operator,
            government,
            accuracy,
            key_pem: std::fs::read_to_string(dir.join("k.pem")).unwrap(),
            cert_pem,
            cert,
            pin: pin_of(cert, DIGESTS, SIGNATURES),
        }
    })
}

/// Signer `index` (module documentation), made once per process.
pub fn signer(index: usize) -> &'static Signer {
    static SIGNERS_MADE: OnceLock<Vec<&'static Signer>> = OnceLock::new();
    SIGNERS_MADE.get_or_init(|| {
        require_openssl_3();
        (0..SIGNERS.len()).map(|i| leak(make_signer(i))).collect()
    })[index]
}

fn authority_id(name: &'static str) -> AuthorityId<'static> {
    AuthorityId::new(name.as_bytes()).unwrap()
}

/// The genesis entries of the three pinned authorities, in key order:
/// `TSA-FREE-1`, `TSA-GOV-1` (two pins), `TSA-GOV-2`.
pub fn authorities() -> Vec<TimestampAuthorityEntry<'static>> {
    let entry =
        |name: &'static str, operator: &'static str, government: bool, pins: &[usize], ms: u32| {
            let mut pins: Vec<&'static [u8]> = pins.iter().map(|&i| signer(i).pin).collect();
            pins.sort();
            TimestampAuthorityEntry {
                tsa_id: authority_id(name),
                operator: OrgId::new(operator.as_bytes()).unwrap(),
                kind: if government {
                    TimestampAuthorityKind::Government
                } else {
                    TimestampAuthorityKind::NonGovernment
                },
                policy_accuracy: PolicyAccuracy::from_millis(ms).unwrap(),
                pins: TimestampPins::new(&pins).unwrap(),
            }
        };
    std::vec![
        entry("TSA-FREE-1", "FREE-TSA", false, &[FREE], 2000),
        entry("TSA-GOV-1", "MOIS-GPKI", true, &[GOV, GOV_ROTATED], 1000),
        entry("TSA-GOV-2", "MOIS-GPKI", true, &[GOV_SAME_OPERATOR], 1000),
    ]
}

/// A DER element: tag, the offset of its content, the content length.
fn tlv(bytes: &[u8], at: usize) -> (u8, usize, usize) {
    let tag = bytes[at];
    let first = bytes[at + 1];
    if first < 0x80 {
        (tag, at + 2, usize::from(first))
    } else {
        let n = usize::from(first & 0x7F);
        let len = bytes[at + 2..at + 2 + n]
            .iter()
            .fold(0usize, |acc, b| acc << 8 | usize::from(*b));
        (tag, at + 2 + n, len)
    }
}

/// The elements inside the content `[start, start + len)`: (offset, tag,
/// content offset, content length).
fn children(bytes: &[u8], start: usize, len: usize) -> Vec<(usize, u8, usize, usize)> {
    let mut out = Vec::new();
    let mut at = start;
    while at < start + len {
        let (tag, content, clen) = tlv(bytes, at);
        out.push((at, tag, content, clen));
        at = content + clen;
    }
    out
}

/// `seconds` (Unix) as DER `GeneralizedTime` text `YYYYMMDDhhmmssZ`.
fn generalized_time(seconds: u64) -> [u8; 15] {
    let days = (seconds / 86_400) as i64;
    let rest = seconds % 86_400;
    // Days to civil date (H. Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    let text = std::format!(
        "{year:04}{month:02}{day:02}{:02}{:02}{:02}Z",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    );
    text.as_bytes().try_into().unwrap()
}

/// A token of signer `index` over `target` (an event's object hash) with
/// `genTime` at Unix second `seconds`, stating an accuracy of `accuracy`
/// seconds or none.
fn make_token(index: usize, target: &Hash512, seconds: u64, accuracy: Option<u32>) -> Vec<u8> {
    let signer = signer(index);
    let accuracy = accuracy.map_or(String::new(), |s| std::format!("accuracy = secs:{s}\n"));
    in_scratch(|dir| {
        std::fs::write(dir.join("k.pem"), &signer.key_pem).unwrap();
        std::fs::write(dir.join("c.pem"), &signer.cert_pem).unwrap();
        std::fs::write(dir.join("hash.bin"), target.as_bytes()).unwrap();
        std::fs::write(dir.join("tsserial"), "01\n").unwrap();
        let config = std::format!(
            "[ tsa ]\ndefault_tsa = t\n[ t ]\nserial = {}\ncrypto_device = builtin\n\
             signer_cert = {}\nsigner_key = {}\nsigner_digest = sha256\n\
             ess_cert_id_alg = sha256\ness_cert_id_chain = no\n\
             default_policy = 1.2.3.4.1\ndigests = sha256, sha512\n{accuracy}",
            dir.join("tsserial").display(),
            dir.join("c.pem").display(),
            dir.join("k.pem").display(),
        );
        std::fs::write(dir.join("ts.cnf"), config).unwrap();
        run(
            dir,
            &[
                "ts",
                "-query",
                "-data",
                "hash.bin",
                "-sha512",
                "-cert",
                "-no_nonce",
                "-out",
                "q.tsq",
            ],
            None,
        );
        run(
            dir,
            &[
                "ts",
                "-reply",
                "-config",
                "ts.cnf",
                "-queryfile",
                "q.tsq",
                "-token_out",
                "-out",
                "t.tst",
            ],
            None,
        );
        let mut token = std::fs::read(dir.join("t.tst")).unwrap();
        // ContentInfo { contentType, [0] SignedData }.
        let (_, ci, ci_len) = tlv(&token, 0);
        let content = children(&token, ci, ci_len)[1];
        let (_, sd, sd_len) = tlv(&token, content.2);
        let signed_data = children(&token, sd, sd_len);
        // encapContentInfo { eContentType, [0] OCTET STRING TSTInfo }.
        let encap = signed_data[2];
        let econtent = children(&token, encap.2, encap.3)[1];
        let (_, octets, _) = tlv(&token, econtent.2);
        let (_, tst, tst_len) = tlv(&token, octets);
        let tst_end = tst + tst_len;
        let gen_time = children(&token, tst, tst_len)[4];
        assert_eq!(
            (gen_time.1, gen_time.3),
            (0x18, 15),
            "genTime is YYYYMMDDhhmmssZ"
        );
        token[gen_time.2..gen_time.2 + 15].copy_from_slice(&generalized_time(seconds));
        let digest = run(
            dir,
            &["dgst", "-sha256", "-binary"],
            Some(&token[octets..tst_end]),
        );
        // signerInfos { SignerInfo { version, sid, digestAlgorithm, [0]
        // signedAttrs, signatureAlgorithm, signature } }.
        let infos = *signed_data.last().unwrap();
        let info = children(&token, infos.2, infos.3)[0];
        let fields = children(&token, info.2, info.3);
        let attrs = fields[3];
        assert_eq!(attrs.1, 0xA0);
        for attribute in children(&token, attrs.2, attrs.3) {
            let parts = children(&token, attribute.2, attribute.3);
            let oid = &token[parts[0].2..parts[0].2 + parts[0].3];
            if oid == [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04] {
                let value = children(&token, parts[1].2, parts[1].3)[0];
                assert_eq!(value.3, 32);
                token[value.2..value.2 + 32].copy_from_slice(&digest);
            }
        }
        let mut to_sign = token[attrs.0..attrs.2 + attrs.3].to_vec();
        to_sign[0] = 0x31;
        std::fs::write(dir.join("attrs.der"), &to_sign).unwrap();
        let signature = run(
            dir,
            &["dgst", "-sha256", "-sign", "k.pem", "-binary", "attrs.der"],
            None,
        );
        let sig = fields[5];
        assert_eq!((sig.1, sig.3), (0x04, signature.len()));
        token[sig.2..sig.2 + sig.3].copy_from_slice(&signature);
        token
    })
}

/// A token of signer `index` over `target` at Unix second `seconds`,
/// stating the signer's own accuracy, made once and shared.
pub fn token(index: usize, target: &Hash512, seconds: u64) -> &'static [u8] {
    token_stating(index, target, seconds, signer(index).accuracy)
}

/// A token of signer `index` over `target` at Unix second `seconds`,
/// stating an accuracy of `accuracy` seconds (or none), made once and
/// shared.
pub fn token_stating(
    index: usize,
    target: &Hash512,
    seconds: u64,
    accuracy: Option<u32>,
) -> &'static [u8] {
    type Key = (usize, [u8; 64], u64, Option<u32>);
    type Cache = Mutex<BTreeMap<Key, &'static [u8]>>;
    static TOKENS: OnceLock<Cache> = OnceLock::new();
    let cache = TOKENS.get_or_init(|| Mutex::new(BTreeMap::new()));
    let key = (index, target.0, seconds, accuracy);
    if let Some(t) = cache.lock().unwrap().get(&key) {
        return t;
    }
    let t = leak_slice(make_token(index, target, seconds, accuracy));
    cache.lock().unwrap().insert(key, t);
    t
}

/// The Unix second `offset` seconds into bucket `bucket` of the tests'
/// election epoch.
pub const fn at(bucket: u64, offset: u64) -> u64 {
    EPOCH_SECONDS + bucket * 900 + offset
}

/// A `TimestampRecord` of `election` naming `authority`, over the event
/// `target` of schema `target_schema`, carrying `token` (`None`: the
/// authority did not answer).
pub fn record_for(
    election: ElectionId<'static>,
    authority: &'static str,
    target_schema: SchemaId,
    target: Hash512,
    token: Option<&'static [u8]>,
) -> &'static [u8] {
    let record = TimestampRecord::new(&TimestampRecordParts {
        election_id: election,
        target_schema,
        target_hash: target,
        authority_id: authority_id(authority),
        token,
    })
    .unwrap();
    object(SCHEMA_TIMESTAMP_RECORD, SCHEMA_VERSION_1, &record)
}

/// A record of signer `index`'s token over the event `event` (its object
/// bytes, of schema `schema`) at Unix second `seconds`, naming the signer's
/// own authority.
pub fn stamp(index: usize, schema: SchemaId, event: &[u8], seconds: u64) -> &'static [u8] {
    let target = ityv_crypto::object_hash(event);
    record_for(
        super::election(),
        signer(index).authority,
        schema,
        target,
        Some(token(index, &target, seconds)),
    )
}

/// The two records that anchor `event` (of schema `schema`): the
/// government and the non-government authority, each a minute into bucket
/// `bucket`.
pub fn anchor(schema: SchemaId, event: &[u8], bucket: u64) -> [&'static [u8]; 2] {
    [
        stamp(GOV, schema, event, at(bucket, 60)),
        stamp(FREE, schema, event, at(bucket, 60)),
    ]
}
