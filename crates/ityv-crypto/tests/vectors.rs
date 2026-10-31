//! Interop reference vectors for a second implementation (V5) and
//! regression guard for this one.
//!
//! `vectors/crypto.txt` holds, for fixed inputs, the three commitment base
//! points, deterministic key derivations, a commitment, a KEM
//! encapsulation with a sealed message (seeded RNG, through the public
//! API), the transcript header of a small OR statement with the
//! Fiat-Shamir reduction of those header bytes, and a complete OR proof
//! with its challenge sum. The independent known-answer tests (NIST and
//! Python) live in `hash.rs`, `sig.rs`, `kem.rs`, `otmac.rs` and the crate's
//! unit tests; the values here were produced by this implementation. Set
//! `ITYV_UPDATE_VECTORS=1` to rewrite the file after an intended change, and
//! say so in the commit message.
// Integration-test crate: outside the TCB. Test code expresses "this must
// hold" with unwrap/expect/panic/indexing and does small arithmetic on test
// sizes, so those restriction lints are relaxed for this file only. No TCB
// crate may do this (CONSTITUTION.md §1.1).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::missing_panics_doc,
    clippy::missing_errors_doc
)]

mod common;

use common::{counting32, encode_to_vec, hex, rng};
use ityv_crypto::{
    Bases, CastId, ChunkIndex, FS_LABEL_OR_REP_V1, HybridKemSecretKey, HybridSigningKey,
    MAX_CHUNKS, Opening, OptionCount, OptionIndex, PROOF_SYSTEM_OR_REP_V1, RecordPurpose,
    RecordSigningKey, Scalar, Statement, commit, decapsulate, encapsulate, fiat_shamir_challenge,
    open, prove, seal, sign_record, verify,
};
use ityv_encoding::{ElectionId, Ident, Token192, Writer};
use std::collections::BTreeMap;
use std::string::{String, ToString};
use std::vec::Vec;

const HEADER: &str = "\
# ityv-crypto reference vectors: the interop reference for a second
# implementation (verification ladder V5) and the regression guard for this
# one. Produced by this implementation from the fixed inputs named in each
# key; independent known answers (NIST, Python) are in the test sources.
# Regenerate with ITYV_UPDATE_VECTORS=1 and say so in the commit message.
#
# Inputs: seed_0_31 = bytes 0x00..0x1f; seed_0_63 = bytes 0x00..0x3f;
# cast_0_23 = bytes 0x00..0x17; election KR-2030-PRES, box BOX-0001,
# style PRES; option_count 4 (one chunk); r_0 = 12345; RNG = ChaCha20
# seeded with the given u64 (rand_chacha seed_from_u64).
# fs_challenge_over_or_header is the Fiat-Shamir reduction of the header
# bytes alone (items 1-7 plus the announcement count of PROTOCOL §7.5),
# a layout check; or_proof_challenge_sum is Σ c_t of the proof, which equals
# the challenge over header ‖ announcements.
# Format: name = lowercase hex
";

const ELECTION: &[u8] = b"KR-2030-PRES";
const BOX: &[u8] = b"BOX-0001";
const STYLE: &[u8] = b"PRES";

/// The transcript header of PROTOCOL §7.5 items 1–7 plus the announcement
/// count, built here independently of the crate's own transcript code.
fn or_header(option_count: u16, commitments: &[[u8; 32]]) -> Vec<u8> {
    let mut buffer = std::vec![0u8; 512];
    let mut w = Writer::new(&mut buffer);
    w.write_ident(&Ident::new(ELECTION, 64).unwrap(), 64)
        .unwrap();
    w.write_ident(&Ident::new(BOX, 64).unwrap(), 64).unwrap();
    w.write_ident(&Ident::new(STYLE, 64).unwrap(), 64).unwrap();
    w.write_u16(PROOF_SYSTEM_OR_REP_V1).unwrap();
    w.write_u16(option_count).unwrap();
    let k = u8::try_from(commitments.len()).unwrap();
    w.write_u8(k).unwrap();
    w.write_count(commitments.len(), 8).unwrap();
    for c in commitments {
        w.write_array(c).unwrap();
    }
    w.write_count(usize::from(option_count) * commitments.len(), 512)
        .unwrap();
    let n = w.finish();
    buffer.truncate(n);
    buffer
}

fn vectors() -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let bases = Bases::derive();
    let [val, id, rand] = bases.compressed();
    out.insert("base_g_val".to_string(), hex(&val));
    out.insert("base_g_id".to_string(), hex(&id));
    out.insert("base_h".to_string(), hex(&rand));

    let hybrid = HybridSigningKey::from_seeds(counting32(), counting32());
    let vk = hybrid.verifying_key();
    out.insert("mldsa87_vk_seed_0_31".to_string(), hex(vk.mldsa87()));
    out.insert("ed25519_vk_seed_0_31".to_string(), hex(vk.ed25519()));

    let mut seed64 = [0u8; 64];
    for (i, b) in seed64.iter_mut().enumerate() {
        *b = u8::try_from(i).unwrap();
    }
    let kem = HybridKemSecretKey::from_parts(seed64, counting32());
    let pk = kem.public_key();
    out.insert("mlkem1024_ek_seed_0_63".to_string(), hex(pk.mlkem1024()));
    out.insert("x25519_pk_seed_0_31".to_string(), hex(pk.x25519()));

    // KEM encapsulation and sealing with a seeded RNG, through the public API.
    let mut kem_rng = rng(0x6b_65_6d);
    let (ciphertext, seal_key) = encapsulate(&pk, &mut kem_rng).unwrap();
    out.insert(
        "kem_ct_mlkem1024_rng_6b656d".to_string(),
        hex(ciphertext.mlkem1024()),
    );
    out.insert(
        "kem_ct_x25519_rng_6b656d".to_string(),
        hex(ciphertext.x25519()),
    );
    let mut sealed = *b"share plaintext for interop";
    let tag = seal(seal_key, b"ityv:share-package", &mut sealed).unwrap();
    out.insert("kem_sealed_rng_6b656d".to_string(), hex(&sealed));
    out.insert("kem_sealed_tag_rng_6b656d".to_string(), hex(tag.as_bytes()));
    let open_key = decapsulate(&kem, &ciphertext).unwrap();
    let plaintext = open(open_key, b"ityv:share-package", &mut sealed, &tag).unwrap();
    assert_eq!(plaintext.into_inner(), b"share plaintext for interop");

    let record_key = RecordSigningKey::from_seed(counting32());
    let sig = sign_record(&record_key, RecordPurpose::CastRecord, b"record body").unwrap();
    out.insert("record_sig_cast_record".to_string(), hex(sig.as_bytes()));

    let mut token = [0u8; 24];
    for (i, b) in token.iter_mut().enumerate() {
        *b = u8::try_from(i).unwrap();
    }
    let cast_id = CastId::new(Token192(token));
    let option = OptionIndex::new(1).unwrap();
    let r0 = Scalar::from_u64(12345);
    let c0 = commit(&bases, option, &cast_id, &r0, ChunkIndex::new(0).unwrap());
    out.insert(
        "commitment_t1_cast_0_23_r12345".to_string(),
        hex(c0.as_bytes()),
    );

    let header = or_header(4, &[*c0.as_bytes()]);
    out.insert("or_transcript_header_m4_k1".to_string(), hex(&header));
    let challenge = fiat_shamir_challenge(FS_LABEL_OR_REP_V1, &header);
    out.insert(
        "fs_challenge_over_or_header_m4_k1".to_string(),
        hex(&challenge.to_bytes()),
    );

    let mut rand = [Scalar::ZERO; MAX_CHUNKS];
    rand[0] = r0;
    let opening = Opening::new(option, cast_id, rand);
    let statement = Statement::new(
        ElectionId::new(ELECTION).unwrap(),
        Ident::new(BOX, 64).unwrap(),
        Ident::new(STYLE, 64).unwrap(),
        OptionCount::new(4).unwrap(),
        &[c0],
    )
    .unwrap();
    let mut proof_rng = rng(0xa11ce);
    let proof = prove(&bases, &statement, &opening, &mut proof_rng).unwrap();
    assert!(verify(&bases, &statement, &proof).is_ok());
    out.insert(
        "or_proof_m4_k1_rng_a11ce".to_string(),
        hex(&encode_to_vec(&proof)),
    );
    let mut sum = Scalar::ZERO;
    for t in 0..4u16 {
        sum = sum.add(proof.challenge(OptionIndex::new(t).unwrap()).unwrap());
    }
    out.insert(
        "or_proof_challenge_sum_m4_k1_rng_a11ce".to_string(),
        hex(&sum.to_bytes()),
    );
    out
}

fn render(map: &BTreeMap<String, String>) -> String {
    let mut text = String::from(HEADER);
    for (name, value) in map {
        text.push_str(name);
        text.push_str(" = ");
        text.push_str(value);
        text.push('\n');
    }
    text
}

fn parse(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .filter(|line| !line.starts_with('#') && !line.trim().is_empty())
        .map(|line| {
            let (name, value) = line.split_once(" = ").expect("name = hex");
            (name.to_string(), value.to_string())
        })
        .collect()
}

#[test]
fn reference_vectors_match() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("vectors/crypto.txt");
    let computed = vectors();
    if std::env::var_os("ITYV_UPDATE_VECTORS").is_some() {
        std::fs::write(&path, render(&computed)).unwrap();
    }
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "missing {}: {e}; run with ITYV_UPDATE_VECTORS=1",
            path.display()
        )
    });
    let stored = parse(&text);
    for (name, value) in &computed {
        assert_eq!(
            stored.get(name),
            Some(value),
            "vector {name} differs; if the change is intended, regenerate with ITYV_UPDATE_VECTORS=1"
        );
    }
    assert_eq!(stored.len(), computed.len(), "stale or missing vectors");
}
