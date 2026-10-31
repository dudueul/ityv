//! Known-answer tests for the domain hashes (ENCODING.md §4) and the
//! `Purpose` parser. Expected values were computed independently with
//! Python `hashlib.sha3_512` over the documented input layouts.
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

use common::{counting, hex, unhex_array};
use ityv_crypto::{Purpose, Scalar, fiat_shamir_challenge, object_hash, signing_digest};

#[test]
fn object_hash_known_answers() {
    assert_eq!(
        hex(object_hash(b"").as_bytes()),
        "b9653f9a8322be7b98af229707d1fb39ebf8da20dea3644152ee2b2a4b7ffd1737da272d8d6f6761ba40e033a434823b86bce1e8e08a081cfdb3065fffddb876"
    );
    assert_eq!(
        hex(object_hash(b"ityv").as_bytes()),
        "13f3f4cd226a713925fb1e9ea7a3ca9988e704a828af40b229f852431c4dbd0c30510394cbc010a62ba9d81617705e149d4888cdd55978427f2e0d4d4b8a1cd8"
    );
    assert_eq!(
        hex(object_hash(&counting(256)).as_bytes()),
        "0079879d612c44c6dc4601266f283a6c878fbd6a54021e89e769a4561c7049ad8f87f4feb5d5b7df3de7f04d880c1d6c0995df30b75c45a1e0092d1dbcba85bc"
    );
}

#[test]
fn signing_digest_known_answers() {
    let checkpoint = Purpose::new(b"checkpoint").unwrap();
    assert_eq!(
        hex(signing_digest(&checkpoint, b"hello").as_bytes()),
        "164a319a922de631e063d36b5c4ff7b4d97a5a918e306a0a5af309a4076212ae2909997082da4c0397c79b7aa8c8be00bde5eb92fd7b68075173cb7080fe54bc"
    );
    let cast_record = Purpose::new(b"cast-record").unwrap();
    assert_eq!(
        hex(signing_digest(&cast_record, &counting(32)).as_bytes()),
        "bf677e91366958bdfc704a13db886babc6b42ebc04217c258c23a062ffd1bd52b1b8d619836d592ec99e2f94027ede5c678f8d7c8205bffc522b0590bc4a0426"
    );
}

#[test]
fn signing_digest_with_maximum_length_purpose() {
    // A 32-byte purpose fills the signing prefix buffer completely; the
    // expected value was computed with Python hashlib over the documented
    // layout, so a truncated prefix would be detected here.
    let purpose = Purpose::new(&[b'a'; 32]).unwrap();
    assert_eq!(
        hex(signing_digest(&purpose, b"max-length purpose object").as_bytes()),
        "04deb3566c51efd45e51414fb944835e3f5726bb110dd0c9e90049c1d02d8b003eddab21dc720890e1d34672d6f7ca2d304befd3bf7a68f8aa14136aeb5115b5"
    );
}

#[test]
fn fiat_shamir_known_answer() {
    let challenge = fiat_shamir_challenge(b"ityv:proof:or-rep:v1", b"transcript");
    let expected = Scalar::from_canonical_bytes(unhex_array::<32>(
        "176c66977be15f0177cd2b8c92506c07ba7452c43014658e77fa95555f19d60c",
    ))
    .unwrap();
    assert_eq!(challenge, expected);
}

#[test]
fn domains_are_separated() {
    let a = Purpose::new(b"a").unwrap();
    let b = Purpose::new(b"b").unwrap();
    assert_ne!(signing_digest(&a, b"x"), signing_digest(&b, b"x"));
    assert_ne!(signing_digest(&a, b"x"), signing_digest(&a, b"y"));
    assert_ne!(
        object_hash(b"x").as_bytes(),
        signing_digest(&a, b"x").as_bytes()
    );
    // The length prefix separates a purpose/object split from any other split.
    let ab = Purpose::new(b"ab").unwrap();
    assert_ne!(signing_digest(&ab, b"c"), signing_digest(&a, b"bc"));
    assert_ne!(
        fiat_shamir_challenge(b"p", b"q"),
        fiat_shamir_challenge(b"pq", b"")
    );
    assert_ne!(
        fiat_shamir_challenge(b"p", b"q"),
        fiat_shamir_challenge(b"q", b"p")
    );
}

#[test]
fn purpose_accepts_exactly_the_identifier_alphabet() {
    assert!(Purpose::new(b"").is_none());
    assert!(Purpose::new(b"cast-record").is_some());
    assert!(Purpose::new(b"a.b_c:d-E9").is_some());
    assert!(Purpose::new(b"has space").is_none());
    assert!(Purpose::new(b"has/slash").is_none());
    assert!(Purpose::new(&[b'a'; 32]).is_some());
    assert!(Purpose::new(&[b'a'; 33]).is_none());
    assert_eq!(Purpose::new(b"slip").unwrap().as_bytes(), b"slip");
}
