//! The secret-bearing schema values (`Scalars`, `ModuleOpening`,
//! `ChallengeOpeningBody`, `MemberShare`) are wiped by `zeroize` (which
//! their `Drop` calls) and print nothing secret (ADR-0017 개정 15).
// Integration-test crate: outside the TCB. Test code expresses "this must
// hold" with unwrap/expect/indexing, so those restriction lints are relaxed
// for this file only (CONSTITUTION.md §1.1).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::missing_panics_doc
)]

use ityv_encoding::{
    BallotStyleId, BoxId, ChallengeOpeningBody, ChallengeOpeningParts, ElectionId, Hash512,
    MAX_CHUNKS, MAX_SECRETS, MemberShare, ModuleId, ModuleOpening, Scalar32, Scalars, Token192,
};
use zeroize::Zeroize;

fn scalars<const N: usize>(n: usize, byte: u8) -> Scalars<N> {
    Scalars::new(&std::vec![Scalar32([byte; 32]); n]).unwrap()
}

#[test]
fn scalars_zeroize_and_redact() {
    let mut s = scalars::<MAX_CHUNKS>(3, 0xAB);
    let copy = s.duplicate();
    assert_eq!(copy, s);
    assert_eq!(std::format!("{s:?}"), "Scalars { count: 3, .. }");
    s.zeroize();
    assert!(s.as_slice().is_empty());
    assert_eq!(s.count(), 0);
    assert_eq!(copy.as_slice(), &[Scalar32([0xAB; 32]); 3]);
}

fn opening(id: &'static [u8], byte: u8) -> ModuleOpening<'static> {
    ModuleOpening {
        module_id: ModuleId::new(id).unwrap(),
        counter: 7,
        rand: scalars(2, byte),
        cid: Token192([byte; 24]),
    }
}

#[test]
fn module_openings_zeroize_and_redact() {
    let mut m = opening(b"mod-x", 0x11);
    let copy = m.duplicate();
    assert_eq!(copy, m);
    let text = std::format!("{m:?}");
    assert!(text.contains("counter: 7"));
    assert!(!text.contains("rand") && !text.contains("cid") && !text.contains("17"));
    m.zeroize();
    assert!(m.rand.as_slice().is_empty());
    assert_eq!(m.cid, Token192([0; 24]));
    assert_eq!(m.counter, 7, "the counter is public");
    assert_eq!(copy.cid, Token192([0x11; 24]));
}

#[test]
fn challenge_opening_bodies_zeroize_and_redact() {
    let rand = scalars::<MAX_CHUNKS>(2, 0x22);
    let modules = [opening(b"mod-a", 0x33), opening(b"mod-b", 0x44)];
    let mut body = ChallengeOpeningBody::new(&ChallengeOpeningParts {
        election_id: ElectionId::new(b"E").unwrap(),
        box_id: BoxId::new(b"B").unwrap(),
        ballot_style_id: BallotStyleId::new(b"S").unwrap(),
        record_hash: Hash512([5; 64]),
        option_index: 9,
        cast_id: Token192([0x55; 24]),
        rand: &rand,
        modules: &modules,
    })
    .unwrap();
    let text = std::format!("{body:?}");
    assert!(text.contains("module_count: 2"));
    assert!(!text.contains("option_index") && !text.contains("cast_id"));
    body.zeroize();
    assert_eq!(body.option_index(), 0);
    assert_eq!(body.cast_id(), &Token192([0; 24]));
    assert!(body.rand().as_slice().is_empty());
    assert_eq!(body.modules().count(), 2);
    for m in body.modules() {
        assert!(m.rand.as_slice().is_empty());
        assert_eq!(m.cid, Token192([0; 24]));
    }
    // the parts it was built from are separate values
    assert_eq!(rand.count(), 2);
    assert_eq!(modules[0].cid, Token192([0x33; 24]));
}

#[test]
fn member_shares_zeroize_and_redact() {
    let tag = [0x66; 16];
    let shares = scalars::<MAX_SECRETS>(5, 0x77);
    let mut share = MemberShare::new(
        &shares,
        true,
        Token192([0x88; 24]),
        Some(Token192([0x99; 24])),
        &tag,
    )
    .unwrap();
    assert_eq!(
        std::format!("{share:?}"),
        "MemberShare { has_module: true, .. }"
    );
    share.zeroize();
    assert!(share.shares().as_slice().is_empty());
    assert_eq!(share.cid(), &Token192([0; 24]));
    assert!(share.lab().is_none());
    assert_eq!(share.tag(), &tag, "the tag is borrowed, not owned");
    assert_eq!(shares.count(), 5);
}
