//! Linear secret sharing over the chamber access structure (PROTOCOL.md
//! §9.2; ADR-0012): qualified sets reconstruct, unqualified sets get
//! nothing, extra shares are consistency-checked, and shares add.
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

use common::rng;
use ityv_crypto::Chamber::{A, C, J, N, X, Y};
use ityv_crypto::shares::{REST_CHAMBERS, REST_THRESHOLD, reached};
use ityv_crypto::{
    AccessStructure, CHAMBER_COUNT, Chamber, Error, MAX_MEMBERS, MemberId, MemberShares, Scalar,
    Share, Threshold, is_qualified, reconstruct, split,
};
use std::vec::Vec;

fn uniform() -> AccessStructure {
    AccessStructure::uniform(Threshold::new(2, 3).unwrap())
}

/// The first `take` members of each listed chamber.
fn subset(shares: &MemberShares, chambers: &[(Chamber, u8)]) -> Vec<Share> {
    let mut out = Vec::new();
    for (chamber, take) in chambers {
        for index in 0..*take {
            out.push(shares.share(MemberId::new(*chamber, index).unwrap()));
        }
    }
    out
}

#[test]
fn qualified_sets_reconstruct() {
    let structure = uniform();
    let mut rng = rng(40);
    let secret = Scalar::random(&mut rng);
    let shares = split(&secret, &structure, &mut rng);
    let qualified: [&[(Chamber, u8)]; 7] = [
        &[(X, 2), (Y, 2), (J, 2), (A, 2), (C, 2), (N, 2)],
        &[(X, 2), (Y, 2), (J, 2), (A, 2), (C, 2)],
        &[(X, 2), (Y, 2), (J, 2), (A, 2), (N, 2)],
        &[(X, 2), (Y, 2), (J, 2), (C, 2), (N, 2)],
        &[(X, 2), (Y, 2), (A, 2), (C, 2), (N, 2)],
        &[(X, 3), (Y, 3), (J, 3), (A, 3), (C, 3), (N, 3)],
        &[(X, 2), (Y, 3), (N, 2), (C, 3), (A, 2)],
    ];
    for set in qualified {
        assert_eq!(
            reconstruct(&structure, &subset(&shares, set)).unwrap(),
            secret
        );
    }
    // Member order does not matter.
    let mut reversed = subset(&shares, qualified[0]);
    reversed.reverse();
    assert_eq!(reconstruct(&structure, &reversed).unwrap(), secret);
}

#[test]
fn unqualified_sets_get_nothing() {
    let structure = uniform();
    let mut rng = rng(41);
    let secret = Scalar::random(&mut rng);
    let shares = split(&secret, &structure, &mut rng);
    let unqualified: [&[(Chamber, u8)]; 6] = [
        &[],
        &[(Y, 3), (J, 3), (A, 3), (C, 3), (N, 3)],
        &[(X, 3), (J, 3), (A, 3), (C, 3), (N, 3)],
        &[(X, 2), (Y, 2), (J, 2), (A, 2)],
        &[(X, 1), (Y, 2), (J, 2), (A, 2), (C, 2), (N, 2)],
        &[(X, 2), (Y, 1), (J, 3), (A, 3), (C, 3), (N, 3)],
    ];
    for set in unqualified {
        assert_eq!(
            reconstruct(&structure, &subset(&shares, set)).unwrap_err(),
            Error::NotQualified
        );
    }
}

#[test]
fn is_qualified_matches_the_access_structure_definition() {
    let structure = uniform();
    for mask in 0u8..64 {
        let mut counts = [0u8; CHAMBER_COUNT];
        for (i, count) in counts.iter_mut().enumerate() {
            *count = if mask & (1 << i) != 0 { 2 } else { 1 };
        }
        let flags = reached(&structure, counts);
        for (i, flag) in flags.iter().enumerate() {
            assert_eq!(*flag, mask & (1 << i) != 0);
        }
        let x = mask & 1 != 0;
        let y = mask & 2 != 0;
        let rest = (mask >> 2).count_ones() as usize;
        assert_eq!(
            is_qualified(&structure, counts),
            x && y && rest >= REST_THRESHOLD
        );
    }
    assert_eq!(REST_CHAMBERS, 4);
    assert_eq!(Chamber::ALL.len(), CHAMBER_COUNT);
    for (i, chamber) in Chamber::ALL.iter().enumerate() {
        assert_eq!(chamber.index(), i);
        assert_eq!(chamber.is_mandatory(), i < 2);
        assert_eq!(
            chamber.rest_point(),
            if i < 2 {
                None
            } else {
                Some(u8::try_from(i - 1).unwrap())
            }
        );
    }
}

#[test]
fn thresholds_and_members_validate() {
    assert!(Threshold::new(0, 3).is_none());
    assert!(Threshold::new(4, 3).is_none());
    assert!(Threshold::new(3, 9).is_none());
    let t = Threshold::new(1, 1).unwrap();
    assert_eq!((t.k(), t.n()), (1, 1));
    let full = Threshold::new(8, 8).unwrap();
    assert_eq!(full.n(), u8::try_from(MAX_MEMBERS).unwrap());
    assert!(MemberId::new(Chamber::X, 8).is_none());
    let member = MemberId::new(Chamber::N, 7).unwrap();
    assert_eq!(member.chamber(), Chamber::N);
    assert_eq!(member.index(), 7);
    assert_eq!(member.point(), 8);
    let structure = AccessStructure::new([t, full, t, full, t, full]);
    assert_eq!(structure.threshold(Chamber::Y), full);
    assert_eq!(structure.threshold(Chamber::X), t);
    assert_eq!(structure.thresholds()[5], full);
    let share = Share::new(member, Scalar::ONE);
    assert_eq!(share.member(), member);
    assert_eq!(share.value(), &Scalar::ONE);
    assert!(std::format!("{share:?}").starts_with("Share"));
}

#[test]
fn duplicate_and_invalid_members_are_rejected() {
    let structure = uniform();
    let mut rng = rng(42);
    let shares = split(&Scalar::random(&mut rng), &structure, &mut rng);
    let mut set = subset(&shares, &[(X, 2), (Y, 2), (J, 2), (A, 2), (C, 2)]);
    set.push(shares.share(MemberId::new(X, 0).unwrap()));
    assert_eq!(
        reconstruct(&structure, &set).unwrap_err(),
        Error::DuplicateShare
    );
    let mut set = subset(&shares, &[(X, 2), (Y, 2), (J, 2), (A, 2), (C, 2)]);
    set.push(Share::new(MemberId::new(X, 3).unwrap(), Scalar::ONE));
    assert_eq!(
        reconstruct(&structure, &set).unwrap_err(),
        Error::InvalidMember
    );
    // The member bound check happens before qualification.
    assert_eq!(
        reconstruct(
            &structure,
            &[Share::new(MemberId::new(X, 5).unwrap(), Scalar::ONE)]
        )
        .unwrap_err(),
        Error::InvalidMember
    );
}

#[test]
fn inconsistent_extra_shares_are_detected() {
    let structure = uniform();
    let mut rng = rng(43);
    let secret = Scalar::random(&mut rng);
    let shares = split(&secret, &structure, &mut rng);
    // A third X member whose share is wrong: the first two reconstruct X's
    // secret, the third disagrees.
    let mut set = subset(&shares, &[(X, 2), (Y, 2), (J, 2), (A, 2), (C, 2)]);
    let bad = shares.value(MemberId::new(X, 2).unwrap()).add(&Scalar::ONE);
    set.push(Share::new(MemberId::new(X, 2).unwrap(), bad));
    assert_eq!(
        reconstruct(&structure, &set).unwrap_err(),
        Error::InconsistentShares
    );
    // A fourth rest chamber (N) whose chamber secret is wrong: J, A, C are
    // used, N is checked.
    let mut set = subset(&shares, &[(X, 2), (Y, 2), (J, 2), (A, 2), (C, 2)]);
    let n0 = shares.value(MemberId::new(N, 0).unwrap()).add(&Scalar::ONE);
    let n1 = shares.value(MemberId::new(N, 1).unwrap()).add(&Scalar::ONE);
    set.push(Share::new(MemberId::new(N, 0).unwrap(), n0));
    set.push(Share::new(MemberId::new(N, 1).unwrap(), n1));
    assert_eq!(
        reconstruct(&structure, &set).unwrap_err(),
        Error::InconsistentShares
    );
    // With exactly the threshold, a wrong share is not detectable but yields
    // a wrong secret rather than the right one.
    let mut set = subset(&shares, &[(X, 1), (Y, 2), (J, 2), (A, 2), (C, 2)]);
    let x1 = shares.value(MemberId::new(X, 1).unwrap()).add(&Scalar::ONE);
    set.push(Share::new(MemberId::new(X, 1).unwrap(), x1));
    assert_ne!(reconstruct(&structure, &set).unwrap(), secret);
}

#[test]
fn shares_are_homomorphic() {
    let structure = uniform();
    let mut rng = rng(44);
    let first = Scalar::random(&mut rng);
    let second = Scalar::random(&mut rng);
    let shares_first = split(&first, &structure, &mut rng);
    let shares_second = split(&second, &structure, &mut rng);
    let sum = shares_first.add(&shares_second);
    let set = subset(&sum, &[(X, 2), (Y, 2), (J, 2), (A, 2), (C, 2), (N, 2)]);
    assert_eq!(reconstruct(&structure, &set).unwrap(), first.add(&second));
    // Individual shares of different secrets differ.
    let member = MemberId::new(X, 0).unwrap();
    assert_ne!(shares_first.value(member), shares_second.value(member));
    assert_eq!(std::format!("{shares_first:?}"), "MemberShares(..)");
}

#[test]
fn non_uniform_structures_reconstruct_at_their_thresholds() {
    let structure = AccessStructure::new([
        Threshold::new(3, 5).unwrap(),
        Threshold::new(1, 1).unwrap(),
        Threshold::new(2, 2).unwrap(),
        Threshold::new(2, 3).unwrap(),
        Threshold::new(1, 2).unwrap(),
        Threshold::new(4, 8).unwrap(),
    ]);
    let mut rng = rng(45);
    let secret = Scalar::random(&mut rng);
    let shares = split(&secret, &structure, &mut rng);
    let exact = subset(&shares, &[(X, 3), (Y, 1), (J, 2), (A, 2), (C, 1), (N, 4)]);
    assert_eq!(reconstruct(&structure, &exact).unwrap(), secret);
    let all = subset(&shares, &[(X, 5), (Y, 1), (J, 2), (A, 3), (C, 2), (N, 8)]);
    assert_eq!(reconstruct(&structure, &all).unwrap(), secret);
    let short_x = subset(&shares, &[(X, 2), (Y, 1), (J, 2), (A, 2), (C, 1), (N, 4)]);
    assert_eq!(
        reconstruct(&structure, &short_x).unwrap_err(),
        Error::NotQualified
    );
    let short_n = subset(&shares, &[(X, 3), (Y, 1), (J, 1), (A, 2), (C, 1), (N, 3)]);
    assert_eq!(
        reconstruct(&structure, &short_n).unwrap_err(),
        Error::NotQualified
    );
    // Unused member slots beyond n are zero.
    assert_eq!(shares.value(MemberId::new(Y, 1).unwrap()), Scalar::ZERO);
    assert_eq!(shares.value(MemberId::new(X, 7).unwrap()), Scalar::ZERO);
}
