//! Linear secret sharing over the chamber access structure (PROTOCOL.md
//! §9.2; ADR-0019): with `n` party chambers (2..=4), qualified sets
//! reconstruct, unqualified sets get nothing, absent party chambers take no
//! part, extra shares are consistency-checked, and shares add.
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
    clippy::missing_errors_doc,
    clippy::cast_possible_truncation
)]

mod common;

use common::rng;
use ityv_crypto::Chamber::{A, C, J, N, P1, P2, P3, P4};
use ityv_crypto::shares::{REST_CHAMBERS, REST_THRESHOLD, reached};
use ityv_crypto::{
    AccessStructure, CHAMBER_COUNT, Chamber, Error, MAX_MEMBERS, MAX_PARTIES, MIN_PARTIES,
    MemberId, MemberShares, Scalar, Share, Threshold, is_qualified, reconstruct, split,
};
use std::vec::Vec;

fn uniform(parties: u8) -> AccessStructure {
    AccessStructure::uniform(parties, Threshold::new(2, 3).unwrap()).unwrap()
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

/// The party chambers of a structure with `n` parties.
fn parties(n: u8) -> &'static [Chamber] {
    &[P1, P2, P3, P4][..usize::from(n)]
}

#[test]
fn qualified_sets_reconstruct_for_every_party_count() {
    for n in MIN_PARTIES..=MAX_PARTIES {
        let structure = uniform(n);
        let mut rng = rng(40 + u64::from(n));
        let secret = Scalar::random(&mut rng);
        let shares = split(&secret, &structure, &mut rng);
        let party_members: Vec<(Chamber, u8)> = parties(n).iter().map(|p| (*p, 2)).collect();
        for rest in [
            &[(J, 2), (A, 2), (C, 2), (N, 2)][..],
            &[(J, 2), (A, 2), (C, 2)],
            &[(J, 2), (A, 2), (N, 2)],
            &[(J, 2), (C, 2), (N, 2)],
            &[(A, 3), (C, 2), (N, 3)],
        ] {
            let mut set = party_members.clone();
            set.extend_from_slice(rest);
            let collected = subset(&shares, &set);
            assert_eq!(reconstruct(&structure, &collected).unwrap(), secret);
            let mut reversed = collected;
            reversed.reverse();
            assert_eq!(reconstruct(&structure, &reversed).unwrap(), secret);
        }
    }
}

#[test]
fn every_subset_reconstructs_exactly_when_qualified() {
    // Exhaustive over every subset of the chambers taking part, for
    // n = 2, 3, 4 (ADR-0019, V3 item): a chamber in the subset brings two
    // members (its threshold), a chamber outside brings one.
    for n in MIN_PARTIES..=MAX_PARTIES {
        let structure = uniform(n);
        let mut rng = rng(50 + u64::from(n));
        let secret = Scalar::random(&mut rng);
        let shares = split(&secret, &structure, &mut rng);
        let taking_part: Vec<Chamber> = Chamber::ALL
            .iter()
            .copied()
            .filter(|c| structure.includes(*c))
            .collect();
        assert_eq!(taking_part.len(), usize::from(n) + 4);
        for mask in 0u32..(1 << taking_part.len()) {
            let mut set = Vec::new();
            let mut counts = [0u8; CHAMBER_COUNT];
            for (bit, chamber) in taking_part.iter().enumerate() {
                let take = if mask & (1 << bit) != 0 { 2 } else { 1 };
                set.push((*chamber, take));
                counts[chamber.index()] = take;
            }
            let in_set = |c: Chamber| {
                taking_part
                    .iter()
                    .position(|x| *x == c)
                    .is_some_and(|bit| mask & (1 << bit) != 0)
            };
            let expected = parties(n).iter().all(|p| in_set(*p))
                && [J, A, C, N].iter().filter(|c| in_set(**c)).count() >= 3;
            assert_eq!(is_qualified(&structure, counts), expected, "n={n} {mask:b}");
            let result = reconstruct(&structure, &subset(&shares, &set));
            if expected {
                assert_eq!(result.unwrap(), secret, "n={n} {mask:b}");
            } else {
                assert_eq!(result.unwrap_err(), Error::NotQualified, "n={n} {mask:b}");
            }
        }
    }
}

#[test]
fn unqualified_sets_get_nothing() {
    let structure = uniform(3);
    let mut rng = rng(41);
    let secret = Scalar::random(&mut rng);
    let shares = split(&secret, &structure, &mut rng);
    let unqualified: [&[(Chamber, u8)]; 6] = [
        &[],
        &[(P2, 3), (P3, 3), (J, 3), (A, 3), (C, 3), (N, 3)],
        &[(P1, 3), (P2, 3), (J, 3), (A, 3), (C, 3), (N, 3)],
        &[(P1, 2), (P2, 2), (P3, 2), (J, 2), (A, 2)],
        &[(P1, 1), (P2, 2), (P3, 2), (J, 2), (A, 2), (C, 2), (N, 2)],
        &[(P1, 2), (P2, 2), (P3, 1), (J, 3), (A, 3), (C, 3), (N, 3)],
    ];
    for set in unqualified {
        assert_eq!(
            reconstruct(&structure, &subset(&shares, set)).unwrap_err(),
            Error::NotQualified
        );
    }
}

#[test]
fn absent_party_chambers_take_no_part() {
    for n in MIN_PARTIES..MAX_PARTIES {
        let structure = uniform(n);
        let mut rng = rng(60 + u64::from(n));
        let secret = Scalar::random(&mut rng);
        let shares = split(&secret, &structure, &mut rng);
        for absent in &[P3, P4][usize::from(n) - 2..] {
            assert!(!structure.includes(*absent));
            for index in 0..u8::try_from(MAX_MEMBERS).unwrap() {
                let member = MemberId::new(*absent, index).unwrap();
                assert_eq!(
                    shares.value(member),
                    Scalar::ZERO,
                    "no shares for {absent:?}"
                );
            }
            // A share claimed for an absent chamber is refused before
            // qualification is even looked at.
            let mut set = subset(&shares, &[(P1, 2), (P2, 2), (J, 2), (A, 2), (C, 2)]);
            set.push(Share::new(MemberId::new(*absent, 0).unwrap(), Scalar::ONE));
            assert_eq!(
                reconstruct(&structure, &set).unwrap_err(),
                Error::InvalidMember
            );
            // and it never reaches its threshold
            let mut counts = [3u8; CHAMBER_COUNT];
            counts[absent.index()] = 8;
            assert!(!reached(&structure, counts)[absent.index()]);
        }
    }
    // Two parties draw the same randomness in the same order as before the
    // party chambers existed: the first draws are the two party shares.
    let structure = uniform(2);
    let mut a = rng(70);
    let mut b = rng(70);
    let secret = Scalar::from_u64(5);
    let shares = split(&secret, &structure, &mut a);
    let first = Scalar::random(&mut b);
    let p1 = MemberId::new(P1, 0).unwrap();
    let p1b = MemberId::new(P1, 1).unwrap();
    // P1's chamber secret is the first draw: two members interpolate it.
    let members = [shares.share(p1), shares.share(p1b)];
    let x0 = Scalar::from_u64(1);
    let x1 = Scalar::from_u64(2);
    let interpolated = members[0]
        .value()
        .mul(&x1)
        .sub(&members[1].value().mul(&x0))
        .mul(&x1.sub(&x0).invert().unwrap());
    assert_eq!(interpolated, first);
}

#[test]
fn chambers_parties_and_rest_points() {
    assert_eq!(REST_CHAMBERS, 4);
    assert_eq!(REST_THRESHOLD, 3);
    assert_eq!(CHAMBER_COUNT, 8);
    assert_eq!(Chamber::ALL.len(), CHAMBER_COUNT);
    for (i, chamber) in Chamber::ALL.iter().enumerate() {
        assert_eq!(chamber.index(), i);
        assert_eq!(chamber.is_party(), i < 4);
        assert_eq!(chamber.party(), (i < 4).then_some(i as u8));
        assert_eq!(
            chamber.rest_point(),
            (i >= 4).then(|| u8::try_from(i - 3).unwrap())
        );
    }
    for n in 0..=6u8 {
        let structure = AccessStructure::uniform(n, Threshold::new(1, 1).unwrap());
        assert_eq!(structure.is_some(), (2..=4).contains(&n), "{n}");
        if let Some(structure) = structure {
            assert_eq!(structure.parties(), n);
            for chamber in Chamber::ALL {
                assert_eq!(
                    structure.includes(chamber),
                    chamber.party().is_none_or(|p| p < n)
                );
            }
        }
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
    assert_eq!(full.k(), 8);
    let partial = Threshold::new(3, 5).unwrap();
    assert_eq!((partial.k(), partial.n()), (3, 5));
    assert!(MemberId::new(P1, 8).is_none());
    let member = MemberId::new(N, 7).unwrap();
    assert_eq!(member.chamber(), N);
    assert_eq!(member.index(), 7);
    assert_eq!(member.point(), 8);
    let structure = AccessStructure::new(4, [t, full, t, full, t, full, t, full]).unwrap();
    assert_eq!(structure.threshold(P2), full);
    assert_eq!(structure.threshold(P1), t);
    assert_eq!(structure.thresholds()[7], full);
    assert!(AccessStructure::new(1, [t; CHAMBER_COUNT]).is_none());
    assert!(AccessStructure::new(5, [t; CHAMBER_COUNT]).is_none());
    let share = Share::new(member, Scalar::ONE);
    assert_eq!(share.member(), member);
    assert_eq!(share.value(), &Scalar::ONE);
    assert!(std::format!("{share:?}").starts_with("Share"));
}

#[test]
fn duplicate_and_invalid_members_are_rejected() {
    let structure = uniform(2);
    let mut rng = rng(42);
    let shares = split(&Scalar::random(&mut rng), &structure, &mut rng);
    let mut set = subset(&shares, &[(P1, 2), (P2, 2), (J, 2), (A, 2), (C, 2)]);
    set.push(shares.share(MemberId::new(P1, 0).unwrap()));
    assert_eq!(
        reconstruct(&structure, &set).unwrap_err(),
        Error::DuplicateShare
    );
    let mut set = subset(&shares, &[(P1, 2), (P2, 2), (J, 2), (A, 2), (C, 2)]);
    set.push(Share::new(MemberId::new(P1, 3).unwrap(), Scalar::ONE));
    assert_eq!(
        reconstruct(&structure, &set).unwrap_err(),
        Error::InvalidMember
    );
    // The member bound check happens before qualification.
    assert_eq!(
        reconstruct(
            &structure,
            &[Share::new(MemberId::new(P1, 5).unwrap(), Scalar::ONE)]
        )
        .unwrap_err(),
        Error::InvalidMember
    );
}

#[test]
fn inconsistent_extra_shares_are_detected() {
    let structure = uniform(2);
    let mut rng = rng(43);
    let secret = Scalar::random(&mut rng);
    let shares = split(&secret, &structure, &mut rng);
    // A third P1 member whose share is wrong: the first two reconstruct
    // P1's secret, the third disagrees.
    let mut set = subset(&shares, &[(P1, 2), (P2, 2), (J, 2), (A, 2), (C, 2)]);
    let bad = shares
        .value(MemberId::new(P1, 2).unwrap())
        .add(&Scalar::ONE);
    set.push(Share::new(MemberId::new(P1, 2).unwrap(), bad));
    assert_eq!(
        reconstruct(&structure, &set).unwrap_err(),
        Error::InconsistentShares
    );
    // A fourth rest chamber (N) whose chamber secret is wrong: J, A, C are
    // used, N is checked.
    let mut set = subset(&shares, &[(P1, 2), (P2, 2), (J, 2), (A, 2), (C, 2)]);
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
    let mut set = subset(&shares, &[(P1, 1), (P2, 2), (J, 2), (A, 2), (C, 2)]);
    let p1 = shares
        .value(MemberId::new(P1, 1).unwrap())
        .add(&Scalar::ONE);
    set.push(Share::new(MemberId::new(P1, 1).unwrap(), p1));
    assert_ne!(reconstruct(&structure, &set).unwrap(), secret);
}

#[test]
fn shares_are_homomorphic() {
    let structure = uniform(4);
    let mut rng = rng(44);
    let first = Scalar::random(&mut rng);
    let second = Scalar::random(&mut rng);
    let shares_first = split(&first, &structure, &mut rng);
    let shares_second = split(&second, &structure, &mut rng);
    let sum = shares_first.add(&shares_second);
    let set = subset(
        &sum,
        &[
            (P1, 2),
            (P2, 2),
            (P3, 2),
            (P4, 2),
            (J, 2),
            (A, 2),
            (C, 2),
            (N, 2),
        ],
    );
    assert_eq!(reconstruct(&structure, &set).unwrap(), first.add(&second));
    // Individual shares of different secrets differ.
    let member = MemberId::new(P4, 0).unwrap();
    assert_ne!(shares_first.value(member), shares_second.value(member));
    assert_eq!(std::format!("{shares_first:?}"), "MemberShares(..)");
}

#[test]
fn non_uniform_structures_reconstruct_at_their_thresholds() {
    let structure = AccessStructure::new(
        3,
        [
            Threshold::new(3, 5).unwrap(),
            Threshold::new(1, 1).unwrap(),
            Threshold::new(2, 3).unwrap(),
            Threshold::new(8, 8).unwrap(),
            Threshold::new(2, 2).unwrap(),
            Threshold::new(2, 3).unwrap(),
            Threshold::new(1, 2).unwrap(),
            Threshold::new(4, 8).unwrap(),
        ],
    )
    .unwrap();
    let mut rng = rng(45);
    let secret = Scalar::random(&mut rng);
    let shares = split(&secret, &structure, &mut rng);
    let exact = subset(
        &shares,
        &[(P1, 3), (P2, 1), (P3, 2), (J, 2), (A, 2), (C, 1), (N, 4)],
    );
    assert_eq!(reconstruct(&structure, &exact).unwrap(), secret);
    let all = subset(
        &shares,
        &[(P1, 5), (P2, 1), (P3, 3), (J, 2), (A, 3), (C, 2), (N, 8)],
    );
    assert_eq!(reconstruct(&structure, &all).unwrap(), secret);
    let short_p1 = subset(
        &shares,
        &[(P1, 2), (P2, 1), (P3, 2), (J, 2), (A, 2), (C, 1), (N, 4)],
    );
    assert_eq!(
        reconstruct(&structure, &short_p1).unwrap_err(),
        Error::NotQualified
    );
    let short_n = subset(
        &shares,
        &[(P1, 3), (P2, 1), (P3, 2), (J, 1), (A, 2), (C, 1), (N, 3)],
    );
    assert_eq!(
        reconstruct(&structure, &short_n).unwrap_err(),
        Error::NotQualified
    );
    // Unused member slots beyond n are zero; P4 (absent) has none at all.
    assert_eq!(shares.value(MemberId::new(P2, 1).unwrap()), Scalar::ZERO);
    assert_eq!(shares.value(MemberId::new(P1, 7).unwrap()), Scalar::ZERO);
    assert_eq!(shares.value(MemberId::new(P4, 0).unwrap()), Scalar::ZERO);
}
