//! The ballot-box life cycle against signed ledger objects: every event
//! carries real hybrid signatures and their verification tokens.
// Integration tests: outside the TCB. Assertions use unwrap/expect and
// indexing, and counts are computed with plain arithmetic, so these lints
// are relaxed for this file only (CONSTITUTION.md §1.1).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::too_many_lines,
    clippy::panic
)]

mod common;

use common::{
    By, CLOSE_BUCKET, SEAL, WITNESSES, attest, audit, audit_body, authorization, batch_body,
    batch_event, box_id, challenge_body, close_body, close_parts, counts, device_key, election,
    fallback, fallback_body, handoff, handoff_parts, handoffs, issuance, issuance_body, late_batch,
    late_close, leak, manual_close, misregistered, module, module_list, modules, opened_body,
    opening, other_box, other_election, record_body, roster, seal_change, signed_close,
    signed_close_with, spec, station, today, with_device, witnessed, witnessed_with,
};
use ityv_crypto::HybridSigningKey;
use ityv_encoding::{
    BoxClose, CustodyRoute, EnvelopeIssuance, EventRole, FallbackKind, GenesisBox, HYBRID_VK_LEN,
    Hash512, ModuleIds, RouteId, SealChangeReason, SignerRole, StationId,
};
use ityv_state::{
    BallotBox, BallotMark, CloseTokens, Closed, Error, HoldReason, HoldSet, Observed, Open,
    Profile, Provisioned, PublicBoard, Rla, Signed, Transition,
};

fn provisioned(profile: Profile) -> BallotBox<'static, Provisioned> {
    let auth = authorization();
    let cap = auth.grant::<PublicBoard>(today()).unwrap();
    BallotBox::provision(spec(profile), &cap).unwrap()
}

fn open(profile: Profile) -> BallotBox<'static, Open> {
    provisioned(profile)
        .open(leak(opening(modules())))
        .into_result()
        .unwrap()
}

/// Records `n` records and `c` challenges and attests the records.
fn fill(open: &mut BallotBox<'static, Open>, n: u16, c: u16) {
    let auth = authorization();
    let cap = auth.grant::<BallotMark>(today()).unwrap();
    for _ in 0..n {
        let state = open
            .record(&cap, &record_body(box_id(), b"S-1", module_list()))
            .unwrap();
        assert!(!state.is_test());
    }
    for _ in 0..c {
        open.challenge(&challenge_body(box_id())).unwrap();
    }
    if n > 0 {
        open.batch(&batch_body(box_id(), n)).unwrap();
    }
}

fn closed() -> BallotBox<'static, Closed<'static>> {
    let mut b = open(Profile::InPerson);
    fill(&mut b, 10, 1);
    let close = leak(signed_close(&close_parts(counts(10, 10, 1), module_list())));
    b.close(&close.close, &close.tokens(), None)
        .into_result()
        .unwrap()
}

#[test]
fn clean_life_cycle() {
    let b = provisioned(Profile::InPerson);
    assert!(b.holds().is_empty());
    assert_eq!(b.election_id(), election());
    assert_eq!(b.box_id(), box_id());
    assert_eq!(b.profile(), Profile::InPerson);
    assert!(b.modules().is_empty());
    assert_eq!(b.observed(), Observed::ZERO);
    let mut b = b.open(leak(opening(modules()))).into_result().unwrap();
    assert_eq!(b.modules(), &modules());
    assert!(b.holds().is_empty());
    fill(&mut b, 10, 1);
    assert_eq!(
        b.observed(),
        Observed {
            records: 10,
            challenged: 1,
            attested: 10
        }
    );
    assert!(!b.fallback_declared());
    let close = leak(signed_close(&close_parts(counts(10, 10, 1), module_list())));
    let mut b = b
        .close(&close.close, &close.tokens(), None)
        .into_result()
        .unwrap();
    assert!(b.holds().is_empty(), "{:?}", b.holds());
    assert!(!b.is_manual());
    assert_eq!(b.counts(), &counts(10, 10, 1));
    assert_eq!(b.open_batches(), 0);
    assert_eq!(b.closed_at().get(), CLOSE_BUCKET);
    for h in handoffs(10) {
        b.handoff(leak(h)).unwrap();
    }
    assert!(b.custody().is_complete());
    assert_eq!(b.custody().handoffs(), 2);
    let counted = b.count(&audit(0, 0)).into_result().unwrap();
    assert!(counted.holds().is_empty());
    assert!(!counted.is_manual());
    assert_eq!(counted.counts(), &counts(10, 10, 1));
    assert!(counted.custody().is_complete());
    let auth = authorization();
    let rla = auth.grant::<Rla>(today()).unwrap();
    let audited = counted.audited(&rla).into_result().unwrap();
    assert!(audited.holds().is_empty());
    assert_eq!(audited.counts(), &counts(10, 10, 1));
}

#[test]
fn provisioning_refusals() {
    let auth = authorization();
    let cap = auth.grant::<PublicBoard>(today()).unwrap();
    let mut s = spec(Profile::InPerson);
    s.election_id = other_election();
    assert_eq!(BallotBox::provision(s, &cap).unwrap_err(), Error::Mismatch);
    let mut s = spec(Profile::InPerson);
    s.route = &s.route[..1];
    assert_eq!(
        BallotBox::provision(s, &cap).unwrap_err(),
        Error::CustodyRoute
    );
    let mut s = spec(Profile::InPerson);
    s.route = &s.route[..2];
    assert!(BallotBox::provision(s, &cap).is_ok());
}

#[test]
fn spec_matches_the_genesis() {
    let s = spec(Profile::Absentee);
    let mut key = [0u8; HYBRID_VK_LEN];
    let vk = device_key().verifying_key();
    key[..ityv_crypto::sig::MLDSA87_VK_LEN].copy_from_slice(vk.mldsa87());
    key[ityv_crypto::sig::MLDSA87_VK_LEN..].copy_from_slice(vk.ed25519());
    let key = leak(key);
    let registered = ModuleIds::new(s.registered_modules).unwrap();
    let entry = GenesisBox {
        box_id: box_id(),
        station_id: station(),
        ballot_style_id: ityv_encoding::BallotStyleId::new(b"S-1").unwrap(),
        profile: ityv_encoding::CaptureProfile::Absentee,
        route_id: RouteId::new(b"R-1").unwrap(),
        device_key: key,
        modules: registered,
    };
    let route = CustodyRoute::new(RouteId::new(b"R-1").unwrap(), false, s.route).unwrap();
    assert_eq!(s.check_genesis(&entry, &route), Ok(()));
    let differs = |e: GenesisBox<'static>, r: &CustodyRoute<'static>| {
        assert_eq!(s.check_genesis(&e, r), Err(Error::Mismatch));
    };
    differs(
        GenesisBox {
            box_id: other_box(),
            ..entry
        },
        &route,
    );
    differs(
        GenesisBox {
            station_id: StationId::new(b"ST-2").unwrap(),
            ..entry
        },
        &route,
    );
    differs(
        GenesisBox {
            profile: ityv_encoding::CaptureProfile::InPerson,
            ..entry
        },
        &route,
    );
    for index in [0, HYBRID_VK_LEN - 1] {
        let mut other = *key;
        other[index] ^= 1;
        differs(
            GenesisBox {
                device_key: leak(other),
                ..entry
            },
            &route,
        );
    }
    differs(
        GenesisBox {
            modules: modules(),
            ..entry
        },
        &route,
    );
    let mut swapped = registered;
    swapped = ModuleIds::new(&[module(b"MOD-P1"), module(b"MOD-P2"), module(b"MOD-P4")])
        .unwrap_or(swapped);
    differs(
        GenesisBox {
            modules: swapped,
            ..entry
        },
        &route,
    );
    let other_route = CustodyRoute::new(RouteId::new(b"R-2").unwrap(), false, s.route).unwrap();
    differs(entry, &other_route);
    let short = CustodyRoute::new(RouteId::new(b"R-1").unwrap(), false, &s.route[..2]).unwrap();
    differs(entry, &short);
    let reordered = CustodyRoute::new(
        RouteId::new(b"R-1").unwrap(),
        false,
        &[s.route[0], s.route[2], s.route[1]],
    )
    .unwrap();
    differs(entry, &reordered);
}

fn refused_opening(o: Signed<'static>) -> Error {
    match provisioned(Profile::InPerson).open(leak(o)) {
        Transition::Refused(b, error) => {
            // The refused box is unchanged and can still open.
            assert!(b.open(leak(opening(modules()))).into_result().is_ok());
            error
        }
        Transition::Done(_) => panic!("opened"),
    }
}

#[test]
fn opening_refusals_and_holds() {
    let all = with_device(&WITNESSES);
    let body = |b, m, s, i| opened_body(b, m, s, i);
    assert_eq!(
        refused_opening(witnessed(body(other_box(), modules(), true, 0), &all)),
        Error::Mismatch
    );
    let unregistered = ModuleIds::new(&[module(b"MOD-P1"), module(b"MOD-X")]).unwrap();
    assert_eq!(
        refused_opening(witnessed(body(box_id(), unregistered, true, 0), &all)),
        Error::NotRegistered
    );
    assert_eq!(
        refused_opening(witnessed(
            body(box_id(), modules(), true, 0),
            &with_device(&misregistered())
        )),
        Error::NotRegistered
    );
    // The device must sign, with the box's own key.
    let stranger = leak(HybridSigningKey::from_seeds([40; 32], [41; 32]));
    let mut forged = std::vec![By::Other(b"BOX-001", EventRole::Device, b"NEC", stranger)];
    forged.extend_from_slice(&WITNESSES);
    assert_eq!(
        refused_opening(witnessed(body(box_id(), modules(), true, 0), &forged)),
        Error::SignatureSigner
    );
    // Another event schema is not an opening.
    assert_eq!(
        refused_opening(fallback(FallbackKind::Declared)),
        Error::Decode
    );
    // A missing token.
    let good = opening(modules());
    let short = Signed {
        event: good.event,
        tokens: &good.tokens[..4],
    };
    assert_eq!(refused_opening(short), Error::Unverified);
    // Swapped tokens: each token belongs to another signer.
    let mut swapped = good.tokens.to_vec();
    swapped.swap(0, 1);
    let swapped = Signed {
        event: good.event,
        tokens: common::leak_slice(swapped),
    };
    assert_eq!(refused_opening(swapped), Error::SignatureObject);
    // Discrepancies open under hold.
    let b = provisioned(Profile::InPerson)
        .open(leak(witnessed(body(box_id(), modules(), false, 0), &all)))
        .into_result()
        .unwrap();
    assert_eq!(b.holds(), HoldSet::empty().with(HoldReason::SealMismatch));
    let b = provisioned(Profile::InPerson)
        .open(leak(witnessed(body(box_id(), modules(), true, 1), &all)))
        .into_result()
        .unwrap();
    assert_eq!(b.holds(), HoldSet::empty().with(HoldReason::OpeningNonZero));
    // No modules before stage 2.
    let b = provisioned(Profile::InPerson)
        .open(leak(witnessed(
            body(box_id(), ModuleIds::EMPTY, true, 0),
            &all,
        )))
        .into_result()
        .unwrap();
    assert!(b.modules().is_empty());
}

#[test]
fn shared_key_halves_count_once() {
    // Two observers whose keys share the Ed25519 half are one signer.
    let a = leak(HybridSigningKey::from_seeds([60; 32], [61; 32]));
    let b = leak(HybridSigningKey::from_seeds([62; 32], [61; 32]));
    let mut s = spec(Profile::InPerson);
    let mut people = roster().to_vec();
    people.push(ityv_state::RosterEntry {
        signer_id: ityv_encoding::SignerId::new(b"obs-x").unwrap(),
        role: ityv_encoding::RosterRole::Observer,
        org_id: ityv_encoding::OrgId::new(b"PARTY-X").unwrap(),
        key: leak(a.verifying_key()),
    });
    people.push(ityv_state::RosterEntry {
        signer_id: ityv_encoding::SignerId::new(b"obs-y").unwrap(),
        role: ityv_encoding::RosterRole::Observer,
        org_id: ityv_encoding::OrgId::new(b"PARTY-Y").unwrap(),
        key: leak(b.verifying_key()),
    });
    s.roster = common::leak_slice(people);
    let auth = authorization();
    let cap = auth.grant::<PublicBoard>(today()).unwrap();
    let signers = [
        By::Device,
        By::Person(b"clerk-1", EventRole::Clerk),
        By::Person(b"clerk-2", EventRole::Clerk),
        By::Other(b"obs-x", EventRole::Observer, b"PARTY-X", a),
        By::Other(b"obs-y", EventRole::Observer, b"PARTY-Y", b),
    ];
    let event = leak(witnessed(
        opened_body(box_id(), modules(), true, 0),
        &signers,
    ));
    let refused = BallotBox::provision(s, &cap).unwrap().open(event);
    assert_eq!(refused.error(), Some(Error::SignatureSigner));
}

#[test]
fn record_refusals() {
    let mut b = open(Profile::InPerson);
    let auth = authorization();
    let cap = auth.grant::<BallotMark>(today()).unwrap();
    assert_eq!(
        b.record(&cap, &record_body(other_box(), b"S-1", module_list())),
        Err(Error::Mismatch)
    );
    let stray = [module(b"MOD-P1"), module(b"MOD-P3")];
    assert_eq!(
        b.record(&cap, &record_body(box_id(), b"S-1", &stray)),
        Err(Error::NotRegistered)
    );
    let test = b
        .record(&cap, &record_body(box_id(), b"TEST-1", module_list()))
        .unwrap();
    assert!(test.is_test());
    assert_eq!(b.observed().records, 1);
    // A capability of another election.
    let other = common::signed_authorization_for(other_election());
    let foreign = other.grant::<BallotMark>(today()).unwrap();
    assert_eq!(
        b.record(&foreign, &record_body(box_id(), b"S-1", module_list())),
        Err(Error::Mismatch)
    );
    assert_eq!(
        b.challenge(&challenge_body(other_box())),
        Err(Error::Mismatch)
    );
    assert_eq!(b.batch(&batch_body(other_box(), 1)), Err(Error::Mismatch));
    assert_eq!(b.observed().records, 1);
    assert_eq!(b.observed().challenged, 0);
    assert_eq!(b.observed().attested, 0);
    let mut scan = open(Profile::ReceiptScan);
    assert_eq!(
        scan.challenge(&challenge_body(box_id())),
        Err(Error::Profile)
    );
}

#[test]
fn fallback_life() {
    let b = open(Profile::InPerson);
    let weak = leak(witnessed(
        fallback_body(box_id(), FallbackKind::Declared),
        &misregistered(),
    ));
    let b = match b.declare_fallback(weak) {
        Transition::Refused(b, error) => {
            assert_eq!(error, Error::NotRegistered);
            b
        }
        Transition::Done(_) => panic!(),
    };
    let elsewhere = leak(witnessed(
        fallback_body(other_box(), FallbackKind::Declared),
        &WITNESSES,
    ));
    let b = match b.declare_fallback(elsewhere) {
        Transition::Refused(b, error) => {
            assert_eq!(error, Error::Mismatch);
            b
        }
        Transition::Done(_) => panic!(),
    };
    // An end is not a declaration.
    let b = match b.declare_fallback(leak(fallback(FallbackKind::Ended))) {
        Transition::Refused(b, error) => {
            assert_eq!(error, Error::Mismatch);
            b
        }
        Transition::Done(_) => panic!(),
    };
    let mut f = b
        .declare_fallback(leak(fallback(FallbackKind::Declared)))
        .into_result()
        .unwrap();
    assert!(f.fallback_declared());
    assert!(f.holds().is_empty());
    f.batch(&batch_body(box_id(), 2)).unwrap();
    assert_eq!(f.observed().attested, 2);
    assert_eq!(f.batch(&batch_body(other_box(), 1)), Err(Error::Mismatch));
    let weak_end = leak(witnessed(
        fallback_body(box_id(), FallbackKind::Ended),
        &misregistered(),
    ));
    let f = match f.end_fallback(weak_end) {
        Transition::Refused(f, error) => {
            assert_eq!(error, Error::NotRegistered);
            f
        }
        Transition::Done(_) => panic!(),
    };
    let f = match f.end_fallback(leak(fallback(FallbackKind::Declared))) {
        Transition::Refused(f, error) => {
            assert_eq!(error, Error::Mismatch);
            f
        }
        Transition::Done(_) => panic!(),
    };
    let mut b = f
        .end_fallback(leak(fallback(FallbackKind::Ended)))
        .into_result()
        .unwrap();
    assert!(b.fallback_declared());
    let auth = authorization();
    let cap = auth.grant::<BallotMark>(today()).unwrap();
    b.record(&cap, &record_body(box_id(), b"S-1", module_list()))
        .unwrap();
    b.record(&cap, &record_body(box_id(), b"S-1", module_list()))
        .unwrap();
    // Two records, three ballots through the emergency slot.
    let mut c = counts(5, 2, 0);
    c.without_record = 3;
    let close = leak(signed_close(&close_parts(c, module_list())));
    let closed = b
        .close(&close.close, &close.tokens(), None)
        .into_result()
        .unwrap();
    assert!(closed.holds().is_empty(), "{:?}", closed.holds());
}

#[test]
fn fallback_takes_records_uploaded_late() {
    let b = open(Profile::InPerson);
    let mut f = b
        .declare_fallback(leak(fallback(FallbackKind::Declared)))
        .into_result()
        .unwrap();
    let auth = authorization();
    let cap = auth.grant::<BallotMark>(today()).unwrap();
    let state = f
        .record(&cap, &record_body(box_id(), b"TEST-9", module_list()))
        .unwrap();
    assert!(state.is_test());
    f.challenge(&challenge_body(box_id())).unwrap();
    assert_eq!(
        f.record(&cap, &record_body(other_box(), b"S-1", module_list())),
        Err(Error::Mismatch)
    );
    assert_eq!(
        f.challenge(&challenge_body(other_box())),
        Err(Error::Mismatch)
    );
    assert_eq!(
        f.observed(),
        Observed {
            records: 1,
            challenged: 1,
            attested: 0
        }
    );
    let scan = open(Profile::ReceiptScan);
    let mut f = scan
        .declare_fallback(leak(fallback(FallbackKind::Declared)))
        .into_result()
        .unwrap();
    assert_eq!(f.challenge(&challenge_body(box_id())), Err(Error::Profile));
}

#[test]
fn emergency_ballots_without_fallback_hold() {
    let mut b = open(Profile::InPerson);
    fill(&mut b, 2, 0);
    let mut c = counts(5, 2, 0);
    c.without_record = 3;
    let close = leak(signed_close(&close_parts(c, module_list())));
    let closed = b
        .close(&close.close, &close.tokens(), None)
        .into_result()
        .unwrap();
    assert_eq!(
        closed.holds(),
        HoldSet::empty().with(HoldReason::FallbackUndeclared)
    );
}

#[test]
fn close_in_fallback() {
    let mut b = open(Profile::InPerson);
    fill(&mut b, 2, 0);
    let f = b
        .declare_fallback(leak(fallback(FallbackKind::Declared)))
        .into_result()
        .unwrap();
    let mut c = counts(4, 2, 0);
    c.without_record = 2;
    let other_modules = common::leak_slice(std::vec![module(b"MOD-P1"), module(b"MOD-P3")]);
    let manual = leak(manual_close(&close_parts(c, other_modules)));
    let closed = f
        .close(&manual.close, &manual.tokens(), None)
        .into_result()
        .unwrap();
    assert_eq!(
        closed.holds(),
        HoldSet::empty()
            .with(HoldReason::ModuleCounterGap)
            .with(HoldReason::ManualClose)
    );
    let mut b = open(Profile::InPerson);
    fill(&mut b, 2, 0);
    let f = b
        .declare_fallback(leak(fallback(FallbackKind::Declared)))
        .into_result()
        .unwrap();
    let close = leak(signed_close(&close_parts(c, module_list())));
    let wrong = leak(signed_close(&close_parts(counts(2, 2, 0), module_list())));
    // A device token for another close is refused and the box kept.
    let mixed = CloseTokens {
        device: wrong.device.as_ref(),
        humans: close.humans,
    };
    let f = match f.close(&close.close, &mixed, None) {
        Transition::Refused(f, error) => {
            assert_eq!(error, Error::SignatureObject);
            f
        }
        Transition::Done(_) => panic!(),
    };
    let closed = f
        .close(&close.close, &close.tokens(), None)
        .into_result()
        .unwrap();
    assert!(closed.holds().is_empty(), "{:?}", closed.holds());
}

fn refused_close(close: &BoxClose<'static>, tokens: &CloseTokens<'static>) -> Error {
    refused_close_with(close, tokens, None)
}

fn refused_close_with(
    close: &BoxClose<'static>,
    tokens: &CloseTokens<'static>,
    issuance: Option<&Signed<'static>>,
) -> Error {
    let mut b = open(Profile::InPerson);
    fill(&mut b, 10, 1);
    match b.close(close, tokens, issuance) {
        Transition::Refused(b, error) => {
            assert_eq!(b.observed().records, 10);
            error
        }
        Transition::Done(_) => panic!("closed"),
    }
}

#[test]
fn close_signature_binding() {
    let parts = close_parts(counts(10, 10, 1), module_list());
    let good = leak(signed_close(&parts));
    let humans = good.humans;
    let tokens = |device| CloseTokens { device, humans };
    // A signature without a token.
    assert_eq!(refused_close(&good.close, &tokens(None)), Error::Unverified);
    // A device token for a manual close.
    let manual = leak(manual_close(&parts));
    assert_eq!(
        refused_close(
            &manual.close,
            &CloseTokens {
                device: good.device.as_ref(),
                humans: manual.humans
            }
        ),
        Error::SignatureObject
    );
    // A token for another object.
    let mut other = parts;
    other.journal_head = Hash512([0x77; 64]);
    let other = leak(signed_close(&other));
    assert_eq!(
        refused_close(&good.close, &tokens(other.device.as_ref())),
        Error::SignatureObject
    );
    // A token with another purpose (the humans too sign the late purpose).
    let late = leak(late_close(&parts));
    assert_eq!(
        refused_close(&late.close, &late.tokens()),
        Error::SignatureObject
    );
    // Only the device signed under another purpose; the humans signed
    // `box-close`, so the device check alone must refuse.
    let body = close_body(&parts);
    let (late_sig, late_token) = common::signed_by(device_key(), b"late-box-close", body);
    let (late_atts, box_humans) = attest(
        body,
        b"box-close",
        &[
            (b"clerk-1", SignerRole::Clerk),
            (b"clerk-2", SignerRole::Clerk),
            (b"obs-a", SignerRole::Observer),
            (b"obs-b", SignerRole::Observer),
        ],
    );
    let mixed = leak(BoxClose::new(body, Some(late_sig), late_atts).unwrap());
    assert_eq!(
        refused_close(
            mixed,
            &CloseTokens {
                device: Some(leak(late_token)),
                humans: box_humans
            }
        ),
        Error::SignatureObject
    );
    // A device token from another key.
    let stranger = leak(HybridSigningKey::from_seeds([40; 32], [41; 32]));
    let forged = leak(signed_close_with(&parts, stranger, b"box-close"));
    assert_eq!(
        refused_close(&forged.close, &forged.tokens()),
        Error::SignatureSigner
    );
    // One half of the device signature altered: the ML-DSA half (first
    // byte) or the Ed25519 half (last byte).
    let attestations: std::vec::Vec<_> = good.close.attestations().collect();
    let good_bytes = good.close.device_sig().unwrap();
    for index in [0, ityv_encoding::HYBRID_SIG_LEN - 1] {
        let mut altered = *good_bytes;
        altered[index] ^= 1;
        let close =
            BoxClose::new(good.close.body_bytes(), Some(leak(altered)), &attestations).unwrap();
        assert_eq!(
            refused_close(leak(close), &good.tokens()),
            Error::SignatureObject
        );
    }
    // Human attestations need one token each, from the registered keys.
    assert_eq!(
        refused_close(
            &good.close,
            &CloseTokens {
                device: good.device.as_ref(),
                humans: &humans[..3]
            }
        ),
        Error::Unverified
    );
    let mut swapped = humans.to_vec();
    swapped.swap(0, 2);
    assert_eq!(
        refused_close(
            &good.close,
            &CloseTokens {
                device: good.device.as_ref(),
                humans: common::leak_slice(swapped)
            }
        ),
        Error::SignatureObject
    );
    // A human signature altered.
    let mut tampered = attestations.clone();
    let mut sig = *tampered[0].sig;
    sig[0] ^= 1;
    tampered[0].sig = leak(sig);
    let close =
        leak(BoxClose::new(good.close.body_bytes(), good.close.device_sig(), &tampered).unwrap());
    assert_eq!(refused_close(close, &good.tokens()), Error::SignatureObject);
    // Another box, another election.
    let mut elsewhere = parts;
    elsewhere.box_id = other_box();
    let elsewhere = leak(signed_close(&elsewhere));
    assert_eq!(
        refused_close(&elsewhere.close, &elsewhere.tokens()),
        Error::Mismatch
    );
    let mut elsewhere = parts;
    elsewhere.election_id = other_election();
    let elsewhere = leak(signed_close(&elsewhere));
    assert_eq!(
        refused_close(&elsewhere.close, &elsewhere.tokens()),
        Error::Mismatch
    );
    // Close signers must be registered: an observer of another
    // organisation than the roster says.
    let body = close_body(&parts);
    let (mut atts, toks) = {
        let (a, t) = attest(
            body,
            b"box-close",
            &[
                (b"clerk-1", SignerRole::Clerk),
                (b"clerk-2", SignerRole::Clerk),
                (b"obs-a", SignerRole::Observer),
                (b"obs-b", SignerRole::Observer),
            ],
        );
        (a.to_vec(), t)
    };
    atts[3].org_id = ityv_encoding::OrgId::new(b"PARTY-Z").unwrap();
    let unregistered = leak(BoxClose::new(body, None, &atts).unwrap());
    assert_eq!(
        refused_close(
            unregistered,
            &CloseTokens {
                device: None,
                humans: toks
            }
        ),
        Error::NotRegistered
    );
}

#[test]
fn close_holds() {
    let check = |c: ityv_encoding::CloseCounts| {
        let mut b = open(Profile::InPerson);
        fill(&mut b, 10, 1);
        let close = leak(signed_close(&close_parts(c, module_list())));
        b.close(&close.close, &close.tokens(), None)
            .into_result()
            .unwrap()
            .holds()
    };
    assert_eq!(
        check(counts(11, 10, 1)),
        HoldSet::empty().with(HoldReason::PaperRecordMismatch)
    );
    let mut c = counts(10, 10, 1);
    c.spoil_envelopes = 2;
    assert_eq!(
        check(c),
        HoldSet::empty().with(HoldReason::SpoilEnvelopeMismatch)
    );
    let mut c = counts(10, 10, 1);
    c.visits = 1;
    assert_eq!(check(c), HoldSet::empty().with(HoldReason::VisitBounds));
    // The ledger shows ten records; a close reporting nine holds.
    let reported = check(counts(9, 9, 1));
    assert!(reported.contains(HoldReason::ObservedCountMismatch));
    // A module counter with a gap.
    let mut b = open(Profile::InPerson);
    fill(&mut b, 10, 1);
    let mut parts = close_parts(counts(10, 10, 1), module_list());
    parts.module_counters = ityv_encoding::ModuleCounters::new(&[
        ityv_encoding::ModuleCounter {
            module_id: module(b"MOD-P1"),
            counter: 11,
        },
        ityv_encoding::ModuleCounter {
            module_id: module(b"MOD-P2"),
            counter: 12,
        },
    ])
    .unwrap();
    let close = leak(signed_close(&parts));
    let closed = b
        .close(&close.close, &close.tokens(), None)
        .into_result()
        .unwrap();
    assert_eq!(
        closed.holds(),
        HoldSet::empty().with(HoldReason::ModuleCounterGap)
    );
}

fn make_manual(
    parts: &ityv_encoding::BoxCloseParts<'static>,
) -> BallotBox<'static, Closed<'static>> {
    let mut b = open(Profile::InPerson);
    fill(&mut b, 10, 1);
    let manual = leak(manual_close(parts));
    b.close(&manual.close, &manual.tokens(), None)
        .into_result()
        .unwrap()
}

#[test]
fn manual_close_and_late_close() {
    let parts = close_parts(counts(10, 10, 1), module_list());
    let mut b = make_manual(&parts);
    assert!(b.is_manual());
    assert_eq!(b.holds(), HoldSet::empty().with(HoldReason::ManualClose));
    // A late close needs the device signature with its own purpose.
    let wrong_purpose = leak(signed_close(&parts));
    assert_eq!(
        b.late_close(&wrong_purpose.close, &wrong_purpose.tokens()),
        Err(Error::SignatureObject)
    );
    let late = leak(late_close(&parts));
    let no_device = leak(manual_close(&parts));
    assert_eq!(
        b.late_close(&no_device.close, &late.tokens()),
        Err(Error::LateClose)
    );
    assert_eq!(
        b.late_close(
            &late.close,
            &CloseTokens {
                device: None,
                humans: late.humans
            }
        ),
        Err(Error::Unverified)
    );
    let mut elsewhere = parts;
    elsewhere.box_id = other_box();
    let elsewhere = leak(late_close(&elsewhere));
    assert_eq!(
        b.late_close(&elsewhere.close, &elsewhere.tokens()),
        Err(Error::Mismatch)
    );
    let stranger = leak(HybridSigningKey::from_seeds([40; 32], [41; 32]));
    let forged = leak(signed_close_with(&parts, stranger, b"late-box-close"));
    assert_eq!(
        b.late_close(&forged.close, &forged.tokens()),
        Err(Error::SignatureSigner)
    );
    // After the 24-hour window.
    let mut too_late = parts;
    too_late.time_bucket = ityv_encoding::TimeBucket::new(CLOSE_BUCKET + 97);
    let too_late = leak(late_close(&too_late));
    assert_eq!(
        b.late_close(&too_late.close, &too_late.tokens()),
        Err(Error::LateWindow)
    );
    assert!(b.is_manual());
    let mut at_deadline = parts;
    at_deadline.time_bucket = ityv_encoding::TimeBucket::new(CLOSE_BUCKET + 96);
    let at_deadline = leak(late_close(&at_deadline));
    b.late_close(&at_deadline.close, &at_deadline.tokens())
        .unwrap();
    assert!(!b.is_manual());
    assert!(b.holds().is_empty());
    // Only once.
    assert_eq!(
        b.late_close(&late.close, &late.tokens()),
        Err(Error::LateClose)
    );

    // Human counts that differ keep the manual close's holds.
    for change in 0..4 {
        let mut b = make_manual(&parts);
        let mut c = counts(10, 10, 1);
        match change {
            0 => c.paper = 11,
            1 => c.envelopes = 1,
            2 => c.stickers = 1,
            _ => c.spoil_envelopes = 2,
        }
        let late = leak(late_close(&close_parts(c, module_list())));
        b.late_close(&late.close, &late.tokens()).unwrap();
        assert!(b.is_manual());
        assert!(b.holds().contains(HoldReason::ManualClose));
        assert!(b.holds().contains(HoldReason::LateCloseDiffers));
        assert_eq!(b.counts(), &counts(10, 10, 1));
    }

    // A manual close whose device counts were unknown: the late close's
    // verdict replaces them.
    let mut unknown = counts(10, 0, 0);
    unknown.attested = 0;
    unknown.visits = 0;
    unknown.spoil_envelopes = 1;
    let mut b = make_manual(&close_parts(unknown, module_list()));
    assert!(b.holds().contains(HoldReason::PaperRecordMismatch));
    let mut late_parts = parts;
    late_parts.open_batches = 1;
    late_parts.counts.attested = 10;
    let late = leak(late_close(&late_parts));
    b.late_close(&late.close, &late.tokens()).unwrap();
    assert_eq!(b.holds(), HoldSet::empty().with(HoldReason::OpenBatches));
    assert_eq!(b.open_batches(), 1);
    assert_eq!(b.counts(), &late_parts.counts);
}

#[test]
fn late_batch_resolves_open_batches() {
    let auth = authorization();
    let cap = auth.grant::<BallotMark>(today()).unwrap();
    let mut b = open(Profile::InPerson);
    for _ in 0..10 {
        b.record(&cap, &record_body(box_id(), b"S-1", module_list()))
            .unwrap();
    }
    b.batch(&batch_body(box_id(), 6)).unwrap();
    let mut c = counts(10, 10, 0);
    c.attested = 6;
    let mut parts = close_parts(c, module_list());
    parts.open_batches = 1;
    let close = leak(signed_close(&parts));
    let mut b = b
        .close(&close.close, &close.tokens(), None)
        .into_result()
        .unwrap();
    assert_eq!(b.holds(), HoldSet::empty().with(HoldReason::OpenBatches));
    let within = CLOSE_BUCKET + 10;
    let five = leak(batch_event(box_id(), 5, 1));
    assert_eq!(
        b.late_batch(five, leak(late_batch(five, within, &WITNESSES))),
        Err(Error::BatchExceedsRecords)
    );
    let foreign = leak(batch_event(other_box(), 1, 1));
    assert_eq!(
        b.late_batch(foreign, leak(late_batch(foreign, within, &WITNESSES))),
        Err(Error::Mismatch)
    );
    let two = leak(batch_event(box_id(), 2, 1));
    // The late close must name this batch.
    let other_two = leak(batch_event(box_id(), 2, 2));
    assert_eq!(
        b.late_batch(two, leak(late_batch(other_two, within, &WITNESSES))),
        Err(Error::Mismatch)
    );
    assert_eq!(
        b.late_batch(two, leak(late_batch(two, within, &misregistered()))),
        Err(Error::NotRegistered)
    );
    assert_eq!(
        b.late_batch(two, leak(late_batch(two, CLOSE_BUCKET + 97, &WITNESSES))),
        Err(Error::LateWindow)
    );
    assert_eq!(b.late_batch(two, leak(audit(0, 0))), Err(Error::Decode));
    b.late_batch(two, leak(late_batch(two, within, &WITNESSES)))
        .unwrap();
    assert_eq!(b.observed().attested, 8);
    assert!(b.holds().contains(HoldReason::OpenBatches));
    for h in handoffs(10) {
        b.handoff(leak(h)).unwrap();
    }
    // Counting may come before the late-close window ends.
    let mut counted = b.count(&audit(0, 0)).into_result().unwrap();
    assert!(counted.holds().contains(HoldReason::OpenBatches));
    let last = leak(batch_event(box_id(), 2, 3));
    counted
        .late_batch(last, leak(late_batch(last, CLOSE_BUCKET + 96, &WITNESSES)))
        .unwrap();
    assert!(counted.holds().is_empty(), "{:?}", counted.holds());
    let one = leak(batch_event(box_id(), 1, 4));
    assert_eq!(
        counted.late_batch(one, leak(late_batch(one, within, &WITNESSES))),
        Err(Error::BatchExceedsRecords)
    );
}

#[test]
fn late_close_after_counting() {
    let parts = close_parts(counts(10, 10, 1), module_list());
    let mut b = make_manual(&parts);
    for h in handoffs(10) {
        b.handoff(leak(h)).unwrap();
    }
    let mut counted = b.count(&audit(0, 0)).into_result().unwrap();
    assert!(counted.is_manual());
    let late = leak(late_close(&parts));
    counted.late_close(&late.close, &late.tokens()).unwrap();
    assert!(!counted.is_manual());
    assert!(counted.holds().is_empty());
}

#[test]
fn custody_signatures() {
    let first = handoff_parts(1, b"chief", b"officer", Hash512::ZERO, 10);
    let body = common::handoff_body(&first);
    let refused = |signed: Signed<'static>| {
        let mut b = closed();
        let error = b.handoff(leak(signed)).unwrap_err();
        assert_eq!(b.custody().handoffs(), 0);
        error
    };
    // Signed by someone other than the named sender.
    assert_eq!(
        refused(witnessed(
            body,
            &[
                By::Person(b"counter", EventRole::Sender),
                By::Person(b"officer", EventRole::Receiver)
            ]
        )),
        Error::NotRegistered
    );
    // The named sender with a key that is not the registered one.
    let stranger = leak(HybridSigningKey::from_seeds([42; 32], [43; 32]));
    assert_eq!(
        refused(witnessed(
            body,
            &[
                By::Other(b"chief", EventRole::Sender, b"STATION", stranger),
                By::Person(b"officer", EventRole::Receiver)
            ]
        )),
        Error::SignatureSigner
    );
    // The named sender with the right key, but under another organisation
    // than the body names.
    assert_eq!(
        refused(witnessed(
            body,
            &[
                By::Other(
                    b"chief",
                    EventRole::Sender,
                    b"POLICE",
                    common::person_key(b"chief")
                ),
                By::Person(b"officer", EventRole::Receiver)
            ]
        )),
        Error::NotRegistered
    );
    // An observer is not a custody party.
    let observer = handoff_parts(1, b"obs-a", b"officer", Hash512::ZERO, 10);
    assert_eq!(refused(handoff(&observer)), Error::NotRegistered);
    // Wrong purpose.
    assert_eq!(
        refused(witnessed_with(
            body,
            &[
                By::Person(b"chief", EventRole::Sender),
                By::Person(b"officer", EventRole::Receiver)
            ],
            b"seal-change"
        )),
        Error::SignatureObject
    );
    // Not a handoff.
    assert_eq!(refused(audit(0, 0)), Error::Decode);
    // Another box.
    let mut elsewhere = first;
    elsewhere.box_id = other_box();
    assert_eq!(refused(handoff(&elsewhere)), Error::Mismatch);
    // The chain links by the object hash of the previous body.
    let mut b = closed();
    b.handoff(leak(handoff(&first))).unwrap();
    let unlinked = handoff_parts(2, b"officer", b"counter", Hash512([1; 64]), 10);
    assert_eq!(
        b.handoff(leak(handoff(&unlinked))),
        Err(Error::CustodyPrevious)
    );
    let linked = handoff_parts(
        2,
        b"officer",
        b"counter",
        ityv_crypto::hash::object_hash(body),
        10,
    );
    b.handoff(leak(handoff(&linked))).unwrap();
    assert!(b.custody().is_complete());
}

#[test]
fn custody_and_counting_holds() {
    let mut b = closed();
    let first = handoff_parts(1, b"chief", b"officer", Hash512::ZERO, 9);
    b.handoff(leak(handoff(&first))).unwrap();
    assert_eq!(
        b.holds(),
        HoldSet::empty().with(HoldReason::CustodyCountMismatch)
    );
    assert_eq!(
        b.seal_change(leak(witnessed(
            common::issuance_body(election(), station(), None),
            &WITNESSES
        ))),
        Err(Error::Decode)
    );
    let weak = leak(witnessed(
        seal_change(SealChangeReason::Inspection, SEAL, Hash512([0x5f; 64]))
            .event
            .body_bytes(),
        &misregistered(),
    ));
    assert_eq!(b.seal_change(weak), Err(Error::NotRegistered));
    b.seal_change(leak(seal_change(
        SealChangeReason::Inspection,
        SEAL,
        Hash512([0x5f; 64]),
    )))
    .unwrap();
    let mut second = handoff_parts(
        2,
        b"officer",
        b"counter",
        ityv_crypto::hash::object_hash(common::handoff_body(&first)),
        10,
    );
    second.seal_digest = Hash512([0x5f; 64]);
    b.handoff(leak(handoff(&second))).unwrap();
    assert_eq!(
        b.holds(),
        HoldSet::empty().with(HoldReason::CustodyCountMismatch)
    );
    assert_eq!(b.custody().seal(), &Hash512([0x5f; 64]));
    // A seal found broken holds.
    let mut b = closed();
    b.seal_change(leak(seal_change(
        SealChangeReason::Broken,
        SEAL,
        Hash512([0x60; 64]),
    )))
    .unwrap();
    assert_eq!(b.holds(), HoldSet::empty().with(HoldReason::SealBroken));

    // Counting without a complete chain, with imprint findings.
    for (unimprinted, duplicates) in [(1, 0), (0, 1)] {
        let b = closed();
        let counted = b
            .count(&audit(unimprinted, duplicates))
            .into_result()
            .unwrap();
        assert_eq!(
            counted.holds(),
            HoldSet::empty()
                .with(HoldReason::ImprintAudit)
                .with(HoldReason::CustodyIncomplete)
        );
    }
    let b = closed();
    let wrong = witnessed(audit_body(other_box(), 0, 0), &WITNESSES);
    let b = match b.count(&wrong) {
        Transition::Refused(b, error) => {
            assert_eq!(error, Error::Mismatch);
            b
        }
        Transition::Done(_) => panic!(),
    };
    let weak = witnessed(audit_body(box_id(), 0, 0), &misregistered());
    let refused = b.count(&weak);
    assert_eq!(refused.error(), Some(Error::NotRegistered));
    let b = match refused {
        Transition::Refused(b, _) => b,
        Transition::Done(_) => panic!(),
    };
    let not_audit = b.count(&fallback(FallbackKind::Declared));
    assert_eq!(not_audit.error(), Some(Error::Decode));
    let b = match not_audit {
        Transition::Refused(b, _) => b,
        Transition::Done(_) => panic!(),
    };
    let counted = b.count(&audit(0, 0));
    assert_eq!(counted.error(), None);
    let counted = counted.into_result().unwrap();
    // Auditing needs the RLA capability of this election.
    let other = common::signed_authorization_for(other_election());
    let foreign = other.grant::<Rla>(today()).unwrap();
    let refused = counted.audited(&foreign);
    assert_eq!(refused.error(), Some(Error::Mismatch));
    let counted = match refused {
        Transition::Refused(counted, _) => counted,
        Transition::Done(_) => panic!(),
    };
    // Holds survive the audit.
    assert_eq!(
        counted.holds(),
        HoldSet::empty().with(HoldReason::CustodyIncomplete)
    );
    let auth = authorization();
    let rla = auth.grant::<Rla>(today()).unwrap();
    let audited = counted.audited(&rla).into_result().unwrap();
    assert_eq!(
        audited.holds(),
        HoldSet::empty().with(HoldReason::CustodyIncomplete)
    );
}

#[test]
fn absentee_box() {
    let envelopes = |issued, returned_empty| {
        Some(EnvelopeIssuance {
            issued,
            returned_empty,
        })
    };
    let mut c = counts(0, 10, 0);
    c.visits = 4;
    c.envelopes = 4;
    c.stickers = 4;
    let close = leak(signed_close(&close_parts(c, module_list())));
    let make = || {
        let mut b = open(Profile::Absentee);
        let auth = authorization();
        let cap = auth.grant::<BallotMark>(today()).unwrap();
        for _ in 0..10 {
            let r = b
                .record(&cap, &record_body(box_id(), b"S-1", module_list()))
                .unwrap();
            assert_eq!(r.profile(), Profile::Absentee);
        }
        b.batch(&batch_body(box_id(), 10)).unwrap();
        b
    };
    let good = leak(issuance(envelopes(5, 1), &WITNESSES));
    let closed = make()
        .close(&close.close, &close.tokens(), Some(good))
        .into_result()
        .unwrap();
    assert!(closed.holds().is_empty(), "{:?}", closed.holds());
    // The custody chain carries the envelope count.
    let mut b = closed;
    let [first, _] = handoffs(4);
    b.handoff(leak(first)).unwrap();
    assert!(b.holds().is_empty());
    let short = leak(issuance(envelopes(5, 0), &WITNESSES));
    let closed = make()
        .close(&close.close, &close.tokens(), Some(short))
        .into_result()
        .unwrap();
    assert_eq!(
        closed.holds(),
        HoldSet::empty().with(HoldReason::EnvelopeMismatch)
    );
    let closed = make()
        .close(&close.close, &close.tokens(), None)
        .into_result()
        .unwrap();
    assert_eq!(
        closed.holds(),
        HoldSet::empty().with(HoldReason::IssuanceMissing)
    );
    let weak = leak(issuance(envelopes(5, 1), &misregistered()));
    assert_eq!(
        make()
            .close(&close.close, &close.tokens(), Some(weak))
            .error(),
        Some(Error::NotRegistered)
    );
    for (e, s) in [
        (other_election(), station()),
        (election(), StationId::new(b"ST-2").unwrap()),
    ] {
        let foreign = leak(witnessed(issuance_body(e, s, envelopes(5, 1)), &WITNESSES));
        assert_eq!(
            make()
                .close(&close.close, &close.tokens(), Some(foreign))
                .error(),
            Some(Error::Mismatch)
        );
    }
    assert_eq!(
        make()
            .close(&close.close, &close.tokens(), Some(leak(audit(0, 0))))
            .error(),
        Some(Error::Decode)
    );
    let _ = refused_close_with;
}

#[test]
fn transition_helpers() {
    let t: Transition<u8, u16> = Transition::Done(7);
    assert_eq!(t.error(), None);
    assert_eq!(t.into_result(), Ok(7));
    let t: Transition<u8, u16> = Transition::Refused(1, Error::Mismatch);
    assert_eq!(t.error(), Some(Error::Mismatch));
    assert_eq!(t.into_result(), Err(Error::Mismatch));
    let _ = roster();
}
