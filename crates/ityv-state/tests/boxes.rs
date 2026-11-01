//! The ballot-box life cycle against signed ledger objects.
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
    SEAL, authorization, batch_body, box_id, challenge_body, close_parts, counts, device_key,
    election, leak, leak_slice, manual_close, module, modules, org, other_box, other_election,
    record_body, roster, signed_close, signed_close_with, spec, today, weak_witnesses, witnesses,
};
use ityv_crypto::HybridSigningKey;
use ityv_encoding::{BoxClose, Hash512, ModuleId, SignerId, StationId, TimeBucket};
use ityv_state::{
    Actor, BallotBox, BallotMark, BoxOpening, Closed, CustodyHandoff, Error, FallbackEvent,
    HoldReason, HoldSet, ImprintAudit, LateBatchClose, Observed, Open, PhysicalCounts, Profile,
    Provisioned, PublicBoard, ReasonCode, Rla, SealChange, Transition,
};

fn provisioned(profile: Profile) -> BallotBox<'static, Provisioned> {
    let auth = authorization();
    let cap = auth.grant::<PublicBoard>(today()).unwrap();
    BallotBox::provision(spec(profile), &cap).unwrap()
}

fn opening(modules: &'static [ModuleId<'static>]) -> BoxOpening<'static> {
    BoxOpening {
        election_id: election(),
        box_id: box_id(),
        modules,
        seals_match: true,
        initial_count: 0,
        witnesses: witnesses(),
    }
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
            .record(&cap, &record_body(box_id(), b"S-1", modules()))
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

const PHYSICAL: PhysicalCounts = PhysicalCounts { spoil_envelopes: 1 };

fn closed() -> BallotBox<'static, Closed<'static>> {
    let mut b = open(Profile::InPerson);
    fill(&mut b, 10, 1);
    let close = leak(signed_close(&close_parts(counts(10, 10, 1), modules())));
    b.close(&close.close, Some(&close.token), PHYSICAL, None)
        .into_result()
        .unwrap()
}

fn actor(id: &'static [u8], name: &'static [u8]) -> Actor<'static> {
    Actor {
        id: SignerId::new(id).unwrap(),
        org: org(name),
    }
}

fn handoffs(count: u64) -> [CustodyHandoff<'static>; 2] {
    let first = CustodyHandoff {
        election_id: election(),
        box_id: box_id(),
        index: 1,
        from: actor(b"clerk-1", b"STATION"),
        to: actor(b"officer", b"POLICE"),
        hash: Hash512([1; 64]),
        previous: Hash512::ZERO,
        seal_digest: SEAL,
        paper_count: count,
        time_bucket: TimeBucket::new(510),
        sender_signed: true,
        receiver_signed: true,
    };
    let second = CustodyHandoff {
        index: 2,
        from: actor(b"officer", b"POLICE"),
        to: actor(b"counter", b"CENTRE"),
        hash: Hash512([2; 64]),
        previous: Hash512([1; 64]),
        ..first
    };
    [first, second]
}

fn audit(unimprinted: u64, duplicates: u64) -> ImprintAudit<'static> {
    ImprintAudit {
        election_id: election(),
        box_id: box_id(),
        unimprinted,
        duplicate_cast_ids: duplicates,
        witnesses: witnesses(),
    }
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
    let mut b = b.open(&opening(modules())).into_result().unwrap();
    assert_eq!(b.modules(), modules());
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
    let close = signed_close(&close_parts(counts(10, 10, 1), modules()));
    let mut b = b
        .close(&close.close, Some(&close.token), PHYSICAL, None)
        .into_result()
        .unwrap();
    assert!(b.holds().is_empty(), "{:?}", b.holds());
    assert!(!b.is_manual());
    assert_eq!(b.counts(), &counts(10, 10, 1));
    assert_eq!(b.open_batches(), 0);
    for h in handoffs(10) {
        b.handoff(&h).unwrap();
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

fn refused_opening(o: BoxOpening<'static>) -> Error {
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
    let mut o = opening(modules());
    o.box_id = other_box();
    assert_eq!(refused_opening(o), Error::Mismatch);
    let mut o = opening(modules());
    o.election_id = other_election();
    assert_eq!(refused_opening(o), Error::Mismatch);
    let unregistered = leak_slice(std::vec![module(b"MOD-P1"), module(b"MOD-X")]);
    assert_eq!(refused_opening(opening(unregistered)), Error::NotRegistered);
    let repeated = leak_slice(std::vec![module(b"MOD-P1"), module(b"MOD-P1")]);
    assert_eq!(refused_opening(opening(repeated)), Error::Duplicate);
    let eight = leak_slice(std::vec![module(b"MOD-P1"); 8]);
    assert_eq!(refused_opening(opening(eight)), Error::NotRegistered);
    let seven: &'static [ModuleId<'static>] = leak_slice(std::vec![module(b"MOD-P1"); 7]);
    assert_eq!(refused_opening(opening(seven)), Error::Duplicate);
    let mut o = opening(modules());
    o.witnesses = weak_witnesses();
    assert_eq!(refused_opening(o), Error::SignersShort);
    // Discrepancies open under hold.
    let mut o = opening(modules());
    o.seals_match = false;
    let b = provisioned(Profile::InPerson)
        .open(leak(o))
        .into_result()
        .unwrap();
    assert_eq!(b.holds(), HoldSet::empty().with(HoldReason::SealMismatch));
    let mut o = opening(modules());
    o.initial_count = 1;
    let b = provisioned(Profile::InPerson)
        .open(leak(o))
        .into_result()
        .unwrap();
    assert_eq!(b.holds(), HoldSet::empty().with(HoldReason::OpeningNonZero));
    // No modules before stage 2.
    let b = provisioned(Profile::InPerson)
        .open(leak(opening(&[])))
        .into_result()
        .unwrap();
    assert!(b.modules().is_empty());
}

#[test]
fn record_refusals() {
    let mut b = open(Profile::InPerson);
    let auth = authorization();
    let cap = auth.grant::<BallotMark>(today()).unwrap();
    assert_eq!(
        b.record(&cap, &record_body(other_box(), b"S-1", modules())),
        Err(Error::Mismatch)
    );
    let stray = [module(b"MOD-P1"), module(b"MOD-P3")];
    assert_eq!(
        b.record(&cap, &record_body(box_id(), b"S-1", &stray)),
        Err(Error::NotRegistered)
    );
    let test = b
        .record(&cap, &record_body(box_id(), b"TEST-1", modules()))
        .unwrap();
    assert!(test.is_test());
    assert_eq!(b.observed().records, 1);
    // A capability of another election.
    let other = common::signed_authorization_for(other_election());
    let foreign = other.grant::<BallotMark>(today()).unwrap();
    assert_eq!(
        b.record(&foreign, &record_body(box_id(), b"S-1", modules())),
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

fn fallback_event() -> FallbackEvent<'static> {
    FallbackEvent {
        election_id: election(),
        box_id: box_id(),
        witnesses: witnesses(),
    }
}

#[test]
fn fallback() {
    let b = open(Profile::InPerson);
    let weak = FallbackEvent {
        witnesses: weak_witnesses(),
        ..fallback_event()
    };
    let b = match b.declare_fallback(&weak) {
        Transition::Refused(b, error) => {
            assert_eq!(error, Error::SignersShort);
            b
        }
        Transition::Done(_) => panic!(),
    };
    let elsewhere = FallbackEvent {
        box_id: other_box(),
        ..fallback_event()
    };
    let b = match b.declare_fallback(&elsewhere) {
        Transition::Refused(b, error) => {
            assert_eq!(error, Error::Mismatch);
            b
        }
        Transition::Done(_) => panic!(),
    };
    let mut f = b.declare_fallback(&fallback_event()).into_result().unwrap();
    assert!(f.fallback_declared());
    assert!(f.holds().is_empty());
    f.batch(&batch_body(box_id(), 2)).unwrap();
    assert_eq!(f.observed().attested, 2);
    assert_eq!(f.batch(&batch_body(other_box(), 1)), Err(Error::Mismatch));
    let f = match f.end_fallback(&weak) {
        Transition::Refused(f, error) => {
            assert_eq!(error, Error::SignersShort);
            f
        }
        Transition::Done(_) => panic!(),
    };
    let mut b = f.end_fallback(&fallback_event()).into_result().unwrap();
    assert!(b.fallback_declared());
    let auth = authorization();
    let cap = auth.grant::<BallotMark>(today()).unwrap();
    b.record(&cap, &record_body(box_id(), b"S-1", modules()))
        .unwrap();
    b.record(&cap, &record_body(box_id(), b"S-1", modules()))
        .unwrap();
    // Two records, three ballots through the emergency slot.
    let mut c = counts(5, 2, 0);
    c.without_record = 3;
    let close = signed_close(&close_parts(c, modules()));
    let none = PhysicalCounts { spoil_envelopes: 0 };
    let closed = b
        .close(&close.close, Some(&close.token), none, None)
        .into_result()
        .unwrap();
    assert!(closed.holds().is_empty(), "{:?}", closed.holds());
}

#[test]
fn fallback_takes_records_uploaded_late() {
    let b = open(Profile::InPerson);
    let mut f = b.declare_fallback(&fallback_event()).into_result().unwrap();
    let auth = authorization();
    let cap = auth.grant::<BallotMark>(today()).unwrap();
    let state = f
        .record(&cap, &record_body(box_id(), b"TEST-9", modules()))
        .unwrap();
    assert!(state.is_test());
    f.challenge(&challenge_body(box_id())).unwrap();
    assert_eq!(
        f.record(&cap, &record_body(other_box(), b"S-1", modules())),
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
        .declare_fallback(&fallback_event())
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
    let close = signed_close(&close_parts(c, modules()));
    let none = PhysicalCounts { spoil_envelopes: 0 };
    let closed = b
        .close(&close.close, Some(&close.token), none, None)
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
    let f = b.declare_fallback(&fallback_event()).into_result().unwrap();
    let mut c = counts(4, 2, 0);
    c.without_record = 2;
    let close = signed_close(&close_parts(c, modules()));
    let none = PhysicalCounts { spoil_envelopes: 0 };
    let closed = f
        .close(
            &manual_close(&close_parts(c, other_modules())),
            None,
            none,
            None,
        )
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
    let f = b.declare_fallback(&fallback_event()).into_result().unwrap();
    let wrong = leak(signed_close(&close_parts(counts(2, 2, 0), modules())));
    // A token for another close is refused and the box kept.
    let f = match f.close(&close.close, Some(&wrong.token), none, None) {
        Transition::Refused(f, error) => {
            assert_eq!(error, Error::SignatureObject);
            f
        }
        Transition::Done(_) => panic!(),
    };
    let closed = f
        .close(&close.close, Some(&close.token), none, None)
        .into_result()
        .unwrap();
    assert!(closed.holds().is_empty(), "{:?}", closed.holds());
}

fn other_modules() -> &'static [ModuleId<'static>] {
    leak_slice(std::vec![module(b"MOD-P1"), module(b"MOD-P3")])
}

fn refused_close(
    close: &BoxClose<'static>,
    token: Option<&ityv_crypto::Verified<ityv_crypto::HybridSigned<'static>>>,
    issuance: Option<&ityv_state::IssuanceCount<'static>>,
) -> Error {
    let mut b = open(Profile::InPerson);
    fill(&mut b, 10, 1);
    match b.close(close, token, PHYSICAL, issuance) {
        Transition::Refused(b, error) => {
            assert_eq!(b.observed().records, 10);
            error
        }
        Transition::Done(_) => panic!("closed"),
    }
}

#[test]
fn close_signature_binding() {
    let parts = close_parts(counts(10, 10, 1), modules());
    let good = leak(signed_close(&parts));
    // A signature without a token.
    assert_eq!(refused_close(&good.close, None, None), Error::Unverified);
    // A token for a manual close.
    let manual = leak(manual_close(&parts));
    assert_eq!(
        refused_close(manual, Some(&good.token), None),
        Error::SignatureObject
    );
    // A token for another object.
    let mut other = parts;
    other.journal_head = Hash512([0x77; 64]);
    let other = leak(signed_close(&other));
    assert_eq!(
        refused_close(&good.close, Some(&other.token), None),
        Error::SignatureObject
    );
    // A token with another purpose.
    let late = leak(signed_close_with(&parts, device_key(), b"late-box-close"));
    assert_eq!(
        refused_close(&late.close, Some(&late.token), None),
        Error::SignatureObject
    );
    // A token from another key.
    let stranger = leak(HybridSigningKey::from_seeds([40; 32], [41; 32]));
    let forged = leak(signed_close_with(&parts, stranger, b"box-close"));
    assert_eq!(
        refused_close(&forged.close, Some(&forged.token), None),
        Error::SignatureSigner
    );
    // A token for the same body but another signature.
    let resigned = leak(signed_close_with(&parts, device_key(), b"box-close"));
    let mixed = BoxClose::new(
        good.close.body_bytes(),
        Some(leak(common::signature_bytes(&common::sign(
            device_key(),
            &ityv_crypto::Purpose::new(b"box-close").unwrap(),
            b"something else",
        )))),
        witnesses(),
    )
    .unwrap();
    assert_eq!(
        refused_close(leak(mixed), Some(&resigned.token), None),
        Error::SignatureObject
    );
    // One half of the signature altered: the ML-DSA half (first byte) or
    // the Ed25519 half (last byte).
    let good_bytes = good.close.device_sig().unwrap();
    for index in [0, ityv_encoding::HYBRID_SIG_LEN - 1] {
        let mut altered = *good_bytes;
        altered[index] ^= 1;
        let close =
            BoxClose::new(good.close.body_bytes(), Some(leak(altered)), witnesses()).unwrap();
        assert_eq!(
            refused_close(leak(close), Some(&good.token), None),
            Error::SignatureObject
        );
    }
    // Another box, another election.
    let mut elsewhere = parts;
    elsewhere.box_id = other_box();
    let elsewhere = leak(signed_close(&elsewhere));
    assert_eq!(
        refused_close(&elsewhere.close, Some(&elsewhere.token), None),
        Error::Mismatch
    );
    let mut elsewhere = parts;
    elsewhere.election_id = other_election();
    let elsewhere = leak(signed_close(&elsewhere));
    assert_eq!(
        refused_close(&elsewhere.close, Some(&elsewhere.token), None),
        Error::Mismatch
    );
    // Close signers must be registered.
    let stranger_witnesses = leak_slice(std::vec![
        common::attestation(common::person(
            b"clerk-1",
            ityv_encoding::SignerRole::Clerk,
            b"NEC"
        )),
        common::attestation(common::person(
            b"clerk-2",
            ityv_encoding::SignerRole::Clerk,
            b"NEC"
        )),
        common::attestation(common::person(
            b"obs-a",
            ityv_encoding::SignerRole::Observer,
            b"PARTY-A"
        )),
        common::attestation(common::person(
            b"obs-z",
            ityv_encoding::SignerRole::Observer,
            b"PARTY-Z"
        )),
    ]);
    let unregistered =
        leak(BoxClose::new(common::close_body(&parts), None, stranger_witnesses).unwrap());
    assert_eq!(
        refused_close(unregistered, None, None),
        Error::NotRegistered
    );
}

#[test]
fn close_holds() {
    let check = |c: ityv_encoding::CloseCounts, physical: PhysicalCounts| {
        let mut b = open(Profile::InPerson);
        fill(&mut b, 10, 1);
        let close = signed_close(&close_parts(c, modules()));
        b.close(&close.close, Some(&close.token), physical, None)
            .into_result()
            .unwrap()
            .holds()
    };
    assert_eq!(
        check(counts(11, 10, 1), PHYSICAL),
        HoldSet::empty().with(HoldReason::PaperRecordMismatch)
    );
    assert_eq!(
        check(counts(10, 10, 1), PhysicalCounts { spoil_envelopes: 2 }),
        HoldSet::empty().with(HoldReason::SpoilEnvelopeMismatch)
    );
    let mut c = counts(10, 10, 1);
    c.visits = 1;
    assert_eq!(
        check(c, PHYSICAL),
        HoldSet::empty().with(HoldReason::VisitBounds)
    );
    // The ledger shows ten records; a close reporting nine holds.
    let reported = check(counts(9, 9, 1), PHYSICAL);
    assert!(reported.contains(HoldReason::ObservedCountMismatch));
    // A module counter with a gap.
    let mut b = open(Profile::InPerson);
    fill(&mut b, 10, 1);
    let mut parts = close_parts(counts(10, 10, 1), modules());
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
    let close = signed_close(&parts);
    let closed = b
        .close(&close.close, Some(&close.token), PHYSICAL, None)
        .into_result()
        .unwrap();
    assert_eq!(
        closed.holds(),
        HoldSet::empty().with(HoldReason::ModuleCounterGap)
    );
}

#[test]
fn manual_close_and_late_close() {
    let parts = close_parts(counts(10, 10, 1), modules());
    let make_manual = || {
        let mut b = open(Profile::InPerson);
        fill(&mut b, 10, 1);
        b.close(leak(manual_close(&parts)), None, PHYSICAL, None)
            .into_result()
            .unwrap()
    };
    let mut b = make_manual();
    assert!(b.is_manual());
    assert_eq!(b.holds(), HoldSet::empty().with(HoldReason::ManualClose));
    // A late close needs the device signature with its own purpose.
    let wrong_purpose = leak(signed_close(&parts));
    assert_eq!(
        b.late_close(&wrong_purpose.close, &wrong_purpose.token),
        Err(Error::SignatureObject)
    );
    let late = leak(signed_close_with(&parts, device_key(), b"late-box-close"));
    assert_eq!(
        b.late_close(leak(manual_close(&parts)), &late.token),
        Err(Error::LateClose)
    );
    let mut elsewhere = parts;
    elsewhere.box_id = other_box();
    let elsewhere = leak(signed_close_with(
        &elsewhere,
        device_key(),
        b"late-box-close",
    ));
    assert_eq!(
        b.late_close(&elsewhere.close, &elsewhere.token),
        Err(Error::Mismatch)
    );
    let stranger = leak(HybridSigningKey::from_seeds([40; 32], [41; 32]));
    let forged = leak(signed_close_with(&parts, stranger, b"late-box-close"));
    assert_eq!(
        b.late_close(&forged.close, &forged.token),
        Err(Error::SignatureSigner)
    );
    assert!(b.is_manual());
    b.late_close(&late.close, &late.token).unwrap();
    assert!(!b.is_manual());
    assert!(b.holds().is_empty());
    // Only once.
    assert_eq!(
        b.late_close(&late.close, &late.token),
        Err(Error::LateClose)
    );

    // Human counts that differ keep the manual close's holds.
    for change in 0..3 {
        let mut b = make_manual();
        let mut c = counts(10, 10, 1);
        match change {
            0 => c.paper = 11,
            1 => c.envelopes = 1,
            _ => c.stickers = 1,
        }
        let late = leak(signed_close_with(
            &close_parts(c, modules()),
            device_key(),
            b"late-box-close",
        ));
        b.late_close(&late.close, &late.token).unwrap();
        assert!(b.is_manual());
        assert!(b.holds().contains(HoldReason::ManualClose));
        assert!(b.holds().contains(HoldReason::LateCloseDiffers));
        assert_eq!(b.counts(), &counts(10, 10, 1));
    }

    // A manual close whose device counts were unknown: the late close's
    // verdict replaces them.
    let mut b = open(Profile::InPerson);
    fill(&mut b, 10, 1);
    let mut unknown = counts(10, 0, 0);
    unknown.attested = 0;
    unknown.visits = 0;
    let b2 = b
        .close(
            leak(manual_close(&close_parts(unknown, modules()))),
            None,
            PHYSICAL,
            None,
        )
        .into_result()
        .unwrap();
    let mut b = b2;
    assert!(b.holds().contains(HoldReason::PaperRecordMismatch));
    let mut late_parts = parts;
    late_parts.open_batches = 1;
    late_parts.counts.attested = 10;
    let late = leak(signed_close_with(
        &late_parts,
        device_key(),
        b"late-box-close",
    ));
    b.late_close(&late.close, &late.token).unwrap();
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
        b.record(&cap, &record_body(box_id(), b"S-1", modules()))
            .unwrap();
    }
    b.batch(&batch_body(box_id(), 6)).unwrap();
    let mut c = counts(10, 10, 0);
    c.attested = 6;
    let mut parts = close_parts(c, modules());
    parts.open_batches = 1;
    let close = signed_close(&parts);
    let none = PhysicalCounts { spoil_envelopes: 0 };
    let mut b = b
        .close(&close.close, Some(&close.token), none, None)
        .into_result()
        .unwrap();
    assert_eq!(b.holds(), HoldSet::empty().with(HoldReason::OpenBatches));
    let late = |n, box_id, witnesses| LateBatchClose {
        batch: leak(batch_body(box_id, n)),
        witnesses,
    };
    assert_eq!(
        b.late_batch(&late(5, box_id(), witnesses())),
        Err(Error::BatchExceedsRecords)
    );
    assert_eq!(
        b.late_batch(&late(1, other_box(), witnesses())),
        Err(Error::Mismatch)
    );
    assert_eq!(
        b.late_batch(&late(1, box_id(), weak_witnesses())),
        Err(Error::SignersShort)
    );
    b.late_batch(&late(2, box_id(), witnesses())).unwrap();
    assert_eq!(b.observed().attested, 8);
    assert!(b.holds().contains(HoldReason::OpenBatches));
    for h in handoffs(10) {
        b.handoff(&h).unwrap();
    }
    // Counting may come before the late-close window ends.
    let mut counted = b.count(&audit(0, 0)).into_result().unwrap();
    assert!(counted.holds().contains(HoldReason::OpenBatches));
    counted.late_batch(&late(2, box_id(), witnesses())).unwrap();
    assert!(counted.holds().is_empty(), "{:?}", counted.holds());
    assert_eq!(
        counted.late_batch(&late(1, box_id(), witnesses())),
        Err(Error::BatchExceedsRecords)
    );
}

#[test]
fn late_close_after_counting() {
    let parts = close_parts(counts(10, 10, 1), modules());
    let mut b = open(Profile::InPerson);
    fill(&mut b, 10, 1);
    let mut b = b
        .close(leak(manual_close(&parts)), None, PHYSICAL, None)
        .into_result()
        .unwrap();
    for h in handoffs(10) {
        b.handoff(&h).unwrap();
    }
    let mut counted = b.count(&audit(0, 0)).into_result().unwrap();
    assert!(counted.is_manual());
    let late = leak(signed_close_with(&parts, device_key(), b"late-box-close"));
    counted.late_close(&late.close, &late.token).unwrap();
    assert!(!counted.is_manual());
    assert!(counted.holds().is_empty());
}

#[test]
fn custody_and_counting_holds() {
    let mut b = closed();
    let [first, second] = handoffs(9);
    b.handoff(&first).unwrap();
    assert_eq!(
        b.holds(),
        HoldSet::empty().with(HoldReason::CustodyCountMismatch)
    );
    let change = SealChange {
        election_id: election(),
        box_id: box_id(),
        reason: ReasonCode::new(2).unwrap(),
        previous_seal: SEAL,
        new_seal: Hash512([0x5f; 64]),
        signed: true,
    };
    b.seal_change(&change).unwrap();
    b.handoff(&CustodyHandoff {
        seal_digest: Hash512([0x5f; 64]),
        paper_count: 10,
        ..second
    })
    .unwrap();
    assert_eq!(
        b.holds(),
        HoldSet::empty().with(HoldReason::CustodyCountMismatch)
    );
    assert_eq!(b.custody().seal(), &Hash512([0x5f; 64]));

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
    let wrong = ImprintAudit {
        box_id: other_box(),
        ..audit(0, 0)
    };
    let b = match b.count(&wrong) {
        Transition::Refused(b, error) => {
            assert_eq!(error, Error::Mismatch);
            b
        }
        Transition::Done(_) => panic!(),
    };
    let weak = ImprintAudit {
        witnesses: weak_witnesses(),
        ..audit(0, 0)
    };
    let refused = b.count(&weak);
    assert_eq!(refused.error(), Some(Error::SignersShort));
    let b = match refused {
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
    let station = StationId::new(b"ST-1").unwrap();
    let issuance = |issued, returned_empty, witnesses| ityv_state::IssuanceCount {
        election_id: election(),
        station_id: station,
        issued: 40,
        voter_spoiled: 0,
        returned: 0,
        unused: 0,
        envelopes: Some(ityv_state::EnvelopeIssuance {
            issued,
            returned_empty,
        }),
        witnesses,
    };
    let mut c = counts(0, 10, 0);
    c.visits = 4;
    c.envelopes = 4;
    c.stickers = 4;
    let close = leak(signed_close(&close_parts(c, modules())));
    let none = PhysicalCounts { spoil_envelopes: 0 };
    let make = || {
        let mut b = open(Profile::Absentee);
        let auth = authorization();
        let cap = auth.grant::<BallotMark>(today()).unwrap();
        for _ in 0..10 {
            let r = b
                .record(&cap, &record_body(box_id(), b"S-1", modules()))
                .unwrap();
            assert_eq!(r.profile(), Profile::Absentee);
        }
        b.batch(&batch_body(box_id(), 10)).unwrap();
        b
    };
    let closed = make()
        .close(
            &close.close,
            Some(&close.token),
            none,
            Some(&issuance(5, 1, witnesses())),
        )
        .into_result()
        .unwrap();
    assert!(closed.holds().is_empty(), "{:?}", closed.holds());
    // The custody chain carries the envelope count.
    let mut b = closed;
    let [first, _] = handoffs(4);
    b.handoff(&first).unwrap();
    assert!(b.holds().is_empty());
    let closed = make()
        .close(
            &close.close,
            Some(&close.token),
            none,
            Some(&issuance(5, 0, witnesses())),
        )
        .into_result()
        .unwrap();
    assert_eq!(
        closed.holds(),
        HoldSet::empty().with(HoldReason::EnvelopeMismatch)
    );
    let closed = make()
        .close(&close.close, Some(&close.token), none, None)
        .into_result()
        .unwrap();
    assert_eq!(
        closed.holds(),
        HoldSet::empty().with(HoldReason::IssuanceMissing)
    );
    let weak = leak(issuance(5, 1, weak_witnesses()));
    assert_eq!(
        make()
            .close(&close.close, Some(&close.token), none, Some(weak))
            .error(),
        Some(Error::SignersShort)
    );
    let mut foreign = issuance(5, 1, witnesses());
    foreign.election_id = other_election();
    assert_eq!(
        make()
            .close(&close.close, Some(&close.token), none, Some(&foreign))
            .error(),
        Some(Error::Mismatch)
    );
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
