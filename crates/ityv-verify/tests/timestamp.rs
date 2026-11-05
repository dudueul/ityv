//! External timestamps (PROTOCOL.md §5.5, §14 2; ADR-0034, ADR-0039;
//! VC-114..118): real RFC 3161 tokens made by OpenSSL over the world's real
//! checkpoints, genesis and legal decision (`tests/common/tsa.rs`). Every
//! record the stage refuses, the anchor window and the backdating edge with
//! and without a stated accuracy, a rotated certificate, two authorities of
//! one operator, and the status each gives.
// Integration tests: outside the TCB. Assertions use unwrap/expect, so these
// lints are relaxed for this file only (CONSTITUTION.md §1.1).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::missing_panics_doc,
    clippy::arithmetic_side_effects
)]

mod common;
mod world;

use common::tsa::{self, FREE, GOV, GOV_ROTATED, GOV_SAME_OPERATOR, ROGUE, at, record_for, stamp};
use common::{election, leak};
use ityv_crypto::object_hash;
use ityv_encoding::{
    AuthorityId, DisputeType, Hash512, SCHEMA_SIGNED_GENESIS, SCHEMA_TIMESTAMP_RECORD,
    SCHEMA_WITNESSED_EVENT, SchemaId, TallyEffect, TimeBucket, TimestampAuthorityKind,
};
use ityv_ledger::SCHEMA_SIGNED_CHECKPOINT;
use ityv_state::{HoldReason, Publication, Status};
use ityv_tsa::TsaError;
use ityv_verify::{
    Anchoring, CheckpointChain, CheckpointFindingKind, Publications, TimestampProblem,
    authorize_ledger, build_index, verify_checkpoints, verify_ledger,
};

use world::{B1, Book, decision, filing, world};

/// The checkpoints' bucket in these tests.
const B: u64 = 300;

fn chain(book: &Book) -> &'static CheckpointChain<'static> {
    let g = book.world.genesis;
    let index = leak(build_index(g, book.ledger.bytes(), &book.ledger.events));
    assert!(index.ledger_holds().is_empty(), "{:?}", index.findings());
    let authority = leak(authorize_ledger(g, index));
    leak(verify_checkpoints(g, index, authority))
}

/// The last event pushed.
fn last(book: &Book) -> &'static [u8] {
    book.ledger.events.last().unwrap()
}

/// A book with one unstamped checkpoint at bucket `B`: the book and the
/// checkpoint event.
fn bare() -> (Book, &'static [u8]) {
    let mut book = Book::new(world());
    book.checkpoint_bare_at(B);
    let checkpoint = last(&book);
    (book, checkpoint)
}

fn push(book: &mut Book, record: &'static [u8]) -> u64 {
    book.push(SCHEMA_TIMESTAMP_RECORD, record)
}

/// The start of bucket `k`, in Unix seconds.
const fn start(k: u64) -> u64 {
    at(k, 0)
}

#[test]
fn real_tokens_of_two_operators_anchor_a_checkpoint() {
    let (mut book, checkpoint) = bare();
    let checkpoint_frame = book.frames.len() as u64;
    let gov = push(
        &mut book,
        stamp(GOV, SCHEMA_SIGNED_CHECKPOINT, checkpoint, at(B, 60)),
    );
    let free = push(
        &mut book,
        stamp(FREE, SCHEMA_SIGNED_CHECKPOINT, checkpoint, at(B, 60)),
    );
    let c = chain(&book);
    assert!(c.findings().is_empty());
    assert!(c.holds().is_empty());
    let verified = c.last().unwrap();
    assert_eq!(verified.event_hash, object_hash(checkpoint));
    assert_eq!(
        verified.anchoring,
        Anchoring {
            government: true,
            non_government: true,
            operators: 2
        }
    );
    assert!(verified.anchoring.satisfied());
    let tokens = c.timestamps().tokens();
    assert_eq!(tokens.len(), 2);
    assert_eq!(tokens[0].frame.get(), gov);
    assert_eq!(tokens[1].frame.get(), free);
    for t in tokens {
        assert_eq!(t.target, object_hash(checkpoint));
        assert_eq!(t.target_schema, SCHEMA_SIGNED_CHECKPOINT);
        assert_eq!(t.target_frame.get(), checkpoint_frame);
        assert_eq!(t.gen_time, at(B, 60));
    }
    // The government's tokens state one second of accuracy; the other
    // authority's state none and its policy gives 500 ms.
    assert_eq!(tokens[0].authority.as_bytes(), b"TSA-GOV-1");
    assert_eq!(tokens[0].operator.as_bytes(), b"MOIS-GPKI");
    assert_eq!(tokens[0].kind, TimestampAuthorityKind::Government);
    assert_eq!(tokens[0].latest, at(B, 61));
    assert_eq!(
        tokens[0].certificate_sha256[..],
        tsa::signer(GOV).pin[1..33]
    );
    assert_eq!(tokens[1].authority.as_bytes(), b"TSA-FREE-1");
    assert_eq!(tokens[1].kind, TimestampAuthorityKind::NonGovernment);
    assert_eq!(tokens[1].latest, at(B, 60));
    assert_eq!(
        c.timestamps().tokens_for(&object_hash(checkpoint)).count(),
        2
    );
    assert_eq!(c.timestamps().tokens_for(&Hash512([7; 64])).count(), 0);
    assert_eq!(
        c.anchor_deadline(TimeBucket::new(B + 100)),
        Publication::Satisfied
    );
}

#[test]
fn a_token_anchors_only_within_the_window_of_its_latest_instant() {
    // Both tokens one second before bucket B + 5: the government's
    // accuracy carries its latest instant into B + 5, outside the window;
    // the other's 500 ms keeps it in B + 4.
    let (mut book, checkpoint) = bare();
    push(
        &mut book,
        stamp(GOV, SCHEMA_SIGNED_CHECKPOINT, checkpoint, start(B + 5) - 1),
    );
    push(
        &mut book,
        stamp(FREE, SCHEMA_SIGNED_CHECKPOINT, checkpoint, start(B + 5) - 1),
    );
    let c = chain(&book);
    assert!(c.holds().is_empty());
    assert_eq!(
        c.last().unwrap().anchoring,
        Anchoring {
            government: false,
            non_government: true,
            operators: 1
        }
    );
    assert_eq!(
        c.anchor_deadline(TimeBucket::new(B + 4)),
        Publication::Pending
    );
    assert_eq!(
        c.anchor_deadline(TimeBucket::new(B + 5)),
        Publication::Breached(ityv_ledger::Breach::AnchorsShort { have: 1, need: 2 })
    );
    // Two seconds earlier both are in the window.
    let (mut book, checkpoint) = bare();
    push(
        &mut book,
        stamp(GOV, SCHEMA_SIGNED_CHECKPOINT, checkpoint, start(B + 5) - 2),
    );
    push(
        &mut book,
        stamp(FREE, SCHEMA_SIGNED_CHECKPOINT, checkpoint, start(B + 5) - 2),
    );
    assert!(chain(&book).last().unwrap().anchoring.satisfied());
}

#[test]
fn a_token_earlier_than_the_tolerance_ends_the_chain() {
    // A second before bucket B − 1: the government's token, with its one
    // second of accuracy, reaches B − 1 and is within the tolerance; the
    // other's latest instant, 500 ms later, stays in B − 2.
    let (mut book, checkpoint) = bare();
    push(
        &mut book,
        stamp(GOV, SCHEMA_SIGNED_CHECKPOINT, checkpoint, start(B - 1) - 1),
    );
    let c = chain(&book);
    assert!(c.findings().is_empty());
    assert!(c.holds().is_empty());
    let (mut book, checkpoint) = bare();
    push(
        &mut book,
        stamp(FREE, SCHEMA_SIGNED_CHECKPOINT, checkpoint, start(B - 1)),
    );
    assert!(chain(&book).findings().is_empty());
    let (mut book, checkpoint) = bare();
    push(
        &mut book,
        stamp(FREE, SCHEMA_SIGNED_CHECKPOINT, checkpoint, start(B - 1) - 1),
    );
    // A later, valid checkpoint is not checked: the chain ended.
    book.checkpoint_at(B + 1);
    let c = chain(&book);
    assert_eq!(c.findings().len(), 1);
    assert_eq!(c.findings()[0].kind, CheckpointFindingKind::Backdated);
    assert_eq!(c.findings()[0].frame.get(), 3);
    assert_eq!(c.unchecked(), 1);
    assert!(c.checkpoints().is_empty());
    assert!(c.holds().contains(HoldReason::TimestampMismatch));
    assert!(!c.holds().contains(HoldReason::CheckpointInvalid));
    assert!(!c.holds().contains(HoldReason::TimestampInvalid));
}

#[test]
fn every_record_that_cannot_be_taken_is_listed_and_holds() {
    let (mut book, checkpoint) = bare();
    let target = object_hash(checkpoint);
    let token = tsa::token(GOV, &target, at(B, 60));
    let mut expected: Vec<(u64, TimestampProblem)> = Vec::new();
    // An authority the genesis does not pin.
    let f = push(
        &mut book,
        record_for(
            election(),
            "TSA-UNKNOWN",
            SCHEMA_SIGNED_CHECKPOINT,
            target,
            Some(token),
        ),
    );
    expected.push((f, TimestampProblem::Authority));
    // No such event.
    let missing = Hash512([0x77; 64]);
    let f = push(
        &mut book,
        record_for(
            election(),
            "TSA-GOV-1",
            SCHEMA_SIGNED_CHECKPOINT,
            missing,
            Some(tsa::token(GOV, &missing, at(B, 60))),
        ),
    );
    expected.push((f, TimestampProblem::Target));
    // The checkpoint under another schema.
    let f = push(
        &mut book,
        record_for(
            election(),
            "TSA-GOV-1",
            SCHEMA_SIGNED_GENESIS,
            target,
            Some(token),
        ),
    );
    expected.push((f, TimestampProblem::Target));
    // A witnessed event of a kind that is not stamped: a dispute filing.
    let (_, filed) = filing(DisputeType::Other, B1, Hash512([0x31; 64]), 0x32);
    book.w(filed);
    let f = push(
        &mut book,
        stamp(GOV, SCHEMA_WITNESSED_EVENT, filed, at(B, 60)),
    );
    expected.push((f, TimestampProblem::Target));
    // A legal decision stamped before it is on the ledger.
    let decided = decision(Hash512([0x41; 64]), TallyEffect::NoEffect);
    let f = push(
        &mut book,
        stamp(GOV, SCHEMA_WITNESSED_EVENT, decided, at(B, 60)),
    );
    expected.push((f, TimestampProblem::Target));
    book.w(decided);
    // An authority no genesis pins, under a pinned authority's name.
    let f = push(
        &mut book,
        record_for(
            election(),
            "TSA-GOV-1",
            SCHEMA_SIGNED_CHECKPOINT,
            target,
            Some(tsa::token(ROGUE, &target, at(B, 60))),
        ),
    );
    expected.push((f, TimestampProblem::Token(TsaError::CertificateNotPinned)));
    // Another authority's token under this one's name.
    let f = push(
        &mut book,
        record_for(
            election(),
            "TSA-GOV-2",
            SCHEMA_SIGNED_CHECKPOINT,
            target,
            Some(token),
        ),
    );
    expected.push((f, TimestampProblem::Token(TsaError::CertificateNotPinned)));
    // A token over another event.
    let f = push(
        &mut book,
        record_for(
            election(),
            "TSA-GOV-1",
            SCHEMA_SIGNED_CHECKPOINT,
            target,
            Some(tsa::token(GOV, &missing, at(B, 60))),
        ),
    );
    expected.push((f, TimestampProblem::Token(TsaError::ImprintMismatch)));
    // The same from the authority's other certificate: whichever of the
    // two pins comes first, the one whose certificate is the token's names
    // the error, never the other's `CertificateNotPinned`.
    let f = push(
        &mut book,
        record_for(
            election(),
            "TSA-GOV-1",
            SCHEMA_SIGNED_CHECKPOINT,
            target,
            Some(tsa::token(GOV_ROTATED, &missing, at(B, 60))),
        ),
    );
    expected.push((f, TimestampProblem::Token(TsaError::ImprintMismatch)));
    // A token whose signature was changed.
    let mut forged = token.to_vec();
    let n = forged.len();
    forged[n - 1] ^= 1;
    let f = push(
        &mut book,
        record_for(
            election(),
            "TSA-GOV-1",
            SCHEMA_SIGNED_CHECKPOINT,
            target,
            Some(common::leak_slice(forged)),
        ),
    );
    expected.push((f, TimestampProblem::Token(TsaError::SignatureInvalid)));
    // Not a token at all.
    let f = push(
        &mut book,
        record_for(
            election(),
            "TSA-GOV-1",
            SCHEMA_SIGNED_CHECKPOINT,
            target,
            Some(&[0x30, 0x00]),
        ),
    );
    expected.push((
        f,
        TimestampProblem::Token(TsaError::Der(ityv_tsa::DerError::MissingField)),
    ));
    // The authority did not answer: listed, not a hold.
    let unanswered = push(
        &mut book,
        record_for(
            election(),
            "TSA-FREE-1",
            SCHEMA_SIGNED_CHECKPOINT,
            target,
            None,
        ),
    );
    let c = chain(&book);
    let got: Vec<(u64, TimestampProblem)> = c
        .timestamps()
        .refusals()
        .iter()
        .map(|r| (r.frame.get(), r.problem))
        .collect();
    assert_eq!(got, expected);
    assert_eq!(
        c.timestamps().refusals()[0].authority.as_bytes(),
        b"TSA-UNKNOWN"
    );
    assert_eq!(c.timestamps().refusals()[1].target, missing);
    assert_eq!(c.timestamps().unanswered().len(), 1);
    assert_eq!(c.timestamps().unanswered()[0].frame.get(), unanswered);
    assert_eq!(
        c.timestamps().unanswered()[0].authority.as_bytes(),
        b"TSA-FREE-1"
    );
    assert_eq!(c.timestamps().unanswered()[0].target, target);
    assert!(c.timestamps().tokens().is_empty());
    // The witnesses' chain stands; the records hold the ledger.
    assert!(c.findings().is_empty());
    assert_eq!(c.checkpoints().len(), 1);
    assert_eq!(c.holds(), HoldSetOf::one(HoldReason::TimestampInvalid));
    assert_eq!(
        c.timestamps().holds(),
        HoldSetOf::one(HoldReason::TimestampInvalid)
    );
    // Without the bad records, the note alone holds nothing.
    let (mut book, checkpoint) = bare();
    push(
        &mut book,
        record_for(
            election(),
            "TSA-FREE-1",
            SCHEMA_SIGNED_CHECKPOINT,
            object_hash(checkpoint),
            None,
        ),
    );
    assert!(chain(&book).holds().is_empty());
}

/// `HoldSet` with one reason.
struct HoldSetOf;

impl HoldSetOf {
    fn one(reason: HoldReason) -> ityv_state::HoldSet {
        ityv_state::HoldSet::empty().with(reason)
    }
}

#[test]
fn a_rotated_certificate_verifies_and_one_operator_counts_once() {
    let (mut book, checkpoint) = bare();
    for signer in [GOV_ROTATED, GOV_SAME_OPERATOR, GOV] {
        push(
            &mut book,
            stamp(signer, SCHEMA_SIGNED_CHECKPOINT, checkpoint, at(B, 60)),
        );
    }
    let c = chain(&book);
    assert!(c.holds().is_empty());
    let tokens = c.timestamps().tokens();
    assert_eq!(tokens.len(), 3);
    // The second pin of TSA-GOV-1 verified the rotated certificate.
    assert_eq!(tokens[0].authority.as_bytes(), b"TSA-GOV-1");
    assert_eq!(
        tokens[0].certificate_sha256[..],
        tsa::signer(GOV_ROTATED).pin[1..33]
    );
    assert_eq!(tokens[1].authority.as_bytes(), b"TSA-GOV-2");
    assert_eq!(
        c.last().unwrap().anchoring,
        Anchoring {
            government: true,
            non_government: false,
            operators: 1
        }
    );
    // Many tokens of one authority are still one authority.
    let (mut book, checkpoint) = bare();
    for offset in [10, 20, 30] {
        push(
            &mut book,
            stamp(FREE, SCHEMA_SIGNED_CHECKPOINT, checkpoint, at(B, offset)),
        );
    }
    let c = chain(&book);
    assert_eq!(c.timestamps().tokens().len(), 3);
    assert_eq!(
        c.last().unwrap().anchoring,
        Anchoring {
            government: false,
            non_government: true,
            operators: 1
        }
    );
}

#[test]
fn the_genesis_and_a_legal_decision_are_stamped() {
    let mut book = Book::new(world());
    let genesis = book.ledger.events[0];
    let decided = decision(Hash512([0x41; 64]), TallyEffect::NoEffect);
    let decision_frame = book.w(decided);
    for (signer, schema, event) in [
        (GOV, SCHEMA_SIGNED_GENESIS, genesis),
        (FREE, SCHEMA_SIGNED_GENESIS, genesis),
        (GOV, SCHEMA_WITNESSED_EVENT, decided),
    ] {
        push(&mut book, stamp(signer, schema, event, at(10, 0)));
    }
    book.checkpoint_at(B);
    let c = chain(&book);
    assert!(c.holds().is_empty(), "{:?}", c.timestamps().refusals());
    let tokens = c.timestamps().tokens();
    assert_eq!(tokens.len(), 5);
    assert_eq!(tokens[0].target, object_hash(genesis));
    assert_eq!(tokens[0].target_frame.get(), 1);
    assert_eq!(tokens[2].target, object_hash(decided));
    assert_eq!(tokens[2].target_frame.get(), decision_frame);
    assert_eq!(c.timestamps().tokens_for(&object_hash(genesis)).count(), 2);
}

#[test]
fn records_and_tokens_reach_the_status() {
    let now = Publications {
        now: TimeBucket::new(B),
        board: Publication::Pending,
    };
    let report = |book: &Book| {
        verify_ledger(
            world().genesis,
            book.ledger.bytes(),
            &book.ledger.events,
            now,
        )
    };
    // Anchored: the ledger is consistent as far as it goes.
    let mut book = Book::new(world());
    book.checkpoint_at(B);
    assert_eq!(report(&book).status().status(), Status::LogConsistent);
    // A record that cannot be taken holds.
    let (mut book, checkpoint) = bare();
    for record in tsa::anchor(SCHEMA_SIGNED_CHECKPOINT, checkpoint, B) {
        push(&mut book, record);
    }
    push(
        &mut book,
        record_for(
            election(),
            "TSA-UNKNOWN",
            SCHEMA_SIGNED_CHECKPOINT,
            object_hash(checkpoint),
            Some(tsa::token(GOV, &object_hash(checkpoint), at(B, 60))),
        ),
    );
    let r = report(&book);
    assert_eq!(r.status().status(), Status::HoldReview);
    assert!(r.status().holds().contains(HoldReason::TimestampInvalid));
    // A backdated checkpoint holds.
    let (mut book, checkpoint) = bare();
    for record in tsa::anchor(SCHEMA_SIGNED_CHECKPOINT, checkpoint, B) {
        push(&mut book, record);
    }
    push(
        &mut book,
        stamp(FREE, SCHEMA_SIGNED_CHECKPOINT, checkpoint, start(B - 2)),
    );
    let r = report(&book);
    assert_eq!(r.status().status(), Status::HoldReview);
    assert!(r.status().holds().contains(HoldReason::TimestampMismatch));
    // A record of another election is refused by the index.
    let (mut book, checkpoint) = bare();
    let other = record_for(
        ityv_encoding::ElectionId::new(b"E-OTHER").unwrap(),
        "TSA-GOV-1",
        SCHEMA_SIGNED_CHECKPOINT,
        object_hash(checkpoint),
        Some(tsa::token(GOV, &object_hash(checkpoint), at(B, 60))),
    );
    push(&mut book, other);
    let r = report(&book);
    assert_eq!(r.status().status(), Status::HoldReview);
    assert!(r.status().holds().contains(HoldReason::LedgerUnchecked));
}

#[test]
fn a_record_names_its_authority_by_identifier() {
    // `AuthorityId` is the genesis key of the set.
    let ids: Vec<&[u8]> = world()
        .genesis
        .timestamp_authorities()
        .map(|a| a.tsa_id.as_bytes())
        .collect();
    assert_eq!(ids, [b"TSA-FREE-1".as_slice(), b"TSA-GOV-1", b"TSA-GOV-2"]);
    let gov = world().genesis.timestamp_authority(b"TSA-GOV-1").unwrap();
    assert_eq!(gov.pins.len(), 2);
    assert_eq!(gov.tsa_id, AuthorityId::new(b"TSA-GOV-1").unwrap());
    assert!(world().genesis.timestamp_authority(b"TSA-ROGUE").is_none());
    let _: SchemaId = SCHEMA_TIMESTAMP_RECORD;
}
