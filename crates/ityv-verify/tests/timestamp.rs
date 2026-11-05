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
    // The government's tokens state one second of accuracy, as the genesis
    // declares; the other authority's state none and the genesis declares
    // two seconds.
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
    assert_eq!(tokens[1].latest, at(B, 62));
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
    // Both tokens two seconds before bucket B + 5: the other authority's
    // declared two seconds carry its latest instant into B + 5, outside
    // the window; the government's one second keeps it in B + 4.
    let (mut book, checkpoint) = bare();
    push(
        &mut book,
        stamp(GOV, SCHEMA_SIGNED_CHECKPOINT, checkpoint, start(B + 5) - 2),
    );
    push(
        &mut book,
        stamp(FREE, SCHEMA_SIGNED_CHECKPOINT, checkpoint, start(B + 5) - 2),
    );
    let c = chain(&book);
    assert!(c.holds().is_empty());
    assert_eq!(
        c.last().unwrap().anchoring,
        Anchoring {
            government: true,
            non_government: false,
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
    // A second earlier both are in the window; a second later the
    // government's is out too.
    let (mut book, checkpoint) = bare();
    push(
        &mut book,
        stamp(GOV, SCHEMA_SIGNED_CHECKPOINT, checkpoint, start(B + 5) - 3),
    );
    push(
        &mut book,
        stamp(FREE, SCHEMA_SIGNED_CHECKPOINT, checkpoint, start(B + 5) - 3),
    );
    assert!(chain(&book).last().unwrap().anchoring.satisfied());
    let (mut book, checkpoint) = bare();
    push(
        &mut book,
        stamp(GOV, SCHEMA_SIGNED_CHECKPOINT, checkpoint, start(B + 5) - 1),
    );
    assert_eq!(chain(&book).last().unwrap().anchoring.kinds(), 0);
}

#[test]
fn the_larger_of_the_stated_and_the_declared_accuracy_counts() {
    // ADR-0039 5: TSA-GOV-2's tokens state three seconds, more than the
    // one second its entry declares: the stated accuracy counts.
    let (mut book, checkpoint) = bare();
    push(
        &mut book,
        stamp(
            GOV_SAME_OPERATOR,
            SCHEMA_SIGNED_CHECKPOINT,
            checkpoint,
            start(B + 5) - 3,
        ),
    );
    push(
        &mut book,
        stamp(
            GOV_SAME_OPERATOR,
            SCHEMA_SIGNED_CHECKPOINT,
            checkpoint,
            start(B + 5) - 4,
        ),
    );
    let c = chain(&book);
    let latest: Vec<u64> = c.timestamps().tokens().iter().map(|t| t.latest).collect();
    assert_eq!(latest, [start(B + 5), start(B + 5) - 1]);
    // TSA-GOV-1 declares one second: a token stating none, or one second,
    // reaches a second later; one stating five seconds reaches five.
    let (mut book, checkpoint) = bare();
    let target = object_hash(checkpoint);
    for (stated, seconds) in [
        (None, at(B, 10)),
        (Some(1), at(B, 20)),
        (Some(5), at(B, 30)),
    ] {
        push(
            &mut book,
            record_for(
                election(),
                "TSA-GOV-1",
                SCHEMA_SIGNED_CHECKPOINT,
                target,
                Some(tsa::token_stating(GOV, &target, seconds, stated)),
            ),
        );
    }
    let c = chain(&book);
    assert!(c.holds().is_empty(), "{:?}", c.timestamps().refusals());
    let latest: Vec<u64> = c.timestamps().tokens().iter().map(|t| t.latest).collect();
    assert_eq!(latest, [at(B, 11), at(B, 21), at(B, 35)]);
    // Before the backdating edge, the declared accuracy alone decides for
    // a token that states none: TSA-FREE-1's two seconds.
    let (mut book, checkpoint) = bare();
    push(
        &mut book,
        stamp(FREE, SCHEMA_SIGNED_CHECKPOINT, checkpoint, start(B - 1) - 2),
    );
    assert!(chain(&book).findings().is_empty());
}

#[test]
fn a_token_stating_more_than_a_minute_is_refused() {
    // ADR-0039 5: the stated accuracy is capped at a minute
    // (`MAX_TIMESTAMP_ACCURACY_MS`); a vaguer token is refused and holds.
    let (mut book, checkpoint) = bare();
    let target = object_hash(checkpoint);
    let minute = push(
        &mut book,
        record_for(
            election(),
            "TSA-GOV-1",
            SCHEMA_SIGNED_CHECKPOINT,
            target,
            Some(tsa::token_stating(GOV, &target, at(B, 60), Some(60))),
        ),
    );
    let over = push(
        &mut book,
        record_for(
            election(),
            "TSA-FREE-1",
            SCHEMA_SIGNED_CHECKPOINT,
            target,
            Some(tsa::token_stating(FREE, &target, at(B, 60), Some(61))),
        ),
    );
    let c = chain(&book);
    let tokens = c.timestamps().tokens();
    assert_eq!(tokens.len(), 1);
    assert_eq!(tokens[0].frame.get(), minute);
    assert_eq!(tokens[0].latest, at(B, 120));
    let refused: Vec<(u64, TimestampProblem)> = c
        .timestamps()
        .refusals()
        .iter()
        .map(|r| (r.frame.get(), r.problem))
        .collect();
    assert_eq!(refused, [(over, TimestampProblem::Accuracy)]);
    assert_eq!(c.holds(), HoldSetOf::one(HoldReason::TimestampInvalid));
    // The refused token anchors nothing.
    assert!(!c.last().unwrap().anchoring.non_government);
}

#[test]
fn a_token_earlier_than_the_tolerance_ends_the_chain() {
    // A second before bucket B − 1: the government's token, with its one
    // second of accuracy, reaches B − 1 and is within the tolerance; two
    // seconds before, it stays in B − 2. The other's declared two seconds
    // reach B − 1 from two seconds before it, not from three.
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
        stamp(FREE, SCHEMA_SIGNED_CHECKPOINT, checkpoint, start(B - 1) - 2),
    );
    assert!(chain(&book).findings().is_empty());
    let (mut book, checkpoint) = bare();
    push(
        &mut book,
        stamp(GOV, SCHEMA_SIGNED_CHECKPOINT, checkpoint, start(B - 1) - 2),
    );
    assert_eq!(
        chain(&book).findings()[0].kind,
        CheckpointFindingKind::Backdated
    );
    let (mut book, checkpoint) = bare();
    push(
        &mut book,
        stamp(FREE, SCHEMA_SIGNED_CHECKPOINT, checkpoint, start(B - 1) - 3),
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
    // Every pin carries its certificate, which stands in for the one the
    // token embeds and is not the signer the token names.
    expected.push((
        f,
        TimestampProblem::Token(TsaError::SignerIdentifierMismatch),
    ));
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
    expected.push((
        f,
        TimestampProblem::Token(TsaError::SignerIdentifierMismatch),
    ));
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
    // the error, never the other's `SignerIdentifierMismatch`.
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

#[test]
fn a_record_without_a_token_names_an_earlier_stamped_event() {
    // The note that an authority did not answer is checked against its
    // target as a token would be (PROTOCOL.md §5.5, ADR-0039 4): no such
    // event, a witnessed kind that is never stamped (VC-117), an event
    // recorded only later. Each is refused and holds.
    let mut book = Book::new(world());
    book.checkpoint_bare_at(B);
    let checkpoint = last(&book);
    let ghost = push(
        &mut book,
        record_for(
            election(),
            "TSA-GOV-1",
            SCHEMA_SIGNED_CHECKPOINT,
            Hash512([0x77; 64]),
            None,
        ),
    );
    let (_, filed) = filing(DisputeType::Other, B1, Hash512([0x31; 64]), 0x32);
    book.w(filed);
    let unstamped_kind = push(
        &mut book,
        record_for(
            election(),
            "TSA-GOV-1",
            SCHEMA_WITNESSED_EVENT,
            object_hash(filed),
            None,
        ),
    );
    let decided = decision(Hash512([0x41; 64]), TallyEffect::NoEffect);
    let before_target = push(
        &mut book,
        record_for(
            election(),
            "TSA-FREE-1",
            SCHEMA_WITNESSED_EVENT,
            object_hash(decided),
            None,
        ),
    );
    book.w(decided);
    // The checkpoint under another schema.
    let wrong_schema = push(
        &mut book,
        record_for(
            election(),
            "TSA-FREE-1",
            SCHEMA_SIGNED_GENESIS,
            object_hash(checkpoint),
            None,
        ),
    );
    // An authority the genesis does not pin is refused first.
    let unknown = push(
        &mut book,
        record_for(
            election(),
            "TSA-UNKNOWN",
            SCHEMA_SIGNED_CHECKPOINT,
            object_hash(checkpoint),
            None,
        ),
    );
    // The same notes over events that are stamped and earlier are notes.
    let answered_not = [
        push(
            &mut book,
            record_for(
                election(),
                "TSA-GOV-1",
                SCHEMA_SIGNED_CHECKPOINT,
                object_hash(checkpoint),
                None,
            ),
        ),
        push(
            &mut book,
            record_for(
                election(),
                "TSA-GOV-2",
                SCHEMA_WITNESSED_EVENT,
                object_hash(decided),
                None,
            ),
        ),
    ];
    let c = chain(&book);
    let got: Vec<(u64, TimestampProblem)> = c
        .timestamps()
        .refusals()
        .iter()
        .map(|r| (r.frame.get(), r.problem))
        .collect();
    assert_eq!(
        got,
        [
            (ghost, TimestampProblem::Target),
            (unstamped_kind, TimestampProblem::Target),
            (before_target, TimestampProblem::Target),
            (wrong_schema, TimestampProblem::Target),
            (unknown, TimestampProblem::Authority),
        ]
    );
    let notes: Vec<u64> = c
        .timestamps()
        .unanswered()
        .iter()
        .map(|u| u.frame.get())
        .collect();
    assert_eq!(notes, answered_not);
    assert!(c.timestamps().tokens().is_empty());
    assert_eq!(c.holds(), HoldSetOf::one(HoldReason::TimestampInvalid));
    // The notes alone hold nothing.
    let mut book = Book::new(world());
    book.checkpoint_bare_at(B);
    let checkpoint = last(&book);
    book.w(decided);
    for (authority, schema, target) in [
        (
            "TSA-GOV-1",
            SCHEMA_SIGNED_CHECKPOINT,
            object_hash(checkpoint),
        ),
        ("TSA-FREE-1", SCHEMA_WITNESSED_EVENT, object_hash(decided)),
        (
            "TSA-GOV-2",
            SCHEMA_SIGNED_GENESIS,
            object_hash(book.ledger.events[0]),
        ),
    ] {
        push(
            &mut book,
            record_for(election(), authority, schema, target, None),
        );
    }
    let c = chain(&book);
    assert!(c.timestamps().refusals().is_empty());
    assert_eq!(c.timestamps().unanswered().len(), 3);
    assert!(c.holds().is_empty());
}

#[test]
fn openssl_scratch_directories_are_fresh_and_never_left_behind() {
    // Keys are written to a scratch directory only for one OpenSSL call
    // (`tests/common/tsa.rs`): it is removed even when the call panics,
    // and every call gets its own, unpredictable directory.
    let mut seen = std::path::PathBuf::new();
    let unwound = std::panic::catch_unwind(core::panic::AssertUnwindSafe(|| {
        tsa::in_scratch(|dir| {
            seen = dir.to_path_buf();
            std::fs::write(dir.join("k.pem"), "not a key").unwrap();
            panic!("an OpenSSL call failed");
        })
    }));
    assert!(unwound.is_err());
    assert!(!seen.as_os_str().is_empty());
    assert!(!seen.exists(), "{} was left behind", seen.display());
    let first = tsa::in_scratch(|dir| {
        assert!(std::fs::read_dir(dir).unwrap().next().is_none());
        dir.to_path_buf()
    });
    let second = tsa::in_scratch(std::path::Path::to_path_buf);
    assert_ne!(first, second);
    assert!(!first.exists() && !second.exists());
    assert!(first.starts_with(std::env::temp_dir()));
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
fn one_operator_spelled_two_ways_counts_once() {
    // The review's third proof of concept, the case the genesis takes:
    // TSA-GOV-2's operator spelled in lower case, still the government's.
    // Its tokens and TSA-GOV-1's are one operator's, and anchor nothing
    // without the other kind.
    let mut d = world::draft();
    let second = d
        .timestamps
        .iter_mut()
        .find(|a| a.tsa_id.as_bytes() == b"TSA-GOV-2")
        .unwrap();
    second.operator = ityv_encoding::OrgId::new(b"mois-gpki").unwrap();
    let w = leak(world::build(&d, &world::TALLY_SCOPES));
    let mut book = Book::new(w);
    book.checkpoint_bare_at(B);
    let checkpoint = last(&book);
    for signer in [GOV, GOV_SAME_OPERATOR] {
        push(
            &mut book,
            stamp(signer, SCHEMA_SIGNED_CHECKPOINT, checkpoint, at(B, 60)),
        );
    }
    let c = chain(&book);
    assert!(c.holds().is_empty());
    assert_eq!(c.timestamps().tokens().len(), 2);
    assert_eq!(
        c.last().unwrap().anchoring,
        Anchoring {
            government: true,
            non_government: false,
            operators: 1
        }
    );
    push(
        &mut book,
        stamp(FREE, SCHEMA_SIGNED_CHECKPOINT, checkpoint, at(B, 60)),
    );
    let c = chain(&book);
    assert_eq!(c.last().unwrap().anchoring.operators, 2);
    assert!(c.last().unwrap().anchoring.satisfied());
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
fn the_callers_clock_never_anchors_a_checkpoint() {
    // The review's fourth proof of concept, kept as a regression test: the
    // caller's `now` and board status never make an unanchored last
    // checkpoint read as anchored; a deadline past the end of the bucket
    // range holds.
    let mut book = Book::new(world());
    book.checkpoint_bare_at(B);
    let checkpoint = last(&book);
    // One kind only: not anchored.
    push(
        &mut book,
        stamp(GOV, SCHEMA_SIGNED_CHECKPOINT, checkpoint, at(B, 60)),
    );
    for now in [0, B, B + 4, B + 5, u64::MAX] {
        for board in [Publication::Pending, Publication::Satisfied] {
            let r = verify_ledger(
                world().genesis,
                book.ledger.bytes(),
                &book.ledger.events,
                Publications {
                    now: TimeBucket::new(now),
                    board,
                },
            );
            assert_eq!(r.status().status(), Status::Unverified, "now {now}");
            assert!(r.status().holds().is_empty());
        }
    }
    // With both kinds the same ledger is consistent at any `now`.
    push(
        &mut book,
        stamp(FREE, SCHEMA_SIGNED_CHECKPOINT, checkpoint, at(B, 60)),
    );
    for now in [0, B + 5, u64::MAX] {
        let r = verify_ledger(
            world().genesis,
            book.ledger.bytes(),
            &book.ledger.events,
            Publications {
                now: TimeBucket::new(now),
                board: Publication::Pending,
            },
        );
        assert_eq!(r.status().status(), Status::LogConsistent, "now {now}");
    }
    // A last checkpoint at the end of the bucket range: its deadline
    // overflows, which holds.
    let mut book = Book::new(world());
    book.checkpoint_bare_at(u64::MAX);
    let r = verify_ledger(
        world().genesis,
        book.ledger.bytes(),
        &book.ledger.events,
        Publications {
            now: TimeBucket::new(u64::MAX),
            board: Publication::Pending,
        },
    );
    assert_eq!(r.status().status(), Status::HoldReview);
    assert!(r.status().holds().contains(HoldReason::StepFailed));
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

#[test]
fn a_roll_freeze_and_its_receipts_are_stamped_and_an_extract_is_not() {
    use common::roll;
    // `LEGAL_ANNEX.md` amendment 15, §278-7 ①: the frozen roll's hash and the
    // custody receipts are timestamped (ADR-0034 §2, ADR-0040).
    let mut book = Book::new(world());
    let events = roll::standard(&[b"ST-1"]);
    let mut frames = Vec::new();
    for (schema, event) in &events {
        frames.push(book.push(*schema, event));
    }
    let extract = events[0].1;
    let freeze = events[2].1;
    let receipt = events[3].1;
    for event in [freeze, receipt, extract] {
        push(
            &mut book,
            stamp(GOV, SCHEMA_WITNESSED_EVENT, event, at(10, 0)),
        );
    }
    book.checkpoint_at(B);
    let c = chain(&book);
    let stamped = c.timestamps();
    assert_eq!(stamped.tokens_for(&object_hash(freeze)).count(), 1);
    assert_eq!(stamped.tokens_for(&object_hash(receipt)).count(), 1);
    let t = stamped.tokens_for(&object_hash(freeze)).next().unwrap();
    assert_eq!(t.target_frame.get(), frames[2]);
    assert_eq!(stamped.tokens_for(&object_hash(extract)).count(), 0);
    assert_eq!(
        stamped
            .refusals()
            .iter()
            .map(|r| (r.target, r.problem))
            .collect::<Vec<_>>(),
        [(object_hash(extract), TimestampProblem::Target)]
    );
    assert!(c.holds().contains(HoldReason::TimestampInvalid));
}
