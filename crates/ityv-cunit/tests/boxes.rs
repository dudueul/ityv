//! Box accounting: the journal chain, counter high-water marks, batches,
//! scan counts, quarantine, imprint failure, the fault latch and close.
// Integration-test crate: outside the TCB. Tests express "this must hold"
// with unwrap/expect/panic/indexing and small arithmetic on test sizes,
// so these lints are relaxed for this file only (CONSTITUTION.md §1.1).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::too_many_lines,
    clippy::missing_panics_doc,
    clippy::many_single_char_names
)]

mod common;

use common::{
    Buffers, MemJournal, MemStaging, MockModule, SEED, STYLE_SMALL, World, build_position,
    cast_one, challenge_one, interpretation, mocks, ports, signer, tb, visit_end, visit_work, work,
    world,
};
use ityv_crypto::{HybridSignature, Purpose, verify_hybrid};
use ityv_cunit::boxstate::{BATCH_WORK_LEN, CLOSE_WORK_LEN, CloseInputs, OpenBox};
use ityv_cunit::config::Profile;
use ityv_cunit::error::Invariant;
use ityv_cunit::link::{JournalEntry, JournalKind, SCHEMA_JOURNAL_ENTRY};
use ityv_cunit::rules::{CloseFacts, EnvelopeCounts, close_verdict};
use ityv_cunit::visit::Decision;
use ityv_cunit::{Error, JournalError, PortError, Staged};
use ityv_encoding::{
    BatchAttest, BoxCloseBody, Decode, Hash512, Reader, SCHEMA_BATCH_ATTEST, SCHEMA_BOX_CLOSE_BODY,
    SCHEMA_SCAN_COUNT_ATTEST_BODY, SCHEMA_VERSION_1, ScanCountAttestBody, decode_object,
};
use ityv_ledger::merkle::sorted_set_root;

fn entry(bytes: &[u8]) -> JournalEntry<'_> {
    decode_object(SCHEMA_JOURNAL_ENTRY, SCHEMA_VERSION_1, bytes).unwrap()
}

fn kinds(j: &MemJournal) -> std::vec::Vec<JournalKind> {
    j.entries.iter().map(|e| entry(e).kind()).collect()
}

/// The `(module id, counter)` pairs of the last journal entry.
fn last_counters(j: &MemJournal) -> std::vec::Vec<(std::vec::Vec<u8>, u64)> {
    entry(j.entries.last().unwrap())
        .module_counters()
        .iter()
        .map(|c| (c.module_id.as_bytes().to_vec(), c.counter))
        .collect()
}

/// Closes the batch with the head the host re-reads from storage.
fn close(
    w: &World,
    b: &mut OpenBox<'static>,
    m: &mut [MockModule],
    j: &mut MemJournal,
    at: u64,
) -> Result<std::vec::Vec<u8>, Error> {
    let head = j.head();
    let mut out = std::vec![0u8; BATCH_WORK_LEN];
    b.close_batch(&head, &mut ports(m), signer(w), j, tb(at), &mut out)
        .map(<[u8]>::to_vec)
}

fn refusals(attest: &[u8]) -> std::vec::Vec<std::vec::Vec<u8>> {
    let parsed: BatchAttest<'_> =
        decode_object(SCHEMA_BATCH_ATTEST, SCHEMA_VERSION_1, attest).unwrap();
    parsed
        .body()
        .module_refusals()
        .iter()
        .map(|id| id.as_bytes().to_vec())
        .collect()
}

/// Verifies every module signature of a `BatchAttest` and returns the
/// signers.
fn verified_signers(m: &[MockModule], attest: &[u8]) -> std::vec::Vec<std::vec::Vec<u8>> {
    let parsed: BatchAttest<'_> =
        decode_object(SCHEMA_BATCH_ATTEST, SCHEMA_VERSION_1, attest).unwrap();
    let purpose = Purpose::new(b"batch-attest").unwrap();
    parsed
        .module_sigs()
        .map(|sig| {
            let module = m.iter().find(|x| x.id == sig.module_id.as_bytes()).unwrap();
            let s = HybridSignature::decode(&mut Reader::new(sig.sig)).unwrap();
            let _ = verify_hybrid(
                &module.batch_verifying_key(),
                &purpose,
                parsed.body_bytes(),
                &s,
            )
            .unwrap();
            sig.module_id.as_bytes().to_vec()
        })
        .collect()
}

fn ids(list: &[&[u8]]) -> std::vec::Vec<std::vec::Vec<u8>> {
    list.iter().map(|id| id.to_vec()).collect()
}

#[test]
fn journal_entries_chain_and_carry_the_consumed_counters() {
    let w = world(Profile::InPerson, false);
    let mut b = OpenBox::open(w.config, tb(1));
    let mut m = mocks(&w);
    let mut j = MemJournal::default();
    cast_one(&w, &mut b, &mut m, &mut j, 1);
    challenge_one(&w, &mut b, &mut m, &mut j, 2);
    cast_one(&w, &mut b, &mut m, &mut j, 3);
    let mut head = Hash512::ZERO;
    // per visit: the position entry, the decision entry (no counters),
    // and for a cast ballot its imprint entry repeating the record's
    // counters
    let consumed = [
        Some(1u64),
        None,
        Some(1),
        Some(2),
        None,
        Some(3),
        None,
        Some(3),
    ];
    assert_eq!(j.entries.len(), consumed.len());
    for (bytes, &expected) in j.entries.iter().zip(&consumed) {
        let e = entry(bytes);
        assert_eq!(e.prev_head(), &head);
        if let Some(expected) = expected {
            assert_eq!(e.module_counters().len(), 5);
            for counter in e.module_counters().iter() {
                assert_eq!(counter.counter, expected);
            }
        } else {
            assert_eq!(e.kind(), JournalKind::VisitDecision);
            assert!(e.module_counters().is_empty());
        }
        head = ityv_crypto::object_hash(bytes);
    }
    assert_eq!(b.journal_head(), &head);
    assert_eq!(j.head(), head);
    assert_eq!(
        kinds(&j),
        [
            JournalKind::Record,
            JournalKind::VisitDecision,
            JournalKind::Imprinted,
            JournalKind::Challenge,
            JournalKind::VisitDecision,
            JournalKind::Record,
            JournalKind::VisitDecision,
            JournalKind::Imprinted
        ]
    );
    // the imprint entry names the record; only the record entry carries a
    // package
    assert_eq!(
        entry(&j.entries[2]).record_hash(),
        entry(&j.entries[0]).record_hash()
    );
    assert_eq!(entry(&j.entries[2]).share_package_hash(), &Hash512::ZERO);
    assert!(
        j.packages[1..]
            .iter()
            .step_by(1)
            .enumerate()
            .all(|(i, p)| { p.is_none() || i + 1 == 5 })
    );
    assert!(j.packages[5].is_some());
    assert_eq!(b.module_counters(), &[3, 3, 3, 3, 3]);
    assert_eq!(
        entry(&j.entries[0]).share_package_hash(),
        &ityv_crypto::object_hash(j.packages[0].as_ref().unwrap())
    );
}

#[test]
fn a_backwards_or_replayed_counter_is_refused_and_leaves_the_mark() {
    let w = world(Profile::InPerson, false);
    let mut b = OpenBox::open(w.config, tb(1));
    let mut m = mocks(&w);
    let mut j = MemJournal::default();
    cast_one(&w, &mut b, &mut m, &mut j, 1);
    cast_one(&w, &mut b, &mut m, &mut j, 1);
    assert_eq!(b.module_counters(), &[2, 2, 2, 2, 2]);
    let mut area = work();
    for forced in [1, 2] {
        m[0].force_counter = Some(forced);
        let ballot = b
            .interpret(&interpretation(b"E-2026", STYLE_SMALL, 1), &mut area)
            .unwrap();
        let err = ballot.issue(&mut b, &mut ports(&mut m), &SEED).unwrap_err();
        assert_eq!(err, Error::CounterRegression, "counter {forced}");
        assert_eq!(b.module_counters(), &[2, 2, 2, 2, 2]);
        // nothing was consumed, so nothing is journaled
        b.abandon_visit(&mut j, tb(1)).unwrap();
        assert_eq!(j.entries.len(), 6);
    }
    // The mark was not moved back: the module's next counter, 3, is the
    // one accepted (a mark of 1 would have made it a gap).
    cast_one(&w, &mut b, &mut m, &mut j, 1);
    assert_eq!(b.module_counters(), &[3, 3, 3, 3, 3]);
}

#[test]
fn a_counter_gap_is_refused_without_moving_that_module_mark() {
    let w = world(Profile::InPerson, false);
    let mut b = OpenBox::open(w.config, tb(1));
    let mut m = mocks(&w);
    let mut j = MemJournal::default();
    cast_one(&w, &mut b, &mut m, &mut j, 1);
    m[3].skip_counter = true; // mod-p1 answers 3 after 1
    let mut area = work();
    let ballot = b
        .interpret(&interpretation(b"E-2026", STYLE_SMALL, 1), &mut area)
        .unwrap();
    assert_eq!(
        ballot.issue(&mut b, &mut ports(&mut m), &SEED).unwrap_err(),
        Error::CounterGap
    );
    // mod-a, mod-c and mod-j consumed counter 2; mod-p1 and mod-p2 did not
    assert_eq!(b.module_counters(), &[2, 2, 2, 1, 1]);
    b.abandon_visit(&mut j, tb(1)).unwrap();
    assert_eq!(kinds(&j).last(), Some(&JournalKind::Quarantine));
    assert_eq!(
        entry(j.entries.last().unwrap()).record_hash(),
        &Hash512::ZERO
    );
    assert_eq!(
        last_counters(&j),
        [
            (b"mod-a".to_vec(), 2),
            (b"mod-c".to_vec(), 2),
            (b"mod-j".to_vec(), 2)
        ]
    );
    assert_eq!(b.totals().quarantined, 1);
}

#[test]
fn batch_attest_covers_records_and_every_counter_since_the_last_batch() {
    let w = world(Profile::InPerson, false);
    let mut b = OpenBox::open(w.config, tb(1));
    let mut m = mocks(&w);
    let mut j = MemJournal::default();
    let mut codes = std::vec![cast_one(&w, &mut b, &mut m, &mut j, 1)];
    challenge_one(&w, &mut b, &mut m, &mut j, 1);
    codes.push(cast_one(&w, &mut b, &mut m, &mut j, 1));
    assert_eq!(b.batch_records(), 2);
    let head = j.head();
    let attest = close(&w, &mut b, &mut m, &mut j, 2).unwrap();
    let parsed: BatchAttest<'_> =
        decode_object(SCHEMA_BATCH_ATTEST, SCHEMA_VERSION_1, &attest).unwrap();
    let body = parsed.body();
    assert_eq!(body.batch_index(), 0);
    assert_eq!(body.record_count(), 2);
    codes.sort_by_key(|h| h.0);
    assert_eq!(body.records_root(), &sorted_set_root(&codes).unwrap());
    assert_eq!(body.journal_head(), &head);
    for range in body.module_ranges() {
        assert_eq!((range.counter_first, range.counter_last), (1, 3));
    }
    assert!(body.module_refusals().is_empty());
    let purpose = Purpose::new(b"batch-attest").unwrap();
    let device = HybridSignature::decode(&mut Reader::new(parsed.device_sig())).unwrap();
    let _ = verify_hybrid(
        &w.device_hybrid.verifying_key(),
        &purpose,
        parsed.body_bytes(),
        &device,
    )
    .unwrap();
    assert_eq!(
        verified_signers(&m, &attest),
        ids(&[b"mod-a", b"mod-c", b"mod-j", b"mod-p1", b"mod-p2"])
    );
    // one dry run and one signature per module
    assert!(m.iter().all(|x| x.checks == 1 && x.signs == 1));
    assert!(m.iter().all(|x| x.pending.is_empty()));
    assert_eq!(b.totals().attested, 2);
    assert_eq!(b.batch_records(), 0);
    assert_eq!(b.batch_index(), 1);
    let e = entry(j.entries.last().unwrap());
    assert_eq!(e.kind(), JournalKind::BatchClose);
    assert_eq!(e.record_hash(), body.records_root());
    assert_eq!(e.module_counters().len(), 5);
    // the next batch starts after the attested counters
    cast_one(&w, &mut b, &mut m, &mut j, 3);
    let attest = close(&w, &mut b, &mut m, &mut j, 3).unwrap();
    let parsed: BatchAttest<'_> =
        decode_object(SCHEMA_BATCH_ATTEST, SCHEMA_VERSION_1, &attest).unwrap();
    for range in parsed.body().module_ranges() {
        assert_eq!((range.counter_first, range.counter_last), (4, 4));
    }
    assert_eq!(parsed.body().batch_index(), 1);
}

#[test]
fn a_refusing_module_is_listed_and_the_others_sign_once_without_cascade() {
    let w = world(Profile::InPerson, false);
    let mut b = OpenBox::open(w.config, tb(1));
    let mut m = mocks(&w);
    let mut j = MemJournal::default();
    cast_one(&w, &mut b, &mut m, &mut j, 1);
    m[2].refuse_batches = true; // mod-j
    let attest = close(&w, &mut b, &mut m, &mut j, 1).unwrap();
    assert_eq!(refusals(&attest), ids(&[b"mod-j"]));
    assert_eq!(
        verified_signers(&m, &attest),
        ids(&[b"mod-a", b"mod-c", b"mod-p1", b"mod-p2"])
    );
    for (i, module) in m.iter().enumerate() {
        assert_eq!(module.checks, 1);
        assert_eq!(module.signs, usize::from(i != 2), "{:?}", module.id);
    }
    // The consenting modules cleared their pending counters once, so the
    // next batch is signed by them again: the refusal did not cascade.
    m[2].refuse_batches = false;
    cast_one(&w, &mut b, &mut m, &mut j, 2);
    let attest = close(&w, &mut b, &mut m, &mut j, 2).unwrap();
    // mod-j still holds counter 1 as pending, so its range 2..=2 fails
    assert_eq!(refusals(&attest), ids(&[b"mod-j"]));
    assert_eq!(verified_signers(&m, &attest).len(), 4);
    assert!(m.iter().enumerate().all(|(i, x)| i == 2 || x.signs == 2));
}

#[test]
fn every_module_refusing_still_closes_with_all_listed() {
    let w = world(Profile::InPerson, false);
    let mut b = OpenBox::open(w.config, tb(1));
    let mut m = mocks(&w);
    let mut j = MemJournal::default();
    cast_one(&w, &mut b, &mut m, &mut j, 1);
    for module in &mut m {
        module.refuse_batches = true;
    }
    let attest = close(&w, &mut b, &mut m, &mut j, 1).unwrap();
    assert_eq!(refusals(&attest).len(), 5);
    assert!(verified_signers(&m, &attest).is_empty());
    assert!(m.iter().all(|x| x.signs == 0));
    assert_eq!(b.batch_records(), 0);
}

#[test]
fn a_module_that_consents_then_refuses_or_signs_wrongly_leaves_the_batch_open() {
    let w = world(Profile::InPerson, false);
    let mut b = OpenBox::open(w.config, tb(1));
    let mut m = mocks(&w);
    let mut j = MemJournal::default();
    cast_one(&w, &mut b, &mut m, &mut j, 1);
    m[4].refuse_at_signing = true;
    assert_eq!(
        close(&w, &mut b, &mut m, &mut j, 1).unwrap_err(),
        Error::Port(PortError::Refused)
    );
    assert_eq!(
        (b.batch_records(), b.batch_index(), j.entries.len()),
        (1, 0, 3)
    );
    let mut m = mocks(&w);
    let mut b2 = OpenBox::open(w.config, tb(1));
    let mut j2 = MemJournal::default();
    cast_one(&w, &mut b2, &mut m, &mut j2, 1);
    m[1].wrong_batch_key = true;
    assert_eq!(
        close(&w, &mut b2, &mut m, &mut j2, 1).unwrap_err(),
        Error::BatchSignature
    );
    assert_eq!(b2.batch_records(), 1);
    assert_eq!(
        kinds(&j2),
        [
            JournalKind::Record,
            JournalKind::VisitDecision,
            JournalKind::Imprinted
        ]
    );
    assert!(!b2.is_faulted());
}

#[test]
fn batch_close_checks_every_precondition_before_asking_a_module() {
    let w = world(Profile::InPerson, false);
    let mut b = OpenBox::open(w.config, tb(1));
    let mut m = mocks(&w);
    let mut j = MemJournal::default();
    let mut out = std::vec![0u8; BATCH_WORK_LEN];
    assert_eq!(
        close(&w, &mut b, &mut m, &mut j, 1).unwrap_err(),
        Error::BatchEmpty
    );
    cast_one(&w, &mut b, &mut m, &mut j, 5);
    let head = j.head();
    assert_eq!(
        b.close_batch(
            &head,
            &mut ports(&mut m[..4]),
            signer(&w),
            &mut j,
            tb(5),
            &mut out
        ),
        Err(Error::PortCount)
    );
    assert_eq!(
        close(&w, &mut b, &mut m, &mut j, 4).unwrap_err(),
        Error::TimeRegression
    );
    let mut small = std::vec![0u8; BATCH_WORK_LEN - 1];
    assert_eq!(
        b.close_batch(
            &head,
            &mut ports(&mut m),
            signer(&w),
            &mut j,
            tb(5),
            &mut small
        ),
        Err(Error::BufferTooSmall)
    );
    let mut area = work();
    let _ballot = b
        .interpret(&interpretation(b"E-2026", STYLE_SMALL, 1), &mut area)
        .unwrap();
    assert_eq!(
        b.close_batch(
            &head,
            &mut ports(&mut m),
            signer(&w),
            &mut j,
            tb(5),
            &mut out
        ),
        Err(Error::VisitOpen)
    );
    assert!(m.iter().all(|x| x.checks == 0 && x.signs == 0));
    assert_eq!(b.batch_records(), 1);
    assert!(!b.is_faulted());
}

#[test]
fn a_journal_mismatch_latches_the_box() {
    let w = world(Profile::InPerson, false);
    let mut b = OpenBox::open(w.config, tb(1));
    let mut m = mocks(&w);
    let mut j = MemJournal::default();
    cast_one(&w, &mut b, &mut m, &mut j, 1);
    // storage lost the last entry: the head the host re-reads differs
    let rewound = Hash512::ZERO;
    let mut out = std::vec![0u8; BATCH_WORK_LEN];
    assert_eq!(
        b.close_batch(
            &rewound,
            &mut ports(&mut m),
            signer(&w),
            &mut j,
            tb(1),
            &mut out
        ),
        Err(Error::JournalMismatch)
    );
    assert!(b.is_faulted());
    assert!(m.iter().all(|x| x.checks == 0));
    // everything is refused from now on, even with the right head
    assert_eq!(
        close(&w, &mut b, &mut m, &mut j, 1).unwrap_err(),
        Error::JournalMismatch
    );
    let mut area = work();
    assert_eq!(
        b.interpret(&interpretation(b"E-2026", STYLE_SMALL, 1), &mut area)
            .unwrap_err(),
        Error::JournalMismatch
    );
    let mut small = std::vec![0u8; 512];
    assert_eq!(
        b.scan_count_body(tb(1), &mut small).unwrap_err(),
        Error::JournalMismatch
    );
    let mut close_out = std::vec![0u8; CLOSE_WORK_LEN];
    let inputs = CloseInputs {
        paper: 1,
        without_record: 0,
        spoiled_envelopes: 0,
        envelopes: None,
        fallback_declared: false,
        record_set_root: Hash512::ZERO,
        seal_digest: Hash512::ZERO,
    };
    assert_eq!(
        b.prepare_close(&inputs, signer(&w), &mut j, tb(1), &mut close_out)
            .unwrap_err(),
        Error::JournalMismatch
    );
    assert_eq!(
        kinds(&j),
        [
            JournalKind::Record,
            JournalKind::VisitDecision,
            JournalKind::Imprinted
        ]
    );
}

#[test]
fn batch_triggers_on_idle_time_and_refuses_the_sixty_fifth_record() {
    let w = world(Profile::InPerson, false);
    let mut b = OpenBox::open(w.config, tb(1));
    let mut m = mocks(&w);
    let mut j = MemJournal::default();
    assert!(!b.batch_due(tb(100)));
    cast_one(&w, &mut b, &mut m, &mut j, 5);
    assert!(!b.batch_due(tb(5)));
    assert!(b.batch_due(tb(6)));
    // a visit starts only while the batch has room for eight more records
    for _ in 1..56 {
        cast_one(&w, &mut b, &mut m, &mut j, 5);
    }
    assert_eq!(b.batch_records(), 56);
    assert!(!b.batch_due(tb(5)));
    cast_one(&w, &mut b, &mut m, &mut j, 5);
    assert_eq!(b.batch_records(), 57);
    assert!(b.batch_due(tb(5)));
    let mut area = work();
    assert_eq!(
        b.interpret(&interpretation(b"E-2026", STYLE_SMALL, 1), &mut area)
            .unwrap_err(),
        Error::BatchFull
    );
}

#[test]
fn scan_count_is_due_after_fifty_records_or_eight_buckets() {
    let w = world(Profile::InPerson, false);
    let mut b = OpenBox::open(w.config, tb(10));
    let mut m = mocks(&w);
    let mut j = MemJournal::default();
    assert!(!b.scan_count_due(tb(17)));
    assert!(b.scan_count_due(tb(18)));
    cast_one(&w, &mut b, &mut m, &mut j, 11);
    let mut out = std::vec![0u8; 512];
    let body = b.scan_count_body(tb(12), &mut out).unwrap().to_vec();
    let parsed: ScanCountAttestBody<'_> =
        decode_object(SCHEMA_SCAN_COUNT_ATTEST_BODY, SCHEMA_VERSION_1, &body).unwrap();
    assert_eq!(parsed.record_count(), 1);
    assert_eq!(parsed.journal_head(), b.journal_head());
    assert!(!b.scan_count_due(tb(19)));
    assert!(b.scan_count_due(tb(20)));
    for _ in 0..49 {
        cast_one(&w, &mut b, &mut m, &mut j, 12);
        if b.batch_due(tb(12)) {
            close(&w, &mut b, &mut m, &mut j, 12).unwrap();
        }
    }
    assert!(!b.scan_count_due(tb(12)));
    cast_one(&w, &mut b, &mut m, &mut j, 12);
    assert!(b.scan_count_due(tb(12)));
    assert_eq!(
        b.scan_count_body(tb(11), &mut out).unwrap_err(),
        Error::TimeRegression
    );
}

#[test]
fn scan_count_is_refused_mid_visit_and_holds_the_time_line() {
    let w = world(Profile::InPerson, false);
    let mut b = OpenBox::open(w.config, tb(1));
    let mut m = mocks(&w);
    let mut j = MemJournal::default();
    let mut out = std::vec![0u8; 512];
    let mut area = work();
    let ballot = b
        .interpret(&interpretation(b"E-2026", STYLE_SMALL, 1), &mut area)
        .unwrap();
    assert_eq!(
        b.scan_count_body(tb(1), &mut out).unwrap_err(),
        Error::VisitOpen
    );
    drop(ballot);
    b.abandon_visit(&mut j, tb(1)).unwrap();
    b.scan_count_body(tb(9), &mut out).unwrap();
    // nothing journaled afterwards may carry an earlier bucket
    let mut staging = MemStaging::default();
    let mut visit = visit_work();
    build_position(&w, &mut b, &mut m, &mut staging, &mut visit, STYLE_SMALL, 1);
    let ready = b.end_visit(&visit_end(b"E-2026", 1), &mut visit).unwrap();
    let mut package = std::vec![0u8; 300_000];
    assert_eq!(
        ready
            .decide(
                &mut b,
                Decision::CAST_ALL,
                &mut j,
                &mut staging,
                &mut package,
                tb(8)
            )
            .unwrap_err(),
        Error::TimeRegression
    );
}

/// Builds `n` small-style positions and ends the visit; returns the codes.
fn bind_visit(
    w: &World,
    b: &mut OpenBox<'static>,
    m: &mut [MockModule],
    staging: &mut MemStaging,
    visit: &mut ityv_cunit::VisitWork,
    n: u8,
) -> std::vec::Vec<Hash512> {
    (0..n)
        .map(|i| {
            *build_position(w, b, m, staging, visit, STYLE_SMALL, u16::from(i % 4)).tracking_code()
        })
        .collect()
}

#[test]
fn imprint_failure_quarantines_and_withdraws_the_record() {
    let w = world(Profile::InPerson, false);
    let mut b = OpenBox::open(w.config, tb(1));
    let mut m = mocks(&w);
    let mut j = MemJournal::default();
    let first = cast_one(&w, &mut b, &mut m, &mut j, 1);
    let mut staging = MemStaging::default();
    let mut visit = visit_work();
    let codes = bind_visit(&w, &mut b, &mut m, &mut staging, &mut visit, 3);
    let ready = b.end_visit(&visit_end(b"E-2026", 3), &mut visit).unwrap();
    let mut package = std::vec![0u8; 300_000];
    let mut decided = ready
        .decide(
            &mut b,
            Decision::CAST_ALL,
            &mut j,
            &mut staging,
            &mut package,
            tb(2),
        )
        .unwrap();
    assert_eq!((b.totals().records, b.batch_records()), (4, 4));
    decided.imprinted(&mut b, &mut j, tb(2)).unwrap();
    // the middle position's imprint fails: its record leaves the batch,
    // the others go on
    decided.imprint_failed(&mut b, &mut j, tb(2)).unwrap();
    assert_eq!(b.totals().records, 3);
    assert_eq!(b.totals().quarantined, 1);
    assert_eq!(b.totals().visits, 2, "the visit still has cast ballots");
    assert_eq!(b.batch_records(), 3);
    let e = entry(j.entries.last().unwrap());
    assert_eq!(e.kind(), JournalKind::Quarantine);
    assert_eq!(e.record_hash(), &codes[1]);
    assert_eq!(e.module_counters().len(), 5);
    decided.imprinted(&mut b, &mut j, tb(2)).unwrap();
    decided
        .finish_positions(&mut b)
        .unwrap()
        .finish(&mut b)
        .unwrap();
    // the batch holds the other three records
    let attest = close(&w, &mut b, &mut m, &mut j, 2).unwrap();
    let parsed: BatchAttest<'_> =
        decode_object(SCHEMA_BATCH_ATTEST, SCHEMA_VERSION_1, &attest).unwrap();
    assert_eq!(parsed.body().record_count(), 3);
    let mut kept = std::vec![first, codes[0], codes[2]];
    kept.sort_by_key(|h| h.0);
    assert_eq!(
        parsed.body().records_root(),
        &sorted_set_root(&kept).unwrap()
    );
}

#[test]
fn an_imprint_failure_whose_entry_fails_stays_to_be_quarantined() {
    let w = world(Profile::InPerson, false);
    let mut b = OpenBox::open(w.config, tb(1));
    let mut m = mocks(&w);
    let mut j = MemJournal::default();
    let mut staging = MemStaging::default();
    let mut visit = visit_work();
    let codes = bind_visit(&w, &mut b, &mut m, &mut staging, &mut visit, 1);
    let ready = b.end_visit(&visit_end(b"E-2026", 1), &mut visit).unwrap();
    let mut package = std::vec![0u8; 300_000];
    let mut decided = ready
        .decide(
            &mut b,
            Decision::CAST_ALL,
            &mut j,
            &mut staging,
            &mut package,
            tb(1),
        )
        .unwrap();
    j.fail = true;
    assert_eq!(
        decided.imprint_failed(&mut b, &mut j, tb(1)).unwrap_err(),
        Error::Journal(JournalError::NotDurable)
    );
    assert_eq!(
        decided.imprinted(&mut b, &mut j, tb(1)).unwrap_err(),
        Error::Journal(JournalError::NotDurable)
    );
    // the record still stands until a quarantine entry is durable
    assert_eq!((b.totals().records, b.batch_records()), (1, 1));
    assert!(b.has_visit_open());
    drop(decided);
    j.fail = false;
    b.abandon_visit(&mut j, tb(1)).unwrap();
    assert_eq!((b.totals().records, b.batch_records()), (0, 0));
    assert_eq!((b.totals().quarantined, b.totals().visits), (1, 0));
    assert_eq!(entry(j.entries.last().unwrap()).record_hash(), &codes[0]);
    assert_eq!(b.abandon_visit(&mut j, tb(1)).unwrap_err(), Error::NoVisit);
}

#[test]
fn a_dropped_decided_visit_is_quarantined_by_its_record_hashes() {
    let w = world(Profile::InPerson, false);
    let mut b = OpenBox::open(w.config, tb(1));
    let mut m = mocks(&w);
    let mut j = MemJournal::default();
    let mut staging = MemStaging::default();
    let mut visit = visit_work();
    let codes = bind_visit(&w, &mut b, &mut m, &mut staging, &mut visit, 3);
    let ready = b.end_visit(&visit_end(b"E-2026", 3), &mut visit).unwrap();
    let mut package = std::vec![0u8; 300_000];
    let mut decided = ready
        .decide(
            &mut b,
            Decision::checking(&[2]).unwrap(),
            &mut j,
            &mut staging,
            &mut package,
            tb(1),
        )
        .unwrap();
    decided.imprinted(&mut b, &mut j, tb(1)).unwrap();
    drop(decided);
    b.abandon_visit(&mut j, tb(1)).unwrap();
    // the imprinted one stays cast; the open cast one is quarantined; the
    // checked one needs nothing more
    let e = entry(j.entries.last().unwrap());
    assert_eq!(e.kind(), JournalKind::Quarantine);
    assert_eq!(e.record_hash(), &codes[1]);
    assert_eq!(
        (
            b.totals().records,
            b.totals().challenged,
            b.totals().quarantined
        ),
        (1, 1, 1)
    );
    assert_eq!(b.batch_records(), 1);
    assert_eq!(b.module_counters(), &[3, 3, 3, 3, 3]);
}

#[test]
fn a_journal_failure_at_the_decision_leaves_the_visit_to_quarantine() {
    let w = world(Profile::InPerson, false);
    let mut b = OpenBox::open(w.config, tb(1));
    let mut m = mocks(&w);
    let mut j = MemJournal::default();
    let mut staging = MemStaging::default();
    let mut visit = visit_work();
    bind_visit(&w, &mut b, &mut m, &mut staging, &mut visit, 1);
    let ready = b.end_visit(&visit_end(b"E-2026", 1), &mut visit).unwrap();
    let mut package = std::vec![0u8; 300_000];
    j.fail = true;
    assert_eq!(
        ready
            .decide(
                &mut b,
                Decision::CAST_ALL,
                &mut j,
                &mut staging,
                &mut package,
                tb(1)
            )
            .unwrap_err(),
        Error::Journal(JournalError::NotDurable)
    );
    assert_eq!(b.totals().records, 0);
    assert!(b.has_visit_open());
    assert_eq!(
        b.abandon_visit(&mut j, tb(1)).unwrap_err(),
        Error::Journal(JournalError::NotDurable)
    );
    j.fail = false;
    b.abandon_visit(&mut j, tb(1)).unwrap();
    assert_eq!(b.totals().quarantined, 1);
    assert_eq!(kinds(&j), [JournalKind::Quarantine]);
    assert_eq!(entry(&j.entries[0]).record_hash(), &Hash512::ZERO);
    assert_eq!(entry(&j.entries[0]).module_counters().len(), 5);
    assert_eq!(b.abandon_visit(&mut j, tb(1)).unwrap_err(), Error::NoVisit);
    // a failure after the first position entry: that one is quarantined by
    // its record hash, the second without record
    let mut visit = visit_work();
    let codes = bind_visit(&w, &mut b, &mut m, &mut staging, &mut visit, 2);
    let ready = b.end_visit(&visit_end(b"E-2026", 2), &mut visit).unwrap();
    j.fail_after = Some(1);
    assert!(
        ready
            .decide(
                &mut b,
                Decision::CAST_ALL,
                &mut j,
                &mut staging,
                &mut package,
                tb(1)
            )
            .is_err()
    );
    j.fail_after = None;
    b.abandon_visit(&mut j, tb(1)).unwrap();
    let tail: std::vec::Vec<JournalKind> = kinds(&j)[1..].to_vec();
    assert_eq!(
        tail,
        [
            JournalKind::Record,
            JournalKind::Quarantine,
            JournalKind::Quarantine
        ]
    );
    assert_eq!(entry(&j.entries[2]).record_hash(), &codes[0]);
    assert_eq!(entry(&j.entries[3]).record_hash(), &Hash512::ZERO);
    assert_eq!((b.totals().records, b.totals().quarantined), (0, 3));
    assert_eq!(b.batch_records(), 0);
}

#[test]
fn a_staged_object_that_changed_is_refused() {
    let w = world(Profile::InPerson, false);
    let mut b = OpenBox::open(w.config, tb(1));
    let mut m = mocks(&w);
    let mut j = MemJournal::default();
    let mut staging = MemStaging::default();
    let mut visit = visit_work();
    bind_visit(&w, &mut b, &mut m, &mut staging, &mut visit, 2);
    let ready = b.end_visit(&visit_end(b"E-2026", 2), &mut visit).unwrap();
    let mut package = std::vec![0u8; 300_000];
    staging.tamper = Some((1, Staged::Package));
    assert_eq!(
        ready
            .decide(
                &mut b,
                Decision::CAST_ALL,
                &mut j,
                &mut staging,
                &mut package,
                tb(1)
            )
            .unwrap_err(),
        Error::StagedMismatch
    );
    // the first position was journaled before the swap was found
    assert_eq!(kinds(&j), [JournalKind::Record]);
    b.abandon_visit(&mut j, tb(1)).unwrap();
    // a swapped record is refused for publication
    staging.tamper = None;
    let mut visit = visit_work();
    bind_visit(&w, &mut b, &mut m, &mut staging, &mut visit, 1);
    let ready = b.end_visit(&visit_end(b"E-2026", 1), &mut visit).unwrap();
    let decided = ready
        .decide(
            &mut b,
            Decision::CAST_ALL,
            &mut j,
            &mut staging,
            &mut package,
            tb(1),
        )
        .unwrap();
    let mut out = std::vec![0u8; 30_000];
    assert!(decided.record(&b, &mut staging, 0, &mut out).is_ok());
    staging.tamper = Some((0, Staged::Record));
    assert_eq!(
        decided.record(&b, &mut staging, 0, &mut out).unwrap_err(),
        Error::StagedMismatch
    );
    let mut small = std::vec![0u8; 16];
    assert_eq!(
        decided.record(&b, &mut staging, 0, &mut small).unwrap_err(),
        Error::Port(PortError::BufferTooSmall)
    );
    assert!(decided.record(&b, &mut staging, 1, &mut out).is_err());
}

#[test]
fn a_visit_end_must_match_and_the_visit_takes_eight_positions() {
    let w = world(Profile::InPerson, false);
    let mut b = OpenBox::open(w.config, tb(1));
    let mut m = mocks(&w);
    let mut j = MemJournal::default();
    let mut staging = MemStaging::default();
    let mut visit = visit_work();
    let mut other = visit_work();
    assert_eq!(
        b.end_visit(&visit_end(b"E-2026", 1), &mut visit)
            .unwrap_err(),
        Error::NoVisit
    );
    bind_visit(&w, &mut b, &mut m, &mut staging, &mut visit, 8);
    let mut area = work();
    assert_eq!(
        b.interpret(&interpretation(b"E-2026", STYLE_SMALL, 1), &mut area)
            .unwrap_err(),
        Error::VisitFull
    );
    assert_eq!(
        b.end_visit(&visit_end(b"E-2027", 8), &mut visit)
            .unwrap_err(),
        Error::WrongElection
    );
    assert_eq!(
        b.end_visit(&visit_end(b"E-2026", 7), &mut visit)
            .unwrap_err(),
        Error::VisitCountMismatch
    );
    assert_eq!(
        b.end_visit(&visit_end(b"E-2026", 8), &mut other)
            .unwrap_err(),
        Error::StaleVisit
    );
    assert!(b.end_visit(&[0u8; 8], &mut visit).is_err());
    // the clerks confirm and the visit is quarantined without a decision:
    // one entry without record per position, with its counters
    b.abandon_visit(&mut j, tb(1)).unwrap();
    assert_eq!(kinds(&j), [JournalKind::Quarantine; 8]);
    assert!(
        j.entries
            .iter()
            .all(|e| entry(e).record_hash() == &Hash512::ZERO)
    );
    assert_eq!(b.totals().quarantined, 8);
    assert_eq!(b.module_counters(), &[8, 8, 8, 8, 8]);
    // the abandoned visit's work area cannot end the next visit, even one
    // with as many positions
    bind_visit(&w, &mut b, &mut m, &mut staging, &mut other, 8);
    assert_eq!(
        b.end_visit(&visit_end(b"E-2026", 8), &mut visit)
            .unwrap_err(),
        Error::StaleVisit
    );
    b.abandon_visit(&mut j, tb(1)).unwrap();
    // after the end, no new position and no second end
    let mut visit = visit_work();
    bind_visit(&w, &mut b, &mut m, &mut staging, &mut visit, 1);
    let ready = b.end_visit(&visit_end(b"E-2026", 1), &mut visit).unwrap();
    assert_eq!(
        b.interpret(&interpretation(b"E-2026", STYLE_SMALL, 1), &mut area)
            .unwrap_err(),
        Error::VisitInProgress
    );
    let mut again = visit_work();
    assert_eq!(
        b.end_visit(&visit_end(b"E-2026", 1), &mut again)
            .unwrap_err(),
        Error::VisitInProgress
    );
    // a decision may not check a position beyond the visit
    let mut package = std::vec![0u8; 300_000];
    assert_eq!(
        ready
            .decide(
                &mut b,
                Decision::from_checks(0b10),
                &mut j,
                &mut staging,
                &mut package,
                tb(1)
            )
            .unwrap_err(),
        Error::InvalidDecision
    );
}

#[test]
fn a_ballot_quarantined_by_the_box_is_stale() {
    let w = world(Profile::InPerson, false);
    let mut b = OpenBox::open(w.config, tb(1));
    let mut m = mocks(&w);
    let mut j = MemJournal::default();
    let mut first = work();
    let mut second = work();
    let ballot = b
        .interpret(&interpretation(b"E-2026", STYLE_SMALL, 2), &mut first)
        .unwrap();
    let ballot = ballot.issue(&mut b, &mut ports(&mut m), &SEED).unwrap();
    b.abandon_visit(&mut j, tb(1)).unwrap();
    assert_eq!(ballot.commit(&b).unwrap_err(), Error::NoBallotInFlight);
    // a newer ballot makes the old one stale rather than absent
    let ballot = b
        .interpret(&interpretation(b"E-2026", STYLE_SMALL, 1), &mut first)
        .unwrap();
    let other = b.interpret(&interpretation(b"E-2026", STYLE_SMALL, 1), &mut second);
    assert_eq!(other.unwrap_err(), Error::BallotInFlight);
    b.abandon_visit(&mut j, tb(1)).unwrap();
    let _fresh = b
        .interpret(&interpretation(b"E-2026", STYLE_SMALL, 1), &mut second)
        .unwrap();
    assert_eq!(
        ballot.issue(&mut b, &mut ports(&mut m), &SEED).unwrap_err(),
        Error::StaleBallot
    );
}

#[test]
fn a_visit_state_is_bound_to_its_own_visit() {
    let w = world(Profile::InPerson, true);
    let mut b = OpenBox::open(w.config, tb(1));
    let mut m = mocks(&w);
    let mut j = MemJournal::default();
    let mut staging = MemStaging::default();
    let mut visit = visit_work();
    bind_visit(&w, &mut b, &mut m, &mut staging, &mut visit, 1);
    let ready = b.end_visit(&visit_end(b"E-2026", 1), &mut visit).unwrap();
    let mut package = std::vec![0u8; 300_000];
    let decided = ready
        .decide(
            &mut b,
            Decision::CAST_ALL,
            &mut j,
            &mut staging,
            &mut package,
            tb(1),
        )
        .unwrap();
    assert!(decided.imprint_command(&b).is_ok());
    assert_eq!(
        decided.finish_positions(&mut b).unwrap_err(),
        Error::VisitIncomplete
    );
    // (finish_positions consumed the state; the box still holds the visit)
    b.abandon_visit(&mut j, tb(1)).unwrap();
    // a fresh visit: the old one's ready state no longer exists, and a
    // second box's states cannot act on this one
    let mut visit = visit_work();
    bind_visit(&w, &mut b, &mut m, &mut staging, &mut visit, 1);
    let ready = b.end_visit(&visit_end(b"E-2026", 1), &mut visit).unwrap();
    let mut other_box = OpenBox::open(w.config, tb(1));
    assert_eq!(ready.positions(&other_box), 0);
    assert!(ready.style(&other_box, 0).is_none());
    assert_eq!(
        ready
            .decide(
                &mut other_box,
                Decision::CAST_ALL,
                &mut j,
                &mut staging,
                &mut package,
                tb(1)
            )
            .unwrap_err(),
        Error::NoVisit
    );
    b.abandon_visit(&mut j, tb(1)).unwrap();
    let mut visit = visit_work();
    bind_visit(&w, &mut b, &mut m, &mut staging, &mut visit, 1);
    let ready = b.end_visit(&visit_end(b"E-2026", 1), &mut visit).unwrap();
    let decided = ready
        .decide(
            &mut b,
            Decision::CAST_ALL,
            &mut j,
            &mut staging,
            &mut package,
            tb(1),
        )
        .unwrap();
    let mut other_visit = visit_work();
    let mut other_modules = mocks(&w);
    bind_visit(
        &w,
        &mut other_box,
        &mut other_modules,
        &mut staging,
        &mut other_visit,
        1,
    );
    assert_eq!(decided.current(&other_box), None);
    assert_eq!(
        decided.imprint_command(&other_box).err(),
        Some(Error::StaleVisit)
    );
    assert_eq!(
        decided.finish_positions(&mut other_box).err(),
        Some(Error::StaleVisit)
    );
}

#[test]
fn a_ballot_without_any_issue_is_returned_not_quarantined() {
    let w = world(Profile::InPerson, false);
    let mut b = OpenBox::open(w.config, tb(1));
    let mut m = mocks(&w);
    let mut j = MemJournal::default();
    m[0].fail_issue = true;
    let mut area = work();
    let ballot = b
        .interpret(&interpretation(b"E-2026", STYLE_SMALL, 2), &mut area)
        .unwrap();
    assert_eq!(
        ballot.issue(&mut b, &mut ports(&mut m), &SEED).unwrap_err(),
        Error::Port(PortError::Transport)
    );
    b.abandon_visit(&mut j, tb(1)).unwrap();
    assert!(j.entries.is_empty());
    assert_eq!(b.totals().quarantined, 0);
}

#[test]
fn time_buckets_must_not_go_back() {
    let w = world(Profile::InPerson, false);
    let mut b = OpenBox::open(w.config, tb(5));
    let mut m = mocks(&w);
    let mut j = MemJournal::default();
    let mut bufs = Buffers::new(&w);
    let mut area = work();
    let ballot = b
        .interpret(&interpretation(b"E-2026", STYLE_SMALL, 2), &mut area)
        .unwrap();
    let ballot = ballot.issue(&mut b, &mut ports(&mut m), &SEED).unwrap();
    let ballot = ballot.commit(&b).unwrap();
    let ballot = ballot
        .build(&b, &mut ports(&mut m), &w.device_record, bufs.as_build())
        .unwrap();
    let mut staging = MemStaging::default();
    let mut visit = visit_work();
    ballot.bind(&mut b, &mut staging, &mut visit).unwrap();
    let ready = b.end_visit(&visit_end(b"E-2026", 1), &mut visit).unwrap();
    let mut package = std::vec![0u8; 300_000];
    assert_eq!(
        ready
            .decide(
                &mut b,
                Decision::CAST_ALL,
                &mut j,
                &mut staging,
                &mut package,
                tb(4)
            )
            .unwrap_err(),
        Error::TimeRegression
    );
    assert_eq!(
        b.abandon_visit(&mut j, tb(4)).unwrap_err(),
        Error::TimeRegression
    );
}

/// A box with `n` records, one challenge and one quarantine, batch closed.
fn busy_box(
    w: &World,
    m: &mut [MockModule],
    j: &mut MemJournal,
    n: usize,
) -> (OpenBox<'static>, std::vec::Vec<Hash512>) {
    let mut b = OpenBox::open(w.config, tb(1));
    let mut codes = std::vec::Vec::new();
    for _ in 0..n {
        codes.push(cast_one(w, &mut b, m, j, 1));
    }
    challenge_one(w, &mut b, m, j, 1);
    let mut area = work();
    let ballot = b
        .interpret(&interpretation(b"E-2026", STYLE_SMALL, 2), &mut area)
        .unwrap();
    let _ = ballot.issue(&mut b, &mut ports(m), &SEED).unwrap();
    b.abandon_visit(j, tb(1)).unwrap();
    close(w, &mut b, m, j, 1).unwrap();
    (b, codes)
}

fn good_inputs(codes: &mut [Hash512]) -> CloseInputs {
    codes.sort_by_key(|h| h.0);
    CloseInputs {
        paper: codes.len() as u64,
        without_record: 0,
        spoiled_envelopes: 2,
        envelopes: None,
        fallback_declared: false,
        record_set_root: sorted_set_root(codes).unwrap(),
        seal_digest: Hash512([7; 64]),
    }
}

#[test]
fn a_consistent_box_closes_without_violations() {
    let w = world(Profile::InPerson, false);
    let mut m = mocks(&w);
    let mut j = MemJournal::default();
    let (mut b, mut codes) = busy_box(&w, &mut m, &mut j, 2);
    let inputs = good_inputs(&mut codes);
    let mut out = std::vec![0u8; CLOSE_WORK_LEN];
    let head_before = *b.journal_head();
    let closed_out = b
        .prepare_close(&inputs, signer(&w), &mut j, tb(2), &mut out)
        .unwrap();
    assert!(closed_out.verdict.is_empty());
    let body: BoxCloseBody<'_> =
        decode_object(SCHEMA_BOX_CLOSE_BODY, SCHEMA_VERSION_1, closed_out.body).unwrap();
    let counts = body.counts();
    assert_eq!(
        (
            counts.records,
            counts.attested,
            counts.challenged,
            counts.quarantined
        ),
        (2, 2, 1, 1)
    );
    // in person: one visit per record, no envelopes or stickers
    assert_eq!(
        (counts.visits, counts.envelopes, counts.stickers),
        (2, 0, 0)
    );
    assert_eq!(b.totals().visits, 2);
    assert_eq!(body.journal_head(), &head_before);
    assert_eq!(body.record_set_root(), &inputs.record_set_root);
    assert_eq!(body.open_batches(), 0);
    for counter in body.module_counters().iter() {
        assert_eq!(counter.counter, 4);
    }
    let sig = HybridSignature::decode(&mut Reader::new(closed_out.device_sig)).unwrap();
    let _ = verify_hybrid(
        &w.device_hybrid.verifying_key(),
        &Purpose::new(b"box-close").unwrap(),
        closed_out.body,
        &sig,
    )
    .unwrap();
    let body_hash = ityv_crypto::object_hash(closed_out.body);
    let token = closed_out.token;
    assert_eq!(token.close_body_hash(), &body_hash);
    let e = entry(j.entries.last().unwrap());
    assert_eq!(e.kind(), JournalKind::BoxClose);
    assert_eq!(e.record_hash(), &inputs.record_set_root);
    // closing twice, interpreting or batching after close is refused
    let mut again = std::vec![0u8; CLOSE_WORK_LEN];
    assert_eq!(
        b.prepare_close(&inputs, signer(&w), &mut j, tb(2), &mut again)
            .unwrap_err(),
        Error::BoxClosed
    );
    let mut area = work();
    assert_eq!(
        b.interpret(&interpretation(b"E-2026", STYLE_SMALL, 1), &mut area)
            .unwrap_err(),
        Error::BoxClosed
    );
    let mut small = std::vec![0u8; 512];
    assert_eq!(
        b.scan_count_body(tb(2), &mut small).unwrap_err(),
        Error::BoxClosed
    );
    let closed = b.into_closed(token).unwrap();
    assert_eq!(closed.totals().records, 2);
    assert_eq!(closed.module_counters(), &[4, 4, 4, 4, 4]);
    assert_eq!(closed.close_body_hash(), &body_hash);
    assert_eq!(closed.journal_head(), &j.head());
    assert!(core::ptr::eq(closed.config(), w.config));
}

#[test]
fn a_close_token_opens_only_its_own_box() {
    let w = world(Profile::InPerson, false);
    let mut m = mocks(&w);
    let mut j = MemJournal::default();
    let (mut first, mut codes) = busy_box(&w, &mut m, &mut j, 1);
    let mut m2 = mocks(&w);
    let mut j2 = MemJournal::default();
    let (mut second, _) = busy_box(&w, &mut m2, &mut j2, 2);
    let inputs = good_inputs(&mut codes);
    let mut out = std::vec![0u8; CLOSE_WORK_LEN];
    let token_first = first
        .prepare_close(&inputs, signer(&w), &mut j, tb(3), &mut out)
        .unwrap()
        .token;
    let mut out2 = std::vec![0u8; CLOSE_WORK_LEN];
    let token_second = second
        .prepare_close(&inputs, signer(&w), &mut j2, tb(3), &mut out2)
        .unwrap()
        .token;
    assert_ne!(token_first, token_second);
    assert_eq!(
        second.into_closed(token_first).unwrap_err(),
        Error::ForeignCloseToken
    );
    // a token cannot close a box that has not been closed
    let open = OpenBox::open(w.config, tb(1));
    assert_eq!(
        open.into_closed(token_second).unwrap_err(),
        Error::ForeignCloseToken
    );
}

#[test]
fn close_checks_its_preconditions_before_signing() {
    let w = world(Profile::InPerson, false);
    let mut m = mocks(&w);
    let mut j = MemJournal::default();
    let (mut b, mut codes) = busy_box(&w, &mut m, &mut j, 1);
    let good = good_inputs(&mut codes);
    let entries = j.entries.len();
    let mut out = std::vec![0u8; CLOSE_WORK_LEN];
    assert_eq!(
        b.prepare_close(&good, signer(&w), &mut j, tb(0), &mut out)
            .unwrap_err(),
        Error::TimeRegression
    );
    let in_person_with_envelopes = CloseInputs {
        envelopes: Some(ENVELOPES_ONE),
        ..good
    };
    assert_eq!(
        b.prepare_close(
            &in_person_with_envelopes,
            signer(&w),
            &mut j,
            tb(1),
            &mut out
        )
        .unwrap_err(),
        Error::EnvelopeCountProfile
    );
    let mut small = std::vec![0u8; CLOSE_WORK_LEN - 1];
    assert_eq!(
        b.prepare_close(&good, signer(&w), &mut j, tb(1), &mut small)
            .unwrap_err(),
        Error::BufferTooSmall
    );
    assert!(small.iter().all(|&byte| byte == 0), "no body was written");
    let mut area = work();
    let ballot = b
        .interpret(&interpretation(b"E-2026", STYLE_SMALL, 1), &mut area)
        .unwrap();
    assert_eq!(
        b.prepare_close(&good, signer(&w), &mut j, tb(1), &mut out)
            .unwrap_err(),
        Error::VisitOpen
    );
    drop(ballot);
    b.abandon_visit(&mut j, tb(1)).unwrap();
    assert_eq!(j.entries.len(), entries);
    assert!(out.iter().all(|&byte| byte == 0), "nothing was signed");
    // a larger work buffer is fine
    let mut roomy = std::vec![0u8; CLOSE_WORK_LEN + 64];
    b.prepare_close(&good, signer(&w), &mut j, tb(1), &mut roomy)
        .unwrap();
}

/// One envelope with one sticker, from three issued and two returned
/// empty.
const ENVELOPES_ONE: EnvelopeCounts = EnvelopeCounts {
    envelopes: 1,
    stickers: 1,
    issued: 3,
    returned_empty: 2,
};

#[test]
fn an_absentee_box_must_count_its_envelopes_and_stickers() {
    let w = world(Profile::Absentee, false);
    let mut m = mocks(&w);
    let mut j = MemJournal::default();
    let mut b = OpenBox::open(w.config, tb(1));
    let mut codes = std::vec![cast_one(&w, &mut b, &mut m, &mut j, 1)];
    close(&w, &mut b, &mut m, &mut j, 1).unwrap();
    let base = CloseInputs {
        spoiled_envelopes: 0,
        paper: 0,
        ..good_inputs(&mut codes)
    };
    let mut out = std::vec![0u8; CLOSE_WORK_LEN];
    assert_eq!(
        b.prepare_close(&base, signer(&w), &mut j, tb(1), &mut out)
            .unwrap_err(),
        Error::EnvelopeCountProfile
    );
    let right = CloseInputs {
        envelopes: Some(ENVELOPES_ONE),
        ..base
    };
    let check = |inputs: CloseInputs, invariant: Invariant| {
        let verdict = close_verdict(&b.close_facts(&inputs));
        assert!(verdict.contains(invariant), "{invariant:?}");
        assert_eq!(verdict.count(), 1, "{invariant:?}");
    };
    // the ballots stay in their envelopes: no paper count
    check(CloseInputs { paper: 1, ..right }, Invariant::PaperCount);
    let with = |counts: EnvelopeCounts| CloseInputs {
        envelopes: Some(counts),
        ..right
    };
    // envelopes in the box == issued − returned empty
    check(
        with(EnvelopeCounts {
            envelopes: 2,
            ..ENVELOPES_ONE
        }),
        Invariant::EnvelopeCount,
    );
    check(
        with(EnvelopeCounts {
            issued: 4,
            ..ENVELOPES_ONE
        }),
        Invariant::EnvelopeCount,
    );
    check(
        with(EnvelopeCounts {
            returned_empty: 1,
            ..ENVELOPES_ONE
        }),
        Invariant::EnvelopeCount,
    );
    // more empty envelopes returned than issued: the subtraction fails
    check(
        with(EnvelopeCounts {
            envelopes: 0,
            issued: 1,
            returned_empty: 2,
            ..ENVELOPES_ONE
        }),
        Invariant::EnvelopeCount,
    );
    // one sticker per visit
    check(
        with(EnvelopeCounts {
            stickers: 2,
            ..ENVELOPES_ONE
        }),
        Invariant::StickerCount,
    );
    check(
        with(EnvelopeCounts {
            stickers: 0,
            ..ENVELOPES_ONE
        }),
        Invariant::StickerCount,
    );
    let closed = b
        .prepare_close(&right, signer(&w), &mut j, tb(1), &mut out)
        .unwrap();
    assert!(closed.verdict.is_empty());
    let body: BoxCloseBody<'_> =
        decode_object(SCHEMA_BOX_CLOSE_BODY, SCHEMA_VERSION_1, closed.body).unwrap();
    let counts = body.counts();
    assert_eq!(
        (counts.paper, counts.records, counts.visits),
        (0, 1, 1),
        "an absentee box reports no paper count"
    );
    assert_eq!((counts.envelopes, counts.stickers), (1, 1));
}

#[test]
fn every_close_invariant_is_reported_on_its_own() {
    let w = world(Profile::InPerson, false);
    let mut m = mocks(&w);
    let mut j = MemJournal::default();
    let (b, mut codes) = busy_box(&w, &mut m, &mut j, 2);
    let good = good_inputs(&mut codes);
    let check = |inputs: CloseInputs, invariant: Invariant| {
        let verdict = close_verdict(&b.close_facts(&inputs));
        assert!(verdict.contains(invariant), "{invariant:?}");
        assert_eq!(verdict.count(), 1, "{invariant:?}");
    };
    assert!(close_verdict(&b.close_facts(&good)).is_empty());
    check(CloseInputs { paper: 3, ..good }, Invariant::PaperCount);
    check(
        CloseInputs {
            spoiled_envelopes: 1,
            ..good
        },
        Invariant::SpoiledEnvelopes,
    );
    check(
        CloseInputs {
            without_record: 1,
            paper: 3,
            ..good
        },
        Invariant::FallbackDeclared,
    );
    let ok = CloseInputs {
        without_record: 1,
        paper: 3,
        fallback_declared: true,
        ..good
    };
    assert!(close_verdict(&b.close_facts(&ok)).is_empty());
}

#[test]
fn a_lost_attestation_is_an_attested_count_violation() {
    // The unit's own accounting keeps records = attested + open batch; a
    // close assembled from facts where a batch attestation went missing
    // (an attested count short by the batch) must report AttestedCount.
    let counters = [3u64; 5];
    let facts = CloseFacts {
        paper: 3,
        records: 3,
        attested: 1,
        open_batch_records: 0,
        without_record: 0,
        challenged: 0,
        quarantined: 0,
        spoiled_envelopes: 0,
        module_final_counters: &counters,
        open_batches: 0,
        visits: 3,
        envelopes: None,
        fallback_declared: false,
        paper_incidents: 0,
    };
    let verdict = close_verdict(&facts);
    assert!(verdict.contains(Invariant::AttestedCount));
    assert_eq!(verdict.count(), 1);
    assert!(
        close_verdict(&CloseFacts {
            attested: 3,
            ..facts
        })
        .is_empty()
    );
}

#[test]
fn visits_bound_the_records_from_both_sides() {
    // visit_count ≤ record_count ≤ 8·visit_count (ADR-0021)
    let counters = [8u64; 5];
    let facts = |records: u64, visits: u64| CloseFacts {
        paper: records,
        records,
        attested: records,
        open_batch_records: 0,
        without_record: 0,
        challenged: 0,
        quarantined: 0,
        spoiled_envelopes: 0,
        module_final_counters: &[],
        open_batches: 0,
        visits,
        envelopes: None,
        fallback_declared: false,
        paper_incidents: 0,
    };
    let violated = |records: u64, visits: u64| {
        let verdict = close_verdict(&facts(records, visits));
        assert!(verdict.count() <= 1, "only the visit rule can fail");
        verdict.contains(Invariant::VisitCount)
    };
    assert!(!violated(0, 0));
    assert!(!violated(1, 1));
    assert!(!violated(8, 1), "eight ballots in one visit");
    assert!(violated(9, 1), "nine ballots cannot come from one visit");
    assert!(
        violated(1, 2),
        "a visit without a cast ballot is not counted"
    );
    assert!(violated(1, 0));
    assert!(violated(0, 1));
    assert!(!violated(16, 2));
    assert!(violated(17, 2));
    assert!(!violated(2, 2));
    // the product saturates instead of overflowing
    assert!(!violated(u64::MAX, u64::MAX / 4));
    assert!(!violated(u64::MAX, u64::MAX));
    // counters checked against the facts as well
    let with_counters = CloseFacts {
        module_final_counters: &counters,
        ..facts(8, 1)
    };
    assert!(close_verdict(&with_counters).is_empty());
}

#[test]
fn an_open_batch_and_a_module_gap_are_reported_at_close() {
    let w = world(Profile::InPerson, false);
    let mut m = mocks(&w);
    let mut j = MemJournal::default();
    let mut b = OpenBox::open(w.config, tb(1));
    let mut codes = std::vec![cast_one(&w, &mut b, &mut m, &mut j, 1)];
    let inputs = CloseInputs {
        spoiled_envelopes: 0,
        ..good_inputs(&mut codes)
    };
    let verdict = close_verdict(&b.close_facts(&inputs));
    assert!(verdict.contains(Invariant::OpenBatches));
    assert_eq!(verdict.count(), 1);
    // A module that skips a counter: the unit refuses the ballot without
    // moving that module's mark, the module refuses the batch (its pending
    // list has the skipped counter), and the close reports the mismatch.
    m[3].skip_counter = true;
    let mut area = work();
    let ballot = b
        .interpret(&interpretation(b"E-2026", STYLE_SMALL, 1), &mut area)
        .unwrap();
    assert_eq!(
        ballot.issue(&mut b, &mut ports(&mut m), &SEED).unwrap_err(),
        Error::CounterGap
    );
    assert_eq!(b.module_counters(), &[2, 2, 2, 1, 1]);
    b.abandon_visit(&mut j, tb(1)).unwrap();
    let attest = close(&w, &mut b, &mut m, &mut j, 1).unwrap();
    assert_eq!(refusals(&attest), ids(&[b"mod-p1"]));
    let inputs = CloseInputs {
        spoiled_envelopes: 1,
        ..good_inputs(&mut codes)
    };
    let verdict = close_verdict(&b.close_facts(&inputs));
    assert!(verdict.contains(Invariant::ModuleCounters));
    assert_eq!(verdict.count(), 1);
}
