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
    Buffers, MemJournal, MockModule, SEED, STYLE_SMALL, World, cast_one, challenge_one,
    interpretation, mocks, ports, signer, tb, work, world,
};
use ityv_crypto::{HybridSignature, Purpose, verify_hybrid};
use ityv_cunit::boxstate::{BATCH_WORK_LEN, CLOSE_WORK_LEN, CloseInputs, OpenBox};
use ityv_cunit::config::Profile;
use ityv_cunit::error::Invariant;
use ityv_cunit::link::{JournalEntry, JournalKind, SCHEMA_JOURNAL_ENTRY};
use ityv_cunit::rules::{CloseFacts, close_verdict};
use ityv_cunit::{Error, JournalError, PortError};
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
    // record 1, its imprint, challenge 2, record 3, its imprint: the
    // imprint entries repeat their record's counters
    let consumed = [1u64, 1, 2, 3, 3];
    for (bytes, &expected) in j.entries.iter().zip(&consumed) {
        let e = entry(bytes);
        assert_eq!(e.prev_head(), &head);
        assert_eq!(e.module_counters().len(), 5);
        for counter in e.module_counters().iter() {
            assert_eq!(counter.counter, expected);
        }
        head = ityv_crypto::object_hash(bytes);
    }
    assert_eq!(b.journal_head(), &head);
    assert_eq!(j.head(), head);
    assert_eq!(
        kinds(&j),
        [
            JournalKind::Record,
            JournalKind::Imprinted,
            JournalKind::Challenge,
            JournalKind::Record,
            JournalKind::Imprinted
        ]
    );
    assert_eq!(
        entry(&j.entries[1]).record_hash(),
        entry(&j.entries[0]).record_hash()
    );
    assert_eq!(entry(&j.entries[1]).share_package_hash(), &Hash512::ZERO);
    assert_eq!(j.packages[1], None);
    assert_eq!(j.packages[2], None);
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
        b.quarantine_in_flight(&mut j, tb(1)).unwrap();
        assert_eq!(j.entries.len(), 4);
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
    m[3].skip_counter = true; // mod-x answers 3 after 1
    let mut area = work();
    let ballot = b
        .interpret(&interpretation(b"E-2026", STYLE_SMALL, 1), &mut area)
        .unwrap();
    assert_eq!(
        ballot.issue(&mut b, &mut ports(&mut m), &SEED).unwrap_err(),
        Error::CounterGap
    );
    // mod-a, mod-c and mod-j consumed counter 2; mod-x and mod-y did not
    assert_eq!(b.module_counters(), &[2, 2, 2, 1, 1]);
    b.quarantine_in_flight(&mut j, tb(1)).unwrap();
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
        ids(&[b"mod-a", b"mod-c", b"mod-j", b"mod-x", b"mod-y"])
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
        ids(&[b"mod-a", b"mod-c", b"mod-x", b"mod-y"])
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
        (1, 0, 2)
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
    assert_eq!(kinds(&j2), [JournalKind::Record, JournalKind::Imprinted]);
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
        Err(Error::BallotInFlight)
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
        absentee_envelopes: None,
        fallback_declared: false,
        record_set_root: Hash512::ZERO,
        seal_digest: Hash512::ZERO,
    };
    assert_eq!(
        b.prepare_close(&inputs, signer(&w), &mut j, tb(1), &mut close_out)
            .unwrap_err(),
        Error::JournalMismatch
    );
    assert_eq!(kinds(&j), [JournalKind::Record, JournalKind::Imprinted]);
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
    for _ in 1..64 {
        cast_one(&w, &mut b, &mut m, &mut j, 5);
    }
    assert_eq!(b.batch_records(), 64);
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
fn scan_count_is_refused_mid_ballot_and_holds_the_time_line() {
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
        Error::BallotInFlight
    );
    drop(ballot);
    b.quarantine_in_flight(&mut j, tb(1)).unwrap();
    b.scan_count_body(tb(9), &mut out).unwrap();
    // nothing journaled afterwards may carry an earlier bucket
    let mut area = work();
    let mut bufs = Buffers::new(&w);
    let ballot = b
        .interpret(&interpretation(b"E-2026", STYLE_SMALL, 1), &mut area)
        .unwrap();
    let ballot = ballot.issue(&mut b, &mut ports(&mut m), &SEED).unwrap();
    let ballot = ballot.commit(&b).unwrap();
    let ballot = ballot
        .build(&b, &mut ports(&mut m), &w.device_record, bufs.as_build())
        .unwrap();
    assert_eq!(
        ballot.cast(&mut b, &mut j, tb(8)).unwrap_err(),
        Error::TimeRegression
    );
}

/// Builds and casts one ballot, leaving it durable; returns its code.
fn durable_one(
    w: &World,
    b: &mut OpenBox<'static>,
    m: &mut [MockModule],
    j: &mut MemJournal,
    at: u64,
) -> Hash512 {
    let mut bufs = Buffers::new(w);
    let mut area = work();
    let ballot = b
        .interpret(&interpretation(b"E-2026", STYLE_SMALL, 2), &mut area)
        .unwrap();
    let ballot = ballot.issue(b, &mut ports(m), &SEED).unwrap();
    let ballot = ballot.commit(b).unwrap();
    let ballot = ballot
        .build(b, &mut ports(m), &w.device_record, bufs.as_build())
        .unwrap();
    let ballot = ballot.cast(b, j, tb(at)).unwrap();
    *ballot.tracking_code()
}

#[test]
fn imprint_failure_quarantines_and_withdraws_the_record() {
    let w = world(Profile::InPerson, false);
    let mut b = OpenBox::open(w.config, tb(1));
    let mut m = mocks(&w);
    let mut j = MemJournal::default();
    cast_one(&w, &mut b, &mut m, &mut j, 1);
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
    let ballot = ballot.cast(&mut b, &mut j, tb(2)).unwrap();
    let code = *ballot.tracking_code();
    assert_eq!(b.totals().records, 2);
    ballot.imprint_failed(&mut b, &mut j, tb(2)).unwrap();
    assert_eq!(b.totals().records, 1);
    assert_eq!(b.totals().quarantined, 1);
    assert_eq!(b.batch_records(), 1);
    let e = entry(j.entries.last().unwrap());
    assert_eq!(e.kind(), JournalKind::Quarantine);
    assert_eq!(e.record_hash(), &code);
    assert_eq!(e.module_counters().len(), 5);
    assert!(!b.has_ballot_in_flight());
    // the batch holds only the first record
    let attest = close(&w, &mut b, &mut m, &mut j, 2).unwrap();
    let parsed: BatchAttest<'_> =
        decode_object(SCHEMA_BATCH_ATTEST, SCHEMA_VERSION_1, &attest).unwrap();
    assert_eq!(parsed.body().record_count(), 1);
}

#[test]
fn an_imprint_failure_whose_entry_fails_stays_to_be_quarantined() {
    let w = world(Profile::InPerson, false);
    let mut b = OpenBox::open(w.config, tb(1));
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
    let ballot = ballot.cast(&mut b, &mut j, tb(1)).unwrap();
    let code = *ballot.tracking_code();
    j.fail = true;
    assert_eq!(
        ballot.imprint_failed(&mut b, &mut j, tb(1)).unwrap_err(),
        Error::Journal(JournalError::NotDurable)
    );
    // the record still stands until the quarantine entry is durable
    assert_eq!((b.totals().records, b.batch_records()), (1, 1));
    assert!(b.has_ballot_in_flight());
    j.fail = false;
    b.quarantine_in_flight(&mut j, tb(1)).unwrap();
    assert_eq!((b.totals().records, b.batch_records()), (0, 0));
    assert_eq!(b.totals().quarantined, 1);
    assert_eq!(entry(j.entries.last().unwrap()).record_hash(), &code);
}

#[test]
fn a_dropped_durable_ballot_is_quarantined_by_its_record_hash() {
    let w = world(Profile::InPerson, false);
    let mut b = OpenBox::open(w.config, tb(1));
    let mut m = mocks(&w);
    let mut j = MemJournal::default();
    let code = durable_one(&w, &mut b, &mut m, &mut j, 1);
    assert!(b.has_ballot_in_flight());
    b.quarantine_in_flight(&mut j, tb(1)).unwrap();
    let e = entry(j.entries.last().unwrap());
    assert_eq!(e.kind(), JournalKind::Quarantine);
    assert_eq!(e.record_hash(), &code);
    assert_eq!(b.totals().records, 0);
    assert_eq!(b.totals().quarantined, 1);
    assert_eq!(b.batch_records(), 0);
    assert_eq!(b.module_counters(), &[1, 1, 1, 1, 1]);
    assert_eq!(
        close(&w, &mut b, &mut m, &mut j, 1).unwrap_err(),
        Error::BatchEmpty
    );
}

#[test]
fn a_journal_failure_at_cast_leaves_the_ballot_to_quarantine() {
    let w = world(Profile::InPerson, false);
    let mut b = OpenBox::open(w.config, tb(1));
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
    j.fail = true;
    assert_eq!(
        ballot.cast(&mut b, &mut j, tb(1)).unwrap_err(),
        Error::Journal(JournalError::NotDurable)
    );
    assert_eq!(b.totals().records, 0);
    assert!(b.has_ballot_in_flight());
    assert_eq!(
        b.quarantine_in_flight(&mut j, tb(1)).unwrap_err(),
        Error::Journal(JournalError::NotDurable)
    );
    j.fail = false;
    b.quarantine_in_flight(&mut j, tb(1)).unwrap();
    assert_eq!(b.totals().quarantined, 1);
    assert_eq!(kinds(&j), [JournalKind::Quarantine]);
    assert_eq!(entry(&j.entries[0]).record_hash(), &Hash512::ZERO);
    assert_eq!(
        b.quarantine_in_flight(&mut j, tb(1)).unwrap_err(),
        Error::NoBallotInFlight
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
    b.quarantine_in_flight(&mut j, tb(1)).unwrap();
    assert_eq!(ballot.commit(&b).unwrap_err(), Error::NoBallotInFlight);
    // a newer ballot makes the old one stale rather than absent
    let ballot = b
        .interpret(&interpretation(b"E-2026", STYLE_SMALL, 1), &mut first)
        .unwrap();
    let other = b.interpret(&interpretation(b"E-2026", STYLE_SMALL, 1), &mut second);
    assert_eq!(other.unwrap_err(), Error::BallotInFlight);
    b.quarantine_in_flight(&mut j, tb(1)).unwrap();
    let _fresh = b
        .interpret(&interpretation(b"E-2026", STYLE_SMALL, 1), &mut second)
        .unwrap();
    assert_eq!(
        ballot.issue(&mut b, &mut ports(&mut m), &SEED).unwrap_err(),
        Error::StaleBallot
    );
}

#[test]
fn imprint_command_and_slip_need_the_ballot_still_in_flight() {
    let w = world(Profile::InPerson, true);
    let mut b = OpenBox::open(w.config, tb(1));
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
    let ballot = ballot.cast(&mut b, &mut j, tb(1)).unwrap();
    assert!(ballot.imprint_command(&b).is_ok());
    b.quarantine_in_flight(&mut j, tb(1)).unwrap();
    assert_eq!(
        ballot.imprint_command(&b).unwrap_err(),
        Error::NoBallotInFlight
    );
    let mut out = std::vec![0u8; ityv_cunit::ballot::MAX_SLIP_LEN];
    assert_eq!(
        ballot.slip(&b, signer(&w), tb(1), &mut out).unwrap_err(),
        Error::NoBallotInFlight
    );
    assert_eq!(
        ballot.imprinted(&mut b, &mut j, tb(1)).unwrap_err(),
        Error::NoBallotInFlight
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
    b.quarantine_in_flight(&mut j, tb(1)).unwrap();
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
    assert_eq!(
        ballot.cast(&mut b, &mut j, tb(4)).unwrap_err(),
        Error::TimeRegression
    );
    assert_eq!(
        b.quarantine_in_flight(&mut j, tb(4)).unwrap_err(),
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
    b.quarantine_in_flight(j, tb(1)).unwrap();
    close(w, &mut b, m, j, 1).unwrap();
    (b, codes)
}

fn good_inputs(codes: &mut [Hash512]) -> CloseInputs {
    codes.sort_by_key(|h| h.0);
    CloseInputs {
        paper: codes.len() as u64,
        without_record: 0,
        spoiled_envelopes: 2,
        absentee_envelopes: None,
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
        absentee_envelopes: Some(1),
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
        Error::BallotInFlight
    );
    drop(ballot);
    b.quarantine_in_flight(&mut j, tb(1)).unwrap();
    assert_eq!(j.entries.len(), entries);
    assert!(out.iter().all(|&byte| byte == 0), "nothing was signed");
    // a larger work buffer is fine
    let mut roomy = std::vec![0u8; CLOSE_WORK_LEN + 64];
    b.prepare_close(&good, signer(&w), &mut j, tb(1), &mut roomy)
        .unwrap();
}

#[test]
fn an_absentee_box_must_count_its_envelopes() {
    let w = world(Profile::Absentee, false);
    let mut m = mocks(&w);
    let mut j = MemJournal::default();
    let mut b = OpenBox::open(w.config, tb(1));
    let mut codes = std::vec![cast_one(&w, &mut b, &mut m, &mut j, 1)];
    close(&w, &mut b, &mut m, &mut j, 1).unwrap();
    let base = CloseInputs {
        spoiled_envelopes: 0,
        ..good_inputs(&mut codes)
    };
    let mut out = std::vec![0u8; CLOSE_WORK_LEN];
    assert_eq!(
        b.prepare_close(&base, signer(&w), &mut j, tb(1), &mut out)
            .unwrap_err(),
        Error::EnvelopeCountProfile
    );
    let wrong = CloseInputs {
        absentee_envelopes: Some(2),
        ..base
    };
    let verdict = close_verdict(&b.close_facts(&wrong));
    assert!(verdict.contains(Invariant::EnvelopeCount));
    assert_eq!(verdict.count(), 1);
    let right = CloseInputs {
        absentee_envelopes: Some(1),
        ..base
    };
    let closed = b
        .prepare_close(&right, signer(&w), &mut j, tb(1), &mut out)
        .unwrap();
    assert!(closed.verdict.is_empty());
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
            absentee_envelopes: Some(1),
            ..good
        },
        Invariant::EnvelopeCount,
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
        absentee_envelopes: None,
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
    b.quarantine_in_flight(&mut j, tb(1)).unwrap();
    let attest = close(&w, &mut b, &mut m, &mut j, 1).unwrap();
    assert_eq!(refusals(&attest), ids(&[b"mod-x"]));
    let inputs = CloseInputs {
        spoiled_envelopes: 1,
        ..good_inputs(&mut codes)
    };
    let verdict = close_verdict(&b.close_facts(&inputs));
    assert!(verdict.contains(Invariant::ModuleCounters));
    assert_eq!(verdict.count(), 1);
}
