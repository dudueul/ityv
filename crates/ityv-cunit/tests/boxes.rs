//! Box accounting: batches, scan counts, quarantine, imprint failure, close.
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
    Buffers, MemJournal, MockModule, STYLE_SMALL, World, interpretation, mocks, ports, world,
};
use ityv_crypto::{HybridSignature, Purpose, verify_hybrid};
use ityv_cunit::Error;
use ityv_cunit::boxstate::{BATCH_WORK_LEN, CLOSE_WORK_LEN, CloseInputs, OpenBox};
use ityv_cunit::config::Profile;
use ityv_cunit::error::Invariant;
use ityv_cunit::link::{JournalEntry, JournalKind, SCHEMA_JOURNAL_ENTRY};
use ityv_encoding::{
    BatchAttest, BoxCloseBody, Decode, Hash512, Reader, SCHEMA_BATCH_ATTEST, SCHEMA_BOX_CLOSE_BODY,
    SCHEMA_SCAN_COUNT_ATTEST_BODY, SCHEMA_VERSION_1, ScanCountAttestBody, TimeBucket,
    decode_object,
};
use ityv_ledger::merkle::sorted_set_root;

const SEED: [u8; 32] = [11; 32];

fn tb(n: u64) -> TimeBucket {
    TimeBucket::new(n)
}

/// Casts and imprints one ballot; returns its tracking code.
fn cast_one(
    w: &World,
    b: &mut OpenBox<'static>,
    m: &mut [MockModule],
    j: &mut MemJournal,
    at: u64,
) -> Hash512 {
    let mut bufs = Buffers::new(w);
    let ballot = b
        .interpret(&interpretation(b"E-2026", STYLE_SMALL, 1))
        .unwrap();
    let ballot = ballot.issue(b, &mut ports(m), &SEED).unwrap();
    let ballot = ballot.commit(b).unwrap();
    let ballot = ballot
        .build(b, &mut ports(m), &w.device_record, bufs.as_build())
        .unwrap();
    let ballot = ballot.cast(b, j, tb(at)).unwrap();
    let code = *ballot.tracking_code();
    ballot.imprinted(b).unwrap();
    code
}

/// Builds one ballot and challenges it.
fn challenge_one(
    w: &World,
    b: &mut OpenBox<'static>,
    m: &mut [MockModule],
    j: &mut MemJournal,
    at: u64,
) {
    let mut bufs = Buffers::new(w);
    let ballot = b
        .interpret(&interpretation(b"E-2026", STYLE_SMALL, 0))
        .unwrap();
    let ballot = ballot.issue(b, &mut ports(m), &SEED).unwrap();
    let ballot = ballot.commit(b).unwrap();
    let ballot = ballot
        .build(b, &mut ports(m), &w.device_record, bufs.as_build())
        .unwrap();
    let mut work = std::vec![0u8; 8192];
    ballot
        .challenge(b, j, &w.device_hybrid, &SEED, tb(at), &mut work)
        .unwrap();
}

fn kinds(j: &MemJournal) -> std::vec::Vec<JournalKind> {
    j.entries
        .iter()
        .map(|e| {
            let entry: JournalEntry<'_> =
                decode_object(SCHEMA_JOURNAL_ENTRY, SCHEMA_VERSION_1, e).unwrap();
            entry.kind()
        })
        .collect()
}

#[test]
fn journal_entries_chain_and_carry_the_consumed_counters() {
    let w = world(Profile::InPerson, false);
    let mut b = OpenBox::open(w.config, tb(1));
    let mut m = mocks(&w, 1);
    let mut j = MemJournal::default();
    cast_one(&w, &mut b, &mut m, &mut j, 1);
    challenge_one(&w, &mut b, &mut m, &mut j, 2);
    cast_one(&w, &mut b, &mut m, &mut j, 3);
    let mut head = Hash512::ZERO;
    for (n, bytes) in j.entries.iter().enumerate() {
        let entry: JournalEntry<'_> =
            decode_object(SCHEMA_JOURNAL_ENTRY, SCHEMA_VERSION_1, bytes).unwrap();
        assert_eq!(entry.prev_head(), &head);
        for counter in entry.module_counters().iter() {
            assert_eq!(counter.counter, n as u64 + 1);
        }
        head = ityv_crypto::object_hash(bytes);
    }
    assert_eq!(b.journal_head(), &head);
    assert_eq!(
        kinds(&j),
        [
            JournalKind::Record,
            JournalKind::Challenge,
            JournalKind::Record
        ]
    );
    assert_eq!(j.packages[1], None);
}

#[test]
fn batch_attest_covers_records_and_every_counter_since_the_last_batch() {
    let w = world(Profile::InPerson, false);
    let mut b = OpenBox::open(w.config, tb(1));
    let mut m = mocks(&w, 1);
    let mut j = MemJournal::default();
    let mut codes = std::vec![cast_one(&w, &mut b, &mut m, &mut j, 1)];
    challenge_one(&w, &mut b, &mut m, &mut j, 1);
    codes.push(cast_one(&w, &mut b, &mut m, &mut j, 1));
    assert_eq!(b.batch_records(), 2);
    let mut work = std::vec![0u8; BATCH_WORK_LEN];
    let head = *b.journal_head();
    let attest = b
        .close_batch(
            &head,
            &mut ports(&mut m),
            &w.device_hybrid,
            &SEED,
            &mut j,
            tb(2),
            &mut work,
        )
        .unwrap()
        .to_vec();
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
    for (sig, module) in parsed.module_sigs().zip(&m) {
        assert_eq!(sig.module_id.as_bytes(), module.id);
        let s = HybridSignature::decode(&mut Reader::new(sig.sig)).unwrap();
        let _ = verify_hybrid(
            &module.batch_verifying_key(),
            &purpose,
            parsed.body_bytes(),
            &s,
        )
        .unwrap();
    }
    assert_eq!(b.totals().attested, 2);
    assert_eq!(b.batch_records(), 0);
    assert_eq!(b.batch_index(), 1);
    assert_eq!(kinds(&j).last(), Some(&JournalKind::BatchClose));
    // the next batch starts after the attested counters
    cast_one(&w, &mut b, &mut m, &mut j, 3);
    let head = *b.journal_head();
    let attest = b
        .close_batch(
            &head,
            &mut ports(&mut m),
            &w.device_hybrid,
            &SEED,
            &mut j,
            tb(3),
            &mut work,
        )
        .unwrap()
        .to_vec();
    let parsed: BatchAttest<'_> =
        decode_object(SCHEMA_BATCH_ATTEST, SCHEMA_VERSION_1, &attest).unwrap();
    for range in parsed.body().module_ranges() {
        assert_eq!((range.counter_first, range.counter_last), (4, 4));
    }
    assert_eq!(parsed.body().batch_index(), 1);
}

#[test]
fn a_refusing_module_is_listed_and_the_others_sign_the_final_body() {
    let w = world(Profile::InPerson, false);
    let mut b = OpenBox::open(w.config, tb(1));
    let mut m = mocks(&w, 1);
    let mut j = MemJournal::default();
    cast_one(&w, &mut b, &mut m, &mut j, 1);
    m[1].refuse_batches = true; // mod-j
    let mut work = std::vec![0u8; BATCH_WORK_LEN];
    let head = *b.journal_head();
    let attest = b
        .close_batch(
            &head,
            &mut ports(&mut m),
            &w.device_hybrid,
            &SEED,
            &mut j,
            tb(1),
            &mut work,
        )
        .unwrap()
        .to_vec();
    let parsed: BatchAttest<'_> =
        decode_object(SCHEMA_BATCH_ATTEST, SCHEMA_VERSION_1, &attest).unwrap();
    let refusals: std::vec::Vec<&[u8]> = parsed
        .body()
        .module_refusals()
        .iter()
        .map(|id| id.as_bytes())
        .collect();
    assert_eq!(refusals, [b"mod-j".as_slice()]);
    let signers: std::vec::Vec<&[u8]> = parsed
        .module_sigs()
        .map(|s| s.module_id.as_bytes())
        .collect();
    assert_eq!(signers, [b"mod-a".as_slice(), b"mod-x", b"mod-y"]);
    let purpose = Purpose::new(b"batch-attest").unwrap();
    for sig in parsed.module_sigs() {
        let module = m.iter().find(|x| x.id == sig.module_id.as_bytes()).unwrap();
        let s = HybridSignature::decode(&mut Reader::new(sig.sig)).unwrap();
        let _ = verify_hybrid(
            &module.batch_verifying_key(),
            &purpose,
            parsed.body_bytes(),
            &s,
        )
        .unwrap();
    }
}

#[test]
fn every_module_refusing_still_closes_with_all_listed() {
    let w = world(Profile::InPerson, false);
    let mut b = OpenBox::open(w.config, tb(1));
    let mut m = mocks(&w, 1);
    let mut j = MemJournal::default();
    cast_one(&w, &mut b, &mut m, &mut j, 1);
    for module in &mut m {
        module.refuse_batches = true;
    }
    let mut work = std::vec![0u8; BATCH_WORK_LEN];
    let head = *b.journal_head();
    let attest = b
        .close_batch(
            &head,
            &mut ports(&mut m),
            &w.device_hybrid,
            &SEED,
            &mut j,
            tb(1),
            &mut work,
        )
        .unwrap()
        .to_vec();
    let parsed: BatchAttest<'_> =
        decode_object(SCHEMA_BATCH_ATTEST, SCHEMA_VERSION_1, &attest).unwrap();
    assert_eq!(parsed.body().module_refusals().len(), 4);
    assert_eq!(parsed.module_sigs().count(), 0);
}

#[test]
fn batch_close_checks_the_host_head_and_the_preconditions() {
    let w = world(Profile::InPerson, false);
    let mut b = OpenBox::open(w.config, tb(1));
    let mut m = mocks(&w, 1);
    let mut j = MemJournal::default();
    let mut work = std::vec![0u8; BATCH_WORK_LEN];
    let head = *b.journal_head();
    assert_eq!(
        b.close_batch(
            &head,
            &mut ports(&mut m),
            &w.device_hybrid,
            &SEED,
            &mut j,
            tb(1),
            &mut work
        ),
        Err(Error::BatchEmpty)
    );
    cast_one(&w, &mut b, &mut m, &mut j, 1);
    let wrong = Hash512([1; 64]);
    assert_eq!(
        b.close_batch(
            &wrong,
            &mut ports(&mut m),
            &w.device_hybrid,
            &SEED,
            &mut j,
            tb(1),
            &mut work
        ),
        Err(Error::JournalMismatch)
    );
    let head = *b.journal_head();
    assert_eq!(
        b.close_batch(
            &head,
            &mut ports(&mut m[..3]),
            &w.device_hybrid,
            &SEED,
            &mut j,
            tb(1),
            &mut work
        ),
        Err(Error::PortCount)
    );
    let mut small = std::vec![0u8; 100];
    assert_eq!(
        b.close_batch(
            &head,
            &mut ports(&mut m),
            &w.device_hybrid,
            &SEED,
            &mut j,
            tb(1),
            &mut small
        ),
        Err(Error::BufferTooSmall)
    );
    let _ballot = b
        .interpret(&interpretation(b"E-2026", STYLE_SMALL, 1))
        .unwrap();
    assert_eq!(
        b.close_batch(
            &head,
            &mut ports(&mut m),
            &w.device_hybrid,
            &SEED,
            &mut j,
            tb(1),
            &mut work
        ),
        Err(Error::BallotInFlight)
    );
}

#[test]
fn batch_triggers_on_idle_time_and_refuses_the_sixty_fifth_record() {
    let w = world(Profile::InPerson, false);
    let mut b = OpenBox::open(w.config, tb(1));
    let mut m = mocks(&w, 1);
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
    assert_eq!(
        b.interpret(&interpretation(b"E-2026", STYLE_SMALL, 1))
            .unwrap_err(),
        Error::BatchFull
    );
}

#[test]
fn scan_count_is_due_after_fifty_records_or_eight_buckets() {
    let w = world(Profile::InPerson, false);
    let mut b = OpenBox::open(w.config, tb(10));
    let mut m = mocks(&w, 1);
    let mut j = MemJournal::default();
    assert!(!b.scan_count_due(tb(17)));
    assert!(b.scan_count_due(tb(18)));
    cast_one(&w, &mut b, &mut m, &mut j, 11);
    let mut work = std::vec![0u8; 512];
    let body = b.scan_count_body(tb(12), &mut work).unwrap().to_vec();
    let parsed: ScanCountAttestBody<'_> =
        decode_object(SCHEMA_SCAN_COUNT_ATTEST_BODY, SCHEMA_VERSION_1, &body).unwrap();
    assert_eq!(parsed.record_count(), 1);
    assert_eq!(parsed.journal_head(), b.journal_head());
    assert!(!b.scan_count_due(tb(19)));
    assert!(b.scan_count_due(tb(20)));
    for _ in 0..49 {
        cast_one(&w, &mut b, &mut m, &mut j, 12);
        if b.batch_due(tb(12)) {
            let head = *b.journal_head();
            let mut bw = std::vec![0u8; BATCH_WORK_LEN];
            b.close_batch(
                &head,
                &mut ports(&mut m),
                &w.device_hybrid,
                &SEED,
                &mut j,
                tb(12),
                &mut bw,
            )
            .unwrap();
        }
    }
    assert!(!b.scan_count_due(tb(12)));
    cast_one(&w, &mut b, &mut m, &mut j, 12);
    assert!(b.scan_count_due(tb(12)));
    assert_eq!(
        b.scan_count_body(tb(11), &mut work).unwrap_err(),
        Error::TimeRegression
    );
}

#[test]
fn imprint_failure_quarantines_and_withdraws_the_record() {
    let w = world(Profile::InPerson, false);
    let mut b = OpenBox::open(w.config, tb(1));
    let mut m = mocks(&w, 1);
    let mut j = MemJournal::default();
    cast_one(&w, &mut b, &mut m, &mut j, 1);
    let mut bufs = Buffers::new(&w);
    let ballot = b
        .interpret(&interpretation(b"E-2026", STYLE_SMALL, 2))
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
    let entry: JournalEntry<'_> = decode_object(
        SCHEMA_JOURNAL_ENTRY,
        SCHEMA_VERSION_1,
        j.entries.last().unwrap(),
    )
    .unwrap();
    assert_eq!(entry.kind(), JournalKind::Quarantine);
    assert_eq!(entry.record_hash(), &code);
    assert!(!b.has_ballot_in_flight());
}

#[test]
fn a_journal_failure_at_cast_leaves_the_ballot_to_quarantine() {
    let w = world(Profile::InPerson, false);
    let mut b = OpenBox::open(w.config, tb(1));
    let mut m = mocks(&w, 1);
    let mut j = MemJournal::default();
    let mut bufs = Buffers::new(&w);
    let ballot = b
        .interpret(&interpretation(b"E-2026", STYLE_SMALL, 2))
        .unwrap();
    let ballot = ballot.issue(&mut b, &mut ports(&mut m), &SEED).unwrap();
    let ballot = ballot.commit(&b).unwrap();
    let ballot = ballot
        .build(&b, &mut ports(&mut m), &w.device_record, bufs.as_build())
        .unwrap();
    j.fail = true;
    assert_eq!(
        ballot.cast(&mut b, &mut j, tb(1)).unwrap_err(),
        Error::Journal(ityv_cunit::JournalError::NotDurable)
    );
    assert_eq!(b.totals().records, 0);
    assert!(b.has_ballot_in_flight());
    assert_eq!(
        b.quarantine_in_flight(&mut j, tb(1)).unwrap_err(),
        Error::Journal(ityv_cunit::JournalError::NotDurable)
    );
    j.fail = false;
    b.quarantine_in_flight(&mut j, tb(1)).unwrap();
    assert_eq!(b.totals().quarantined, 1);
    assert_eq!(kinds(&j), [JournalKind::Quarantine]);
    assert_eq!(
        b.quarantine_in_flight(&mut j, tb(1)).unwrap_err(),
        Error::NoBallotInFlight
    );
}

#[test]
fn a_ballot_quarantined_by_the_box_is_stale() {
    let w = world(Profile::InPerson, false);
    let mut b = OpenBox::open(w.config, tb(1));
    let mut m = mocks(&w, 1);
    let mut j = MemJournal::default();
    let ballot = b
        .interpret(&interpretation(b"E-2026", STYLE_SMALL, 2))
        .unwrap();
    let ballot = ballot.issue(&mut b, &mut ports(&mut m), &SEED).unwrap();
    b.quarantine_in_flight(&mut j, tb(1)).unwrap();
    assert_eq!(ballot.commit(&b).unwrap_err(), Error::NoBallotInFlight);
    // a newer ballot makes the old one stale rather than absent
    let ballot = b
        .interpret(&interpretation(b"E-2026", STYLE_SMALL, 1))
        .unwrap();
    let other = b.interpret(&interpretation(b"E-2026", STYLE_SMALL, 1));
    assert_eq!(other.unwrap_err(), Error::BallotInFlight);
    b.quarantine_in_flight(&mut j, tb(1)).unwrap();
    let _fresh = b
        .interpret(&interpretation(b"E-2026", STYLE_SMALL, 1))
        .unwrap();
    assert_eq!(
        ballot.issue(&mut b, &mut ports(&mut m), &SEED).unwrap_err(),
        Error::StaleBallot
    );
}

#[test]
fn a_ballot_without_any_issue_is_returned_not_quarantined() {
    let w = world(Profile::InPerson, false);
    let mut b = OpenBox::open(w.config, tb(1));
    let mut m = mocks(&w, 1);
    let mut j = MemJournal::default();
    m[0].fail_issue = true;
    let ballot = b
        .interpret(&interpretation(b"E-2026", STYLE_SMALL, 2))
        .unwrap();
    assert_eq!(
        ballot.issue(&mut b, &mut ports(&mut m), &SEED).unwrap_err(),
        Error::Port(ityv_cunit::PortError::Transport)
    );
    b.quarantine_in_flight(&mut j, tb(1)).unwrap();
    assert!(j.entries.is_empty());
    assert_eq!(b.totals().quarantined, 0);
}

#[test]
fn time_buckets_must_not_go_back() {
    let w = world(Profile::InPerson, false);
    let mut b = OpenBox::open(w.config, tb(5));
    let mut m = mocks(&w, 1);
    let mut j = MemJournal::default();
    let mut bufs = Buffers::new(&w);
    let ballot = b
        .interpret(&interpretation(b"E-2026", STYLE_SMALL, 2))
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
    let ballot = b
        .interpret(&interpretation(b"E-2026", STYLE_SMALL, 2))
        .unwrap();
    let _ = ballot.issue(&mut b, &mut ports(m), &SEED).unwrap();
    b.quarantine_in_flight(j, tb(1)).unwrap();
    let head = *b.journal_head();
    let mut work = std::vec![0u8; BATCH_WORK_LEN];
    b.close_batch(
        &head,
        &mut ports(m),
        &w.device_hybrid,
        &SEED,
        j,
        tb(1),
        &mut work,
    )
    .unwrap();
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
    let mut m = mocks(&w, 1);
    let mut j = MemJournal::default();
    let (mut b, mut codes) = busy_box(&w, &mut m, &mut j, 2);
    let inputs = good_inputs(&mut codes);
    let mut work = std::vec![0u8; CLOSE_WORK_LEN];
    let head_before = *b.journal_head();
    let out = b
        .prepare_close(&inputs, &w.device_hybrid, &SEED, &mut j, tb(2), &mut work)
        .unwrap();
    assert!(out.verdict.is_empty());
    let body: BoxCloseBody<'_> =
        decode_object(SCHEMA_BOX_CLOSE_BODY, SCHEMA_VERSION_1, out.body).unwrap();
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
    let sig = HybridSignature::decode(&mut Reader::new(out.device_sig)).unwrap();
    let _ = verify_hybrid(
        &w.device_hybrid.verifying_key(),
        &Purpose::new(b"box-close").unwrap(),
        out.body,
        &sig,
    )
    .unwrap();
    let token = out.token;
    assert_eq!(kinds(&j).last(), Some(&JournalKind::BoxClose));
    // closing twice, interpreting or batching after close is refused
    let mut again = std::vec![0u8; CLOSE_WORK_LEN];
    assert_eq!(
        b.prepare_close(&inputs, &w.device_hybrid, &SEED, &mut j, tb(2), &mut again)
            .unwrap_err(),
        Error::BoxClosed
    );
    assert_eq!(
        b.interpret(&interpretation(b"E-2026", STYLE_SMALL, 1))
            .unwrap_err(),
        Error::BoxClosed
    );
    let closed = b.into_closed(token);
    assert_eq!(closed.totals().records, 2);
    assert_eq!(closed.module_counters(), &[4, 4, 4, 4]);
    assert_eq!(
        closed.journal_head(),
        &ityv_crypto::object_hash(j.entries.last().unwrap())
    );
}

#[test]
fn every_close_invariant_is_reported_on_its_own() {
    let w = world(Profile::InPerson, false);
    let mut m = mocks(&w, 1);
    let mut j = MemJournal::default();
    let (b, mut codes) = busy_box(&w, &mut m, &mut j, 2);
    let good = good_inputs(&mut codes);
    let check = |inputs: CloseInputs, invariant: Invariant| {
        let verdict = ityv_cunit::rules::close_verdict(&b.close_facts(&inputs));
        assert!(verdict.contains(invariant), "{invariant:?}");
        assert_eq!(verdict.bits().count_ones(), 1, "{invariant:?}");
    };
    assert!(ityv_cunit::rules::close_verdict(&b.close_facts(&good)).is_empty());
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
    assert!(ityv_cunit::rules::close_verdict(&b.close_facts(&ok)).is_empty());
}

#[test]
fn an_open_batch_and_a_module_gap_are_reported_at_close() {
    let w = world(Profile::InPerson, false);
    let mut m = mocks(&w, 1);
    let mut j = MemJournal::default();
    let mut b = OpenBox::open(w.config, tb(1));
    let mut codes = std::vec![cast_one(&w, &mut b, &mut m, &mut j, 1)];
    let inputs = CloseInputs {
        spoiled_envelopes: 0,
        ..good_inputs(&mut codes)
    };
    let verdict = ityv_cunit::rules::close_verdict(&b.close_facts(&inputs));
    assert!(verdict.contains(Invariant::OpenBatches));
    assert_eq!(verdict.bits().count_ones(), 1);
    // A module that skips a counter: the unit records the counter it saw,
    // refuses the ballot, the module refuses the batch (its pending list
    // has a gap), and the close reports the counter mismatch.
    m[2].skip_counter = true;
    let ballot = b
        .interpret(&interpretation(b"E-2026", STYLE_SMALL, 1))
        .unwrap();
    assert_eq!(
        ballot.issue(&mut b, &mut ports(&mut m), &SEED).unwrap_err(),
        Error::CounterGap
    );
    assert_eq!(b.module_counters(), &[2, 2, 3, 1]);
    b.quarantine_in_flight(&mut j, tb(1)).unwrap();
    let head = *b.journal_head();
    let mut work = std::vec![0u8; BATCH_WORK_LEN];
    let attest = b
        .close_batch(
            &head,
            &mut ports(&mut m),
            &w.device_hybrid,
            &SEED,
            &mut j,
            tb(1),
            &mut work,
        )
        .unwrap()
        .to_vec();
    let parsed: BatchAttest<'_> =
        decode_object(SCHEMA_BATCH_ATTEST, SCHEMA_VERSION_1, &attest).unwrap();
    let refusals: std::vec::Vec<&[u8]> = parsed
        .body()
        .module_refusals()
        .iter()
        .map(|id| id.as_bytes())
        .collect();
    assert_eq!(refusals, [b"mod-x".as_slice()]);
    let inputs = CloseInputs {
        spoiled_envelopes: 1,
        ..good_inputs(&mut codes)
    };
    let verdict = ityv_cunit::rules::close_verdict(&b.close_facts(&inputs));
    assert!(verdict.contains(Invariant::ModuleCounters));
    assert_eq!(verdict.bits().count_ones(), 1);
}
