//! Resume after a power loss (PROTOCOL.md §7.3 step 7, §7.8; ADR-0017
//! 개정 11): the rebuilt box equals the box that wrote the journal, the
//! waiting-area ballot is quarantined, and every broken or inconsistent
//! journal is refused.
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
use ityv_crypto::object_hash;
use ityv_cunit::boxstate::{BATCH_WORK_LEN, CLOSE_WORK_LEN, CloseInputs, OpenBox, ResumeInputs};
use ityv_cunit::config::Profile;
use ityv_cunit::link::{JournalEntry, JournalKind, MAX_JOURNAL_ENTRY_LEN, SCHEMA_JOURNAL_ENTRY};
use ityv_cunit::port::{JournalItem, JournalSource};
use ityv_cunit::{Error, JournalError};
use ityv_encoding::{
    BatchAttest, Hash512, ModuleCounter, ModuleCounters, ModuleId, SCHEMA_BATCH_ATTEST,
    SCHEMA_VERSION_1, TimeBucket, decode_object, encode_object,
};
use ityv_ledger::merkle::sorted_set_root;

const PACKAGE_ROOM: usize = 64 * 1024;

fn entry(bytes: &[u8]) -> JournalEntry<'_> {
    decode_object(SCHEMA_JOURNAL_ENTRY, SCHEMA_VERSION_1, bytes).unwrap()
}

/// Resumes from a copy of `j`, appending to `j` itself.
fn resume_at(
    w: &World,
    j: &mut MemJournal,
    occupied: bool,
    opened: u64,
    at: u64,
) -> Result<OpenBox<'static>, Error> {
    let copy = MemJournal {
        entries: j.entries.clone(),
        packages: j.packages.clone(),
        fail: false,
    };
    let mut package = std::vec![0u8; PACKAGE_ROOM];
    OpenBox::resume(
        w.config,
        &mut copy.reader(),
        j,
        &ResumeInputs {
            opened: tb(opened),
            waiting_area_occupied: occupied,
            time_bucket: tb(at),
        },
        &mut package,
    )
}

fn resume(
    w: &World,
    j: &mut MemJournal,
    occupied: bool,
    at: u64,
) -> Result<OpenBox<'static>, Error> {
    resume_at(w, j, occupied, 1, at)
}

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

/// Everything observable about a box.
fn assert_same(live: &OpenBox<'_>, resumed: &OpenBox<'_>) {
    assert_eq!(live.journal_head(), resumed.journal_head());
    assert_eq!(live.totals(), resumed.totals());
    assert_eq!(live.module_counters(), resumed.module_counters());
    assert_eq!(live.batch_records(), resumed.batch_records());
    assert_eq!(live.batch_index(), resumed.batch_index());
    for at in [1, 2, 3, 4, 5, 6] {
        assert_eq!(live.batch_due(tb(at)), resumed.batch_due(tb(at)), "{at}");
    }
    assert!(!resumed.has_ballot_in_flight());
    assert!(!resumed.is_faulted());
}

/// Builds and casts one ballot, leaving it durable (not imprinted).
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

/// A ballot whose issue consumed counters, then quarantined unjournaled.
fn partial_one(w: &World, b: &mut OpenBox<'static>, m: &mut [MockModule], j: &mut MemJournal) {
    let mut area = work();
    let ballot = b
        .interpret(&interpretation(b"E-2026", STYLE_SMALL, 1), &mut area)
        .unwrap();
    let _ = ballot.issue(b, &mut ports(m), &SEED).unwrap();
    let _ = w;
    b.quarantine_in_flight(j, tb(4)).unwrap();
}

#[test]
fn an_empty_journal_resumes_a_fresh_box() {
    let w = world(Profile::InPerson, false);
    let live = OpenBox::open(w.config, tb(1));
    let mut j = MemJournal::default();
    let resumed = resume(&w, &mut j, false, 1).unwrap();
    assert_same(&live, &resumed);
    assert!(j.entries.is_empty());
}

#[test]
fn the_resumed_box_equals_the_live_box_after_every_entry_kind() {
    type Step = fn(&World, &mut OpenBox<'static>, &mut [MockModule], &mut MemJournal);
    let record: Step = |w, b, m, j| {
        cast_one(w, b, m, j, 4);
    };
    let challenge: Step = |w, b, m, j| challenge_one(w, b, m, j, 4);
    let quarantine_record: Step = |w, b, m, j| {
        durable_one(w, b, m, j, 4);
        b.quarantine_in_flight(j, tb(4)).unwrap();
    };
    let quarantine_partial: Step = partial_one;
    let batch: Step = |w, b, m, j| {
        close(w, b, m, j, 4).unwrap();
    };
    let scenarios: [(&str, &[Step]); 7] = [
        ("record", &[record]),
        ("challenge", &[record, challenge]),
        ("quarantine of a record", &[record, quarantine_record]),
        ("quarantine before a record", &[quarantine_partial]),
        ("batch close", &[record, challenge, record, batch]),
        ("after a batch", &[record, batch, record]),
        (
            "everything",
            &[
                record,
                quarantine_partial,
                challenge,
                quarantine_record,
                record,
                batch,
                challenge,
                record,
            ],
        ),
    ];
    for (name, steps) in scenarios {
        let w = world(Profile::InPerson, false);
        let mut live = OpenBox::open(w.config, tb(1));
        let mut m = mocks(&w);
        let mut j = MemJournal::default();
        for step in steps {
            step(&w, &mut live, &mut m, &mut j);
        }
        let entries = j.entries.len();
        let mut resumed = resume(&w, &mut j, false, 4).unwrap();
        assert_same(&live, &resumed);
        assert_eq!(j.entries.len(), entries, "{name}: nothing appended");
        // the resumed box carries on: the modules (which kept their state
        // across the power loss) sign the next batch over the restored
        // ranges, and the batch root covers the restored records
        let open_codes: std::vec::Vec<Hash512> = {
            let mut codes = std::vec::Vec::new();
            for bytes in &j.entries {
                let e = entry(bytes);
                match e.kind() {
                    JournalKind::Record => codes.push(*e.record_hash()),
                    JournalKind::Quarantine if *e.record_hash() != Hash512::ZERO => {
                        codes.pop();
                    }
                    JournalKind::BatchClose => codes.clear(),
                    JournalKind::Challenge | JournalKind::Quarantine | JournalKind::BoxClose => {}
                }
            }
            codes
        };
        let next = cast_one(&w, &mut resumed, &mut m, &mut j, 5);
        let attest = close(&w, &mut resumed, &mut m, &mut j, 5).unwrap();
        let parsed: BatchAttest<'_> =
            decode_object(SCHEMA_BATCH_ATTEST, SCHEMA_VERSION_1, &attest).unwrap();
        assert!(parsed.body().module_refusals().is_empty(), "{name}");
        let mut expected = open_codes;
        expected.push(next);
        expected.sort_by_key(|h| h.0);
        assert_eq!(
            parsed.body().records_root(),
            &sorted_set_root(&expected).unwrap(),
            "{name}"
        );
        assert_eq!(resumed.batch_index(), live.batch_index() + 1, "{name}");
    }
}

#[test]
fn a_ballot_left_in_the_waiting_area_quarantines_the_last_record() {
    let w = world(Profile::InPerson, false);
    let mut live = OpenBox::open(w.config, tb(1));
    let mut m = mocks(&w);
    let mut j = MemJournal::default();
    cast_one(&w, &mut live, &mut m, &mut j, 2);
    let code = durable_one(&w, &mut live, &mut m, &mut j, 2);
    // power lost before the imprint
    let resumed = resume(&w, &mut j, true, 3).unwrap();
    let last = entry(j.entries.last().unwrap());
    assert_eq!(last.kind(), JournalKind::Quarantine);
    assert_eq!(last.record_hash(), &code);
    assert_eq!(last.time_bucket(), tb(3));
    let record = entry(&j.entries[1]);
    assert_eq!(last.module_counters(), record.module_counters());
    assert_eq!(resumed.totals().records, 1);
    assert_eq!(resumed.totals().quarantined, 1);
    assert_eq!(resumed.batch_records(), 1);
    assert_eq!(resumed.journal_head(), &j.head());
    // resuming again replays the quarantine and appends nothing more
    let entries = j.entries.len();
    let again = resume(&w, &mut j, false, 3).unwrap();
    assert_eq!(again.totals(), resumed.totals());
    assert_eq!(j.entries.len(), entries);
}

#[test]
fn a_ballot_left_without_a_record_is_quarantined_without_one() {
    let w = world(Profile::InPerson, false);
    let mut live = OpenBox::open(w.config, tb(1));
    let mut m = mocks(&w);
    let mut j = MemJournal::default();
    cast_one(&w, &mut live, &mut m, &mut j, 2);
    challenge_one(&w, &mut live, &mut m, &mut j, 2);
    let resumed = resume(&w, &mut j, true, 2).unwrap();
    let last = entry(j.entries.last().unwrap());
    assert_eq!(last.kind(), JournalKind::Quarantine);
    assert_eq!(last.record_hash(), &Hash512::ZERO);
    assert_eq!(last.module_counters().len(), 0);
    assert_eq!(resumed.totals().records, 1);
    assert_eq!(resumed.totals().quarantined, 1);
    assert_eq!(resumed.batch_records(), 1);
    // an empty journal with an occupied waiting area
    let mut empty = MemJournal::default();
    let fresh = resume(&w, &mut empty, true, 1).unwrap();
    assert_eq!(fresh.totals().quarantined, 1);
    assert_eq!(empty.entries.len(), 1);
}

#[test]
fn the_waiting_area_quarantine_needs_a_durable_entry_and_time() {
    let w = world(Profile::InPerson, false);
    let mut live = OpenBox::open(w.config, tb(1));
    let mut m = mocks(&w);
    let mut j = MemJournal::default();
    durable_one(&w, &mut live, &mut m, &mut j, 4);
    assert_eq!(
        resume(&w, &mut j, true, 3).unwrap_err(),
        Error::TimeRegression
    );
    j.fail = true;
    assert_eq!(
        resume(&w, &mut j, true, 4).unwrap_err(),
        Error::Journal(JournalError::NotDurable)
    );
    j.fail = false;
    assert_eq!(j.entries.len(), 1);
}

#[test]
fn a_scan_count_is_due_right_after_resume() {
    let w = world(Profile::InPerson, false);
    let mut live = OpenBox::open(w.config, tb(1));
    let mut m = mocks(&w);
    let mut j = MemJournal::default();
    cast_one(&w, &mut live, &mut m, &mut j, 2);
    assert!(!live.scan_count_due(tb(2)));
    let mut resumed = resume(&w, &mut j, false, 2).unwrap();
    assert!(resumed.scan_count_due(tb(2)));
    let mut out = std::vec![0u8; 512];
    resumed.scan_count_body(tb(2), &mut out).unwrap();
    assert!(!resumed.scan_count_due(tb(2)));
}

#[test]
fn a_closed_box_does_not_resume() {
    let w = world(Profile::InPerson, false);
    let mut live = OpenBox::open(w.config, tb(1));
    let mut m = mocks(&w);
    let mut j = MemJournal::default();
    let code = cast_one(&w, &mut live, &mut m, &mut j, 2);
    close(&w, &mut live, &mut m, &mut j, 2).unwrap();
    let inputs = CloseInputs {
        paper: 1,
        without_record: 0,
        spoiled_envelopes: 0,
        absentee_envelopes: None,
        fallback_declared: false,
        record_set_root: sorted_set_root(&[code]).unwrap(),
        seal_digest: Hash512::ZERO,
    };
    let mut out = std::vec![0u8; CLOSE_WORK_LEN];
    live.prepare_close(&inputs, signer(&w), &mut j, tb(2), &mut out)
        .unwrap();
    assert_eq!(resume(&w, &mut j, false, 2).unwrap_err(), Error::BoxClosed);
}

#[test]
fn a_source_failure_is_reported_as_such() {
    let w = world(Profile::InPerson, false);
    let mut live = OpenBox::open(w.config, tb(1));
    let mut m = mocks(&w);
    let mut j = MemJournal::default();
    cast_one(&w, &mut live, &mut m, &mut j, 2);
    let mut reader = j.reader();
    reader.fail_at = Some(1);
    let mut sink = MemJournal::default();
    let mut package = std::vec![0u8; PACKAGE_ROOM];
    let err = OpenBox::resume(
        w.config,
        &mut reader,
        &mut sink,
        &ResumeInputs {
            opened: tb(1),
            waiting_area_occupied: false,
            time_bucket: tb(2),
        },
        &mut package,
    )
    .unwrap_err();
    assert_eq!(err, Error::Journal(JournalError::Unreadable));
}

/// A source that reports lengths larger than the buffers it filled.
struct Overlong {
    entry_len: usize,
    package_len: Option<usize>,
    done: bool,
}

impl JournalSource for Overlong {
    fn next_item(
        &mut self,
        _entry: &mut [u8],
        _package: &mut [u8],
    ) -> Result<Option<JournalItem>, JournalError> {
        if self.done {
            return Ok(None);
        }
        self.done = true;
        Ok(Some(JournalItem {
            entry_len: self.entry_len,
            package_len: self.package_len,
        }))
    }
}

#[test]
fn lengths_beyond_the_buffers_are_corrupt() {
    let w = world(Profile::InPerson, false);
    let mut package = std::vec![0u8; 16];
    for (entry_len, package_len) in [(MAX_JOURNAL_ENTRY_LEN + 1, None), (100, Some(17))] {
        let mut source = Overlong {
            entry_len,
            package_len,
            done: false,
        };
        let err = OpenBox::resume(
            w.config,
            &mut source,
            &mut MemJournal::default(),
            &ResumeInputs {
                opened: tb(1),
                waiting_area_occupied: false,
                time_bucket: tb(1),
            },
            &mut package,
        )
        .unwrap_err();
        assert_eq!(err, Error::JournalCorrupt, "{entry_len} {package_len:?}");
    }
}

// --- crafted journals -------------------------------------------------------

/// One journal entry as the tests write it.
#[derive(Clone)]
struct Spec {
    kind: JournalKind,
    record_hash: Hash512,
    package: Option<std::vec::Vec<u8>>,
    /// Overrides the share-package hash derived from `package`.
    package_hash: Option<Hash512>,
    counters: std::vec::Vec<(std::vec::Vec<u8>, u64)>,
    bucket: u64,
}

fn specs(j: &MemJournal) -> std::vec::Vec<Spec> {
    j.entries
        .iter()
        .zip(&j.packages)
        .map(|(bytes, package)| {
            let e = entry(bytes);
            Spec {
                kind: e.kind(),
                record_hash: *e.record_hash(),
                package: package.clone(),
                package_hash: None,
                counters: e
                    .module_counters()
                    .iter()
                    .map(|c| (c.module_id.as_bytes().to_vec(), c.counter))
                    .collect(),
                bucket: e.time_bucket().get(),
            }
        })
        .collect()
}

/// Writes `specs` as a correctly chained journal.
fn chain(specs: &[Spec]) -> MemJournal {
    let mut j = MemJournal::default();
    let mut head = Hash512::ZERO;
    for spec in specs {
        let list: std::vec::Vec<ModuleCounter<'_>> = spec
            .counters
            .iter()
            .map(|(id, counter)| ModuleCounter {
                module_id: ModuleId::new(id).unwrap(),
                counter: *counter,
            })
            .collect();
        let package_hash = spec
            .package_hash
            .unwrap_or_else(|| spec.package.as_deref().map_or(Hash512::ZERO, object_hash));
        let value = JournalEntry::new(
            head,
            spec.kind,
            spec.record_hash,
            package_hash,
            ModuleCounters::new(&list).unwrap(),
            TimeBucket::new(spec.bucket),
        );
        let mut buf = std::vec![0u8; MAX_JOURNAL_ENTRY_LEN];
        let len = encode_object(SCHEMA_JOURNAL_ENTRY, SCHEMA_VERSION_1, &value, &mut buf).unwrap();
        buf.truncate(len);
        head = object_hash(&buf);
        j.entries.push(buf);
        j.packages.push(spec.package.clone());
    }
    j
}

/// A live journal: record, challenge, record, batch close, record, record
/// and its quarantine, a quarantine before any record (marks end at 6).
fn sample() -> (World, std::vec::Vec<Spec>) {
    let w = world(Profile::InPerson, false);
    let mut b = OpenBox::open(w.config, tb(1));
    let mut m = mocks(&w);
    let mut j = MemJournal::default();
    cast_one(&w, &mut b, &mut m, &mut j, 2);
    challenge_one(&w, &mut b, &mut m, &mut j, 2);
    cast_one(&w, &mut b, &mut m, &mut j, 2);
    close(&w, &mut b, &mut m, &mut j, 3).unwrap();
    cast_one(&w, &mut b, &mut m, &mut j, 3);
    durable_one(&w, &mut b, &mut m, &mut j, 3);
    b.quarantine_in_flight(&mut j, tb(3)).unwrap();
    partial_one(&w, &mut b, &mut m, &mut j);
    let s = specs(&j);
    (w, s)
}

fn corrupt(w: &World, specs: &[Spec]) -> Error {
    let mut j = chain(specs);
    resume(w, &mut j, false, 9).unwrap_err()
}

#[test]
fn the_sample_journal_resumes_when_rechained() {
    use JournalKind::{BatchClose as B, Challenge as C, Quarantine as Q, Record as R};
    let (w, s) = sample();
    let kinds: std::vec::Vec<JournalKind> = s.iter().map(|x| x.kind).collect();
    assert_eq!(kinds, [R, C, R, B, R, R, Q, Q]);
    let mut j = chain(&s);
    let resumed = resume(&w, &mut j, false, 9).unwrap();
    assert_eq!(resumed.totals().records, 3);
    assert_eq!(resumed.totals().quarantined, 2);
    assert_eq!(resumed.totals().challenged, 1);
    assert_eq!(resumed.totals().attested, 2);
    assert_eq!(resumed.module_counters(), &[6, 6, 6, 6, 6]);
}

#[test]
fn a_broken_or_undecodable_entry_is_refused() {
    let (w, s) = sample();
    let good = chain(&s);
    // a flipped byte inside the second entry breaks its decoding or the
    // chain of the entry after it
    for at in [16, 40, 100, 200] {
        let mut j = MemJournal {
            entries: good.entries.clone(),
            packages: good.packages.clone(),
            fail: false,
        };
        j.entries[1][at] ^= 1;
        assert_eq!(
            resume(&w, &mut j, false, 9).unwrap_err(),
            Error::JournalCorrupt,
            "byte {at}"
        );
    }
    // a missing entry breaks the chain
    let mut j = MemJournal {
        entries: good.entries.clone(),
        packages: good.packages.clone(),
        fail: false,
    };
    j.entries.remove(1);
    j.packages.remove(1);
    assert_eq!(
        resume(&w, &mut j, false, 9).unwrap_err(),
        Error::JournalCorrupt
    );
    // a truncated entry does not decode
    let mut j = MemJournal {
        entries: good.entries.clone(),
        packages: good.packages.clone(),
        fail: false,
    };
    j.entries[0].pop();
    assert_eq!(
        resume(&w, &mut j, false, 9).unwrap_err(),
        Error::JournalCorrupt
    );
}

#[test]
fn share_packages_must_sit_exactly_after_records_and_match() {
    let (w, s) = sample();
    let mut x = s.clone();
    x[0].package.as_mut().unwrap()[0] ^= 1;
    x[0].package_hash = Some(object_hash(s[0].package.as_ref().unwrap()));
    assert_eq!(corrupt(&w, &x), Error::JournalCorrupt, "altered package");
    let mut x = s.clone();
    x[0].package = None;
    x[0].package_hash = Some(object_hash(s[0].package.as_ref().unwrap()));
    assert_eq!(corrupt(&w, &x), Error::JournalCorrupt, "missing package");
    let mut x = s.clone();
    x[1].package = Some(std::vec![1, 2, 3]);
    assert_eq!(
        corrupt(&w, &x),
        Error::JournalCorrupt,
        "package on a challenge"
    );
    let mut x = s.clone();
    x[1].package_hash = Some(Hash512([1; 64]));
    assert_eq!(
        corrupt(&w, &x),
        Error::JournalCorrupt,
        "hash without package"
    );
}

#[test]
fn time_must_not_run_backwards_in_the_journal() {
    let (w, s) = sample();
    let mut x = s.clone();
    x[4].bucket = 2; // after the batch close at bucket 3
    assert_eq!(corrupt(&w, &x), Error::JournalCorrupt);
    let mut j = chain(&s);
    assert_eq!(
        resume_at(&w, &mut j, false, 3, 9).unwrap_err(),
        Error::JournalCorrupt,
        "entries before the box opened"
    );
}

#[test]
fn counters_must_follow_each_module_mark() {
    let (w, s) = sample();
    let mut x = s.clone();
    x[2].counters[0].1 = 4; // record: gap (mark 2)
    assert_eq!(corrupt(&w, &x), Error::JournalCorrupt, "record gap");
    let mut x = s.clone();
    x[1].counters[4].1 = 1; // challenge: replay (mark 1)
    assert_eq!(corrupt(&w, &x), Error::JournalCorrupt, "challenge replay");
    let mut x = s.clone();
    x[7].counters[2].1 = 9; // partial quarantine: gap
    assert_eq!(corrupt(&w, &x), Error::JournalCorrupt, "quarantine gap");
    let mut x = s.clone();
    x[0].counters[3].0 = b"mod-q".to_vec(); // unknown module
    x[0].counters.sort();
    assert_eq!(corrupt(&w, &x), Error::JournalCorrupt, "unknown module");
}

#[test]
fn a_record_quarantine_must_follow_its_record() {
    let (w, s) = sample();
    let mut x = s.clone();
    x[6].record_hash = s[4].record_hash; // names an earlier record
    assert_eq!(corrupt(&w, &x), Error::JournalCorrupt, "other record");
    let mut x = s.clone();
    x[6].counters[0].1 = 4;
    assert_eq!(corrupt(&w, &x), Error::JournalCorrupt, "other counters");
    let mut x = s.clone();
    x[6].counters.pop();
    assert_eq!(corrupt(&w, &x), Error::JournalCorrupt, "fewer counters");
    // after a challenge, no record is there to quarantine
    let mut x = s[..2].to_vec();
    x.push(Spec {
        kind: JournalKind::Quarantine,
        record_hash: s[1].record_hash,
        package: None,
        package_hash: None,
        counters: s[1].counters.clone(),
        bucket: 2,
    });
    assert_eq!(corrupt(&w, &x), Error::JournalCorrupt, "after a challenge");
}

#[test]
fn a_batch_close_must_match_the_replayed_batch() {
    let (w, s) = sample();
    let mut x = s.clone();
    x[3].record_hash = Hash512([5; 64]);
    assert_eq!(corrupt(&w, &x), Error::JournalCorrupt, "root");
    let mut x = s.clone();
    x[3].counters.pop();
    assert_eq!(corrupt(&w, &x), Error::JournalCorrupt, "missing module");
    let mut x = s.clone();
    x[3].counters[1].1 = 2;
    assert_eq!(corrupt(&w, &x), Error::JournalCorrupt, "counter below mark");
    // a second batch close right after the first closes an empty batch
    let mut x = s[..4].to_vec();
    x.push(s[3].clone());
    assert_eq!(corrupt(&w, &x), Error::JournalCorrupt, "empty batch");
}

#[test]
fn a_box_close_must_name_the_marks_and_end_the_journal() {
    let (w, s) = sample();
    let close_entry = Spec {
        kind: JournalKind::BoxClose,
        record_hash: Hash512([3; 64]),
        package: None,
        package_hash: None,
        counters: s[7].counters.clone(),
        bucket: 4,
    };
    let mut x = s.clone();
    x.push(Spec {
        counters: s[0].counters.clone(),
        ..close_entry.clone()
    });
    assert_eq!(corrupt(&w, &x), Error::JournalCorrupt, "stale counters");
    let mut x = s.clone();
    let mut partial = close_entry.clone();
    partial.counters.truncate(4);
    x.push(partial);
    assert_eq!(corrupt(&w, &x), Error::JournalCorrupt, "missing module");
    let mut full = s.clone();
    full.push(close_entry);
    assert_eq!(corrupt(&w, &full), Error::BoxClosed, "a valid close");
    full.push(full[0].clone());
    assert_eq!(
        corrupt(&w, &full),
        Error::JournalCorrupt,
        "entry after close"
    );
}

#[test]
fn a_sixty_fifth_unbatched_record_is_corrupt() {
    let w = world(Profile::InPerson, false);
    let ids: [&[u8]; 5] = [b"mod-a", b"mod-c", b"mod-j", b"mod-x", b"mod-y"];
    let record = |n: u64| Spec {
        kind: JournalKind::Record,
        record_hash: Hash512([n as u8; 64]),
        package: Some(std::vec![n as u8]),
        package_hash: None,
        counters: ids.iter().map(|id| (id.to_vec(), n)).collect(),
        bucket: 1,
    };
    let x: std::vec::Vec<Spec> = (1..=64).map(record).collect();
    let mut j = chain(&x);
    let resumed = resume(&w, &mut j, false, 1).unwrap();
    assert_eq!(resumed.batch_records(), 64);
    let x: std::vec::Vec<Spec> = (1..=65).map(record).collect();
    assert_eq!(corrupt(&w, &x), Error::JournalCorrupt);
}
