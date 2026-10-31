//! Construction, invariant, round-trip and rejection tests for the batch
//! attestation, scan-count attestation, box close and slip schemas
//! (ENCODING.md §8.12–§8.18).
// Integration-test crate: outside the TCB. Test code expresses "this must
// hold" with unwrap/expect/panic/indexing and does small arithmetic on test
// sizes, so those restriction lints are relaxed for this file only. No TCB
// crate may do this (CONSTITUTION.md §1.1). Each test walks one object
// through every rejection rule in sequence and names the byte offsets it
// patches (`x_at`, `y_at`), so the length and similar-name style lints are
// relaxed here as well.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::missing_panics_doc,
    clippy::missing_errors_doc,
    clippy::too_many_lines,
    clippy::similar_names
)]

mod common;

use common::{encode_to_vec, ident_len, patterned, patterned64};
use ityv_encoding::{
    Attestation, BatchAttest, BatchAttestBody, BatchAttestParts, BoxClose, BoxCloseBody,
    BoxCloseParts, BoxId, CloseCounts, ElectionId, ErrorKind, HEADER_LEN, Hash512,
    MAX_BATCH_BODY_LEN, MAX_BOX_CLOSE_BODY_LEN, MAX_SCAN_COUNT_BODY_LEN, MAX_SLIP_BODY_LEN,
    ModuleBatchSig, ModuleCounter, ModuleCounters, ModuleId, ModuleIds, ModuleRange, ObserverId,
    ObserverSig, OrgId, SCHEMA_BATCH_ATTEST, SCHEMA_BATCH_ATTEST_BODY, SCHEMA_BOX_CLOSE,
    SCHEMA_BOX_CLOSE_BODY, SCHEMA_SCAN_COUNT_ATTEST, SCHEMA_SCAN_COUNT_ATTEST_BODY, SCHEMA_SLIP,
    SCHEMA_SLIP_BODY, SCHEMA_VERSION_1, ScanCountAttest, ScanCountAttestBody, SignerId, SignerRole,
    Slip, SlipBody, StationId, TimeBucket, decode_object,
};
use std::vec::Vec;

const E: &[u8] = b"KR-2030-PRES";
const BOX: &[u8] = b"box-11-0042";

fn kind_at(result: Result<impl core::fmt::Debug, ityv_encoding::Error>) -> (ErrorKind, usize) {
    let err = result.expect_err("expected an error");
    (err.kind(), err.offset())
}

fn decode_batch_attest_body(b: &[u8]) -> Result<BatchAttestBody<'_>, ityv_encoding::Error> {
    decode_object(SCHEMA_BATCH_ATTEST_BODY, SCHEMA_VERSION_1, b)
}

fn decode_batch_attest(b: &[u8]) -> Result<BatchAttest<'_>, ityv_encoding::Error> {
    decode_object(SCHEMA_BATCH_ATTEST, SCHEMA_VERSION_1, b)
}

fn decode_scan_count_attest(b: &[u8]) -> Result<ScanCountAttest<'_>, ityv_encoding::Error> {
    decode_object(SCHEMA_SCAN_COUNT_ATTEST, SCHEMA_VERSION_1, b)
}

fn decode_box_close(b: &[u8]) -> Result<BoxClose<'_>, ityv_encoding::Error> {
    decode_object(SCHEMA_BOX_CLOSE, SCHEMA_VERSION_1, b)
}

fn decode_slip(b: &[u8]) -> Result<Slip<'_>, ityv_encoding::Error> {
    decode_object(SCHEMA_SLIP, SCHEMA_VERSION_1, b)
}

fn mid(id: &'static [u8]) -> ModuleId<'static> {
    ModuleId::new(id).unwrap()
}

fn range(id: &'static [u8], first: u64, last: u64) -> ModuleRange<'static> {
    ModuleRange {
        module_id: mid(id),
        counter_first: first,
        counter_last: last,
    }
}

fn batch_parts<'a>(ranges: &'a [ModuleRange<'a>], refusals: ModuleIds<'a>) -> BatchAttestParts<'a> {
    BatchAttestParts {
        election_id: ElectionId::new(E).unwrap(),
        box_id: BoxId::new(BOX).unwrap(),
        batch_index: 3,
        record_count: 64,
        records_root: patterned64(0x10),
        module_ranges: ranges,
        module_refusals: refusals,
        journal_head: patterned64(0x20),
        time_bucket: TimeBucket::new(500),
    }
}

#[test]
fn batch_attest_body_round_trip_and_rules() {
    let ranges = [range(b"mod-X", 100, 163), range(b"mod-Y", 200, 263)];
    let refusals = ModuleIds::new(&[mid(b"mod-Y")]).unwrap();
    let body = BatchAttestBody::new(&batch_parts(&ranges, refusals)).unwrap();
    let bytes = encode_to_vec(SCHEMA_BATCH_ATTEST_BODY, SCHEMA_VERSION_1, &body);
    let count_at = HEADER_LEN + ident_len(E) + ident_len(BOX) + 4;
    let ranges_at = count_at + 2 + 64;
    let x_at = ranges_at + 4;
    let x_last_at = x_at + ident_len(b"mod-X") + 8;
    let y_at = x_last_at + 8;
    let refusals_at = y_at + ident_len(b"mod-Y") + 16;
    let head_at = refusals_at + 4 + ident_len(b"mod-Y");
    assert_eq!(bytes.len(), head_at + 64 + 8);
    let decoded: BatchAttestBody<'_> =
        decode_object(SCHEMA_BATCH_ATTEST_BODY, SCHEMA_VERSION_1, &bytes).unwrap();
    assert_eq!(decoded, body);
    assert_eq!(decoded.batch_index(), 3);
    assert_eq!(decoded.record_count(), 64);
    assert_eq!(decoded.records_root(), &patterned64(0x10));
    assert_eq!(decoded.journal_head(), &patterned64(0x20));
    assert_eq!(decoded.time_bucket().get(), 500);
    let got: Vec<ModuleRange<'_>> = decoded.module_ranges().collect();
    assert_eq!(got, ranges);
    assert_eq!(decoded.module_refusals(), &refusals);
    assert!(decoded.module_refusals().contains(mid(b"mod-Y")));
    assert!(!decoded.module_refusals().contains(mid(b"mod-X")));
    let signers: Vec<ModuleId<'_>> = decoded.expected_signers().collect();
    assert_eq!(signers, [mid(b"mod-X")]);
    assert_eq!(decoded.election_id().as_bytes(), E);
    assert_eq!(decoded.box_id().as_bytes(), BOX);

    for bad in [0u16, 65] {
        let mut v = bytes.clone();
        v[count_at..count_at + 2].copy_from_slice(&bad.to_be_bytes());
        assert_eq!(
            kind_at(decode_batch_attest_body(&v)),
            (ErrorKind::ValueOutOfRange, count_at)
        );
    }
    let mut v = bytes.clone();
    v[count_at..count_at + 2].copy_from_slice(&1u16.to_be_bytes());
    assert_eq!(decode_batch_attest_body(&v).unwrap().record_count(), 1);
    // counter_first > counter_last for module X.
    let mut v = bytes.clone();
    v[x_last_at..x_last_at + 8].copy_from_slice(&99u64.to_be_bytes());
    assert_eq!(
        kind_at(decode_batch_attest_body(&v)),
        (ErrorKind::ValueOutOfRange, x_last_at)
    );
    let mut v = bytes.clone();
    v[x_last_at..x_last_at + 8].copy_from_slice(&100u64.to_be_bytes());
    assert!(decode_batch_attest_body(&v).is_ok());
    // Unsorted / duplicate ranges.
    let mut v = bytes.clone();
    v[x_at + 4 + 4] = b'Y';
    v[y_at + 4 + 4] = b'X';
    assert_eq!(
        kind_at(decode_batch_attest_body(&v)),
        (ErrorKind::NotSorted, y_at)
    );
    let mut v = bytes.clone();
    v[y_at + 4 + 4] = b'X';
    assert_eq!(
        kind_at(decode_batch_attest_body(&v)),
        (ErrorKind::Duplicate, y_at)
    );
    // A refusal naming a module without a range.
    let mut v = bytes.clone();
    v[refusals_at + 4 + 4 + 4] = b'Z';
    assert_eq!(
        kind_at(decode_batch_attest_body(&v)),
        (ErrorKind::InvariantViolation, refusals_at)
    );
    // Seven ranges.
    let mut v = bytes.clone();
    v[ranges_at..ranges_at + 4].copy_from_slice(&7u32.to_be_bytes());
    assert_eq!(
        kind_at(decode_batch_attest_body(&v)),
        (ErrorKind::CountExceedsMax, ranges_at)
    );

    // Constructor rejections.
    let mut p = batch_parts(&ranges, refusals);
    p.record_count = 0;
    assert!(BatchAttestBody::new(&p).is_none());
    p.record_count = 65;
    assert!(BatchAttestBody::new(&p).is_none());
    let bad_range = [range(b"mod-X", 5, 4)];
    assert!(BatchAttestBody::new(&batch_parts(&bad_range, ModuleIds::new(&[]).unwrap())).is_none());
    let swapped = [ranges[1], ranges[0]];
    assert!(BatchAttestBody::new(&batch_parts(&swapped, ModuleIds::new(&[]).unwrap())).is_none());
    let foreign = ModuleIds::new(&[mid(b"mod-Z")]).unwrap();
    assert!(BatchAttestBody::new(&batch_parts(&ranges, foreign)).is_none());
    assert!(ModuleIds::new(&[mid(b"b"), mid(b"a")]).is_none());
    assert!(ModuleIds::new(&[mid(b"a"), mid(b"a")]).is_none());
    assert!(ModuleIds::new(&[mid(b"a"); 7]).is_none());
    assert!(ModuleIds::new(&[]).unwrap().is_empty());
    assert!(!ModuleIds::new(&[mid(b"a")]).unwrap().is_empty());
    assert_eq!(ModuleIds::new(&[mid(b"a")]).unwrap().len(), 1);
    let seven: Vec<ModuleRange<'_>> = (0..7u8)
        .map(|i| ModuleRange {
            module_id: ModuleId::new(match i {
                0 => b"m0".as_slice(),
                1 => b"m1",
                2 => b"m2",
                3 => b"m3",
                4 => b"m4",
                5 => b"m5",
                _ => b"m6",
            })
            .unwrap(),
            counter_first: 1,
            counter_last: 1,
        })
        .collect();
    assert!(BatchAttestBody::new(&batch_parts(&seven, ModuleIds::new(&[]).unwrap())).is_none());
}

#[test]
fn batch_attest_round_trip_and_signer_set() {
    let ranges = [range(b"mod-X", 100, 163), range(b"mod-Y", 200, 263)];
    let refusals = ModuleIds::new(&[mid(b"mod-Y")]).unwrap();
    let body = BatchAttestBody::new(&batch_parts(&ranges, refusals)).unwrap();
    let body_bytes = encode_to_vec(SCHEMA_BATCH_ATTEST_BODY, SCHEMA_VERSION_1, &body);
    assert!(body_bytes.len() <= MAX_BATCH_BODY_LEN);
    let sx = patterned::<4691>(0x31);
    let sy = patterned::<4691>(0x32);
    let device = patterned::<4691>(0x33);
    let sigs = [ModuleBatchSig {
        module_id: mid(b"mod-X"),
        sig: &sx,
    }];
    let event = BatchAttest::new(&body_bytes, &sigs, &device).unwrap();
    let bytes = encode_to_vec(SCHEMA_BATCH_ATTEST, SCHEMA_VERSION_1, &event);
    let sigs_at = HEADER_LEN + 4 + body_bytes.len();
    assert_eq!(bytes.len(), sigs_at + 4 + ident_len(b"mod-X") + 4691 + 4691);
    let decoded: BatchAttest<'_> =
        decode_object(SCHEMA_BATCH_ATTEST, SCHEMA_VERSION_1, &bytes).unwrap();
    assert_eq!(decoded, event);
    assert_eq!(decoded.body(), &body);
    assert_eq!(decoded.body_bytes(), &body_bytes[..]);
    assert_eq!(decoded.device_sig(), &device);
    let got: Vec<ModuleBatchSig<'_>> = decoded.module_sigs().collect();
    assert_eq!(got, sigs);

    // A signature from the refusing module, or a missing one.
    let both = [
        sigs[0],
        ModuleBatchSig {
            module_id: mid(b"mod-Y"),
            sig: &sy,
        },
    ];
    assert_eq!(
        kind_at(BatchAttest::new(&body_bytes, &both, &device)),
        (ErrorKind::InvariantViolation, 0)
    );
    assert_eq!(
        kind_at(BatchAttest::new(&body_bytes, &[], &device)),
        (ErrorKind::InvariantViolation, 0)
    );
    let other = [ModuleBatchSig {
        module_id: mid(b"mod-Z"),
        sig: &sx,
    }];
    assert_eq!(
        kind_at(BatchAttest::new(&body_bytes, &other, &device)),
        (ErrorKind::InvariantViolation, 0)
    );
    let long = std::vec![0u8; MAX_BATCH_BODY_LEN + 1];
    assert_eq!(
        kind_at(BatchAttest::new(&long, &sigs, &device)),
        (ErrorKind::LengthExceedsMax, 0)
    );
    // Decoder: zero signatures.
    let mut v = bytes[..sigs_at].to_vec();
    v.extend_from_slice(&0u32.to_be_bytes());
    v.extend_from_slice(&device);
    let body_len = u32::try_from(v.len() - HEADER_LEN).unwrap();
    v[12..16].copy_from_slice(&body_len.to_be_bytes());
    assert_eq!(
        kind_at(decode_batch_attest(&v)),
        (ErrorKind::InvariantViolation, sigs_at)
    );
    // Decoder: inner body rule at the rebased offset (record_count 0).
    let count_at = HEADER_LEN + ident_len(E) + ident_len(BOX) + 4;
    let mut v = bytes.clone();
    v[HEADER_LEN + 4 + count_at..HEADER_LEN + 4 + count_at + 2].copy_from_slice(&[0, 0]);
    assert_eq!(
        kind_at(decode_batch_attest(&v)),
        (ErrorKind::ValueOutOfRange, HEADER_LEN + 4 + count_at)
    );
    // Maximal wrapper: six signers, no refusals.
    let ids: [&[u8]; 6] = [b"m1", b"m2", b"m3", b"m4", b"m5", b"m6"];
    let six: Vec<ModuleRange<'_>> = ids
        .iter()
        .map(|id| ModuleRange {
            module_id: ModuleId::new(id).unwrap(),
            counter_first: 0,
            counter_last: 63,
        })
        .collect();
    let body6 = BatchAttestBody::new(&batch_parts(&six, ModuleIds::new(&[]).unwrap())).unwrap();
    let body6_bytes = encode_to_vec(SCHEMA_BATCH_ATTEST_BODY, SCHEMA_VERSION_1, &body6);
    let sig6: Vec<ModuleBatchSig<'_>> = ids
        .iter()
        .map(|id| ModuleBatchSig {
            module_id: ModuleId::new(id).unwrap(),
            sig: &sx,
        })
        .collect();
    let event6 = BatchAttest::new(&body6_bytes, &sig6, &device).unwrap();
    let bytes6 = encode_to_vec(SCHEMA_BATCH_ATTEST, SCHEMA_VERSION_1, &event6);
    let back: BatchAttest<'_> =
        decode_object(SCHEMA_BATCH_ATTEST, SCHEMA_VERSION_1, &bytes6).unwrap();
    assert_eq!(back, event6);
    assert_eq!(back.module_sigs().count(), 6);
}

fn scan_body() -> ScanCountAttestBody<'static> {
    ScanCountAttestBody::new(
        ElectionId::new(E).unwrap(),
        BoxId::new(BOX).unwrap(),
        150,
        2,
        4,
        patterned64(0x40),
        TimeBucket::new(77),
    )
}

fn observer<'a>(id: &'static [u8], org: &'static [u8], sig: &'a [u8; 4691]) -> ObserverSig<'a> {
    ObserverSig {
        observer_id: ObserverId::new(id).unwrap(),
        org_id: OrgId::new(org).unwrap(),
        sig,
    }
}

#[test]
fn scan_count_attest_round_trip_and_rules() {
    let body = scan_body();
    let body_bytes = encode_to_vec(SCHEMA_SCAN_COUNT_ATTEST_BODY, SCHEMA_VERSION_1, &body);
    assert_eq!(
        body_bytes.len(),
        HEADER_LEN + ident_len(E) + ident_len(BOX) + 24 + 64 + 8
    );
    assert!(body_bytes.len() <= MAX_SCAN_COUNT_BODY_LEN);
    let decoded: ScanCountAttestBody<'_> =
        decode_object(SCHEMA_SCAN_COUNT_ATTEST_BODY, SCHEMA_VERSION_1, &body_bytes).unwrap();
    assert_eq!(decoded, body);
    assert_eq!(decoded.record_count(), 150);
    assert_eq!(decoded.challenge_count(), 2);
    assert_eq!(decoded.quarantine_count(), 4);
    assert_eq!(decoded.journal_head(), &patterned64(0x40));
    assert_eq!(decoded.time_bucket().get(), 77);
    assert_eq!(decoded.election_id().as_bytes(), E);
    assert_eq!(decoded.box_id().as_bytes(), BOX);

    let s1 = patterned::<4691>(0x51);
    let s2 = patterned::<4691>(0x52);
    let sigs = [
        observer(b"obs-1", b"org-A", &s1),
        observer(b"obs-2", b"org-B", &s2),
    ];
    let event = ScanCountAttest::new(&body_bytes, &sigs).unwrap();
    let bytes = encode_to_vec(SCHEMA_SCAN_COUNT_ATTEST, SCHEMA_VERSION_1, &event);
    let sigs_at = HEADER_LEN + 4 + body_bytes.len();
    let one = ident_len(b"obs-1") + ident_len(b"org-A") + 4691;
    assert_eq!(bytes.len(), sigs_at + 4 + 2 * one);
    let decoded: ScanCountAttest<'_> =
        decode_object(SCHEMA_SCAN_COUNT_ATTEST, SCHEMA_VERSION_1, &bytes).unwrap();
    assert_eq!(decoded, event);
    assert_eq!(decoded.body(), &body);
    assert_eq!(decoded.body_bytes(), &body_bytes[..]);
    let got: Vec<ObserverSig<'_>> = decoded.observer_sigs().collect();
    assert_eq!(got, sigs);

    // Same organization twice, one signature, unsorted, five signatures.
    let same_org = [
        observer(b"obs-1", b"org-A", &s1),
        observer(b"obs-2", b"org-A", &s2),
    ];
    assert_eq!(
        kind_at(ScanCountAttest::new(&body_bytes, &same_org)),
        (ErrorKind::InvariantViolation, 0)
    );
    assert_eq!(
        kind_at(ScanCountAttest::new(&body_bytes, &sigs[..1])),
        (ErrorKind::InvariantViolation, 0)
    );
    assert_eq!(
        kind_at(ScanCountAttest::new(&body_bytes, &[sigs[1], sigs[0]])),
        (ErrorKind::InvariantViolation, 0)
    );
    let five = [
        observer(b"obs-1", b"org-A", &s1),
        observer(b"obs-2", b"org-B", &s2),
        observer(b"obs-3", b"org-C", &s1),
        observer(b"obs-4", b"org-D", &s2),
        observer(b"obs-5", b"org-E", &s1),
    ];
    assert_eq!(
        kind_at(ScanCountAttest::new(&body_bytes, &five)),
        (ErrorKind::InvariantViolation, 0)
    );
    let four = ScanCountAttest::new(&body_bytes, &five[..4]).unwrap();
    let four_bytes = encode_to_vec(SCHEMA_SCAN_COUNT_ATTEST, SCHEMA_VERSION_1, &four);
    let back: ScanCountAttest<'_> =
        decode_object(SCHEMA_SCAN_COUNT_ATTEST, SCHEMA_VERSION_1, &four_bytes).unwrap();
    assert_eq!(back, four);

    // Decoder: one signature.
    let mut v = bytes[..sigs_at].to_vec();
    v.extend_from_slice(&1u32.to_be_bytes());
    v.extend_from_slice(&bytes[sigs_at + 4..sigs_at + 4 + one]);
    let body_len = u32::try_from(v.len() - HEADER_LEN).unwrap();
    v[12..16].copy_from_slice(&body_len.to_be_bytes());
    assert_eq!(
        kind_at(decode_scan_count_attest(&v)),
        (ErrorKind::InvariantViolation, sigs_at)
    );
    // Decoder: both from org-A.
    let org2_at = sigs_at + 4 + one + ident_len(b"obs-2") + 4;
    let mut v = bytes.clone();
    v[org2_at + 4] = b'A';
    assert_eq!(
        kind_at(decode_scan_count_attest(&v)),
        (ErrorKind::InvariantViolation, sigs_at)
    );
    // Decoder: unsorted observers.
    let o1_at = sigs_at + 4;
    let o2_at = o1_at + one;
    let mut v = bytes.clone();
    v[o1_at + 4 + 4] = b'2';
    v[o2_at + 4 + 4] = b'1';
    assert_eq!(
        kind_at(decode_scan_count_attest(&v)),
        (ErrorKind::NotSorted, o2_at)
    );
    // Decoder: five signatures declared.
    let mut v = bytes.clone();
    v[sigs_at..sigs_at + 4].copy_from_slice(&5u32.to_be_bytes());
    assert_eq!(
        kind_at(decode_scan_count_attest(&v)),
        (ErrorKind::CountExceedsMax, sigs_at)
    );
    // Decoder: inner body error rebased (bad identifier byte).
    let mut v = bytes.clone();
    v[HEADER_LEN + 4 + HEADER_LEN + 4] = b' ';
    assert_eq!(
        kind_at(decode_scan_count_attest(&v)),
        (ErrorKind::InvalidIdentByte, HEADER_LEN + 4 + HEADER_LEN + 4)
    );
}

fn close_parts(counters: ModuleCounters<'static>) -> BoxCloseParts<'static> {
    BoxCloseParts {
        election_id: ElectionId::new(E).unwrap(),
        box_id: BoxId::new(BOX).unwrap(),
        counts: CloseCounts {
            paper: 1_000,
            records: 990,
            attested: 990,
            without_record: 10,
            challenged: 3,
            quarantined: 1,
        },
        record_set_root: patterned64(0x60),
        journal_head: patterned64(0x61),
        seal_digest: patterned64(0x62),
        module_counters: counters,
        open_batches: 2,
        time_bucket: TimeBucket::new(900),
    }
}

fn attestation<'a>(
    id: &'static [u8],
    role: SignerRole,
    org: &'static [u8],
    sig: &'a [u8; 4691],
) -> Attestation<'a> {
    Attestation {
        signer_id: SignerId::new(id).unwrap(),
        role,
        org_id: OrgId::new(org).unwrap(),
        sig,
    }
}

#[test]
fn box_close_round_trip_and_rules() {
    let counters = ModuleCounters::new(&[
        ModuleCounter {
            module_id: mid(b"mod-X"),
            counter: 994,
        },
        ModuleCounter {
            module_id: mid(b"mod-Y"),
            counter: 994,
        },
    ])
    .unwrap();
    let body = BoxCloseBody::new(&close_parts(counters));
    let body_bytes = encode_to_vec(SCHEMA_BOX_CLOSE_BODY, SCHEMA_VERSION_1, &body);
    let counters_at = HEADER_LEN + ident_len(E) + ident_len(BOX) + 48 + 192;
    assert_eq!(
        body_bytes.len(),
        counters_at + 4 + 2 * (ident_len(b"mod-X") + 8) + 1 + 8
    );
    assert!(body_bytes.len() <= MAX_BOX_CLOSE_BODY_LEN);
    let decoded: BoxCloseBody<'_> =
        decode_object(SCHEMA_BOX_CLOSE_BODY, SCHEMA_VERSION_1, &body_bytes).unwrap();
    assert_eq!(decoded, body);
    assert_eq!(decoded.counts().paper, 1_000);
    assert_eq!(decoded.counts().records, 990);
    assert_eq!(decoded.counts().attested, 990);
    assert_eq!(decoded.counts().without_record, 10);
    assert_eq!(decoded.counts().challenged, 3);
    assert_eq!(decoded.counts().quarantined, 1);
    assert_eq!(decoded.record_set_root(), &patterned64(0x60));
    assert_eq!(decoded.journal_head(), &patterned64(0x61));
    assert_eq!(decoded.seal_digest(), &patterned64(0x62));
    assert_eq!(decoded.module_counters(), &counters);
    assert_eq!(decoded.open_batches(), 2);
    assert_eq!(decoded.time_bucket().get(), 900);
    assert_eq!(decoded.election_id().as_bytes(), E);
    assert_eq!(decoded.box_id().as_bytes(), BOX);
    // Empty module counters are allowed by the table.
    let none = BoxCloseBody::new(&close_parts(ModuleCounters::new(&[]).unwrap()));
    let nb = encode_to_vec(SCHEMA_BOX_CLOSE_BODY, SCHEMA_VERSION_1, &none);
    let back: BoxCloseBody<'_> =
        decode_object(SCHEMA_BOX_CLOSE_BODY, SCHEMA_VERSION_1, &nb).unwrap();
    assert!(back.module_counters().is_empty());
    assert_eq!(back.module_counters().iter().count(), 0);

    let s = patterned::<4691>(0x71);
    let device = patterned::<4691>(0x72);
    let attestations = [
        attestation(b"clerk-1", SignerRole::Clerk, b"nec", &s),
        attestation(b"clerk-2", SignerRole::Clerk, b"nec", &s),
        attestation(b"obs-1", SignerRole::Observer, b"party-A", &s),
        attestation(b"obs-2", SignerRole::Observer, b"party-B", &s),
    ];
    let event = BoxClose::new(&body_bytes, Some(&device), &attestations).unwrap();
    let bytes = encode_to_vec(SCHEMA_BOX_CLOSE, SCHEMA_VERSION_1, &event);
    let att_at = HEADER_LEN + 4 + body_bytes.len() + 1 + 4691;
    let clerk = ident_len(b"clerk-1") + 1 + ident_len(b"nec") + 4691;
    let obs = ident_len(b"obs-1") + 1 + ident_len(b"party-A") + 4691;
    assert_eq!(bytes.len(), att_at + 4 + 2 * clerk + 2 * obs);
    let decoded: BoxClose<'_> = decode_object(SCHEMA_BOX_CLOSE, SCHEMA_VERSION_1, &bytes).unwrap();
    assert_eq!(decoded, event);
    assert_eq!(decoded.body(), &body);
    assert_eq!(decoded.body_bytes(), &body_bytes[..]);
    assert_eq!(decoded.device_sig(), Some(&device));
    let got: Vec<Attestation<'_>> = decoded.attestations().collect();
    assert_eq!(got, attestations);
    assert_eq!(SignerRole::from_code(2), Some(SignerRole::Observer));
    assert_eq!(SignerRole::Clerk.code(), 1);
    assert_eq!(SignerRole::from_code(0), None);

    // Manual close: no device signature.
    let manual = BoxClose::new(&body_bytes, None, &attestations).unwrap();
    let mb = encode_to_vec(SCHEMA_BOX_CLOSE, SCHEMA_VERSION_1, &manual);
    assert_eq!(mb.len(), bytes.len() - 4691);
    let back: BoxClose<'_> = decode_object(SCHEMA_BOX_CLOSE, SCHEMA_VERSION_1, &mb).unwrap();
    assert_eq!(back, manual);
    assert_eq!(back.device_sig(), None);

    // Constructor: one clerk, observers from one organization, unsorted, nine.
    let one_clerk = [attestations[0], attestations[2], attestations[3]];
    assert_eq!(
        kind_at(BoxClose::new(&body_bytes, None, &one_clerk)),
        (ErrorKind::InvariantViolation, 0)
    );
    let same_org = [
        attestations[0],
        attestations[1],
        attestation(b"obs-1", SignerRole::Observer, b"party-A", &s),
        attestation(b"obs-2", SignerRole::Observer, b"party-A", &s),
    ];
    assert_eq!(
        kind_at(BoxClose::new(&body_bytes, None, &same_org)),
        (ErrorKind::InvariantViolation, 0)
    );
    let unsorted = [
        attestations[1],
        attestations[0],
        attestations[2],
        attestations[3],
    ];
    assert_eq!(
        kind_at(BoxClose::new(&body_bytes, None, &unsorted)),
        (ErrorKind::InvariantViolation, 0)
    );
    let mut nine: Vec<Attestation<'_>> = attestations.to_vec();
    for id in [b"x1".as_slice(), b"x2", b"x3", b"x4", b"x5"] {
        nine.push(Attestation {
            signer_id: SignerId::new(id).unwrap(),
            role: SignerRole::Clerk,
            org_id: OrgId::new(b"nec").unwrap(),
            sig: &s,
        });
    }
    assert_eq!(
        kind_at(BoxClose::new(&body_bytes, None, &nine)),
        (ErrorKind::InvariantViolation, 0)
    );
    let eight = BoxClose::new(&body_bytes, Some(&device), &nine[..8]).unwrap();
    let eb = encode_to_vec(SCHEMA_BOX_CLOSE, SCHEMA_VERSION_1, &eight);
    let back: BoxClose<'_> = decode_object(SCHEMA_BOX_CLOSE, SCHEMA_VERSION_1, &eb).unwrap();
    assert_eq!(back, eight);
    let long = std::vec![0u8; MAX_BOX_CLOSE_BODY_LEN + 1];
    assert_eq!(
        kind_at(BoxClose::new(&long, None, &attestations)),
        (ErrorKind::LengthExceedsMax, 0)
    );

    // Decoder: presence tag 2.
    let presence_at = HEADER_LEN + 4 + body_bytes.len();
    let mut v = bytes.clone();
    v[presence_at] = 2;
    assert_eq!(
        kind_at(decode_box_close(&v)),
        (ErrorKind::InvalidPresenceTag, presence_at)
    );
    // Decoder: role 3 on the first attestation.
    let role_at = att_at + 4 + ident_len(b"clerk-1");
    let mut v = bytes.clone();
    v[role_at] = 3;
    assert_eq!(
        kind_at(decode_box_close(&v)),
        (ErrorKind::ValueOutOfRange, role_at)
    );
    // Decoder: the second clerk becomes an observer from party-A: one clerk.
    let role2_at = att_at + 4 + clerk + ident_len(b"clerk-2");
    let mut v = bytes.clone();
    v[role2_at] = 2;
    assert_eq!(
        kind_at(decode_box_close(&v)),
        (ErrorKind::InvariantViolation, att_at)
    );
    // Decoder: both observers from party-A.
    let org2_at = att_at + 4 + 2 * clerk + obs + ident_len(b"obs-2") + 1;
    let mut v = bytes.clone();
    v[org2_at + 4 + 6] = b'A';
    assert_eq!(
        kind_at(decode_box_close(&v)),
        (ErrorKind::InvariantViolation, att_at)
    );
    // Decoder: unsorted signers.
    let c1_at = att_at + 4;
    let c2_at = c1_at + clerk;
    let mut v = bytes.clone();
    v[c1_at + 4 + 6] = b'2';
    v[c2_at + 4 + 6] = b'1';
    assert_eq!(kind_at(decode_box_close(&v)), (ErrorKind::NotSorted, c2_at));
    // Decoder: nine declared.
    let mut v = bytes.clone();
    v[att_at..att_at + 4].copy_from_slice(&9u32.to_be_bytes());
    assert_eq!(
        kind_at(decode_box_close(&v)),
        (ErrorKind::CountExceedsMax, att_at)
    );
    // Decoder: body error rebased (bad identifier byte).
    let mut v = bytes.clone();
    v[HEADER_LEN + 4 + HEADER_LEN + 4] = b'!';
    assert_eq!(
        kind_at(decode_box_close(&v)),
        (ErrorKind::InvalidIdentByte, HEADER_LEN + 4 + HEADER_LEN + 4)
    );
}

#[test]
fn slip_round_trip_and_rules() {
    let body = SlipBody::new(
        ElectionId::new(E).unwrap(),
        StationId::new(b"station-0007").unwrap(),
        TimeBucket::new(41),
        patterned64(0x90),
    );
    let body_bytes = encode_to_vec(SCHEMA_SLIP_BODY, SCHEMA_VERSION_1, &body);
    assert_eq!(
        body_bytes.len(),
        HEADER_LEN + ident_len(E) + ident_len(b"station-0007") + 8 + 64
    );
    let decoded: SlipBody<'_> =
        decode_object(SCHEMA_SLIP_BODY, SCHEMA_VERSION_1, &body_bytes).unwrap();
    assert_eq!(decoded, body);
    assert_eq!(decoded.election_id().as_bytes(), E);
    assert_eq!(decoded.station_id().as_bytes(), b"station-0007");
    assert_eq!(decoded.time_bucket().get(), 41);
    assert_eq!(decoded.tracking_code(), &patterned64(0x90));
    // Maximal body.
    let long = [b'S'; 64];
    let max = SlipBody::new(
        ElectionId::new(&long).unwrap(),
        StationId::new(&long).unwrap(),
        TimeBucket::new(u64::MAX),
        Hash512([0xff; 64]),
    );
    let max_bytes = encode_to_vec(SCHEMA_SLIP_BODY, SCHEMA_VERSION_1, &max);
    assert_eq!(max_bytes.len(), 224);
    assert!(max_bytes.len() <= MAX_SLIP_BODY_LEN);

    let sig = patterned::<4691>(0x91);
    let slip = Slip::new(&body_bytes, &sig).unwrap();
    let bytes = encode_to_vec(SCHEMA_SLIP, SCHEMA_VERSION_1, &slip);
    assert_eq!(bytes.len(), HEADER_LEN + 4 + body_bytes.len() + 4691);
    let decoded: Slip<'_> = decode_object(SCHEMA_SLIP, SCHEMA_VERSION_1, &bytes).unwrap();
    assert_eq!(decoded, slip);
    assert_eq!(decoded.body(), &body);
    assert_eq!(decoded.body_bytes(), &body_bytes[..]);
    assert_eq!(decoded.device_sig(), &sig);
    let max_slip = Slip::new(&max_bytes, &sig).unwrap();
    assert_eq!(
        encode_to_vec(SCHEMA_SLIP, SCHEMA_VERSION_1, &max_slip).len(),
        4935
    );

    // Body error rebased, body too long for the field, signature truncated.
    let mut v = bytes.clone();
    v[HEADER_LEN + 4 + HEADER_LEN + 4] = b' ';
    assert_eq!(
        kind_at(decode_slip(&v)),
        (ErrorKind::InvalidIdentByte, HEADER_LEN + 4 + HEADER_LEN + 4)
    );
    let mut v = bytes.clone();
    v[HEADER_LEN..HEADER_LEN + 4].copy_from_slice(&257u32.to_be_bytes());
    assert_eq!(
        kind_at(decode_slip(&v)),
        (ErrorKind::LengthExceedsMax, HEADER_LEN)
    );
    let mut v = bytes.clone();
    v.truncate(bytes.len() - 1);
    let body_len = u32::try_from(v.len() - HEADER_LEN).unwrap();
    v[12..16].copy_from_slice(&body_len.to_be_bytes());
    assert_eq!(
        kind_at(decode_slip(&v)),
        (ErrorKind::UnexpectedEnd, HEADER_LEN + 4 + body_bytes.len())
    );
    let oversized = std::vec![0u8; MAX_SLIP_BODY_LEN + 1];
    assert_eq!(
        kind_at(Slip::new(&oversized, &sig)),
        (ErrorKind::LengthExceedsMax, 0)
    );
    // Exactly the maximum length passes the length check and fails on content.
    let at_max = std::vec![0u8; MAX_SLIP_BODY_LEN];
    assert_eq!(kind_at(Slip::new(&at_max, &sig)), (ErrorKind::BadMagic, 0));
    assert_eq!(
        kind_at(Slip::new(&body_bytes[..HEADER_LEN], &sig)),
        (ErrorKind::BodyLengthMismatch, 12)
    );
}
