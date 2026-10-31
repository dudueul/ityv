//! Golden test vectors (ENCODING.md §7) for the M3 schemas, one file per
//! schema under `vectors/`. The mechanism is the one of `vectors.rs`: the
//! test regenerates each file from fixed inputs, fails if the checked-in
//! file differs (`ITYV_UPDATE_VECTORS=1` rewrites it), and re-reads every
//! line through the decoder the way an independent implementation would.
//!
//! Signatures in these vectors are patterned bytes, not real signatures:
//! the encoding layer treats them as opaque fixed-width fields.
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
    clippy::missing_errors_doc
)]

mod common;

use common::{
    Vector, check_file, commitments, encode_to_vec, ident_len, patterned, patterned64, proof_bytes,
    render, scalars, self_check,
};
use ityv_encoding::{
    Attestation, BallotStyleId, BatchAttest, BatchAttestBody, BatchAttestParts, BoxClose,
    BoxCloseBody, BoxCloseParts, BoxId, CastRecord, CastRecordBody, CastRecordParts,
    ChallengeOpening, ChallengeOpeningBody, ChallengeOpeningParts, ChamberCode, CloseCounts,
    ElectionId, HEADER_LEN, MAX_CHUNKS, MAX_SECRETS, MemberShare, ModuleBatchSig, ModuleCounter,
    ModuleCounters, ModuleId, ModuleIds, ModuleOpening, ModuleRange, ModuleRecordSig, ObserverId,
    ObserverSig, OrgId, SCHEMA_BATCH_ATTEST, SCHEMA_BATCH_ATTEST_BODY, SCHEMA_BOX_CLOSE,
    SCHEMA_BOX_CLOSE_BODY, SCHEMA_CAST_RECORD, SCHEMA_CAST_RECORD_BODY, SCHEMA_CHALLENGE_OPENING,
    SCHEMA_CHALLENGE_OPENING_BODY, SCHEMA_MEMBER_SHARE, SCHEMA_SCAN_COUNT_ATTEST,
    SCHEMA_SCAN_COUNT_ATTEST_BODY, SCHEMA_SHARE_PACKAGE, SCHEMA_SLIP, SCHEMA_SLIP_BODY,
    SCHEMA_VERSION_1, Scalars, ScanCountAttest, ScanCountAttestBody, ShareEntry, SharePackage,
    SignerId, SignerRole, Slip, SlipBody, StationId, TimeBucket, Token192, Transport, TrusteeId,
    decode_object,
};
use std::vec::Vec;

const E: &[u8] = b"KR-2030-PRES";
const BOX: &[u8] = b"box-11-0042";
const STYLE: &[u8] = b"pres-2030";

fn valid(label: &'static str, bytes: Vec<u8>) -> Vector {
    Vector {
        label,
        bytes,
        expected: None,
    }
}

fn invalid(label: &'static str, bytes: Vec<u8>, kind: &'static str, offset: usize) -> Vector {
    Vector {
        label,
        bytes,
        expected: Some((kind, offset)),
    }
}

/// Rewrites the header's body length after a splice.
fn fix_len(v: &mut [u8]) {
    let body_len = u32::try_from(v.len() - HEADER_LEN).unwrap();
    v[12..16].copy_from_slice(&body_len.to_be_bytes());
}

fn module(id: &'static [u8], counter: u64) -> ModuleCounter<'static> {
    ModuleCounter {
        module_id: ModuleId::new(id).unwrap(),
        counter,
    }
}

/// Renders, checks against the file on disk, and re-reads every line through
/// the decoder of the named type.
macro_rules! check {
    ($ty:ty, $name:expr, $title:expr, $schema:expr, $vectors:expr $(,)?) => {{
        let content = render($title, $schema, $vectors);
        check_file($name, &content);
        self_check(&content, |b| {
            let v: $ty = decode_object($schema, SCHEMA_VERSION_1, b)?;
            Ok(encode_to_vec($schema, SCHEMA_VERSION_1, &v))
        });
    }};
}

fn record_body_bytes(proof: &[u8], flags: u8) -> Vec<u8> {
    record_body_bytes_k(proof, flags, 2)
}

fn record_body_bytes_k(proof: &[u8], flags: u8, k: usize) -> Vec<u8> {
    let body = CastRecordBody::new(&CastRecordParts {
        election_id: ElectionId::new(E).unwrap(),
        box_id: BoxId::new(BOX).unwrap(),
        ballot_style_id: BallotStyleId::new(STYLE).unwrap(),
        proof_system_id: 1,
        commitments: commitments(k, 0x10),
        proof,
        module_counters: ModuleCounters::new(&[module(b"mod-X", 7), module(b"mod-Y", 9)]).unwrap(),
        share_package_hash: patterned64(0x30),
        transport_flags: flags,
    })
    .unwrap();
    encode_to_vec(SCHEMA_CAST_RECORD_BODY, SCHEMA_VERSION_1, &body)
}

#[test]
fn cast_record_body_vectors() {
    let proof = proof_bytes(16, 2, 0xab);
    let bytes = record_body_bytes(&proof, 0);
    let psid_at = HEADER_LEN + ident_len(E) + ident_len(BOX) + ident_len(STYLE);
    let commitments_at = psid_at + 2;
    let proof_at = commitments_at + 4 + 64;
    let counters_at = proof_at + 4 + proof.len();
    let flags_at = counters_at + 4 + 2 * (ident_len(b"mod-X") + 8) + 64;
    let mut v = std::vec![
        valid("presidential 14 options 2 chunks", bytes.clone()),
        valid(
            "kem fallback and neutral module flags",
            record_body_bytes(&proof, 3)
        ),
        valid(
            "single chunk 9 options",
            record_body_bytes_k(&proof_bytes(9, 1, 0x01), 0, 1)
        ),
    ];
    let mut b = bytes.clone();
    b[psid_at + 1] = 2;
    v.push(invalid("proof system 2", b, "ValueOutOfRange", psid_at));
    let mut b = bytes.clone();
    b[proof_at + 4 + 2] = 3;
    v.push(invalid(
        "proof header chunk count mismatch",
        b,
        "InvariantViolation",
        proof_at,
    ));
    let mut b = bytes.clone();
    b[flags_at] = 4;
    v.push(invalid(
        "transport flag bit 2",
        b,
        "ValueOutOfRange",
        flags_at,
    ));
    let mut b = bytes.clone();
    b[commitments_at..commitments_at + 4].copy_from_slice(&0u32.to_be_bytes());
    v.push(invalid(
        "no commitments",
        b,
        "ValueOutOfRange",
        commitments_at,
    ));
    let x_at = counters_at + 4;
    let y_at = x_at + ident_len(b"mod-X") + 8;
    let mut b = bytes.clone();
    b[y_at + 4 + 4] = b'X';
    v.push(invalid("duplicate module", b, "Duplicate", y_at));
    let mut b = bytes[..counters_at].to_vec();
    b.extend_from_slice(&0u32.to_be_bytes());
    b.extend_from_slice(&bytes[flags_at - 64..]);
    fix_len(&mut b);
    v.push(invalid(
        "no module counters",
        b,
        "ValueOutOfRange",
        counters_at,
    ));
    check!(
        CastRecordBody<'_>,
        "cast_record_body.txt",
        "CastRecordBody",
        SCHEMA_CAST_RECORD_BODY,
        &v,
    );
}

#[test]
fn cast_record_vectors() {
    let proof = proof_bytes(16, 2, 0xab);
    let body_bytes = record_body_bytes(&proof, 0);
    let device = patterned::<64>(0x70);
    let sx = patterned::<64>(0x71);
    let sy = patterned::<64>(0x72);
    let sigs = [
        ModuleRecordSig {
            module_id: ModuleId::new(b"mod-X").unwrap(),
            ed25519: &sx,
        },
        ModuleRecordSig {
            module_id: ModuleId::new(b"mod-Y").unwrap(),
            ed25519: &sy,
        },
    ];
    let record = CastRecord::new(&body_bytes, &device, &sigs).unwrap();
    let bytes = encode_to_vec(SCHEMA_CAST_RECORD, SCHEMA_VERSION_1, &record);
    let sigs_at = HEADER_LEN + 4 + body_bytes.len() + 64;
    let mut v = std::vec![valid("two module signatures", bytes.clone())];
    let mut b = bytes[..sigs_at].to_vec();
    b.extend_from_slice(&1u32.to_be_bytes());
    b.extend_from_slice(&bytes[sigs_at + 4..sigs_at + 4 + ident_len(b"mod-X") + 64]);
    fix_len(&mut b);
    v.push(invalid(
        "signature set differs from module counters",
        b,
        "InvariantViolation",
        sigs_at,
    ));
    let psid_at = HEADER_LEN + ident_len(E) + ident_len(BOX) + ident_len(STYLE);
    let mut b = bytes.clone();
    b[HEADER_LEN + 4 + psid_at + 1] = 2;
    v.push(invalid(
        "embedded body rejected at rebased offset",
        b,
        "ValueOutOfRange",
        HEADER_LEN + 4 + psid_at,
    ));
    check!(
        CastRecord<'_>,
        "cast_record.txt",
        "CastRecord",
        SCHEMA_CAST_RECORD,
        &v
    );
}

fn challenge_body_bytes() -> Vec<u8> {
    let rand = Scalars::<MAX_CHUNKS>::new(&scalars(2, 0x50)).unwrap();
    let modules = [
        ModuleOpening {
            module_id: ModuleId::new(b"mod-X").unwrap(),
            counter: 7,
            rand: Scalars::new(&scalars(2, 0x60)).unwrap(),
            cid: Token192(patterned::<24>(0xa0)),
        },
        ModuleOpening {
            module_id: ModuleId::new(b"mod-Y").unwrap(),
            counter: 9,
            rand: Scalars::new(&scalars(2, 0x61)).unwrap(),
            cid: Token192(patterned::<24>(0xa1)),
        },
    ];
    let body = ChallengeOpeningBody::new(&ChallengeOpeningParts {
        election_id: ElectionId::new(E).unwrap(),
        box_id: BoxId::new(BOX).unwrap(),
        ballot_style_id: BallotStyleId::new(STYLE).unwrap(),
        record_hash: patterned64(0x20),
        option_index: 3,
        cast_id: Token192(patterned::<24>(0x21)),
        rand: &rand,
        modules: &modules,
    })
    .unwrap();
    encode_to_vec(SCHEMA_CHALLENGE_OPENING_BODY, SCHEMA_VERSION_1, &body)
}

#[test]
fn challenge_opening_vectors() {
    let bytes = challenge_body_bytes();
    let index_at = HEADER_LEN + ident_len(E) + ident_len(BOX) + ident_len(STYLE) + 64;
    let rand_at = index_at + 2 + 24;
    let x_rand_at = rand_at + 4 + 64 + 4 + ident_len(b"mod-X") + 8;
    let mut v = std::vec![valid("option 3 two modules", bytes.clone())];
    let mut b = bytes.clone();
    b[index_at + 1] = 64;
    v.push(invalid("option index 64", b, "ValueOutOfRange", index_at));
    let mut b = bytes[..x_rand_at].to_vec();
    b.extend_from_slice(&1u32.to_be_bytes());
    b.extend_from_slice(&bytes[x_rand_at + 4..x_rand_at + 4 + 32]);
    b.extend_from_slice(&bytes[x_rand_at + 4 + 64..]);
    fix_len(&mut b);
    v.push(invalid(
        "module rand count differs",
        b,
        "InvariantViolation",
        x_rand_at,
    ));
    let x_at = rand_at + 4 + 64 + 4;
    let y_at = x_rand_at + 4 + 64 + 24;
    let mut b = bytes.clone();
    b[x_at + 4 + 4] = b'Y';
    b[y_at + 4 + 4] = b'X';
    v.push(invalid("modules out of order", b, "NotSorted", y_at));
    let mut b = bytes[..rand_at].to_vec();
    b.extend_from_slice(&0u32.to_be_bytes());
    b.extend_from_slice(&bytes[rand_at + 4 + 64..]);
    fix_len(&mut b);
    v.push(invalid("no rand", b, "ValueOutOfRange", rand_at));
    check!(
        ChallengeOpeningBody<'_>,
        "challenge_opening_body.txt",
        "ChallengeOpeningBody",
        SCHEMA_CHALLENGE_OPENING_BODY,
        &v,
    );

    let sig = patterned::<4691>(0x77);
    let event = ChallengeOpening::new(&bytes, &sig).unwrap();
    let eb = encode_to_vec(SCHEMA_CHALLENGE_OPENING, SCHEMA_VERSION_1, &event);
    let mut w = std::vec![valid("signed opening", eb.clone())];
    let mut b = eb.clone();
    b[HEADER_LEN + 4 + index_at + 1] = 64;
    w.push(invalid(
        "embedded body rejected at rebased offset",
        b,
        "ValueOutOfRange",
        HEADER_LEN + 4 + index_at,
    ));
    check!(
        ChallengeOpening<'_>,
        "challenge_opening.txt",
        "ChallengeOpening",
        SCHEMA_CHALLENGE_OPENING,
        &w,
    );
}

#[test]
fn share_package_vectors() {
    let ct_a = std::vec![0x11u8; 300];
    let ct_b = std::vec![0x22u8; 1900];
    let tag_a = patterned::<16>(0x01);
    let tag_b = patterned::<16>(0x02);
    let entries = [
        ShareEntry {
            trustee_id: TrusteeId::new(b"trustee-A").unwrap(),
            chamber: ChamberCode::X,
            transport: Transport::Pad {
                pad_id: 5,
                pad_index: 3_000,
            },
            ciphertext: &ct_a,
            tag: &tag_a,
        },
        ShareEntry {
            trustee_id: TrusteeId::new(b"trustee-B").unwrap(),
            chamber: ChamberCode::N,
            transport: Transport::Kem,
            ciphertext: &ct_b,
            tag: &tag_b,
        },
    ];
    let package = SharePackage::new(
        ElectionId::new(E).unwrap(),
        BoxId::new(BOX).unwrap(),
        &commitments(2, 0x10),
        &entries,
    )
    .unwrap();
    let bytes = encode_to_vec(SCHEMA_SHARE_PACKAGE, SCHEMA_VERSION_1, &package);
    let a_chamber =
        HEADER_LEN + ident_len(E) + ident_len(BOX) + 4 + 64 + 4 + ident_len(b"trustee-A");
    let b_chamber = a_chamber + 1 + 1 + 4 + 8 + 4 + 300 + 16 + ident_len(b"trustee-B");
    let mut v = std::vec![valid("pad and kem entries", bytes.clone())];
    let mut b = bytes.clone();
    b[a_chamber] = 7;
    v.push(invalid("chamber 7", b, "ValueOutOfRange", a_chamber));
    let mut b = bytes.clone();
    b[b_chamber + 2 + 3] = 1;
    v.push(invalid(
        "kem entry with pad id",
        b,
        "ValueOutOfRange",
        b_chamber + 2,
    ));
    let mut b = bytes.clone();
    b[b_chamber + 2 + 4 + 7] = 1;
    v.push(invalid(
        "kem entry with pad index",
        b,
        "ValueOutOfRange",
        b_chamber + 2 + 4,
    ));
    let mut b = bytes.clone();
    b[a_chamber + 1] = 2;
    v.push(invalid("transport 2", b, "ValueOutOfRange", a_chamber + 1));
    let a_at = a_chamber - ident_len(b"trustee-A");
    let b_at = b_chamber - ident_len(b"trustee-B");
    let mut b = bytes.clone();
    b[a_at + 4 + 8] = b'B';
    b[b_at + 4 + 8] = b'A';
    v.push(invalid("trustees out of order", b, "NotSorted", b_at));
    let commitments_at = HEADER_LEN + ident_len(E) + ident_len(BOX);
    let mut b = bytes.clone();
    b[commitments_at..commitments_at + 4].copy_from_slice(&0u32.to_be_bytes());
    v.push(invalid(
        "no commitments",
        b,
        "ValueOutOfRange",
        commitments_at,
    ));
    check!(
        SharePackage<'_>,
        "share_package.txt",
        "SharePackage",
        SCHEMA_SHARE_PACKAGE,
        &v,
    );
}

#[test]
fn member_share_vectors() {
    let tag = patterned::<16>(0x09);
    let with_module = MemberShare::new(
        &Scalars::<MAX_SECRETS>::new(&scalars(5, 0x80)).unwrap(),
        true,
        Token192(patterned::<24>(0x0a)),
        Some(Token192(patterned::<24>(0x0b))),
        &tag,
    )
    .unwrap();
    let zero = [0u8; 16];
    let without = MemberShare::new(
        &Scalars::<MAX_SECRETS>::new(&scalars(3, 0x80)).unwrap(),
        false,
        Token192([0; 24]),
        None,
        &zero,
    )
    .unwrap();
    let wb = encode_to_vec(SCHEMA_MEMBER_SHARE, SCHEMA_VERSION_1, &without);
    let cid_at = HEADER_LEN + 4 + 3 * 32 + 1;
    let mut m = std::vec![
        valid(
            "chamber with module and label",
            encode_to_vec(SCHEMA_MEMBER_SHARE, SCHEMA_VERSION_1, &with_module)
        ),
        valid("chamber without module", wb.clone()),
    ];
    let lab_at = cid_at + 24;
    let tag_at = lab_at + 1;
    let mut b = wb.clone();
    b[cid_at] = 1;
    m.push(invalid(
        "no module but non-zero cid",
        b,
        "InvariantViolation",
        cid_at,
    ));
    let mut b = wb[..lab_at].to_vec();
    b.push(1);
    b.extend_from_slice(&[0u8; 24]);
    b.extend_from_slice(&wb[lab_at + 1..]);
    fix_len(&mut b);
    m.push(invalid(
        "no module but label present",
        b,
        "InvariantViolation",
        lab_at,
    ));
    let mut b = wb.clone();
    b[tag_at + 15] = 1;
    m.push(invalid(
        "no module but non-zero tag",
        b,
        "InvariantViolation",
        tag_at,
    ));
    let mut b = wb.clone();
    b[HEADER_LEN..HEADER_LEN + 4].copy_from_slice(&0u32.to_be_bytes());
    m.push(invalid("no shares", b, "ValueOutOfRange", HEADER_LEN));
    check!(
        MemberShare<'_>,
        "member_share.txt",
        "MemberShare",
        SCHEMA_MEMBER_SHARE,
        &m
    );
}

fn batch_body_bytes() -> Vec<u8> {
    let ranges = [
        ModuleRange {
            module_id: ModuleId::new(b"mod-X").unwrap(),
            counter_first: 100,
            counter_last: 163,
        },
        ModuleRange {
            module_id: ModuleId::new(b"mod-Y").unwrap(),
            counter_first: 200,
            counter_last: 263,
        },
    ];
    let body = BatchAttestBody::new(&BatchAttestParts {
        election_id: ElectionId::new(E).unwrap(),
        box_id: BoxId::new(BOX).unwrap(),
        batch_index: 3,
        record_count: 64,
        records_root: patterned64(0x10),
        module_ranges: &ranges,
        module_refusals: ModuleIds::new(&[ModuleId::new(b"mod-Y").unwrap()]).unwrap(),
        journal_head: patterned64(0x20),
        time_bucket: TimeBucket::new(500),
    })
    .unwrap();
    encode_to_vec(SCHEMA_BATCH_ATTEST_BODY, SCHEMA_VERSION_1, &body)
}

#[test]
fn batch_attest_vectors() {
    let bytes = batch_body_bytes();
    let count_at = HEADER_LEN + ident_len(E) + ident_len(BOX) + 4;
    let x_last_at = count_at + 2 + 64 + 4 + ident_len(b"mod-X") + 8;
    let refusals_at = x_last_at + 8 + ident_len(b"mod-Y") + 16;
    let mut v = std::vec![valid("batch 3 with one refusal", bytes.clone())];
    let mut b = bytes.clone();
    b[count_at..count_at + 2].copy_from_slice(&65u16.to_be_bytes());
    v.push(invalid("record count 65", b, "ValueOutOfRange", count_at));
    let mut b = bytes.clone();
    b[x_last_at..x_last_at + 8].copy_from_slice(&99u64.to_be_bytes());
    v.push(invalid(
        "counter_last below counter_first",
        b,
        "ValueOutOfRange",
        x_last_at,
    ));
    let mut b = bytes.clone();
    b[refusals_at + 4 + 4 + 4] = b'Z';
    v.push(invalid(
        "refusal without a range",
        b,
        "InvariantViolation",
        refusals_at,
    ));
    check!(
        BatchAttestBody<'_>,
        "batch_attest_body.txt",
        "BatchAttestBody",
        SCHEMA_BATCH_ATTEST_BODY,
        &v,
    );

    let sx = patterned::<4691>(0x31);
    let device = patterned::<4691>(0x33);
    let sigs = [ModuleBatchSig {
        module_id: ModuleId::new(b"mod-X").unwrap(),
        sig: &sx,
    }];
    let event = BatchAttest::new(&bytes, &sigs, &device).unwrap();
    let eb = encode_to_vec(SCHEMA_BATCH_ATTEST, SCHEMA_VERSION_1, &event);
    let sigs_at = HEADER_LEN + 4 + bytes.len();
    let mut w = std::vec![valid("one module signature", eb.clone())];
    let mut b = eb[..sigs_at].to_vec();
    b.extend_from_slice(&0u32.to_be_bytes());
    b.extend_from_slice(&device);
    fix_len(&mut b);
    w.push(invalid(
        "missing module signature",
        b,
        "InvariantViolation",
        sigs_at,
    ));
    // mod-Y refused the batch, so its signature must not appear.
    let sy = patterned::<4691>(0x32);
    let mut b = eb[..sigs_at].to_vec();
    b.extend_from_slice(&2u32.to_be_bytes());
    b.extend_from_slice(&eb[sigs_at + 4..sigs_at + 4 + ident_len(b"mod-X") + 4691]);
    b.extend_from_slice(&5u32.to_be_bytes());
    b.extend_from_slice(b"mod-Y");
    b.extend_from_slice(&sy);
    b.extend_from_slice(&device);
    fix_len(&mut b);
    w.push(invalid(
        "signature from a refusing module",
        b,
        "InvariantViolation",
        sigs_at,
    ));
    check!(
        BatchAttest<'_>,
        "batch_attest.txt",
        "BatchAttest",
        SCHEMA_BATCH_ATTEST,
        &w
    );
}

#[test]
fn scan_count_attest_vectors() {
    let body = ScanCountAttestBody::new(
        ElectionId::new(E).unwrap(),
        BoxId::new(BOX).unwrap(),
        150,
        2,
        1,
        patterned64(0x40),
        TimeBucket::new(77),
    );
    let bytes = encode_to_vec(SCHEMA_SCAN_COUNT_ATTEST_BODY, SCHEMA_VERSION_1, &body);
    let mut v = std::vec![valid("counts 150 2 1", bytes.clone())];
    let mut b = bytes.clone();
    b[HEADER_LEN + 4] = b' ';
    v.push(invalid(
        "space in election id",
        b,
        "InvalidIdentByte",
        HEADER_LEN + 4,
    ));
    check!(
        ScanCountAttestBody<'_>,
        "scan_count_attest_body.txt",
        "ScanCountAttestBody",
        SCHEMA_SCAN_COUNT_ATTEST_BODY,
        &v,
    );

    let s1 = patterned::<4691>(0x51);
    let s2 = patterned::<4691>(0x52);
    let sigs = [
        ObserverSig {
            observer_id: ObserverId::new(b"obs-1").unwrap(),
            org_id: OrgId::new(b"org-A").unwrap(),
            sig: &s1,
        },
        ObserverSig {
            observer_id: ObserverId::new(b"obs-2").unwrap(),
            org_id: OrgId::new(b"org-B").unwrap(),
            sig: &s2,
        },
    ];
    let event = ScanCountAttest::new(&bytes, &sigs).unwrap();
    let eb = encode_to_vec(SCHEMA_SCAN_COUNT_ATTEST, SCHEMA_VERSION_1, &event);
    let sigs_at = HEADER_LEN + 4 + bytes.len();
    let one = ident_len(b"obs-1") + ident_len(b"org-A") + 4691;
    let org2_at = sigs_at + 4 + one + ident_len(b"obs-2") + 4;
    let mut w = std::vec![valid("two observers two organizations", eb.clone())];
    let mut b = eb.clone();
    b[org2_at + 4] = b'A';
    w.push(invalid(
        "observers from one organization",
        b,
        "InvariantViolation",
        sigs_at,
    ));
    let mut b = eb[..sigs_at].to_vec();
    b.extend_from_slice(&1u32.to_be_bytes());
    b.extend_from_slice(&eb[sigs_at + 4..sigs_at + 4 + one]);
    fix_len(&mut b);
    w.push(invalid(
        "one observer signature",
        b,
        "ValueOutOfRange",
        sigs_at,
    ));
    check!(
        ScanCountAttest<'_>,
        "scan_count_attest.txt",
        "ScanCountAttest",
        SCHEMA_SCAN_COUNT_ATTEST,
        &w,
    );
}

#[test]
fn box_close_vectors() {
    let body = BoxCloseBody::new(&BoxCloseParts {
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
        module_counters: ModuleCounters::new(&[module(b"mod-X", 994), module(b"mod-Y", 994)])
            .unwrap(),
        open_batches: 0,
        time_bucket: TimeBucket::new(900),
    });
    let bytes = encode_to_vec(SCHEMA_BOX_CLOSE_BODY, SCHEMA_VERSION_1, &body);
    let counters_at = HEADER_LEN + ident_len(E) + ident_len(BOX) + 48 + 192;
    let y_at = counters_at + 4 + ident_len(b"mod-X") + 8;
    let mut v = std::vec![valid("clean close", bytes.clone())];
    let mut b = bytes.clone();
    b[y_at + 4 + 4] = b'X';
    v.push(invalid("duplicate module", b, "Duplicate", y_at));
    check!(
        BoxCloseBody<'_>,
        "box_close_body.txt",
        "BoxCloseBody",
        SCHEMA_BOX_CLOSE_BODY,
        &v,
    );

    let s = patterned::<4691>(0x71);
    let device = patterned::<4691>(0x72);
    let att = |id: &'static [u8], role: SignerRole, org: &'static [u8]| Attestation {
        signer_id: SignerId::new(id).unwrap(),
        role,
        org_id: OrgId::new(org).unwrap(),
        sig: &s,
    };
    let attestations = [
        att(b"clerk-1", SignerRole::Clerk, b"nec"),
        att(b"clerk-2", SignerRole::Clerk, b"nec"),
        att(b"obs-1", SignerRole::Observer, b"party-A"),
        att(b"obs-2", SignerRole::Observer, b"party-B"),
    ];
    let signed = BoxClose::new(&bytes, Some(&device), &attestations).unwrap();
    let manual = BoxClose::new(&bytes, None, &attestations).unwrap();
    let sb = encode_to_vec(SCHEMA_BOX_CLOSE, SCHEMA_VERSION_1, &signed);
    let mb = encode_to_vec(SCHEMA_BOX_CLOSE, SCHEMA_VERSION_1, &manual);
    let att_at = HEADER_LEN + 4 + bytes.len() + 1;
    let role2_at =
        att_at + 4 + ident_len(b"clerk-1") + 1 + ident_len(b"nec") + 4691 + ident_len(b"clerk-2");
    let mut w = std::vec![
        valid("device signed close", sb.clone()),
        valid("manual close", mb.clone()),
    ];
    let mut b = mb.clone();
    b[role2_at] = 2;
    w.push(invalid("only one clerk", b, "InvariantViolation", att_at));
    let mut b = mb.clone();
    b[role2_at] = 3;
    w.push(invalid("role 3", b, "ValueOutOfRange", role2_at));
    let mut b = mb.clone();
    b[role2_at] = 0;
    w.push(invalid("role 0", b, "ValueOutOfRange", role2_at));
    let obs2_org_at = role2_at
        + 1
        + ident_len(b"nec")
        + 4691
        + ident_len(b"obs-1")
        + 1
        + ident_len(b"party-A")
        + 4691
        + ident_len(b"obs-2")
        + 1;
    let mut b = mb.clone();
    b[obs2_org_at + 4 + 6] = b'A';
    w.push(invalid(
        "observers from one organization",
        b,
        "InvariantViolation",
        att_at,
    ));
    let mut b = mb.clone();
    b[att_at - 1] = 2;
    w.push(invalid(
        "presence tag 2",
        b,
        "InvalidPresenceTag",
        att_at - 1,
    ));
    check!(
        BoxClose<'_>,
        "box_close.txt",
        "BoxClose",
        SCHEMA_BOX_CLOSE,
        &w
    );
}

#[test]
fn slip_vectors() {
    let body = SlipBody::new(
        ElectionId::new(E).unwrap(),
        StationId::new(b"station-0007").unwrap(),
        TimeBucket::new(41),
        patterned64(0x90),
    );
    let bytes = encode_to_vec(SCHEMA_SLIP_BODY, SCHEMA_VERSION_1, &body);
    let mut v = std::vec![valid("station 7 bucket 41", bytes.clone())];
    let mut b = bytes.clone();
    b.truncate(bytes.len() - 1);
    v.push(invalid("truncated", b, "BodyLengthMismatch", 12));
    check!(
        SlipBody<'_>,
        "slip_body.txt",
        "SlipBody",
        SCHEMA_SLIP_BODY,
        &v
    );

    let sig = patterned::<4691>(0x91);
    let slip = Slip::new(&bytes, &sig).unwrap();
    let sb = encode_to_vec(SCHEMA_SLIP, SCHEMA_VERSION_1, &slip);
    let mut w = std::vec![valid("signed slip", sb.clone())];
    let mut b = sb.clone();
    b[HEADER_LEN..HEADER_LEN + 4].copy_from_slice(&257u32.to_be_bytes());
    w.push(invalid(
        "body longer than 256",
        b,
        "LengthExceedsMax",
        HEADER_LEN,
    ));
    check!(Slip<'_>, "slip.txt", "Slip", SCHEMA_SLIP, &w);
}
