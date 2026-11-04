//! Kani bounded model-checking harnesses (verification ladder V2).
//!
//! Compiled only under `cargo kani`. Each harness states one property from
//! ENCODING.md. Kani additionally checks every harness for panics, overflow
//! and out-of-bounds access on all explored inputs, which is the mechanical
//! form of the crate's "no panics" promise.
//!
//! Run with `cargo kani -p ityv-encoding` from the workspace root. The file
//! lives outside `src/` and is included as `crate::proofs` by a `#[path]`
//! attribute in `src/lib.rs`.
// Harness file: outside the TCB and outside `src/` (CONSTITUTION.md §1.1).
// A harness states expected values with plain indexing and unchecked
// arithmetic on bounded symbolic inputs, and Kani itself reports any panic
// or overflow in them, so these restriction lints are relaxed for this file
// only.
#![allow(
    clippy::unreachable,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::missing_panics_doc
)]

use crate::codec::{Decode, Encode};
use crate::envelope::{Header, MAGIC, decode, encode};
use crate::error::Kind;
use crate::primitives::{ElectionId, Hash512, Ident, SchemaId, Seq};
use crate::reader::Reader;
use crate::schema::ledger_frame::LedgerFrame;
use crate::schema::{SCHEMA_LEDGER_FRAME, SCHEMA_VERSION_1};
use crate::writer::Writer;

/// `u64` survives a write/read round trip and consumes exactly eight bytes.
#[kani::proof]
fn u64_round_trip() {
    let value: u64 = kani::any();
    let mut buf = [0u8; 8];
    let mut w = Writer::new(&mut buf);
    assert!(w.write_u64(value).is_ok());
    assert_eq!(w.finish(), 8);
    let mut r = Reader::new(&buf);
    assert_eq!(r.read_u64(), Ok(value));
    assert!(r.finish().is_ok());
}

/// `u32` and `u16` round trips.
#[kani::proof]
fn small_int_round_trips() {
    let a: u32 = kani::any();
    let b: u16 = kani::any();
    let mut buf = [0u8; 6];
    let mut w = Writer::new(&mut buf);
    assert!(w.write_u32(a).is_ok());
    assert!(w.write_u16(b).is_ok());
    let mut r = Reader::new(&buf);
    assert_eq!(r.read_u32(), Ok(a));
    assert_eq!(r.read_u16(), Ok(b));
    assert!(r.finish().is_ok());
}

/// A `bool` byte decodes if and only if it is `0x00` or `0x01`.
#[kani::proof]
fn bool_is_strict() {
    let byte: u8 = kani::any();
    let buf = [byte];
    let mut r = Reader::new(&buf);
    let result = r.read_bool();
    assert_eq!(result.is_ok(), byte == 0 || byte == 1);
    if byte > 1 {
        assert_eq!(
            result.map(|_| ()).err().map(|e| e.kind()),
            Some(Kind::InvalidBool)
        );
    }
}

/// A presence tag decodes if and only if it is `0x00` or `0x01`.
#[kani::proof]
fn presence_is_strict() {
    let byte: u8 = kani::any();
    let buf = [byte];
    let mut r = Reader::new(&buf);
    let result = r.read_presence();
    assert_eq!(result.is_ok(), byte == 0 || byte == 1);
}

/// `Ident::new` accepts exactly the strings of length 1..=max over the
/// alphabet `[A-Za-z0-9._:-]`.
#[kani::proof]
#[kani::unwind(6)]
fn ident_alphabet_is_exact() {
    const N: usize = 4;
    let bytes: [u8; N] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= N);
    let (prefix, _) = bytes.split_at_checked(len).unwrap_or((&[], &bytes));
    let accepted = Ident::new(prefix, N).is_some();
    let expected = len >= 1 && prefix.iter().all(|b| Ident::is_valid_byte(*b));
    assert_eq!(accepted, expected);
}

/// `Ident::is_valid_byte` matches the specified alphabet exactly.
#[kani::proof]
fn ident_byte_alphabet() {
    let b: u8 = kani::any();
    let expected = b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b':' || b == b'-';
    assert_eq!(Ident::is_valid_byte(b), expected);
}

/// A header whose first four bytes are not the magic is rejected at offset 0.
#[kani::proof]
fn header_rejects_bad_magic() {
    let input: [u8; 16] = kani::any();
    let magic_ok = input.first_chunk::<4>().is_some_and(|m| *m == MAGIC);
    kani::assume(!magic_ok);
    let mut r = Reader::new(&input);
    let result = Header::read(&mut r);
    assert_eq!(
        result.err().map(|e| (e.kind(), e.offset())),
        Some((Kind::BadMagic, 0))
    );
}

/// A header with non-zero flags or a wrong body length is rejected.
#[kani::proof]
fn header_rejects_flags_and_length() {
    let flags: u16 = kani::any();
    let body_len: u32 = kani::any();
    let mut buf = [0u8; 16];
    let mut w = Writer::new(&mut buf);
    assert!(w.write_array(&MAGIC).is_ok());
    assert!(w.write_u32(1).is_ok());
    assert!(w.write_u16(1).is_ok());
    assert!(w.write_u16(flags).is_ok());
    assert!(w.write_u32(body_len).is_ok());
    let mut r = Reader::new(&buf);
    let result = Header::read(&mut r);
    if flags != 0 {
        assert_eq!(result.err().map(|e| e.kind()), Some(Kind::NonZeroFlags));
    } else if body_len != 0 {
        assert_eq!(
            result.err().map(|e| e.kind()),
            Some(Kind::BodyLengthMismatch)
        );
    } else {
        assert!(result.is_ok());
    }
}

/// The reader never panics on arbitrary bounded input, whatever sequence of
/// reads is attempted.
#[kani::proof]
#[kani::unwind(10)]
fn reader_never_panics() {
    let buf: [u8; 24] = kani::any();
    let mut r = Reader::new(&buf);
    let _ = r.read_u8();
    let _ = r.read_u16();
    let _ = r.read_u32();
    let _ = r.read_u64();
    let _ = r.read_bool();
    let _ = r.read_presence();
    let _ = r.read_len(8);
    let _ = r.read_count(8);
    let _ = r.read_bytes(8);
    let _ = r.read_ident(8);
    let _ = r.read_array::<3>();
    let _ = r.take(5);
    let _ = r.finish();
}

/// The writer never panics on arbitrary bounded output space.
#[kani::proof]
fn writer_never_panics() {
    let mut buf = [0u8; 12];
    let limit: usize = kani::any();
    kani::assume(limit <= 12);
    let (out, _) = buf
        .split_at_mut_checked(limit)
        .unwrap_or((&mut [], &mut []));
    let mut w = Writer::new(out);
    let _ = w.write_u8(kani::any());
    let _ = w.write_u16(kani::any());
    let _ = w.write_u32(kani::any());
    let _ = w.write_u64(kani::any());
    let _ = w.write_bool(kani::any());
    let _ = w.write_bytes(b"ab", 2);
    assert!(w.finish() <= limit);
}

/// A `LedgerFrame` with arbitrary hashes and a non-zero sequence survives an
/// object-level round trip, and decoding consumes every byte.
#[kani::proof]
#[kani::unwind(70)] // 64-byte array comparisons unroll to 64 iterations plus slack.
fn ledger_frame_round_trip() {
    let seq_raw: u64 = kani::any();
    kani::assume(seq_raw >= 1);
    let Some(seq) = Seq::new(seq_raw) else {
        unreachable!("seq_raw >= 1 by assumption");
    };
    let prev: [u8; 64] = kani::any();
    let event: [u8; 64] = kani::any();
    let schema_raw: u32 = kani::any();
    let Some(election_id) = ElectionId::new(b"E") else {
        unreachable!("literal identifier is valid");
    };
    let frame = LedgerFrame::new(
        election_id,
        seq,
        Hash512(prev),
        SchemaId::new(schema_raw),
        Hash512(event),
    );
    let mut buf = [0u8; 256];
    let Ok(len) = encode(SCHEMA_LEDGER_FRAME, SCHEMA_VERSION_1, &frame, &mut buf) else {
        unreachable!("256 bytes suffice for a one-byte identifier");
    };
    assert_eq!(len, 16 + frame.encoded_len());
    let (bytes, _) = buf.split_at_checked(len).unwrap_or((&[], &buf));
    let decoded: Result<LedgerFrame<'_>, _> = decode(SCHEMA_LEDGER_FRAME, SCHEMA_VERSION_1, bytes);
    assert_eq!(decoded, Ok(frame));
}

/// A zero sequence number is rejected at the offset of the `seq` field.
#[kani::proof]
#[kani::unwind(4)]
fn ledger_frame_rejects_zero_seq() {
    let mut buf = [0u8; 256];
    let mut w = Writer::new(&mut buf);
    assert!(w.write_u32(1).is_ok());
    assert!(w.write_u8(b'E').is_ok());
    assert!(w.write_u64(0).is_ok());
    let result = LedgerFrame::decode(&mut Reader::new(&buf));
    assert_eq!(
        result.err().map(|e| (e.kind(), e.offset())),
        Some((Kind::ValueOutOfRange, 5))
    );
}

// ---------------------------------------------------------------------------
// M3 schemas (ENCODING.md §8.6–§8.18)
// ---------------------------------------------------------------------------

use crate::primitives::{BoxId, StationId, TimeBucket};
use crate::schema::SCHEMA_SCAN_COUNT_ATTEST_BODY;
use crate::schema::batch_attest::record_count_valid;
use crate::schema::box_close::SignerRole;
use crate::schema::cast_record::{ProofHeader, transport_flags_valid};
use crate::schema::scan_count::ScanCountAttestBody;
use crate::schema::share_package::{ChamberCode, pad_fields_valid, transport_code_valid};
use crate::schema::slip::SlipBody;

/// `SlipBody::new` accepts exactly one to eight tracking codes without a
/// repeat, and keeps them in position order, for every count `0..=9`. The
/// codes are symbolic in their first byte (the rest zero), so equality is
/// equality of that byte. The count runs over concrete values: a symbolic
/// slice length would unroll every comparison loop to the bound. The
/// object-level round trip of this body with an array field is covered by
/// V1 like the other array bodies (README).
#[kani::proof]
#[kani::unwind(70)] // 64-byte array comparisons unroll to 64 iterations plus slack.
fn slip_body_constructor_is_exact() {
    const SLOTS: usize = 9;
    let firsts: [u8; SLOTS] = kani::any();
    let mut codes = [Hash512::ZERO; SLOTS];
    for (code, first) in codes.iter_mut().zip(firsts) {
        code.0[0] = first;
    }
    let Some(election_id) = ElectionId::new(b"E") else {
        unreachable!("literal identifier is valid");
    };
    let Some(station_id) = StationId::new(b"S") else {
        unreachable!("literal identifier is valid");
    };
    for n in 0..=SLOTS {
        let built = SlipBody::new(election_id, station_id, TimeBucket::new(0), &codes[..n]);
        let mut distinct = true;
        for i in 0..n {
            for j in 0..i {
                if firsts[i] == firsts[j] {
                    distinct = false;
                }
            }
        }
        assert_eq!(built.is_some(), (1..=8).contains(&n) && distinct);
        if let Some(body) = built {
            assert_eq!(body.tracking_codes().len(), n);
            for i in 0..n {
                assert_eq!(body.tracking_codes()[i].0[0], firsts[i]);
            }
        }
    }
}

/// A `ScanCountAttestBody` with symbolic counts and bucket survives an
/// object-level round trip (the journal head is concrete to keep the model
/// small; its bytes are copied verbatim like every other digest).
#[kani::proof]
#[kani::unwind(70)]
fn scan_count_body_round_trip() {
    let records: u64 = kani::any();
    let challenges: u64 = kani::any();
    let quarantines: u64 = kani::any();
    let bucket: u64 = kani::any();
    let Some(election_id) = ElectionId::new(b"E") else {
        unreachable!("literal identifier is valid");
    };
    let Some(box_id) = BoxId::new(b"B") else {
        unreachable!("literal identifier is valid");
    };
    let body = ScanCountAttestBody::new(
        election_id,
        box_id,
        records,
        challenges,
        quarantines,
        Hash512([7; 64]),
        TimeBucket::new(bucket),
    );
    let mut buf = [0u8; 160];
    let Ok(len) = encode(
        SCHEMA_SCAN_COUNT_ATTEST_BODY,
        SCHEMA_VERSION_1,
        &body,
        &mut buf,
    ) else {
        unreachable!("160 bytes suffice for one-byte identifiers");
    };
    assert_eq!(len, 16 + 5 + 5 + 24 + 64 + 8);
    let (bytes, _) = buf.split_at_checked(len).unwrap_or((&[], &buf));
    let decoded: Result<ScanCountAttestBody<'_>, _> =
        decode(SCHEMA_SCAN_COUNT_ATTEST_BODY, SCHEMA_VERSION_1, bytes);
    assert_eq!(decoded, Ok(body));
}

/// The proof header check of a cast record body, stated against PROTOCOL
/// §7.5 written out independently of the implementation: for any header
/// bytes and any claimed proof length, the header parses exactly when
/// `2 <= option_count <= 64`, `chunk_count` is the integer
/// `(option_count + 8) / 9`, and the length is
/// `3 + 32·option_count·chunk_count + 64·option_count` (one 32-byte
/// scalar per option per chunk, plus two per option). Hence a chunk count
/// that differs from the commitment count can never pass the body's
/// cross-field check.
#[kani::proof]
#[kani::unwind(4)]
fn proof_header_is_exact() {
    let head: [u8; 3] = kani::any();
    let len: usize = kani::any();
    let option_count = u16::from_be_bytes([head[0], head[1]]);
    let chunk_count = head[2];
    // Model the proof as its header plus an opaque tail of `len - 3` bytes;
    // the parser reads only the header and the total length.
    let parsed = ProofHeader::parse_with_len(head, len);
    let oc = usize::from(option_count);
    let cc = usize::from(chunk_count);
    let expected =
        (2..=64).contains(&option_count) && cc == (oc + 8) / 9 && len == 3 + 32 * oc * cc + 64 * oc;
    assert_eq!(parsed.is_some(), expected);
    if let Some(h) = parsed {
        assert_eq!(h.option_count, option_count);
        assert_eq!(h.chunk_count, chunk_count);
    }
}

// ---------------------------------------------------------------------------
// Finite-domain cross-field checks (ENCODING.md §8.6, §8.10, §8.12, §8.17)
// ---------------------------------------------------------------------------

/// `transport_flags` admits exactly the values whose bits above bit 1 are
/// clear (bit 0 KEM fallback, bit 1 neutral module).
#[kani::proof]
fn transport_flags_mask_is_exact() {
    let flags: u8 = kani::any();
    assert_eq!(transport_flags_valid(flags), flags >> 2 == 0);
}

/// Chamber codes: exactly 1 P1, 2 P2, 3 P3, 4 P4, 5 J, 6 A, 7 C, 8 N
/// decode, each to the chamber whose code it is; every other byte is
/// rejected (ADR-0019).
#[kani::proof]
fn chamber_codes_are_exact() {
    let code: u8 = kani::any();
    let expected = match code {
        1 => Some(ChamberCode::P1),
        2 => Some(ChamberCode::P2),
        3 => Some(ChamberCode::P3),
        4 => Some(ChamberCode::P4),
        5 => Some(ChamberCode::J),
        6 => Some(ChamberCode::A),
        7 => Some(ChamberCode::C),
        8 => Some(ChamberCode::N),
        _ => None,
    };
    assert_eq!(ChamberCode::from_code(code), expected);
    if let Some(chamber) = expected {
        assert_eq!(chamber.code(), code);
    }
}

/// Signer roles: exactly 1 (clerk) and 2 (observer) decode, each to the
/// role whose code it is; every other byte is rejected.
#[kani::proof]
fn signer_role_codes_are_exact() {
    let code: u8 = kani::any();
    let expected = match code {
        1 => Some(SignerRole::Clerk),
        2 => Some(SignerRole::Observer),
        _ => None,
    };
    assert_eq!(SignerRole::from_code(code), expected);
    if let Some(role) = expected {
        assert_eq!(role.code(), code);
    }
}

/// Transport codes and KEM pad fields: transport 0 admits any pad fields,
/// transport 1 only zero pad fields, and every other code is rejected.
#[kani::proof]
fn transport_and_pad_fields_are_exact() {
    let code: u8 = kani::any();
    let pad_id: u32 = kani::any();
    let pad_index: u64 = kani::any();
    assert_eq!(transport_code_valid(code), code == 0 || code == 1);
    let expected = match code {
        0 => true,
        1 => pad_id == 0 && pad_index == 0,
        _ => false,
    };
    assert_eq!(
        transport_code_valid(code) && pad_fields_valid(code, pad_id, pad_index),
        expected
    );
}

/// `record_count` admits exactly `1..=64`.
#[kani::proof]
fn record_count_range_is_exact() {
    let record_count: u16 = kani::any();
    assert_eq!(
        record_count_valid(record_count),
        record_count != 0 && record_count < 65
    );
}

use crate::primitives::{OrgId, SignerId};
use crate::schema::audit::{AuditRound, AuditRounds, ComparisonCode};
use crate::schema::checkin::ObserverCountKind;
use crate::schema::events::{
    CustodyHandoffBody, CustodyHandoffParts, DisputeAction, DisputeEventBody, DisputeEventParts,
    DisputeType, FallbackBody, FallbackKind, FallbackParts, FallbackReason, LateBatchReason,
    LegalOutcome, SealChangeReason, TallyEffect,
};
use crate::schema::genesis::{CaptureProfile, RosterRole, StationKind};
use crate::schema::genesis_body::AmendmentReason;
use crate::schema::tally::{ExclusionReason, ReceiptOutcome};
use crate::schema::witnessed::EventRole;

static E1: ElectionId<'static> = match ElectionId::new(b"E") {
    Some(id) => id,
    None => unreachable!(),
};
static B1: BoxId<'static> = match BoxId::new(b"B") {
    Some(id) => id,
    None => unreachable!(),
};
static S1: SignerId<'static> = match SignerId::new(b"S") {
    Some(id) => id,
    None => unreachable!(),
};
static ORG_A: OrgId<'static> = match OrgId::new(b"A") {
    Some(id) => id,
    None => unreachable!(),
};
static ORG_B: OrgId<'static> = match OrgId::new(b"B") {
    Some(id) => id,
    None => unreachable!(),
};

/// Every one-byte code of the M5 event schemas decodes exactly to the
/// value whose code it is, and nothing else decodes.
#[kani::proof]
fn event_codes_are_exact() {
    let code: u8 = kani::any();
    let role = EventRole::from_code(code);
    assert_eq!(role.is_some(), (1..=10).contains(&code));
    if let Some(r) = role {
        assert_eq!(r.code(), code);
    }
    let checks = [
        (DisputeType::from_code(code).map(DisputeType::code), 1..=8),
        (
            DisputeAction::from_code(code).map(DisputeAction::code),
            1..=4,
        ),
        (LegalOutcome::from_code(code).map(LegalOutcome::code), 1..=5),
        (TallyEffect::from_code(code).map(TallyEffect::code), 0..=2),
        (FallbackKind::from_code(code).map(FallbackKind::code), 1..=2),
        (
            FallbackReason::from_code(code).map(FallbackReason::code),
            0..=4,
        ),
        (
            SealChangeReason::from_code(code).map(SealChangeReason::code),
            1..=5,
        ),
        (
            LateBatchReason::from_code(code).map(LateBatchReason::code),
            1..=4,
        ),
        (
            CaptureProfile::from_code(code).map(CaptureProfile::code),
            1..=3,
        ),
        (RosterRole::from_code(code).map(RosterRole::code), 1..=6),
        (StationKind::from_code(code).map(StationKind::code), 1..=3),
        (
            AmendmentReason::from_code(code).map(AmendmentReason::code),
            1..=4,
        ),
        (
            ObserverCountKind::from_code(code).map(ObserverCountKind::code),
            1..=2,
        ),
        (
            ExclusionReason::from_code(code).map(ExclusionReason::code),
            1..=8,
        ),
        (
            ReceiptOutcome::from_code(code).map(ReceiptOutcome::code),
            1..=5,
        ),
        (
            ComparisonCode::from_code(code).map(ComparisonCode::code),
            0..=6,
        ),
    ];
    for (decoded, range) in checks {
        assert_eq!(decoded.is_some(), range.contains(&code));
        if let Some(back) = decoded {
            assert_eq!(back, code);
        }
    }
}

/// A custody handoff body is built exactly when the index is at least 1,
/// the previous hash is zero exactly for index 1, and the organisations
/// differ.
#[kani::proof]
fn custody_handoff_rules_are_exact() {
    let index: u32 = kani::any();
    let zero_previous: bool = kani::any();
    let same_org: bool = kani::any();
    let parts = CustodyHandoffParts {
        election_id: E1,
        box_id: B1,
        index,
        from_signer: S1,
        from_org: ORG_A,
        to_signer: S1,
        to_org: if same_org { ORG_A } else { ORG_B },
        previous_handoff_hash: if zero_previous {
            Hash512([0; 64])
        } else {
            Hash512([1; 64])
        },
        seal_digest: Hash512([2; 64]),
        count: kani::any(),
        time_bucket: TimeBucket::new(kani::any()),
    };
    let expected = index >= 1 && (index == 1) == zero_previous && !same_org;
    assert_eq!(CustodyHandoffBody::new(&parts).is_ok(), expected);
}

/// A dispute event body is built exactly when the filing hash is zero
/// exactly for a filing, the result hash is nonzero exactly for the two
/// resolutions, and a record is named only with its box.
#[kani::proof]
fn dispute_event_rules_are_exact() {
    let action = match kani::any::<u8>() % 4 {
        0 => DisputeAction::Filed,
        1 => DisputeAction::Investigating,
        2 => DisputeAction::ResolvedTechnical,
        _ => DisputeAction::ReferredLegal,
    };
    let zero_filing: bool = kani::any();
    let zero_result: bool = kani::any();
    let with_box: bool = kani::any();
    let with_record: bool = kani::any();
    let parts = DisputeEventParts {
        election_id: E1,
        action,
        dispute_type: DisputeType::Other,
        box_id: if with_box { Some(B1) } else { None },
        record_hash: if with_record {
            Some(Hash512([3; 64]))
        } else {
            None
        },
        evidence_hash: Hash512([4; 64]),
        filing_hash: if zero_filing {
            Hash512([0; 64])
        } else {
            Hash512([5; 64])
        },
        result_hash: if zero_result {
            Hash512([0; 64])
        } else {
            Hash512([6; 64])
        },
        time_bucket: TimeBucket::new(0),
    };
    let filed = action == DisputeAction::Filed;
    let resolved = matches!(
        action,
        DisputeAction::ResolvedTechnical | DisputeAction::ReferredLegal
    );
    let expected = filed == zero_filing && resolved != zero_result && (with_box || !with_record);
    assert_eq!(DisputeEventBody::new(&parts).is_ok(), expected);
}

/// A fallback body is built exactly when the reason is `NotApplicable`
/// exactly for an end and a marker range runs forward.
#[kani::proof]
fn fallback_rules_are_exact() {
    let ended: bool = kani::any();
    let reason_code: u8 = kani::any();
    let Some(reason) = FallbackReason::from_code(reason_code) else {
        return;
    };
    let first: u64 = kani::any();
    let last: u64 = kani::any();
    let with_markers: bool = kani::any();
    let parts = FallbackParts {
        election_id: E1,
        box_id: B1,
        kind: if ended {
            FallbackKind::Ended
        } else {
            FallbackKind::Declared
        },
        reason,
        statement_hash: Hash512([7; 64]),
        markers: if with_markers {
            Some(crate::schema::events::MarkerRange { first, last })
        } else {
            None
        },
        time_bucket: TimeBucket::new(0),
    };
    let expected = ended == (reason_code == 0) && (!with_markers || first <= last);
    assert_eq!(FallbackBody::new(&parts).is_ok(), expected);
}

use crate::primitives::UnitId;
use crate::schema::SCHEMA_BOX_PROGRESS_BODY;
use crate::schema::genesis::StationProgressPolicy;
use crate::schema::progress::{
    BoxProgressBody, BoxProgressParts, BoxProgressState, CheckinProgressBody, CheckinProgressParts,
    CheckinProgressState, ProgressAlarm, ProgressCheckBody, ProgressCheckParts, ProgressFinding,
};

static ST1: StationId<'static> = match StationId::new(b"S") {
    Some(id) => id,
    None => unreachable!(),
};

static U1: UnitId<'static> = match UnitId::new(b"U") {
    Some(id) => id,
    None => unreachable!(),
};

/// A check-in progress body is built exactly when the spoiled and returned
/// sheets together do not exceed the issued sheets, computed without
/// overflow (ENCODING.md §8.45).
#[kani::proof]
fn checkin_progress_rules_are_exact() {
    let issued: u64 = kani::any();
    let spoiled: u64 = kani::any();
    let returned: u64 = kani::any();
    let parts = CheckinProgressParts {
        election_id: E1,
        station_id: ST1,
        unit_id: U1,
        slot: kani::any(),
        checkins: kani::any(),
        issued,
        spoiled,
        returned,
        state: CheckinProgressState::Checking,
    };
    let expected = u128::from(spoiled) + u128::from(returned) <= u128::from(issued);
    assert_eq!(CheckinProgressBody::new(&parts).is_ok(), expected);
}

/// A progress-check body is built exactly when sheets are named for a
/// carried-out finding and only then (ENCODING.md §8.47).
#[kani::proof]
fn progress_check_rules_are_exact() {
    let Some(finding) = ProgressFinding::from_code(kani::any()) else {
        return;
    };
    let carried_out: u64 = kani::any();
    let parts = ProgressCheckParts {
        election_id: E1,
        station_id: ST1,
        alarm_slot: kani::any(),
        alarm: ProgressAlarm::Floor,
        holding: kani::any(),
        finding,
        carried_out,
        statement_hash: Hash512([5; 64]),
        time_bucket: TimeBucket::new(0),
    };
    let expected = (finding.code() == 2) == (carried_out >= 1);
    assert_eq!(ProgressCheckBody::new(&parts).is_ok(), expected);
}

/// A box progress body with symbolic slot, count and state survives an
/// object-level round trip.
#[kani::proof]
#[kani::unwind(70)]
fn box_progress_round_trip() {
    let Some(state) = BoxProgressState::from_code(kani::any()) else {
        return;
    };
    let body = BoxProgressBody::new(&BoxProgressParts {
        election_id: E1,
        box_id: B1,
        slot: kani::any(),
        sheets_in: kani::any(),
        state,
    });
    let mut buf = [0u8; 64];
    let Ok(len) = encode(SCHEMA_BOX_PROGRESS_BODY, SCHEMA_VERSION_1, &body, &mut buf) else {
        unreachable!("64 bytes suffice for one-byte identifiers");
    };
    assert_eq!(len, 16 + 5 + 5 + 17);
    let (bytes, _) = buf.split_at_checked(len).unwrap_or((&[], &buf));
    let decoded: Result<BoxProgressBody<'_>, _> =
        decode(SCHEMA_BOX_PROGRESS_BODY, SCHEMA_VERSION_1, bytes);
    assert_eq!(decoded, Ok(body));
}

/// A station progress policy is built exactly when both counts are
/// nonzero.
#[kani::proof]
fn station_progress_policy_rules_are_exact() {
    let booths: u16 = kani::any();
    let limit: u32 = kani::any();
    assert_eq!(
        StationProgressPolicy::new(ST1, booths, limit).is_ok(),
        booths >= 1 && limit >= 1
    );
}

// ---------------------------------------------------------------------------
// The genesis and the check-in events (ADR-0028)

use crate::primitives::BallotStyleId;
use crate::schema::SCHEMA_OBSERVER_COUNT_ATTEST_BODY;
use crate::schema::checkin::{
    BoxUnitSwapBody, BoxUnitSwapParts, CheckinUnitSwapBody, CheckinUnitSwapParts,
    ObserverCountAttestBody, ObserverCountParts,
};
use crate::schema::genesis::{BallotStyleEntry, chunks_for};
use crate::schema::genesis_body::WitnessQuorum;

static BS1: BallotStyleId<'static> = match BallotStyleId::new(b"P") {
    Some(id) => id,
    None => unreachable!(),
};

static U2: UnitId<'static> = match UnitId::new(b"V") {
    Some(id) => id,
    None => unreachable!(),
};

/// A ballot style is built exactly for one to seventy choices, and its
/// chunk count is `⌈(m + 2)/9⌉` (PROTOCOL.md §7.4).
#[kani::proof]
fn ballot_style_rules_are_exact() {
    let choices: u16 = kani::any();
    let entry = BallotStyleEntry::new(BS1, choices, Hash512([1; 64]));
    assert_eq!(entry.is_ok(), (1..=70).contains(&choices));
    if let Ok(e) = entry {
        let m = u32::from(choices);
        assert_eq!(u32::from(e.chunks()), (m + 2).div_ceil(9));
        assert!(e.chunks() >= 1 && e.chunks() <= 8);
    }
    assert_eq!(chunks_for(choices), (u32::from(choices) + 2).div_ceil(9));
}

/// The witness quorum profile is accepted exactly when `13 ≤ n ≤ 64`,
/// `9 ≤ q ≤ n`, `2q − n > f` and the diversity minimums lie in
/// `[7, q]`, `[4, q]`, `[3, q]` (PROTOCOL.md §5.4).
#[kani::proof]
fn witness_quorum_rule_is_exact() {
    let q = WitnessQuorum {
        witnesses: kani::any(),
        quorum: kani::any(),
        byzantine_max: kani::any(),
        min_orgs: kani::any(),
        min_providers: kani::any(),
        min_regions: kani::any(),
    };
    let n = u32::from(q.witnesses);
    let k = u32::from(q.quorum);
    let f = u32::from(q.byzantine_max);
    let within = |v: u8, floor: u8| v >= floor && v <= q.quorum;
    let expected = (13..=64).contains(&n)
        && k >= 9
        && k <= n
        && 2 * k > n + f
        && within(q.min_orgs, 7)
        && within(q.min_providers, 4)
        && within(q.min_regions, 3);
    assert_eq!(q.is_valid(), expected);
}

/// A check-in unit swap is built exactly for two different units, a
/// sequence from 1, and zero counts unless confirmed; a commitment-unit
/// swap exactly for zero sheets unless confirmed (ENCODING.md §8.58,
/// §8.59).
#[kani::proof]
fn swap_rules_are_exact() {
    let same: bool = kani::any();
    let confirmed: bool = kani::any();
    let next_seq: u64 = kani::any();
    let issued: u64 = kani::any();
    let spoiled: u64 = kani::any();
    let returned: u64 = kani::any();
    let parts = CheckinUnitSwapParts {
        election_id: E1,
        station_id: ST1,
        failed_unit: U1,
        spare_unit: if same { U1 } else { U2 },
        at_slot: kani::any(),
        confirmed,
        next_seq,
        issued,
        spoiled,
        returned,
    };
    let zero = issued == 0 && spoiled == 0 && returned == 0;
    let expected = !same && next_seq >= 1 && (confirmed || zero);
    assert_eq!(CheckinUnitSwapBody::new(&parts).is_ok(), expected);
    assert_eq!(parts.counts()[0], next_seq.saturating_sub(1));
    let sheets_in: u64 = kani::any();
    let box_parts = BoxUnitSwapParts {
        election_id: E1,
        box_id: B1,
        at_slot: kani::any(),
        confirmed,
        sheets_in,
    };
    assert_eq!(
        BoxUnitSwapBody::new(&box_parts).is_ok(),
        confirmed || sheets_in == 0
    );
}

/// An observer count with symbolic count, kind and bucket survives an
/// object-level round trip.
#[kani::proof]
#[kani::unwind(70)]
fn observer_count_round_trip() {
    let Some(kind) = crate::schema::checkin::ObserverCountKind::from_code(kani::any()) else {
        return;
    };
    let body = ObserverCountAttestBody::new(&ObserverCountParts {
        election_id: E1,
        station_id: ST1,
        unit_id: U1,
        count: kani::any(),
        kind,
        time_bucket: TimeBucket::new(kani::any()),
    });
    let mut buf = [0u8; 64];
    let Ok(len) = encode(
        SCHEMA_OBSERVER_COUNT_ATTEST_BODY,
        SCHEMA_VERSION_1,
        &body,
        &mut buf,
    ) else {
        unreachable!("64 bytes suffice for one-byte identifiers");
    };
    assert_eq!(len, 16 + 5 + 5 + 5 + 17);
    let (bytes, _) = buf.split_at_checked(len).unwrap_or((&[], &buf));
    let decoded: Result<ObserverCountAttestBody<'_>, _> =
        decode(SCHEMA_OBSERVER_COUNT_ATTEST_BODY, SCHEMA_VERSION_1, bytes);
    assert_eq!(decoded, Ok(body));
}

/// Two rounds of a sampling rule are accepted exactly when each size is in
/// `1..=2^26 − 1` with its threshold below it, the second size is above
/// the first and the second threshold is not below the first (ADR-0036);
/// one round alone exactly when its size is in range and its threshold
/// below it.
#[kani::proof]
#[kani::unwind(4)]
fn audit_round_rules_are_exact() {
    let first = AuditRound {
        sample_size: kani::any(),
        threshold: kani::any(),
    };
    let second = AuditRound {
        sample_size: kani::any(),
        threshold: kani::any(),
    };
    let in_range = |r: AuditRound| {
        r.sample_size >= 1 && r.sample_size <= 67_108_863 && u64::from(r.threshold) < r.sample_size
    };
    assert_eq!(AuditRounds::new(&[first]).is_some(), in_range(first));
    let expected = in_range(first)
        && in_range(second)
        && second.sample_size > first.sample_size
        && second.threshold >= first.threshold;
    let built = AuditRounds::new(&[first, second]);
    assert_eq!(built.is_some(), expected);
    if let Some(r) = built {
        assert_eq!(r.count(), 2);
        assert_eq!(r.get(0), Some(first));
        assert_eq!(r.get(1), Some(second));
        assert_eq!(r.get(2), None);
    }
}
