//! Construction, invariant, round-trip and rejection tests for the cast
//! record, challenge opening and share package schemas (ENCODING.md
//! §8.6–§8.11).
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

use common::{commitments, encode_to_vec, ident_len, patterned, patterned64, proof_bytes, scalars};
use ityv_encoding::{
    BallotStyleId, BoxId, CastRecord, CastRecordBody, CastRecordParts, ChallengeOpening,
    ChallengeOpeningBody, ChallengeOpeningParts, ChamberCode, Commitments, ElectionId, Encode as _,
    ErrorKind, HEADER_LEN, Hash512, MAX_CAST_RECORD_BODY_LEN, MAX_CHUNKS, MAX_PROOF_LEN,
    MAX_SECRETS, MemberShare, ModuleCounter, ModuleCounters, ModuleId, ModuleOpening,
    ModuleRecordSig, Point32, ProofHeader, SCHEMA_CAST_RECORD, SCHEMA_CAST_RECORD_BODY,
    SCHEMA_CHALLENGE_OPENING, SCHEMA_CHALLENGE_OPENING_BODY, SCHEMA_MEMBER_SHARE,
    SCHEMA_SHARE_PACKAGE, SCHEMA_VERSION_1, Scalar32, Scalars, ShareEntry, SharePackage, Token192,
    Transport, TrusteeId, decode_object,
};
use std::vec::Vec;

const E: &[u8] = b"KR-2030-PRES";
const BOX: &[u8] = b"box-11-0042";
const STYLE: &[u8] = b"pres-2030";

fn kind_at(result: Result<impl core::fmt::Debug, ityv_encoding::Error>) -> (ErrorKind, usize) {
    let err = result.expect_err("expected an error");
    (err.kind(), err.offset())
}

fn decode_cast_record_body(b: &[u8]) -> Result<CastRecordBody<'_>, ityv_encoding::Error> {
    decode_object(SCHEMA_CAST_RECORD_BODY, SCHEMA_VERSION_1, b)
}

fn decode_cast_record(b: &[u8]) -> Result<CastRecord<'_>, ityv_encoding::Error> {
    decode_object(SCHEMA_CAST_RECORD, SCHEMA_VERSION_1, b)
}

fn decode_challenge_opening_body(
    b: &[u8],
) -> Result<ChallengeOpeningBody<'_>, ityv_encoding::Error> {
    decode_object(SCHEMA_CHALLENGE_OPENING_BODY, SCHEMA_VERSION_1, b)
}

fn decode_share_package(b: &[u8]) -> Result<SharePackage<'_>, ityv_encoding::Error> {
    decode_object(SCHEMA_SHARE_PACKAGE, SCHEMA_VERSION_1, b)
}

fn decode_member_share(b: &[u8]) -> Result<MemberShare<'_>, ityv_encoding::Error> {
    decode_object(SCHEMA_MEMBER_SHARE, SCHEMA_VERSION_1, b)
}

fn module(id: &'static [u8], counter: u64) -> ModuleCounter<'static> {
    ModuleCounter {
        module_id: ModuleId::new(id).unwrap(),
        counter,
    }
}

fn counters(entries: &[ModuleCounter<'static>]) -> ModuleCounters<'static> {
    ModuleCounters::new(entries).unwrap()
}

struct Record {
    proof: Vec<u8>,
    flags: u8,
}

impl Record {
    fn parts(&self) -> CastRecordParts<'_> {
        CastRecordParts {
            election_id: ElectionId::new(E).unwrap(),
            box_id: BoxId::new(BOX).unwrap(),
            ballot_style_id: BallotStyleId::new(STYLE).unwrap(),
            proof_system_id: 1,
            commitments: commitments(2, 0x10),
            proof: &self.proof,
            module_counters: counters(&[module(b"mod-X", 7), module(b"mod-Y", 9)]),
            share_package_hash: patterned64(0x30),
            transport_flags: self.flags,
        }
    }
}

fn record() -> Record {
    Record {
        proof: proof_bytes(16, 2, 0xab),
        flags: 0,
    }
}

/// Byte offsets of the fields of the default record body within the object.
struct BodyOffsets {
    proof_system_id: usize,
    commitments: usize,
    proof: usize,
    module_counters: usize,
    transport_flags: usize,
    end: usize,
}

fn body_offsets(k: usize, proof_len: usize, modules: &[&[u8]]) -> BodyOffsets {
    let proof_system_id = HEADER_LEN + ident_len(E) + ident_len(BOX) + ident_len(STYLE);
    let commitments = proof_system_id + 2;
    let proof = commitments + 4 + 32 * k;
    let module_counters = proof + 4 + proof_len;
    let modules_len: usize = modules.iter().map(|m| ident_len(m) + 8).sum();
    let transport_flags = module_counters + 4 + modules_len + 64;
    BodyOffsets {
        proof_system_id,
        commitments,
        proof,
        module_counters,
        transport_flags,
        end: transport_flags + 1,
    }
}

#[test]
fn proof_header_parses_the_protocol_formula() {
    let proof = proof_bytes(16, 2, 0);
    assert_eq!(
        ProofHeader::parse(&proof),
        Some(ProofHeader {
            option_count: 16,
            chunk_count: 2
        })
    );
    assert_eq!(proof.len(), 2051);
    assert!(ProofHeader::parse(&proof[..proof.len() - 1]).is_none());
    assert!(ProofHeader::parse(&proof_bytes(16, 3, 0)).is_none());
    assert!(ProofHeader::parse(&proof_bytes(0, 1, 0)).is_none());
    // PROTOCOL §7.5: at least two options (one candidate plus BLANK is the
    // smallest ballot the proof system is defined for) and at most 64.
    assert!(ProofHeader::parse(&proof_bytes(1, 1, 0)).is_none());
    assert!(ProofHeader::parse(&proof_bytes(2, 1, 0)).is_some());
    assert!(ProofHeader::parse(&proof_bytes(65, 8, 0)).is_none());
    assert!(ProofHeader::parse(&[0, 9]).is_none());
    assert_eq!(proof_bytes(64, 8, 0).len(), MAX_PROOF_LEN);
    assert!(ProofHeader::parse(&proof_bytes(64, 8, 0)).is_some());
    assert_eq!(proof_bytes(9, 1, 0).len(), 3 + 9 * 3 * 32);
    assert!(ProofHeader::parse(&proof_bytes(9, 1, 0)).is_some());
    assert!(ProofHeader::parse(&proof_bytes(10, 1, 0)).is_none());
}

#[test]
fn cast_record_body_round_trip_and_length() {
    let r = record();
    let body = CastRecordBody::new(&r.parts()).unwrap();
    let off = body_offsets(2, r.proof.len(), &[b"mod-X", b"mod-Y"]);
    assert_eq!(HEADER_LEN + body.encoded_len(), off.end);
    let bytes = encode_to_vec(SCHEMA_CAST_RECORD_BODY, SCHEMA_VERSION_1, &body);
    assert_eq!(bytes.len(), off.end);
    let decoded: CastRecordBody<'_> =
        decode_object(SCHEMA_CAST_RECORD_BODY, SCHEMA_VERSION_1, &bytes).unwrap();
    assert_eq!(decoded, body);
    assert_eq!(CastRecordBody::proof_system_id(), 1);
    assert_eq!(decoded.commitments().chunk_count(), 2);
    assert_eq!(decoded.proof(), &r.proof[..]);
    assert_eq!(decoded.proof_header().option_count, 16);
    assert_eq!(decoded.module_counters().len(), 2);
    assert_eq!(
        decoded
            .module_counters()
            .get(ModuleId::new(b"mod-Y").unwrap()),
        Some(9)
    );
    assert_eq!(
        decoded
            .module_counters()
            .get(ModuleId::new(b"mod-Z").unwrap()),
        None
    );
    assert_eq!(decoded.share_package_hash(), &patterned64(0x30));
    assert_eq!(decoded.transport_flags(), 0);
    assert_eq!(decoded.election_id().as_bytes(), E);
    assert_eq!(decoded.box_id().as_bytes(), BOX);
    assert_eq!(decoded.ballot_style_id().as_bytes(), STYLE);
}

#[test]
fn cast_record_body_maximal_size() {
    let proof = proof_bytes(64, 8, 0x5a);
    let ids: Vec<Vec<u8>> = (0..6u8)
        .map(|i| {
            let mut id = std::vec![b'a' + i; 64];
            id[63] = b'0' + i;
            id
        })
        .collect();
    let entries: Vec<ModuleCounter<'_>> = ids
        .iter()
        .map(|id| ModuleCounter {
            module_id: ModuleId::new(id).unwrap(),
            counter: u64::MAX,
        })
        .collect();
    let long = [b'E'; 64];
    let parts = CastRecordParts {
        election_id: ElectionId::new(&long).unwrap(),
        box_id: BoxId::new(&long).unwrap(),
        ballot_style_id: BallotStyleId::new(&long).unwrap(),
        proof_system_id: 1,
        commitments: commitments(8, 0x40),
        proof: &proof,
        module_counters: ModuleCounters::new(&entries).unwrap(),
        share_package_hash: patterned64(0x30),
        transport_flags: 3,
    };
    let body = CastRecordBody::new(&parts).unwrap();
    let bytes = encode_to_vec(SCHEMA_CAST_RECORD_BODY, SCHEMA_VERSION_1, &body);
    assert_eq!(bytes.len(), 21_494);
    assert!(bytes.len() <= MAX_CAST_RECORD_BODY_LEN);
    let decoded: CastRecordBody<'_> =
        decode_object(SCHEMA_CAST_RECORD_BODY, SCHEMA_VERSION_1, &bytes).unwrap();
    assert_eq!(decoded, body);
}

#[test]
fn cast_record_body_constructor_rejects() {
    let r = record();
    let mut parts = r.parts();
    parts.proof_system_id = 2;
    assert!(CastRecordBody::new(&parts).is_none());
    let mut parts = r.parts();
    parts.commitments = commitments(3, 0x10);
    assert!(CastRecordBody::new(&parts).is_none());
    let short = &r.proof[..r.proof.len() - 32];
    let mut parts = r.parts();
    parts.proof = short;
    assert!(CastRecordBody::new(&parts).is_none());
    let long = std::vec![0u8; MAX_PROOF_LEN + 1];
    let mut parts = r.parts();
    parts.proof = &long;
    assert!(CastRecordBody::new(&parts).is_none());
    let mut parts = r.parts();
    parts.module_counters = ModuleCounters::new(&[]).unwrap();
    assert!(CastRecordBody::new(&parts).is_none());
    let mut parts = r.parts();
    parts.transport_flags = 4;
    assert!(CastRecordBody::new(&parts).is_none());
    assert!(ModuleCounters::new(&[module(b"mod-Y", 1), module(b"mod-X", 2)]).is_none());
    assert!(ModuleCounters::new(&[module(b"mod-X", 1), module(b"mod-X", 2)]).is_none());
    assert!(Commitments::new(&[]).is_none());
    assert!(Commitments::new(&[Point32([0; 32]); 9]).is_none());
    assert!(Scalars::<MAX_CHUNKS>::new(&[Scalar32([0; 32]); 9]).is_none());
}

#[test]
fn cast_record_body_decoder_rejects_each_rule() {
    let r = record();
    let body = CastRecordBody::new(&r.parts()).unwrap();
    let bytes = encode_to_vec(SCHEMA_CAST_RECORD_BODY, SCHEMA_VERSION_1, &body);
    let off = body_offsets(2, r.proof.len(), &[b"mod-X", b"mod-Y"]);

    let mut v = bytes.clone();
    v[off.proof_system_id + 1] = 2;
    assert_eq!(
        kind_at(decode_cast_record_body(&v)),
        (ErrorKind::ValueOutOfRange, off.proof_system_id)
    );

    // Proof header names three chunks while two commitments are present.
    let mut v = bytes.clone();
    v[off.proof + 4 + 2] = 3;
    assert_eq!(
        kind_at(decode_cast_record_body(&v)),
        (ErrorKind::InvariantViolation, off.proof)
    );

    // Proof header option count that does not match the length.
    let mut v = bytes.clone();
    v[off.proof + 4 + 1] = 15;
    assert_eq!(
        kind_at(decode_cast_record_body(&v)),
        (ErrorKind::InvariantViolation, off.proof)
    );

    // Transport flag bit 2.
    let mut v = bytes.clone();
    v[off.transport_flags] = 0b100;
    assert_eq!(
        kind_at(decode_cast_record_body(&v)),
        (ErrorKind::ValueOutOfRange, off.transport_flags)
    );
    for ok in [1u8, 2, 3] {
        let mut v = bytes.clone();
        v[off.transport_flags] = ok;
        assert_eq!(decode_cast_record_body(&v).unwrap().transport_flags(), ok);
    }

    // Unsorted and duplicate module identifiers (swap the two entries).
    let x_at = off.module_counters + 4;
    let y_at = x_at + ident_len(b"mod-X") + 8;
    let mut v = bytes.clone();
    v[x_at + 4 + 4] = b'Y';
    v[y_at + 4 + 4] = b'X';
    assert_eq!(
        kind_at(decode_cast_record_body(&v)),
        (ErrorKind::NotSorted, y_at)
    );
    let mut v = bytes.clone();
    v[y_at + 4 + 4] = b'X';
    assert_eq!(
        kind_at(decode_cast_record_body(&v)),
        (ErrorKind::Duplicate, y_at)
    );

    // Empty module counters: rebuild with a zero count and shorter body.
    let empty = CastRecordParts {
        module_counters: ModuleCounters::new(&[]).unwrap(),
        ..r.parts()
    };
    let mut forged = Vec::new();
    forged.extend_from_slice(&bytes[..off.module_counters]);
    forged.extend_from_slice(&0u32.to_be_bytes());
    forged.extend_from_slice(&bytes[off.transport_flags - 64..]);
    let body_len = u32::try_from(forged.len() - HEADER_LEN).unwrap();
    forged[12..16].copy_from_slice(&body_len.to_be_bytes());
    assert_eq!(
        kind_at(decode_cast_record_body(&forged)),
        (ErrorKind::ValueOutOfRange, off.module_counters)
    );
    assert!(CastRecordBody::new(&empty).is_none());

    // Empty commitments: a minimum-count violation (ENCODING §8.20).
    let mut v = bytes.clone();
    v[off.commitments..off.commitments + 4].copy_from_slice(&0u32.to_be_bytes());
    assert_eq!(
        kind_at(decode_cast_record_body(&v)),
        (ErrorKind::ValueOutOfRange, off.commitments)
    );
    let mut v = bytes.clone();
    v[off.commitments..off.commitments + 4].copy_from_slice(&9u32.to_be_bytes());
    assert_eq!(
        kind_at(decode_cast_record_body(&v)),
        (ErrorKind::CountExceedsMax, off.commitments)
    );
}

fn sig64(seed: u8) -> [u8; 64] {
    patterned::<64>(seed)
}

#[test]
fn cast_record_round_trip_and_set_rules() {
    let r = record();
    let body = CastRecordBody::new(&r.parts()).unwrap();
    let body_bytes = encode_to_vec(SCHEMA_CAST_RECORD_BODY, SCHEMA_VERSION_1, &body);
    let device = sig64(0x70);
    let sx = sig64(0x71);
    let sy = sig64(0x72);
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
    assert_eq!(bytes.len(), sigs_at + 4 + 2 * (ident_len(b"mod-X") + 64));
    let decoded: CastRecord<'_> =
        decode_object(SCHEMA_CAST_RECORD, SCHEMA_VERSION_1, &bytes).unwrap();
    assert_eq!(decoded, record);
    assert_eq!(decoded.body_bytes(), &body_bytes[..]);
    assert_eq!(decoded.body(), &body);
    assert_eq!(decoded.device_sig_ed25519(), &device);
    let got: Vec<ModuleRecordSig<'_>> = decoded.module_sigs().collect();
    assert_eq!(got, sigs);

    // Missing a module signature.
    assert_eq!(
        kind_at(CastRecord::new(&body_bytes, &device, &sigs[..1])),
        (ErrorKind::InvariantViolation, 0)
    );
    // Extra module signature.
    let sz = sig64(0x73);
    let three = [
        sigs[0],
        sigs[1],
        ModuleRecordSig {
            module_id: ModuleId::new(b"mod-Z").unwrap(),
            ed25519: &sz,
        },
    ];
    assert_eq!(
        kind_at(CastRecord::new(&body_bytes, &device, &three)),
        (ErrorKind::InvariantViolation, 0)
    );
    // Unsorted.
    assert_eq!(
        kind_at(CastRecord::new(&body_bytes, &device, &[sigs[1], sigs[0]])),
        (ErrorKind::InvariantViolation, 0)
    );
    // Same count, different identifier.
    let swapped_id = [
        sigs[0],
        ModuleRecordSig {
            module_id: ModuleId::new(b"mod-Z").unwrap(),
            ed25519: &sy,
        },
    ];
    assert_eq!(
        kind_at(CastRecord::new(&body_bytes, &device, &swapped_id)),
        (ErrorKind::InvariantViolation, 0)
    );
    // Body too long or not a body object.
    let long = std::vec![0u8; MAX_CAST_RECORD_BODY_LEN + 1];
    assert_eq!(
        kind_at(CastRecord::new(&long, &device, &sigs)),
        (ErrorKind::LengthExceedsMax, 0)
    );
    assert_eq!(
        kind_at(CastRecord::new(&body_bytes[..20], &device, &sigs)),
        (ErrorKind::BodyLengthMismatch, 12)
    );

    // Decoder: wrong signature set (drop the second entry).
    let mut v = bytes.clone();
    v[sigs_at..sigs_at + 4].copy_from_slice(&1u32.to_be_bytes());
    v.truncate(sigs_at + 4 + ident_len(b"mod-X") + 64);
    let body_len = u32::try_from(v.len() - HEADER_LEN).unwrap();
    v[12..16].copy_from_slice(&body_len.to_be_bytes());
    assert_eq!(
        kind_at(decode_cast_record(&v)),
        (ErrorKind::InvariantViolation, sigs_at)
    );
    // Decoder: unsorted signatures.
    let x_at = sigs_at + 4;
    let y_at = x_at + ident_len(b"mod-X") + 64;
    let mut v = bytes.clone();
    v[x_at + 4 + 4] = b'Y';
    v[y_at + 4 + 4] = b'X';
    assert_eq!(
        kind_at(decode_cast_record(&v)),
        (ErrorKind::NotSorted, y_at)
    );
    // Decoder: a body rule violation surfaces at the rebased offset.
    let off = body_offsets(2, r.proof.len(), &[b"mod-X", b"mod-Y"]);
    let mut v = bytes.clone();
    v[HEADER_LEN + 4 + off.transport_flags] = 0x80;
    assert_eq!(
        kind_at(decode_cast_record(&v)),
        (
            ErrorKind::ValueOutOfRange,
            HEADER_LEN + 4 + off.transport_flags
        )
    );
    // Decoder: a body with the wrong schema id.
    let mut v = bytes.clone();
    v[HEADER_LEN + 4 + 7] = 0x06;
    assert_eq!(
        kind_at(decode_cast_record(&v)),
        (ErrorKind::SchemaMismatch, HEADER_LEN + 4 + 4)
    );
}

fn opening_parts<'a>(
    rand: &'a Scalars<MAX_CHUNKS>,
    modules: &'a [ModuleOpening<'a>],
) -> ChallengeOpeningParts<'a> {
    ChallengeOpeningParts {
        election_id: ElectionId::new(E).unwrap(),
        box_id: BoxId::new(BOX).unwrap(),
        ballot_style_id: BallotStyleId::new(STYLE).unwrap(),
        record_hash: patterned64(0x20),
        option_index: 3,
        cast_id: Token192(patterned::<24>(0x21)),
        rand,
        modules,
    }
}

fn module_opening(id: &'static [u8], counter: u64, k: usize, seed: u8) -> ModuleOpening<'static> {
    ModuleOpening {
        module_id: ModuleId::new(id).unwrap(),
        counter,
        rand: Scalars::new(&scalars(k, seed)).unwrap(),
        cid: Token192(patterned::<24>(seed.wrapping_add(0x40))),
    }
}

#[test]
fn challenge_opening_round_trip_and_rules() {
    let rand = Scalars::<MAX_CHUNKS>::new(&scalars(2, 0x50)).unwrap();
    let modules = [
        module_opening(b"mod-X", 7, 2, 0x60),
        module_opening(b"mod-Y", 9, 2, 0x61),
    ];
    let parts = opening_parts(&rand, &modules);
    let body = ChallengeOpeningBody::new(&parts).unwrap();
    let bytes = encode_to_vec(SCHEMA_CHALLENGE_OPENING_BODY, SCHEMA_VERSION_1, &body);
    let index_at = HEADER_LEN + ident_len(E) + ident_len(BOX) + ident_len(STYLE) + 64;
    let rand_at = index_at + 2 + 24;
    let modules_at = rand_at + 4 + 64;
    let x_at = modules_at + 4;
    let x_rand_at = x_at + ident_len(b"mod-X") + 8;
    let y_at = x_rand_at + 4 + 64 + 24;
    assert_eq!(bytes.len(), y_at + ident_len(b"mod-Y") + 8 + 4 + 64 + 24);
    let decoded: ChallengeOpeningBody<'_> =
        decode_object(SCHEMA_CHALLENGE_OPENING_BODY, SCHEMA_VERSION_1, &bytes).unwrap();
    assert_eq!(decoded, body);
    assert_eq!(decoded.option_index(), 3);
    assert_eq!(decoded.cast_id(), &Token192(patterned::<24>(0x21)));
    assert_eq!(decoded.record_hash(), &patterned64(0x20));
    assert_eq!(decoded.rand().count(), 2);
    let got: Vec<ModuleOpening<'_>> = decoded.modules().collect();
    assert_eq!(got, modules);
    assert_eq!(decoded.election_id().as_bytes(), E);
    assert_eq!(decoded.box_id().as_bytes(), BOX);
    assert_eq!(decoded.ballot_style_id().as_bytes(), STYLE);

    let mut v = bytes.clone();
    v[index_at + 1] = 64;
    assert_eq!(
        kind_at(decode_challenge_opening_body(&v)),
        (ErrorKind::ValueOutOfRange, index_at)
    );
    let mut v = bytes.clone();
    v[index_at + 1] = 63;
    assert_eq!(
        decode_challenge_opening_body(&v).unwrap().option_index(),
        63
    );
    // Module rand count 1 while the top-level count is 2: shorten the X module.
    let mut v = bytes[..x_rand_at].to_vec();
    v.extend_from_slice(&1u32.to_be_bytes());
    v.extend_from_slice(&bytes[x_rand_at + 4..x_rand_at + 4 + 32]);
    v.extend_from_slice(&bytes[x_rand_at + 4 + 64..]);
    let body_len = u32::try_from(v.len() - HEADER_LEN).unwrap();
    v[12..16].copy_from_slice(&body_len.to_be_bytes());
    assert_eq!(
        kind_at(decode_challenge_opening_body(&v)),
        (ErrorKind::InvariantViolation, x_rand_at)
    );
    // Unsorted modules.
    let mut v = bytes.clone();
    v[x_at + 4 + 4] = b'Y';
    v[y_at + 4 + 4] = b'X';
    assert_eq!(
        kind_at(decode_challenge_opening_body(&v)),
        (ErrorKind::NotSorted, y_at)
    );
    // Empty rand.
    let mut v = bytes[..rand_at].to_vec();
    v.extend_from_slice(&0u32.to_be_bytes());
    v.extend_from_slice(&bytes[rand_at + 4 + 64..]);
    let body_len = u32::try_from(v.len() - HEADER_LEN).unwrap();
    v[12..16].copy_from_slice(&body_len.to_be_bytes());
    assert_eq!(
        kind_at(decode_challenge_opening_body(&v)),
        (ErrorKind::ValueOutOfRange, rand_at)
    );

    // Constructor rejections.
    let mut p = opening_parts(&rand, &modules);
    p.option_index = 64;
    assert!(ChallengeOpeningBody::new(&p).is_none());
    let empty = Scalars::<MAX_CHUNKS>::new(&[]).unwrap();
    assert!(ChallengeOpeningBody::new(&opening_parts(&empty, &modules)).is_none());
    let swapped = [modules[1], modules[0]];
    assert!(ChallengeOpeningBody::new(&opening_parts(&rand, &swapped)).is_none());
    let mismatched = [module_opening(b"mod-X", 7, 1, 0x60)];
    assert!(ChallengeOpeningBody::new(&opening_parts(&rand, &mismatched)).is_none());
    let seven: Vec<ModuleOpening<'_>> =
        [b"m1".as_slice(), b"m2", b"m3", b"m4", b"m5", b"m6", b"m7"]
            .iter()
            .map(|id| ModuleOpening {
                module_id: ModuleId::new(id).unwrap(),
                counter: 1,
                rand,
                cid: Token192([0; 24]),
            })
            .collect();
    assert!(ChallengeOpeningBody::new(&opening_parts(&rand, &seven)).is_none());
    // No modules is allowed by the table.
    assert!(ChallengeOpeningBody::new(&opening_parts(&rand, &[])).is_some());

    // Wrapper.
    let sig = patterned::<4691>(0x77);
    let event = ChallengeOpening::new(&bytes, &sig).unwrap();
    let wrapped = encode_to_vec(SCHEMA_CHALLENGE_OPENING, SCHEMA_VERSION_1, &event);
    assert_eq!(wrapped.len(), HEADER_LEN + 4 + bytes.len() + 4691);
    let decoded: ChallengeOpening<'_> =
        decode_object(SCHEMA_CHALLENGE_OPENING, SCHEMA_VERSION_1, &wrapped).unwrap();
    assert_eq!(decoded, event);
    assert_eq!(decoded.body(), &body);
    assert_eq!(decoded.body_bytes(), &bytes[..]);
    assert_eq!(decoded.device_sig(), &sig);
    let mut v = wrapped.clone();
    v[HEADER_LEN + 4 + index_at + 1] = 64;
    let e: Result<ChallengeOpening<'_>, _> =
        decode_object(SCHEMA_CHALLENGE_OPENING, SCHEMA_VERSION_1, &v);
    assert_eq!(
        kind_at(e),
        (ErrorKind::ValueOutOfRange, HEADER_LEN + 4 + index_at)
    );
    let truncated: Result<ChallengeOpening<'_>, _> = decode_object(
        SCHEMA_CHALLENGE_OPENING,
        SCHEMA_VERSION_1,
        &wrapped[..wrapped.len() - 1],
    );
    assert_eq!(kind_at(truncated), (ErrorKind::BodyLengthMismatch, 12));
    assert_eq!(
        kind_at(ChallengeOpening::new(&bytes[..10], &sig)),
        (ErrorKind::UnexpectedEnd, 10)
    );
}

fn share_entry<'a>(
    id: &'static [u8],
    chamber: ChamberCode,
    transport: Transport,
    ciphertext: &'a [u8],
    tag: &'a [u8; 16],
) -> ShareEntry<'a> {
    ShareEntry {
        trustee_id: TrusteeId::new(id).unwrap(),
        chamber,
        transport,
        ciphertext,
        tag,
    }
}

#[test]
fn share_package_round_trip_and_rules() {
    let ct_a = std::vec![0x11u8; 300];
    let ct_b = std::vec![0x22u8; 1900];
    let tag_a = patterned::<16>(0x01);
    let tag_b = patterned::<16>(0x02);
    let entries = [
        share_entry(
            b"trustee-A",
            ChamberCode::X,
            Transport::Pad {
                pad_id: 5,
                pad_index: 3_000,
            },
            &ct_a,
            &tag_a,
        ),
        share_entry(b"trustee-B", ChamberCode::N, Transport::Kem, &ct_b, &tag_b),
    ];
    let package = SharePackage::new(
        ElectionId::new(E).unwrap(),
        BoxId::new(BOX).unwrap(),
        &commitments(2, 0x10),
        &entries,
    )
    .unwrap();
    let bytes = encode_to_vec(SCHEMA_SHARE_PACKAGE, SCHEMA_VERSION_1, &package);
    let entries_at = HEADER_LEN + ident_len(E) + ident_len(BOX) + 4 + 64;
    let a_at = entries_at + 4;
    let a_chamber = a_at + ident_len(b"trustee-A");
    let b_at = a_chamber + 1 + 1 + 4 + 8 + 4 + 300 + 16;
    let b_chamber = b_at + ident_len(b"trustee-B");
    assert_eq!(bytes.len(), b_chamber + 1 + 1 + 4 + 8 + 4 + 1900 + 16);
    let decoded: SharePackage<'_> =
        decode_object(SCHEMA_SHARE_PACKAGE, SCHEMA_VERSION_1, &bytes).unwrap();
    assert_eq!(decoded, package);
    assert_eq!(decoded.entry_count(), 2);
    let got: Vec<ShareEntry<'_>> = decoded.entries().collect();
    assert_eq!(got, entries);
    assert_eq!(decoded.commitments(), &commitments(2, 0x10));
    assert_eq!(decoded.election_id().as_bytes(), E);
    assert_eq!(decoded.box_id().as_bytes(), BOX);
    assert_eq!(ChamberCode::from_code(6), Some(ChamberCode::N));
    assert_eq!(ChamberCode::N.code(), 6);
    assert_eq!(ChamberCode::from_code(0), None);

    let mut v = bytes.clone();
    v[a_chamber] = 7;
    assert_eq!(
        kind_at(decode_share_package(&v)),
        (ErrorKind::ValueOutOfRange, a_chamber)
    );
    let mut v = bytes.clone();
    v[a_chamber + 1] = 2;
    assert_eq!(
        kind_at(decode_share_package(&v)),
        (ErrorKind::ValueOutOfRange, a_chamber + 1)
    );
    // KEM entry with a non-zero pad id / pad index.
    let mut v = bytes.clone();
    v[b_chamber + 2 + 3] = 1;
    assert_eq!(
        kind_at(decode_share_package(&v)),
        (ErrorKind::ValueOutOfRange, b_chamber + 2)
    );
    let mut v = bytes.clone();
    v[b_chamber + 2 + 4 + 7] = 1;
    assert_eq!(
        kind_at(decode_share_package(&v)),
        (ErrorKind::ValueOutOfRange, b_chamber + 2 + 4)
    );
    // ENCODING §8.20: each field is checked as soon as it is read. A body
    // that ends right after an invalid transport code, or right after a
    // non-zero KEM pad id, reports that field rather than UnexpectedEnd.
    let mut v = bytes[..a_chamber + 2].to_vec();
    v[a_chamber + 1] = 2;
    let body_len = u32::try_from(v.len() - HEADER_LEN).unwrap();
    v[12..16].copy_from_slice(&body_len.to_be_bytes());
    assert_eq!(
        kind_at(decode_share_package(&v)),
        (ErrorKind::ValueOutOfRange, a_chamber + 1)
    );
    let mut v = bytes[..b_chamber + 2 + 4].to_vec();
    v[b_chamber + 2 + 3] = 1;
    let body_len = u32::try_from(v.len() - HEADER_LEN).unwrap();
    v[12..16].copy_from_slice(&body_len.to_be_bytes());
    assert_eq!(
        kind_at(decode_share_package(&v)),
        (ErrorKind::ValueOutOfRange, b_chamber + 2)
    );
    // Unsorted / duplicate trustee ids.
    let mut v = bytes.clone();
    v[a_at + 4 + 8] = b'B';
    v[b_at + 4 + 8] = b'A';
    assert_eq!(
        kind_at(decode_share_package(&v)),
        (ErrorKind::NotSorted, b_at)
    );
    let mut v = bytes.clone();
    v[b_at + 4 + 8] = b'A';
    assert_eq!(
        kind_at(decode_share_package(&v)),
        (ErrorKind::Duplicate, b_at)
    );
    // Ciphertext length prefix beyond the maximum.
    let mut v = bytes.clone();
    let ct_len_at = a_chamber + 2 + 4 + 8;
    v[ct_len_at..ct_len_at + 4].copy_from_slice(&4097u32.to_be_bytes());
    assert_eq!(
        kind_at(decode_share_package(&v)),
        (ErrorKind::LengthExceedsMax, ct_len_at)
    );
    // Entry count above 64.
    let mut v = bytes.clone();
    v[entries_at..entries_at + 4].copy_from_slice(&65u32.to_be_bytes());
    assert_eq!(
        kind_at(decode_share_package(&v)),
        (ErrorKind::CountExceedsMax, entries_at)
    );
    // Empty commitments: a minimum-count violation (ENCODING §8.20).
    let c_at = HEADER_LEN + ident_len(E) + ident_len(BOX);
    let mut v = bytes.clone();
    v[c_at..c_at + 4].copy_from_slice(&0u32.to_be_bytes());
    assert_eq!(
        kind_at(decode_share_package(&v)),
        (ErrorKind::ValueOutOfRange, c_at)
    );

    // Constructor rejections.
    let big = std::vec![0u8; 4097];
    let too_long = [share_entry(
        b"trustee-A",
        ChamberCode::X,
        Transport::Kem,
        &big,
        &tag_a,
    )];
    assert!(
        SharePackage::new(
            ElectionId::new(E).unwrap(),
            BoxId::new(BOX).unwrap(),
            &commitments(1, 0),
            &too_long
        )
        .is_none()
    );
    let swapped = [entries[1], entries[0]];
    assert!(
        SharePackage::new(
            ElectionId::new(E).unwrap(),
            BoxId::new(BOX).unwrap(),
            &commitments(1, 0),
            &swapped
        )
        .is_none()
    );
    let empty = SharePackage::new(
        ElectionId::new(E).unwrap(),
        BoxId::new(BOX).unwrap(),
        &commitments(1, 0),
        &[],
    )
    .unwrap();
    let eb = encode_to_vec(SCHEMA_SHARE_PACKAGE, SCHEMA_VERSION_1, &empty);
    let back: SharePackage<'_> =
        decode_object(SCHEMA_SHARE_PACKAGE, SCHEMA_VERSION_1, &eb).unwrap();
    assert_eq!(back.entry_count(), 0);
}

#[test]
fn share_package_maximal_size() {
    let ids: Vec<Vec<u8>> = (0..64u8)
        .map(|i| {
            let mut id = std::vec![b'T'; 62];
            id.push(b'0' + i / 10);
            id.push(b'0' + i % 10);
            id
        })
        .collect();
    let ct = std::vec![0x33u8; 4096];
    let tag = [0x44u8; 16];
    let entries: Vec<ShareEntry<'_>> = ids
        .iter()
        .map(|id| ShareEntry {
            trustee_id: TrusteeId::new(id).unwrap(),
            chamber: ChamberCode::C,
            transport: Transport::Pad {
                pad_id: u32::MAX,
                pad_index: u64::MAX,
            },
            ciphertext: &ct,
            tag: &tag,
        })
        .collect();
    let long = [b'E'; 64];
    let package = SharePackage::new(
        ElectionId::new(&long).unwrap(),
        BoxId::new(&long).unwrap(),
        &commitments(8, 0),
        &entries,
    )
    .unwrap();
    let bytes = encode_to_vec(SCHEMA_SHARE_PACKAGE, SCHEMA_VERSION_1, &package);
    assert_eq!(bytes.len(), 269_088);
    let decoded: SharePackage<'_> =
        decode_object(SCHEMA_SHARE_PACKAGE, SCHEMA_VERSION_1, &bytes).unwrap();
    assert_eq!(decoded, package);
}

#[test]
fn member_share_round_trip_and_rules() {
    let tag = patterned::<16>(0x09);
    let with_module = MemberShare::new(
        &Scalars::<MAX_SECRETS>::new(&scalars(5, 0x80)).unwrap(),
        true,
        Token192(patterned::<24>(0x0a)),
        Some(Token192(patterned::<24>(0x0b))),
        &tag,
    )
    .unwrap();
    let bytes = encode_to_vec(SCHEMA_MEMBER_SHARE, SCHEMA_VERSION_1, &with_module);
    let shares_at = HEADER_LEN;
    let flag_at = shares_at + 4 + 5 * 32;
    let cid_at = flag_at + 1;
    let lab_at = cid_at + 24;
    let tag_at = lab_at + 1 + 24;
    assert_eq!(bytes.len(), tag_at + 16);
    let decoded: MemberShare<'_> =
        decode_object(SCHEMA_MEMBER_SHARE, SCHEMA_VERSION_1, &bytes).unwrap();
    assert_eq!(decoded, with_module);
    assert!(decoded.has_module());
    assert_eq!(decoded.shares().count(), 5);
    assert_eq!(decoded.cid(), &Token192(patterned::<24>(0x0a)));
    assert_eq!(decoded.lab(), Some(&Token192(patterned::<24>(0x0b))));
    assert_eq!(decoded.tag(), &tag);

    let zero_tag = [0u8; 16];
    let without = MemberShare::new(
        &Scalars::<MAX_SECRETS>::new(&scalars(50, 0x80)).unwrap(),
        false,
        Token192([0; 24]),
        None,
        &zero_tag,
    )
    .unwrap();
    let wb = encode_to_vec(SCHEMA_MEMBER_SHARE, SCHEMA_VERSION_1, &without);
    assert_eq!(wb.len(), HEADER_LEN + 4 + 50 * 32 + 1 + 24 + 1 + 16);
    assert_eq!(wb.len(), 1662);
    // The maximal object: fifty shares, a module, and an envelope label.
    let maximal = MemberShare::new(
        &Scalars::<MAX_SECRETS>::new(&scalars(50, 0x80)).unwrap(),
        true,
        Token192([0xff; 24]),
        Some(Token192([0xfe; 24])),
        &tag,
    )
    .unwrap();
    assert_eq!(
        encode_to_vec(SCHEMA_MEMBER_SHARE, SCHEMA_VERSION_1, &maximal).len(),
        1686
    );
    let back: MemberShare<'_> = decode_object(SCHEMA_MEMBER_SHARE, SCHEMA_VERSION_1, &wb).unwrap();
    assert_eq!(back, without);
    assert!(!back.has_module());
    assert_eq!(back.lab(), None);

    // Without a module: non-zero cid, present lab, non-zero tag.
    let w_flag_at = HEADER_LEN + 4 + 50 * 32;
    let w_cid_at = w_flag_at + 1;
    let w_lab_at = w_cid_at + 24;
    let w_tag_at = w_lab_at + 1;
    let mut v = wb.clone();
    v[w_cid_at + 3] = 1;
    assert_eq!(
        kind_at(decode_member_share(&v)),
        (ErrorKind::InvariantViolation, w_cid_at)
    );
    let mut v = wb.clone();
    v[w_tag_at + 15] = 1;
    assert_eq!(
        kind_at(decode_member_share(&v)),
        (ErrorKind::InvariantViolation, w_tag_at)
    );
    let mut v = wb[..w_lab_at].to_vec();
    v.push(1);
    v.extend_from_slice(&[0u8; 24]);
    v.extend_from_slice(&wb[w_lab_at + 1..]);
    let body_len = u32::try_from(v.len() - HEADER_LEN).unwrap();
    v[12..16].copy_from_slice(&body_len.to_be_bytes());
    assert_eq!(
        kind_at(decode_member_share(&v)),
        (ErrorKind::InvariantViolation, w_lab_at)
    );
    // ENCODING §8.20: `cid` is checked as soon as it is read and `lab` as
    // soon as it is read, so a body that ends right after the offending
    // field still reports that field rather than UnexpectedEnd.
    let mut v = wb[..w_cid_at + 24].to_vec();
    v[w_cid_at + 3] = 1;
    let body_len = u32::try_from(v.len() - HEADER_LEN).unwrap();
    v[12..16].copy_from_slice(&body_len.to_be_bytes());
    assert_eq!(
        kind_at(decode_member_share(&v)),
        (ErrorKind::InvariantViolation, w_cid_at)
    );
    let mut v = wb[..w_lab_at].to_vec();
    v.push(1);
    v.extend_from_slice(&[0u8; 24]);
    let body_len = u32::try_from(v.len() - HEADER_LEN).unwrap();
    v[12..16].copy_from_slice(&body_len.to_be_bytes());
    assert_eq!(
        kind_at(decode_member_share(&v)),
        (ErrorKind::InvariantViolation, w_lab_at)
    );
    // Flag byte that is neither 0 nor 1.
    let mut v = wb.clone();
    v[w_flag_at] = 2;
    assert_eq!(
        kind_at(decode_member_share(&v)),
        (ErrorKind::InvalidBool, w_flag_at)
    );
    // Empty shares: a minimum-count violation (ENCODING §8.20).
    let mut v = bytes.clone();
    v[shares_at..shares_at + 4].copy_from_slice(&0u32.to_be_bytes());
    assert_eq!(
        kind_at(decode_member_share(&v)),
        (ErrorKind::ValueOutOfRange, shares_at)
    );
    let mut v = bytes.clone();
    v[shares_at..shares_at + 4].copy_from_slice(&51u32.to_be_bytes());
    assert_eq!(
        kind_at(decode_member_share(&v)),
        (ErrorKind::CountExceedsMax, shares_at)
    );

    // Constructor rejections.
    let empty = Scalars::<MAX_SECRETS>::new(&[]).unwrap();
    assert!(MemberShare::new(&empty, true, Token192([0; 24]), None, &tag).is_none());
    let one = Scalars::<MAX_SECRETS>::new(&scalars(1, 0)).unwrap();
    assert!(MemberShare::new(&one, false, Token192([1; 24]), None, &zero_tag).is_none());
    assert!(
        MemberShare::new(
            &one,
            false,
            Token192([0; 24]),
            Some(Token192([0; 24])),
            &zero_tag
        )
        .is_none()
    );
    assert!(MemberShare::new(&one, false, Token192([0; 24]), None, &tag).is_none());
    assert!(MemberShare::new(&one, true, Token192([0; 24]), None, &zero_tag).is_some());
    assert!(Scalars::<MAX_SECRETS>::new(&scalars(51, 0)).is_none());
    let _ = Hash512::ZERO;
}
