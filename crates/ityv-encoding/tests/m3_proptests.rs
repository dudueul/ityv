//! Property-based tests (verification ladder V1) for the M3 schemas:
//! round trips, canonicity under single-byte mutation, rejection of every
//! proper prefix, and decoder totality on arbitrary bytes.
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

use common::{encode_to_vec, hash64, ident_bytes, proof_bytes};
use ityv_encoding::{
    BallotStyleId, BatchAttest, BatchAttestBody, BatchAttestParts, BoxClose, BoxCloseBody,
    BoxCloseParts, BoxId, CastRecord, CastRecordBody, CastRecordParts, ChallengeOpening,
    ChallengeOpeningBody, ChallengeOpeningParts, ChamberCode, CloseCounts, Commitments, ElectionId,
    Hash512, MAX_CHUNKS, MAX_SECRETS, MemberShare, ModuleCounter, ModuleCounters, ModuleId,
    ModuleIds, ModuleOpening, ModuleRange, Point32, SCHEMA_BATCH_ATTEST, SCHEMA_BATCH_ATTEST_BODY,
    SCHEMA_BOX_CLOSE, SCHEMA_BOX_CLOSE_BODY, SCHEMA_CAST_RECORD, SCHEMA_CAST_RECORD_BODY,
    SCHEMA_CHALLENGE_OPENING, SCHEMA_CHALLENGE_OPENING_BODY, SCHEMA_MEMBER_SHARE,
    SCHEMA_SCAN_COUNT_ATTEST, SCHEMA_SCAN_COUNT_ATTEST_BODY, SCHEMA_SHARE_PACKAGE, SCHEMA_SLIP,
    SCHEMA_SLIP_BODY, SCHEMA_VERSION_1, Scalar32, Scalars, ScanCountAttest, ScanCountAttestBody,
    ShareEntry, SharePackage, Slip, SlipBody, StationId, TimeBucket, Token192, Transport,
    TrusteeId, decode_object,
};
use proptest::prelude::*;
use std::vec::Vec;

/// Byte masks applied to each position: lowest bit, highest bit, all bits.
const MASKS: [u8; 3] = [0x01, 0x80, 0xff];

/// Checks canonicity of one object encoding: every single-byte mutation is
/// either rejected or decodes to a *different* value whose canonical
/// encoding is exactly the mutated bytes. Every proper prefix is rejected.
macro_rules! check_canonical {
    ($ty:ty, $schema:expr, $bytes:expr) => {{
        let bytes: &[u8] = $bytes;
        let original: $ty = decode_object($schema, SCHEMA_VERSION_1, bytes).unwrap();
        for i in 0..bytes.len() {
            for mask in MASKS {
                let mut mutated = bytes.to_vec();
                mutated[i] ^= mask;
                let outcome: Result<$ty, _> = decode_object($schema, SCHEMA_VERSION_1, &mutated);
                if let Ok(other) = outcome {
                    prop_assert_ne!(
                        &other,
                        &original,
                        "mutation at {} decoded to the same value",
                        i
                    );
                    let re = encode_to_vec($schema, SCHEMA_VERSION_1, &other);
                    prop_assert_eq!(&re, &mutated, "re-encoding differs after mutation at {}", i);
                }
            }
        }
        for k in 0..bytes.len() {
            let prefix: Result<$ty, _> = decode_object($schema, SCHEMA_VERSION_1, &bytes[..k]);
            prop_assert!(prefix.is_err(), "proper prefix of length {} decoded", k);
        }
    }};
}

/// Up to `max` distinct identifiers in ascending byte order.
fn sorted_ids(max: usize) -> impl Strategy<Value = Vec<Vec<u8>>> {
    prop::collection::btree_set(ident_bytes(6), 0..=max).prop_map(|s| s.into_iter().collect())
}

fn point() -> impl Strategy<Value = Point32> {
    any::<[u8; 32]>().prop_map(Point32)
}

fn scalar() -> impl Strategy<Value = Scalar32> {
    any::<[u8; 32]>().prop_map(Scalar32)
}

fn token() -> impl Strategy<Value = Token192> {
    any::<[u8; 24]>().prop_map(Token192)
}

/// A commitment vector of `k` points and a proof whose header matches:
/// `option_count` in `2..=9` for one chunk and `10..=18` for two.
fn record_core() -> impl Strategy<Value = (Vec<Point32>, Vec<u8>)> {
    (1u8..=2).prop_flat_map(|k| {
        let lo = (u16::from(k - 1) * 9 + 1).max(2);
        let hi = u16::from(k) * 9;
        (
            prop::collection::vec(point(), usize::from(k)),
            lo..=hi,
            any::<u8>(),
        )
            .prop_map(move |(points, options, fill)| (points, proof_bytes(options, k, fill)))
    })
}

fn counters_from<'a>(ids: &'a [Vec<u8>], values: &[u64]) -> ModuleCounters<'a> {
    let entries: Vec<ModuleCounter<'_>> = ids
        .iter()
        .zip(values.iter().cycle())
        .map(|(id, v)| ModuleCounter {
            module_id: ModuleId::new(id).unwrap(),
            counter: *v,
        })
        .collect();
    ModuleCounters::new(&entries).unwrap()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn cast_record_body_and_record_round_trip(
        e in ident_bytes(8), b in ident_bytes(8), s in ident_bytes(8),
        core in record_core(), ids in sorted_ids(2), values in prop::collection::vec(any::<u64>(), 1..=2),
        pkg in hash64(), flags in 0u8..=3, device in any::<[u8; 64]>()
    ) {
        prop_assume!(!ids.is_empty());
        let (points, proof) = core;
        let commitments = Commitments::new(&points).unwrap();
        let counters = counters_from(&ids, &values);
        let body = CastRecordBody::new(&CastRecordParts {
            election_id: ElectionId::new(&e).unwrap(),
            box_id: BoxId::new(&b).unwrap(),
            ballot_style_id: BallotStyleId::new(&s).unwrap(),
            proof_system_id: 1,
            commitments,
            proof: &proof,
            module_counters: counters,
            share_package_hash: Hash512(pkg),
            transport_flags: flags,
        }).unwrap();
        let bytes = encode_to_vec(SCHEMA_CAST_RECORD_BODY, SCHEMA_VERSION_1, &body);
        let decoded: CastRecordBody<'_> = decode_object(SCHEMA_CAST_RECORD_BODY, SCHEMA_VERSION_1, &bytes).unwrap();
        prop_assert_eq!(decoded, body);
        check_canonical!(CastRecordBody<'_>, SCHEMA_CAST_RECORD_BODY, &bytes);

        let sigs: Vec<ityv_encoding::ModuleRecordSig<'_>> = ids.iter().map(|id| ityv_encoding::ModuleRecordSig {
            module_id: ModuleId::new(id).unwrap(),
            ed25519: &device,
        }).collect();
        let record = CastRecord::new(&bytes, &device, &sigs).unwrap();
        let rb = encode_to_vec(SCHEMA_CAST_RECORD, SCHEMA_VERSION_1, &record);
        let back: CastRecord<'_> = decode_object(SCHEMA_CAST_RECORD, SCHEMA_VERSION_1, &rb).unwrap();
        prop_assert_eq!(back, record);
        for k in 0..rb.len() {
            let prefix: Result<CastRecord<'_>, _> = decode_object(SCHEMA_CAST_RECORD, SCHEMA_VERSION_1, &rb[..k]);
            prop_assert!(prefix.is_err());
        }
    }

    #[test]
    fn challenge_opening_round_trip(
        e in ident_bytes(8), b in ident_bytes(8), s in ident_bytes(8), record in hash64(),
        index in 0u16..=63, cast in token(), k in 1usize..=2, ids in sorted_ids(2),
        counters in prop::collection::vec(any::<u64>(), 2), cids in prop::collection::vec(token(), 2),
        seed in any::<u8>(), sig in any::<[u8; 32]>()
    ) {
        let rand_scalars: Vec<Scalar32> = (0..k).map(|i| Scalar32([seed.wrapping_add(u8::try_from(i).unwrap()); 32])).collect();
        let rand = Scalars::<MAX_CHUNKS>::new(&rand_scalars).unwrap();
        let modules: Vec<ModuleOpening<'_>> = ids.iter().enumerate().map(|(i, id)| ModuleOpening {
            module_id: ModuleId::new(id).unwrap(),
            counter: counters[i],
            rand: rand.duplicate(),
            cid: cids[i],
        }).collect();
        let body = ChallengeOpeningBody::new(&ChallengeOpeningParts {
            election_id: ElectionId::new(&e).unwrap(),
            box_id: BoxId::new(&b).unwrap(),
            ballot_style_id: BallotStyleId::new(&s).unwrap(),
            record_hash: Hash512(record),
            option_index: index,
            cast_id: cast,
            rand: &rand,
            modules: &modules,
        }).unwrap();
        let bytes = encode_to_vec(SCHEMA_CHALLENGE_OPENING_BODY, SCHEMA_VERSION_1, &body);
        let decoded: ChallengeOpeningBody<'_> = decode_object(SCHEMA_CHALLENGE_OPENING_BODY, SCHEMA_VERSION_1, &bytes).unwrap();
        prop_assert_eq!(decoded, body);
        check_canonical!(ChallengeOpeningBody<'_>, SCHEMA_CHALLENGE_OPENING_BODY, &bytes);
        let mut full = [0u8; 4691];
        full[..32].copy_from_slice(&sig);
        let event = ChallengeOpening::new(&bytes, &full).unwrap();
        let eb = encode_to_vec(SCHEMA_CHALLENGE_OPENING, SCHEMA_VERSION_1, &event);
        let back: ChallengeOpening<'_> = decode_object(SCHEMA_CHALLENGE_OPENING, SCHEMA_VERSION_1, &eb).unwrap();
        prop_assert_eq!(back, event);
    }

    #[test]
    fn share_package_round_trip(
        e in ident_bytes(8), b in ident_bytes(8), points in prop::collection::vec(point(), 1..=2),
        ids in sorted_ids(2), chambers in prop::collection::vec(1u8..=8, 2),
        pad in prop::collection::vec((any::<bool>(), any::<u32>(), any::<u64>()), 2),
        cts in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..=8), 2),
        tags in prop::collection::vec(any::<[u8; 16]>(), 2)
    ) {
        let entries: Vec<ShareEntry<'_>> = ids.iter().enumerate().map(|(i, id)| ShareEntry {
            trustee_id: TrusteeId::new(id).unwrap(),
            chamber: ChamberCode::from_code(chambers[i]).unwrap(),
            transport: if pad[i].0 { Transport::Pad { pad_id: pad[i].1, pad_index: pad[i].2 } } else { Transport::Kem },
            ciphertext: &cts[i],
            tag: &tags[i],
        }).collect();
        let package = SharePackage::new(
            ElectionId::new(&e).unwrap(), BoxId::new(&b).unwrap(), &Commitments::new(&points).unwrap(), &entries,
        ).unwrap();
        let bytes = encode_to_vec(SCHEMA_SHARE_PACKAGE, SCHEMA_VERSION_1, &package);
        let decoded: SharePackage<'_> = decode_object(SCHEMA_SHARE_PACKAGE, SCHEMA_VERSION_1, &bytes).unwrap();
        prop_assert_eq!(decoded, package);
        check_canonical!(SharePackage<'_>, SCHEMA_SHARE_PACKAGE, &bytes);
    }

    #[test]
    fn member_share_round_trip(
        shares in prop::collection::vec(scalar(), 1..=3), has_module in any::<bool>(),
        cid in token(), lab in proptest::option::of(token()), tag in any::<[u8; 16]>()
    ) {
        let (cid, lab, tag) = if has_module { (cid, lab, tag) } else { (Token192([0; 24]), None, [0u8; 16]) };
        let share = MemberShare::new(&Scalars::<MAX_SECRETS>::new(&shares).unwrap(), has_module, cid, lab, &tag).unwrap();
        let bytes = encode_to_vec(SCHEMA_MEMBER_SHARE, SCHEMA_VERSION_1, &share);
        let decoded: MemberShare<'_> = decode_object(SCHEMA_MEMBER_SHARE, SCHEMA_VERSION_1, &bytes).unwrap();
        prop_assert_eq!(decoded, share);
        check_canonical!(MemberShare<'_>, SCHEMA_MEMBER_SHARE, &bytes);
    }

    #[test]
    fn batch_attest_round_trip(
        e in ident_bytes(8), b in ident_bytes(8), index in any::<u32>(), count in 1u16..=64,
        root in hash64(), ids in sorted_ids(3), firsts in prop::collection::vec(any::<u64>(), 3),
        spans in prop::collection::vec(0u64..1000, 3), refuse in prop::collection::vec(any::<bool>(), 3),
        head in hash64(), bucket in any::<u64>(), sig in any::<[u8; 32]>()
    ) {
        let ranges: Vec<ModuleRange<'_>> = ids.iter().enumerate().map(|(i, id)| ModuleRange {
            module_id: ModuleId::new(id).unwrap(),
            counter_first: firsts[i],
            counter_last: firsts[i].saturating_add(spans[i]),
        }).collect();
        let refused: Vec<ModuleId<'_>> = ids.iter().enumerate().filter(|(i, _)| refuse[*i]).map(|(_, id)| ModuleId::new(id).unwrap()).collect();
        let body = BatchAttestBody::new(&BatchAttestParts {
            election_id: ElectionId::new(&e).unwrap(),
            box_id: BoxId::new(&b).unwrap(),
            batch_index: index,
            record_count: count,
            records_root: Hash512(root),
            module_ranges: &ranges,
            module_refusals: ModuleIds::new(&refused).unwrap(),
            journal_head: Hash512(head),
            time_bucket: TimeBucket::new(bucket),
        }).unwrap();
        let bytes = encode_to_vec(SCHEMA_BATCH_ATTEST_BODY, SCHEMA_VERSION_1, &body);
        let decoded: BatchAttestBody<'_> = decode_object(SCHEMA_BATCH_ATTEST_BODY, SCHEMA_VERSION_1, &bytes).unwrap();
        prop_assert_eq!(decoded, body);
        check_canonical!(BatchAttestBody<'_>, SCHEMA_BATCH_ATTEST_BODY, &bytes);
        let mut full = [0u8; 4691];
        full[..32].copy_from_slice(&sig);
        let sigs: Vec<ityv_encoding::ModuleBatchSig<'_>> = body.expected_signers().map(|id| ityv_encoding::ModuleBatchSig { module_id: id, sig: &full }).collect();
        let event = BatchAttest::new(&bytes, &sigs, &full).unwrap();
        let eb = encode_to_vec(SCHEMA_BATCH_ATTEST, SCHEMA_VERSION_1, &event);
        let back: BatchAttest<'_> = decode_object(SCHEMA_BATCH_ATTEST, SCHEMA_VERSION_1, &eb).unwrap();
        prop_assert_eq!(back, event);
    }

    #[test]
    fn scan_count_round_trip(
        e in ident_bytes(8), b in ident_bytes(8), counts in prop::collection::vec(any::<u64>(), 3),
        head in hash64(), bucket in any::<u64>(), sig in any::<[u8; 32]>(), orgs in sorted_ids(2)
    ) {
        let body = ScanCountAttestBody::new(
            ElectionId::new(&e).unwrap(), BoxId::new(&b).unwrap(), counts[0], counts[1], counts[2], Hash512(head), TimeBucket::new(bucket),
        );
        let bytes = encode_to_vec(SCHEMA_SCAN_COUNT_ATTEST_BODY, SCHEMA_VERSION_1, &body);
        let decoded: ScanCountAttestBody<'_> = decode_object(SCHEMA_SCAN_COUNT_ATTEST_BODY, SCHEMA_VERSION_1, &bytes).unwrap();
        prop_assert_eq!(decoded, body);
        check_canonical!(ScanCountAttestBody<'_>, SCHEMA_SCAN_COUNT_ATTEST_BODY, &bytes);
        prop_assume!(orgs.len() == 2);
        let mut full = [0u8; 4691];
        full[..32].copy_from_slice(&sig);
        let sigs = [
            ityv_encoding::ObserverSig { observer_id: ityv_encoding::ObserverId::new(b"o1").unwrap(), org_id: ityv_encoding::OrgId::new(&orgs[0]).unwrap(), sig: &full },
            ityv_encoding::ObserverSig { observer_id: ityv_encoding::ObserverId::new(b"o2").unwrap(), org_id: ityv_encoding::OrgId::new(&orgs[1]).unwrap(), sig: &full },
        ];
        let event = ScanCountAttest::new(&bytes, &sigs).unwrap();
        let eb = encode_to_vec(SCHEMA_SCAN_COUNT_ATTEST, SCHEMA_VERSION_1, &event);
        let back: ScanCountAttest<'_> = decode_object(SCHEMA_SCAN_COUNT_ATTEST, SCHEMA_VERSION_1, &eb).unwrap();
        prop_assert_eq!(back, event);
    }

    #[test]
    fn box_close_round_trip(
        e in ident_bytes(8), b in ident_bytes(8), counts in prop::collection::vec(any::<u64>(), 9),
        hashes in prop::collection::vec(hash64(), 3), ids in sorted_ids(2),
        values in prop::collection::vec(any::<u64>(), 1..=2), open in any::<u8>(), bucket in any::<u64>(),
        with_device in any::<bool>(), sig in any::<[u8; 32]>(), orgs in sorted_ids(2)
    ) {
        let body = BoxCloseBody::new(&BoxCloseParts {
            election_id: ElectionId::new(&e).unwrap(),
            box_id: BoxId::new(&b).unwrap(),
            counts: CloseCounts { paper: counts[0], records: counts[1], attested: counts[2], without_record: counts[3], challenged: counts[4], quarantined: counts[5], visits: counts[6], envelopes: counts[7], stickers: counts[8] },
            record_set_root: Hash512(hashes[0]),
            journal_head: Hash512(hashes[1]),
            seal_digest: Hash512(hashes[2]),
            module_counters: counters_from(&ids, &values),
            open_batches: open,
            time_bucket: TimeBucket::new(bucket),
        });
        let bytes = encode_to_vec(SCHEMA_BOX_CLOSE_BODY, SCHEMA_VERSION_1, &body);
        let decoded: BoxCloseBody<'_> = decode_object(SCHEMA_BOX_CLOSE_BODY, SCHEMA_VERSION_1, &bytes).unwrap();
        prop_assert_eq!(decoded, body);
        check_canonical!(BoxCloseBody<'_>, SCHEMA_BOX_CLOSE_BODY, &bytes);
        prop_assume!(orgs.len() == 2);
        let mut full = [0u8; 4691];
        full[..32].copy_from_slice(&sig);
        let attestations = [
            ityv_encoding::Attestation { signer_id: ityv_encoding::SignerId::new(b"c1").unwrap(), role: ityv_encoding::SignerRole::Clerk, org_id: ityv_encoding::OrgId::new(b"nec").unwrap(), sig: &full },
            ityv_encoding::Attestation { signer_id: ityv_encoding::SignerId::new(b"c2").unwrap(), role: ityv_encoding::SignerRole::Clerk, org_id: ityv_encoding::OrgId::new(b"nec").unwrap(), sig: &full },
            ityv_encoding::Attestation { signer_id: ityv_encoding::SignerId::new(b"o1").unwrap(), role: ityv_encoding::SignerRole::Observer, org_id: ityv_encoding::OrgId::new(&orgs[0]).unwrap(), sig: &full },
            ityv_encoding::Attestation { signer_id: ityv_encoding::SignerId::new(b"o2").unwrap(), role: ityv_encoding::SignerRole::Observer, org_id: ityv_encoding::OrgId::new(&orgs[1]).unwrap(), sig: &full },
        ];
        let event = BoxClose::new(&bytes, if with_device { Some(&full) } else { None }, &attestations).unwrap();
        let eb = encode_to_vec(SCHEMA_BOX_CLOSE, SCHEMA_VERSION_1, &event);
        let back: BoxClose<'_> = decode_object(SCHEMA_BOX_CLOSE, SCHEMA_VERSION_1, &eb).unwrap();
        prop_assert_eq!(back, event);
    }

    #[test]
    fn slip_round_trip(
        e in ident_bytes(8), st in ident_bytes(8), bucket in any::<u64>(), code in hash64(), n in 1usize..=8, sig in any::<[u8; 32]>()
    ) {
        let codes: Vec<Hash512> = (0..n).map(|i| { let mut c = code; c[0] ^= u8::try_from(i).unwrap(); c[63] = 0x5a; Hash512(c) }).collect();
        let body = SlipBody::new(ElectionId::new(&e).unwrap(), StationId::new(&st).unwrap(), TimeBucket::new(bucket), &codes).unwrap();
        prop_assert_eq!(body.tracking_codes(), codes.as_slice());
        let bytes = encode_to_vec(SCHEMA_SLIP_BODY, SCHEMA_VERSION_1, &body);
        let decoded: SlipBody<'_> = decode_object(SCHEMA_SLIP_BODY, SCHEMA_VERSION_1, &bytes).unwrap();
        prop_assert_eq!(decoded, body);
        check_canonical!(SlipBody<'_>, SCHEMA_SLIP_BODY, &bytes);
        let mut full = [0u8; 4691];
        full[..32].copy_from_slice(&sig);
        let slip = Slip::new(&bytes, &full).unwrap();
        let sb = encode_to_vec(SCHEMA_SLIP, SCHEMA_VERSION_1, &slip);
        let back: Slip<'_> = decode_object(SCHEMA_SLIP, SCHEMA_VERSION_1, &sb).unwrap();
        prop_assert_eq!(back, slip);
    }

    #[test]
    fn arbitrary_bytes_never_panic_the_m3_decoders(bytes in prop::collection::vec(any::<u8>(), 0..400)) {
        let _ = decode_object::<CastRecordBody<'_>>(SCHEMA_CAST_RECORD_BODY, SCHEMA_VERSION_1, &bytes);
        let _ = decode_object::<CastRecord<'_>>(SCHEMA_CAST_RECORD, SCHEMA_VERSION_1, &bytes);
        let _ = decode_object::<ChallengeOpeningBody<'_>>(SCHEMA_CHALLENGE_OPENING_BODY, SCHEMA_VERSION_1, &bytes);
        let _ = decode_object::<ChallengeOpening<'_>>(SCHEMA_CHALLENGE_OPENING, SCHEMA_VERSION_1, &bytes);
        let _ = decode_object::<SharePackage<'_>>(SCHEMA_SHARE_PACKAGE, SCHEMA_VERSION_1, &bytes);
        let _ = decode_object::<MemberShare<'_>>(SCHEMA_MEMBER_SHARE, SCHEMA_VERSION_1, &bytes);
        let _ = decode_object::<BatchAttestBody<'_>>(SCHEMA_BATCH_ATTEST_BODY, SCHEMA_VERSION_1, &bytes);
        let _ = decode_object::<BatchAttest<'_>>(SCHEMA_BATCH_ATTEST, SCHEMA_VERSION_1, &bytes);
        let _ = decode_object::<ScanCountAttestBody<'_>>(SCHEMA_SCAN_COUNT_ATTEST_BODY, SCHEMA_VERSION_1, &bytes);
        let _ = decode_object::<ScanCountAttest<'_>>(SCHEMA_SCAN_COUNT_ATTEST, SCHEMA_VERSION_1, &bytes);
        let _ = decode_object::<BoxCloseBody<'_>>(SCHEMA_BOX_CLOSE_BODY, SCHEMA_VERSION_1, &bytes);
        let _ = decode_object::<BoxClose<'_>>(SCHEMA_BOX_CLOSE, SCHEMA_VERSION_1, &bytes);
        let _ = decode_object::<SlipBody<'_>>(SCHEMA_SLIP_BODY, SCHEMA_VERSION_1, &bytes);
        let _ = decode_object::<Slip<'_>>(SCHEMA_SLIP, SCHEMA_VERSION_1, &bytes);
    }
}
