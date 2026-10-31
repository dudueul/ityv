//! Pedersen commitments and digit packing (PROTOCOL.md §7.4): packed
//! values against the specification formula, digit decoding, openings,
//! aggregation over many records, encoding and validation.
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

use common::{decode_exact, encode_to_vec, rng};
use ityv_crypto::commit::{extract_bits, has_bits_above_packed_range};
use ityv_crypto::{
    Bases, CastId, ChunkIndex, Commitment, DIGIT_BITS, DIGITS_PER_CHUNK, Error, MAX_CHUNKS,
    MAX_OPTIONS, Opening, OptionIndex, Scalar, commit, decode_digits, packed_exponent,
    packed_value, sum_commitments, verify_aggregate, verify_opening,
};
use ityv_encoding::{ErrorKind, Point32, Token192};
use rand_core::CryptoRng;
use std::vec::Vec;

/// `2^e` by repeated doubling, independent of the bit-setting code under test.
fn pow2(exponent: u32) -> Scalar {
    let mut value = Scalar::ONE;
    for _ in 0..exponent {
        value = value.add(&value);
    }
    value
}

fn random_cast_id(rng: &mut impl CryptoRng) -> CastId {
    let mut token = [0u8; 24];
    rng.fill_bytes(&mut token);
    CastId::new(Token192(token))
}

#[test]
fn packed_exponent_and_value_match_specification() {
    for t in 0..u16::try_from(MAX_OPTIONS).unwrap() {
        for j in 0..u8::try_from(MAX_CHUNKS).unwrap() {
            let option = OptionIndex::new(t).unwrap();
            let chunk = ChunkIndex::new(j).unwrap();
            let expected = if t / DIGITS_PER_CHUNK == u16::from(j) {
                Some(DIGIT_BITS * u32::from(t - DIGITS_PER_CHUNK * u16::from(j)))
            } else {
                None
            };
            assert_eq!(packed_exponent(option, chunk), expected, "t={t} j={j}");
            let value = packed_value(option, chunk);
            assert_eq!(value, expected.map_or(Scalar::ZERO, pow2), "t={t} j={j}");
        }
    }
    assert!(OptionIndex::new(u16::try_from(MAX_OPTIONS).unwrap()).is_none());
    assert!(OptionIndex::new(u16::MAX).is_none());
    assert!(ChunkIndex::new(u8::try_from(MAX_CHUNKS).unwrap()).is_none());
    assert_eq!(OptionIndex::new(5).unwrap().get(), 5);
    assert_eq!(ChunkIndex::new(7).unwrap().get(), 7);
}

#[test]
fn digits_round_trip_and_overflow_is_rejected() {
    let digits = [1u32, 2, 3, 0, (1 << 26) - 1, 5, 6, 7, 8];
    let mut packed = Scalar::ZERO;
    for (position, count) in digits.iter().enumerate() {
        let weight = pow2(DIGIT_BITS * u32::try_from(position).unwrap());
        packed = packed.add(&weight.mul(&Scalar::from_u64(u64::from(*count))));
    }
    assert_eq!(decode_digits(&packed).unwrap(), digits);
    assert_eq!(decode_digits(&Scalar::ZERO).unwrap(), [0u32; 9]);

    // Bit 233 is the top bit of the last digit; bit 234 is beyond the range.
    let top = decode_digits(&pow2(233)).unwrap();
    assert_eq!(top[8], 1 << 25);
    assert_eq!(decode_digits(&pow2(234)).unwrap_err(), Error::DigitOverflow);
    assert_eq!(decode_digits(&pow2(240)).unwrap_err(), Error::DigitOverflow);
    assert_eq!(decode_digits(&pow2(251)).unwrap_err(), Error::DigitOverflow);
    assert_eq!(
        decode_digits(&Scalar::ONE.neg()).unwrap_err(),
        Error::DigitOverflow
    );

    // The bit helpers.
    let bytes = pow2(234).to_bytes();
    assert!(has_bits_above_packed_range(&bytes));
    assert!(!has_bits_above_packed_range(&pow2(233).to_bytes()));
    assert_eq!(extract_bits(&bytes, 234, 1), Some(1));
    assert_eq!(extract_bits(&bytes, 233, 1), Some(0));
    assert_eq!(extract_bits(&bytes, 0, 33), None);
    assert_eq!(extract_bits(&bytes, 250, 7), None);
    assert_eq!(extract_bits(&bytes, 224, 32), Some(1 << 10));
    assert_eq!(extract_bits(&bytes, u32::MAX, 1), None);
}

#[test]
fn commitments_open_and_aggregate_over_many_records() {
    let bases = Bases::derive();
    let mut rng = rng(20);
    let option_count: u16 = 16;
    let chunk_count = 2usize;
    let records = 50u16;
    let mut digit_counts = [0u32; 18];
    let mut id_sum = Scalar::ZERO;
    let mut rand_sums = [Scalar::ZERO; 2];
    let mut per_chunk: Vec<Vec<Commitment>> = std::vec![Vec::new(), Vec::new()];
    for i in 0..records {
        let t = i % option_count;
        let option = OptionIndex::new(t).unwrap();
        let cast_id = random_cast_id(&mut rng);
        let mut rand = [Scalar::ZERO; MAX_CHUNKS];
        for slot in rand.iter_mut().take(chunk_count) {
            *slot = Scalar::random(&mut rng);
        }
        let commitments: Vec<Commitment> = (0..chunk_count)
            .map(|j| {
                commit(
                    &bases,
                    option,
                    &cast_id,
                    &rand[j],
                    ChunkIndex::new(u8::try_from(j).unwrap()).unwrap(),
                )
            })
            .collect();
        let opening = Opening::new(option, cast_id, rand);
        assert!(verify_opening(&bases, &commitments, &opening).is_ok());
        assert_eq!(opening.option(), option);
        assert_eq!(opening.cast_id(), &cast_id);
        assert_eq!(opening.rand(), &rand);
        check_opening_negatives(&bases, &commitments, &opening, option_count, &mut rng);

        digit_counts[usize::from(t)] += 1;
        id_sum = id_sum.add(&cast_id.to_scalar());
        for j in 0..chunk_count {
            rand_sums[j] = rand_sums[j].add(&rand[j]);
            per_chunk[j].push(commitments[j]);
        }
    }

    for j in 0..chunk_count {
        let total = sum_commitments(&per_chunk[j]).unwrap();
        let mut packed = Scalar::ZERO;
        for d in 0..9usize {
            let count = digit_counts[9 * j + d];
            packed = packed.add(
                &pow2(DIGIT_BITS * u32::try_from(d).unwrap())
                    .mul(&Scalar::from_u64(u64::from(count))),
            );
        }
        assert!(verify_aggregate(&bases, &total, &packed, &id_sum, &rand_sums[j]).is_ok());
        assert_eq!(
            decode_digits(&packed).unwrap(),
            digit_counts[9 * j..9 * j + 9]
        );
        assert_eq!(
            verify_aggregate(
                &bases,
                &total,
                &packed,
                &id_sum.add(&Scalar::ONE),
                &rand_sums[j]
            )
            .unwrap_err(),
            Error::AggregateInvalid
        );
        assert_eq!(
            verify_aggregate(
                &bases,
                &total,
                &packed.add(&Scalar::ONE),
                &id_sum,
                &rand_sums[j]
            )
            .unwrap_err(),
            Error::AggregateInvalid
        );
        assert_eq!(
            verify_aggregate(&bases, &total, &packed, &id_sum, &rand_sums[j].neg()).unwrap_err(),
            Error::AggregateInvalid
        );
        // Dropping one record from the sum breaks the equation.
        let partial = sum_commitments(&per_chunk[j][1..]).unwrap();
        assert!(verify_aggregate(&bases, &partial, &packed, &id_sum, &rand_sums[j]).is_err());
    }
    assert_eq!(digit_counts.iter().sum::<u32>(), u32::from(records));
}

/// Every single-field change to a valid opening must be rejected.
fn check_opening_negatives(
    bases: &Bases,
    commitments: &[Commitment],
    opening: &Opening,
    option_count: u16,
    rng: &mut impl CryptoRng,
) {
    let option = opening.option();
    let cast_id = *opening.cast_id();
    let rand = *opening.rand();
    let wrong_option = Opening::new(
        OptionIndex::new((option.get() + 1) % option_count).unwrap(),
        cast_id,
        rand,
    );
    assert_eq!(
        verify_opening(bases, commitments, &wrong_option).unwrap_err(),
        Error::OpeningInvalid
    );
    let wrong_id = Opening::new(option, random_cast_id(rng), rand);
    assert_eq!(
        verify_opening(bases, commitments, &wrong_id).unwrap_err(),
        Error::OpeningInvalid
    );
    let mut other_rand = rand;
    other_rand[1] = Scalar::random(rng);
    let wrong_rand = Opening::new(option, cast_id, other_rand);
    assert_eq!(
        verify_opening(bases, commitments, &wrong_rand).unwrap_err(),
        Error::OpeningInvalid
    );
}

#[test]
fn opening_capacity_and_range_errors() {
    let bases = Bases::derive();
    let mut rng = rng(21);
    let cast_id = random_cast_id(&mut rng);
    let rand = [Scalar::ZERO; MAX_CHUNKS];
    let option = OptionIndex::new(9).unwrap();
    let opening = Opening::new(option, cast_id, rand);
    assert_eq!(
        verify_opening(&bases, &[], &opening).unwrap_err(),
        Error::CapacityExceeded
    );
    let one = commit(
        &bases,
        option,
        &cast_id,
        &rand[0],
        ChunkIndex::new(0).unwrap(),
    );
    // Option 9 lives in chunk 1, which does not exist with one commitment.
    assert_eq!(
        verify_opening(&bases, &[one], &opening).unwrap_err(),
        Error::OptionOutOfRange
    );
    let nine = [one; 9];
    assert_eq!(
        verify_opening(&bases, &nine, &opening).unwrap_err(),
        Error::CapacityExceeded
    );
    assert_eq!(std::format!("{opening:?}"), "Opening(..)");
}

#[test]
fn commitment_encoding_and_point_validation() {
    let bases = Bases::derive();
    let mut rng = rng(22);
    let cast_id = random_cast_id(&mut rng);
    let rand = Scalar::random(&mut rng);
    let commitment = commit(
        &bases,
        OptionIndex::new(3).unwrap(),
        &cast_id,
        &rand,
        ChunkIndex::new(0).unwrap(),
    );
    let bytes = encode_to_vec(&commitment);
    assert_eq!(bytes.len(), Commitment::ENCODED_LEN);
    assert_eq!(decode_exact::<Commitment>(&bytes).unwrap(), commitment);
    assert_eq!(
        Commitment::from_point32(commitment.to_point32()).unwrap(),
        commitment
    );
    assert_eq!(commitment.as_bytes(), &commitment.to_point32().0);

    // Not a valid encoding: the field element 2^255 − 1 is non-canonical.
    assert_eq!(
        Commitment::from_point32(Point32([0xff; 32])).unwrap_err(),
        Error::InvalidPoint
    );
    let err = decode_exact::<Commitment>(&[0xff; 32]).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::ValueOutOfRange);
    assert_eq!(err.offset(), 0);

    // The sum of no commitments is the identity (all-zero encoding).
    assert_eq!(sum_commitments(&[]).unwrap().as_bytes(), &[0u8; 32]);
    // Summing a commitment with its own negative randomness counterpart is
    // consistent with the aggregate equation.
    let other = commit(
        &bases,
        OptionIndex::new(3).unwrap(),
        &cast_id,
        &rand.neg(),
        ChunkIndex::new(0).unwrap(),
    );
    let total = sum_commitments(&[commitment, other]).unwrap();
    let packed = pow2(26 * 3).add(&pow2(26 * 3));
    let id_sum = cast_id.to_scalar().add(&cast_id.to_scalar());
    assert!(verify_aggregate(&bases, &total, &packed, &id_sum, &Scalar::ZERO).is_ok());
}

#[test]
fn bases_are_distinct_and_deterministic() {
    let first = Bases::derive();
    let second = Bases::derive();
    assert_eq!(first, second);
    let [val, id, rand] = first.compressed();
    assert_ne!(val, id);
    assert_ne!(id, rand);
    assert_ne!(val, rand);
    assert_ne!(val, [0u8; 32]);
}

#[test]
fn cast_id_maps_little_endian_and_encodes() {
    let mut token = [0u8; 24];
    token[0] = 1;
    assert_eq!(CastId::new(Token192(token)).to_scalar(), Scalar::ONE);
    let mut token = [0u8; 24];
    token[1] = 1;
    assert_eq!(
        CastId::new(Token192(token)).to_scalar(),
        Scalar::from_u64(256)
    );
    let token = Token192([0xff; 24]);
    let cast_id = CastId::new(token);
    assert_eq!(cast_id.token(), token);
    let bytes = encode_to_vec(&cast_id);
    assert_eq!(bytes.len(), CastId::ENCODED_LEN);
    assert_eq!(decode_exact::<CastId>(&bytes).unwrap(), cast_id);
    // 2^192 − 1 as a scalar: bytes 0..24 all 0xff, rest zero.
    let mut expected = [0u8; 32];
    expected[..24].copy_from_slice(&[0xff; 24]);
    assert_eq!(cast_id.to_scalar().to_bytes(), expected);
}
