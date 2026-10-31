//! Property tests (verification ladder V1) for the pure arithmetic and the
//! algebraic properties the protocol relies on.
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
use ityv_crypto::{
    AccessStructure, Bases, CastId, Chamber, ChunkIndex, DIGIT_BITS, MAX_CHUNKS, MemberId, Opening,
    OptionIndex, Purpose, Scalar, Threshold, commit, decode_digits, is_qualified, packed_value,
    reconstruct, signing_digest, split, verify_opening, xor_in_place,
};
use ityv_encoding::Token192;
use proptest::prelude::*;
use std::vec::Vec;

fn pow2(exponent: u32) -> Scalar {
    let mut value = Scalar::ONE;
    for _ in 0..exponent {
        value = value.add(&value);
    }
    value
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn xor_is_an_involution(data in prop::collection::vec(any::<u8>(), 0..64)) {
        let pad: Vec<u8> = data.iter().map(|b| b.wrapping_mul(31).wrapping_add(7)).collect();
        let mut buffer = data.clone();
        xor_in_place(&mut buffer, &pad).unwrap();
        for ((out, inp), mask) in buffer.iter().zip(&data).zip(&pad) {
            prop_assert_eq!(*out, inp ^ mask);
        }
        xor_in_place(&mut buffer, &pad).unwrap();
        prop_assert_eq!(buffer, data);
    }

    #[test]
    fn xor_rejects_length_mismatch(len in 0usize..32, delta in 1usize..4) {
        let mut buffer = std::vec![0u8; len];
        let pad = std::vec![1u8; len + delta];
        prop_assert!(xor_in_place(&mut buffer, &pad).is_err());
        prop_assert!(buffer.iter().all(|b| *b == 0));
    }

    #[test]
    fn digits_round_trip(digits in prop::array::uniform9(0u32..(1 << 26))) {
        let mut packed = Scalar::ZERO;
        for (position, count) in digits.iter().enumerate() {
            let weight = pow2(DIGIT_BITS * u32::try_from(position).unwrap());
            packed = packed.add(&weight.mul(&Scalar::from_u64(u64::from(*count))));
        }
        prop_assert_eq!(decode_digits(&packed).unwrap(), digits);
    }

    #[test]
    fn scalars_round_trip_through_the_encoding(wide in any::<[u8; 64]>()) {
        let scalar = Scalar::from_bytes_mod_order_wide(&wide);
        let bytes = encode_to_vec(&scalar);
        prop_assert_eq!(bytes.len(), 32);
        prop_assert_eq!(decode_exact::<Scalar>(&bytes).unwrap(), scalar);
        prop_assert_eq!(Scalar::from_canonical_bytes(scalar.to_bytes()).unwrap(), scalar);
        // Field laws used by the proof: a − a = 0, a·a⁻¹ = 1 for a ≠ 0.
        prop_assert_eq!(scalar.sub(&scalar), Scalar::ZERO);
        prop_assert_eq!(scalar.add(&scalar.neg()), Scalar::ZERO);
        if !scalar.is_zero() {
            prop_assert_eq!(scalar.mul(&scalar.invert().unwrap()), Scalar::ONE);
        }
    }

    #[test]
    fn signing_digest_separates_purposes(obj in prop::collection::vec(any::<u8>(), 0..40), tail in 0u8..3) {
        let a = Purpose::new(b"cast-record").unwrap();
        let b = Purpose::new(b"module-record").unwrap();
        prop_assert_ne!(signing_digest(&a, &obj), signing_digest(&b, &obj));
        let mut other = obj.clone();
        other.push(tail);
        prop_assert_ne!(signing_digest(&a, &obj), signing_digest(&a, &other));
    }

    #[test]
    fn reconstruction_succeeds_exactly_on_qualified_sets(counts in prop::array::uniform6(0u8..=3), seed in any::<u64>()) {
        let structure = AccessStructure::uniform(Threshold::new(2, 3).unwrap());
        let mut rng = rng(seed);
        let secret = Scalar::random(&mut rng);
        let shares = split(&secret, &structure, &mut rng);
        let mut set = Vec::new();
        for (chamber, count) in Chamber::ALL.iter().zip(counts.iter()) {
            for index in 0..*count {
                set.push(shares.share(MemberId::new(*chamber, index).unwrap()));
            }
        }
        let result = reconstruct(&structure, &set);
        if is_qualified(&structure, counts) {
            prop_assert_eq!(result.unwrap(), secret);
        } else {
            prop_assert_eq!(result.unwrap_err(), ityv_crypto::Error::NotQualified);
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]

    #[test]
    fn commitments_open_only_to_their_witness(option in 0u16..18, token in any::<[u8; 24]>(), seed in any::<u64>()) {
        let bases = Bases::derive();
        let mut rng = rng(seed);
        let option = OptionIndex::new(option).unwrap();
        let cast_id = CastId::new(Token192(token));
        let mut rand = [Scalar::ZERO; MAX_CHUNKS];
        rand[0] = Scalar::random(&mut rng);
        rand[1] = Scalar::random(&mut rng);
        let commitments = [
            commit(&bases, option, &cast_id, &rand[0], ChunkIndex::new(0).unwrap()),
            commit(&bases, option, &cast_id, &rand[1], ChunkIndex::new(1).unwrap()),
        ];
        let opening = Opening::new(option, cast_id, rand);
        prop_assert!(verify_opening(&bases, &commitments, &opening).is_ok());
        let other = OptionIndex::new((option.get() + 1) % 18).unwrap();
        let wrong = Opening::new(other, cast_id, rand);
        prop_assert!(verify_opening(&bases, &commitments, &wrong).is_err());
        // packed values of distinct options in the same chunk differ.
        for j in 0..2u8 {
            let chunk = ChunkIndex::new(j).unwrap();
            if option.get() / 9 == u16::from(j) && other.get() / 9 == u16::from(j) {
                prop_assert_ne!(packed_value(option, chunk), packed_value(other, chunk));
            }
        }
    }
}
