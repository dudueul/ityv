//! The OR proof of representation (PROTOCOL.md §7.5): completeness for
//! every option position, soundness negatives, statement validation, the
//! proof encoding and its length formula.
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
    Bases, CastId, ChunkIndex, Commitment, Error, MAX_CHUNKS, Opening, OptionCount, OptionIndex,
    PROOF_SYSTEM_OR_REP_V1, Proof, Scalar, Statement, commit, prove, prove_into, verify,
};
use ityv_encoding::{ElectionId, ErrorKind, Ident, Token192};
use rand_chacha::ChaCha20Rng;
use rand_core::Rng;
use std::vec::Vec;

const ELECTION: &[u8] = b"KR-2030-PRES";
const BOX: &[u8] = b"BOX-0001";
const STYLE: &[u8] = b"PRES";

fn options(raw: u16) -> OptionCount {
    OptionCount::new(raw).unwrap()
}

fn statement(option_count: u16, commitments: &[Commitment]) -> Statement<'static> {
    Statement::new(
        ElectionId::new(ELECTION).unwrap(),
        Ident::new(BOX, 64).unwrap(),
        Ident::new(STYLE, 64).unwrap(),
        options(option_count),
        commitments,
    )
    .unwrap()
}

fn record(
    bases: &Bases,
    option_count: u16,
    option: u16,
    rng: &mut ChaCha20Rng,
) -> (Opening, Vec<Commitment>) {
    let mut token = [0u8; 24];
    rng.fill_bytes(&mut token);
    let cast_id = CastId::new(Token192(token));
    let mut rand = [Scalar::ZERO; MAX_CHUNKS];
    let chunks = usize::from(options(option_count).chunk_count());
    for slot in rand.iter_mut().take(chunks) {
        *slot = Scalar::random(rng);
    }
    let option = OptionIndex::new(option).unwrap();
    let commitments = (0..chunks)
        .map(|j| {
            commit(
                bases,
                option,
                &cast_id,
                &rand[j],
                ChunkIndex::new(u8::try_from(j).unwrap()).unwrap(),
            )
        })
        .collect();
    (Opening::new(option, cast_id, rand), commitments)
}

#[test]
fn completeness_for_every_option_position() {
    let bases = Bases::derive();
    let mut rng = rng(30);
    for option_count in [1u16, 2, 3, 9, 10, 16, 18] {
        let last = option_count - 1;
        let middle = option_count / 2;
        for option in [0, middle, last] {
            let (opening, commitments) = record(&bases, option_count, option, &mut rng);
            let st = statement(option_count, &commitments);
            assert_eq!(st.chunk_count(), options(option_count).chunk_count());
            let proof = prove(&bases, &st, &opening, &mut rng).unwrap();
            let proven = verify(&bases, &st, &proof)
                .unwrap_or_else(|e| panic!("option_count={option_count} option={option}: {e}"));
            assert_eq!(proven.get().statement(), &st);
            assert_eq!(proven.get().proof(), &proof);
            assert_eq!(proof.option_count().get(), option_count);
            assert_eq!(proof.chunk_count(), st.chunk_count());
        }
    }
}

#[test]
fn completeness_at_full_capacity() {
    let bases = Bases::derive();
    let mut rng = rng(31);
    let (opening, commitments) = record(&bases, 64, 63, &mut rng);
    let st = statement(64, &commitments);
    assert_eq!(st.chunk_count(), 8);
    let proof = prove(&bases, &st, &opening, &mut rng).unwrap();
    assert!(verify(&bases, &st, &proof).is_ok());
    assert_eq!(
        encode_to_vec(&proof).len(),
        Proof::encoded_len_for(options(64))
    );
    assert_eq!(Proof::encoded_len_for(options(64)), 3 + 64 * (64 + 32 * 8));
}

#[test]
fn encoded_length_matches_the_formula_for_every_option_count() {
    let bases = Bases::derive();
    let mut rng = rng(37);
    for option_count in 1..=64u16 {
        let (opening, commitments) = record(&bases, option_count, option_count - 1, &mut rng);
        let st = statement(option_count, &commitments);
        let proof = prove(&bases, &st, &opening, &mut rng).unwrap();
        let bytes = encode_to_vec(&proof);
        let k = usize::from(option_count.div_ceil(9));
        assert_eq!(bytes.len(), 3 + usize::from(option_count) * (64 + 32 * k));
        assert_eq!(bytes.len(), Proof::encoded_len_for(options(option_count)));
        assert_eq!(decode_exact::<Proof>(&bytes).unwrap(), proof);
    }
}

#[test]
fn soundness_negatives_for_tampered_proofs() {
    let bases = Bases::derive();
    let mut rng = rng(32);
    let option_count = 16u16;
    let (opening, commitments) = record(&bases, option_count, 2, &mut rng);
    let st = statement(option_count, &commitments);
    let proof = prove(&bases, &st, &opening, &mut rng).unwrap();
    assert!(verify(&bases, &st, &proof).is_ok());

    // Flip one bit in each kind of scalar through the encoding.
    let bytes = encode_to_vec(&proof);
    for offset in [3usize, 3 + 32, 3 + 64, 3 + 96, bytes.len() - 1] {
        let mut tampered = bytes.clone();
        tampered[offset] ^= 0x01;
        // The flipped byte may make the scalar non-canonical; either the
        // decoder or the verifier must reject it.
        match decode_exact::<Proof>(&tampered) {
            Ok(bad) => assert_eq!(
                verify(&bases, &st, &bad).unwrap_err(),
                Error::ProofInvalid,
                "offset {offset}"
            ),
            Err(err) => assert_eq!(err.kind(), ErrorKind::ValueOutOfRange),
        }
    }

    // Count mismatch between statement and proof.
    let (opening18, commitments18) = record(&bases, 18, 2, &mut rng);
    let st18 = statement(18, &commitments18);
    let proof18 = prove(&bases, &st18, &opening18, &mut rng).unwrap();
    assert_eq!(
        verify(&bases, &st, &proof18).unwrap_err(),
        Error::ProofInvalid
    );
    assert_eq!(
        verify(&bases, &st18, &proof).unwrap_err(),
        Error::ProofInvalid
    );
}

#[test]
fn soundness_negatives_for_statement_and_witness() {
    let bases = Bases::derive();
    let mut rng = rng(36);
    let option_count = 16u16;
    let (opening, commitments) = record(&bases, option_count, 2, &mut rng);
    let st = statement(option_count, &commitments);
    let proof = prove(&bases, &st, &opening, &mut rng).unwrap();

    // A different statement: election, box, ballot style, commitments.
    let other_election = Statement::new(
        ElectionId::new(b"KR-2034-PRES").unwrap(),
        Ident::new(BOX, 64).unwrap(),
        Ident::new(STYLE, 64).unwrap(),
        options(option_count),
        &commitments,
    )
    .unwrap();
    assert_eq!(
        verify(&bases, &other_election, &proof).unwrap_err(),
        Error::ProofInvalid
    );
    let other_box = Statement::new(
        ElectionId::new(ELECTION).unwrap(),
        Ident::new(b"BOX-0002", 64).unwrap(),
        Ident::new(STYLE, 64).unwrap(),
        options(option_count),
        &commitments,
    )
    .unwrap();
    assert_eq!(
        verify(&bases, &other_box, &proof).unwrap_err(),
        Error::ProofInvalid
    );
    let other_style = Statement::new(
        ElectionId::new(ELECTION).unwrap(),
        Ident::new(BOX, 64).unwrap(),
        Ident::new(b"PRES2", 64).unwrap(),
        options(option_count),
        &commitments,
    )
    .unwrap();
    assert_eq!(
        verify(&bases, &other_style, &proof).unwrap_err(),
        Error::ProofInvalid
    );
    let (_, other_commitments) = record(&bases, option_count, 2, &mut rng);
    let other_record = statement(option_count, &other_commitments);
    assert_eq!(
        verify(&bases, &other_record, &proof).unwrap_err(),
        Error::ProofInvalid
    );
    let swapped = statement(option_count, &[commitments[1], commitments[0]]);
    assert_eq!(
        verify(&bases, &swapped, &proof).unwrap_err(),
        Error::ProofInvalid
    );

    // A witness that does not open the commitments, or is out of the option
    // set (PROTOCOL §7.3), is rejected by `prove` through `verify_opening`.
    let (other_opening, _) = record(&bases, option_count, 2, &mut rng);
    assert_eq!(
        prove(&bases, &st, &other_opening, &mut rng).unwrap_err(),
        Error::OpeningInvalid
    );
    let out_of_range = Opening::new(
        OptionIndex::new(16).unwrap(),
        *opening.cast_id(),
        *opening.rand(),
    );
    assert_eq!(
        prove(&bases, &st, &out_of_range, &mut rng).unwrap_err(),
        Error::OptionOutOfRange
    );
    let wrong_option = Opening::new(
        OptionIndex::new(3).unwrap(),
        *opening.cast_id(),
        *opening.rand(),
    );
    assert_eq!(
        prove(&bases, &st, &wrong_option, &mut rng).unwrap_err(),
        Error::OpeningInvalid
    );
}

#[test]
fn maximum_length_identifiers_fit_the_transcript() {
    // 64-byte identifiers need the full 68-byte identifier field buffer; a
    // shorter buffer would make proving fail, and the field length enters
    // the declared transcript length.
    let bases = Bases::derive();
    let mut rng = rng(38);
    let (opening, commitments) = record(&bases, 4, 1, &mut rng);
    let long_election = [b'E'; 64];
    let long_box = [b'B'; 64];
    let long_style = [b'S'; 64];
    let st = Statement::new(
        ElectionId::new(&long_election).unwrap(),
        Ident::new(&long_box, 64).unwrap(),
        Ident::new(&long_style, 64).unwrap(),
        options(4),
        &commitments,
    )
    .unwrap();
    let proof = prove(&bases, &st, &opening, &mut rng).unwrap();
    assert!(verify(&bases, &st, &proof).is_ok());
    // The same proof does not verify under identifiers of other lengths.
    for len in [1usize, 63] {
        let other = Statement::new(
            ElectionId::new(&long_election[..len]).unwrap(),
            Ident::new(&long_box, 64).unwrap(),
            Ident::new(&long_style, 64).unwrap(),
            options(4),
            &commitments,
        )
        .unwrap();
        assert_eq!(
            verify(&bases, &other, &proof).unwrap_err(),
            Error::ProofInvalid
        );
    }
    let short = statement(4, &commitments);
    assert_eq!(
        verify(&bases, &short, &proof).unwrap_err(),
        Error::ProofInvalid
    );
    let short_proof = prove(&bases, &short, &opening, &mut rng).unwrap();
    assert_eq!(
        verify(&bases, &st, &short_proof).unwrap_err(),
        Error::ProofInvalid
    );
}

#[test]
fn decode_accepts_the_capacity_boundaries_and_rejects_beyond() {
    let bases = Bases::derive();
    let mut rng = rng(39);
    let (opening, commitments) = record(&bases, 64, 0, &mut rng);
    let st = statement(64, &commitments);
    let proof = prove(&bases, &st, &opening, &mut rng).unwrap();
    let bytes = encode_to_vec(&proof);
    assert_eq!(bytes[0..2], 64u16.to_be_bytes());
    assert_eq!(bytes[2], 8);
    let decoded: Proof = decode_exact(&bytes).unwrap();
    assert_eq!(decoded.option_count().get(), 64);
    assert_eq!(decoded.chunk_count(), 8);
    assert!(verify(&bases, &st, &decoded).is_ok());
    // 65 options: rejected at offset 0; 9 chunks: rejected at offset 2.
    let mut bad = bytes.clone();
    bad[0..2].copy_from_slice(&65u16.to_be_bytes());
    let err = decode_exact::<Proof>(&bad).unwrap_err();
    assert_eq!((err.kind(), err.offset()), (ErrorKind::CountExceedsMax, 0));
    let mut bad = bytes.clone();
    bad[2] = 9;
    let err = decode_exact::<Proof>(&bad).unwrap_err();
    assert_eq!((err.kind(), err.offset()), (ErrorKind::CountExceedsMax, 2));
    // One option with one chunk is the smallest proof.
    let (opening, commitments) = record(&bases, 1, 0, &mut rng);
    let st = statement(1, &commitments);
    let proof = prove(&bases, &st, &opening, &mut rng).unwrap();
    let bytes = encode_to_vec(&proof);
    assert_eq!(bytes.len(), 3 + 96);
    assert!(verify(&bases, &st, &decode_exact::<Proof>(&bytes).unwrap()).is_ok());
    // A proof for 16 options against a 9-option statement with the same
    // first commitment fails on the option count alone.
    let (opening16, commitments16) = record(&bases, 16, 0, &mut rng);
    let st16 = statement(16, &commitments16);
    let proof16 = prove(&bases, &st16, &opening16, &mut rng).unwrap();
    let st9 = statement(9, &commitments16[..1]);
    assert_eq!(
        verify(&bases, &st9, &proof16).unwrap_err(),
        Error::ProofInvalid
    );
}

#[test]
fn proofs_are_randomized_and_option_is_hidden() {
    let bases = Bases::derive();
    let mut rng = rng(33);
    let (opening, commitments) = record(&bases, 4, 1, &mut rng);
    let st = statement(4, &commitments);
    let first = prove(&bases, &st, &opening, &mut rng).unwrap();
    let second = prove(&bases, &st, &opening, &mut rng).unwrap();
    assert_ne!(first, second);
    assert!(verify(&bases, &st, &first).is_ok());
    assert!(verify(&bases, &st, &second).is_ok());
    // Every branch carries a challenge and responses; none is empty.
    for t in 0..4u16 {
        let option = OptionIndex::new(t).unwrap();
        assert!(first.challenge(option).is_some());
        assert!(first.response_id(option).is_some());
        assert!(
            first
                .response_rand(option, ChunkIndex::new(0).unwrap())
                .is_some()
        );
        assert_ne!(first.challenge(option).unwrap(), &Scalar::ZERO);
    }
    assert!(first.challenge(OptionIndex::new(63).unwrap()).is_some());
    assert_eq!(
        first.challenge(OptionIndex::new(63).unwrap()).unwrap(),
        &Scalar::ZERO
    );
    assert!(std::format!("{first:?}").starts_with("Proof"));
    assert_eq!(st.proof_system_id(), PROOF_SYSTEM_OR_REP_V1);
    assert_eq!(st.election_id().as_bytes(), ELECTION);
    assert_eq!(st.box_id().as_bytes(), BOX);
    assert_eq!(st.ballot_style_id().as_bytes(), STYLE);
    assert_eq!(st.option_count().get(), 4);
    assert_eq!(st.commitments(), &commitments[..]);
}

#[test]
fn proof_encoding_round_trip_and_rejections() {
    let bases = Bases::derive();
    let mut rng = rng(34);
    let (opening, commitments) = record(&bases, 10, 9, &mut rng);
    let st = statement(10, &commitments);
    let proof = prove(&bases, &st, &opening, &mut rng).unwrap();
    let bytes = encode_to_vec(&proof);
    assert_eq!(bytes.len(), 3 + 10 * (64 + 32 * 2));
    assert_eq!(bytes[0..2], 10u16.to_be_bytes());
    assert_eq!(bytes[2], 2);
    let decoded: Proof = decode_exact(&bytes).unwrap();
    assert_eq!(decoded, proof);
    assert!(verify(&bases, &st, &decoded).is_ok());

    // Non-canonical scalar (all 0xff) at the first challenge.
    let mut bad = bytes.clone();
    for b in &mut bad[3..35] {
        *b = 0xff;
    }
    let err = decode_exact::<Proof>(&bad).unwrap_err();
    assert_eq!((err.kind(), err.offset()), (ErrorKind::ValueOutOfRange, 3));

    // Option counts outside 1..=64 and chunk counts outside 1..=8.
    for (option_count, chunk_count) in [(0u16, 2u8), (65, 8), (10, 0), (10, 9)] {
        let mut bad = bytes.clone();
        bad[0..2].copy_from_slice(&option_count.to_be_bytes());
        bad[2] = chunk_count;
        let err = decode_exact::<Proof>(&bad).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::CountExceedsMax);
        assert_eq!(
            err.offset(),
            if option_count == 0 || option_count > 64 {
                0
            } else {
                2
            }
        );
    }
    // A chunk count that does not match the option count can never verify
    // and is rejected at decode time.
    for chunk_count in [1u8, 3, 8] {
        let mut bad = bytes.clone();
        bad[2] = chunk_count;
        let err = decode_exact::<Proof>(&bad).unwrap_err();
        assert_eq!(
            (err.kind(), err.offset()),
            (ErrorKind::InvariantViolation, 2)
        );
    }

    // Truncated and extended input.
    assert_eq!(
        decode_exact::<Proof>(&bytes[..bytes.len() - 1])
            .unwrap_err()
            .kind(),
        ErrorKind::UnexpectedEnd
    );
    let mut extended = bytes.clone();
    extended.push(0);
    assert_eq!(
        decode_exact::<Proof>(&extended).unwrap_err().kind(),
        ErrorKind::TrailingBytes
    );
}

#[test]
fn statement_validation() {
    let bases = Bases::derive();
    let mut rng = rng(35);
    let (_, commitments) = record(&bases, 16, 0, &mut rng);
    let election = ElectionId::new(ELECTION).unwrap();
    let box_id = Ident::new(BOX, 64).unwrap();
    let style = Ident::new(STYLE, 64).unwrap();
    assert!(OptionCount::new(0).is_none());
    assert!(OptionCount::new(65).is_none());
    assert_eq!(
        Statement::new(election, box_id, style, options(16), &[]).unwrap_err(),
        Error::InvalidStatement
    );
    assert_eq!(
        Statement::new(election, box_id, style, options(16), &commitments[..1]).unwrap_err(),
        Error::InvalidStatement
    );
    assert_eq!(
        Statement::new(election, box_id, style, options(9), &commitments).unwrap_err(),
        Error::InvalidStatement
    );
    let nine = [commitments[0]; 9];
    assert_eq!(
        Statement::new(election, box_id, style, options(64), &nine).unwrap_err(),
        Error::InvalidStatement
    );
    let long = [b'a'; 65];
    let long_ident = Ident::new(&long, 128).unwrap();
    assert_eq!(
        Statement::new(election, long_ident, style, options(16), &commitments).unwrap_err(),
        Error::InvalidStatement
    );
    assert_eq!(
        Statement::new(election, box_id, long_ident, options(16), &commitments).unwrap_err(),
        Error::InvalidStatement
    );
    assert!(Statement::new(election, box_id, style, options(16), &commitments).is_ok());
}

#[test]
fn prove_into_overwrites_in_place_with_the_same_proof() {
    let bases = Bases::derive();
    let mut setup = rng(77);
    let (opening, commitments) = record(&bases, 18, 11, &mut setup);
    let st = statement(18, &commitments);
    let expected = prove(&bases, &st, &opening, &mut rng(5)).unwrap();
    // A proof already holding another, larger proof is fully overwritten.
    let (big_opening, big_commitments) = record(&bases, 64, 40, &mut setup);
    let big = statement(64, &big_commitments);
    let mut out = Proof::EMPTY;
    prove_into(&mut out, &bases, &big, &big_opening, &mut rng(6)).unwrap();
    assert_eq!(out.option_count().get(), 64);
    prove_into(&mut out, &bases, &st, &opening, &mut rng(5)).unwrap();
    assert_eq!(out, expected);
    assert_eq!(encode_to_vec(&out), encode_to_vec(&expected));
    assert!(verify(&bases, &st, &out).is_ok());
}

#[test]
fn a_failed_prove_into_leaves_the_empty_proof_of_the_statement() {
    let bases = Bases::derive();
    let mut setup = rng(78);
    let (opening, commitments) = record(&bases, 9, 4, &mut setup);
    let st = statement(9, &commitments);
    let mut out = prove(&bases, &st, &opening, &mut setup).unwrap();
    let (other, _) = record(&bases, 9, 2, &mut setup);
    assert_eq!(
        prove_into(&mut out, &bases, &st, &other, &mut setup).unwrap_err(),
        Error::OpeningInvalid
    );
    // all-zero proof of nine options, one chunk: 3 + 9·(64 + 32) bytes
    let mut zero = std::vec![0u8, 9, 1];
    zero.resize(3 + 9 * 96, 0);
    let empty: Proof = decode_exact(&zero).unwrap();
    assert_eq!(out, empty);
}

#[test]
fn the_empty_proof_and_clear() {
    assert_eq!(Proof::EMPTY.option_count().get(), 1);
    assert_eq!(
        encode_to_vec(&Proof::EMPTY),
        [0, 1, 1]
            .iter()
            .copied()
            .chain([0u8; 96])
            .collect::<Vec<u8>>()
    );
    let bases = Bases::derive();
    let mut setup = rng(79);
    let (opening, commitments) = record(&bases, 3, 1, &mut setup);
    let mut proof = prove(&bases, &statement(3, &commitments), &opening, &mut setup).unwrap();
    assert_ne!(proof, Proof::EMPTY);
    assert!(!proof.is_empty());
    proof.clear();
    assert_eq!(proof, Proof::EMPTY);
    assert!(proof.is_empty());
    assert!(Proof::EMPTY.is_empty());
    // a one-option proof is not empty, nor is an all-zero proof of nine
    let (one, one_commitments) = record(&bases, 1, 0, &mut setup);
    let single = prove(&bases, &statement(1, &one_commitments), &one, &mut setup).unwrap();
    assert_eq!(single.option_count().get(), 1);
    assert!(!single.is_empty());
    let mut zero = std::vec![0u8, 9, 1];
    zero.resize(3 + 9 * 96, 0);
    let nine: Proof = decode_exact(&zero).unwrap();
    assert!(!nine.is_empty());
}
