//! Frame chain rules, chain state, and the on-disk stream parser.
// Integration-test crate: outside the TCB (CONSTITUTION.md §1.1).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::missing_panics_doc
)]

mod common;

use common::{ELECTION, decode_exact, encode_to_vec, frame_chain, frame_object, leaf_input};
use ityv_encoding::{ElectionId, ErrorKind, Hash512, SchemaId, Seq, Writer};
use ityv_ledger::{
    ChainHead, ChainState, Error, FrameStream, MAX_FRAME_LEN, MIN_FRAME_LEN, Resend,
    classify_resend, link, next_frame, root_of_leaves, write_record,
};

#[test]
fn frames_link_into_a_chain_and_the_state_tracks_the_tree() {
    let chain = frame_chain(5);
    let mut state = ChainState::new();
    assert!(state.head().is_none());
    let mut hashes = std::vec::Vec::new();
    for (i, bytes) in chain.iter().enumerate() {
        let hash = state.append(bytes).unwrap();
        assert_eq!(hash, ityv_crypto::object_hash(bytes));
        hashes.push(hash);
        let head = state.head().unwrap();
        assert_eq!(head.seq().get(), i as u64 + 1);
        assert_eq!(*head.hash(), hash);
        assert_eq!(head.election_id().as_bytes(), ELECTION);
        assert_eq!(state.accumulator().size(), i as u64 + 1);
    }
    assert_eq!(
        state.accumulator().root(),
        root_of_leaves(&hashes.as_slice(), 5).unwrap()
    );
    let bytes = encode_to_vec(&state);
    let back: ChainState<'_> = decode_exact(&bytes).unwrap();
    assert_eq!(back, state);
    assert!(ChainState::from_parts(None, state.accumulator()).is_none());
    assert!(
        ChainState::from_parts(state.head().copied(), &ityv_ledger::Accumulator::new()).is_none()
    );
}

#[test]
fn link_rejects_gaps_wrong_hashes_and_other_elections() {
    let chain = frame_chain(3);
    let first = link(None, &chain[0]).unwrap().into_inner();
    assert_eq!(first.prev_seq(), None);
    assert!(first.prev_hash().is_zero());
    let head = first.head();
    let second = link(Some(&head), &chain[1]).unwrap().into_inner();
    assert_eq!(second.prev_seq(), Some(Seq::FIRST));
    assert_eq!(second.prev_hash(), head.hash());
    assert_eq!(second.frame().seq().get(), 2);
    // Skipping a sequence number.
    assert_eq!(
        link(Some(&head), &chain[2]).unwrap_err(),
        Error::SequenceGap
    );
    // First frame must have seq 1 and a zero previous hash.
    assert_eq!(link(None, &chain[1]).unwrap_err(), Error::SequenceGap);
    let bad_first = frame_object(ELECTION, 1, Hash512([1; 64]), 5, leaf_input(1));
    assert_eq!(
        link(None, &bad_first).unwrap_err(),
        Error::PreviousHashMismatch
    );
    // Wrong previous hash.
    let wrong_prev = frame_object(ELECTION, 2, Hash512([1; 64]), 5, leaf_input(2));
    assert_eq!(
        link(Some(&head), &wrong_prev).unwrap_err(),
        Error::PreviousHashMismatch
    );
    // Election change.
    let other = frame_object(b"KR-2030-OTHER", 2, *head.hash(), 5, leaf_input(2));
    assert_eq!(
        link(Some(&head), &other).unwrap_err(),
        Error::ElectionMismatch
    );
    // Not a frame object.
    assert!(matches!(
        link(None, b"not a frame"),
        Err(Error::Encoding(_))
    ));
    let mut state = ChainState::new();
    state.append(&chain[0]).unwrap();
    let before = state;
    assert_eq!(state.append(&chain[2]).unwrap_err(), Error::SequenceGap);
    assert_eq!(state, before, "a failed append changes nothing");
}

#[test]
fn next_frame_builds_the_successor() {
    let election = ElectionId::new(ELECTION).unwrap();
    let first = next_frame(None, election, SchemaId::new(5), leaf_input(1)).unwrap();
    assert!(first.seq().is_first());
    assert!(first.prev_hash().is_zero());
    let bytes = common::object_to_vec(ityv_encoding::SCHEMA_LEDGER_FRAME, &first);
    let linked = link(None, &bytes).unwrap().into_inner();
    let head = linked.head();
    let second = next_frame(Some(&head), election, SchemaId::new(5), leaf_input(2)).unwrap();
    assert_eq!(second.seq().get(), 2);
    assert_eq!(second.prev_hash(), head.hash());
    let other = ElectionId::new(b"KR-2030-OTHER").unwrap();
    assert_eq!(
        next_frame(Some(&head), other, SchemaId::new(5), leaf_input(2)).unwrap_err(),
        Error::ElectionMismatch
    );
    let max_head = ChainHead::from_parts(election, Seq::new(u64::MAX).unwrap(), Hash512::ZERO);
    assert_eq!(
        next_frame(Some(&max_head), election, SchemaId::new(5), leaf_input(2)).unwrap_err(),
        Error::SequenceGap
    );
    let head_bytes = encode_to_vec(&head);
    let back: ChainHead<'_> = decode_exact(&head_bytes).unwrap();
    assert_eq!(back, head);
}

fn stream_of(frames: &[std::vec::Vec<u8>]) -> std::vec::Vec<u8> {
    let mut out = std::vec![0u8; frames.len() * (MAX_FRAME_LEN + 4)];
    let mut w = Writer::new(&mut out);
    for f in frames {
        write_record(&mut w, f).unwrap();
    }
    let used = w.finish();
    out.truncate(used);
    out
}

#[test]
fn stream_round_trips_and_isolates_a_torn_tail_at_every_cut() {
    let chain = frame_chain(4);
    let stream = stream_of(&chain);
    let records: std::vec::Vec<_> = FrameStream::new(&stream).map(|r| r.unwrap()).collect();
    assert_eq!(records.len(), 4);
    for (i, r) in records.iter().enumerate() {
        assert_eq!(r.bytes(), chain[i].as_slice());
        assert_eq!(r.frame().seq().get(), i as u64 + 1);
    }
    assert_eq!(records[1].offset(), 4 + chain[0].len());
    let mut s = FrameStream::new(&stream);
    while s.next_record().is_some() {}
    assert_eq!(s.position(), stream.len());
    // Every truncation point inside the last record is a torn tail at the
    // record's offset; the three complete records stay valid.
    let last_offset = records[3].offset();
    for cut in last_offset + 1..stream.len() {
        let mut s = FrameStream::new(&stream[..cut]);
        for _ in 0..3 {
            s.next_record().unwrap().unwrap();
        }
        assert_eq!(
            s.next_record().unwrap().unwrap_err(),
            Error::TornTail {
                offset: last_offset
            },
            "cut at {cut}"
        );
        assert!(s.next_record().is_none(), "nothing after an error");
    }
    // A cut exactly at the boundary is a clean end.
    let mut s = FrameStream::new(&stream[..last_offset]);
    assert_eq!(s.by_ref().count(), 3);
    assert!(s.next_record().is_none());
}

#[test]
fn stream_rejects_impossible_lengths_and_bad_records() {
    let chain = frame_chain(2);
    let mut stream = stream_of(&chain);
    // Length prefix above the maximum.
    let mut big = stream.clone();
    big[0..4].copy_from_slice(&(MAX_FRAME_LEN as u32 + 1).to_be_bytes());
    assert_eq!(
        FrameStream::new(&big).next().unwrap().unwrap_err(),
        Error::CorruptRecord { offset: 0 }
    );
    // Length prefix below the minimum.
    let mut small = stream.clone();
    small[0..4].copy_from_slice(&(MIN_FRAME_LEN as u32 - 1).to_be_bytes());
    assert_eq!(
        FrameStream::new(&small).next().unwrap().unwrap_err(),
        Error::CorruptRecord { offset: 0 }
    );
    // A record whose bytes are not a frame object.
    stream[4] ^= 0xff;
    let err = FrameStream::new(&stream).next().unwrap().unwrap_err();
    assert_eq!(
        err,
        Error::Record {
            offset: 0,
            inner: ityv_encoding::Error::new(ErrorKind::BadMagic, 0),
        }
    );
    // write_record refuses impossible lengths.
    let mut buf = [0u8; 8];
    let mut w = Writer::new(&mut buf);
    assert_eq!(
        write_record(&mut w, &[0u8; 3]).unwrap_err(),
        Error::CorruptRecord { offset: 0 }
    );
    assert!(matches!(
        write_record(&mut w, &chain[0]),
        Err(Error::Encoding(_))
    ));
}

#[test]
fn resends_are_classified_bytewise() {
    let chain = frame_chain(2);
    assert_eq!(classify_resend(&chain[0], &chain[0]), Resend::Identical);
    assert_eq!(classify_resend(&chain[0], &chain[1]), Resend::Conflict);
    let mut flipped = chain[0].clone();
    *flipped.last_mut().unwrap() ^= 1;
    assert_eq!(classify_resend(&chain[0], &flipped), Resend::Conflict);
}

#[test]
fn frame_length_bounds_match_the_schema() {
    let shortest = frame_object(b"A", 1, Hash512::ZERO, 1, Hash512::ZERO);
    assert_eq!(shortest.len(), MIN_FRAME_LEN);
    let longest = frame_object(&[b'A'; 64], 1, Hash512::ZERO, 1, Hash512::ZERO);
    assert_eq!(longest.len(), MAX_FRAME_LEN);
}
