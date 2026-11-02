//! The pinned genesis (ADR-0028, PROTOCOL.md §4): the pin (VC-005), the
//! commission's, the committee's and the witnesses' signatures with the
//! quorum and diversity rule (VC-104), entry proofs, and amendments
//! (VC-105), against real hybrid signatures and Merkle proofs.
// Integration tests: outside the TCB. Assertions use unwrap/expect, so these
// lints are relaxed for this file only (CONSTITUTION.md §1.1).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]

mod common;

use common::genesis::{
    QUORUM, SIGNERS, body, commission, committee, key_bytes, seal, spare_device_key,
};
use common::{BOX, fixture, leak, leak_slice};
use ityv_crypto::hash::object_hash;
use ityv_encoding::{
    AMENDABLE_SET_COUNT, AmendmentReason, CaptureProfile, ElectionId, EntrySet,
    GenesisAmendmentBody, GenesisAmendmentParts, GenesisBox, Hash512,
    SCHEMA_GENESIS_AMENDMENT_BODY, SCHEMA_VERSION_1, SetCommitment, StationEntry, TimeBucket,
    WitnessQuorum, WitnessRosterEntry, encode_object,
};
use ityv_ledger::InclusionProof;
use ityv_state::{Error, Genesis, Pinned};

fn legal() -> Hash512 {
    Hash512([0x4C; 64])
}

#[test]
fn the_pin_decides() {
    let b = fixture();
    assert_eq!(object_hash(b.signed.body_bytes()), b.pin);
    let mut wrong = b.pin;
    wrong.0[0] ^= 1;
    assert_eq!(Pinned::new(&wrong, b.signed).unwrap_err(), Error::Pin);
    assert!(Pinned::new(&b.pin, b.signed).is_ok());
    // An amendment is not a genesis, whatever its hash.
    let body = b.amendment_body(1, b.pin);
    let (amendment, _) = seal(body, b"genesis-amendment", &SIGNERS);
    assert_eq!(
        Pinned::new(&object_hash(body), amendment).unwrap_err(),
        Error::Mismatch
    );
}

#[test]
fn seal_needs_the_quorum() {
    let b = fixture();
    let pinned = || Pinned::new(&b.pin, b.signed).unwrap();
    let (_, tokens) = seal(b.signed.body_bytes(), b"genesis", &SIGNERS);
    let witnesses = b.witnesses_via(&pinned(), &SIGNERS);
    let genesis = pinned().seal(tokens, witnesses).unwrap();
    assert_eq!(genesis.hash(), &b.pin);
    assert_eq!(genesis.head(), &b.pin);
    assert_eq!(genesis.seq(), 0);
    assert_eq!(genesis.election_id(), common::election());
    assert_eq!(genesis.sets(), b.genesis.body().sets());
    assert_eq!(genesis.release_manifest_hash(), &Hash512([0x13; 64]));
    assert_eq!(
        genesis.commission_key(),
        key_bytes(&commission().verifying_key())
    );
    assert_eq!(
        genesis.committee_key(),
        key_bytes(&committee().verifying_key())
    );
    assert_eq!(genesis.body().quorum(), &QUORUM);
    // The witness entries must name the signers one to one.
    assert_eq!(
        pinned().seal(tokens, &witnesses[..8]).unwrap_err(),
        Error::NotRegistered
    );
    let mut swapped = witnesses.to_vec();
    swapped.swap(0, 1);
    assert_eq!(
        pinned().seal(tokens, &swapped).unwrap_err(),
        Error::NotRegistered
    );
    // One token per signature, in order.
    assert_eq!(
        pinned().seal(&tokens[..10], witnesses).unwrap_err(),
        Error::Unverified
    );
    let mut reordered = tokens.to_vec();
    reordered.swap(0, 1);
    assert_eq!(
        pinned().seal(&reordered, witnesses).unwrap_err(),
        Error::SignatureObject
    );
    // A witness token from a key the roster does not register.
    let stranger = leak(ityv_crypto::HybridSigningKey::from_seeds([9; 32], [8; 32]));
    let (sig, token) = common::signed_by(stranger, b"genesis", b.signed.body_bytes());
    let mut sigs: Vec<_> = b.signed.witness_sigs().collect();
    sigs[0].sig = sig;
    let forged = leak(
        ityv_encoding::SignedGenesis::new(
            b.signed.body_bytes(),
            b.signed.commission_sig(),
            b.signed.committee_sig(),
            &sigs,
        )
        .unwrap(),
    );
    let mut forged_tokens = tokens.to_vec();
    forged_tokens[2] = token;
    let pinned_forged = Pinned::new(&b.pin, forged).unwrap();
    assert_eq!(
        pinned_forged
            .seal(leak_slice(forged_tokens), witnesses)
            .unwrap_err(),
        Error::SignatureSigner
    );
}

#[test]
fn seal_needs_diverse_witnesses() {
    let b = fixture();
    // Witness i is of organisation i mod 7, provider i mod 4, region i mod 3.
    for who in [
        // Six organisations.
        [0, 1, 2, 3, 4, 5, 7, 8, 9],
        // Three providers.
        [0, 1, 2, 4, 5, 6, 8, 9, 10],
        // Two regions.
        [0, 1, 3, 4, 6, 7, 9, 10, 12],
    ] {
        let (signed, tokens) = seal(b.signed.body_bytes(), b"genesis", &who);
        let pinned = Pinned::new(&b.pin, signed).unwrap();
        let witnesses = b.witnesses_via(&pinned, &who);
        assert_eq!(
            pinned.seal(tokens, witnesses).unwrap_err(),
            Error::SignersShort,
            "{who:?}"
        );
    }
    // Any nine with seven organisations, four providers and three regions.
    let who = [2, 3, 4, 5, 6, 7, 8, 9, 10];
    let (signed, tokens) = seal(b.signed.body_bytes(), b"genesis", &who);
    let pinned = Pinned::new(&b.pin, signed).unwrap();
    let witnesses = b.witnesses_via(&pinned, &who);
    assert!(pinned.seal(tokens, witnesses).is_ok());
}

#[test]
fn entries_need_their_proof() {
    let b = fixture();
    let g = &b.genesis;
    let (bytes, index, proof) = b.raw(EntrySet::Boxes, BOX);
    let entry = g.entry::<GenesisBox<'static>>(bytes, index, proof).unwrap();
    assert_eq!(entry.get().box_id.as_bytes(), BOX);
    assert_eq!(entry.hash(), &object_hash(bytes));
    assert_eq!(entry.index(), index);
    // Another index, another entry's proof, altered bytes.
    assert_eq!(
        g.entry::<GenesisBox<'static>>(bytes, index + 1, proof)
            .unwrap_err(),
        Error::NotIncluded
    );
    let (other_bytes, other_index, other_proof) = b.raw(EntrySet::Boxes, b"BOX-002");
    assert_ne!(other_index, index);
    assert_eq!(
        g.entry::<GenesisBox<'static>>(bytes, index, other_proof)
            .unwrap_err(),
        Error::NotIncluded
    );
    let mut altered = bytes.to_vec();
    let last = altered.len() - 1;
    altered[last] ^= 1;
    let altered = leak_slice(altered);
    assert!(matches!(
        g.entry::<GenesisBox<'static>>(altered, index, proof),
        Err(Error::NotIncluded | Error::Decode)
    ));
    let empty = leak(InclusionProof::from_hashes(&[]).unwrap());
    assert_eq!(
        g.entry::<GenesisBox<'static>>(bytes, index, empty)
            .unwrap_err(),
        Error::NotIncluded
    );
    // The bytes of another set's entry do not decode as a box.
    let (station, s_index, s_proof) = b.raw(EntrySet::Stations, b"ST-1");
    assert_eq!(
        g.entry::<GenesisBox<'static>>(station, s_index, s_proof)
            .unwrap_err(),
        Error::Decode
    );
    assert!(
        g.entry::<StationEntry<'static>>(station, s_index, s_proof)
            .is_ok()
    );
    // A box entry proved into another set's root fails: each set has its
    // own root.
    assert_eq!(
        g.entry::<GenesisBox<'static>>(other_bytes, other_index, other_proof)
            .map(|e| e.index()),
        Ok(other_index)
    );
    // Witness entries proved against another genesis state are refused
    // when sealing.
    let (amended, _) = b.amended();
    let elsewhere = b.witnesses_in(amended, &SIGNERS);
    let (_, tokens) = seal(b.signed.body_bytes(), b"genesis", &SIGNERS);
    assert_eq!(
        Pinned::new(&b.pin, b.signed)
            .unwrap()
            .seal(tokens, elsewhere)
            .unwrap_err(),
        Error::StaleEntry
    );
    // The anchor of a state.
    let anchor = amended.anchor();
    assert_eq!(anchor.pin(), &b.pin);
    assert_eq!(anchor.seq(), 1);
    assert_eq!(anchor.head(), amended.head());
    assert_eq!(g.anchor().seq(), 0);
    assert_eq!(g.anchor().head(), &b.pin);
    assert_eq!(entry.head(), g.head());
    // A witness entry through the pinned body.
    let pinned = Pinned::new(&b.pin, b.signed).unwrap();
    let (w, w_index, w_proof) = b.raw(EntrySet::Witnesses, b"W01");
    let witness: ityv_state::Entry<WitnessRosterEntry<'static>> =
        pinned.witness(w, w_index, w_proof).unwrap();
    assert_eq!(witness.get().witness_id.as_bytes(), b"W01");
    assert_eq!(
        pinned.witness(w, w_index + 1, w_proof).unwrap_err(),
        Error::NotIncluded
    );
}

fn amendment(
    b: &common::genesis::Built,
    election: ElectionId<'static>,
    seq: u64,
    previous: Hash512,
) -> &'static [u8] {
    let mut sets = [SetCommitment {
        count: 0,
        root: Hash512::ZERO,
    }; AMENDABLE_SET_COUNT];
    sets.copy_from_slice(&b.genesis.sets()[..AMENDABLE_SET_COUNT]);
    let body = GenesisAmendmentBody::new(&GenesisAmendmentParts {
        election_id: election,
        seq,
        previous_hash: previous,
        reason: AmendmentReason::RosterChange,
        reason_hash: Hash512([0x5E; 64]),
        time_bucket: TimeBucket::new(300),
        release_manifest_hash: Hash512([0x13; 64]),
        sets,
    })
    .unwrap();
    let mut buf = vec![0u8; 4096];
    let len = encode_object(
        SCHEMA_GENESIS_AMENDMENT_BODY,
        SCHEMA_VERSION_1,
        &body,
        &mut buf,
    )
    .unwrap();
    buf.truncate(len);
    leak_slice(buf)
}

#[test]
fn amendments_chain_and_replace_sets() {
    let b = fixture();
    let g = &b.genesis;
    let witnesses = b.witnesses(&SIGNERS);
    let (amended, spare) = b.amended();
    assert_eq!(amended.seq(), 1);
    assert_eq!(amended.hash(), &b.pin);
    let body = b.amendment_body(1, b.pin);
    assert_eq!(amended.head(), &object_hash(body));
    assert_eq!(amended.release_manifest_hash(), &Hash512([0x5F; 64]));
    assert_ne!(
        amended.sets()[EntrySet::Boxes.index()],
        g.sets()[EntrySet::Boxes.index()]
    );
    assert_eq!(
        amended.sets()[EntrySet::Stations.index()],
        g.sets()[EntrySet::Stations.index()]
    );
    assert_eq!(
        amended.sets()[EntrySet::Witnesses.index()],
        g.sets()[EntrySet::Witnesses.index()]
    );
    assert_eq!(
        spare.get().device_key,
        key_bytes(&spare_device_key().verifying_key())
    );
    // The old box entry no longer proves against the amended root, and
    // other sets still do.
    let (bytes, index, proof) = b.raw(EntrySet::Boxes, BOX);
    assert_eq!(
        amended
            .entry::<GenesisBox<'static>>(bytes, index, proof)
            .unwrap_err(),
        Error::NotIncluded
    );
    let (station, s_index, s_proof) = b.raw(EntrySet::Stations, b"ST-1");
    assert!(
        amended
            .entry::<StationEntry<'static>>(station, s_index, s_proof)
            .is_ok()
    );
    // The next amendment names the last body, with witness entries
    // proved against the amended state; entries of the original state are
    // stale.
    let next = amendment(b, common::election(), 2, *amended.head());
    let (signed, tokens) = seal(next, b"genesis-amendment", &SIGNERS);
    assert_eq!(
        amended.amend(signed, tokens, witnesses).unwrap_err(),
        Error::StaleEntry
    );
    let current = b.witnesses_in(amended, &SIGNERS);
    assert!(current.iter().all(|w| w.head() == amended.head()));
    assert!(witnesses.iter().all(|w| w.head() == &b.pin));
    let twice = amended.amend(signed, tokens, current).unwrap();
    assert_eq!(twice.seq(), 2);
    assert_eq!(twice.head(), &object_hash(next));
    // Refusals: a skipped number, a repeated number, another previous
    // hash, another election, a genesis body.
    for (election, seq, previous) in [
        (common::election(), 3, *amended.head()),
        (common::election(), 1, *amended.head()),
        (common::election(), 2, b.pin),
        (common::other_election(), 2, *amended.head()),
    ] {
        let body = amendment(b, election, seq, previous);
        let (signed, tokens) = seal(body, b"genesis-amendment", &SIGNERS);
        assert_eq!(
            amended.amend(signed, tokens, current).unwrap_err(),
            Error::Mismatch
        );
    }
    assert_eq!(
        g.amend(b.signed, &[], witnesses).unwrap_err(),
        Error::Mismatch
    );
    // Signatures are checked as for the genesis.
    let body = amendment(b, common::election(), 1, b.pin);
    let (signed, tokens) = seal(body, b"genesis-amendment", &SIGNERS);
    assert_eq!(
        g.amend(signed, &tokens[..10], witnesses).unwrap_err(),
        Error::Unverified
    );
    let (signed, tokens) = seal(body, b"genesis", &SIGNERS);
    assert_eq!(
        g.amend(signed, tokens, witnesses).unwrap_err(),
        Error::SignatureObject
    );
}

#[test]
fn amendment_needs_the_genesis_quorum() {
    // A genesis whose quorum is ten: a nine-witness amendment is short.
    let ten = WitnessQuorum {
        quorum: 10,
        byzantine_max: 4,
        ..QUORUM
    };
    let (body_bytes, _) = body(legal(), CaptureProfile::InPerson, ten);
    let who: [usize; 10] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    let (signed, tokens) = seal(body_bytes, b"genesis", &who);
    let pin = object_hash(body_bytes);
    let pinned = Pinned::new(&pin, signed).unwrap();
    let b = fixture();
    // The witness set is the same in both bodies.
    let witnesses = b.witnesses_via(&pinned, &who);
    let genesis: Genesis<'static> = pinned.seal(tokens, witnesses).unwrap();
    let nine = amendment(b, common::election(), 1, pin);
    let (signed, tokens) = seal(nine, b"genesis-amendment", &SIGNERS);
    assert_eq!(
        genesis.amend(signed, tokens, &witnesses[..9]).unwrap_err(),
        Error::SignersShort
    );
    let (signed, tokens) = seal(nine, b"genesis-amendment", &who);
    assert!(genesis.amend(signed, tokens, witnesses).is_ok());
}
