//! End-to-end ballot flows checked as the public verifier and the trustees
//! would check them.
// Integration-test crate: outside the TCB. Tests express "this must hold"
// with unwrap/expect/panic/indexing and small arithmetic on test sizes,
// so these lints are relaxed for this file only (CONSTITUTION.md §1.1).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::too_many_lines,
    clippy::missing_panics_doc,
    clippy::many_single_char_names
)]

mod common;

use common::{
    Buffers, MemJournal, SEED, STYLE_SMALL, STYLE_WIDE, World, interpretation, mocks, pad_bytes,
    ports, signer, tb, work, world,
};
use ityv_crypto::{
    AeadTag, Bases, CastId, ChunkIndex, Commitment, HybridCiphertext, MemberId, OneTimeKey,
    OneTimeTag, OptionIndex, Proof, Purpose, RecordPurpose, RecordSignature, Scalar, Share,
    Statement, decapsulate, open, reconstruct, verify, verify_hybrid, verify_one_time_tag,
    verify_record,
};
use ityv_cunit::ballot::KEM_CIPHERTEXT_LEN;
use ityv_cunit::boxstate::OpenBox;
use ityv_cunit::config::Profile;
use ityv_cunit::link::{JournalEntry, JournalKind, SCHEMA_JOURNAL_ENTRY};
use ityv_cunit::rules::{PAD_MAC_KEY_OFFSET, PAD_PLAINTEXT_OFFSET};
use ityv_encoding::{
    CastRecord, ChallengeOpening, Decode, Encode, HYBRID_SIG_LEN, MemberShare, Reader,
    SCHEMA_CAST_RECORD, SCHEMA_CHALLENGE_OPENING, SCHEMA_MEMBER_SHARE, SCHEMA_SHARE_PACKAGE,
    SCHEMA_VERSION_1, SharePackage, TRANSPORT_KEM_FALLBACK, TRANSPORT_NEUTRAL_MODULE, Token192,
    Transport, Writer, decode_object,
};

/// Verifies a `CastRecord` the way the public verifier does: tracking code,
/// device and module record signatures, OR proof.
fn verify_cast_record(
    w: &World,
    modules: &[common::MockModule],
    record_bytes: &[u8],
    tracking: &ityv_encoding::Hash512,
) {
    let record: CastRecord<'_> =
        decode_object(SCHEMA_CAST_RECORD, SCHEMA_VERSION_1, record_bytes).unwrap();
    let body_bytes = record.body_bytes();
    assert_eq!(&ityv_crypto::object_hash(body_bytes), tracking);
    let device_vk = w.device_record.verifying_key();
    let device_sig = RecordSignature::from_bytes(*record.device_sig_ed25519());
    let _ = verify_record(
        &device_vk,
        RecordPurpose::CastRecord,
        body_bytes,
        &device_sig,
    )
    .unwrap();
    let body = record.body();
    for (sig, m) in record.module_sigs().zip(modules) {
        assert_eq!(sig.module_id.as_bytes(), m.id);
        let counter = body.module_counters().get(sig.module_id).unwrap();
        let mut message = [0u8; 140];
        let mut wr = Writer::new(&mut message);
        tracking.encode(&mut wr).unwrap();
        sig.module_id.encode(&mut wr).unwrap();
        wr.write_u64(counter).unwrap();
        let len = wr.finish();
        let _ = verify_record(
            &m.record_verifying_key(),
            RecordPurpose::ModuleRecord,
            &message[..len],
            &RecordSignature::from_bytes(*sig.ed25519),
        )
        .unwrap();
    }
    let style = w.config.style(body.ballot_style_id()).unwrap().1;
    let commitments: std::vec::Vec<Commitment> = body
        .commitments()
        .as_slice()
        .iter()
        .map(|p| Commitment::from_point32(*p).unwrap())
        .collect();
    let statement = Statement::new(
        w.config.election_id(),
        w.config.box_id().ident(),
        body.ballot_style_id().ident(),
        style.option_count(),
        &commitments,
    )
    .unwrap();
    let mut reader = Reader::new(body.proof());
    let proof = Proof::decode(&mut reader).unwrap();
    let _ = verify(&Bases::derive(), &statement, &proof).unwrap();
}

#[test]
fn in_person_ballot_is_cast_imprinted_and_publicly_verifiable() {
    let w = world(Profile::InPerson, false);
    let mut box_ = OpenBox::open(w.config, tb(10));
    let mut modules = mocks(&w);
    let mut journal = MemJournal::default();
    let mut bufs = Buffers::new(&w);
    let mut area = work();
    let ballot = box_
        .interpret(&interpretation(b"E-2026", STYLE_SMALL, 2), &mut area)
        .unwrap();
    let ballot = ballot
        .issue(&mut box_, &mut ports(&mut modules), &SEED)
        .unwrap();
    let ballot = ballot.commit(&box_).unwrap();
    let ballot = ballot
        .build(
            &box_,
            &mut ports(&mut modules),
            &w.device_record,
            bufs.as_build(),
        )
        .unwrap();
    let tracking = *ballot.tracking_code();
    let record = ballot.record_bytes().to_vec();
    let package = ballot.package_bytes().to_vec();
    let ballot = ballot.cast(&mut box_, &mut journal, tb(11)).unwrap();
    let imprint = ballot.imprint_command(&box_).unwrap();
    assert!(imprint.env_label().is_none());
    let _done = ballot.imprinted(&mut box_).unwrap();

    verify_cast_record(&w, &modules, &record, &tracking);
    let parsed: CastRecord<'_> =
        decode_object(SCHEMA_CAST_RECORD, SCHEMA_VERSION_1, &record).unwrap();
    assert_eq!(parsed.body().transport_flags(), TRANSPORT_NEUTRAL_MODULE);
    assert_eq!(
        parsed.body().share_package_hash(),
        &ityv_crypto::object_hash(&package)
    );
    // cast id = SHA3-512("ityv:castid:v1" ‖ 0x00 ‖ cid in module order)[0..24]
    let mut h = ityv_crypto::Sha3Hasher::new();
    h.absorb(b"ityv:castid:v1");
    h.absorb(&[0]);
    for m in &modules {
        h.absorb(&m.last_issue().cid);
    }
    assert_eq!(imprint.cast_id()[..], h.finish()[..24]);

    assert_eq!(journal.entries.len(), 1);
    let entry: JournalEntry<'_> =
        decode_object(SCHEMA_JOURNAL_ENTRY, SCHEMA_VERSION_1, &journal.entries[0]).unwrap();
    assert_eq!(entry.kind(), JournalKind::Record);
    assert_eq!(entry.record_hash(), &tracking);
    assert_eq!(entry.prev_head(), &ityv_encoding::Hash512::ZERO);
    assert_eq!(journal.packages[0].as_deref(), Some(package.as_slice()));
    assert_eq!(
        box_.journal_head(),
        &ityv_crypto::object_hash(&journal.entries[0])
    );
    assert_eq!(box_.totals().records, 1);
    assert_eq!(box_.module_counters(), &[1, 1, 1, 1, 1]);
    assert!(!box_.has_ballot_in_flight());
}

/// Decrypts every member share of a package (pads for module chambers, the
/// KEM for the others) and returns `(trustee index, member, MemberShare bytes)`.
fn decrypt_package(
    w: &World,
    package: &[u8],
) -> std::vec::Vec<(usize, MemberId, std::vec::Vec<u8>)> {
    let pkg: SharePackage<'_> =
        decode_object(SCHEMA_SHARE_PACKAGE, SCHEMA_VERSION_1, package).unwrap();
    let mut out = std::vec::Vec::new();
    for (index, entry) in pkg.entries().enumerate() {
        let trustee = &w.trustees[index];
        assert_eq!(entry.trustee_id.as_bytes(), trustee.id);
        let member = MemberId::new(trustee.chamber, trustee.member_index).unwrap();
        let plain = match entry.transport {
            Transport::Pad { pad_index, .. } => {
                let module = w
                    .modules
                    .iter()
                    .find(|m| m.chamber == trustee.chamber)
                    .unwrap();
                let pad = pad_bytes(
                    module.id,
                    trustee.member_index,
                    pad_index + PAD_PLAINTEXT_OFFSET,
                    entry.ciphertext.len(),
                );
                let plain: std::vec::Vec<u8> = entry
                    .ciphertext
                    .iter()
                    .zip(pad)
                    .map(|(c, p)| c ^ p)
                    .collect();
                let key = pad_bytes(
                    module.id,
                    trustee.member_index,
                    pad_index + PAD_MAC_KEY_OFFSET,
                    32,
                );
                let _ = verify_one_time_tag(
                    OneTimeKey::from_bytes(key.try_into().unwrap()),
                    &plain,
                    &OneTimeTag::from_bytes(*entry.tag),
                )
                .unwrap();
                plain
            }
            Transport::Kem => {
                let ct = HybridCiphertext::decode(&mut Reader::new(
                    &entry.ciphertext[..KEM_CIPHERTEXT_LEN],
                ))
                .unwrap();
                let key = decapsulate(&trustee.kem, &ct).unwrap();
                let mut aad = [0u8; 512];
                let mut wr = Writer::new(&mut aad);
                w.config.election_id().encode(&mut wr).unwrap();
                w.config.box_id().encode(&mut wr).unwrap();
                pkg.commitments().encode(&mut wr).unwrap();
                entry.trustee_id.encode(&mut wr).unwrap();
                wr.write_u8(1).unwrap();
                wr.write_u32(0).unwrap();
                wr.write_u64(0).unwrap();
                let aad_len = wr.finish();
                let mut buf = entry.ciphertext[KEM_CIPHERTEXT_LEN..].to_vec();
                let _ = open(
                    key,
                    &aad[..aad_len],
                    &mut buf,
                    &AeadTag::from_bytes(*entry.tag),
                )
                .unwrap();
                buf
            }
        };
        out.push((index, member, plain));
    }
    out
}

/// Reconstructs secret `index` from the shares of the trustees `who`.
fn reconstruct_secret(
    w: &World,
    shares: &[(usize, MemberId, std::vec::Vec<u8>)],
    who: &[usize],
    index: usize,
) -> Result<Scalar, ityv_crypto::Error> {
    let picked: std::vec::Vec<Share> = shares
        .iter()
        .filter(|(i, _, _)| who.contains(i))
        .map(|(_, member, bytes)| {
            let share: MemberShare<'_> =
                decode_object(SCHEMA_MEMBER_SHARE, SCHEMA_VERSION_1, bytes).unwrap();
            let value = share.shares().as_slice()[index];
            Share::new(*member, Scalar::from_canonical_bytes(value.0).unwrap())
        })
        .collect();
    reconstruct(w.config.access(), &picked)
}

fn run_challenge(profile: Profile, style: &[u8], chunks: usize, option: u16) {
    let w = world(profile, false);
    let mut box_ = OpenBox::open(w.config, tb(1));
    let mut modules = mocks(&w);
    let mut journal = MemJournal::default();
    let mut bufs = Buffers::new(&w);
    let mut area = work();
    let ballot = box_
        .interpret(&interpretation(b"E-2026", style, option), &mut area)
        .unwrap();
    let ballot = ballot
        .issue(&mut box_, &mut ports(&mut modules), &SEED)
        .unwrap();
    let ballot = ballot.commit(&box_).unwrap();
    let ballot = ballot
        .build(
            &box_,
            &mut ports(&mut modules),
            &w.device_record,
            bufs.as_build(),
        )
        .unwrap();
    let tracking = *ballot.tracking_code();
    let record = ballot.record_bytes().to_vec();
    let package = ballot.package_bytes().to_vec();
    let mut out = std::vec![0u8; 8192];
    let (_spoiled, opening) = ballot
        .challenge(&mut box_, &mut journal, signer(&w), tb(2), &mut out)
        .unwrap();
    let opening = opening.to_vec();
    assert_eq!(box_.totals().challenged, 1);
    assert_eq!(box_.totals().records, 0);
    let entry: JournalEntry<'_> =
        decode_object(SCHEMA_JOURNAL_ENTRY, SCHEMA_VERSION_1, &journal.entries[0]).unwrap();
    assert_eq!(entry.kind(), JournalKind::Challenge);
    assert_eq!(entry.record_hash(), &tracking);

    // The opening is signed and reconstructs the published commitments (VC-028).
    let parsed: ChallengeOpening<'_> =
        decode_object(SCHEMA_CHALLENGE_OPENING, SCHEMA_VERSION_1, &opening).unwrap();
    let sig = ityv_crypto::HybridSignature::decode(&mut Reader::new(parsed.device_sig())).unwrap();
    let purpose = Purpose::new(b"challenge").unwrap();
    let _ = verify_hybrid(
        &w.device_hybrid.verifying_key(),
        &purpose,
        parsed.body_bytes(),
        &sig,
    )
    .unwrap();
    let body = parsed.body();
    assert_eq!(body.option_index(), option);
    assert_eq!(body.record_hash(), &tracking);
    let rec: CastRecord<'_> = decode_object(SCHEMA_CAST_RECORD, SCHEMA_VERSION_1, &record).unwrap();
    assert_eq!(rec.body().commitments().as_slice().len(), chunks);
    let bases = Bases::derive();
    let cast_id = CastId::new(*body.cast_id());
    for (j, (point, r)) in rec
        .body()
        .commitments()
        .as_slice()
        .iter()
        .zip(body.rand().as_slice())
        .enumerate()
    {
        let rand = Scalar::from_canonical_bytes(r.0).unwrap();
        let c = ityv_crypto::commit(
            &bases,
            OptionIndex::new(option).unwrap(),
            &cast_id,
            &rand,
            ChunkIndex::new(j as u8).unwrap(),
        );
        assert_eq!(&c.to_point32(), point);
        // r_j is the sum of the module contributions
        let sum = body
            .modules()
            .map(|m| Scalar::from_canonical_bytes(m.rand.as_slice()[j].0).unwrap())
            .fold(Scalar::ZERO, |a, b| a.add(&b));
        assert_eq!(sum.to_bytes(), rand.to_bytes());
    }
    for (opened, mock) in body.modules().zip(&modules) {
        assert_eq!(opened.module_id.as_bytes(), mock.id);
        assert_eq!(opened.counter, mock.last_issue().counter);
        assert_eq!(opened.cid.0, mock.last_issue().cid);
    }

    // Trustees decrypt their shares and a qualified set reconstructs every
    // secret; the reconstructed values equal the opening (§9.1 order).
    let shares = decrypt_package(&w, &package);
    let qualified: std::vec::Vec<usize> = w
        .trustees
        .iter()
        .enumerate()
        .filter(|(_, t)| t.chamber != ityv_crypto::Chamber::N)
        .map(|(i, _)| i)
        .collect();
    let mut index = 0;
    for opened in body.modules() {
        for r in opened.rand.as_slice() {
            let got = reconstruct_secret(&w, &shares, &qualified, index).unwrap();
            assert_eq!(got.to_bytes(), r.0);
            index += 1;
        }
    }
    let got = reconstruct_secret(&w, &shares, &qualified, index).unwrap();
    assert_eq!(got.to_bytes(), cast_id.to_scalar().to_bytes());
    if profile == Profile::Absentee {
        let label = reconstruct_secret(&w, &shares, &qualified, index + 1).unwrap();
        let mut h = ityv_crypto::Sha3Hasher::new();
        h.absorb(b"ityv:envlabel:v1");
        h.absorb(&[0]);
        for m in &modules {
            h.absorb(&m.last_issue().lab.unwrap());
        }
        let mut token = [0u8; 24];
        token.copy_from_slice(&h.finish()[..24]);
        assert_eq!(
            label.to_bytes(),
            CastId::new(Token192(token)).to_scalar().to_bytes()
        );
        // module members carry the module's label contribution
        for (i, _, bytes) in &shares {
            let share: MemberShare<'_> =
                decode_object(SCHEMA_MEMBER_SHARE, SCHEMA_VERSION_1, bytes).unwrap();
            assert_eq!(share.lab().is_some(), share.has_module(), "trustee {i}");
        }
    }
    // Without both X members the set is not qualified.
    let unqualified: std::vec::Vec<usize> = qualified
        .iter()
        .copied()
        .filter(|&i| {
            !(w.trustees[i].chamber == ityv_crypto::Chamber::X && w.trustees[i].member_index == 0)
        })
        .collect();
    assert!(reconstruct_secret(&w, &shares, &unqualified, 0).is_err());
    // Module members hold their module's cid and tag; the others hold zeros.
    for (i, _, bytes) in &shares {
        let share: MemberShare<'_> =
            decode_object(SCHEMA_MEMBER_SHARE, SCHEMA_VERSION_1, bytes).unwrap();
        let trustee = &w.trustees[*i];
        if let Some(mi) = w.modules.iter().position(|m| m.chamber == trustee.chamber) {
            assert!(share.has_module());
            assert_eq!(share.cid().0, modules[mi].last_issue().cid);
        } else {
            assert!(!share.has_module());
            assert_eq!(share.cid().0, [0; 24]);
            assert_eq!(share.tag(), &[0; 16]);
        }
    }
}

#[test]
fn challenge_opening_matches_commitments_and_trustee_reconstruction() {
    run_challenge(Profile::InPerson, STYLE_SMALL, 1, 3);
}

#[test]
fn two_chunk_challenge_reconstructs_every_chunk() {
    run_challenge(Profile::InPerson, STYLE_WIDE, 2, 11);
}

#[test]
fn absentee_challenge_reconstructs_the_envelope_label() {
    run_challenge(Profile::Absentee, STYLE_SMALL, 1, 0);
}

#[test]
fn absentee_ballot_imprints_an_envelope_label() {
    let w = world(Profile::Absentee, false);
    let mut box_ = OpenBox::open(w.config, tb(1));
    let mut modules = mocks(&w);
    let mut journal = MemJournal::default();
    let mut bufs = Buffers::new(&w);
    let mut area = work();
    let ballot = box_
        .interpret(&interpretation(b"E-2026", STYLE_SMALL, 1), &mut area)
        .unwrap();
    let ballot = ballot
        .issue(&mut box_, &mut ports(&mut modules), &SEED)
        .unwrap();
    let ballot = ballot.commit(&box_).unwrap();
    let ballot = ballot
        .build(
            &box_,
            &mut ports(&mut modules),
            &w.device_record,
            bufs.as_build(),
        )
        .unwrap();
    let ballot = ballot.cast(&mut box_, &mut journal, tb(1)).unwrap();
    let imprint = ballot.imprint_command(&box_).unwrap();
    assert!(imprint.env_label().is_some());
    assert_ne!(imprint.env_label(), Some(imprint.cast_id()));
    ballot.imprinted(&mut box_).unwrap();
}

#[test]
fn exhausted_pad_falls_back_to_the_kem_and_sets_bit_zero() {
    let w = world(Profile::InPerson, false);
    let mut box_ = OpenBox::open(w.config, tb(1));
    let mut modules = mocks(&w);
    modules[3].exhaust_member = Some(1); // mod-x, member 1
    modules[2].exhaust_member = Some(0); // mod-j, member 0
    let mut journal = MemJournal::default();
    let mut bufs = Buffers::new(&w);
    let mut area = work();
    let ballot = box_
        .interpret(&interpretation(b"E-2026", STYLE_SMALL, 0), &mut area)
        .unwrap();
    let ballot = ballot
        .issue(&mut box_, &mut ports(&mut modules), &SEED)
        .unwrap();
    let ballot = ballot.commit(&box_).unwrap();
    let ballot = ballot
        .build(
            &box_,
            &mut ports(&mut modules),
            &w.device_record,
            bufs.as_build(),
        )
        .unwrap();
    let record = ballot.record_bytes().to_vec();
    let package = ballot.package_bytes().to_vec();
    ballot
        .cast(&mut box_, &mut journal, tb(1))
        .unwrap()
        .imprinted(&mut box_)
        .unwrap();
    let rec: CastRecord<'_> = decode_object(SCHEMA_CAST_RECORD, SCHEMA_VERSION_1, &record).unwrap();
    assert_eq!(
        rec.body().transport_flags(),
        TRANSPORT_NEUTRAL_MODULE | TRANSPORT_KEM_FALLBACK
    );
    let pkg: SharePackage<'_> =
        decode_object(SCHEMA_SHARE_PACKAGE, SCHEMA_VERSION_1, &package).unwrap();
    for (entry, trustee) in pkg.entries().zip(&w.trustees) {
        let expect_kem = trustee.chamber == ityv_crypto::Chamber::N
            || (trustee.chamber == ityv_crypto::Chamber::X && trustee.member_index == 1)
            || (trustee.chamber == ityv_crypto::Chamber::J && trustee.member_index == 0);
        assert_eq!(
            entry.transport == Transport::Kem,
            expect_kem,
            "{:?}",
            trustee.id
        );
        if let Transport::Pad { pad_id, pad_index } = entry.transport {
            assert_eq!(pad_id, trustee.pad_id);
            assert_eq!(pad_index, modules[0].pad_b); // counter 1 × b
        }
    }
    let shares = decrypt_package(&w, &package);
    assert_eq!(shares.len(), 12);
}

#[test]
fn slip_is_signed_over_the_tracking_code() {
    let w = world(Profile::InPerson, true);
    let mut box_ = OpenBox::open(w.config, tb(1));
    let mut modules = mocks(&w);
    let mut journal = MemJournal::default();
    let mut bufs = Buffers::new(&w);
    let mut area = work();
    let ballot = box_
        .interpret(&interpretation(b"E-2026", STYLE_SMALL, 1), &mut area)
        .unwrap();
    let ballot = ballot
        .issue(&mut box_, &mut ports(&mut modules), &SEED)
        .unwrap();
    let ballot = ballot.commit(&box_).unwrap();
    let ballot = ballot
        .build(
            &box_,
            &mut ports(&mut modules),
            &w.device_record,
            bufs.as_build(),
        )
        .unwrap();
    let ballot = ballot.cast(&mut box_, &mut journal, tb(3)).unwrap();
    let mut out = std::vec![0u8; ityv_cunit::ballot::MAX_SLIP_LEN];
    let slip_bytes = ballot
        .slip(&box_, signer(&w), tb(3), &mut out)
        .unwrap()
        .to_vec();
    let slip: ityv_encoding::Slip<'_> =
        decode_object(ityv_encoding::SCHEMA_SLIP, SCHEMA_VERSION_1, &slip_bytes).unwrap();
    assert_eq!(slip.body().tracking_code(), ballot.tracking_code());
    assert_eq!(slip.body().station_id().as_bytes(), b"ST-1");
    assert_eq!(slip.device_sig().len(), HYBRID_SIG_LEN);
    let sig = ityv_crypto::HybridSignature::decode(&mut Reader::new(slip.device_sig())).unwrap();
    let _ = verify_hybrid(
        &w.device_hybrid.verifying_key(),
        &Purpose::new(b"slip").unwrap(),
        slip.body_bytes(),
        &sig,
    )
    .unwrap();
    ballot.imprinted(&mut box_).unwrap();
}

#[test]
fn slip_requires_the_voter_code_scope() {
    let w = world(Profile::InPerson, false);
    let mut box_ = OpenBox::open(w.config, tb(1));
    let mut modules = mocks(&w);
    let mut journal = MemJournal::default();
    let mut bufs = Buffers::new(&w);
    let mut area = work();
    let ballot = box_
        .interpret(&interpretation(b"E-2026", STYLE_SMALL, 1), &mut area)
        .unwrap();
    let ballot = ballot
        .issue(&mut box_, &mut ports(&mut modules), &SEED)
        .unwrap();
    let ballot = ballot.commit(&box_).unwrap();
    let ballot = ballot
        .build(
            &box_,
            &mut ports(&mut modules),
            &w.device_record,
            bufs.as_build(),
        )
        .unwrap();
    let ballot = ballot.cast(&mut box_, &mut journal, tb(3)).unwrap();
    let mut out = std::vec![0u8; ityv_cunit::ballot::MAX_SLIP_LEN];
    assert_eq!(
        ballot.slip(&box_, signer(&w), tb(3), &mut out).unwrap_err(),
        ityv_cunit::Error::VoterCodeDisabled
    );
}

/// Casts one ballot of `style` and returns its record and package bytes.
fn cast_bytes(
    w: &World,
    box_: &mut OpenBox<'static>,
    modules: &mut [common::MockModule],
    journal: &mut MemJournal,
    style: &[u8],
    option: u16,
) -> (std::vec::Vec<u8>, std::vec::Vec<u8>) {
    let mut bufs = Buffers::new(w);
    let mut area = work();
    let ballot = box_
        .interpret(&interpretation(b"E-2026", style, option), &mut area)
        .unwrap();
    let ballot = ballot.issue(box_, &mut ports(modules), &SEED).unwrap();
    let ballot = ballot.commit(box_).unwrap();
    let ballot = ballot
        .build(box_, &mut ports(modules), &w.device_record, bufs.as_build())
        .unwrap();
    let record = ballot.record_bytes().to_vec();
    let package = ballot.package_bytes().to_vec();
    ballot
        .cast(box_, journal, tb(1))
        .unwrap()
        .imprinted(box_)
        .unwrap();
    assert!(area.is_clear());
    (record, package)
}

#[test]
fn styles_with_different_chunk_counts_never_share_pad_bytes() {
    let w = world(Profile::InPerson, false);
    let mut box_ = OpenBox::open(w.config, tb(1));
    let mut modules = mocks(&w);
    let mut journal = MemJournal::default();
    let b = w.config.pad_consumption();
    // in person, five modules: k = 1 shares 254 bytes, k = 2 shares 414
    assert_eq!(b, 414 + 64);
    assert_eq!(modules[0].pad_b, b);
    let mut packages = std::vec::Vec::new();
    for (style, option) in [(STYLE_SMALL, 1), (STYLE_WIDE, 9), (STYLE_SMALL, 3)] {
        let (_, package) = cast_bytes(&w, &mut box_, &mut modules, &mut journal, style, option);
        packages.push(package);
    }
    for module in &modules {
        for member in 0..2u8 {
            let mut regions: std::vec::Vec<(u64, u64)> = module
                .pad_uses
                .iter()
                .filter(|(m, _, _)| *m == member)
                .map(|&(_, offset, len)| (offset, offset + len))
                .collect();
            assert_eq!(regions.len(), 3, "{:?}", module.id);
            regions.sort_unstable();
            for (n, pair) in regions.windows(2).enumerate() {
                assert!(pair[0].1 <= pair[1].0, "{:?} overlap at {n}", module.id);
            }
            for (n, region) in regions.iter().enumerate() {
                assert_eq!(region.0, (n as u64 + 1) * b);
            }
        }
    }
    // every member opens every share with the per-box layout
    let lens: std::vec::Vec<usize> = packages
        .iter()
        .map(|package| {
            let shares = decrypt_package(&w, package);
            assert_eq!(shares.len(), 12);
            shares[0].2.len()
        })
        .collect();
    assert_eq!(lens, [254, 414, 254]);
}

#[test]
fn trustees_check_the_module_tag_with_their_pad_key() {
    let w = world(Profile::InPerson, false);
    let mut box_ = OpenBox::open(w.config, tb(1));
    let mut modules = mocks(&w);
    let mut journal = MemJournal::default();
    cast_bytes(&w, &mut box_, &mut modules, &mut journal, STYLE_SMALL, 2);
    let (record, package) = cast_bytes(&w, &mut box_, &mut modules, &mut journal, STYLE_SMALL, 1);
    let rec: CastRecord<'_> = decode_object(SCHEMA_CAST_RECORD, SCHEMA_VERSION_1, &record).unwrap();
    let shares = decrypt_package(&w, &package);
    let qualified: std::vec::Vec<usize> = w
        .trustees
        .iter()
        .enumerate()
        .filter(|(_, t)| t.chamber != ityv_crypto::Chamber::N)
        .map(|(i, _)| i)
        .collect();
    // the sampled chamber X: its module is the fourth, so with k = 1 its
    // contribution r_{X,0} is secret 3 (§9.1 order)
    let module_index = 3;
    let module = &modules[module_index];
    let counter = rec
        .body()
        .module_counters()
        .get(ityv_encoding::ModuleId::new(module.id).unwrap())
        .unwrap();
    assert_eq!(counter, 2);
    let r = reconstruct_secret(&w, &shares, &qualified, module_index).unwrap();
    let b = w.config.pad_consumption();
    for (i, member, bytes) in &shares {
        if member.chamber() != ityv_crypto::Chamber::X {
            continue;
        }
        let share: MemberShare<'_> =
            decode_object(SCHEMA_MEMBER_SHARE, SCHEMA_VERSION_1, bytes).unwrap();
        let key = pad_bytes(
            module.id,
            member.index(),
            counter * b + ityv_cunit::rules::PAD_TAG_KEY_OFFSET,
            32,
        );
        let mut message = r.to_bytes().to_vec();
        message.extend_from_slice(&share.cid().0);
        let _ = verify_one_time_tag(
            OneTimeKey::from_bytes(key.clone().try_into().unwrap()),
            &message,
            &OneTimeTag::from_bytes(*share.tag()),
        )
        .unwrap_or_else(|_| panic!("trustee {i}: the module's tag verifies"));
        // a unit that replaced the module's randomness fails the check
        let mut forged = r.add(&Scalar::from_u64(1)).to_bytes().to_vec();
        forged.extend_from_slice(&share.cid().0);
        assert!(
            verify_one_time_tag(
                OneTimeKey::from_bytes(key.try_into().unwrap()),
                &forged,
                &OneTimeTag::from_bytes(*share.tag()),
            )
            .is_err()
        );
    }
}

#[test]
fn a_kem_share_opens_only_under_its_own_associated_data() {
    let w = world(Profile::InPerson, false);
    let mut box_ = OpenBox::open(w.config, tb(1));
    let mut modules = mocks(&w);
    let mut journal = MemJournal::default();
    let (_, package) = cast_bytes(&w, &mut box_, &mut modules, &mut journal, STYLE_SMALL, 1);
    let pkg: SharePackage<'_> =
        decode_object(SCHEMA_SHARE_PACKAGE, SCHEMA_VERSION_1, &package).unwrap();
    let (index, entry) = pkg
        .entries()
        .enumerate()
        .find(|(_, e)| e.transport == Transport::Kem)
        .unwrap();
    let trustee = &w.trustees[index];
    assert_eq!(trustee.chamber, ityv_crypto::Chamber::N);
    let aad = |commitments: &ityv_encoding::Commitments, trustee_id: &[u8]| {
        let mut out = [0u8; 512];
        let mut wr = Writer::new(&mut out);
        w.config.election_id().encode(&mut wr).unwrap();
        w.config.box_id().encode(&mut wr).unwrap();
        commitments.encode(&mut wr).unwrap();
        ityv_encoding::TrusteeId::new(trustee_id)
            .unwrap()
            .encode(&mut wr)
            .unwrap();
        wr.write_u8(1).unwrap();
        wr.write_u32(0).unwrap();
        wr.write_u64(0).unwrap();
        let len = wr.finish();
        out[..len].to_vec()
    };
    let try_open = |aad: &[u8]| {
        let ct =
            HybridCiphertext::decode(&mut Reader::new(&entry.ciphertext[..KEM_CIPHERTEXT_LEN]))
                .unwrap();
        let key = decapsulate(&trustee.kem, &ct).unwrap();
        let mut buf = entry.ciphertext[KEM_CIPHERTEXT_LEN..].to_vec();
        open(key, aad, &mut buf, &AeadTag::from_bytes(*entry.tag)).is_ok()
    };
    assert!(try_open(&aad(pkg.commitments(), trustee.id)));
    let mut points = pkg.commitments().as_slice().to_vec();
    points[0].0[0] ^= 1;
    let other = ityv_encoding::Commitments::new(&points).unwrap();
    assert!(!try_open(&aad(&other, trustee.id)), "other commitments");
    assert!(
        !try_open(&aad(pkg.commitments(), b"t-n-1")),
        "another trustee"
    );
}

#[test]
fn ports_in_another_order_are_rejected() {
    let w = world(Profile::InPerson, false);
    let mut box_ = OpenBox::open(w.config, tb(1));
    let mut modules = mocks(&w);
    let mut journal = MemJournal::default();
    let mut area = work();
    // at issue, the first answer names the wrong module
    let ballot = box_
        .interpret(&interpretation(b"E-2026", STYLE_SMALL, 1), &mut area)
        .unwrap();
    modules.swap(0, 1);
    assert_eq!(
        ballot
            .issue(&mut box_, &mut ports(&mut modules), &SEED)
            .unwrap_err(),
        ityv_cunit::Error::WrongModule
    );
    assert!(area.is_clear());
    box_.quarantine_in_flight(&mut journal, tb(1)).unwrap();
    // The misrouted request still consumed a counter inside mod-c, which
    // the unit never accepted: from now on mod-c's answers are gaps.
    modules.swap(0, 1);
    let ballot = box_
        .interpret(&interpretation(b"E-2026", STYLE_SMALL, 1), &mut area)
        .unwrap();
    assert_eq!(
        ballot
            .issue(&mut box_, &mut ports(&mut modules), &SEED)
            .unwrap_err(),
        ityv_cunit::Error::CounterGap
    );
    box_.quarantine_in_flight(&mut journal, tb(1)).unwrap();
    // at build, another module's pad belongs to other members
    let mut box_ = OpenBox::open(w.config, tb(1));
    let mut modules = mocks(&w);
    let mut bufs = Buffers::new(&w);
    let ballot = box_
        .interpret(&interpretation(b"E-2026", STYLE_SMALL, 1), &mut area)
        .unwrap();
    let ballot = ballot
        .issue(&mut box_, &mut ports(&mut modules), &SEED)
        .unwrap();
    let ballot = ballot.commit(&box_).unwrap();
    modules.swap(2, 3);
    assert_eq!(
        ballot
            .build(
                &box_,
                &mut ports(&mut modules),
                &w.device_record,
                bufs.as_build()
            )
            .unwrap_err(),
        ityv_cunit::Error::PadIdMismatch
    );
    assert!(area.is_clear());
}

#[test]
fn a_record_signature_from_another_key_is_rejected() {
    let w = world(Profile::InPerson, false);
    let mut box_ = OpenBox::open(w.config, tb(1));
    let mut modules = mocks(&w);
    modules[4].wrong_record_key = true;
    let mut bufs = Buffers::new(&w);
    let mut area = work();
    let ballot = box_
        .interpret(&interpretation(b"E-2026", STYLE_SMALL, 1), &mut area)
        .unwrap();
    let ballot = ballot
        .issue(&mut box_, &mut ports(&mut modules), &SEED)
        .unwrap();
    let ballot = ballot.commit(&box_).unwrap();
    assert_eq!(
        ballot
            .build(
                &box_,
                &mut ports(&mut modules),
                &w.device_record,
                bufs.as_build()
            )
            .unwrap_err(),
        ityv_cunit::Error::RecordSignature
    );
    assert!(area.is_clear());
}

#[test]
fn the_work_area_is_wiped_at_every_terminal_and_failing_exit() {
    let w = world(Profile::Absentee, false);
    let mut box_ = OpenBox::open(w.config, tb(1));
    let mut modules = mocks(&w);
    let mut journal = MemJournal::default();
    let mut bufs = Buffers::new(&w);
    let mut area = work();
    // challenged
    let ballot = box_
        .interpret(&interpretation(b"E-2026", STYLE_SMALL, 2), &mut area)
        .unwrap();
    let ballot = ballot
        .issue(&mut box_, &mut ports(&mut modules), &SEED)
        .unwrap();
    let ballot = ballot.commit(&box_).unwrap();
    let ballot = ballot
        .build(
            &box_,
            &mut ports(&mut modules),
            &w.device_record,
            bufs.as_build(),
        )
        .unwrap();
    let mut out = std::vec![0u8; 8192];
    let (spoiled, _) = ballot
        .challenge(&mut box_, &mut journal, signer(&w), tb(1), &mut out)
        .unwrap();
    assert_eq!(format!("{spoiled:?}"), "Challenged(())");
    assert!(area.is_clear());
    // a challenge whose journal entry fails wipes the opening too
    let ballot = box_
        .interpret(&interpretation(b"E-2026", STYLE_SMALL, 2), &mut area)
        .unwrap();
    let ballot = ballot
        .issue(&mut box_, &mut ports(&mut modules), &SEED)
        .unwrap();
    let ballot = ballot.commit(&box_).unwrap();
    let ballot = ballot
        .build(
            &box_,
            &mut ports(&mut modules),
            &w.device_record,
            bufs.as_build(),
        )
        .unwrap();
    journal.fail = true;
    let mut out = std::vec![0xAAu8; 8192];
    assert!(
        ballot
            .challenge(&mut box_, &mut journal, signer(&w), tb(1), &mut out)
            .is_err()
    );
    assert!(out.iter().all(|&b| b == 0), "the opening was wiped");
    assert!(area.is_clear());
    journal.fail = false;
    box_.quarantine_in_flight(&mut journal, tb(1)).unwrap();
    // imprint failed
    let ballot = box_
        .interpret(&interpretation(b"E-2026", STYLE_SMALL, 2), &mut area)
        .unwrap();
    let ballot = ballot
        .issue(&mut box_, &mut ports(&mut modules), &SEED)
        .unwrap();
    let ballot = ballot.commit(&box_).unwrap();
    let ballot = ballot
        .build(
            &box_,
            &mut ports(&mut modules),
            &w.device_record,
            bufs.as_build(),
        )
        .unwrap();
    let ballot = ballot.cast(&mut box_, &mut journal, tb(1)).unwrap();
    let done = ballot
        .imprint_failed(&mut box_, &mut journal, tb(1))
        .unwrap();
    assert_eq!(format!("{done:?}"), "Done(())");
    assert!(area.is_clear());
    // a ballot value dropped mid-way
    let ballot = box_
        .interpret(&interpretation(b"E-2026", STYLE_SMALL, 2), &mut area)
        .unwrap();
    let ballot = ballot
        .issue(&mut box_, &mut ports(&mut modules), &SEED)
        .unwrap();
    let ballot = ballot.commit(&box_).unwrap();
    drop(ballot);
    assert!(area.is_clear());
    box_.quarantine_in_flight(&mut journal, tb(1)).unwrap();
}
