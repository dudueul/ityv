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
    Buffers, MODULES, MODULES_FOUR_PARTIES, MemJournal, MemStaging, ModuleSpec, SEED, STYLE_SMALL,
    STYLE_WIDE, World, build_position, cast_built, interpretation, mocks, pad_bytes, ports, signer,
    tb, visit_end, visit_work, work, world, world_with,
};
use ityv_crypto::{
    AeadTag, Bases, CastId, ChunkIndex, Commitment, HybridCiphertext, MemberId, OneTimeKey,
    OneTimeTag, OptionIndex, Proof, Purpose, RecordPurpose, RecordSignature, Scalar, Share,
    Statement, decapsulate, open, reconstruct, verify, verify_hybrid, verify_one_time_tag,
    verify_record,
};
use ityv_cunit::ballot::KEM_CIPHERTEXT_LEN;
use ityv_cunit::boxstate::OpenBox;
use ityv_cunit::config::{MAX_MODULES, Profile};
use ityv_cunit::link::{JournalEntry, JournalKind, SCHEMA_JOURNAL_ENTRY, visit_digest};
use ityv_cunit::rules::{PAD_MAC_KEY_OFFSET, PAD_PLAINTEXT_OFFSET};
use ityv_cunit::visit::Decision;
use ityv_cunit::{Choice, Error};
use ityv_encoding::{
    CastRecord, ChallengeOpening, Decode, Encode, MemberShare, Reader, SCHEMA_CAST_RECORD,
    SCHEMA_CHALLENGE_OPENING, SCHEMA_MEMBER_SHARE, SCHEMA_SHARE_PACKAGE, SCHEMA_VERSION_1,
    SharePackage, TRANSPORT_KEM_FALLBACK, TRANSPORT_NEUTRAL_MODULE, Token192, Transport, Writer,
    decode_object,
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
    let mut staging = MemStaging::default();
    let mut visit = visit_work();
    let bound = ballot
        .bind(&mut box_, &mut journal, &mut staging, &mut visit, tb(10))
        .unwrap();
    assert_eq!((bound.position(), bound.tracking_code()), (0, &tracking));
    // binding journals the bound entry, durable: the record hash and the
    // counters the ballot consumed, no package
    assert_eq!(kinds(&journal), [JournalKind::Bound]);
    assert_eq!((journal.deferred, journal.syncs), (0, 1));
    let bound_bytes = journal.entries[0].clone();
    let bound_entry: JournalEntry<'_> =
        decode_object(SCHEMA_JOURNAL_ENTRY, SCHEMA_VERSION_1, &bound_bytes).unwrap();
    assert_eq!(bound_entry.record_hash(), &tracking);
    assert_eq!(bound_entry.prev_head(), &ityv_encoding::Hash512::ZERO);
    assert_eq!(
        bound_entry.share_package_hash(),
        &ityv_encoding::Hash512::ZERO
    );
    assert_eq!(bound_entry.module_counters().len(), 5);
    assert_eq!(journal.packages[0], None);
    let ready = box_
        .end_visit(&visit_end(b"E-2026", 1), &mut visit)
        .unwrap();
    let mut package_buf = std::vec![0u8; 300_000];
    let mut decided = ready
        .decide(
            &mut box_,
            Decision::CAST_ALL,
            &mut journal,
            &mut staging,
            &mut package_buf,
            tb(11),
        )
        .unwrap();
    let imprint = decided.imprint_command(&box_).unwrap();
    decided.imprinted(&mut box_, &mut journal, tb(11)).unwrap();
    let processed = decided.finish_positions(&mut box_).unwrap();
    assert_eq!(processed.label_command(&box_).err(), Some(Error::NoLabel));
    processed.finish(&mut box_).unwrap();
    assert!(visit.is_clear());

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

    // the bound entry, then the record entry and the decision entry (one
    // fsync), then the imprint entry
    assert_eq!(journal.entries.len(), 4);
    assert_eq!((journal.deferred, journal.syncs), (1, 3));
    let entry: JournalEntry<'_> =
        decode_object(SCHEMA_JOURNAL_ENTRY, SCHEMA_VERSION_1, &journal.entries[1]).unwrap();
    assert_eq!(entry.kind(), JournalKind::Record);
    assert_eq!(entry.record_hash(), &tracking);
    assert_eq!(entry.module_counters(), bound_entry.module_counters());
    assert_eq!(
        entry.prev_head(),
        &ityv_crypto::object_hash(&journal.entries[0])
    );
    assert_eq!(journal.packages[1].as_deref(), Some(package.as_slice()));
    let decision: JournalEntry<'_> =
        decode_object(SCHEMA_JOURNAL_ENTRY, SCHEMA_VERSION_1, &journal.entries[2]).unwrap();
    assert_eq!(decision.kind(), JournalKind::VisitDecision);
    assert_eq!(
        decision.record_hash(),
        &visit_digest(&[(JournalKind::Record.code(), tracking)])
    );
    assert!(decision.module_counters().is_empty());
    // the imprint entry names the record, repeats its counters and comes
    // before the paper drops
    let imprint_entry: JournalEntry<'_> =
        decode_object(SCHEMA_JOURNAL_ENTRY, SCHEMA_VERSION_1, &journal.entries[3]).unwrap();
    assert_eq!(imprint_entry.kind(), JournalKind::Imprinted);
    assert_eq!(imprint_entry.record_hash(), &tracking);
    assert_eq!(imprint_entry.module_counters(), entry.module_counters());
    assert_eq!(imprint_entry.time_bucket(), tb(11));
    assert_eq!(
        imprint_entry.prev_head(),
        &ityv_crypto::object_hash(&journal.entries[2])
    );
    assert_eq!(journal.packages[3], None);
    assert_eq!(
        box_.journal_head(),
        &ityv_crypto::object_hash(&journal.entries[3])
    );
    assert_eq!(box_.totals().records, 1);
    assert_eq!(box_.totals().visits, 1);
    assert_eq!(box_.module_counters(), &[1, 1, 1, 1, 1]);
    assert!(!box_.has_ballot_in_flight());
    assert!(!box_.has_visit_open());
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
    run_challenge_in(&world(profile, false), style, chunks, option);
}

fn run_challenge_in(w: &World, style: &[u8], chunks: usize, option: u16) {
    let profile = w.config.profile();
    let mut box_ = OpenBox::open(w.config, tb(1));
    let mut modules = mocks(w);
    let mut journal = MemJournal::default();
    let mut bufs = Buffers::new(w);
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
    let mut staging = MemStaging::default();
    let mut visit = visit_work();
    ballot
        .bind(&mut box_, &mut journal, &mut staging, &mut visit, tb(1))
        .unwrap();
    let ready = box_
        .end_visit(&visit_end(b"E-2026", 1), &mut visit)
        .unwrap();
    let mut package_buf = std::vec![0u8; 300_000];
    let mut decided = ready
        .decide(
            &mut box_,
            Decision::from_checks(1),
            &mut journal,
            &mut staging,
            &mut package_buf,
            tb(2),
        )
        .unwrap();
    assert_eq!(
        decided.imprint_command(&box_).err(),
        Some(Error::WrongPosition),
        "a checked ballot is never imprinted"
    );
    let mut out = std::vec![0u8; 8192];
    let opening = decided
        .open_challenge(&mut box_, signer(w), &mut out)
        .unwrap()
        .to_vec();
    let mut staged = std::vec![0u8; 30_000];
    assert_eq!(
        decided.record(&box_, &mut staging, 0, &mut staged).unwrap(),
        record.as_slice(),
        "the checked record is published too"
    );
    decided
        .finish_positions(&mut box_)
        .unwrap()
        .finish(&mut box_)
        .unwrap();
    assert!(visit.is_clear());
    assert_eq!(box_.totals().challenged, 1);
    assert_eq!(box_.totals().records, 0);
    let entry: JournalEntry<'_> =
        decode_object(SCHEMA_JOURNAL_ENTRY, SCHEMA_VERSION_1, &journal.entries[1]).unwrap();
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
    let shares = decrypt_package(w, &package);
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
            let got = reconstruct_secret(w, &shares, &qualified, index).unwrap();
            assert_eq!(got.to_bytes(), r.0);
            index += 1;
        }
    }
    let got = reconstruct_secret(w, &shares, &qualified, index).unwrap();
    assert_eq!(got.to_bytes(), cast_id.to_scalar().to_bytes());
    if profile == Profile::Absentee {
        let label = reconstruct_secret(w, &shares, &qualified, index + 1).unwrap();
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
    // Without both members (2-of-2) of any one party chamber, or with only
    // two of J, A, C, N (J's 1-of-2 dropped whole), the set is not
    // qualified (ADR-0019 §4).
    let parties: std::vec::Vec<ityv_crypto::Chamber> = ityv_crypto::Chamber::ALL
        .into_iter()
        .filter(|&c| c.is_party() && w.config.access().includes(c))
        .collect();
    assert_eq!(parties.len(), usize::from(w.config.access().parties()));
    for dropped in parties.into_iter().chain([ityv_crypto::Chamber::J]) {
        let unqualified: std::vec::Vec<usize> = qualified
            .iter()
            .copied()
            .filter(|&i| {
                let t = &w.trustees[i];
                t.chamber != dropped || (t.chamber.is_party() && t.member_index != 0)
            })
            .collect();
        assert!(
            reconstruct_secret(w, &shares, &unqualified, 0).is_err(),
            "{dropped:?}"
        );
    }
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
fn three_parties_challenge_reconstructs_every_secret() {
    let mut modules = MODULES.to_vec();
    modules.push(ModuleSpec {
        id: b"mod-p3",
        chamber: ityv_crypto::Chamber::P3,
        neutral: false,
    });
    let w = world_with(Profile::InPerson, false, &modules);
    assert_eq!(w.config.access().parties(), 3);
    assert_eq!(w.config.trustees().len(), 14);
    run_challenge_in(&w, STYLE_SMALL, 1, 2);
}

#[test]
fn four_parties_and_seven_modules_reconstruct_every_secret() {
    // the largest configuration: seven modules, eight chambers, and with
    // the two-chunk style and an envelope label 7·2 + 2 = 16 secrets
    let w = world_with(Profile::Absentee, false, &MODULES_FOUR_PARTIES);
    assert_eq!(w.config.access().parties(), 4);
    assert_eq!(w.config.modules().len(), MAX_MODULES);
    assert_eq!(w.config.trustees().len(), 16);
    let (_, style) = w
        .config
        .style(ityv_encoding::BallotStyleId::new(STYLE_WIDE).unwrap())
        .unwrap();
    assert_eq!(w.config.secret_count(style), 16);
    run_challenge_in(&w, STYLE_WIDE, 2, 7);
}

#[test]
fn absentee_challenge_reconstructs_the_envelope_label() {
    run_challenge(Profile::Absentee, STYLE_SMALL, 1, 0);
}

fn kinds(journal: &MemJournal) -> std::vec::Vec<JournalKind> {
    journal
        .entries
        .iter()
        .map(|e| {
            decode_object::<JournalEntry<'_>>(SCHEMA_JOURNAL_ENTRY, SCHEMA_VERSION_1, e)
                .unwrap()
                .kind()
        })
        .collect()
}

fn entry_at(journal: &MemJournal, index: usize) -> JournalEntry<'_> {
    decode_object(
        SCHEMA_JOURNAL_ENTRY,
        SCHEMA_VERSION_1,
        &journal.entries[index],
    )
    .unwrap()
}

/// `SHA3-512(label ‖ 0x00 ‖ parts)[0..24]`.
fn token(label: &[u8], parts: &[[u8; 24]]) -> [u8; 24] {
    let mut h = ityv_crypto::Sha3Hasher::new();
    h.absorb(label);
    h.absorb(&[0]);
    for part in parts {
        h.absorb(part);
    }
    h.finish()[..24].try_into().unwrap()
}

#[test]
fn a_visit_binds_every_position_before_the_decision() {
    // three ballots: cast, checked, cast (VC-068, VC-069)
    let w = world(Profile::InPerson, true);
    let mut box_ = OpenBox::open(w.config, tb(1));
    let mut modules = mocks(&w);
    let mut journal = MemJournal::default();
    let mut staging = MemStaging::default();
    let mut visit = visit_work();
    let ballots: [(&[u8], u16); 3] = [(STYLE_SMALL, 1), (STYLE_WIDE, 9), (STYLE_SMALL, 3)];
    let mut codes = std::vec::Vec::new();
    for (i, &(style, option)) in ballots.iter().enumerate() {
        let bound = build_position(
            &w,
            &mut box_,
            &mut modules,
            &mut journal,
            &mut staging,
            &mut visit,
            (style, option),
        );
        assert_eq!(usize::from(bound.position()), i);
        codes.push(*bound.tracking_code());
        // each record is signed by the device and every module before the
        // decision, and staged with its package
        let mut record = std::vec![0u8; 30_000];
        let len = ityv_cunit::StagingPort::fetch(
            &mut staging,
            bound.position(),
            ityv_cunit::Staged::Record,
            &mut record,
        )
        .unwrap();
        verify_cast_record(&w, &modules, &record[..len], bound.tracking_code());
        for m in &modules {
            assert_eq!(
                m.signed.len(),
                i + 1,
                "{:?} signed every record so far",
                m.id
            );
        }
    }
    // each position's bound entry is durable before the next comes
    assert_eq!(kinds(&journal), [JournalKind::Bound; 3]);
    assert_eq!((journal.deferred, journal.syncs), (0, 3));
    for (i, code) in codes.iter().enumerate() {
        assert_eq!(entry_at(&journal, i).record_hash(), code);
    }
    assert!(box_.has_visit_open());
    // a scan count, a batch and the close wait for the visit
    let mut small = std::vec![0u8; 512];
    assert_eq!(
        box_.scan_count_body(tb(1), &mut small).unwrap_err(),
        Error::VisitOpen
    );
    let ready = box_
        .end_visit(&visit_end(b"E-2026", 3), &mut visit)
        .unwrap();
    assert_eq!(ready.positions(&box_), 3);
    let styles: std::vec::Vec<&[u8]> = (0..3)
        .map(|i| ready.style(&box_, i).unwrap().id().as_bytes())
        .collect();
    assert_eq!(styles, [STYLE_SMALL, STYLE_WIDE, STYLE_SMALL]);
    assert!(ready.style(&box_, 3).is_none());
    let mut package = std::vec![0u8; 300_000];
    let mut decided = ready
        .decide(
            &mut box_,
            Decision::checking(&[1]).unwrap(),
            &mut journal,
            &mut staging,
            &mut package,
            tb(2),
        )
        .unwrap();
    // the positions' decision entries in order, then the decision; one
    // fsync
    assert_eq!(
        kinds(&journal)[3..],
        [
            JournalKind::Record,
            JournalKind::Challenge,
            JournalKind::Record,
            JournalKind::VisitDecision
        ]
    );
    assert_eq!((journal.deferred, journal.syncs), (3, 4));
    let digest = visit_digest(&[
        (JournalKind::Record.code(), codes[0]),
        (JournalKind::Challenge.code(), codes[1]),
        (JournalKind::Record.code(), codes[2]),
    ]);
    assert_eq!(entry_at(&journal, 6).record_hash(), &digest);
    assert!(entry_at(&journal, 6).module_counters().is_empty());
    for i in 0..3 {
        assert_eq!(
            entry_at(&journal, 3 + i).module_counters(),
            entry_at(&journal, i).module_counters(),
            "a decision entry repeats its bound entry's counters"
        );
    }
    assert!(
        journal.packages[4].is_none(),
        "a checked position has no package"
    );
    assert_eq!(
        (
            box_.totals().records,
            box_.totals().challenged,
            box_.totals().visits
        ),
        (2, 1, 1)
    );
    assert_eq!(box_.batch_records(), 2);
    // processing in position order
    assert_eq!(decided.current(&box_), Some((0, Choice::Cast)));
    let mut out = std::vec![0u8; 8192];
    assert_eq!(
        decided
            .open_challenge(&mut box_, signer(&w), &mut out)
            .unwrap_err(),
        Error::WrongPosition
    );
    let first = decided.imprint_command(&box_).unwrap();
    assert_eq!(
        first.cast_id(),
        &token(
            b"ityv:castid:v1",
            &modules
                .iter()
                .map(|m| m.issued[0].cid)
                .collect::<std::vec::Vec<_>>()
        )
    );
    decided.imprinted(&mut box_, &mut journal, tb(2)).unwrap();
    assert_eq!(decided.current(&box_), Some((1, Choice::Check)));
    assert_eq!(
        decided.imprint_command(&box_).err(),
        Some(Error::WrongPosition)
    );
    assert_eq!(
        decided
            .imprinted(&mut box_, &mut journal, tb(2))
            .unwrap_err(),
        Error::WrongPosition
    );
    assert_eq!(
        decided
            .imprint_failed(&mut box_, &mut journal, tb(2))
            .unwrap_err(),
        Error::WrongPosition
    );
    let opening = decided
        .open_challenge(&mut box_, signer(&w), &mut out)
        .unwrap()
        .to_vec();
    let parsed: ChallengeOpening<'_> =
        decode_object(SCHEMA_CHALLENGE_OPENING, SCHEMA_VERSION_1, &opening).unwrap();
    assert_eq!(parsed.body().record_hash(), &codes[1]);
    assert_eq!(parsed.body().option_index(), 9);
    for (opened, m) in parsed.body().modules().zip(&modules) {
        assert_eq!(opened.counter, m.issued[1].counter);
        assert_eq!(opened.cid.0, m.issued[1].cid);
    }
    let third = decided.imprint_command(&box_).unwrap();
    assert_ne!(third.cast_id(), first.cast_id());
    let early = std::vec![0u8; 0];
    drop(early);
    decided.imprinted(&mut box_, &mut journal, tb(2)).unwrap();
    assert_eq!(decided.current(&box_), None);
    assert_eq!(
        decided.imprint_command(&box_).err(),
        Some(Error::WrongPosition)
    );
    let mut processed = decided.finish_positions(&mut box_).unwrap();
    assert_eq!(processed.label_command(&box_).err(), Some(Error::NoLabel));
    assert_eq!(
        processed
            .label_printed(&mut box_, &mut journal, tb(2))
            .unwrap_err(),
        Error::NoLabel
    );
    assert_eq!(
        processed
            .label_failed(&mut box_, &mut journal, tb(2))
            .unwrap_err(),
        Error::NoLabel
    );
    // one slip for the visit: the cast codes in position order (VC-070)
    let mut slip_out = std::vec![0u8; ityv_cunit::ballot::MAX_SLIP_LEN];
    let slip_bytes = processed
        .slip(&box_, signer(&w), tb(2), &mut slip_out)
        .unwrap()
        .to_vec();
    let slip: ityv_encoding::Slip<'_> =
        decode_object(ityv_encoding::SCHEMA_SLIP, SCHEMA_VERSION_1, &slip_bytes).unwrap();
    assert_eq!(slip.body().tracking_codes(), &[codes[0], codes[2]]);
    assert_eq!(slip.body().station_id().as_bytes(), b"ST-1");
    let sig = ityv_crypto::HybridSignature::decode(&mut Reader::new(slip.device_sig())).unwrap();
    let _ = verify_hybrid(
        &w.device_hybrid.verifying_key(),
        &Purpose::new(b"slip").unwrap(),
        slip.body_bytes(),
        &sig,
    )
    .unwrap();
    // every record, cast or checked, is published from the staging store
    let mut record = std::vec![0u8; 30_000];
    for i in 0..3u8 {
        let bytes = processed
            .record(&box_, &mut staging, i, &mut record)
            .unwrap();
        let parsed: CastRecord<'_> =
            decode_object(SCHEMA_CAST_RECORD, SCHEMA_VERSION_1, bytes).unwrap();
        assert_eq!(
            &ityv_crypto::object_hash(parsed.body_bytes()),
            &codes[usize::from(i)]
        );
    }
    processed.finish(&mut box_).unwrap();
    assert!(visit.is_clear());
    assert!(!box_.has_visit_open());
    assert_eq!(
        kinds(&journal)[7..],
        [JournalKind::Imprinted, JournalKind::Imprinted]
    );
    // the visit is over: a scan count is allowed again
    assert!(box_.scan_count_body(tb(2), &mut small).is_ok());
}

#[test]
fn a_bound_record_cannot_change_after_the_decision() {
    // VC-068: each module keeps the body hash it signed for a counter and
    // refuses any other body for that counter
    let w = world(Profile::InPerson, false);
    let mut box_ = OpenBox::open(w.config, tb(1));
    let mut modules = mocks(&w);
    let mut journal = MemJournal::default();
    let mut staging = MemStaging::default();
    let mut visit = visit_work();
    let bound = build_position(
        &w,
        &mut box_,
        &mut modules,
        &mut journal,
        &mut staging,
        &mut visit,
        (STYLE_SMALL, 1),
    );
    for m in &mut modules {
        let counter = m.issued[0].counter;
        let signed = m.signed[&counter];
        assert_eq!(&signed, &bound.tracking_code().0);
        let message = |hash: [u8; 64]| {
            let mut out = std::vec![0u8; 140];
            let mut wr = Writer::new(&mut out);
            ityv_encoding::Hash512(hash).encode(&mut wr).unwrap();
            ityv_encoding::ModuleId::new(m.id)
                .unwrap()
                .encode(&mut wr)
                .unwrap();
            wr.write_u64(counter).unwrap();
            let len = wr.finish();
            out.truncate(len);
            out
        };
        let other = message([9; 64]);
        assert_eq!(
            ityv_cunit::ModulePort::sign_record(m, &other).unwrap_err(),
            ityv_cunit::PortError::Refused
        );
        // the same body again is harmless
        assert!(ityv_cunit::ModulePort::sign_record(m, &message(signed)).is_ok());
    }
}

#[test]
fn an_absentee_visit_prints_one_sticker_with_every_label() {
    let w = world(Profile::Absentee, true);
    let mut box_ = OpenBox::open(w.config, tb(1));
    let mut modules = mocks(&w);
    let mut journal = MemJournal::default();
    let mut staging = MemStaging::default();
    let mut visit = visit_work();
    for option in [1u16, 2, 3] {
        build_position(
            &w,
            &mut box_,
            &mut modules,
            &mut journal,
            &mut staging,
            &mut visit,
            (STYLE_SMALL, option),
        );
    }
    let ready = box_
        .end_visit(&visit_end(b"E-2026", 3), &mut visit)
        .unwrap();
    let mut package = std::vec![0u8; 300_000];
    let mut decided = ready
        .decide(
            &mut box_,
            Decision::checking(&[1]).unwrap(),
            &mut journal,
            &mut staging,
            &mut package,
            tb(1),
        )
        .unwrap();
    decided.imprinted(&mut box_, &mut journal, tb(1)).unwrap();
    let mut out = std::vec![0u8; 8192];
    decided
        .open_challenge(&mut box_, signer(&w), &mut out)
        .unwrap();
    decided.imprinted(&mut box_, &mut journal, tb(1)).unwrap();
    let mut processed = decided.finish_positions(&mut box_).unwrap();
    // the slip waits for the sticker, and so does the end of the visit
    let mut slip_out = std::vec![0u8; ityv_cunit::ballot::MAX_SLIP_LEN];
    assert_eq!(
        processed
            .slip(&box_, signer(&w), tb(1), &mut slip_out)
            .unwrap_err(),
        Error::LabelPending
    );
    let label = processed.label_command(&box_).unwrap();
    let expected: std::vec::Vec<[u8; 24]> = [0usize, 2]
        .iter()
        .map(|&i| {
            let labs: std::vec::Vec<[u8; 24]> =
                modules.iter().map(|m| m.issued[i].lab.unwrap()).collect();
            token(b"ityv:envlabel:v1", &labs)
        })
        .collect();
    assert_eq!(label.labels(), expected.as_slice());
    assert_eq!(format!("{label:?}"), "LabelCommand(..)");
    processed
        .label_printed(&mut box_, &mut journal, tb(1))
        .unwrap();
    assert_eq!(processed.label_command(&box_).err(), Some(Error::NoLabel));
    let last = entry_at(&journal, journal.entries.len() - 1);
    assert_eq!(last.kind(), JournalKind::LabelPrinted);
    let decision = (0..journal.entries.len())
        .map(|i| entry_at(&journal, i))
        .find(|e| e.kind() == JournalKind::VisitDecision)
        .unwrap();
    assert_eq!(last.record_hash(), decision.record_hash());
    assert!(last.module_counters().is_empty());
    assert!(
        processed
            .slip(&box_, signer(&w), tb(1), &mut slip_out)
            .is_ok()
    );
    processed.finish(&mut box_).unwrap();
    assert_eq!(
        kinds(&journal),
        [
            JournalKind::Bound,
            JournalKind::Bound,
            JournalKind::Bound,
            JournalKind::Record,
            JournalKind::Challenge,
            JournalKind::Record,
            JournalKind::VisitDecision,
            JournalKind::Imprinted,
            JournalKind::Imprinted,
            JournalKind::LabelPrinted
        ]
    );
    assert_eq!(box_.totals().visits, 1);
}

#[test]
fn a_failed_sticker_quarantines_the_visits_cast_records() {
    let w = world(Profile::Absentee, false);
    let mut box_ = OpenBox::open(w.config, tb(1));
    let mut modules = mocks(&w);
    let mut journal = MemJournal::default();
    let mut staging = MemStaging::default();
    let mut visit = visit_work();
    for option in [1u16, 2] {
        build_position(
            &w,
            &mut box_,
            &mut modules,
            &mut journal,
            &mut staging,
            &mut visit,
            (STYLE_SMALL, option),
        );
    }
    let ready = box_
        .end_visit(&visit_end(b"E-2026", 2), &mut visit)
        .unwrap();
    let mut package = std::vec![0u8; 300_000];
    let mut decided = ready
        .decide(
            &mut box_,
            Decision::CAST_ALL,
            &mut journal,
            &mut staging,
            &mut package,
            tb(1),
        )
        .unwrap();
    decided.imprinted(&mut box_, &mut journal, tb(1)).unwrap();
    // the second imprint fails: that record is quarantined, the first stays
    decided
        .imprint_failed(&mut box_, &mut journal, tb(1))
        .unwrap();
    assert_eq!((box_.totals().records, box_.totals().quarantined), (1, 1));
    let mut processed = decided.finish_positions(&mut box_).unwrap();
    assert_eq!(processed.label_command(&box_).unwrap().labels().len(), 1);
    // the sticker printer failed: the labels cannot be printed again
    processed
        .label_failed(&mut box_, &mut journal, tb(1))
        .unwrap();
    assert_eq!(
        (
            box_.totals().records,
            box_.totals().quarantined,
            box_.totals().visits
        ),
        (0, 2, 0)
    );
    assert_eq!(processed.label_command(&box_).err(), Some(Error::NoLabel));
    processed.finish(&mut box_).unwrap();
    assert_eq!(
        kinds(&journal),
        [
            JournalKind::Bound,
            JournalKind::Bound,
            JournalKind::Record,
            JournalKind::Record,
            JournalKind::VisitDecision,
            JournalKind::Imprinted,
            JournalKind::Quarantine,
            JournalKind::Quarantine
        ]
    );
    // a visit cannot end while its sticker is owed; the host abandons it,
    // which quarantines its cast records
    let mut visit = visit_work();
    build_position(
        &w,
        &mut box_,
        &mut modules,
        &mut journal,
        &mut staging,
        &mut visit,
        (STYLE_SMALL, 1),
    );
    let ready = box_
        .end_visit(&visit_end(b"E-2026", 1), &mut visit)
        .unwrap();
    let mut decided = ready
        .decide(
            &mut box_,
            Decision::CAST_ALL,
            &mut journal,
            &mut staging,
            &mut package,
            tb(1),
        )
        .unwrap();
    decided.imprinted(&mut box_, &mut journal, tb(1)).unwrap();
    let processed = decided.finish_positions(&mut box_).unwrap();
    assert_eq!(
        processed.finish(&mut box_).unwrap_err(),
        Error::LabelPending
    );
    assert!(visit.is_clear(), "the work area is wiped anyway");
    assert!(box_.has_visit_open());
    box_.abandon_visit(&mut journal, tb(1)).unwrap();
    assert!(!box_.has_visit_open());
    assert_eq!(
        (
            box_.totals().records,
            box_.totals().quarantined,
            box_.totals().visits
        ),
        (0, 3, 0)
    );
}

#[test]
fn exhausted_pad_falls_back_to_the_kem_and_sets_bit_zero() {
    let w = world(Profile::InPerson, false);
    let mut box_ = OpenBox::open(w.config, tb(1));
    let mut modules = mocks(&w);
    modules[3].exhaust_member = Some(1); // mod-p1, member 1
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
    cast_built(&mut box_, &mut journal, ballot);
    let rec: CastRecord<'_> = decode_object(SCHEMA_CAST_RECORD, SCHEMA_VERSION_1, &record).unwrap();
    assert_eq!(
        rec.body().transport_flags(),
        TRANSPORT_NEUTRAL_MODULE | TRANSPORT_KEM_FALLBACK
    );
    let pkg: SharePackage<'_> =
        decode_object(SCHEMA_SHARE_PACKAGE, SCHEMA_VERSION_1, &package).unwrap();
    for (entry, trustee) in pkg.entries().zip(&w.trustees) {
        let expect_kem = trustee.chamber == ityv_crypto::Chamber::N
            || (trustee.chamber == ityv_crypto::Chamber::P1 && trustee.member_index == 1)
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
fn slip_needs_the_voter_code_scope_and_a_cast_ballot() {
    let w = world(Profile::InPerson, false);
    let mut box_ = OpenBox::open(w.config, tb(1));
    let mut modules = mocks(&w);
    let mut journal = MemJournal::default();
    let mut staging = MemStaging::default();
    let mut visit = visit_work();
    build_position(
        &w,
        &mut box_,
        &mut modules,
        &mut journal,
        &mut staging,
        &mut visit,
        (STYLE_SMALL, 1),
    );
    let ready = box_
        .end_visit(&visit_end(b"E-2026", 1), &mut visit)
        .unwrap();
    let mut package = std::vec![0u8; 300_000];
    let mut decided = ready
        .decide(
            &mut box_,
            Decision::CAST_ALL,
            &mut journal,
            &mut staging,
            &mut package,
            tb(3),
        )
        .unwrap();
    decided.imprinted(&mut box_, &mut journal, tb(3)).unwrap();
    let processed = decided.finish_positions(&mut box_).unwrap();
    let mut out = std::vec![0u8; ityv_cunit::ballot::MAX_SLIP_LEN];
    assert_eq!(
        processed
            .slip(&box_, signer(&w), tb(3), &mut out)
            .unwrap_err(),
        Error::VoterCodeDisabled
    );
    processed.finish(&mut box_).unwrap();
    // a visit whose ballots were all checked has no slip
    let w = world(Profile::InPerson, true);
    let mut box_ = OpenBox::open(w.config, tb(1));
    let mut modules = mocks(&w);
    let mut visit = visit_work();
    build_position(
        &w,
        &mut box_,
        &mut modules,
        &mut journal,
        &mut staging,
        &mut visit,
        (STYLE_SMALL, 1),
    );
    let ready = box_
        .end_visit(&visit_end(b"E-2026", 1), &mut visit)
        .unwrap();
    let mut decided = ready
        .decide(
            &mut box_,
            Decision::from_checks(1),
            &mut journal,
            &mut staging,
            &mut package,
            tb(3),
        )
        .unwrap();
    let mut opening = std::vec![0u8; 8192];
    decided
        .open_challenge(&mut box_, signer(&w), &mut opening)
        .unwrap();
    let processed = decided.finish_positions(&mut box_).unwrap();
    assert_eq!(
        processed
            .slip(&box_, signer(&w), tb(3), &mut out)
            .unwrap_err(),
        Error::NothingCast
    );
    processed.finish(&mut box_).unwrap();
    assert_eq!(
        box_.totals().visits,
        0,
        "a visit without a cast ballot is not counted"
    );
    // a cast ballot whose imprint failed is quarantined and left off the slip
    let mut visit = visit_work();
    let codes: std::vec::Vec<ityv_encoding::Hash512> = [1, 2]
        .into_iter()
        .map(|option| {
            *build_position(
                &w,
                &mut box_,
                &mut modules,
                &mut journal,
                &mut staging,
                &mut visit,
                (STYLE_SMALL, option),
            )
            .tracking_code()
        })
        .collect();
    let ready = box_
        .end_visit(&visit_end(b"E-2026", 2), &mut visit)
        .unwrap();
    let mut decided = ready
        .decide(
            &mut box_,
            Decision::CAST_ALL,
            &mut journal,
            &mut staging,
            &mut package,
            tb(3),
        )
        .unwrap();
    decided
        .imprint_failed(&mut box_, &mut journal, tb(3))
        .unwrap();
    decided.imprinted(&mut box_, &mut journal, tb(3)).unwrap();
    let processed = decided.finish_positions(&mut box_).unwrap();
    let slip_bytes = processed
        .slip(&box_, signer(&w), tb(3), &mut out)
        .unwrap()
        .to_vec();
    let slip: ityv_encoding::Slip<'_> =
        decode_object(ityv_encoding::SCHEMA_SLIP, SCHEMA_VERSION_1, &slip_bytes).unwrap();
    assert_eq!(slip.body().tracking_codes(), &[codes[1]]);
    processed.finish(&mut box_).unwrap();
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
    cast_built(box_, journal, ballot);
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
        if member.chamber() != ityv_crypto::Chamber::P1 {
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
    box_.abandon_visit(&mut journal, tb(1)).unwrap();
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
    box_.abandon_visit(&mut journal, tb(1)).unwrap();
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
fn the_work_areas_are_wiped_at_every_exit() {
    let w = world(Profile::Absentee, false);
    let mut box_ = OpenBox::open(w.config, tb(1));
    let mut modules = mocks(&w);
    let mut journal = MemJournal::default();
    let mut staging = MemStaging::default();
    let mut package = std::vec![0u8; 300_000];
    let mut area = work();
    // a ballot value dropped mid-way wipes the ballot work area
    let ballot = box_
        .interpret(&interpretation(b"E-2026", STYLE_SMALL, 2), &mut area)
        .unwrap();
    let ballot = ballot
        .issue(&mut box_, &mut ports(&mut modules), &SEED)
        .unwrap();
    let ballot = ballot.commit(&box_).unwrap();
    drop(ballot);
    assert!(area.is_clear());
    box_.abandon_visit(&mut journal, tb(1)).unwrap();
    // a failed bind (the staging store fails) wipes it too
    let mut visit = visit_work();
    let mut bufs = Buffers::new(&w);
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
    staging.fail = true;
    assert_eq!(
        ballot
            .bind(&mut box_, &mut journal, &mut staging, &mut visit, tb(1))
            .unwrap_err(),
        Error::Port(ityv_cunit::PortError::Transport)
    );
    staging.fail = false;
    assert!(area.is_clear());
    box_.abandon_visit(&mut journal, tb(1)).unwrap();
    // a ready visit dropped without a decision
    build_position(
        &w,
        &mut box_,
        &mut modules,
        &mut journal,
        &mut staging,
        &mut visit,
        (STYLE_SMALL, 1),
    );
    assert!(!visit.is_clear());
    let ready = box_
        .end_visit(&visit_end(b"E-2026", 1), &mut visit)
        .unwrap();
    assert!(format!("{ready:?}").starts_with("ReadyVisit"));
    drop(ready);
    assert!(visit.is_clear());
    box_.abandon_visit(&mut journal, tb(1)).unwrap();
    // a failed decision
    build_position(
        &w,
        &mut box_,
        &mut modules,
        &mut journal,
        &mut staging,
        &mut visit,
        (STYLE_SMALL, 1),
    );
    let ready = box_
        .end_visit(&visit_end(b"E-2026", 1), &mut visit)
        .unwrap();
    journal.fail = true;
    assert!(
        ready
            .decide(
                &mut box_,
                Decision::CAST_ALL,
                &mut journal,
                &mut staging,
                &mut package,
                tb(1)
            )
            .is_err()
    );
    journal.fail = false;
    assert!(visit.is_clear());
    box_.abandon_visit(&mut journal, tb(1)).unwrap();
    // a decided visit dropped mid-way
    build_position(
        &w,
        &mut box_,
        &mut modules,
        &mut journal,
        &mut staging,
        &mut visit,
        (STYLE_SMALL, 1),
    );
    let ready = box_
        .end_visit(&visit_end(b"E-2026", 1), &mut visit)
        .unwrap();
    let decided = ready
        .decide(
            &mut box_,
            Decision::CAST_ALL,
            &mut journal,
            &mut staging,
            &mut package,
            tb(1),
        )
        .unwrap();
    assert!(format!("{decided:?}").starts_with("DecidedVisit"));
    drop(decided);
    assert!(visit.is_clear());
    box_.abandon_visit(&mut journal, tb(1)).unwrap();
    // a processed visit
    build_position(
        &w,
        &mut box_,
        &mut modules,
        &mut journal,
        &mut staging,
        &mut visit,
        (STYLE_SMALL, 1),
    );
    let ready = box_
        .end_visit(&visit_end(b"E-2026", 1), &mut visit)
        .unwrap();
    let mut decided = ready
        .decide(
            &mut box_,
            Decision::CAST_ALL,
            &mut journal,
            &mut staging,
            &mut package,
            tb(1),
        )
        .unwrap();
    decided.imprinted(&mut box_, &mut journal, tb(1)).unwrap();
    let mut processed = decided.finish_positions(&mut box_).unwrap();
    assert!(format!("{processed:?}").starts_with("ProcessedVisit"));
    processed
        .label_printed(&mut box_, &mut journal, tb(1))
        .unwrap();
    processed.finish(&mut box_).unwrap();
    assert!(visit.is_clear());
    assert!(area.is_clear());
}
