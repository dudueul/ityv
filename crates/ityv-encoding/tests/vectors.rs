//! Golden test vectors (ENCODING.md §7).
//!
//! The files under `vectors/` are the published, implementation-independent
//! vectors. This test regenerates them from fixed inputs and fails if the
//! checked-in files differ. Set `ITYV_UPDATE_VECTORS=1` to rewrite them.
//! Every `VALID` line must decode and re-encode byte-identically; every
//! `INVALID` line must fail with the stated kind at the stated offset.
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

use common::{Vector, check_file, encode_to_vec, render, self_check};
use ityv_encoding::{
    CheckpointBody, CheckpointParts, Day, ElectionId, Encode, Hash512, KeysetId, LedgerFrame,
    LedgerId, LegalAuthorizationBody, SCHEMA_CHECKPOINT_BODY, SCHEMA_LEDGER_FRAME,
    SCHEMA_LEGAL_AUTHORIZATION, SCHEMA_SIGNED_LEGAL_AUTHORIZATION, SCHEMA_VERSION_1, SchemaId,
    Scope, ScopeSet, Seq, SignedLegalAuthorization, TimeBucket, TreeSize, decode_object,
};
use std::vec::Vec;

fn patterned(seed: u8) -> Hash512 {
    let mut h = [0u8; 64];
    for (i, b) in h.iter_mut().enumerate() {
        *b = seed.wrapping_add(u8::try_from(i).unwrap());
    }
    Hash512(h)
}

fn ledger_frame_vectors() -> Vec<Vector> {
    let frame = LedgerFrame::new(
        ElectionId::new(b"KR-2030-PRES").unwrap(),
        Seq::new(1).unwrap(),
        Hash512::ZERO,
        SchemaId::new(0x0005),
        patterned(0x10),
    );
    let valid = encode_to_vec(SCHEMA_LEDGER_FRAME, SCHEMA_VERSION_1, &frame);
    let frame2 = LedgerFrame::new(
        ElectionId::new(b"E").unwrap(),
        Seq::new(0xffff_ffff_ffff_ffff).unwrap(),
        patterned(0x20),
        SchemaId::new(0xffff_ffff),
        patterned(0x30),
    );
    let valid2 = encode_to_vec(SCHEMA_LEDGER_FRAME, SCHEMA_VERSION_1, &frame2);
    let mut v = std::vec![
        Vector {
            label: "minimal first frame",
            bytes: valid.clone(),
            expected: None
        },
        Vector {
            label: "maximal values",
            bytes: valid2,
            expected: None
        },
    ];
    let mut bad_magic = valid.clone();
    bad_magic[0] = b'X';
    v.push(Vector {
        label: "bad magic",
        bytes: bad_magic,
        expected: Some(("BadMagic", 0)),
    });
    let mut flags = valid.clone();
    flags[10] = 0x80;
    v.push(Vector {
        label: "non-zero flags",
        bytes: flags,
        expected: Some(("NonZeroFlags", 10)),
    });
    let mut trailing = valid.clone();
    trailing.push(0);
    v.push(Vector {
        label: "body length mismatch",
        bytes: trailing,
        expected: Some(("BodyLengthMismatch", 12)),
    });
    let mut zero_seq = valid.clone();
    zero_seq[32..40].copy_from_slice(&[0; 8]);
    v.push(Vector {
        label: "zero seq",
        bytes: zero_seq,
        expected: Some(("ValueOutOfRange", 32)),
    });
    let mut bad_ident = valid.clone();
    bad_ident[22] = b' ';
    v.push(Vector {
        label: "space in ident",
        bytes: bad_ident,
        expected: Some(("InvalidIdentByte", 22)),
    });
    let mut empty_ident = valid.clone();
    empty_ident[16..20].copy_from_slice(&[0; 4]);
    v.push(Vector {
        label: "empty ident",
        bytes: empty_ident,
        expected: Some(("EmptyIdent", 16)),
    });
    let truncated = valid[..valid.len() - 1].to_vec();
    v.push(Vector {
        label: "truncated",
        bytes: truncated,
        expected: Some(("BodyLengthMismatch", 12)),
    });
    let mut lying = valid.clone();
    lying[15] = lying[15].wrapping_sub(1);
    v.push(Vector {
        label: "body_len one short",
        bytes: lying,
        expected: Some(("BodyLengthMismatch", 12)),
    });
    v
}

fn authorization_vectors() -> Vec<Vector> {
    let body = LegalAuthorizationBody::new(
        ElectionId::new(b"KR-2030-PRES").unwrap(),
        ScopeSet::from_slice(&[Scope::PublicBoard, Scope::TrusteeBody, Scope::BallotMark]),
        patterned(0x40),
        Day::new(20_000),
        Day::new(20_030),
    )
    .unwrap();
    let valid = encode_to_vec(SCHEMA_LEGAL_AUTHORIZATION, SCHEMA_VERSION_1, &body);
    let all = LegalAuthorizationBody::new(
        ElectionId::new(b"KR-2030-PRES").unwrap(),
        ScopeSet::from_slice(&Scope::ALL),
        patterned(0x41),
        Day::new(0),
        Day::new(0),
    )
    .unwrap();
    let none = LegalAuthorizationBody::new(
        ElectionId::new(b"KR-2030-PRES").unwrap(),
        ScopeSet::empty(),
        patterned(0x42),
        Day::new(1),
        Day::new(u64::MAX),
    )
    .unwrap();
    let mut v = std::vec![
        Vector {
            label: "stage 0-2 scopes",
            bytes: valid.clone(),
            expected: None
        },
        Vector {
            label: "all scopes",
            bytes: encode_to_vec(SCHEMA_LEGAL_AUTHORIZATION, SCHEMA_VERSION_1, &all),
            expected: None
        },
        Vector {
            label: "no scopes",
            bytes: encode_to_vec(SCHEMA_LEGAL_AUTHORIZATION, SCHEMA_VERSION_1, &none),
            expected: None
        },
    ];
    // scopes count at 32, codes at 36..39, statute hash at 39, from at 103, until at 111.
    let mut unknown = valid.clone();
    unknown[38] = 10;
    v.push(Vector {
        label: "unknown scope code",
        bytes: unknown,
        expected: Some(("InvalidScopeCode", 38)),
    });
    let mut duplicate = valid.clone();
    duplicate[38] = 2;
    v.push(Vector {
        label: "duplicate scope",
        bytes: duplicate,
        expected: Some(("Duplicate", 38)),
    });
    let mut unsorted = valid.clone();
    unsorted[36] = 3;
    unsorted[38] = 1;
    v.push(Vector {
        label: "unsorted scopes",
        bytes: unsorted,
        expected: Some(("NotSorted", 37)),
    });
    let mut count = valid.clone();
    count[32..36].copy_from_slice(&17u32.to_be_bytes());
    v.push(Vector {
        label: "count above max",
        bytes: count,
        expected: Some(("CountExceedsMax", 32)),
    });
    let mut days = valid.clone();
    days[111..119].copy_from_slice(&19_999u64.to_be_bytes());
    v.push(Vector {
        label: "until before from",
        bytes: days,
        expected: Some(("ValueOutOfRange", 111)),
    });
    let mut wrong_schema = valid.clone();
    wrong_schema[4..8].copy_from_slice(&1u32.to_be_bytes());
    v.push(Vector {
        label: "schema mismatch",
        bytes: wrong_schema,
        expected: Some(("SchemaMismatch", 4)),
    });
    let mut version = valid.clone();
    version[8..10].copy_from_slice(&2u16.to_be_bytes());
    v.push(Vector {
        label: "unsupported version",
        bytes: version,
        expected: Some(("UnsupportedVersion", 8)),
    });
    v
}

fn checkpoint_vectors() -> Vec<Vector> {
    let make = |seq: u64, previous: Hash512| {
        CheckpointBody::new(&CheckpointParts {
            election_id: ElectionId::new(b"KR-2030-PRES").unwrap(),
            ledger_id: LedgerId::new(b"ledger.main").unwrap(),
            keyset_id: KeysetId::new(b"witness-keyset-2030-01").unwrap(),
            checkpoint_seq: Seq::new(seq).unwrap(),
            tree_size: TreeSize::new(44_000_000),
            root_hash: patterned(0x50),
            previous_checkpoint_hash: previous,
            box_close_root: patterned(0x60),
            dispute_root: patterned(0x70),
            genesis_hash: patterned(0x80),
            time_bucket: TimeBucket::new(1_000),
        })
        .unwrap()
    };
    let first = encode_to_vec(
        SCHEMA_CHECKPOINT_BODY,
        SCHEMA_VERSION_1,
        &make(1, Hash512::ZERO),
    );
    let later = encode_to_vec(
        SCHEMA_CHECKPOINT_BODY,
        SCHEMA_VERSION_1,
        &make(2, patterned(0x90)),
    );
    let mut v = std::vec![
        Vector {
            label: "first checkpoint",
            bytes: first.clone(),
            expected: None
        },
        Vector {
            label: "second checkpoint",
            bytes: later.clone(),
            expected: None
        },
    ];
    // header 16, election 16, ledger 15, keyset 26 -> seq at 73, tree 81, root 89, previous 153.
    let mut nonzero_first = first.clone();
    nonzero_first[153] = 1;
    v.push(Vector {
        label: "first with non-zero previous",
        bytes: nonzero_first,
        expected: Some(("InvalidPreviousHash", 153)),
    });
    let mut zero_later = later.clone();
    zero_later[153..217].copy_from_slice(&[0; 64]);
    v.push(Vector {
        label: "later with zero previous",
        bytes: zero_later,
        expected: Some(("InvalidPreviousHash", 153)),
    });
    let mut zero_seq = first.clone();
    zero_seq[73..81].copy_from_slice(&[0; 8]);
    v.push(Vector {
        label: "zero seq",
        bytes: zero_seq,
        expected: Some(("ValueOutOfRange", 73)),
    });
    v
}

#[test]
fn ledger_frame_vectors_are_current_and_self_consistent() {
    let content = render("LedgerFrame", SCHEMA_LEDGER_FRAME, &ledger_frame_vectors());
    check_file("ledger_frame.txt", &content);
    self_check(&content, |b| {
        let v: LedgerFrame<'_> = decode_object(SCHEMA_LEDGER_FRAME, SCHEMA_VERSION_1, b)?;
        let _ = v.encoded_len();
        Ok(encode_to_vec(SCHEMA_LEDGER_FRAME, SCHEMA_VERSION_1, &v))
    });
}

#[test]
fn authorization_vectors_are_current_and_self_consistent() {
    let content = render(
        "LegalAuthorization",
        SCHEMA_LEGAL_AUTHORIZATION,
        &authorization_vectors(),
    );
    check_file("legal_authorization.txt", &content);
    self_check(&content, |b| {
        let v: LegalAuthorizationBody<'_> =
            decode_object(SCHEMA_LEGAL_AUTHORIZATION, SCHEMA_VERSION_1, b)?;
        Ok(encode_to_vec(
            SCHEMA_LEGAL_AUTHORIZATION,
            SCHEMA_VERSION_1,
            &v,
        ))
    });
}

fn signed_authorization_vectors() -> Vec<Vector> {
    let body = authorization_vectors().remove(0).bytes;
    let commission = [0x31u8; 4691];
    let committee = [0x32u8; 4691];
    let signed = SignedLegalAuthorization::new(&body, &commission, &committee).unwrap();
    let valid = encode_to_vec(SCHEMA_SIGNED_LEGAL_AUTHORIZATION, SCHEMA_VERSION_1, &signed);
    let mut v = std::vec![Vector {
        label: "two signatures over a stage 0-2 body",
        bytes: valid.clone(),
        expected: None,
    }];
    // header 16, body length 4, then the embedded body object: its schema
    // identifier sits 4 bytes into its own header.
    let mut other_schema = valid.clone();
    other_schema[24..26].copy_from_slice(&0x0004u16.to_be_bytes());
    v.push(Vector {
        label: "embedded object of another schema",
        bytes: other_schema,
        expected: Some(("SchemaMismatch", 24)),
    });
    let mut too_long = valid;
    too_long[16..20].copy_from_slice(&513u32.to_be_bytes());
    v.push(Vector {
        label: "embedded body longer than 512 bytes",
        bytes: too_long,
        expected: Some(("LengthExceedsMax", 16)),
    });
    v
}

#[test]
fn signed_authorization_vectors_are_current_and_self_consistent() {
    let content = render(
        "SignedLegalAuthorization",
        SCHEMA_SIGNED_LEGAL_AUTHORIZATION,
        &signed_authorization_vectors(),
    );
    check_file("signed_legal_authorization.txt", &content);
    self_check(&content, |b| {
        let v: SignedLegalAuthorization<'_> =
            decode_object(SCHEMA_SIGNED_LEGAL_AUTHORIZATION, SCHEMA_VERSION_1, b)?;
        Ok(encode_to_vec(
            SCHEMA_SIGNED_LEGAL_AUTHORIZATION,
            SCHEMA_VERSION_1,
            &v,
        ))
    });
    let v = &signed_authorization_vectors()[0].bytes;
    let decoded: SignedLegalAuthorization<'_> =
        decode_object(SCHEMA_SIGNED_LEGAL_AUTHORIZATION, SCHEMA_VERSION_1, v).unwrap();
    assert_eq!(
        decoded.body_bytes(),
        authorization_vectors()[0].bytes.as_slice()
    );
    assert_eq!(decoded.commission_sig(), &[0x31u8; 4691]);
    assert_eq!(decoded.committee_sig(), &[0x32u8; 4691]);
    assert_eq!(decoded.body().election_id().as_bytes(), b"KR-2030-PRES");
    assert_eq!(decoded.encoded_len() + 16, v.len());
    // The constructor applies the same rules as the decoder.
    let body = &authorization_vectors()[0].bytes;
    let long = std::vec![0u8; 513];
    assert_eq!(
        SignedLegalAuthorization::new(&long, &[0; 4691], &[0; 4691])
            .unwrap_err()
            .kind(),
        ityv_encoding::ErrorKind::LengthExceedsMax
    );
    assert!(
        SignedLegalAuthorization::new(&body[..body.len() - 1], &[0; 4691], &[0; 4691]).is_err()
    );
}

#[test]
fn checkpoint_vectors_are_current_and_self_consistent() {
    let content = render(
        "CheckpointBody",
        SCHEMA_CHECKPOINT_BODY,
        &checkpoint_vectors(),
    );
    check_file("checkpoint_body.txt", &content);
    self_check(&content, |b| {
        let v: CheckpointBody<'_> = decode_object(SCHEMA_CHECKPOINT_BODY, SCHEMA_VERSION_1, b)?;
        Ok(encode_to_vec(SCHEMA_CHECKPOINT_BODY, SCHEMA_VERSION_1, &v))
    });
}

// ---------------------------------------------------------------------------
// The participation ledger and its key ceremonies (ENCODING.md §8.25, §8.31,
// §8.32): `ParticipationSet` 0x0020, `ModuleProvisioned` 0x0026,
// `PartyKeyCeremony` 0x0027.
// ---------------------------------------------------------------------------

mod participation {
    use super::common::{Vector, check_file, encode_to_vec, render, self_check};
    use ityv_encoding::{
        ActorSig, ChamberCode, ElectionId, Encode, HEADER_LEN, HYBRID_SIG_LEN, Hash512, Ident,
        KEM_EK_LEN, ModuleId, ModuleProvisioned, ModuleProvisionedMessage, ModuleProvisionedParts,
        ParticipationMessage, ParticipationModuleSig, ParticipationSet, PartyKeyCeremony,
        PartyKeyMessage, PartyKeyParts, Pseudonyms, SCHEMA_MODULE_PROVISIONED,
        SCHEMA_PARTICIPATION_SET, SCHEMA_PARTY_KEY_CEREMONY, SCHEMA_VERSION_1, ShareHolder,
        StationId, TimeBucket, TrusteeId, Writer, decode_object,
    };
    use std::vec::Vec;

    const E: &[u8] = b"KR-2030-PRES";
    static SIG_A: [u8; HYBRID_SIG_LEN] = [0xA1; HYBRID_SIG_LEN];
    static SIG_B: [u8; HYBRID_SIG_LEN] = [0xB2; HYBRID_SIG_LEN];
    static SIG_C: [u8; HYBRID_SIG_LEN] = [0xC3; HYBRID_SIG_LEN];
    static SIG_D: [u8; HYBRID_SIG_LEN] = [0xD4; HYBRID_SIG_LEN];
    static SIG_E: [u8; HYBRID_SIG_LEN] = [0xE5; HYBRID_SIG_LEN];
    static KEM: [u8; KEM_EK_LEN] = [0x6B; KEM_EK_LEN];
    static PRF: [u8; 32] = [0x7C; 32];

    fn e() -> ElectionId<'static> {
        ElectionId::new(E).unwrap()
    }

    fn id(bytes: &'static [u8]) -> Ident<'static> {
        Ident::new(bytes, 64).unwrap()
    }

    fn valid(label: &'static str, bytes: Vec<u8>) -> Vector {
        Vector {
            label,
            bytes,
            expected: None,
        }
    }

    fn invalid(label: &'static str, bytes: Vec<u8>, kind: &'static str, offset: usize) -> Vector {
        Vector {
            label,
            bytes,
            expected: Some((kind, offset)),
        }
    }

    /// A field group's encoding, without an object header.
    fn group<T: Encode>(value: &T) -> Vec<u8> {
        let mut out = std::vec![0u8; value.encoded_len()];
        let mut w = Writer::new(&mut out);
        value.encode(&mut w).unwrap();
        assert_eq!(w.finish(), out.len());
        out
    }

    fn leak(v: Vec<u8>) -> &'static [u8] {
        Vec::leak(v)
    }

    // --- ParticipationSet ---------------------------------------------------

    /// Three pseudonyms, the second repeated (a double vote stays visible).
    fn pseudonym_bytes() -> &'static [u8] {
        let mut out = Vec::new();
        for fill in [0x10u8, 0x20, 0x20] {
            out.extend_from_slice(&[fill; 64]);
        }
        leak(out)
    }

    fn participation(pseudonyms: &'static [u8], modules: usize) -> Vec<u8> {
        let message = ParticipationMessage {
            election_id: e(),
            station_id: StationId::new(b"ST-0001").unwrap(),
            pseudonyms: Pseudonyms::new(pseudonyms).unwrap(),
        };
        let message = leak(group(&message));
        let sigs = [
            ParticipationModuleSig {
                module_id: ModuleId::new(b"M-P1").unwrap(),
                sig: &SIG_B,
            },
            ParticipationModuleSig {
                module_id: ModuleId::new(b"M-P2").unwrap(),
                sig: &SIG_C,
            },
        ];
        let set = ParticipationSet::new(message, &SIG_A, &sigs[..modules]).unwrap();
        encode_to_vec(SCHEMA_PARTICIPATION_SET, SCHEMA_VERSION_1, &set)
    }

    // Offsets in the three-pseudonym set: header 16, election 4 + 12,
    // station 4 + 7, then `count`, the array count and the pseudonyms.
    const COUNT_AT: usize = HEADER_LEN + 16 + 11;
    const ARRAY_AT: usize = COUNT_AT + 4;
    const FIRST_AT: usize = ARRAY_AT + 4;
    const SIGS_AT: usize = FIRST_AT + 3 * 64 + HYBRID_SIG_LEN;

    fn participation_vectors() -> Vec<Vector> {
        let set = participation(pseudonym_bytes(), 2);
        let mut v = std::vec![
            valid("two_parties_three_pseudonyms_one_repeated", set.clone()),
            valid("no_pseudonyms", participation(leak(Vec::new()), 2)),
        ];
        let mut count = set.clone();
        count[COUNT_AT..COUNT_AT + 4].copy_from_slice(&2u32.to_be_bytes());
        v.push(invalid(
            "count_not_the_number_of_pseudonyms",
            count,
            "InvariantViolation",
            ARRAY_AT,
        ));
        let mut big = set.clone();
        big[COUNT_AT..COUNT_AT + 4].copy_from_slice(&65_537u32.to_be_bytes());
        v.push(invalid(
            "count_above_65536",
            big,
            "ValueOutOfRange",
            COUNT_AT,
        ));
        let mut descending = set.clone();
        descending[FIRST_AT + 64] = 0x01;
        v.push(invalid(
            "pseudonyms_descending",
            descending,
            "NotSorted",
            FIRST_AT + 64,
        ));
        let mut five = set.clone();
        five[SIGS_AT..SIGS_AT + 4].copy_from_slice(&5u32.to_be_bytes());
        v.push(invalid(
            "five_module_signatures",
            five,
            "CountExceedsMax",
            SIGS_AT,
        ));
        // The second module identifier `M-P2` becomes `M-P1`.
        let second = SIGS_AT + 4 + 8 + HYBRID_SIG_LEN;
        let mut twice = set;
        twice[second + 7] = b'1';
        v.push(invalid(
            "one_module_signs_twice",
            twice,
            "Duplicate",
            second,
        ));
        v
    }

    // --- ModuleProvisioned --------------------------------------------------

    fn provisioned_parts(
        chamber: ChamberCode,
        prf: Option<&'static [u8; 32]>,
    ) -> ModuleProvisionedParts<'static> {
        ModuleProvisionedParts {
            election_id: e(),
            module_id: ModuleId::new(b"M-U1A-P1").unwrap(),
            device_id: id(b"U-1A"),
            chamber,
            member_count: 2,
            pad_length: 1_048_576,
            chassis_id: id(b"CH-0007"),
            pad_card_id: id(b"PAD-0007"),
            reprovision_count: 3,
            chassis_check_hash: Hash512([0x4C; 64]),
            kem_ek: &KEM,
            entropy_commitment: Hash512([0x5D; 64]),
            se_present: prf.is_some(),
            prf_key_check: prf,
        }
    }

    fn actors() -> [ActorSig<'static>; 4] {
        [
            ActorSig {
                actor_id: id(b"T-P1-1"),
                sig: &SIG_A,
            },
            ActorSig {
                actor_id: id(b"committee"),
                sig: &SIG_B,
            },
            ActorSig {
                actor_id: id(b"obs-a"),
                sig: &SIG_C,
            },
            ActorSig {
                actor_id: id(b"obs-b"),
                sig: &SIG_D,
            },
        ]
    }

    fn provisioned(parts: &ModuleProvisionedParts<'static>) -> Vec<u8> {
        let message = leak(group(&ModuleProvisionedMessage::new(parts).unwrap()));
        let record = ModuleProvisioned::new(message, &actors()).unwrap();
        encode_to_vec(SCHEMA_MODULE_PROVISIONED, SCHEMA_VERSION_1, &record)
    }

    // Offsets: header 16, election 16, module 4 + 8, device 4 + 4, then
    // `chamber` and `member_count`; `se_present` and `prf_key_check` after
    // pad length 8, chassis 4 + 7, card 4 + 8, reprovisions 4, chassis
    // check 64, KEM key 1600, entropy commitment 64.
    const CHAMBER_AT: usize = HEADER_LEN + 16 + 12 + 8;
    const MEMBERS_AT: usize = CHAMBER_AT + 1;
    const SE_AT: usize = MEMBERS_AT + 1 + 8 + 11 + 12 + 4 + 64 + KEM_EK_LEN + 64;
    const PRF_AT: usize = SE_AT + 1;

    fn provisioned_vectors() -> Vec<Vector> {
        let party = provisioned(&provisioned_parts(ChamberCode::P1, Some(&PRF)));
        let box_module = provisioned(&provisioned_parts(ChamberCode::J, None));
        let mut v = std::vec![
            valid("checkin_party_module_with_key_check", party.clone()),
            valid("box_module_without_key_check", box_module.clone()),
        ];
        let mut n = box_module.clone();
        n[CHAMBER_AT] = 8;
        v.push(invalid(
            "chamber_n_has_no_module",
            n,
            "ValueOutOfRange",
            CHAMBER_AT,
        ));
        let mut zero_members = box_module.clone();
        zero_members[MEMBERS_AT] = 0;
        v.push(invalid(
            "no_members",
            zero_members,
            "ValueOutOfRange",
            MEMBERS_AT,
        ));
        let mut nine_members = box_module.clone();
        nine_members[MEMBERS_AT] = 9;
        v.push(invalid(
            "nine_members",
            nine_members,
            "ValueOutOfRange",
            MEMBERS_AT,
        ));
        let mut not_bool = box_module;
        not_bool[SE_AT] = 2;
        v.push(invalid(
            "se_present_not_a_bool",
            not_bool,
            "InvalidBool",
            SE_AT,
        ));
        let mut judge = party.clone();
        judge[CHAMBER_AT] = 5;
        v.push(invalid(
            "key_check_on_a_judiciary_module",
            judge,
            "InvariantViolation",
            PRF_AT,
        ));
        let mut no_se = party.clone();
        no_se[SE_AT] = 0;
        v.push(invalid(
            "key_check_without_secure_element",
            no_se,
            "InvariantViolation",
            PRF_AT,
        ));
        // The second actor `committee` becomes `Aommittee`, below the
        // first (`T-P1-1`).
        let sigs_at = PRF_AT + 1 + 32;
        let second = sigs_at + 4 + 4 + 6 + HYBRID_SIG_LEN;
        let mut order = party.clone();
        order[second + 4] = b'A';
        v.push(invalid("actors_not_ascending", order, "NotSorted", second));
        // The third actor `obs-a` becomes `obs-b`, equal to the fourth.
        let third = second + 4 + 9 + HYBRID_SIG_LEN;
        let fourth = third + 4 + 5 + HYBRID_SIG_LEN;
        let mut twice = party;
        twice[third + 4 + 4] = b'b';
        v.push(invalid("actor_signs_twice", twice, "Duplicate", fourth));
        v
    }

    // --- PartyKeyCeremony ---------------------------------------------------

    fn holders() -> [ShareHolder<'static>; 3] {
        [
            ShareHolder {
                trustee_id: TrusteeId::new(b"T-P1-1").unwrap(),
                hsm_model: id(b"YubiHSM2"),
                hsm_serial_hash: Hash512([0x81; 64]),
            },
            ShareHolder {
                trustee_id: TrusteeId::new(b"T-P1-2").unwrap(),
                hsm_model: id(b"NitrokeyHSM2"),
                hsm_serial_hash: Hash512([0x82; 64]),
            },
            ShareHolder {
                trustee_id: TrusteeId::new(b"T-P1-3").unwrap(),
                hsm_model: id(b"SmartCard-HSM"),
                hsm_serial_hash: Hash512([0x83; 64]),
            },
        ]
    }

    fn ceremony() -> Vec<u8> {
        let holders = holders();
        let message = PartyKeyMessage::new(&PartyKeyParts {
            election_id: e(),
            chamber: ChamberCode::P1,
            wrapped_module_count: 37_420,
            share_threshold: 2,
            share_holders: &holders,
            prf_key_check: &PRF,
            time_bucket: TimeBucket::new(1_900_000),
        })
        .unwrap();
        let message = leak(group(&message));
        let sigs = [
            ActorSig {
                actor_id: id(b"T-P1-1"),
                sig: &SIG_A,
            },
            ActorSig {
                actor_id: id(b"T-P1-2"),
                sig: &SIG_B,
            },
            ActorSig {
                actor_id: id(b"committee"),
                sig: &SIG_C,
            },
            ActorSig {
                actor_id: id(b"obs-a"),
                sig: &SIG_D,
            },
            ActorSig {
                actor_id: id(b"obs-b"),
                sig: &SIG_E,
            },
        ];
        let record = PartyKeyCeremony::new(message, &sigs).unwrap();
        encode_to_vec(SCHEMA_PARTY_KEY_CEREMONY, SCHEMA_VERSION_1, &record)
    }

    // Offsets: header 16, election 16, `chamber`, wrapped count 4, then
    // `share_threshold`, `share_count` and the holders.
    const PARTY_AT: usize = HEADER_LEN + 16;
    const THRESHOLD_AT: usize = PARTY_AT + 1 + 4;
    const SHARES_AT: usize = THRESHOLD_AT + 1;
    const HOLDERS_AT: usize = SHARES_AT + 1;

    fn ceremony_vectors() -> Vec<Vector> {
        let ok = ceremony();
        let mut v = std::vec![valid("two_of_three_party_key", ok.clone())];
        let mut judge = ok.clone();
        judge[PARTY_AT] = 5;
        v.push(invalid(
            "not_a_party_chamber",
            judge,
            "ValueOutOfRange",
            PARTY_AT,
        ));
        let mut zero = ok.clone();
        zero[THRESHOLD_AT] = 0;
        v.push(invalid(
            "threshold_zero",
            zero,
            "ValueOutOfRange",
            THRESHOLD_AT,
        ));
        let mut above = ok.clone();
        above[THRESHOLD_AT] = 4;
        v.push(invalid(
            "threshold_above_count",
            above,
            "ValueOutOfRange",
            SHARES_AT,
        ));
        let mut nine = ok.clone();
        nine[SHARES_AT] = 9;
        v.push(invalid("nine_shares", nine, "ValueOutOfRange", SHARES_AT));
        let mut fewer = ok.clone();
        fewer[SHARES_AT] = 2;
        v.push(invalid(
            "holders_not_share_count",
            fewer,
            "InvariantViolation",
            HOLDERS_AT,
        ));
        // The second holder `T-P1-2` becomes `T-P1-0`.
        let second = HOLDERS_AT + 4 + 10 + 12 + 64;
        let mut order = ok;
        order[second + 4 + 5] = b'0';
        v.push(invalid("holders_not_ascending", order, "NotSorted", second));
        v
    }

    #[test]
    fn participation_set_vectors_are_current_and_self_consistent() {
        let content = render(
            "ParticipationSet",
            SCHEMA_PARTICIPATION_SET,
            &participation_vectors(),
        );
        check_file("participation_set.txt", &content);
        self_check(&content, |b| {
            let v: ParticipationSet<'_> =
                decode_object(SCHEMA_PARTICIPATION_SET, SCHEMA_VERSION_1, b)?;
            Ok(encode_to_vec(
                SCHEMA_PARTICIPATION_SET,
                SCHEMA_VERSION_1,
                &v,
            ))
        });
    }

    #[test]
    fn module_provisioned_vectors_are_current_and_self_consistent() {
        let content = render(
            "ModuleProvisioned",
            SCHEMA_MODULE_PROVISIONED,
            &provisioned_vectors(),
        );
        check_file("module_provisioned.txt", &content);
        self_check(&content, |b| {
            let v: ModuleProvisioned<'_> =
                decode_object(SCHEMA_MODULE_PROVISIONED, SCHEMA_VERSION_1, b)?;
            Ok(encode_to_vec(
                SCHEMA_MODULE_PROVISIONED,
                SCHEMA_VERSION_1,
                &v,
            ))
        });
    }

    #[test]
    fn party_key_ceremony_vectors_are_current_and_self_consistent() {
        let content = render(
            "PartyKeyCeremony",
            SCHEMA_PARTY_KEY_CEREMONY,
            &ceremony_vectors(),
        );
        check_file("party_key_ceremony.txt", &content);
        self_check(&content, |b| {
            let v: PartyKeyCeremony<'_> =
                decode_object(SCHEMA_PARTY_KEY_CEREMONY, SCHEMA_VERSION_1, b)?;
            Ok(encode_to_vec(
                SCHEMA_PARTY_KEY_CEREMONY,
                SCHEMA_VERSION_1,
                &v,
            ))
        });
    }

    /// The decoders keep each signed field group exactly as the signers
    /// encoded it, header-less (ENCODING.md §4).
    #[test]
    fn signed_field_groups_are_the_message_bytes() {
        let set = participation(pseudonym_bytes(), 2);
        let decoded: ParticipationSet<'_> =
            decode_object(SCHEMA_PARTICIPATION_SET, SCHEMA_VERSION_1, &set).unwrap();
        assert_eq!(
            decoded.message_bytes(),
            &set[HEADER_LEN..SIGS_AT - HYBRID_SIG_LEN]
        );
        assert_eq!(group(decoded.message()), decoded.message_bytes());
        assert_eq!(decoded.count(), 3);
        assert_eq!(decoded.pseudonyms().len(), 3);
        assert_eq!(decoded.counter_sig(), &SIG_A);
        let ids: Vec<&[u8]> = decoded
            .module_sigs()
            .map(|s| s.module_id.as_bytes())
            .collect();
        assert_eq!(ids, [b"M-P1".as_slice(), b"M-P2"]);

        let record = provisioned(&provisioned_parts(ChamberCode::P1, Some(&PRF)));
        let decoded: ModuleProvisioned<'_> =
            decode_object(SCHEMA_MODULE_PROVISIONED, SCHEMA_VERSION_1, &record).unwrap();
        assert_eq!(decoded.message_bytes(), &record[HEADER_LEN..PRF_AT + 33]);
        assert_eq!(decoded.parts().prf_key_check, Some(&PRF));
        assert_eq!(decoded.signatures().len(), 4);

        let record = ceremony();
        let decoded: PartyKeyCeremony<'_> =
            decode_object(SCHEMA_PARTY_KEY_CEREMONY, SCHEMA_VERSION_1, &record).unwrap();
        let end = record.len() - decoded.signatures().encoded_len();
        assert_eq!(decoded.message_bytes(), &record[HEADER_LEN..end]);
        assert_eq!(group(decoded.message()), decoded.message_bytes());
        assert_eq!(decoded.message().share_count(), 3);
    }
}

// ---------------------------------------------------------------------------
// The tally (ENCODING.md §8.61–§8.64): `TallyScopeBody` 0x0043,
// `AggregateOpeningBody` 0x0044, `QuorumSigned` 0x0045,
// `PaperCountReportBody` 0x0046.
// ---------------------------------------------------------------------------

mod tally {
    use super::common::{Vector, check_file, encode_to_vec, render, self_check};
    use ityv_encoding::{
        AggregateOpeningBody, AggregateOpeningParts, BallotStyleId, BoxId, ElectionId, Encode,
        ExclusionEntry, ExclusionReason, Exclusions, HEADER_LEN, HYBRID_SIG_LEN, Hash512,
        MAX_TALLY_COUNT, PaperCountParts, PaperCountReportBody, PaperVotes, QuorumSig,
        QuorumSigned, RECEIPT_ENTRY_LEN, ReceiptEntries, ReceiptEntry, ReceiptOutcome,
        ReceiptResolutionBody, ReceiptResolutionParts, ReportingUnitId,
        SCHEMA_AGGREGATE_OPENING_BODY, SCHEMA_PAPER_COUNT_REPORT_BODY, SCHEMA_QUORUM_SIGNED,
        SCHEMA_RECEIPT_RESOLUTION_BODY, SCHEMA_TALLY_SCOPE_BODY, SCHEMA_VERSION_1, Scalar32,
        TallyScopeBody, TallyScopeParts, TimeBucket, TrusteeId, Writer, decode_object,
    };
    use std::vec::Vec;

    static SIG_A: [u8; HYBRID_SIG_LEN] = [0xA1; HYBRID_SIG_LEN];
    static SIG_B: [u8; HYBRID_SIG_LEN] = [0xB2; HYBRID_SIG_LEN];

    fn e() -> ElectionId<'static> {
        ElectionId::new(b"KR-2030-PRES").unwrap()
    }

    fn style() -> BallotStyleId<'static> {
        BallotStyleId::new(b"S-11-0001").unwrap()
    }

    fn unit() -> ReportingUnitId<'static> {
        ReportingUnitId::new(b"RU-11-01").unwrap()
    }

    fn valid(label: &'static str, bytes: Vec<u8>) -> Vector {
        Vector {
            label,
            bytes,
            expected: None,
        }
    }

    fn invalid(label: &'static str, bytes: Vec<u8>, kind: &'static str, offset: usize) -> Vector {
        Vector {
            label,
            bytes,
            expected: Some((kind, offset)),
        }
    }

    fn leak(v: Vec<u8>) -> &'static [u8] {
        Vec::leak(v)
    }

    fn fix_len(v: &mut [u8]) {
        let body_len = u32::try_from(v.len() - HEADER_LEN).unwrap();
        v[12..16].copy_from_slice(&body_len.to_be_bytes());
    }

    /// The encoding of `entries`, one after another.
    fn entries(entries: &[ExclusionEntry]) -> &'static [u8] {
        let mut out = std::vec![0u8; entries.len() * 129];
        let mut w = Writer::new(&mut out);
        for entry in entries {
            entry.encode(&mut w).unwrap();
        }
        leak(out)
    }

    fn scope(exclusions: &'static [u8], included: u64) -> Vec<u8> {
        let body = TallyScopeBody::new(&TallyScopeParts {
            election_id: e(),
            ballot_style_id: style(),
            reporting_unit_id: unit(),
            included_count: included,
            included_root: super::patterned(0x30),
            no_record_count: 1,
            exclusions: Exclusions::new(exclusions).unwrap(),
            time_bucket: TimeBucket::new(2_000),
        })
        .unwrap();
        encode_to_vec(SCHEMA_TALLY_SCOPE_BODY, SCHEMA_VERSION_1, &body)
    }

    fn two_exclusions() -> &'static [u8] {
        entries(&[
            ExclusionEntry {
                record_hash: Hash512([0x10; 64]),
                reason: ExclusionReason::TestBallot,
                basis: super::patterned(0x40),
            },
            ExclusionEntry {
                record_hash: Hash512([0x20; 64]),
                reason: ExclusionReason::Unattested,
                basis: super::patterned(0x41),
            },
        ])
    }

    // Offsets: header 16, election 4 + 12, style 4 + 9, unit 4 + 8.
    const INCLUDED_AT: usize = HEADER_LEN + 16 + 13 + 12;
    const NO_RECORD_AT: usize = INCLUDED_AT + 8 + 64;
    const EXCLUSIONS_AT: usize = NO_RECORD_AT + 8;
    const FIRST_AT: usize = EXCLUSIONS_AT + 4;
    const SECOND_AT: usize = FIRST_AT + 129;

    fn scope_vectors() -> Vec<Vector> {
        let ok = scope(two_exclusions(), 3);
        let mut v = std::vec![
            valid("three_included_two_excluded", ok.clone()),
            valid("nothing_excluded", scope(leak(Vec::new()), 0)),
        ];
        let mut b = ok.clone();
        b[INCLUDED_AT..INCLUDED_AT + 8].copy_from_slice(&(MAX_TALLY_COUNT + 1).to_be_bytes());
        v.push(invalid(
            "included_count_above_2^26_-_1",
            b,
            "ValueOutOfRange",
            INCLUDED_AT,
        ));
        let mut b = ok.clone();
        b[NO_RECORD_AT..NO_RECORD_AT + 8].copy_from_slice(&(MAX_TALLY_COUNT + 1).to_be_bytes());
        v.push(invalid(
            "no_record_count_above_2^26_-_1",
            b,
            "ValueOutOfRange",
            NO_RECORD_AT,
        ));
        let mut b = ok.clone();
        b[EXCLUSIONS_AT..EXCLUSIONS_AT + 4].copy_from_slice(&65_537u32.to_be_bytes());
        v.push(invalid(
            "too_many_exclusions",
            b,
            "CountExceedsMax",
            EXCLUSIONS_AT,
        ));
        for (label, code) in [("reason_0", 0u8), ("reason_9", 9)] {
            let mut b = ok.clone();
            b[FIRST_AT + 64] = code;
            v.push(invalid(label, b, "ValueOutOfRange", FIRST_AT + 64));
        }
        let mut b = ok.clone();
        b[FIRST_AT + 65..FIRST_AT + 129].fill(0);
        v.push(invalid("no_basis", b, "InvalidPreviousHash", FIRST_AT + 65));
        let mut b = ok.clone();
        b[SECOND_AT..SECOND_AT + 64].fill(0x10);
        v.push(invalid("record_listed_twice", b, "Duplicate", SECOND_AT));
        let mut b = ok;
        b[SECOND_AT..SECOND_AT + 64].fill(0x05);
        v.push(invalid("records_not_ascending", b, "NotSorted", SECOND_AT));
        v
    }

    fn opening(chunk: u8) -> Vec<u8> {
        let body = AggregateOpeningBody::new(&AggregateOpeningParts {
            election_id: e(),
            ballot_style_id: style(),
            reporting_unit_id: unit(),
            scope_hash: super::patterned(0x50),
            chunk,
            packed_sum: Scalar32([0x01; 32]),
            rand_sum: Scalar32([0x02; 32]),
            id_sum: Scalar32([0x03; 32]),
            time_bucket: TimeBucket::new(2_100),
        })
        .unwrap();
        encode_to_vec(SCHEMA_AGGREGATE_OPENING_BODY, SCHEMA_VERSION_1, &body)
    }

    const SCOPE_AT: usize = HEADER_LEN + 16 + 13 + 12;
    const CHUNK_AT: usize = SCOPE_AT + 64;

    fn opening_vectors() -> Vec<Vector> {
        let ok = opening(0);
        let mut v = std::vec![
            valid("first_chunk", ok.clone()),
            valid("last_chunk", opening(7))
        ];
        let mut b = ok.clone();
        b[SCOPE_AT..SCOPE_AT + 64].fill(0);
        v.push(invalid("no_scope", b, "InvalidPreviousHash", SCOPE_AT));
        let mut b = ok;
        b[CHUNK_AT] = 8;
        v.push(invalid("chunk_8", b, "ValueOutOfRange", CHUNK_AT));
        v
    }

    fn receipt(list: &[(u8, ReceiptOutcome)]) -> Vec<u8> {
        let mut out = std::vec![0u8; list.len() * RECEIPT_ENTRY_LEN];
        let mut w = Writer::new(&mut out);
        for (fill, outcome) in list {
            ReceiptEntry {
                record_hash: Hash512([*fill; 64]),
                outcome: *outcome,
            }
            .encode(&mut w)
            .unwrap();
        }
        let body = ReceiptResolutionBody::new(&ReceiptResolutionParts {
            election_id: e(),
            box_id: BoxId::new(b"BOX-OUT-1").unwrap(),
            entries: ReceiptEntries::new(leak(out)).unwrap(),
            time_bucket: TimeBucket::new(1_900),
        });
        encode_to_vec(SCHEMA_RECEIPT_RESOLUTION_BODY, SCHEMA_VERSION_1, &body)
    }

    // Offsets: header 16, election 4 + 12, box 4 + 9, count 4.
    const RECEIPT_FIRST_AT: usize = HEADER_LEN + 16 + 13 + 4;
    const RECEIPT_SECOND_AT: usize = RECEIPT_FIRST_AT + RECEIPT_ENTRY_LEN;

    fn receipt_vectors() -> Vec<Vector> {
        let ok = receipt(&[
            (0x10, ReceiptOutcome::Received),
            (0x20, ReceiptOutcome::Damaged),
            (0x30, ReceiptOutcome::Late),
            (0x40, ReceiptOutcome::WrongDistrict),
            (0x50, ReceiptOutcome::NotReceived),
        ]);
        let mut v = std::vec![
            valid("every_outcome", ok.clone()),
            valid("empty_box", receipt(&[]))
        ];
        for (label, code) in [("outcome_0", 0u8), ("outcome_6", 6)] {
            let mut b = ok.clone();
            b[RECEIPT_FIRST_AT + 64] = code;
            v.push(invalid(label, b, "ValueOutOfRange", RECEIPT_FIRST_AT + 64));
        }
        let mut b = ok.clone();
        b[RECEIPT_SECOND_AT..RECEIPT_SECOND_AT + 64].fill(0x10);
        v.push(invalid(
            "record_listed_twice",
            b,
            "Duplicate",
            RECEIPT_SECOND_AT,
        ));
        let mut b = ok.clone();
        b[RECEIPT_SECOND_AT..RECEIPT_SECOND_AT + 64].fill(0x05);
        v.push(invalid(
            "records_not_ascending",
            b,
            "NotSorted",
            RECEIPT_SECOND_AT,
        ));
        let mut b = ok;
        b[RECEIPT_FIRST_AT - 4..RECEIPT_FIRST_AT].copy_from_slice(&65_537u32.to_be_bytes());
        v.push(invalid(
            "too_many_entries",
            b,
            "CountExceedsMax",
            RECEIPT_FIRST_AT - 4,
        ));
        v
    }

    fn sig(id: &'static [u8], sig: &'static [u8; HYBRID_SIG_LEN]) -> QuorumSig<'static> {
        QuorumSig {
            trustee_id: TrusteeId::new(id).unwrap(),
            sig,
        }
    }

    fn quorum(body: Vec<u8>) -> Vec<u8> {
        let body = leak(body);
        let sigs = [sig(b"T-A", &SIG_A), sig(b"T-J", &SIG_B)];
        let event = QuorumSigned::new(body, &sigs).unwrap();
        encode_to_vec(SCHEMA_QUORUM_SIGNED, SCHEMA_VERSION_1, &event)
    }

    fn paper(votes: &[u64]) -> Vec<u8> {
        let body = PaperCountReportBody::new(&PaperCountParts {
            election_id: e(),
            reporting_unit_id: unit(),
            ballot_style_id: style(),
            votes: PaperVotes::new(votes).unwrap(),
            invalid: 4,
            time_bucket: TimeBucket::new(2_200),
        })
        .unwrap();
        encode_to_vec(SCHEMA_PAPER_COUNT_REPORT_BODY, SCHEMA_VERSION_1, &body)
    }

    /// The object header of a `QuorumSigned`, body length still zero.
    fn quorum_header() -> Vec<u8> {
        let mut h = std::vec![0u8; HEADER_LEN];
        h[0..4].copy_from_slice(b"ITYV");
        h[4..8].copy_from_slice(&SCHEMA_QUORUM_SIGNED.get().to_be_bytes());
        h[8..10].copy_from_slice(&SCHEMA_VERSION_1.to_be_bytes());
        h
    }

    fn quorum_vectors() -> Vec<Vector> {
        let body_len = opening(0).len();
        let ok = quorum(opening(0));
        let count_at = HEADER_LEN + 4 + body_len;
        let second_at = count_at + 4 + 4 + 3 + HYBRID_SIG_LEN;
        let mut v = std::vec![
            valid("opening_two_trustees", ok.clone()),
            valid("scope_two_trustees", quorum(scope(two_exclusions(), 3))),
            valid(
                "receipt_resolution_two_trustees",
                quorum(receipt(&[(0x10, ReceiptOutcome::Received)]))
            ),
        ];
        let mut b = ok[..count_at].to_vec();
        b.extend_from_slice(&0u32.to_be_bytes());
        fix_len(&mut b);
        v.push(invalid("no_signature", b, "InvariantViolation", count_at));
        let mut b = ok.clone();
        b[count_at..count_at + 4].copy_from_slice(&65u32.to_be_bytes());
        v.push(invalid(
            "sixty_five_signatures",
            b,
            "CountExceedsMax",
            count_at,
        ));
        let mut b = ok.clone();
        b[second_at + 4 + 2] = b'A';
        v.push(invalid("trustee_twice", b, "Duplicate", second_at));
        let mut b = ok.clone();
        b[second_at + 4 + 2] = b'0';
        v.push(invalid("trustees_not_ascending", b, "NotSorted", second_at));
        let mut b = ok;
        b[HEADER_LEN + 4 + CHUNK_AT] = 8;
        v.push(invalid(
            "opening_of_chunk_8",
            b,
            "ValueOutOfRange",
            HEADER_LEN + 4 + CHUNK_AT,
        ));
        // A paper count report is not a body a quorum signs.
        let other = paper(&[1, 2]);
        let mut wrapped = quorum_header();
        wrapped.extend_from_slice(&u32::try_from(other.len()).unwrap().to_be_bytes());
        wrapped.extend_from_slice(&other);
        wrapped.extend_from_slice(&1u32.to_be_bytes());
        wrapped.extend_from_slice(&3u32.to_be_bytes());
        wrapped.extend_from_slice(b"T-A");
        wrapped.extend_from_slice(&SIG_A);
        fix_len(&mut wrapped);
        v.push(invalid(
            "paper_count_body",
            wrapped,
            "SchemaMismatch",
            HEADER_LEN + 4 + 4,
        ));
        v
    }

    // Offsets: header 16, election 4 + 12, unit 4 + 8, style 4 + 9.
    const VOTES_AT: usize = HEADER_LEN + 16 + 12 + 13;
    const FIRST_VOTE_AT: usize = VOTES_AT + 4;

    fn paper_vectors() -> Vec<Vector> {
        let ok = paper(&[120, 75, 3]);
        let invalid_at = FIRST_VOTE_AT + 3 * 8;
        let mut v = std::vec![
            valid("three_candidates", ok.clone()),
            valid("one_candidate", paper(&[0]))
        ];
        let mut b = ok[..VOTES_AT].to_vec();
        b.extend_from_slice(&0u32.to_be_bytes());
        b.extend_from_slice(&ok[invalid_at..]);
        fix_len(&mut b);
        v.push(invalid("no_candidate", b, "InvariantViolation", VOTES_AT));
        let mut b = ok.clone();
        b[VOTES_AT..VOTES_AT + 4].copy_from_slice(&71u32.to_be_bytes());
        v.push(invalid(
            "seventy_one_candidates",
            b,
            "CountExceedsMax",
            VOTES_AT,
        ));
        let mut b = ok.clone();
        b[FIRST_VOTE_AT..FIRST_VOTE_AT + 8].copy_from_slice(&(MAX_TALLY_COUNT + 1).to_be_bytes());
        v.push(invalid(
            "votes_above_2^26_-_1",
            b,
            "ValueOutOfRange",
            FIRST_VOTE_AT,
        ));
        let mut b = ok;
        b[invalid_at..invalid_at + 8].copy_from_slice(&(MAX_TALLY_COUNT + 1).to_be_bytes());
        v.push(invalid(
            "invalid_above_2^26_-_1",
            b,
            "ValueOutOfRange",
            invalid_at,
        ));
        v
    }

    #[test]
    fn tally_scope_vectors_are_current_and_self_consistent() {
        let content = render("TallyScopeBody", SCHEMA_TALLY_SCOPE_BODY, &scope_vectors());
        check_file("tally_scope_body.txt", &content);
        self_check(&content, |b| {
            let v: TallyScopeBody<'_> =
                decode_object(SCHEMA_TALLY_SCOPE_BODY, SCHEMA_VERSION_1, b)?;
            Ok(encode_to_vec(SCHEMA_TALLY_SCOPE_BODY, SCHEMA_VERSION_1, &v))
        });
    }

    #[test]
    fn aggregate_opening_vectors_are_current_and_self_consistent() {
        let content = render(
            "AggregateOpeningBody",
            SCHEMA_AGGREGATE_OPENING_BODY,
            &opening_vectors(),
        );
        check_file("aggregate_opening_body.txt", &content);
        self_check(&content, |b| {
            let v: AggregateOpeningBody<'_> =
                decode_object(SCHEMA_AGGREGATE_OPENING_BODY, SCHEMA_VERSION_1, b)?;
            Ok(encode_to_vec(
                SCHEMA_AGGREGATE_OPENING_BODY,
                SCHEMA_VERSION_1,
                &v,
            ))
        });
    }

    #[test]
    fn quorum_signed_vectors_are_current_and_self_consistent() {
        let content = render("QuorumSigned", SCHEMA_QUORUM_SIGNED, &quorum_vectors());
        check_file("quorum_signed.txt", &content);
        self_check(&content, |b| {
            let v: QuorumSigned<'_> = decode_object(SCHEMA_QUORUM_SIGNED, SCHEMA_VERSION_1, b)?;
            Ok(encode_to_vec(SCHEMA_QUORUM_SIGNED, SCHEMA_VERSION_1, &v))
        });
    }

    #[test]
    fn receipt_resolution_vectors_are_current_and_self_consistent() {
        let content = render(
            "ReceiptResolutionBody",
            SCHEMA_RECEIPT_RESOLUTION_BODY,
            &receipt_vectors(),
        );
        check_file("receipt_resolution_body.txt", &content);
        self_check(&content, |b| {
            let v: ReceiptResolutionBody<'_> =
                decode_object(SCHEMA_RECEIPT_RESOLUTION_BODY, SCHEMA_VERSION_1, b)?;
            Ok(encode_to_vec(
                SCHEMA_RECEIPT_RESOLUTION_BODY,
                SCHEMA_VERSION_1,
                &v,
            ))
        });
    }

    #[test]
    fn paper_count_report_vectors_are_current_and_self_consistent() {
        let content = render(
            "PaperCountReportBody",
            SCHEMA_PAPER_COUNT_REPORT_BODY,
            &paper_vectors(),
        );
        check_file("paper_count_report_body.txt", &content);
        self_check(&content, |b| {
            let v: PaperCountReportBody<'_> =
                decode_object(SCHEMA_PAPER_COUNT_REPORT_BODY, SCHEMA_VERSION_1, b)?;
            Ok(encode_to_vec(
                SCHEMA_PAPER_COUNT_REPORT_BODY,
                SCHEMA_VERSION_1,
                &v,
            ))
        });
    }
}
