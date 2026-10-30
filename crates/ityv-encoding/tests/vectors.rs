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

use common::{encode_to_vec, hex, kind_from_name, unhex};
use ityv_encoding::{
    CheckpointBody, CheckpointParts, Day, ElectionId, Encode, Hash512, KeysetId, LedgerFrame,
    LedgerId, LegalAuthorizationBody, SCHEMA_CHECKPOINT_BODY, SCHEMA_LEDGER_FRAME,
    SCHEMA_LEGAL_AUTHORIZATION, SCHEMA_VERSION_1, SchemaId, Scope, ScopeSet, Seq, TimeBucket,
    TreeSize, decode_object,
};
use std::string::String;
use std::vec::Vec;

fn patterned(seed: u8) -> Hash512 {
    let mut h = [0u8; 64];
    for (i, b) in h.iter_mut().enumerate() {
        *b = seed.wrapping_add(u8::try_from(i).unwrap());
    }
    Hash512(h)
}

struct Vector {
    label: &'static str,
    bytes: Vec<u8>,
    expected: Option<(&'static str, usize)>,
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

fn render(title: &str, schema: SchemaId, vectors: &[Vector]) -> String {
    use core::fmt::Write as _;
    let mut out = String::new();
    // Writing to a String cannot fail, so the results are discarded.
    let _ = writeln!(
        out,
        "# ityv-encoding test vectors: {title} (schema_id 0x{:04x}, version {SCHEMA_VERSION_1})",
        schema.get()
    );
    let _ = writeln!(out, "# VALID <label> <hex>");
    let _ = writeln!(out, "# INVALID <ErrorKind> <offset> <label> <hex>");
    for v in vectors {
        let label = v.label.replace(' ', "_");
        let _ = match v.expected {
            None => writeln!(out, "VALID {label} {}", hex(&v.bytes)),
            Some((kind, offset)) => {
                writeln!(out, "INVALID {kind} {offset} {label} {}", hex(&v.bytes))
            }
        };
    }
    out
}

fn check_file(name: &str, content: &str) {
    let path = std::format!("{}/vectors/{name}", env!("CARGO_MANIFEST_DIR"));
    if std::env::var_os("ITYV_UPDATE_VECTORS").is_some() {
        std::fs::write(&path, content).unwrap();
        return;
    }
    let on_disk = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!("missing vector file {path}: {e}; run with ITYV_UPDATE_VECTORS=1")
    });
    assert_eq!(
        on_disk, content,
        "vector file {name} is stale; run with ITYV_UPDATE_VECTORS=1"
    );
}

/// Re-reads a rendered file and checks every line against the decoder, the
/// way an independent implementation would.
fn self_check<F>(content: &str, decode_and_reencode: F)
where
    F: Fn(&[u8]) -> Result<Vec<u8>, ityv_encoding::Error>,
{
    for line in content.lines().filter(|l| !l.starts_with('#')) {
        let fields: Vec<&str> = line.split(' ').collect();
        match fields.first().copied() {
            Some("VALID") => {
                let bytes = unhex(fields[2]);
                let re = decode_and_reencode(&bytes).unwrap_or_else(|e| panic!("{line}: {e}"));
                assert_eq!(re, bytes, "{line}");
            }
            Some("INVALID") => {
                let kind = kind_from_name(fields[1]);
                let offset: usize = fields[2].parse().unwrap();
                let bytes = unhex(fields[4]);
                let e = decode_and_reencode(&bytes).expect_err(line);
                assert_eq!((e.kind(), e.offset()), (kind, offset), "{line}");
            }
            _ => panic!("unexpected line: {line}"),
        }
    }
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
