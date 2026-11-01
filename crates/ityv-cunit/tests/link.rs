//! Link objects, interpretation and issue checks, configuration rules, the
//! generator and the pure counting rules.
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
    Buffers, MODULES, MemJournal, ModuleSpec, SEED, STYLE_SMALL, interpretation, mocks,
    module_config, ports, tb, work, world, world_with,
};
use ityv_crypto::{AccessStructure, Chamber, OptionCount, Threshold};
use ityv_cunit::boxstate::OpenBox;
use ityv_cunit::config::{
    BallotStyle, ConfigParts, ElectionConfig, ModuleConfig, Profile, TrusteeConfig, chamber_code,
    chamber_of,
};
use ityv_cunit::error::{ConfigFault, Invariant as I};
use ityv_cunit::link::{
    Interpretation, JournalEntry, JournalKind, MAX_INTERPRETATION_LEN, MAX_JOURNAL_ENTRY_LEN,
    MAX_MODULE_ISSUE_LEN, ModuleIssue, ModuleIssueParts, SCHEMA_INTERPRETATION,
    SCHEMA_JOURNAL_ENTRY, SCHEMA_MODULE_ISSUE,
};
use ityv_cunit::rng::DeviceRng;
use ityv_cunit::{Error, module_may_sign_batch, rules};
use ityv_encoding::{
    BallotStyleId, ElectionId, ErrorKind, Hash512, ModuleCounter, ModuleCounters, ModuleId,
    SCHEMA_VERSION_1, Scalar32, Token192, decode_object, encode_object,
};
use proptest::prelude::*;
use rand_core::Rng;

#[test]
fn interpretation_layout_is_fixed() {
    let bytes = interpretation(b"E", b"P", 0x0102);
    // header 16 ‖ u32 len 1 ‖ "E" ‖ u32 len 1 ‖ "P" ‖ u16
    assert_eq!(bytes.len(), 16 + 5 + 5 + 2);
    assert_eq!(&bytes[..4], b"ITYV");
    assert_eq!(&bytes[4..8], &0x0101u32.to_be_bytes());
    assert_eq!(&bytes[16..], &[0, 0, 0, 1, b'E', 0, 0, 0, 1, b'P', 1, 2]);
    let parsed: Interpretation<'_> =
        decode_object(SCHEMA_INTERPRETATION, SCHEMA_VERSION_1, &bytes).unwrap();
    assert_eq!(parsed.option_index(), 0x0102);
    assert_eq!(parsed.election_id().as_bytes(), b"E");
    assert_eq!(parsed.ballot_style_id().as_bytes(), b"P");
    assert!(bytes.len() <= MAX_INTERPRETATION_LEN);
}

#[test]
fn interpret_accepts_only_this_election_known_styles_and_options_up_to_m_plus_one() {
    let w = world(Profile::InPerson, false);
    let mut b = OpenBox::open(w.config, tb(1));
    let mut area = work();
    assert_eq!(
        b.interpret(&interpretation(b"E-OTHER", STYLE_SMALL, 0), &mut area)
            .unwrap_err(),
        Error::WrongElection
    );
    assert_eq!(
        b.interpret(&interpretation(b"E-2026", b"NOPE", 0), &mut area)
            .unwrap_err(),
        Error::UnknownBallotStyle
    );
    assert_eq!(
        b.interpret(&interpretation(b"E-2026", STYLE_SMALL, 4), &mut area)
            .unwrap_err(),
        Error::OptionOutOfRange
    );
    assert_eq!(
        b.interpret(&interpretation(b"E-2026", STYLE_SMALL, u16::MAX), &mut area)
            .unwrap_err(),
        Error::OptionOutOfRange
    );
    assert!(matches!(
        b.interpret(&[0u8; 30], &mut area).unwrap_err(),
        Error::Encoding(_)
    ));
    let mut wrong_schema = interpretation(b"E-2026", STYLE_SMALL, 0);
    wrong_schema[7] = 0x02;
    assert!(
        matches!(b.interpret(&wrong_schema, &mut area).unwrap_err(), Error::Encoding(e) if e.kind() == ErrorKind::SchemaMismatch)
    );
    assert!(!b.has_ballot_in_flight());
    let ballot = b
        .interpret(&interpretation(b"E-2026", STYLE_SMALL, 3), &mut area)
        .unwrap();
    assert_eq!(ballot.style().id().as_bytes(), STYLE_SMALL);
    assert!(b.has_ballot_in_flight());
}

fn issue_bytes(parts: &ModuleIssueParts<'_>) -> std::vec::Vec<u8> {
    let issue = ModuleIssue::new(parts).unwrap();
    let mut out = std::vec![0u8; MAX_MODULE_ISSUE_LEN];
    let len = encode_object(SCHEMA_MODULE_ISSUE, SCHEMA_VERSION_1, &issue, &mut out).unwrap();
    out.truncate(len);
    out
}

#[test]
fn module_issue_round_trips_and_rejects_bad_fields() {
    let rand = [Scalar32([1; 32]), Scalar32([2; 32])];
    let tags = [[3u8; 16], [4; 16]];
    let parts = ModuleIssueParts {
        module_id: ModuleId::new(b"mod-x").unwrap(),
        chamber: 1,
        counter: 7,
        rand: &rand,
        cid: Token192([5; 24]),
        lab: Some(Token192([6; 24])),
        tags: &tags,
    };
    let bytes = issue_bytes(&parts);
    assert_eq!(bytes.len(), MAX_MODULE_ISSUE_LEN - 6 * 32 - 6 * 16 - 64 + 5);
    let parsed: ModuleIssue<'_> =
        decode_object(SCHEMA_MODULE_ISSUE, SCHEMA_VERSION_1, &bytes).unwrap();
    assert_eq!(parsed.counter(), 7);
    assert_eq!(parsed.chamber(), 1);
    assert_eq!(parsed.rand(), &rand);
    assert_eq!(parsed.tags(), &tags);
    assert_eq!(parsed.cid().0, [5; 24]);
    assert_eq!(parsed.lab().unwrap().0, [6; 24]);
    assert!(std::format!("{parsed:?}").contains("counter"));
    assert!(!std::format!("{parsed:?}").contains("cid"));
    // body offsets: 16 header, id 4+5, chamber at 25, counter at 26, rand count at 34
    let reject = |at: usize, value: &[u8], kind: ErrorKind, offset: usize| {
        let mut b = bytes.clone();
        b[at..at + value.len()].copy_from_slice(value);
        let e = decode_object::<ModuleIssue<'_>>(SCHEMA_MODULE_ISSUE, SCHEMA_VERSION_1, &b)
            .unwrap_err();
        assert_eq!((e.kind(), e.offset()), (kind, offset));
    };
    reject(25, &[0], ErrorKind::ValueOutOfRange, 25);
    reject(25, &[6], ErrorKind::ValueOutOfRange, 25);
    reject(26, &[0; 8], ErrorKind::ValueOutOfRange, 26);
    reject(34, &[0, 0, 0, 0], ErrorKind::ValueOutOfRange, 34);
    reject(34, &[0, 0, 0, 9], ErrorKind::CountExceedsMax, 34);
    for bad in [
        ModuleIssueParts {
            chamber: 0,
            ..parts
        },
        ModuleIssueParts {
            chamber: 6,
            ..parts
        },
        ModuleIssueParts {
            counter: 0,
            ..parts
        },
        ModuleIssueParts { rand: &[], ..parts },
        ModuleIssueParts {
            rand: &[Scalar32([0; 32]); 9],
            ..parts
        },
        ModuleIssueParts {
            tags: &[[0; 16]; 9],
            ..parts
        },
    ] {
        assert!(ModuleIssue::new(&bad).is_none());
    }
}

#[test]
fn journal_entry_round_trips_and_rejects_unknown_kinds() {
    let counters = [
        ModuleCounter {
            module_id: ModuleId::new(b"mod-x").unwrap(),
            counter: 1,
        },
        ModuleCounter {
            module_id: ModuleId::new(b"mod-y").unwrap(),
            counter: 2,
        },
    ];
    let entry = JournalEntry::new(
        Hash512([1; 64]),
        JournalKind::BatchClose,
        Hash512([2; 64]),
        Hash512::ZERO,
        ModuleCounters::new(&counters).unwrap(),
        tb(9),
    );
    let mut out = [0u8; MAX_JOURNAL_ENTRY_LEN];
    let len = encode_object(SCHEMA_JOURNAL_ENTRY, SCHEMA_VERSION_1, &entry, &mut out).unwrap();
    assert_eq!(len, 16 + 64 + 1 + 64 + 64 + 4 + 2 * (4 + 5 + 8) + 8);
    let parsed: JournalEntry<'_> =
        decode_object(SCHEMA_JOURNAL_ENTRY, SCHEMA_VERSION_1, &out[..len]).unwrap();
    assert_eq!(parsed, entry);
    assert_eq!(parsed.kind(), JournalKind::BatchClose);
    assert_eq!(parsed.time_bucket(), tb(9));
    assert_eq!(parsed.share_package_hash(), &Hash512::ZERO);
    for code in [0u8, 6, 255] {
        let mut b = out[..len].to_vec();
        b[80] = code;
        let e = decode_object::<JournalEntry<'_>>(SCHEMA_JOURNAL_ENTRY, SCHEMA_VERSION_1, &b)
            .unwrap_err();
        assert_eq!((e.kind(), e.offset()), (ErrorKind::ValueOutOfRange, 80));
    }
    for kind in [
        JournalKind::Record,
        JournalKind::Challenge,
        JournalKind::Quarantine,
        JournalKind::BatchClose,
        JournalKind::BoxClose,
    ] {
        assert_eq!(JournalKind::from_code(kind.code()), Some(kind));
    }
    assert_eq!(JournalKind::Record.code(), 1);
    assert_eq!(JournalKind::BoxClose.code(), 5);
}

/// Runs `issue` with the first module misbehaving through `setup`.
fn issue_with(module: usize, setup: impl Fn(&mut common::MockModule)) -> Error {
    let w = world(Profile::InPerson, false);
    let mut b = OpenBox::open(w.config, tb(1));
    let mut m = mocks(&w);
    setup(&mut m[module]);
    let mut area = work();
    let ballot = b
        .interpret(&interpretation(b"E-2026", STYLE_SMALL, 1), &mut area)
        .unwrap();
    ballot.issue(&mut b, &mut ports(&mut m), &SEED).unwrap_err()
}

#[test]
fn issue_rejects_every_module_misbehaviour() {
    assert_eq!(issue_with(0, |m| m.wrong_id = true), Error::WrongModule);
    assert_eq!(
        issue_with(1, |m| m.wrong_chamber = true),
        Error::WrongChamber
    );
    assert_eq!(issue_with(2, |m| m.skip_counter = true), Error::CounterGap);
    assert_eq!(
        issue_with(3, |m| m.extra_rand = true),
        Error::ChunkCountMismatch
    );
    assert_eq!(issue_with(0, |m| m.flip_label = true), Error::LabelPresence);
    assert_eq!(issue_with(1, |m| m.extra_tag = true), Error::TagCount);
    assert_eq!(
        issue_with(2, |m| m.fail_issue = true),
        Error::Port(ityv_cunit::PortError::Transport)
    );
    let w = world(Profile::InPerson, false);
    let mut b = OpenBox::open(w.config, tb(1));
    let mut m = mocks(&w);
    let mut area = work();
    let ballot = b
        .interpret(&interpretation(b"E-2026", STYLE_SMALL, 1), &mut area)
        .unwrap();
    assert_eq!(
        ballot
            .issue(&mut b, &mut ports(&mut m[..2]), &SEED)
            .unwrap_err(),
        Error::PortCount
    );
}

#[test]
fn build_rejects_a_wrong_pad_index_or_pad_id() {
    for (wrong_index, expected) in [
        (true, Error::PadIndexMismatch),
        (false, Error::PadIdMismatch),
    ] {
        let w = world(Profile::InPerson, false);
        let mut b = OpenBox::open(w.config, tb(1));
        let mut m = mocks(&w);
        let mut bufs = Buffers::new(&w);
        let mut area = work();
        let ballot = b
            .interpret(&interpretation(b"E-2026", STYLE_SMALL, 1), &mut area)
            .unwrap();
        let ballot = ballot.issue(&mut b, &mut ports(&mut m), &SEED).unwrap();
        let ballot = ballot.commit(&b).unwrap();
        if wrong_index {
            m[1].wrong_pad_index = true;
        } else {
            m[1].wrong_pad_id = true;
        }
        let err = ballot
            .build(&b, &mut ports(&mut m), &w.device_record, bufs.as_build())
            .unwrap_err();
        assert_eq!(err, expected);
        let mut j = MemJournal::default();
        b.quarantine_in_flight(&mut j, tb(1)).unwrap();
        assert_eq!(b.totals().quarantined, 1);
    }
}

#[test]
fn build_needs_room_for_every_trustee() {
    let w = world(Profile::InPerson, false);
    let mut b = OpenBox::open(w.config, tb(1));
    let mut m = mocks(&w);
    let mut bufs = Buffers::new(&w);
    let mut area = work();
    bufs.scratch.truncate(100);
    let ballot = b
        .interpret(&interpretation(b"E-2026", STYLE_SMALL, 1), &mut area)
        .unwrap();
    let ballot = ballot.issue(&mut b, &mut ports(&mut m), &SEED).unwrap();
    let ballot = ballot.commit(&b).unwrap();
    assert_eq!(
        ballot
            .build(&b, &mut ports(&mut m), &w.device_record, bufs.as_build())
            .unwrap_err(),
        Error::BufferTooSmall
    );
}

fn base_parts(w: &common::World) -> ConfigParts<'static> {
    ConfigParts {
        election_id: w.config.election_id(),
        box_id: w.config.box_id(),
        station_id: w.config.station_id(),
        profile: w.config.profile(),
        styles: w.config.styles(),
        modules: w.config.modules(),
        trustees: w.config.trustees(),
        access: *w.config.access(),
        voter_code_enabled: false,
    }
}

fn config_fault(parts: ConfigParts<'static>) -> ConfigFault {
    match ElectionConfig::new(parts) {
        Err(Error::Config(fault)) => fault,
        other => panic!("expected a configuration fault, got {other:?}"),
    }
}

#[test]
fn configuration_rules_are_enforced() {
    let w = world(Profile::InPerson, false);
    let ok = base_parts(&w);
    assert!(ElectionConfig::new(ok).is_ok());
    let modules = w.config.modules();
    let leak_modules =
        |v: std::vec::Vec<ModuleConfig<'static>>| -> &'static [ModuleConfig<'static>] {
            common::leak(v).as_slice()
        };
    // unsorted
    let mut reversed = modules.to_vec();
    reversed.reverse();
    assert_eq!(
        config_fault(ConfigParts {
            modules: leak_modules(reversed),
            ..ok
        }),
        ConfigFault::ModulesUnsorted
    );
    // missing X
    let without_x: std::vec::Vec<_> = modules
        .iter()
        .copied()
        .filter(|m| m.chamber() != Chamber::X)
        .collect();
    assert_eq!(
        config_fault(ConfigParts {
            modules: leak_modules(without_x),
            ..ok
        }),
        ConfigFault::ChamberModules
    );
    // J, A or C without a module (neither own nor delegated)
    for chamber in [Chamber::J, Chamber::A, Chamber::C] {
        let without: std::vec::Vec<_> = modules
            .iter()
            .copied()
            .filter(|m| m.chamber() != chamber)
            .collect();
        assert_eq!(
            config_fault(ConfigParts {
                modules: leak_modules(without),
                ..ok
            }),
            ConfigFault::ChamberModules,
            "{chamber:?}"
        );
    }
    // N with a module
    let mut with_n = modules.to_vec();
    with_n.push(module_config(b"mod-z", Chamber::N, false));
    assert_eq!(
        config_fault(ConfigParts {
            modules: leak_modules(with_n),
            ..ok
        }),
        ConfigFault::ChamberModules
    );
    // neutral X
    let neutral_x: std::vec::Vec<_> = modules
        .iter()
        .map(|m| {
            if m.chamber() == Chamber::X {
                ModuleConfig::new(
                    m.module_id(),
                    Chamber::X,
                    true,
                    *m.record_key(),
                    m.batch_key(),
                )
            } else {
                *m
            }
        })
        .collect();
    assert_eq!(
        config_fault(ConfigParts {
            modules: leak_modules(neutral_x),
            ..ok
        }),
        ConfigFault::ChamberModules
    );
    // two modules for one chamber
    let mut twice = modules.to_vec();
    twice.push(module_config(b"mod-z", Chamber::J, false));
    assert_eq!(
        config_fault(ConfigParts {
            modules: leak_modules(twice),
            ..ok
        }),
        ConfigFault::ChamberModules
    );
    // seven modules
    let seven: std::vec::Vec<_> = (0..7u8)
        .map(|i| {
            module_config(
                common::leak_bytes(std::vec![b'm', b'0' + i]),
                Chamber::J,
                false,
            )
        })
        .collect();
    assert_eq!(
        config_fault(ConfigParts {
            modules: leak_modules(seven),
            ..ok
        }),
        ConfigFault::ModulesUnsorted
    );

    let trustees = w.config.trustees();
    let leak_trustees =
        |v: std::vec::Vec<TrusteeConfig<'static>>| -> &'static [TrusteeConfig<'static>] {
            common::leak(v).as_slice()
        };
    let mut reversed = trustees.to_vec();
    reversed.reverse();
    assert_eq!(
        config_fault(ConfigParts {
            trustees: leak_trustees(reversed),
            ..ok
        }),
        ConfigFault::TrusteesUnsorted
    );
    let dup_index: std::vec::Vec<_> = trustees
        .iter()
        .map(|t| {
            TrusteeConfig::new(
                t.trustee_id(),
                t.chamber(),
                0,
                t.pad_id(),
                t.kem_public_key(),
            )
        })
        .collect();
    assert_eq!(
        config_fault(ConfigParts {
            trustees: leak_trustees(dup_index),
            ..ok
        }),
        ConfigFault::MemberIndices
    );
    let out_of_range: std::vec::Vec<_> = trustees
        .iter()
        .map(|t| {
            TrusteeConfig::new(
                t.trustee_id(),
                t.chamber(),
                t.member_index() + 2,
                t.pad_id(),
                t.kem_public_key(),
            )
        })
        .collect();
    assert_eq!(
        config_fault(ConfigParts {
            trustees: leak_trustees(out_of_range),
            ..ok
        }),
        ConfigFault::MemberIndices
    );
    let missing: std::vec::Vec<_> = trustees.iter().skip(1).copied().collect();
    assert_eq!(
        config_fault(ConfigParts {
            trustees: leak_trustees(missing),
            ..ok
        }),
        ConfigFault::ThresholdCount
    );
    let t22 = Threshold::new(2, 2).unwrap();
    let t13 = Threshold::new(1, 3).unwrap();
    assert_eq!(
        config_fault(ConfigParts {
            access: AccessStructure::new([t22, t22, t13, t13, t13, t13]),
            ..ok
        }),
        ConfigFault::ThresholdCount
    );

    assert_eq!(
        config_fault(ConfigParts { styles: &[], ..ok }),
        ConfigFault::Styles
    );
    let style = BallotStyle::new(
        BallotStyleId::new(b"S").unwrap(),
        OptionCount::new(4).unwrap(),
    );
    let dup = common::leak(std::vec![style, style]).as_slice();
    assert_eq!(
        config_fault(ConfigParts { styles: dup, ..ok }),
        ConfigFault::Styles
    );
    let many = common::leak(
        (0..65u8)
            .map(|i| {
                BallotStyle::new(
                    BallotStyleId::new(common::leak_bytes(std::vec![
                        b's',
                        i / 10 + b'0',
                        i % 10 + b'0'
                    ]))
                    .unwrap(),
                    OptionCount::new(4).unwrap(),
                )
            })
            .collect::<std::vec::Vec<_>>(),
    )
    .as_slice();
    assert_eq!(
        config_fault(ConfigParts { styles: many, ..ok }),
        ConfigFault::Styles
    );

    // capacity: six modules × 8 chunks + cast id + label = 50 secrets fits
    assert_eq!(
        ityv_cunit::config::secret_count(6, 8, Profile::Absentee),
        50
    );
    assert_eq!(ityv_cunit::config::secret_count(4, 1, Profile::InPerson), 5);
}

#[test]
fn configuration_accessors_and_chamber_codes() {
    let w = world(Profile::Absentee, true);
    let c = w.config;
    assert_eq!(c.election_id().as_bytes(), b"E-2026");
    assert_eq!(c.box_id().as_bytes(), b"BOX-1");
    assert_eq!(c.station_id().as_bytes(), b"ST-1");
    assert_eq!(c.profile(), Profile::Absentee);
    assert!(c.profile().has_label());
    assert!(!Profile::InPerson.has_label());
    assert!(c.voter_code_enabled());
    assert!(c.uses_neutral_module());
    assert_eq!(c.styles().len(), 2);
    assert_eq!(c.modules().len(), 5);
    assert_eq!(c.trustees().len(), 12);
    let (index, style) = c
        .style(BallotStyleId::new(common::STYLE_WIDE).unwrap())
        .unwrap();
    assert_eq!(index, 1);
    assert_eq!(style.chunk_count(), 2);
    assert_eq!(style.option_count().get(), 12);
    assert_eq!(c.secret_count(style), 5 * 2 + 2);
    // one b per box: the two-chunk style's share, 62 + 32·12 + 24 = 470
    assert_eq!(c.member_share_len(style), 470);
    assert_eq!(c.pad_consumption(), 534);
    assert_eq!(c.module_for(Chamber::X).unwrap().0, 3);
    let (record, batch) = common::module_keys(b"mod-x");
    assert_eq!(c.modules()[3].record_key(), &record.verifying_key());
    assert_eq!(c.modules()[3].batch_key(), &batch.verifying_key());
    assert!(c.module_for(Chamber::N).is_none());
    assert!(c.modules()[0].is_neutral());
    for chamber in Chamber::ALL {
        assert_eq!(chamber_of(chamber_code(chamber)), chamber);
    }
    assert_eq!(chamber_code(Chamber::X).code(), 1);
    assert_eq!(chamber_code(Chamber::N).code(), 6);
    let own = |spec: ModuleSpec| ModuleSpec {
        neutral: false,
        ..spec
    };
    let no_neutral: [ModuleSpec; 5] = MODULES.map(own);
    let w2 = world_with(Profile::InPerson, false, &no_neutral);
    assert!(!w2.config.uses_neutral_module());
    // in person: 62 + 32·11 = 414 for the two-chunk style
    assert_eq!(w2.config.pad_consumption(), 478);
    for t in w.config.trustees() {
        assert_eq!(
            t.chamber(),
            w.trustees
                .iter()
                .find(|s| s.id == t.trustee_id().as_bytes())
                .unwrap()
                .chamber
        );
    }
}

#[test]
fn generators_are_deterministic_and_domain_separated() {
    let mut a = DeviceRng::for_signing(&[1; 32]);
    let mut b = DeviceRng::for_signing(&[1; 32]);
    let mut c = DeviceRng::for_signing(&[2; 32]);
    let (mut x, mut y, mut z) = ([0u8; 100], [0u8; 100], [0u8; 100]);
    a.fill_bytes(&mut x);
    b.fill_bytes(&mut y);
    c.fill_bytes(&mut z);
    assert_eq!(x, y);
    assert_ne!(x, z);
    // the stream does not repeat its first block
    assert_ne!(x[..64], x[36..100]);
    let f1 = a.fork(b"one", 0);
    let f2 = a.fork(b"one", 1);
    let f3 = a.fork(b"two", 0);
    let f4 = b.fork(b"one", 0);
    let first = |mut r: DeviceRng| {
        let mut out = [0u8; 32];
        r.fill_bytes(&mut out);
        out
    };
    let (o1, o2, o3, o4) = (first(f1), first(f2), first(f3), first(f4));
    assert_ne!(o1, o2);
    assert_ne!(o1, o3);
    assert_eq!(
        o1, o4,
        "forks depend on the key, not on the stream position"
    );
    let mut r = DeviceRng::for_signing(&[9; 32]);
    let (u, v) = (r.next_u32(), r.next_u64());
    let mut again = DeviceRng::for_signing(&[9; 32]);
    let mut bytes = [0u8; 12];
    again.fill_bytes(&mut bytes);
    assert_eq!(u.to_le_bytes(), bytes[..4]);
    assert_eq!(v.to_le_bytes(), bytes[4..]);
    assert_eq!(std::format!("{r:?}"), "DeviceRng(..)");
}

#[test]
fn module_batch_rule_examples() {
    assert!(module_may_sign_batch(&[4, 5, 6], 4, 6));
    assert!(module_may_sign_batch(&[4], 4, 4));
    assert!(!module_may_sign_batch(&[4, 6], 4, 6));
    assert!(!module_may_sign_batch(&[4, 5, 6, 7], 4, 6));
    assert!(!module_may_sign_batch(&[5, 6], 4, 6));
    assert!(!module_may_sign_batch(&[4, 5], 4, 6));
    assert!(!module_may_sign_batch(&[], 4, 6));
    assert!(!module_may_sign_batch(&[6, 5, 4], 4, 6));
    assert!(!module_may_sign_batch(&[4], 5, 4));
    assert!(module_may_sign_batch(&[u64::MAX], u64::MAX, u64::MAX));
    assert!(!module_may_sign_batch(&[0], 0, u64::MAX));
}

#[test]
fn counting_rule_examples() {
    use rules::CounterCheck::{Gap, Next, Regression};
    assert!(rules::option_in_range(4, 3));
    assert!(!rules::option_in_range(4, 4));
    assert_eq!(rules::check_counter(4, 5), Next);
    assert_eq!(rules::check_counter(4, 6), Gap);
    assert_eq!(rules::check_counter(4, 4), Regression);
    assert_eq!(rules::check_counter(4, 3), Regression);
    assert_eq!(rules::check_counter(u64::MAX, 0), Regression);
    assert_eq!(rules::check_counter(0, u64::MAX), Gap);
    let mut mark = 4;
    assert_eq!(rules::advance_mark(&mut mark, 5), Next);
    assert_eq!(mark, 5);
    assert_eq!(rules::advance_mark(&mut mark, 3), Regression);
    assert_eq!(rules::advance_mark(&mut mark, 7), Gap);
    assert_eq!(mark, 5);
    assert_eq!(rules::PAD_MAC_KEY_OFFSET, 0);
    assert_eq!(rules::PAD_TAG_KEY_OFFSET, 32);
    assert_eq!(rules::PAD_PLAINTEXT_OFFSET, 64);
    assert_eq!(rules::pad_consumption(222), Some(286));
    assert_eq!(rules::pad_index(3, 286), Some(858));
    assert_eq!(rules::pad_index(u64::MAX, 2), None);
    assert!(rules::batch_due(64, 0, 0));
    assert!(!rules::batch_due(63, 5, 5));
    assert!(rules::batch_due(63, 5, 6));
    assert!(!rules::batch_due(0, 5, 100));
    assert!(!rules::batch_due(1, u64::MAX, u64::MAX));
    assert!(rules::scan_count_due(50, 0, 0));
    assert!(!rules::scan_count_due(49, 0, 7));
    assert!(rules::scan_count_due(49, 0, 8));
    assert!(!rules::scan_count_due(0, u64::MAX, u64::MAX));
    let v = rules::Violations::default();
    assert!(v.is_empty());
    assert_eq!(v.count(), 0);
}

#[test]
fn errors_display_without_secrets() {
    for e in [
        Error::BufferTooSmall,
        Error::WrongElection,
        Error::PadIndexMismatch,
        Error::JournalMismatch,
        Error::Config(ConfigFault::Styles),
        Error::Port(ityv_cunit::PortError::Exhausted),
        Error::Journal(ityv_cunit::JournalError::Full),
    ] {
        assert!(!std::format!("{e}").is_empty());
    }
    let shown: std::collections::BTreeSet<std::string::String> = [
        Error::BallotInFlight,
        Error::NoBallotInFlight,
        Error::StaleBallot,
        Error::TimeRegression,
        Error::VoterCodeDisabled,
        Error::BatchEmpty,
        Error::BatchFull,
        Error::BoxClosed,
        Error::CounterGap,
        Error::CounterRegression,
        Error::RecordSignature,
        Error::BatchSignature,
        Error::JournalCorrupt,
        Error::EnvelopeCountProfile,
        Error::ForeignCloseToken,
        Error::Journal(ityv_cunit::JournalError::Unreadable),
    ]
    .iter()
    .map(|e| std::format!("{e}"))
    .collect();
    assert_eq!(shown.len(), 16);
}

proptest! {
    #[test]
    fn link_decoders_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..600)) {
        let _ = decode_object::<Interpretation<'_>>(SCHEMA_INTERPRETATION, SCHEMA_VERSION_1, &bytes);
        let _ = decode_object::<ModuleIssue<'_>>(SCHEMA_MODULE_ISSUE, SCHEMA_VERSION_1, &bytes);
        let _ = decode_object::<JournalEntry<'_>>(SCHEMA_JOURNAL_ENTRY, SCHEMA_VERSION_1, &bytes);
    }

    #[test]
    fn interpretations_round_trip(option in any::<u16>(), style_len in 1usize..=64) {
        let style = std::vec![b'S'; style_len];
        let bytes = interpretation(b"E-2026", &style, option);
        let parsed: Interpretation<'_> = decode_object(SCHEMA_INTERPRETATION, SCHEMA_VERSION_1, &bytes).unwrap();
        prop_assert_eq!(parsed.option_index(), option);
        prop_assert_eq!(parsed.ballot_style_id().as_bytes(), style.as_slice());
        let e = ElectionId::new(b"E-2026").unwrap();
        prop_assert_eq!(parsed.election_id(), e);
        for cut in 0..bytes.len() {
            prop_assert!(decode_object::<Interpretation<'_>>(SCHEMA_INTERPRETATION, SCHEMA_VERSION_1, &bytes[..cut]).is_err());
        }
    }

    #[test]
    fn close_verdict_matches_its_definition(
        paper in 0u64..6, records in 0u64..6, attested in 0u64..6, open in 0u64..6,
        without in 0u64..3, challenged in 0u64..3, quarantined in 0u64..3, spoiled in 0u64..6,
        c0 in 0u64..10, c1 in 0u64..10, batches in 0u8..2, envelopes in proptest::option::of(0u64..6),
        declared in any::<bool>(),
    ) {
        let counters = [c0, c1];
        let facts = rules::CloseFacts {
            paper, records, attested, open_batch_records: open, without_record: without,
            challenged, quarantined, spoiled_envelopes: spoiled, module_final_counters: &counters,
            open_batches: batches, absentee_envelopes: envelopes, fallback_declared: declared,
        };
        let v = rules::close_verdict(&facts);
        prop_assert_eq!(v.contains(I::PaperCount), records + without != paper);
        prop_assert_eq!(v.contains(I::AttestedCount), attested + open != records);
        prop_assert_eq!(v.contains(I::SpoiledEnvelopes), challenged + quarantined != spoiled);
        let consumed = records + challenged + quarantined;
        prop_assert_eq!(v.contains(I::ModuleCounters), c0 != consumed || c1 != consumed);
        prop_assert_eq!(v.contains(I::OpenBatches), batches != 0);
        prop_assert_eq!(v.contains(I::EnvelopeCount), envelopes.is_some_and(|n| n != records));
        prop_assert_eq!(v.contains(I::FallbackDeclared), without > 0 && !declared);
    }
}
