//! The small public surfaces: debug and display text, accessors, and every
//! operation refused after close.
// Integration-test crate: outside the TCB. Tests express "this must hold"
// with unwrap/expect/panic/indexing and small arithmetic on test sizes,
// so these lints are relaxed for this file only (CONSTITUTION.md §1.1).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::too_many_lines,
    clippy::missing_panics_doc,
    clippy::many_single_char_names
)]

mod common;

use std::collections::BTreeSet;
use std::format;
use std::string::String;

use common::{
    Buffers, MemJournal, SEED, STYLE_SMALL, interpretation, mocks, module_config, ports, signer,
    tb, work, world,
};
use ityv_cunit::boxstate::{BATCH_WORK_LEN, CLOSE_WORK_LEN, CloseInputs, OpenBox};
use ityv_cunit::config::Profile;
use ityv_cunit::error::{ConfigFault, Invariant};
use ityv_cunit::{Error, JournalError, PortError};
use ityv_encoding::{
    BoxCloseBody, CastRecord, CastRecordBody, Hash512, SCHEMA_BOX_CLOSE_BODY, SCHEMA_CAST_RECORD,
    SCHEMA_CAST_RECORD_BODY, SCHEMA_VERSION_1, decode_object,
};

fn distinct_nonempty(texts: &[String]) {
    assert!(texts.iter().all(|t| !t.is_empty()));
    let set: BTreeSet<&String> = texts.iter().collect();
    assert_eq!(set.len(), texts.len(), "{texts:?}");
}

#[test]
fn every_enum_displays_a_distinct_text() {
    distinct_nonempty(
        &[
            ConfigFault::ModulesUnsorted,
            ConfigFault::ChamberModules,
            ConfigFault::TrusteesUnsorted,
            ConfigFault::MemberIndices,
            ConfigFault::ThresholdCount,
            ConfigFault::Styles,
        ]
        .map(|f| format!("{f}")),
    );
    distinct_nonempty(
        &[
            Invariant::PaperCount,
            Invariant::AttestedCount,
            Invariant::SpoiledEnvelopes,
            Invariant::ModuleCounters,
            Invariant::OpenBatches,
            Invariant::EnvelopeCount,
            Invariant::FallbackDeclared,
            Invariant::PaperIncidents,
        ]
        .map(|i| format!("{i}")),
    );
    distinct_nonempty(
        &[
            PortError::Exhausted,
            PortError::Refused,
            PortError::Transport,
            PortError::BufferTooSmall,
        ]
        .map(|e| format!("{e}")),
    );
    distinct_nonempty(
        &[
            JournalError::NotDurable,
            JournalError::Full,
            JournalError::Unreadable,
        ]
        .map(|e| format!("{e}")),
    );
    let errors = [
        Error::Encoding(ityv_encoding::Error::new(
            ityv_encoding::ErrorKind::BadMagic,
            0,
        )),
        Error::Crypto(ityv_crypto::Error::InvalidPoint),
        Error::Ledger(ityv_ledger::Error::Capacity),
        Error::Port(PortError::Exhausted),
        Error::Journal(JournalError::Full),
        Error::Config(ConfigFault::Styles),
        Error::BufferTooSmall,
        Error::WrongElection,
        Error::UnknownBallotStyle,
        Error::OptionOutOfRange,
        Error::PortCount,
        Error::WrongModule,
        Error::WrongChamber,
        Error::CounterGap,
        Error::CounterRegression,
        Error::ChunkCountMismatch,
        Error::LabelPresence,
        Error::TagCount,
        Error::PadIdMismatch,
        Error::PadIndexMismatch,
        Error::RecordSignature,
        Error::BatchSignature,
        Error::JournalMismatch,
        Error::JournalCorrupt,
        Error::BatchEmpty,
        Error::BatchFull,
        Error::BoxClosed,
        Error::InvalidPurpose,
        Error::Overflow,
        Error::Capacity,
        Error::BallotInFlight,
        Error::NoBallotInFlight,
        Error::StaleBallot,
        Error::TimeRegression,
        Error::VoterCodeDisabled,
        Error::EnvelopeCountProfile,
        Error::ForeignCloseToken,
    ];
    let texts: std::vec::Vec<String> = errors.iter().map(|e| format!("{e}")).collect();
    distinct_nonempty(&texts);
    // wrapped errors show the inner text
    assert!(
        format!("{}", Error::Config(ConfigFault::Styles))
            .contains(&format!("{}", ConfigFault::Styles))
    );
    assert!(format!("{}", Error::Port(PortError::Exhausted)).contains("pad exhausted"));
    assert!(format!("{}", Error::Journal(JournalError::Full)).contains("full"));
    let e: &dyn core::error::Error = &Error::BoxClosed;
    assert!(e.source().is_none());
}

#[test]
fn ballots_debug_print_only_the_ticket() {
    let w = world(Profile::InPerson, false);
    let mut b = OpenBox::open(w.config, tb(1));
    let mut m = mocks(&w);
    let mut area = work();
    assert_eq!(format!("{area:?}"), "BallotWork(..)");
    let ballot = b
        .interpret(&interpretation(b"E-2026", STYLE_SMALL, 1), &mut area)
        .unwrap();
    let text = format!("{ballot:?}");
    assert!(text.starts_with("Ballot"));
    assert!(text.contains("ticket: 1"));
    let issued = ballot.issue(&mut b, &mut ports(&mut m), &SEED).unwrap();
    let text = format!("{issued:?}");
    assert!(text.contains("ticket: 1"));
    assert!(!text.contains("rand"));
    assert!(!text.contains("cid"));
}

#[test]
fn built_and_durable_accessors_expose_the_written_objects() {
    let w = world(Profile::InPerson, false);
    let mut b = OpenBox::open(w.config, tb(1));
    let mut m = mocks(&w);
    let mut j = MemJournal::default();
    let mut bufs = Buffers::new(&w);
    let mut area = work();
    let ballot = b
        .interpret(&interpretation(b"E-2026", STYLE_SMALL, 1), &mut area)
        .unwrap();
    let ballot = ballot.issue(&mut b, &mut ports(&mut m), &SEED).unwrap();
    let ballot = ballot.commit(&b).unwrap();
    let ballot = ballot
        .build(&b, &mut ports(&mut m), &w.device_record, bufs.as_build())
        .unwrap();
    let body = ballot.body_bytes().to_vec();
    let record = ballot.record_bytes().to_vec();
    let _: CastRecordBody<'_> =
        decode_object(SCHEMA_CAST_RECORD_BODY, SCHEMA_VERSION_1, &body).unwrap();
    let parsed: CastRecord<'_> =
        decode_object(SCHEMA_CAST_RECORD, SCHEMA_VERSION_1, &record).unwrap();
    assert_eq!(parsed.body_bytes(), body.as_slice());
    assert_eq!(ballot.tracking_code(), &ityv_crypto::object_hash(&body));
    let durable = ballot.cast(&mut b, &mut j, tb(1)).unwrap();
    assert_eq!(durable.record_bytes(), record.as_slice());
    assert_eq!(durable.tracking_code(), &ityv_crypto::object_hash(&body));
    durable.imprinted(&mut b, &mut j, tb(1)).unwrap();
    assert_eq!(b.config().election_id().as_bytes(), b"E-2026");
}

#[test]
fn a_close_with_an_open_batch_reports_it_in_the_body() {
    let w = world(Profile::InPerson, false);
    let mut b = OpenBox::open(w.config, tb(1));
    let mut m = mocks(&w);
    let mut j = MemJournal::default();
    let mut bufs = Buffers::new(&w);
    let mut area = work();
    let ballot = b
        .interpret(&interpretation(b"E-2026", STYLE_SMALL, 1), &mut area)
        .unwrap();
    let ballot = ballot.issue(&mut b, &mut ports(&mut m), &SEED).unwrap();
    let ballot = ballot.commit(&b).unwrap();
    let ballot = ballot
        .build(&b, &mut ports(&mut m), &w.device_record, bufs.as_build())
        .unwrap();
    let code = *ballot.tracking_code();
    ballot
        .cast(&mut b, &mut j, tb(1))
        .unwrap()
        .imprinted(&mut b, &mut j, tb(1))
        .unwrap();
    let inputs = CloseInputs {
        paper: 1,
        without_record: 0,
        spoiled_envelopes: 0,
        absentee_envelopes: None,
        fallback_declared: false,
        record_set_root: ityv_ledger::merkle::sorted_set_root(&[code]).unwrap(),
        seal_digest: Hash512([1; 64]),
    };
    let mut out = std::vec![0u8; CLOSE_WORK_LEN];
    let closing = b
        .prepare_close(&inputs, signer(&w), &mut j, tb(2), &mut out)
        .unwrap();
    assert!(closing.verdict.contains(Invariant::OpenBatches));
    let body: BoxCloseBody<'_> =
        decode_object(SCHEMA_BOX_CLOSE_BODY, SCHEMA_VERSION_1, closing.body).unwrap();
    assert_eq!(body.open_batches(), 1);
    assert_eq!(body.counts().records, 1);
    assert_eq!(body.counts().attested, 0);
    assert_eq!(body.time_bucket(), tb(2));
    assert_eq!(body.seal_digest(), &Hash512([1; 64]));
    let token = closing.token;
    // nothing else is accepted once the close entry is written
    let head = *b.journal_head();
    let mut bw = std::vec![0u8; BATCH_WORK_LEN];
    assert_eq!(
        b.close_batch(
            &head,
            &mut ports(&mut m),
            signer(&w),
            &mut j,
            tb(2),
            &mut bw
        )
        .unwrap_err(),
        Error::BoxClosed
    );
    let mut sw = std::vec![0u8; 512];
    assert_eq!(
        b.scan_count_body(tb(2), &mut sw).unwrap_err(),
        Error::BoxClosed
    );
    let closed = b.into_closed(token).unwrap();
    assert_eq!(closed.config().box_id().as_bytes(), b"BOX-1");
}

#[test]
fn close_needs_room_and_no_ballot_in_flight() {
    let w = world(Profile::InPerson, false);
    let mut b = OpenBox::open(w.config, tb(1));
    let mut j = MemJournal::default();
    let inputs = CloseInputs {
        paper: 0,
        without_record: 0,
        spoiled_envelopes: 0,
        absentee_envelopes: None,
        fallback_declared: false,
        record_set_root: Hash512::ZERO,
        seal_digest: Hash512::ZERO,
    };
    let mut small = std::vec![0u8; 100];
    assert_eq!(
        b.prepare_close(&inputs, signer(&w), &mut j, tb(1), &mut small)
            .unwrap_err(),
        Error::BufferTooSmall
    );
    let mut area = work();
    let ballot = b
        .interpret(&interpretation(b"E-2026", STYLE_SMALL, 1), &mut area)
        .unwrap();
    let mut out = std::vec![0u8; CLOSE_WORK_LEN];
    assert_eq!(
        b.prepare_close(&inputs, signer(&w), &mut j, tb(1), &mut out)
            .unwrap_err(),
        Error::BallotInFlight
    );
    drop(ballot);
    b.quarantine_in_flight(&mut j, tb(1)).unwrap();
    let closed = b
        .prepare_close(&inputs, signer(&w), &mut j, tb(1), &mut out)
        .unwrap();
    assert!(closed.verdict.is_empty());
    assert_eq!(j.entries.len(), 1);
}

#[test]
fn work_buffer_sizes_are_exact() {
    assert_eq!(ityv_cunit::boxstate::MAX_BATCH_ATTEST_LEN, 34_483);
    assert_eq!(BATCH_WORK_LEN, 7 * 4691 + 34_483);
    assert_eq!(BATCH_WORK_LEN, 67_320);
    assert_eq!(CLOSE_WORK_LEN, 1024 + 4691);
    assert_eq!(ityv_cunit::ballot::MAX_MEMBER_SHARE_LEN, 1686);
    assert_eq!(ityv_cunit::ballot::SCRATCH_SLOT_LEN, 1600 + 1686);
    assert_eq!(ityv_cunit::link::MAX_MODULE_ISSUE_LEN, 534);
    assert_eq!(ityv_cunit::link::MAX_INTERPRETATION_LEN, 154);
    assert_eq!(ityv_cunit::link::MAX_JOURNAL_ENTRY_LEN, 677);
}

#[test]
fn batch_index_counts_closed_batches() {
    let w = world(Profile::InPerson, false);
    let mut b = OpenBox::open(w.config, tb(1));
    let mut m = mocks(&w);
    let mut j = MemJournal::default();
    assert_eq!(b.batch_index(), 0);
    for expected in 1..=2u32 {
        let mut bufs = Buffers::new(&w);
        let mut area = work();
        let ballot = b
            .interpret(&interpretation(b"E-2026", STYLE_SMALL, 1), &mut area)
            .unwrap();
        let ballot = ballot.issue(&mut b, &mut ports(&mut m), &SEED).unwrap();
        let ballot = ballot.commit(&b).unwrap();
        let ballot = ballot
            .build(&b, &mut ports(&mut m), &w.device_record, bufs.as_build())
            .unwrap();
        ballot
            .cast(&mut b, &mut j, tb(1))
            .unwrap()
            .imprinted(&mut b, &mut j, tb(1))
            .unwrap();
        let head = *b.journal_head();
        let mut out = std::vec![0u8; BATCH_WORK_LEN];
        b.close_batch(
            &head,
            &mut ports(&mut m),
            signer(&w),
            &mut j,
            tb(1),
            &mut out,
        )
        .unwrap();
        assert_eq!(b.batch_index(), expected);
    }
}

#[test]
fn configuration_boundaries_are_exact() {
    use ityv_crypto::{Chamber, OptionCount};
    use ityv_cunit::config::{
        BallotStyle, ConfigParts, ElectionConfig, ModuleConfig, TrusteeConfig,
    };
    use ityv_encoding::BallotStyleId;
    let w = world(Profile::InPerson, false);
    let ok = ConfigParts {
        election_id: w.config.election_id(),
        box_id: w.config.box_id(),
        station_id: w.config.station_id(),
        profile: w.config.profile(),
        styles: w.config.styles(),
        modules: w.config.modules(),
        trustees: w.config.trustees(),
        access: *w.config.access(),
        voter_code_enabled: false,
    };
    let fault = |parts: ConfigParts<'static>| match ElectionConfig::new(parts) {
        Err(Error::Config(fault)) => fault,
        other => panic!("expected a configuration fault, got {other:?}"),
    };
    // a duplicate module identifier is not strictly ascending
    let modules = w.config.modules();
    let mut dup = modules.to_vec();
    dup[1] = ModuleConfig::new(
        modules[0].module_id(),
        modules[1].chamber(),
        false,
        *modules[1].record_key(),
        modules[1].batch_key(),
    );
    assert_eq!(
        fault(ConfigParts {
            modules: common::leak(dup).as_slice(),
            ..ok
        }),
        ConfigFault::ModulesUnsorted
    );
    // six modules pass the capacity rule and fail the one-per-chamber rule
    let six: std::vec::Vec<_> = (0..6u8)
        .map(|i| {
            let chamber = [
                Chamber::A,
                Chamber::C,
                Chamber::J,
                Chamber::J,
                Chamber::X,
                Chamber::Y,
            ][usize::from(i)];
            module_config(
                common::leak_bytes(std::vec![b'm', b'0' + i]),
                chamber,
                false,
            )
        })
        .collect();
    assert_eq!(
        fault(ConfigParts {
            modules: common::leak(six).as_slice(),
            ..ok
        }),
        ConfigFault::ChamberModules
    );
    // a duplicate trustee identifier
    let trustees = w.config.trustees();
    let mut dup = trustees.to_vec();
    let t = trustees[0];
    dup[1] = TrusteeConfig::new(
        t.trustee_id(),
        trustees[1].chamber(),
        trustees[1].member_index(),
        t.pad_id(),
        t.kem_public_key(),
    );
    assert_eq!(
        fault(ConfigParts {
            trustees: common::leak(dup).as_slice(),
            ..ok
        }),
        ConfigFault::TrusteesUnsorted
    );
    // member index n with index n−1 missing
    let gap: std::vec::Vec<_> = trustees
        .iter()
        .map(|t| {
            let index = if t.member_index() == 1 { 2 } else { 0 };
            TrusteeConfig::new(
                t.trustee_id(),
                t.chamber(),
                index,
                t.pad_id(),
                t.kem_public_key(),
            )
        })
        .collect();
    assert_eq!(
        fault(ConfigParts {
            trustees: common::leak(gap).as_slice(),
            ..ok
        }),
        ConfigFault::MemberIndices
    );
    // 64 trustees pass the capacity rule; 65 do not
    let key = trustees[0].kem_public_key();
    let many = |n: u8| -> &'static [TrusteeConfig<'static>] {
        let v: std::vec::Vec<_> = (0..n)
            .map(|i| {
                let id = common::leak_bytes(std::vec![b't', b'0' + i / 10, b'0' + i % 10]);
                TrusteeConfig::new(
                    ityv_encoding::TrusteeId::new(id).unwrap(),
                    Chamber::X,
                    i,
                    0,
                    key,
                )
            })
            .collect();
        common::leak(v).as_slice()
    };
    assert_eq!(
        fault(ConfigParts {
            trustees: many(64),
            ..ok
        }),
        ConfigFault::MemberIndices
    );
    assert_eq!(
        fault(ConfigParts {
            trustees: many(65),
            ..ok
        }),
        ConfigFault::TrusteesUnsorted
    );
    // 64 styles are accepted
    let styles: std::vec::Vec<_> = (0..64u8)
        .map(|i| {
            let id = common::leak_bytes(std::vec![b's', b'0' + i / 10, b'0' + i % 10]);
            BallotStyle::new(
                BallotStyleId::new(id).unwrap(),
                OptionCount::new(4).unwrap(),
            )
        })
        .collect();
    assert!(
        ElectionConfig::new(ConfigParts {
            styles: common::leak(styles).as_slice(),
            ..ok
        })
        .is_ok()
    );
    // neutral flags
    assert!(modules.iter().any(|m| !m.is_neutral()));
    assert!(modules.iter().any(ModuleConfig::is_neutral));
}

#[test]
fn chamber_code_five_is_a_module_chamber() {
    use ityv_cunit::link::{
        MAX_MODULE_ISSUE_LEN, ModuleIssue, ModuleIssueParts, SCHEMA_MODULE_ISSUE,
    };
    use ityv_encoding::{ModuleId, Scalar32, Token192, encode_object};
    let rand = [Scalar32([1; 32])];
    let issue = ModuleIssue::new(&ModuleIssueParts {
        module_id: ModuleId::new(b"mod-c").unwrap(),
        chamber: 5,
        counter: 1,
        rand: &rand,
        cid: Token192([2; 24]),
        lab: None,
        tags: &[],
    })
    .unwrap();
    let mut out = [0u8; MAX_MODULE_ISSUE_LEN];
    let len = encode_object(SCHEMA_MODULE_ISSUE, SCHEMA_VERSION_1, &issue, &mut out).unwrap();
    let parsed: ModuleIssue<'_> =
        decode_object(SCHEMA_MODULE_ISSUE, SCHEMA_VERSION_1, &out[..len]).unwrap();
    assert_eq!(parsed.chamber(), 5);
    assert!(parsed.tags().is_empty());
}

#[test]
fn scan_count_accepts_the_bucket_of_the_last_entry_and_verdicts_report_violations() {
    let w = world(Profile::InPerson, false);
    let mut b = OpenBox::open(w.config, tb(4));
    let mut out = std::vec![0u8; 512];
    assert!(b.scan_count_body(tb(4), &mut out).is_ok());
    let counters = [1u64];
    let facts = ityv_cunit::rules::CloseFacts {
        paper: 1,
        records: 0,
        attested: 0,
        open_batch_records: 0,
        without_record: 0,
        challenged: 0,
        quarantined: 0,
        spoiled_envelopes: 0,
        module_final_counters: &counters,
        open_batches: 0,
        absentee_envelopes: None,
        fallback_declared: false,
        paper_incidents: 0,
    };
    let v = ityv_cunit::rules::close_verdict(&facts);
    assert!(!v.is_empty());
    assert_eq!(v.count(), 2);
    assert!(v.contains(Invariant::PaperCount));
    assert!(v.contains(Invariant::ModuleCounters));
}

#[test]
fn secret_bearing_values_debug_print_nothing_secret() {
    use ityv_cunit::link::ModuleIssueParts;
    use ityv_encoding::{ModuleId, Scalar32, Token192};
    let w = world(Profile::InPerson, true);
    assert_eq!(format!("{:?}", signer(&w)), "Signer(..)");
    let rand = [Scalar32([0xAB; 32])];
    let tags = [[0xCD; 16]];
    let parts = ModuleIssueParts {
        module_id: ModuleId::new(b"mod-x").unwrap(),
        chamber: 1,
        counter: 7,
        rand: &rand,
        cid: Token192([0xEF; 24]),
        lab: Some(Token192([0x12; 24])),
        tags: &tags,
    };
    let text = format!("{parts:?}");
    assert!(text.starts_with("ModuleIssueParts"));
    assert!(text.contains("counter: 7"));
    for secret in ["rand", "cid", "lab", "tags", "171", "205", "239"] {
        assert!(!text.contains(secret), "{secret} in {text}");
    }
    let mut b = OpenBox::open(w.config, tb(1));
    let mut m = mocks(&w);
    let mut j = MemJournal::default();
    let mut bufs = Buffers::new(&w);
    let mut area = work();
    let ballot = b
        .interpret(&interpretation(b"E-2026", STYLE_SMALL, 1), &mut area)
        .unwrap();
    let ballot = ballot.issue(&mut b, &mut ports(&mut m), &SEED).unwrap();
    let ballot = ballot.commit(&b).unwrap();
    let ballot = ballot
        .build(&b, &mut ports(&mut m), &w.device_record, bufs.as_build())
        .unwrap();
    let ballot = ballot.cast(&mut b, &mut j, tb(1)).unwrap();
    let command = ballot.imprint_command(&b).unwrap();
    assert_eq!(format!("{command:?}"), "ImprintCommand(..)");
    assert!(command.env_label().is_none());
    assert_ne!(command.cast_id(), &[0; 24]);
    ballot.imprinted(&mut b, &mut j, tb(1)).unwrap();
    assert!(area.is_clear());
}
