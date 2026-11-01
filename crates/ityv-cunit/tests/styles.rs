//! An early-voting scanner holds every district's ballot style (about
//! 2,300 in a local election): the configuration takes up to 4,096 styles
//! sorted by identifier and the unit finds one by binary search.
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
    clippy::missing_panics_doc
)]

mod common;

use common::{
    Buffers, MODULES, MemJournal, SEED, World, interpretation, mocks, ports, styles, tb, work,
    world_full,
};
use ityv_cunit::Error;
use ityv_cunit::boxstate::OpenBox;
use ityv_cunit::config::{BallotStyle, ConfigParts, ElectionConfig, MAX_STYLES, Profile};
use ityv_cunit::error::ConfigFault;
use ityv_encoding::{
    BallotStyleId, CastRecord, SCHEMA_CAST_RECORD, SCHEMA_VERSION_1, decode_object,
};

fn full_world() -> World {
    world_full(Profile::InPerson, false, &MODULES, styles(MAX_STYLES))
}

fn id(text: &'static [u8]) -> BallotStyleId<'static> {
    BallotStyleId::new(text).unwrap()
}

#[test]
fn a_full_configuration_finds_its_first_middle_and_last_style() {
    let w = full_world();
    assert_eq!(MAX_STYLES, 4096);
    assert_eq!(w.config.styles().len(), 4096);
    for (text, index) in [
        (b"S0000".as_slice(), 0usize),
        (b"S2048", 2048),
        (b"S4095", 4095),
    ] {
        let (found, style) = w.config.style(id(text)).unwrap();
        assert_eq!(found, index);
        assert_eq!(style.id().as_bytes(), text);
        assert_eq!(usize::from(style.option_count().get()), 3 + index % 62);
    }
    // every style is found at its own index
    for (index, style) in w.config.styles().iter().enumerate() {
        assert_eq!(w.config.style(style.id()).unwrap().0, index);
    }
    // identifiers before the first, between two and after the last
    for unknown in [
        b"A".as_slice(),
        b"S",
        b"S000",
        b"S00000",
        b"S2047x",
        b"S4096",
        b"T",
    ] {
        assert!(w.config.style(id(unknown)).is_none(), "{unknown:?}");
    }
    // the box consumes pad for its largest style: 64 options, k = 8
    let longest = ityv_cunit::ballot::member_share_len(5 * 8 + 1, false);
    assert_eq!(w.config.pad_consumption(), (longest + 64) as u64);
}

#[test]
fn ballots_of_the_first_middle_and_last_style_are_cast() {
    let w = full_world();
    let mut b = OpenBox::open(w.config, tb(1));
    let mut m = mocks(&w);
    let mut j = MemJournal::default();
    for text in [b"S0000".as_slice(), b"S2048", b"S4095"] {
        let mut bufs = Buffers::new(&w);
        let mut area = work();
        let ballot = b
            .interpret(&interpretation(b"E-2026", text, 1), &mut area)
            .unwrap();
        assert_eq!(ballot.style().id().as_bytes(), text);
        let ballot = ballot.issue(&mut b, &mut ports(&mut m), &SEED).unwrap();
        let ballot = ballot.commit(&b).unwrap();
        let ballot = ballot
            .build(&b, &mut ports(&mut m), &w.device_record, bufs.as_build())
            .unwrap();
        let record: CastRecord<'_> =
            decode_object(SCHEMA_CAST_RECORD, SCHEMA_VERSION_1, ballot.record_bytes()).unwrap();
        assert_eq!(record.body().ballot_style_id().as_bytes(), text);
        let ballot = ballot.cast(&mut b, &mut j, tb(1)).unwrap();
        ballot.imprinted(&mut b, &mut j, tb(1)).unwrap();
    }
    assert_eq!(b.totals().records, 3);
    let mut area = work();
    assert_eq!(
        b.interpret(&interpretation(b"E-2026", b"S4096", 1), &mut area)
            .unwrap_err(),
        Error::UnknownBallotStyle
    );
}

fn fault(styles: &'static [BallotStyle<'static>]) -> ConfigFault {
    let w = common::world(Profile::InPerson, false);
    let parts = ConfigParts {
        election_id: w.config.election_id(),
        box_id: w.config.box_id(),
        station_id: w.config.station_id(),
        profile: w.config.profile(),
        styles,
        modules: w.config.modules(),
        trustees: w.config.trustees(),
        access: *w.config.access(),
        voter_code_enabled: false,
    };
    match ElectionConfig::new(parts) {
        Err(Error::Config(fault)) => fault,
        other => panic!("expected a configuration fault, got {other:?}"),
    }
}

#[test]
fn unsorted_duplicate_or_too_many_styles_are_refused() {
    let all = styles(MAX_STYLES);
    let mut swapped = all.to_vec();
    swapped.swap(100, 101);
    assert_eq!(
        fault(common::leak(swapped).as_slice()),
        ConfigFault::StylesUnsorted
    );
    let mut last_first = all.to_vec();
    last_first.rotate_right(1);
    assert_eq!(
        fault(common::leak(last_first).as_slice()),
        ConfigFault::StylesUnsorted
    );
    let mut duplicate = all.to_vec();
    duplicate[4095] = duplicate[4094];
    assert_eq!(
        fault(common::leak(duplicate).as_slice()),
        ConfigFault::StylesUnsorted
    );
    assert_eq!(fault(styles(MAX_STYLES + 1)), ConfigFault::Styles);
    assert_eq!(fault(&[]), ConfigFault::Styles);
    // one style, and exactly the capacity, are accepted
    let _ = full_world();
    let one = &styles(1)[..1];
    let w = world_full(
        Profile::InPerson,
        false,
        &MODULES,
        common::leak(one.to_vec()),
    );
    assert_eq!(w.config.style(id(b"S0000")).unwrap().0, 0);
}

#[test]
fn the_configuration_only_borrows_the_style_list() {
    // The host owns the 4,096 entries; the validated configuration holds a
    // slice and stays small (on thumbv7em every reference is half this).
    assert!(core::mem::size_of::<ElectionConfig<'static>>() <= 256);
    assert_eq!(core::mem::size_of::<BallotStyle<'static>>(), 24);
}
