//! The connectivity stage (PROTOCOL.md §5.8, §14 11; ADR-0022, ADR-0041;
//! VC-077..081, VC-083): the manifest's one-way rules, the gateway's
//! sessions and frame logs, each link's frames and objects, inclusion,
//! incidents, and the capture and carrier comparisons. A one-box election
//! with real signatures: BOX-1 at ST-1, opened in bucket 100 (slots 150 and
//! 151) and closed in bucket 140 (slots 210 and 211, the closing tick's
//! slot 212); each test changes one thing an honest device or gateway would
//! do. The tests named after a finding of the review of 2i (C1–C3, E1–E3,
//! M1–M3) are its regressions, and those named `r2_` after a finding of the
//! second review (A–I) are that one's.
// Integration tests: outside the TCB. Assertions use unwrap/expect, so these
// lints are relaxed for this file only (CONSTITUTION.md §1.1).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::missing_panics_doc,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::similar_names,
    clippy::type_complexity,
    clippy::many_single_char_names,
    clippy::unnecessary_wraps
)]

mod common;
mod world;

use std::collections::BTreeSet;
use std::sync::OnceLock;
use std::vec::Vec;

use common::uplink::{
    Built, Link, Plan, box_stream, capture_file, device_frames_of, device_of, entry_at,
    fake_object, incident_body, link, log_key, relog, schema_of, station_links, stream, wire_frame,
    with_packages,
};
use common::{COMMITTEE, SIGNERS, leak, leak_slice};
use ityv_encoding::{
    BoxId, DeviceClass, Direction, EventRole, FrameKind, GatewayId, Hash512, MAX_PAYLOAD_LEN,
    SCHEMA_PARTICIPATION_SET, SCHEMA_PROGRESS_TICK, SCHEMA_SHARE_PACKAGE, SCHEMA_UPLINK_FRAME_LOG,
    SchemaId, SessionLink, SessionLinks, StationKind, StreamObject, TimeBucket, UnitId,
    UplinkSessionParts,
};
use ityv_state::status::{Outcome, Step};
use ityv_state::{HoldReason, HoldSet, Publication};
use ityv_verify::{
    CaptureProblem, CarrierInterval, CarrierLine, CarrierLog, CarrierProblem, IncidentProblem,
    LinkDevice, LinkProblem, LinkReport, ManifestProblem, Publications, Report, SessionProblem,
    StationUplink, compare_capture, compare_carrier, verify_ledger,
};

use world::*;

const ST: &[u8] = b"ST-1";
/// The scanner's link comes first in [`Day::links`], U-1A's second.
const SCANNER: usize = 0;
const UNIT: usize = 1;

/// The day's ledger events after the genesis and the authorization, and
/// the links an honest gateway records at ST-1: BOX-1's scanner and U-1A
/// from slot 150 to 212, one normal frame a slot, every object in the first
/// frame, each of the scanner's records followed by its share package.
struct Day {
    events: Vec<(SchemaId, &'static [u8])>,
    links: Vec<Link>,
}

fn day() -> &'static Day {
    static DAY: OnceLock<&'static Day> = OnceLock::new();
    DAY.get_or_init(|| {
        let world = election_world();
        let mut book = Book::new(world);
        box1_closed(&mut book);
        for (schema, event) in station_record(3) {
            book.push(schema, event);
        }
        book.push(SCHEMA_PARTICIPATION_SET, participation(3));
        let all = book.ledger.events.clone();
        let mut by_station = station_links(world.genesis, &all);
        let (station, links) = by_station.remove(0);
        assert_eq!(station, ST);
        assert!(by_station.is_empty());
        leak(Day {
            events: all[2..].iter().map(|e| (schema_of(e), *e)).collect(),
            links,
        })
    })
}

/// The day's ledger in `world`, before any uplink.
fn book_in(world: &'static World) -> Book {
    let mut book = Book::new(world);
    for (schema, event) in &day().events {
        book.push(*schema, event);
    }
    book
}

fn publications() -> Publications {
    Publications {
        now: TimeBucket::new(0),
        board: Publication::Pending,
    }
}

/// The report over `book` with `uplink` after it.
fn verify_book(mut book: Book, uplink: Vec<(SchemaId, &'static [u8])>) -> Report<'static> {
    for (schema, event) in uplink {
        book.push(schema, event);
    }
    let book = leak(book);
    let r = verify_ledger(
        book.world.genesis,
        book.ledger.bytes(),
        &book.ledger.events,
        publications(),
    );
    assert!(
        r.index().ledger_holds().is_empty(),
        "{:?}",
        r.index().findings()
    );
    r
}

/// The report over the day with `uplink` after it.
fn verify(uplink: Vec<(SchemaId, &'static [u8])>) -> Report<'static> {
    verify_book(book_in(election_world()), uplink)
}

fn honest_links() -> Vec<Link> {
    day().links.clone()
}

fn scanner() -> Hash512 {
    link(day().links[SCANNER].key)
}

fn unit() -> Hash512 {
    link(day().links[UNIT].key)
}

/// The end of a link's stream when every object is in its first frame.
fn stream_len(l: &Link) -> u64 {
    u64::from(l.frames[0].payload_len)
}

/// The share packages of the day's scanner stream: one a record.
const PACKAGES: u64 = 3;

fn station<'r>(r: &'r Report<'static>) -> &'r StationUplink<'static> {
    r.connectivity().station(ST).unwrap()
}

fn sessions_found(r: &Report<'static>) -> Vec<(u32, SessionProblem)> {
    station(r)
        .findings
        .iter()
        .map(|f| (f.session_index, f.problem))
        .collect()
}

fn link_report<'r>(r: &'r Report<'static>, l: Hash512) -> &'r LinkReport<'static> {
    station(r)
        .links
        .iter()
        .find(|x| x.link_id_hash == l)
        .unwrap()
}

fn found(r: &Report<'static>, l: Hash512) -> Vec<LinkProblem> {
    link_report(r, l)
        .findings
        .iter()
        .map(|f| f.problem)
        .collect()
}

fn box_holds(r: &Report<'static>) -> HoldSet {
    r.connectivity().box_holds(B1.id)
}

/// The window of `slot` in the honest plan (six slots from 150).
fn window(slot: u64) -> Option<usize> {
    Some(((slot - 150) / 6) as usize)
}

/// A copy of `l`'s frame at `from`, changed by `change`, re-sealed and put
/// after every frame of its slot or an earlier one.
fn add(l: &mut Link, from: u64, change: impl FnOnce(&mut Built)) {
    let key = l.key;
    let mut f = l.frames.iter().find(|f| f.slot == from).unwrap().clone();
    change(&mut f);
    f.seal(key, link(key));
    let at = l
        .frames
        .iter()
        .rposition(|x| x.slot <= f.slot)
        .map_or(0, |p| p + 1);
    l.frames.insert(at, f);
}

/// `l`'s frame at `slot`, changed by `change` and re-sealed.
fn reseal(l: &mut Link, slot: u64, change: impl FnOnce(&mut Built)) {
    let key = l.key;
    let f = l.frames.iter_mut().find(|f| f.slot == slot).unwrap();
    change(f);
    f.seal(key, link(key));
}

/// The day's links with the scanner's stream (without share packages:
/// [`scanner_objects`]) cut into data frames: slot `s` of each `(s, from)`
/// carries the stream's bytes from `from` to the next cut (the last to the
/// end); every other frame carries none and starts where the data before
/// it end. Each frame lists the objects that overlap it.
fn cut_stream(cuts: &[(u64, usize)]) -> Vec<Link> {
    cut(with_stream(SCANNER, &scanner_objects()), SCANNER, cuts)
}

/// `links` with link `which`'s stream (all in its first frame) cut as
/// [`cut_stream`] does.
fn cut(mut links: Vec<Link>, which: usize, cuts: &[(u64, usize)]) -> Vec<Link> {
    let l = &mut links[which];
    let data = l.frames[0].data.clone();
    let mut offset = 0usize;
    for f in &mut l.frames {
        if let Some(i) = cuts.iter().position(|(s, _)| *s == f.slot) {
            let from = cuts[i].1;
            let to = cuts.get(i + 1).map_or(data.len(), |c| c.1);
            f.data = data[from..to].to_vec();
            f.payload_len = (to - from) as u32;
            f.stream_offset = from as u64;
            offset = to;
        } else {
            f.data = Vec::new();
            f.payload_len = 0;
            f.stream_offset = offset as u64;
        }
    }
    l.relist();
    links
}

/// The objects of the scanner's stream without packages ([`cut_stream`]).
fn cut_objects() -> Vec<StreamObject> {
    stream(&scanner_objects()).1
}

/// The scanner's link, one frame a slot from 150 to 212: slot `s` of each
/// `(s, offset, data, listed)` carries `data` from stream offset `offset`
/// and lists `listed` (the device signs what it lists); the slots in
/// `silent` send nothing; every other frame carries nothing and starts
/// where the data before it end.
fn scanner_frames(parts: &[(u64, u64, Vec<u8>, Vec<StreamObject>)], silent: &[u64]) -> Link {
    let key = day().links[SCANNER].key;
    let mut frames = Vec::new();
    let mut end = 0u64;
    for slot in 150..=212 {
        if silent.contains(&slot) {
            continue;
        }
        let (offset, data, objects) = parts.iter().find(|p| p.0 == slot).map_or_else(
            || (end, Vec::new(), Vec::new()),
            |p| (p.1, p.2.clone(), p.3.clone()),
        );
        let mut f = Built {
            slot,
            index: 0,
            kind: FrameKind::Normal,
            stream_offset: offset,
            payload_len: data.len() as u32,
            data,
            objects,
            fill: Vec::new(),
            payload_root: Hash512::ZERO,
            leaves: Vec::new(),
            sig: [0; 64],
        };
        f.seal(key, link(key));
        end = offset + u64::from(f.payload_len);
        frames.push(f);
    }
    Link {
        key,
        frames,
        objects: Vec::new(),
    }
}

/// Declares one missing slot of the scanner in session `session`.
fn declare_one(session: u32) -> impl Fn(u32, &mut SessionLink) {
    move |i: u32, e: &mut SessionLink| {
        if i == session && e.link_id_hash == scanner() {
            e.missing_slots = 1;
        }
    }
}

/// The device events of `filter` among the day's, in ledger order.
fn device_events(filter: (bool, &'static [u8])) -> Vec<&'static [u8]> {
    day()
        .events
        .iter()
        .map(|(_, e)| *e)
        .filter(|e| device_of(e) == Some(filter))
        .collect()
}

/// The scanner's stream, in order.
fn scanner_objects() -> Vec<&'static [u8]> {
    box_stream(&device_events((true, B1.id)))
}

/// U-1A's stream, in order.
fn unit_objects() -> Vec<&'static [u8]> {
    device_events((false, ST))
}

/// The day's links with the scanner's (or the unit's) stream replaced by
/// `objects`.
fn with_stream(which: usize, objects: &[&'static [u8]]) -> Vec<Link> {
    let mut links = honest_links();
    let l = &links[which];
    let first = l.frames[0].slot;
    let last = l.frames.last().unwrap().slot;
    links[which] = Link::new(l.key, objects, first, last, 1);
    links
}

// ---------------------------------------------------------------------------
// A clean uplink; the stage waits for every final session.

#[test]
fn a_clean_uplink_is_complete_and_includes_every_device_event() {
    let r = verify(Plan::new(ST, honest_links()).events());
    let c = r.connectivity();
    assert!(
        c.manifest_findings().is_empty(),
        "{:?}",
        c.manifest_findings()
    );
    assert!(c.complete());
    assert_eq!(c.holds(), HoldSet::empty());
    assert!(c.incidents().is_empty());
    // One entry per station of the genesis, the one the lookup finds.
    assert_eq!(c.stations().len(), 1);
    assert_eq!(c.stations()[0].station_id.as_bytes(), ST);
    let s = station(&r);
    assert_eq!(s.gateway_id.unwrap().as_bytes(), b"GW-ST-1");
    assert_eq!(s.sessions.len(), 11);
    assert_eq!(
        (s.sessions[0].start_slot, s.sessions[0].end_slot),
        (150, 155)
    );
    assert_eq!(
        (s.sessions[10].start_slot, s.sessions[10].end_slot),
        (210, 215)
    );
    assert!(s.sessions[10].is_final);
    assert!(s.sessions[..10].iter().all(|x| !x.is_final));
    assert_eq!(s.sessions[3].wan_bytes, 4000);
    assert_eq!(s.sessions[3].links, 2);
    assert_eq!(s.sessions[3].observers, 0);
    assert_eq!(s.final_session, Some(s.sessions[10].seq));
    assert!(s.findings.is_empty(), "{:?}", s.findings);
    assert_eq!(s.pending_logs, 0);
    assert!(s.outside.is_empty(), "{:?}", s.outside);
    assert_eq!(s.holds, HoldSet::empty());

    let l = &day().links[SCANNER];
    let data_chunks = stream_len(l).div_ceil(4096);
    let b = link_report(&r, scanner());
    assert_eq!(b.device, LinkDevice::Box(BoxId::new(B1.id).unwrap()));
    assert_eq!(
        (b.frames, b.catchup_frames, b.data_frames, b.missing_slots),
        (63, 0, 1, 0)
    );
    assert_eq!(b.slots, Some((150, 212)));
    assert_eq!(b.stream_end, stream_len(l));
    // The batch attestation, its three records each with its share
    // package, the closing tick; the five device events included.
    assert_eq!((b.objects, b.included), (8, 5));
    // Each package is in a chunk of its own, sealed; every other chunk is
    // recomputed from the ledger (the records' too).
    let packages: Vec<&StreamObject> = l
        .objects
        .iter()
        .filter(|o| o.schema == SCHEMA_SHARE_PACKAGE)
        .collect();
    assert_eq!(packages.len() as u64, PACKAGES);
    assert!(packages.iter().all(|p| p.stream_offset % 4096 == 0));
    assert_eq!(
        (b.checked_chunks, b.opaque_chunks),
        (data_chunks - PACKAGES, PACKAGES)
    );
    assert!(b.findings.is_empty(), "{:?}", b.findings);
    let u = link_report(&r, unit());
    assert_eq!(u.device, LinkDevice::Unit(UnitId::new(b"U-1A").unwrap()));
    assert_eq!((u.frames, u.slots), (63, Some((150, 212))));
    // The closing tick and the participation set.
    assert_eq!((u.objects, u.included), (2, 2));
    assert!(u.findings.is_empty(), "{:?}", u.findings);
    assert_eq!(r.evidence().step(Step::Connectivity), Outcome::Passed);
}

#[test]
fn the_stage_waits_for_every_gateways_final_session() {
    // No uplink at all: nothing is judged, nothing holds.
    let r = verify(Vec::new());
    assert!(!r.connectivity().complete());
    assert_eq!(r.connectivity().holds(), HoldSet::empty());
    let s = station(&r);
    assert!(s.gateway_id.is_some());
    assert!(s.sessions.is_empty());
    assert_eq!(s.final_session, None);
    assert!(s.outside.is_empty());
    assert_eq!(r.evidence().step(Step::Connectivity), Outcome::NotRun);

    // Every session but no final one: the frames are judged, inclusion is
    // not (the objects may still come).
    let not_final = |p: &mut UplinkSessionParts<'static>| p.is_final = false;
    let mut plan = Plan::new(ST, with_stream(SCANNER, &scanner_objects()[..4]));
    plan.tweak_body = Some(&not_final);
    let r = verify(plan.events());
    assert!(!r.connectivity().complete());
    let s = station(&r);
    assert_eq!(s.sessions.len(), 11);
    assert_eq!(s.final_session, None);
    assert!(s.findings.is_empty(), "{:?}", s.findings);
    assert!(s.outside.is_empty());
    assert_eq!(r.connectivity().holds(), HoldSet::empty());
    assert_eq!(r.evidence().step(Step::Connectivity), Outcome::NotRun);
}

// ---------------------------------------------------------------------------
// Sessions (VC-080).

#[test]
fn a_session_the_stations_gateway_did_not_sign_is_refused() {
    // Every session under another key.
    let mut plan = Plan::new(ST, honest_links());
    plan.gateway_key = Some(common::signing(common::ROSTER_BASE));
    let r = verify(plan.events());
    let found = sessions_found(&r);
    assert_eq!(found.len(), 11);
    assert!(found.iter().all(|(_, p)| *p == SessionProblem::Gateway));
    assert!(station(&r).sessions.is_empty());
    assert_eq!(station(&r).pending_logs, 0);
    assert!(!r.connectivity().complete());
    assert_eq!(box_holds(&r), only(HoldReason::UplinkSessionRefused));
    assert_eq!(station(&r).holds, only(HoldReason::UplinkSessionRefused));

    // The final session names a gateway the genesis does not register.
    let other = |p: &mut UplinkSessionParts<'static>| {
        if p.is_final {
            p.gateway_id = GatewayId::new(b"GW-ST-2").unwrap();
        }
    };
    let mut plan = Plan::new(ST, honest_links());
    plan.tweak_body = Some(&other);
    let r = verify(plan.events());
    assert_eq!(sessions_found(&r), [(11, SessionProblem::Gateway)]);
    assert_eq!(station(&r).final_session, None);
    assert_eq!(box_holds(&r), only(HoldReason::UplinkSessionRefused));
}

#[test]
fn observers_must_be_registered_at_the_station_and_sign_the_capture() {
    let mut plan = Plan::new(ST, honest_links());
    plan.observers = std::vec![
        (10, b"obs-a".as_slice(), b"PARTY-A".as_slice(), 2),
        (10, b"obs-b", b"PARTY-B", 3),
    ];
    let r = verify(plan.events());
    assert!(sessions_found(&r).is_empty(), "{:?}", sessions_found(&r));
    assert_eq!(station(&r).sessions[10].observers, 2);
    assert!(r.connectivity().complete());

    for bad in [
        // Another organisation.
        (10, b"obs-a".as_slice(), b"PARTY-B".as_slice(), 2u16),
        // Another observer's key.
        (10, b"obs-a", b"PARTY-A", 3),
        // A clerk.
        (10, b"clerk-1", b"ORG-ST", 0),
    ] {
        let mut plan = Plan::new(ST, honest_links());
        plan.observers = std::vec![bad];
        let r = verify(plan.events());
        assert_eq!(
            sessions_found(&r),
            [(11, SessionProblem::Observer)],
            "{bad:?}"
        );
        assert!(!r.connectivity().complete());
    }
}

#[test]
fn sessions_follow_one_another() {
    type Tweak = fn(&mut UplinkSessionParts<'static>);
    let cases: [(Tweak, (u32, SessionProblem)); 3] = [
        (
            |p| {
                if p.session_index == 11 {
                    p.session_index = 12;
                }
            },
            (12, SessionProblem::Order),
        ),
        (
            |p| {
                if p.session_index == 11 {
                    p.previous_session_hash = Hash512([1; 64]);
                }
            },
            (11, SessionProblem::Previous),
        ),
        (
            |p| {
                if p.session_index == 11 {
                    p.start_slot = 209;
                    p.end_slot = 214;
                }
            },
            (11, SessionProblem::Window),
        ),
    ];
    for (tweak, expected) in cases {
        let mut plan = Plan::new(ST, honest_links());
        plan.tweak_body = Some(&tweak);
        let r = verify(plan.events());
        assert_eq!(sessions_found(&r), [expected]);
        assert!(!r.connectivity().complete());
        assert_eq!(box_holds(&r), only(HoldReason::UplinkSessionRefused));
    }
    // A refused number leaves its logs for a session that never comes.
    let renumber = |p: &mut UplinkSessionParts<'static>| {
        if p.session_index == 11 {
            p.session_index = 12;
        }
    };
    let mut plan = Plan::new(ST, honest_links());
    plan.tweak_body = Some(&renumber);
    assert_eq!(station(&verify(plan.events())).pending_logs, 2);

    // A final session ends the gateway's record: the next is refused.
    let early_final = |p: &mut UplinkSessionParts<'static>| {
        if p.session_index == 10 {
            p.is_final = true;
        }
    };
    let mut plan = Plan::new(ST, honest_links());
    plan.tweak_body = Some(&early_final);
    let r = verify(plan.events());
    // The slots the devices sent in after it are in no session.
    assert_eq!(
        sessions_found(&r),
        [
            (10, SessionProblem::UndeclaredGap),
            (10, SessionProblem::UndeclaredGap),
            (11, SessionProblem::AfterFinal)
        ]
    );
    assert_eq!(station(&r).final_session, Some(station(&r).sessions[9].seq));
    assert!(r.connectivity().complete());
}

#[test]
fn a_session_lists_only_its_stations_links_with_their_logs() {
    // A link the genesis does not register.
    let stranger = |i: u32, e: &mut SessionLink| {
        if i == 11 && e.link_id_hash == scanner() {
            e.link_id_hash = link(999);
        }
    };
    let mut plan = Plan::new(ST, honest_links());
    plan.tweak_link = Some(&stranger);
    let r = verify(plan.events());
    assert_eq!(sessions_found(&r), [(11, SessionProblem::Link)]);

    // A link with frames whose log is not on the ledger.
    let mut events = Plan::new(ST, honest_links()).events();
    events.retain(|(s, e)| !(*s == SCHEMA_UPLINK_FRAME_LOG && log_key(e) == (11, scanner())));
    let r = verify(events);
    assert_eq!(sessions_found(&r), [(11, SessionProblem::LogMissing)]);

    // A log of the session for a link it does not list.
    let drop_scanner = |p: &mut UplinkSessionParts<'static>| {
        if p.session_index == 11 {
            let kept: Vec<u8> = p
                .links
                .iter()
                .filter(|l| l.link_id_hash != scanner())
                .flat_map(|l| {
                    let mut buf = std::vec![0u8; 156];
                    ityv_encoding::Encode::encode(&l, &mut ityv_encoding::Writer::new(&mut buf))
                        .unwrap();
                    buf
                })
                .collect();
            p.links = SessionLinks::new(leak_slice(kept)).unwrap();
        }
    };
    let mut plan = Plan::new(ST, honest_links());
    plan.tweak_body = Some(&drop_scanner);
    let r = verify(plan.events());
    assert_eq!(sessions_found(&r), [(11, SessionProblem::LogUnlisted)]);

    // A log of the session from another gateway.
    let mut events = Plan::new(ST, honest_links()).events();
    for (s, e) in &mut events {
        if *s == SCHEMA_UPLINK_FRAME_LOG && log_key(e) == (11, unit()) {
            *e = relog(e, |p| p.gateway_id = GatewayId::new(b"GW-ST-2").unwrap());
        }
    }
    let r = verify(events);
    assert_eq!(sessions_found(&r), [(11, SessionProblem::LogUnlisted)]);

    // A link of the station that sent nothing in the session needs no log:
    // its head and stream end stay where they were (the spare check-in
    // unit, never used).
    let spare = link(common::uplink::UNIT_FRAME_BASE + 1);
    let add_spare = |p: &mut UplinkSessionParts<'static>| {
        if p.session_index == 3 {
            let mut entries: Vec<SessionLink> = p.links.iter().collect();
            entries.push(SessionLink {
                link_id_hash: spare,
                frames: 0,
                catchup_frames: 0,
                missing_slots: 0,
                stream_end: 0,
                chain_head: ityv_crypto::uplink::chain_start(&spare),
            });
            entries.sort_by(|a, b| a.link_id_hash.as_bytes().cmp(b.link_id_hash.as_bytes()));
            let bytes: Vec<u8> = entries
                .iter()
                .flat_map(|l| {
                    let mut buf = std::vec![0u8; 156];
                    ityv_encoding::Encode::encode(l, &mut ityv_encoding::Writer::new(&mut buf))
                        .unwrap();
                    buf
                })
                .collect();
            p.links = SessionLinks::new(leak_slice(bytes)).unwrap();
        }
    };
    let mut plan = Plan::new(ST, honest_links());
    plan.tweak_body = Some(&add_spare);
    let r = verify(plan.events());
    assert!(sessions_found(&r).is_empty(), "{:?}", sessions_found(&r));
    assert_eq!(station(&r).sessions[2].links, 3);
    assert_eq!(r.connectivity().holds(), HoldSet::empty());
}

#[test]
fn a_log_is_taken_once_by_its_session() {
    let honest = Plan::new(ST, honest_links()).events();
    let first = honest
        .iter()
        .position(|(s, e)| *s == SCHEMA_UPLINK_FRAME_LOG && log_key(e) == (1, scanner()))
        .unwrap();
    let other = relog(honest[first].1, |p| {
        p.gateway_id = GatewayId::new(b"GW-ST-2").unwrap();
    });

    // A second log of the session and link: the first stands.
    let mut events = honest.clone();
    events.insert(first + 1, (SCHEMA_UPLINK_FRAME_LOG, other));
    let r = verify(events);
    assert_eq!(sessions_found(&r), [(1, SessionProblem::LogRepeated)]);
    assert_eq!(link_report(&r, scanner()).objects, 8);

    // A log of a session already taken.
    let mut events = honest.clone();
    events.push((SCHEMA_UPLINK_FRAME_LOG, other));
    let r = verify(events);
    assert_eq!(sessions_found(&r), [(1, SessionProblem::LogDangling)]);

    // A log after the final session.
    let mut events = honest.clone();
    events.push((
        SCHEMA_UPLINK_FRAME_LOG,
        relog(honest[first].1, |p| p.session_index = 12),
    ));
    let r = verify(events);
    assert_eq!(sessions_found(&r), [(12, SessionProblem::LogDangling)]);
    assert_eq!(station(&r).pending_logs, 0);
    assert_eq!(box_holds(&r), only(HoldReason::UplinkSessionRefused));
}

#[test]
fn a_session_must_agree_with_its_logs() {
    type Tweak = fn(u32, &mut SessionLink);
    let cases: [(Tweak, (u32, SessionProblem)); 5] = [
        (
            |i, e| {
                if i == 11 && e.link_id_hash == scanner() {
                    e.chain_head = Hash512([7; 64]);
                }
            },
            (11, SessionProblem::ChainHead),
        ),
        (
            |i, e| {
                if i == 1 && e.link_id_hash == scanner() {
                    e.frames += 1;
                }
            },
            (1, SessionProblem::Frames),
        ),
        (
            |i, e| {
                if i == 1 && e.link_id_hash == scanner() {
                    e.catchup_frames = 1;
                }
            },
            (1, SessionProblem::CatchupFrames),
        ),
        (
            |i, e| {
                if i == 1 && e.link_id_hash == scanner() {
                    e.stream_end += 1;
                }
            },
            (1, SessionProblem::StreamEnd),
        ),
        (
            |i, e| {
                if i == 1 && e.link_id_hash == scanner() {
                    e.missing_slots = 1;
                }
            },
            (1, SessionProblem::MissingSlots),
        ),
    ];
    for (tweak, (index, problem)) in cases {
        let mut plan = Plan::new(ST, honest_links());
        plan.tweak_link = Some(&tweak);
        let r = verify(plan.events());
        let s = station(&r);
        assert_eq!(s.findings.len(), 1, "{problem:?}: {:?}", s.findings);
        assert_eq!(s.findings[0].session_index, index);
        assert_eq!(s.findings[0].link, Some(scanner()));
        assert_eq!(s.findings[0].problem, problem);
        assert_eq!(box_holds(&r), only(HoldReason::UplinkSessionRefused));
    }
    // A chain head that does not agree: the log's frames are not taken.
    let tweak = |i: u32, e: &mut SessionLink| {
        if i == 11 && e.link_id_hash == scanner() {
            e.chain_head = Hash512([7; 64]);
        }
    };
    let mut plan = Plan::new(ST, honest_links());
    plan.tweak_link = Some(&tweak);
    let r = verify(plan.events());
    assert_eq!(link_report(&r, scanner()).frames, 60);
}

#[test]
fn a_lost_frame_is_a_missing_slot_the_session_declares() {
    let lose = |l: usize, f: &Built| {
        if l == SCANNER && f.slot == 152 {
            None
        } else {
            window(f.slot)
        }
    };
    // Undeclared.
    let mut plan = Plan::new(ST, honest_links());
    plan.assign = Some(&lose);
    let r = verify(plan.events());
    assert_eq!(sessions_found(&r), [(1, SessionProblem::MissingSlots)]);
    assert_eq!(link_report(&r, scanner()).missing_slots, 1);

    // Declared: clean. The lost frame carried nothing, so nothing skips.
    let declare = declare_one(1);
    let mut plan = Plan::new(ST, honest_links());
    plan.assign = Some(&lose);
    plan.tweak_link = Some(&declare);
    let r = verify(plan.events());
    assert!(sessions_found(&r).is_empty(), "{:?}", sessions_found(&r));
    let b = link_report(&r, scanner());
    assert!(b.findings.is_empty(), "{:?}", b.findings);
    assert_eq!((b.frames, b.missing_slots), (62, 1));
    assert_eq!(r.connectivity().holds(), HoldSet::empty());

    // The lost frame carried the closing tick: the stream after it starts
    // past the tick, and the tick, sent once, never arrives.
    let o = cut_objects();
    let mut plan = Plan::new(
        ST,
        cut_stream(&[(150, 0), (152, o[4].stream_offset as usize)]),
    );
    plan.assign = Some(&lose);
    plan.tweak_link = Some(&declare);
    let r = verify(plan.events());
    assert!(sessions_found(&r).is_empty(), "{:?}", sessions_found(&r));
    assert!(
        found(&r, scanner()).is_empty(),
        "{:?}",
        found(&r, scanner())
    );
    let outside: Vec<Hash512> = station(&r).outside.iter().map(|e| e.hash).collect();
    assert_eq!(outside, [o[4].object_hash]);
    assert_eq!(box_holds(&r), only(HoldReason::UplinkObjectOutside));

    // A skip is bounded by what the positions no frame took could carry: a
    // slot with no frame taken counts at its catch-up shape (two frames
    // here) of full payloads.
    let most = 2 * MAX_PAYLOAD_LEN as u64;
    for (skip, problems) in [(most, &[][..]), (most + 1, &[LinkProblem::Offset][..])] {
        let mut links = honest_links();
        let end = stream_len(&links[SCANNER]);
        for f in links[SCANNER].frames.iter_mut().filter(|f| f.slot > 152) {
            f.stream_offset = end + skip;
        }
        links[SCANNER].relist();
        let mut plan = Plan::new(ST, links);
        plan.assign = Some(&lose);
        plan.tweak_link = Some(&declare);
        let r = verify(plan.events());
        assert_eq!(found(&r, scanner()), problems, "{skip}");
    }
}

#[test]
fn slots_no_window_covers_are_an_undeclared_gap() {
    let mut plan = Plan::new(ST, honest_links());
    // No session covers slots 156 to 161; their frames are dropped.
    plan.windows.remove(1);
    let r = verify(plan.events());
    let s = station(&r);
    assert_eq!(s.sessions.len(), 10);
    let gaps: Vec<(u32, Option<Hash512>)> = s
        .findings
        .iter()
        .map(|f| {
            assert_eq!(f.problem, SessionProblem::UndeclaredGap);
            (f.session_index, f.link)
        })
        .collect();
    assert_eq!(gaps.len(), 2);
    assert!(gaps.contains(&(10, Some(scanner()))));
    assert!(gaps.contains(&(10, Some(unit()))));
    assert_eq!(link_report(&r, scanner()).missing_slots, 6);
    assert_eq!(box_holds(&r), only(HoldReason::UplinkSessionRefused));

    // The stream may skip across those slots: the data the scanner sent
    // in slot 157 never reached a session, and slot 162 starts after it.
    let o = cut_objects();
    let mut plan = Plan::new(
        ST,
        cut_stream(&[(150, 0), (157, o[1].stream_offset as usize)]),
    );
    plan.windows.remove(1);
    let r = verify(plan.events());
    assert!(
        found(&r, scanner()).is_empty(),
        "{:?}",
        found(&r, scanner())
    );
    assert_eq!(station(&r).outside.len(), 4);
    assert_eq!(
        box_holds(&r),
        only(HoldReason::UplinkSessionRefused).with(HoldReason::UplinkObjectOutside)
    );
}

#[test]
fn lost_frames_cut_the_received_stream() {
    let o = cut_objects();
    let lose = |l: usize, f: &Built| {
        if l == SCANNER && f.slot == 151 {
            None
        } else {
            window(f.slot)
        }
    };
    let declare = declare_one(1);
    // Slot 151's frame, lost, held the end of the batch attestation and
    // the start of the first record: both are listed (by the frames on
    // either side, which carry them out and in), neither lies whole in the
    // received stream.
    let cut = 1000usize;
    assert!((cut as u64) < o[1].stream_offset);
    let mut plan = Plan::new(
        ST,
        cut_stream(&[
            (150, 0),
            (151, cut),
            (152, o[1].stream_offset as usize + 10),
        ]),
    );
    plan.assign = Some(&lose);
    plan.tweak_link = Some(&declare);
    let r = verify(plan.events());
    assert!(sessions_found(&r).is_empty(), "{:?}", sessions_found(&r));
    assert!(
        found(&r, scanner()).is_empty(),
        "{:?}",
        found(&r, scanner())
    );
    // In ledger order: the record, then the batch attestation.
    let outside: Vec<Hash512> = station(&r).outside.iter().map(|e| e.hash).collect();
    assert_eq!(outside, [o[1].object_hash, o[0].object_hash]);
    let b = link_report(&r, scanner());
    assert_eq!((b.objects, b.included), (5, 3));
    assert_eq!(box_holds(&r), only(HoldReason::UplinkObjectOutside));

    // The loss takes the stream's tail: the frames after it carry nothing
    // and start at the stream's end, past what the lost frame carried.
    let mut plan = Plan::new(
        ST,
        cut_stream(&[(150, 0), (151, o[2].stream_offset as usize + 10)]),
    );
    plan.assign = Some(&lose);
    plan.tweak_link = Some(&declare);
    let r = verify(plan.events());
    assert!(sessions_found(&r).is_empty(), "{:?}", sessions_found(&r));
    assert!(
        found(&r, scanner()).is_empty(),
        "{:?}",
        found(&r, scanner())
    );
    assert_eq!(station(&r).outside.len(), 3);
}

// ---------------------------------------------------------------------------
// Frames (VC-078).

#[test]
fn a_frame_not_signed_by_its_devices_frame_key_is_invalid() {
    // A signature changed after signing.
    let mut links = honest_links();
    links[SCANNER].frames[3].sig[0] ^= 1;
    let r = verify(Plan::new(ST, links).events());
    assert_eq!(found(&r, scanner()), [LinkProblem::Signature]);
    assert_eq!(box_holds(&r), only(HoldReason::UplinkFrameInvalid));
    assert_eq!(station(&r).holds, only(HoldReason::UplinkFrameInvalid));

    // The unit's frame key on the scanner's frame.
    let mut links = honest_links();
    let unit_key = links[UNIT].key;
    links[SCANNER].frames[3].sign(unit_key, scanner());
    let r = verify(Plan::new(ST, links).events());
    assert_eq!(found(&r, scanner()), [LinkProblem::Signature]);

    // A data frame that does not verify carries nothing: its objects are
    // outside the received stream.
    let mut links = honest_links();
    links[SCANNER].frames[0].sig[5] ^= 1;
    let r = verify(Plan::new(ST, links).events());
    assert_eq!(found(&r, scanner()), [LinkProblem::Signature]);
    assert_eq!(station(&r).outside.len(), 5);
    assert_eq!(
        box_holds(&r),
        only(HoldReason::UplinkFrameInvalid).with(HoldReason::UplinkObjectOutside)
    );
}

#[test]
fn a_frame_beyond_its_slots_count_or_mixing_kinds_is_invalid() {
    // A second normal frame in a slot of one.
    let mut links = honest_links();
    add(&mut links[SCANNER], 160, |f| f.index = 1);
    let r = verify(Plan::new(ST, links).events());
    assert_eq!(found(&r, scanner()), [LinkProblem::Index]);
    assert!(sessions_found(&r).is_empty(), "{:?}", sessions_found(&r));
    assert_eq!(box_holds(&r), only(HoldReason::UplinkFrameInvalid));

    // A catch-up frame in a slot of normal frames (the close slot, where
    // the scanner may use its catch-up shape).
    let mut links = honest_links();
    add(&mut links[SCANNER], 212, |f| {
        f.kind = FrameKind::CatchUp;
        f.index = 1;
    });
    let r = verify(Plan::new(ST, links).events());
    assert_eq!(found(&r, scanner()), [LinkProblem::Shape]);
    assert!(sessions_found(&r).is_empty(), "{:?}", sessions_found(&r));

    // A whole slot of catch-up frames is a shape of its own.
    let mut links = honest_links();
    reseal(&mut links[SCANNER], 212, |f| f.kind = FrameKind::CatchUp);
    add(&mut links[SCANNER], 212, |f| f.index = 1);
    let r = verify(Plan::new(ST, links).events());
    assert!(
        found(&r, scanner()).is_empty(),
        "{:?}",
        found(&r, scanner())
    );
    assert!(sessions_found(&r).is_empty(), "{:?}", sessions_found(&r));
    assert_eq!(link_report(&r, scanner()).catchup_frames, 2);

    // Half a slot of catch-up frames is a missing slot.
    let mut links = honest_links();
    reseal(&mut links[SCANNER], 212, |f| f.kind = FrameKind::CatchUp);
    let r = verify(Plan::new(ST, links).events());
    assert!(
        found(&r, scanner()).is_empty(),
        "{:?}",
        found(&r, scanner())
    );
    assert_eq!(sessions_found(&r), [(11, SessionProblem::MissingSlots)]);
}

#[test]
fn a_frame_outside_its_window_or_its_boxs_day_is_invalid() {
    // Slot 156 in the session of slots 150 to 155.
    let early = |l: usize, f: &Built| {
        if l == SCANNER && f.slot == 156 {
            Some(0)
        } else {
            window(f.slot)
        }
    };
    let mut plan = Plan::new(ST, honest_links());
    plan.assign = Some(&early);
    let r = verify(plan.events());
    assert_eq!(found(&r, scanner()), [LinkProblem::Window]);
    assert!(sessions_found(&r).is_empty(), "{:?}", sessions_found(&r));

    // A frame before the box opened.
    let mut links = honest_links();
    add(&mut links[SCANNER], 151, |f| {
        f.slot = 149;
        f.stream_offset = 0;
    });
    let r = verify(Plan::new(ST, links).events());
    assert_eq!(found(&r, scanner()), [LinkProblem::BeforeOpening]);
    assert_eq!(box_holds(&r), only(HoldReason::UplinkFrameInvalid));

    // A unit frame before the station's first opening.
    let mut links = honest_links();
    add(&mut links[UNIT], 151, |f| {
        f.slot = 149;
        f.stream_offset = 0;
    });
    let r = verify(Plan::new(ST, links).events());
    assert_eq!(found(&r, unit()), [LinkProblem::BeforeOpening]);
    assert_eq!(box_holds(&r), only(HoldReason::UplinkFrameInvalid));

    // Normal frames up to the slot after the close (the closing tick's),
    // then only resends: from the close slot, which is a resend group.
    let mut links = honest_links();
    reseal(&mut links[SCANNER], 212, |f| {
        f.kind = FrameKind::CloseResend;
    });
    add(&mut links[SCANNER], 212, |f| f.index = 1);
    for index in 0..2 {
        add(&mut links[SCANNER], 211, |f| {
            f.slot = 213;
            f.index = index;
            f.kind = FrameKind::CloseResend;
        });
    }
    let r = verify(Plan::new(ST, links.clone()).events());
    assert!(
        found(&r, scanner()).is_empty(),
        "{:?}",
        found(&r, scanner())
    );
    assert!(sessions_found(&r).is_empty(), "{:?}", sessions_found(&r));
    assert_eq!(link_report(&r, scanner()).slots, Some((150, 213)));
    // A normal frame after them.
    add(&mut links[SCANNER], 211, |f| f.slot = 214);
    let r = verify(Plan::new(ST, links).events());
    assert_eq!(
        found(&r, scanner()),
        [LinkProblem::AfterClose, LinkProblem::KindOrder]
    );
}

#[test]
fn resends_come_last() {
    // A close resend in slot 200, before the close slot, and normal frames
    // after it: each frame is out of its kind's place.
    let mut links = honest_links();
    reseal(&mut links[SCANNER], 200, |f| {
        f.kind = FrameKind::CloseResend;
    });
    add(&mut links[SCANNER], 200, |f| f.index = 1);
    let r = verify(Plan::new(ST, links).events());
    let problems = found(&r, scanner());
    assert_eq!(problems.len(), 14);
    assert!(problems.iter().all(|p| *p == LinkProblem::KindOrder));

    // A witnessed resend of what never arrived (a slot of its own, two
    // frames: the catch-up shape, in a session that starts with it), then
    // a close resend.
    let mut links = witnessed_day(0, (220, 220), MAX_PAYLOAD_LEN);
    let r = run_witnessed(links.clone(), resend_windows(220), &[], 0);
    assert!(
        found(&r, scanner()).is_empty(),
        "{:?}",
        found(&r, scanner())
    );
    assert!(sessions_found(&r).is_empty(), "{:?}", sessions_found(&r));
    let end = links[SCANNER]
        .frames
        .iter()
        .map(|f| f.stream_offset + u64::from(f.payload_len))
        .max()
        .unwrap();
    for index in 0..2 {
        add(&mut links[SCANNER], 211, |f| {
            f.slot = 221;
            f.index = index;
            f.kind = FrameKind::CloseResend;
            f.stream_offset = end;
        });
    }
    let r = run_witnessed(links, resend_windows(220), &[], 0);
    assert_eq!(
        found(&r, scanner()),
        [LinkProblem::KindOrder, LinkProblem::KindOrder]
    );
}

/// The day's links with the scanner's frame of slot 150 (the whole
/// stream) to be lost on the line ([`run_witnessed`] drops and declares
/// it), and a witnessed resend of the whole stream in slots `slots`,
/// laid out from the stream's end plus `skip` with at most `capacity`
/// bytes a frame: what never arrived, sent again after the close.
fn witnessed_day(skip: u64, slots: (u64, u64), capacity: usize) -> Vec<Link> {
    let mut links = honest_links();
    let end = stream_len(&links[SCANNER]);
    add_witnessed(
        &mut links,
        &with_packages(&scanner_objects()),
        end + skip,
        slots,
        capacity,
    );
    links
}

/// The report over the day with `links`, the session windows `windows`
/// (the last one the witnessed resend's), the scanner's frame (150, 0) and
/// the frames `lose` lost on the line; the gateway declares slot 150
/// missing in session 1 and `declared` missing slots in the witnessed
/// resend's session.
fn run_witnessed(
    links: Vec<Link>,
    windows: Vec<(u64, u64)>,
    lose: &[(u64, u16)],
    declared: u32,
) -> Report<'static> {
    let last = windows.len() - 1;
    let file = windows.clone();
    let lose = lose.to_vec();
    let assign = move |l: usize, f: &Built| {
        let lost = (f.slot, f.index) == (150, 0) || lose.contains(&(f.slot, f.index));
        if l == SCANNER && lost {
            None
        } else if f.kind == FrameKind::WitnessedResend {
            Some(last)
        } else {
            file.iter().position(|(a, b)| *a <= f.slot && f.slot <= *b)
        }
    };
    let witnessed = u32::try_from(windows.len()).unwrap();
    let declare = move |i: u32, e: &mut SessionLink| {
        if e.link_id_hash == scanner() {
            e.missing_slots = if i == 1 {
                1
            } else if i == witnessed {
                declared
            } else {
                0
            };
        }
    };
    let mut plan = Plan::new(ST, links);
    plan.windows = windows;
    plan.assign = Some(&assign);
    plan.tweak_link = Some(&declare);
    verify(plan.events())
}

/// The honest plan's windows to slot 215, then one of six slots from
/// `first`: the gateway's session of a witnessed resend that starts in
/// slot `first`.
fn resend_windows(first: u64) -> Vec<(u64, u64)> {
    let mut windows: Vec<(u64, u64)> = (150..=210).step_by(6).map(|s| (s, s + 5)).collect();
    windows.push((first, first + 5));
    windows
}

/// A witnessed `CheckinUnitSwap` at ST-1: U-1A fails, the spare U-1B
/// reports from `at`.
fn checkin_swap(at: u64) -> (SchemaId, &'static [u8]) {
    unit_swap(b"U-1A", b"U-1B", at)
}

/// A witnessed `CheckinUnitSwap` at ST-1 of `failed` by `spare` at `at`.
fn unit_swap(failed: &[u8], spare: &[u8], at: u64) -> (SchemaId, &'static [u8]) {
    use ityv_encoding::{
        CheckinUnitSwapBody, CheckinUnitSwapParts, SCHEMA_CHECKIN_UNIT_SWAP_BODY, SCHEMA_VERSION_1,
        SCHEMA_WITNESSED_EVENT, StationId,
    };
    let body = CheckinUnitSwapBody::new(&CheckinUnitSwapParts {
        election_id: common::election(),
        station_id: StationId::new(ST).unwrap(),
        failed_unit: UnitId::new(leak_slice(failed.to_vec())).unwrap(),
        spare_unit: UnitId::new(leak_slice(spare.to_vec())).unwrap(),
        at_slot: at,
        confirmed: true,
        next_seq: 1,
        issued: 0,
        spoiled: 0,
        returned: 0,
    })
    .unwrap();
    let body = common::object(SCHEMA_CHECKIN_UNIT_SWAP_BODY, SCHEMA_VERSION_1, &body);
    (SCHEMA_WITNESSED_EVENT, witnessed(body, &PEOPLE))
}

/// The day's ledger in `world` with `amendment` and a witnessed swap at
/// slot `at` laid while BOX-1 is open: its tick of slot 150 (casting),
/// the amendment and the swap, its closing tick of slot `at` and its
/// close, then the station's record.
fn book_swapped(world: &'static World, amendment: &'static [u8], at: u64) -> Book {
    use ityv_encoding::BoxProgressState;
    let mut book = Book::new(world);
    let events = &day().events;
    let close = events
        .iter()
        .position(|(s, _)| *s == ityv_encoding::SCHEMA_BOX_CLOSE)
        .unwrap();
    for (schema, event) in &events[..close] {
        book.push(*schema, event);
    }
    book.push(
        SCHEMA_PROGRESS_TICK,
        box_tick_in(150, BoxProgressState::Casting),
    );
    book.push(ityv_encoding::SCHEMA_SIGNED_GENESIS, amendment);
    let (schema, event) = box_swap(at);
    book.push(schema, event);
    book.push(
        SCHEMA_PROGRESS_TICK,
        box_tick_in(at, BoxProgressState::Closed),
    );
    let ours = scanner_objects();
    for (schema, event) in &events[close..] {
        // The day's own closing tick of BOX-1 is replaced by the one above.
        if *schema == SCHEMA_PROGRESS_TICK && ours.contains(event) {
            continue;
        }
        book.push(*schema, event);
    }
    book
}

/// A witnessed `BoxUnitSwap` of BOX-1: the spare scanner reports from
/// `at`.
fn box_swap(at: u64) -> (SchemaId, &'static [u8]) {
    use ityv_encoding::{
        BoxUnitSwapBody, BoxUnitSwapParts, SCHEMA_BOX_UNIT_SWAP_BODY, SCHEMA_VERSION_1,
        SCHEMA_WITNESSED_EVENT,
    };
    let body = BoxUnitSwapBody::new(&BoxUnitSwapParts {
        election_id: common::election(),
        box_id: BoxId::new(B1.id).unwrap(),
        at_slot: at,
        confirmed: true,
        sheets_in: 3,
    })
    .unwrap();
    let body = common::object(SCHEMA_BOX_UNIT_SWAP_BODY, SCHEMA_VERSION_1, &body);
    (SCHEMA_WITNESSED_EVENT, witnessed(body, &PEOPLE))
}

/// The link report of frame key `key`.
fn report_of(r: &Report<'static>, key: u16) -> LinkReport<'static> {
    link_report(r, link(key)).clone()
}

#[test]
fn a_device_sends_from_the_opening_or_its_swap_to_the_close_or_its_swap() {
    // U-1A fails and the spare takes over at slot 181 (a witnessed swap):
    // U-1A sends from the opening to slot 180, the spare from slot 181 to
    // the close. Each link's slots are its own, none missing.
    let world = election_world();
    let spare_key =
        common::uplink::key_number(world.genesis.station(ST).unwrap().spare().frame_key);
    let swapped = |last_old: u64| {
        let mut book = book_in(world);
        let (schema, event) = checkin_swap(181);
        book.push(schema, event);
        let mut links = honest_links();
        links[UNIT].frames.retain(|f| f.slot <= last_old);
        links.push(Link {
            key: spare_key,
            frames: common::uplink::frames(spare_key, &[], 181, 212, 1),
            objects: Vec::new(),
        });
        verify_book(book, Plan::new(ST, links).events())
    };
    let r = swapped(180);
    assert!(sessions_found(&r).is_empty(), "{:?}", sessions_found(&r));
    for (l, frames) in [
        (report_of(&r, spare_key), 32),
        (link_report(&r, unit()).clone(), 31),
    ] {
        assert!(l.findings.is_empty(), "{:?}", l.findings);
        assert_eq!((l.frames, l.missing_slots), (frames, 0));
    }
    assert_eq!(r.connectivity().holds(), HoldSet::empty());
    // The old unit may still send in the swap's slot, not after it.
    let r = swapped(181);
    assert!(found(&r, unit()).is_empty(), "{:?}", found(&r, unit()));
    let r = swapped(183);
    assert_eq!(found(&r, unit()), [LinkProblem::AfterSwap; 2]);
    assert!(
        r.connectivity()
            .box_holds(B1.id)
            .contains(HoldReason::UplinkFrameInvalid)
    );
    // A later swap that takes the spare out ends its slots too (a spare is
    // used once: the unit it replaced does not come back).
    let mut book = book_in(world);
    for (failed, spare, at) in [(&b"U-1A"[..], &b"U-1B"[..], 181), (b"U-1B", b"U-1A", 200)] {
        book.push(
            ityv_encoding::SCHEMA_WITNESSED_EVENT,
            unit_swap(failed, spare, at).1,
        );
    }
    let mut links = honest_links();
    links[UNIT].frames.retain(|f| f.slot <= 180);
    links.push(Link {
        key: spare_key,
        frames: common::uplink::frames(spare_key, &[], 181, 212, 1),
        objects: Vec::new(),
    });
    let r = verify_book(book, Plan::new(ST, links).events());
    let spare = report_of(&r, spare_key);
    assert_eq!(spare.missing_slots, 0);
    assert_eq!(
        spare.findings.iter().map(|f| f.problem).collect::<Vec<_>>(),
        [LinkProblem::AfterSwap; 12]
    );
    assert!(found(&r, unit()).is_empty(), "{:?}", found(&r, unit()));

    // A spare that sends with no swap on the ledger is measured from the
    // station's opening: the slots it did not send in are missing slots.
    let mut links = honest_links();
    links.push(Link {
        key: spare_key,
        frames: common::uplink::frames(spare_key, &[], 181, 200, 1),
        objects: Vec::new(),
    });
    let r = verify(Plan::new(ST, links).events());
    assert_eq!(report_of(&r, spare_key).missing_slots, 31);
    assert_eq!(
        sessions_found(&r),
        (1..=6)
            .map(|i| (i, SessionProblem::MissingSlots))
            .collect::<Vec<_>>()
    );

    // An amendment and a witnessed swap at slot 181 replace BOX-1's
    // scanner: the old frame key sends from the opening to slot 180, the
    // new one from slot 181 to the close; each link's slots are its own,
    // and the box's stream travels the new one.
    let new_key = common::uplink::BOX_FRAME_BASE + 50;
    let (w, amendment) = leak(election_amended(|d| {
        d.boxes[0].frame_key = common::uplink::frame_key(new_key);
    }));
    let mut book = book_in(w);
    book.push(ityv_encoding::SCHEMA_SIGNED_GENESIS, amendment);
    let (schema, event) = box_swap(181);
    book.push(schema, event);
    let old_key = day().links[SCANNER].key;
    let mut links = honest_links();
    links[SCANNER] = Link::new(new_key, &with_packages(&scanner_objects()), 181, 212, 1);
    links.push(Link {
        key: old_key,
        frames: common::uplink::frames(old_key, &[], 150, 180, 1),
        objects: Vec::new(),
    });
    let r = verify_book(book, Plan::new(ST, links).events());
    assert!(sessions_found(&r).is_empty(), "{:?}", sessions_found(&r));
    for (key, frames) in [(old_key, 31), (new_key, 32)] {
        let l = report_of(&r, key);
        assert!(l.findings.is_empty(), "{:?}", l.findings);
        assert_eq!((l.frames, l.missing_slots), (frames, 0), "{key}");
    }
    assert!(station(&r).outside.is_empty());
    assert_eq!(r.connectivity().holds(), HoldSet::empty());
    // The old scanner fell silent at slot 175: to the swap's slot, its
    // silent slots are missing slots.
    let mut book = book_in(w);
    book.push(ityv_encoding::SCHEMA_SIGNED_GENESIS, amendment);
    let (schema, event) = box_swap(181);
    book.push(schema, event);
    let mut links = honest_links();
    links[SCANNER] = Link::new(new_key, &with_packages(&scanner_objects()), 181, 212, 1);
    links.push(Link {
        key: old_key,
        frames: common::uplink::frames(old_key, &[], 150, 175, 1),
        objects: Vec::new(),
    });
    let r = verify_book(book, Plan::new(ST, links).events());
    assert_eq!(report_of(&r, old_key).missing_slots, 5);
}

#[test]
fn the_stream_runs_on_from_zero_without_a_gap() {
    // A frame that starts past the previous one's end with no slot lost.
    let mut links = honest_links();
    let end = stream_len(&links[SCANNER]);
    reseal(&mut links[SCANNER], 160, |f| f.stream_offset = end + 5);
    let r = verify(Plan::new(ST, links).events());
    // It skips, and the next goes back.
    assert_eq!(
        found(&r, scanner()),
        [LinkProblem::Offset, LinkProblem::Offset]
    );
    assert_eq!(box_holds(&r), only(HoldReason::UplinkFrameInvalid));

    // A stream that does not start at zero, though no frame before the
    // first was lost.
    let mut links = honest_links();
    for f in &mut links[UNIT].frames {
        f.stream_offset += 1;
    }
    for o in &mut links[UNIT].objects {
        o.stream_offset += 1;
    }
    links[UNIT].relist();
    let r = verify(Plan::new(ST, links).events());
    assert_eq!(found(&r, unit()), [LinkProblem::Offset]);
}

#[test]
fn a_frame_proves_its_fill_zero_and_its_public_chunks() {
    // A nonzero byte after the data: the published leaves do not give the
    // signed root.
    let mut links = honest_links();
    reseal(&mut links[SCANNER], 151, |f| f.fill = std::vec![(100, 1)]);
    let r = verify(Plan::new(ST, links).events());
    assert_eq!(found(&r, scanner()), [LinkProblem::Fill]);
    assert_eq!(box_holds(&r), only(HoldReason::UplinkFrameInvalid));

    // The same in the data's own last chunk, past the data.
    let mut links = honest_links();
    let at = stream_len(&links[SCANNER]) as usize;
    reseal(&mut links[SCANNER], 150, |f| f.fill = std::vec![(at, 1)]);
    let r = verify(Plan::new(ST, links).events());
    assert_eq!(found(&r, scanner()), [LinkProblem::Chunk]);

    // Data that are not the ledger's objects, signed as sent.
    let mut links = honest_links();
    reseal(&mut links[SCANNER], 150, |f| f.data[20] ^= 1);
    let r = verify(Plan::new(ST, links).events());
    assert_eq!(found(&r, scanner()), [LinkProblem::Chunk]);
    assert_eq!(
        box_holds(&r),
        only(HoldReason::UplinkFrameInvalid).with(HoldReason::UplinkObjectOutside)
    );

    // A nonzero byte in the fill before a share package lies in a chunk of
    // public bytes: recomputed, it does not match. In the fill after a
    // package it lies in the package's sealed chunk: only a tap sees it
    // (`a_capture_shows_bytes_that_are_not_the_published_objects`).
    let package = day().links[SCANNER]
        .objects
        .iter()
        .find(|o| o.schema == SCHEMA_SHARE_PACKAGE)
        .copied()
        .unwrap();
    let before = package.stream_offset as usize - 1;
    let after = (package.stream_offset + u64::from(package.len)) as usize;
    let mut links = honest_links();
    assert_eq!(links[SCANNER].frames[0].data[before], 0);
    reseal(&mut links[SCANNER], 150, |f| f.data[before] = 1);
    let r = verify(Plan::new(ST, links).events());
    assert_eq!(found(&r, scanner()), [LinkProblem::Chunk]);
    let mut links = honest_links();
    assert_eq!(links[SCANNER].frames[0].data[after], 0);
    reseal(&mut links[SCANNER], 150, |f| f.data[after] = 1);
    let r = verify(Plan::new(ST, links).events());
    assert!(
        found(&r, scanner()).is_empty(),
        "{:?}",
        found(&r, scanner())
    );
    assert_eq!(r.connectivity().holds(), HoldSet::empty());
}

/// The number of 4 KiB chunks `[start, end)` touches.
fn chunks_of(start: u64, end: u64) -> u64 {
    (end - 1) / 4096 - start / 4096 + 1
}

#[test]
fn a_chunk_is_checked_only_against_objects_that_tile_it() {
    let l = &day().links[SCANNER];
    let all = stream_len(l).div_ceil(4096);
    // The device lists its closing tick under another schema it may send:
    // the ledger names that hash as a tick, so the listing is a finding of
    // its own (review 2 of 2i, A); the chunks that hold it are not checked
    // against the ledger's bytes, and the tick is not received.
    let tick = *l.objects.last().unwrap();
    let mut links = honest_links();
    reseal(&mut links[SCANNER], 150, |f| {
        f.objects.last_mut().unwrap().schema = ityv_encoding::SCHEMA_CHALLENGE_OPENING;
    });
    let r = verify(Plan::new(ST, links).events());
    assert_eq!(found(&r, scanner()), [LinkProblem::Schema]);
    assert_eq!(
        box_holds(&r),
        only(HoldReason::UplinkObjectInvalid).with(HoldReason::UplinkObjectOutside)
    );
    let b = link_report(&r, scanner());
    let held = chunks_of(tick.stream_offset, tick.stream_offset + u64::from(tick.len));
    assert_eq!(
        (b.checked_chunks, b.opaque_chunks),
        (all - PACKAGES - held, PACKAGES + held)
    );
    assert_eq!(station(&r).outside.len(), 1);
    assert_eq!(station(&r).outside[0].hash, tick.object_hash);
}

// ---------------------------------------------------------------------------
// Objects (VC-079).

#[test]
fn a_device_sends_only_the_kinds_it_may() {
    // The unit carries a witnessed event that is not an observer count.
    let issuance = day()
        .events
        .iter()
        .find(|(s, e)| {
            *s == ityv_encoding::SCHEMA_WITNESSED_EVENT
                && ityv_encoding::decode_object::<ityv_encoding::WitnessedEvent<'_>>(
                    *s,
                    ityv_encoding::SCHEMA_VERSION_WITNESSED,
                    e,
                )
                .unwrap()
                .body_schema()
                    == ityv_encoding::SCHEMA_ISSUANCE_COUNT_BODY
        })
        .unwrap()
        .1;
    let mut objects = unit_objects();
    objects.push(issuance);
    let r = verify(Plan::new(ST, with_stream(UNIT, &objects)).events());
    assert_eq!(found(&r, unit()), [LinkProblem::Kind]);
    assert_eq!(box_holds(&r), only(HoldReason::UplinkObjectInvalid));

    // The scanner carries the station's participation set: a kind it may
    // not send, and another device's object.
    let mut objects = scanner_objects();
    objects.push(unit_objects()[1]);
    let r = verify(Plan::new(ST, with_stream(SCANNER, &objects)).events());
    assert_eq!(
        found(&r, scanner()),
        [LinkProblem::Kind, LinkProblem::Foreign]
    );
    // It is on U-1A's link too: included there.
    assert!(station(&r).outside.is_empty());

    // A manifest whose check-in unit link carries nothing: the unit's tick
    // and participation set are kinds it may send but not on that link.
    let mut entries = common::uplink::standard_entries();
    for e in &mut entries {
        if e.device_class == DeviceClass::CheckinUnit && e.frames_per_slot > 0 {
            e.carries = 0;
        }
    }
    let r = verify_book(
        book_in(manifest_world(common::uplink::manifest(&entries))),
        Plan::new(ST, honest_links()).events(),
    );
    assert!(r.connectivity().manifest_findings().is_empty());
    assert_eq!(found(&r, unit()), [LinkProblem::Kind, LinkProblem::Kind]);
    assert!(found(&r, scanner()).is_empty());
}

#[test]
fn objects_tile_the_received_stream() {
    // The device's own list, signed, leaves bytes uncovered or lists
    // objects outside its data. The frame's chunks are then not
    // recomputed: none of its objects counts as received.
    type Change = fn(&mut Vec<StreamObject>);
    let cases: [(Change, &[LinkProblem], usize); 3] = [
        // A record left out: its bytes belong to no object, and the next
        // record, with no byte lost between, is not the one after the
        // last in its batch.
        (
            |o| {
                o.remove(2);
            },
            &[LinkProblem::NotObject, LinkProblem::Batch],
            5,
        ),
        // The last object left out.
        (
            |o| {
                o.pop();
            },
            &[LinkProblem::NotObject],
            5,
        ),
        // A length that is not the ledger's: the byte after it is no
        // object, and the chunks holding it are not checked.
        (
            |o| o.last_mut().unwrap().len -= 1,
            &[LinkProblem::Length, LinkProblem::NotObject],
            5,
        ),
    ];
    for (change, problems, outside) in cases {
        let mut links = with_stream(SCANNER, &scanner_objects());
        reseal(&mut links[SCANNER], 150, |f| change(&mut f.objects));
        let r = verify(Plan::new(ST, links).events());
        let mut got = found(&r, scanner());
        got.sort_by_key(|p| *p as u8);
        let mut want = problems.to_vec();
        want.sort_by_key(|p| *p as u8);
        assert_eq!(got, want);
        assert_eq!(station(&r).outside.len(), outside);
        assert!(box_holds(&r).contains(HoldReason::UplinkObjectInvalid));
    }

    // A frame without data that lists the closing tick: an entry outside
    // its data.
    let mut links = honest_links();
    let tick = *links[SCANNER].objects.last().unwrap();
    reseal(&mut links[SCANNER], 151, |f| f.objects.push(tick));
    let r = verify(Plan::new(ST, links).events());
    assert_eq!(found(&r, scanner()), [LinkProblem::NotObject]);
    assert_eq!(box_holds(&r), only(HoldReason::UplinkObjectInvalid));

    // Two frames list different objects where one carries out what the
    // next carries in.
    let o = cut_objects();
    let mut links = cut_stream(&[(150, 0), (151, 1000)]);
    reseal(&mut links[SCANNER], 151, |f| {
        f.objects[0].object_hash = Hash512([9; 64]);
    });
    let r = verify(Plan::new(ST, links).events());
    assert_eq!(found(&r, scanner()), [LinkProblem::Overlap]);
    // The second frame's chunks name an object the ledger does not have:
    // not recomputed, so the batch in them is not received.
    assert_eq!(station(&r).outside.len(), 4);
    // The next frame starts inside an object the frame before carries out,
    // with another object (of that hash, so of another length too): an
    // attestation again, before any record of the first.
    let mut links = cut_stream(&[(150, 0), (151, 1000)]);
    reseal(&mut links[SCANNER], 151, |f| {
        f.objects[0].stream_offset = 1000;
        f.objects[0].len = o[0].len - 1000;
    });
    let r = verify(Plan::new(ST, links).events());
    assert_eq!(
        found(&r, scanner()),
        [
            LinkProblem::Overlap,
            LinkProblem::Length,
            LinkProblem::Batch
        ]
    );
    // Or past the end of an object the frame before ends with, starting
    // before the frame.
    let mut links = cut_stream(&[(150, 0), (151, o[1].stream_offset as usize)]);
    reseal(&mut links[SCANNER], 151, |f| {
        f.objects.insert(
            0,
            StreamObject {
                stream_offset: o[1].stream_offset - 16,
                len: 16,
                ..o[0]
            },
        );
        f.objects[1].stream_offset = o[1].stream_offset;
    });
    let r = verify(Plan::new(ST, links).events());
    assert!(found(&r, scanner()).contains(&LinkProblem::Overlap));
}

#[test]
fn records_travel_in_closed_batches_and_packages_after_their_records() {
    // A record before its batch attestation: outside every run, and the
    // run after the attestation does not start at the batch's first
    // record.
    let o = scanner_objects();
    let r = verify(Plan::new(ST, with_stream(SCANNER, &[o[1], o[0], o[2], o[3], o[4]])).events());
    assert_eq!(
        found(&r, scanner()),
        [LinkProblem::Batch, LinkProblem::Batch]
    );
    assert_eq!(box_holds(&r), only(HoldReason::UplinkObjectInvalid));

    // Records out of record-hash order: none where the batch puts it, and
    // the run ends before the batch's last record.
    let r = verify(Plan::new(ST, with_stream(SCANNER, &[o[0], o[3], o[2], o[1], o[4]])).events());
    assert_eq!(found(&r, scanner()), [LinkProblem::Batch; 4]);

    // A share package right after the batch attestation, not after a
    // record, and named by no record: sealed in a chunk of its own.
    let package = fake_object(SCHEMA_SHARE_PACKAGE, &[0x5A; 64]);
    let mut stream = with_packages(&o);
    stream.insert(1, package);
    let r = verify(Plan::new(ST, with_stream(SCANNER, &stream)).events());
    assert_eq!(
        found(&r, scanner()),
        [LinkProblem::Package, LinkProblem::NotOnLedger]
    );
    assert_eq!(link_report(&r, scanner()).opaque_chunks, PACKAGES + 1);

    // Each record's own share package right after it: sealed, not on the
    // ledger, but named by the box's record. The records' chunks hold no
    // sealed byte: they are recomputed from the ledger, and the records are
    // included because they were.
    let stream = with_packages(&o);
    let r = verify(Plan::new(ST, with_stream(SCANNER, &stream)).events());
    assert!(
        found(&r, scanner()).is_empty(),
        "{:?}",
        found(&r, scanner())
    );
    assert!(station(&r).outside.is_empty());
    let b = link_report(&r, scanner());
    let data_chunks = stream_len(&with_stream(SCANNER, &stream)[SCANNER]).div_ceil(4096);
    assert_eq!(
        (b.checked_chunks, b.opaque_chunks, b.included),
        (data_chunks - PACKAGES, PACKAGES, 5)
    );
    // The same with the last two packages swapped: each follows a record
    // that names the other.
    let swapped = [
        stream[0], stream[1], stream[2], stream[3], stream[6], stream[5], stream[4], stream[7],
    ];
    let r = verify(Plan::new(ST, with_stream(SCANNER, &swapped)).events());
    assert_eq!(
        found(&r, scanner()),
        [LinkProblem::Package, LinkProblem::Package]
    );
}

#[test]
fn every_received_object_is_on_the_ledger_once_the_gateway_closed() {
    let extra = fake_object(SCHEMA_PROGRESS_TICK, &[0x33; 40]);
    let mut objects = scanner_objects();
    objects.push(extra);
    let r = verify(Plan::new(ST, with_stream(SCANNER, &objects)).events());
    assert_eq!(found(&r, scanner()), [LinkProblem::NotOnLedger]);
    // The closing tick shares a chunk with it: not received as far as the
    // public can tell.
    assert_eq!(
        box_holds(&r),
        only(HoldReason::UplinkObjectInvalid).with(HoldReason::UplinkObjectOutside)
    );

    // Before the final session it may still come.
    let not_final = |p: &mut UplinkSessionParts<'static>| p.is_final = false;
    let mut plan = Plan::new(ST, with_stream(SCANNER, &objects));
    plan.tweak_body = Some(&not_final);
    let r = verify(plan.events());
    assert!(found(&r, scanner()).is_empty());
}

// ---------------------------------------------------------------------------
// Inclusion (VC-080).

#[test]
fn every_device_event_lies_in_its_devices_link() {
    // The scanner never sent its closing tick.
    let o = scanner_objects();
    let r = verify(Plan::new(ST, with_stream(SCANNER, &o[..4])).events());
    let s = station(&r);
    assert_eq!(s.outside.len(), 1);
    assert_eq!(s.outside[0].schema, SCHEMA_PROGRESS_TICK);
    assert_eq!(s.outside[0].hash, ityv_crypto::object_hash(o[4]));
    assert_eq!(link_report(&r, scanner()).included, 4);
    assert_eq!(box_holds(&r), only(HoldReason::UplinkObjectOutside));
    assert_eq!(s.holds, only(HoldReason::UplinkObjectOutside));

    // The unit sent it instead: another device's object on the unit's
    // link, and still outside the box's.
    let mut links = with_stream(SCANNER, &o[..4]);
    let mut unit_stream = unit_objects();
    unit_stream.push(o[4]);
    let l = &links[UNIT];
    links[UNIT] = Link::new(l.key, &unit_stream, 150, 212, 1);
    let r = verify(Plan::new(ST, links).events());
    assert_eq!(found(&r, unit()), [LinkProblem::Foreign]);
    assert_eq!(station(&r).outside.len(), 1);
    assert_eq!(link_report(&r, unit()).included, 2);

    // The participation set was never sent: the station's boxes hold.
    let r = verify(Plan::new(ST, with_stream(UNIT, &unit_objects()[..1])).events());
    assert_eq!(station(&r).outside.len(), 1);
    assert_eq!(station(&r).outside[0].schema, SCHEMA_PARTICIPATION_SET);
    assert_eq!(box_holds(&r), only(HoldReason::UplinkObjectOutside));
}

// ---------------------------------------------------------------------------
// The review of 2i: each finding's regression.

#[test]
fn c1_covert_bytes_next_to_a_skipped_slot_are_no_object() {
    // The device sends the batch and 3,000 bytes that are no object in
    // slot 150, nothing in slot 151, and the closing tick one byte past
    // the covert bytes in slot 152. The gateway is honest: it declares slot
    // 151 missing.
    let o = scanner_objects();
    let (head, listed) = stream(&o[..4]);
    let tick = o[4];
    let declare = declare_one(1);
    let send = |f150: Vec<u8>, l150: Vec<StreamObject>, at152: u64| {
        let mut links = honest_links();
        links[SCANNER] = scanner_frames(
            &[
                (150, 0, f150, l150),
                (152, at152, tick.to_vec(), std::vec![entry_at(tick, at152)]),
            ],
            &[151],
        );
        let mut plan = Plan::new(ST, links);
        plan.tweak_link = Some(&declare);
        verify(plan.events())
    };
    // The covert bytes listed as nothing: no object covers them.
    let mut f150 = head.clone();
    f150.extend_from_slice(&[0xC5; 3000]);
    let r = send(f150.clone(), listed.clone(), f150.len() as u64 + 1);
    assert!(sessions_found(&r).is_empty(), "{:?}", sessions_found(&r));
    let problems = found(&r, scanner());
    assert!(problems.contains(&LinkProblem::NotObject), "{problems:?}");
    assert!(!problems.contains(&LinkProblem::Offset), "{problems:?}");
    assert!(box_holds(&r).contains(HoldReason::UplinkObjectInvalid));

    // Listed as an object the device made up: no ledger frame names it.
    let covert = fake_object(SCHEMA_PROGRESS_TICK, &[0xC5; 2984]);
    let mut f150 = head.clone();
    f150.extend_from_slice(covert);
    let mut l150 = listed.clone();
    l150.push(entry_at(covert, head.len() as u64));
    let r = send(f150.clone(), l150.clone(), f150.len() as u64 + 1);
    assert_eq!(found(&r, scanner()), [LinkProblem::NotOnLedger]);
    // The record before it shares a chunk with bytes the ledger does not
    // show: it is not received as far as the public can tell.
    assert_eq!(
        box_holds(&r),
        only(HoldReason::UplinkObjectInvalid).with(HoldReason::UplinkObjectOutside)
    );

    // The skip itself is bounded: past what slot 151 could carry (its
    // catch-up shape, two frames, of full payloads) it is a finding.
    let r = send(
        f150.clone(),
        l150,
        f150.len() as u64 + 2 * MAX_PAYLOAD_LEN as u64 + 1,
    );
    assert_eq!(
        found(&r, scanner()),
        [LinkProblem::Offset, LinkProblem::NotOnLedger]
    );
}

/// Adds to the scanner's link a witnessed resend of `objects` in slots
/// `first..=last`, the catch-up shape (two frames) each, laid out as an
/// honest device would from stream offset `at` with at most `capacity`
/// bytes a frame.
fn add_witnessed(
    links: &mut [Link],
    objects: &[&'static [u8]],
    at: u64,
    (first, last): (u64, u64),
    capacity: usize,
) {
    let key = links[SCANNER].key;
    let count = ((last - first + 1) * 2) as usize;
    let (bytes, mut listed, spans) = common::uplink::layout(objects, capacity, count);
    for o in &mut listed {
        o.stream_offset += at;
    }
    for (k, (offset, len)) in spans.into_iter().enumerate() {
        let from = offset as usize;
        let mut f = Built {
            slot: first + (k / 2) as u64,
            index: (k % 2) as u16,
            kind: FrameKind::WitnessedResend,
            stream_offset: at + offset,
            payload_len: len,
            data: bytes[from..from + len as usize].to_vec(),
            objects: common::uplink::overlapping(&listed, at + offset, len),
            fill: Vec::new(),
            payload_root: Hash512::ZERO,
            leaves: Vec::new(),
            sig: [0; 64],
        };
        f.seal(key, link(key));
        links[SCANNER].frames.push(f);
    }
}

#[test]
fn c1_a_witnessed_resend_skips_only_where_a_frame_was_lost() {
    // The frame of slot 150, which held the whole stream, was lost and
    // declared; every frame after it arrived. The gateway's session of a
    // witnessed resend of the stream starts with it, in slot 220. Starting
    // past the stream's end skips where no position went untaken.
    let run = |skip: u64, from: u64, declared: u32| {
        run_witnessed(
            witnessed_day(skip, (220, 220), MAX_PAYLOAD_LEN),
            resend_windows(from),
            &[],
            declared,
        )
    };
    let r = run(0, 220, 0);
    assert!(
        found(&r, scanner()).is_empty(),
        "{:?}",
        found(&r, scanner())
    );
    assert!(sessions_found(&r).is_empty(), "{:?}", sessions_found(&r));
    assert_eq!(r.connectivity().holds(), HoldSet::empty());
    let r = run(100, 220, 0);
    assert_eq!(found(&r, scanner()), [LinkProblem::Offset]);
    assert!(sessions_found(&r).is_empty(), "{:?}", sessions_found(&r));
    // A session that starts earlier makes the slots before the resend
    // slots the device must send in: the skip is allowed across them, but
    // each is a missing slot the gateway must declare.
    let r = run(100, 217, 0);
    assert!(
        found(&r, scanner()).is_empty(),
        "{:?}",
        found(&r, scanner())
    );
    assert_eq!(sessions_found(&r), [(12, SessionProblem::MissingSlots)]);
    assert_eq!(link_report(&r, scanner()).missing_slots, 4);
}

#[test]
fn a_lost_witnessed_resend_is_a_position_the_stream_may_skip() {
    // A witnessed resend of the stream in slots 220 and 221; frame
    // (220, 1) is lost on the line too and the gateway declares slot 220
    // missing. The next frame starts past what it carried: a position of
    // the witnessed slots went untaken. The objects after the loss go on
    // the batch's run where it was cut; those it carried never arrived.
    let links = witnessed_day(0, (220, 221), 3 * 4096);
    let frames = &links[SCANNER].frames;
    let lost = frames
        .iter()
        .find(|f| f.slot == 220 && f.index == 1)
        .unwrap();
    assert!(lost.payload_len > 0);
    assert!(frames.iter().any(|f| f.slot == 221 && f.payload_len > 0));
    let r = run_witnessed(links.clone(), resend_windows(220), &[(220, 1)], 1);
    assert!(
        found(&r, scanner()).is_empty(),
        "{:?}",
        found(&r, scanner())
    );
    assert!(sessions_found(&r).is_empty(), "{:?}", sessions_found(&r));
    assert_eq!(
        r.connectivity().holds(),
        only(HoldReason::UplinkObjectOutside)
    );
    // The witnessed slot is a slot the device must send in: left
    // undeclared, it is a disagreement.
    let r = run_witnessed(links, resend_windows(220), &[(220, 1)], 0);
    assert_eq!(sessions_found(&r), [(12, SessionProblem::MissingSlots)]);
}

#[test]
fn a_share_package_is_no_longer_than_the_election_allows() {
    // A package after a lost range (its record unknown): only its length
    // is judged, against the longest package this election's trustees
    // allow; named by no record, it is not on the ledger either way.
    let o = scanner_objects();
    let members = election_world().genesis.trustees().count();
    let most = ityv_encoding::max_package_len(members);
    for (len, problems) in [
        (most, &[LinkProblem::NotOnLedger][..]),
        (
            most + 1,
            &[LinkProblem::Package, LinkProblem::NotOnLedger][..],
        ),
    ] {
        let package = fake_object(SCHEMA_SHARE_PACKAGE, &std::vec![0x5A; len - 16]);
        assert_eq!(package.len(), len);
        let sent = [o[0], o[1], package];
        let links = with_stream(SCANNER, &sent);
        let listed = links[SCANNER].objects.clone();
        assert_eq!(listed[2].stream_offset % 4096, 0);
        let links = cut(
            links,
            SCANNER,
            &[
                (150, 0),
                (151, listed[1].stream_offset as usize),
                (152, listed[2].stream_offset as usize),
            ],
        );
        let lose = |l: usize, f: &Built| {
            if l == SCANNER && f.slot == 151 {
                None
            } else {
                window(f.slot)
            }
        };
        let declare = declare_one(1);
        let mut plan = Plan::new(ST, links);
        plan.assign = Some(&lose);
        plan.tweak_link = Some(&declare);
        let r = verify(plan.events());
        assert_eq!(found(&r, scanner()), problems, "{len}");
    }
}

#[test]
fn while_a_box_is_open_its_station_unit_sends_to_the_last_session() {
    // The day without BOX-1's close: the devices send to the end of the
    // first window. The unit's frame of its last slot is lost and
    // declared: the stage counts that slot, the box being open.
    let events: Vec<(SchemaId, &'static [u8])> = day()
        .events
        .iter()
        .copied()
        .filter(|(s, _)| *s != ityv_encoding::SCHEMA_BOX_CLOSE)
        .collect();
    let mut book = Book::new(election_world());
    for (schema, event) in &events {
        book.push(*schema, event);
    }
    let all = book.ledger.events.clone();
    let (station_id, links) = station_links(election_world().genesis, &all).remove(0);
    assert_eq!(station_id, ST);
    let last = links[UNIT].frames.last().unwrap().slot;
    assert_eq!(last, 155);
    let lose = move |l: usize, f: &Built| {
        if l == UNIT && f.slot == last {
            None
        } else {
            window(f.slot)
        }
    };
    let declare = |i: u32, e: &mut SessionLink| {
        if i == 1 && e.link_id_hash == unit() {
            e.missing_slots = 1;
        }
    };
    let mut plan = Plan::new(ST, links);
    plan.assign = Some(&lose);
    plan.tweak_link = Some(&declare);
    let r = verify_book(book, plan.events());
    assert!(sessions_found(&r).is_empty(), "{:?}", sessions_found(&r));
    assert_eq!(link_report(&r, unit()).missing_slots, 1);
}

#[test]
fn c2_a_link_that_lists_nothing_still_tiles_its_data() {
    // The sealed spare check-in unit sends 200 KiB that are no object and
    // lists none.
    let world = election_world();
    let spare_key =
        common::uplink::key_number(world.genesis.station(ST).unwrap().spare().frame_key);
    let mut links = honest_links();
    links.push(Link {
        key: spare_key,
        frames: common::uplink::frames(spare_key, &std::vec![0xA5; 200 * 1024], 150, 212, 1),
        objects: Vec::new(),
    });
    let r = verify(Plan::new(ST, links).events());
    // Never brought into service (review 3 of 2i, finding 5): each frame
    // is before a swap that never came.
    let problems = found(&r, link(spare_key));
    assert_eq!(problems.last(), Some(&LinkProblem::NotObject));
    assert_eq!(
        problems
            .iter()
            .filter(|p| **p == LinkProblem::BeforeSwap)
            .count(),
        63
    );
    assert_eq!(
        box_holds(&r),
        only(HoldReason::UplinkObjectInvalid).with(HoldReason::UplinkFrameInvalid)
    );

    // A scanner's frame key from before a swap: an amendment laid before
    // the opening gave BOX-1's scanner a new frame key, and the old one
    // still sends bytes that are no object (and sends after it was
    // replaced).
    let new_key = common::uplink::BOX_FRAME_BASE + 50;
    let (w, amendment) = leak(election_amended(|d| {
        d.boxes[0].frame_key = common::uplink::frame_key(new_key);
    }));
    let mut book = Book::new(w);
    book.push(ityv_encoding::SCHEMA_SIGNED_GENESIS, amendment);
    for (schema, event) in &day().events {
        book.push(*schema, event);
    }
    let old_key = day().links[SCANNER].key;
    let mut links = honest_links();
    links[SCANNER] = Link::new(new_key, &with_packages(&scanner_objects()), 150, 212, 1);
    links.push(Link {
        key: old_key,
        frames: common::uplink::frames(old_key, &[0xA5; 5000], 150, 212, 1),
        objects: Vec::new(),
    });
    let r = verify_book(book, Plan::new(ST, links).events());
    assert!(
        found(&r, link(new_key)).is_empty(),
        "{:?}",
        found(&r, link(new_key))
    );
    let problems = found(&r, link(old_key));
    assert_eq!(problems.last(), Some(&LinkProblem::NotObject));
    assert_eq!(
        problems
            .iter()
            .filter(|p| **p == LinkProblem::AfterSwap)
            .count(),
        62
    );
}

#[test]
fn c3_the_operator_cannot_list_what_the_device_did_not_send() {
    // The device sent R2*, another record of R2's length on no ledger
    // frame, in R2's place, the share packages after the records.
    let o = scanner_objects();
    let mut other = o[2].to_vec();
    let n = other.len();
    other[n / 2] ^= 0xFF;
    let other: &'static [u8] = leak_slice(other);
    let sent = with_packages(&[o[0], o[1], other, o[3], o[4]]);
    // The honest gateway logs what the device listed: R2* is not on the
    // ledger, and R2 never crossed the link.
    let r = verify(Plan::new(ST, with_stream(SCANNER, &sent)).events());
    assert!(found(&r, scanner()).contains(&LinkProblem::NotOnLedger));
    let outside: Vec<Hash512> = station(&r).outside.iter().map(|e| e.hash).collect();
    assert!(
        outside.contains(&ityv_crypto::object_hash(o[2])),
        "{outside:?}"
    );

    // The operator lists R2 where R2* lies: the device did not sign that
    // list, and the frame is not received.
    let mut links = with_stream(SCANNER, &sent);
    let at = links[SCANNER].frames[0]
        .objects
        .iter()
        .position(|x| x.object_hash == ityv_crypto::object_hash(other))
        .unwrap();
    links[SCANNER].frames[0].objects[at].object_hash = ityv_crypto::object_hash(o[2]);
    let r = verify(Plan::new(ST, links).events());
    assert_eq!(found(&r, scanner()), [LinkProblem::Signature]);
    assert_eq!(station(&r).outside.len(), 5);

    // Next to a lost frame, without packages: R3* in R3's place, then the
    // tick twice; the lost slot 151 cuts the first tick. The frames list
    // R3* (the device signed it): no made-up object can stand over the
    // lost range.
    let mut other = o[3].to_vec();
    let n = other.len();
    other[n - 1] ^= 0xFF;
    let other: &'static [u8] = leak_slice(other);
    let sent = [o[0], o[1], o[2], other, o[4], o[4]];
    let (_, all) = stream(&sent);
    let links = cut(
        with_stream(SCANNER, &sent),
        SCANNER,
        &[
            (150, 0),
            (151, all[4].stream_offset as usize + 50),
            (152, all[5].stream_offset as usize),
        ],
    );
    let lose = |l: usize, f: &Built| {
        if l == SCANNER && f.slot == 151 {
            None
        } else {
            window(f.slot)
        }
    };
    let declare = declare_one(1);
    let mut plan = Plan::new(ST, links);
    plan.assign = Some(&lose);
    plan.tweak_link = Some(&declare);
    let r = verify(plan.events());
    assert!(found(&r, scanner()).contains(&LinkProblem::NotOnLedger));
    // R3 never crossed the link; R2 shares a chunk with R3*'s bytes, which
    // the ledger does not show.
    let mut outside: Vec<Hash512> = station(&r).outside.iter().map(|e| e.hash).collect();
    outside.sort_by_key(|h| h.0);
    let mut want = [
        ityv_crypto::object_hash(o[2]),
        ityv_crypto::object_hash(o[3]),
    ];
    want.sort_by_key(|h| h.0);
    assert_eq!(outside, want);
}

#[test]
fn e1_to_e3_honest_line_loss_holds_nothing() {
    // The batch with its packages twice (the second copy the close resend
    // would carry), then the closing tick, spread over frames of 8,192 or
    // 6,000 bytes so the frame boundaries fall at chunk boundaries or
    // anywhere. Any one frame of the first copy lost and declared, the
    // second copy whole: the first data frame (E1), the batch attestation's
    // frame (E2), a frame with a record's start whose package arrives (E3).
    let o = scanner_objects();
    let once = with_packages(&o[..4]);
    let mut twice = once.clone();
    twice.extend(once.iter().copied());
    twice.push(o[4]);
    let key = day().links[SCANNER].key;
    let mut runs = 0;
    for capacity in [8192usize, 6000] {
        let (frames, listed) = device_frames_of(key, &twice, 150, 212, 1, capacity);
        let second = listed[once.len()].stream_offset;
        for lost in frames
            .iter()
            .filter(|f| f.payload_len > 0 && f.stream_offset < second)
        {
            let mut links = honest_links();
            links[SCANNER] = Link {
                key,
                frames: frames.clone(),
                objects: listed.clone(),
            };
            let slot = lost.slot;
            let lose = move |l: usize, f: &Built| {
                if l == SCANNER && f.slot == slot {
                    None
                } else {
                    window(f.slot)
                }
            };
            let declare = declare_one((slot as u32 - 150) / 6 + 1);
            let mut plan = Plan::new(ST, links);
            plan.assign = Some(&lose);
            plan.tweak_link = Some(&declare);
            let r = verify(plan.events());
            assert!(
                found(&r, scanner()).is_empty(),
                "capacity {capacity}, slot {slot}: {:?}",
                found(&r, scanner())
            );
            assert!(sessions_found(&r).is_empty(), "{:?}", sessions_found(&r));
            assert!(station(&r).outside.is_empty(), "{:?}", station(&r).outside);
            assert_eq!(r.connectivity().holds(), HoldSet::empty());
            runs += 1;
        }
    }
    assert!(runs >= 8, "{runs}");

    // A lost trailing slot: the closing tick's slot, declared; undeclared,
    // the session's count is not the stage's.
    let lose = |l: usize, f: &Built| {
        if l == SCANNER && f.slot == 212 {
            None
        } else {
            window(f.slot)
        }
    };
    let declare = declare_one(11);
    let mut plan = Plan::new(ST, honest_links());
    plan.assign = Some(&lose);
    plan.tweak_link = Some(&declare);
    let r = verify(plan.events());
    assert!(sessions_found(&r).is_empty(), "{:?}", sessions_found(&r));
    assert_eq!(r.connectivity().holds(), HoldSet::empty());
    assert_eq!(link_report(&r, scanner()).missing_slots, 1);
    let mut plan = Plan::new(ST, honest_links());
    plan.assign = Some(&lose);
    let r = verify(plan.events());
    assert_eq!(sessions_found(&r), [(11, SessionProblem::MissingSlots)]);
}

#[test]
fn m2_a_device_sends_only_its_own_objects() {
    // The scanner carries the check-in unit's closing tick: a kind it may
    // send, of another device.
    let mut objects = scanner_objects();
    let unit_tick = unit_objects()[0];
    assert_eq!(device_of(unit_tick), Some((false, ST)));
    objects.push(unit_tick);
    let r = verify(Plan::new(ST, with_stream(SCANNER, &objects)).events());
    assert_eq!(found(&r, scanner()), [LinkProblem::Foreign]);
    assert_eq!(box_holds(&r), only(HoldReason::UplinkObjectInvalid));
    // On U-1A's link it is included.
    assert!(station(&r).outside.is_empty());
}

// ---------------------------------------------------------------------------
// Incidents (VC-083).

const COMMITTEE_AND_OBSERVERS: [(&[u8], EventRole, &[u8], u16); 3] = [
    (b"committee", EventRole::Committee, b"IVC", COMMITTEE),
    PEOPLE[2],
    PEOPLE[3],
];

#[test]
fn an_incident_holds_the_electronic_layer_it_names() {
    // On site, about BOX-1's commitment unit.
    let mut events = Plan::new(ST, honest_links()).events();
    events.push((
        ityv_encoding::SCHEMA_WITNESSED_EVENT,
        witnessed(incident_body(Some(ST), Some(B1.id), true), &PEOPLE),
    ));
    let r = verify(events);
    let incidents = r.connectivity().incidents();
    assert_eq!(incidents.len(), 1);
    let i = &incidents[0];
    assert_eq!(i.refused, None);
    assert_eq!(i.boxes, [BoxId::new(B1.id).unwrap()]);
    // No audit compared BOX-1's records.
    assert_eq!(i.full_comparison, [(BoxId::new(B1.id).unwrap(), false)]);
    assert_eq!(i.parts.from_slot, 160);
    assert_eq!(box_holds(&r), only(HoldReason::ConnectivityIncident));
    assert!(
        r.status()
            .holds()
            .contains(HoldReason::ConnectivityIncident)
    );
    // The connectivity step still ran: the hold is the incident's.
    assert_eq!(r.evidence().step(Step::Connectivity), Outcome::Passed);

    // The committee, about the station, no commitment unit.
    let mut events = Plan::new(ST, honest_links()).events();
    events.push((
        ityv_encoding::SCHEMA_WITNESSED_EVENT,
        witnessed(
            incident_body(Some(ST), None, false),
            &COMMITTEE_AND_OBSERVERS,
        ),
    ));
    let r = verify(events);
    let i = &r.connectivity().incidents()[0];
    assert_eq!(i.refused, None);
    assert_eq!(i.boxes, [BoxId::new(B1.id).unwrap()]);
    assert!(i.full_comparison.is_empty());
    assert_eq!(box_holds(&r), only(HoldReason::ConnectivityIncident));

    // The whole election.
    let mut events = Plan::new(ST, honest_links()).events();
    events.push((
        ityv_encoding::SCHEMA_WITNESSED_EVENT,
        witnessed(incident_body(None, None, false), &COMMITTEE_AND_OBSERVERS),
    ));
    let r = verify(events);
    let i = &r.connectivity().incidents()[0];
    assert_eq!(i.boxes, [BoxId::new(B1.id).unwrap()]);
    assert_eq!(
        r.connectivity().box_holds(b"BOX-9"),
        only(HoldReason::ConnectivityIncident)
    );
}

#[test]
fn an_incident_needs_registered_people_and_a_box_of_its_station() {
    // An observer under another observer's key.
    let mut who = PEOPLE;
    who[2].3 = PEOPLE[3].3;
    let mut events = Plan::new(ST, honest_links()).events();
    events.push((
        ityv_encoding::SCHEMA_WITNESSED_EVENT,
        witnessed(incident_body(Some(ST), Some(B1.id), true), &who),
    ));
    let r = verify(events);
    let i = &r.connectivity().incidents()[0];
    assert_eq!(i.refused, Some(IncidentProblem::Signers));
    assert!(i.boxes.is_empty());
    assert!(i.full_comparison.is_empty());
    assert_eq!(
        r.connectivity().holds(),
        only(HoldReason::ConnectivityIncidentRefused)
    );

    // An observer of an organisation the roster does not give them.
    let mut who = PEOPLE;
    who[3].2 = b"PARTY-C";
    let mut events = Plan::new(ST, honest_links()).events();
    events.push((
        ityv_encoding::SCHEMA_WITNESSED_EVENT,
        witnessed(incident_body(Some(ST), None, false), &who),
    ));
    let r = verify(events);
    assert_eq!(
        r.connectivity().incidents()[0].refused,
        Some(IncidentProblem::Signers)
    );

    // BOX-1 at a station that is not its own.
    let mut events = Plan::new(ST, honest_links()).events();
    events.push((
        ityv_encoding::SCHEMA_WITNESSED_EVENT,
        witnessed(incident_body(Some(b"ST-2"), Some(B1.id), false), &PEOPLE),
    ));
    let r = verify(events);
    assert_eq!(
        r.connectivity().incidents()[0].refused,
        Some(IncidentProblem::Subject)
    );
    assert_eq!(box_holds(&r), only(HoldReason::ConnectivityIncidentRefused));
}

#[test]
fn clerks_sign_at_their_station_and_the_election_is_the_committees() {
    // An on-site incident: clerk-2 is registered at no station after the
    // amendment, so the clerks are not the named station's.
    let (w, amendment) = leak(election_amended(|d| {
        for r in &mut d.roster {
            if r.signer_id.as_bytes() == b"clerk-2" {
                r.station_id = None;
            }
        }
    }));
    let mut book = Book::new(w);
    book.push(ityv_encoding::SCHEMA_SIGNED_GENESIS, amendment);
    book.w(witnessed(
        incident_body(Some(ST), Some(B1.id), false),
        &PEOPLE,
    ));
    let r = verify_book(book, Vec::new());
    let i = &r.connectivity().incidents()[0];
    assert_eq!(i.refused, Some(IncidentProblem::Scope));
    assert!(i.boxes.is_empty());
    assert_eq!(
        r.connectivity().holds(),
        only(HoldReason::ConnectivityIncidentRefused)
    );
    // The whole election, by the clerks and observers of one station.
    let mut events = Plan::new(ST, honest_links()).events();
    events.push((
        ityv_encoding::SCHEMA_WITNESSED_EVENT,
        witnessed(incident_body(None, None, false), &PEOPLE),
    ));
    let r = verify(events);
    assert_eq!(
        r.connectivity().incidents()[0].refused,
        Some(IncidentProblem::Scope)
    );
}

#[test]
fn an_incident_signer_may_sign_under_a_key_of_an_earlier_state() {
    // The amendment gives obs-a a new key; obs-a signs an incident after it
    // under the key of the genesis, which registered obs-a too.
    let (w, amendment) = amended_world();
    let mut book = Book::new(w);
    book.push(ityv_encoding::SCHEMA_SIGNED_GENESIS, amendment);
    book.w(witnessed(
        incident_body(Some(ST), Some(B1.id), false),
        &PEOPLE,
    ));
    let r = verify_book(book, Vec::new());
    let i = &r.connectivity().incidents()[0];
    assert_eq!(i.refused, None);
    assert_eq!(i.boxes, [BoxId::new(B1.id).unwrap()]);
    assert!(
        !r.connectivity()
            .ledger_holds()
            .contains(HoldReason::ConnectivityIncidentRefused)
    );
}

#[test]
fn an_object_may_span_two_frames() {
    // The scanner's first object starts in slot 150's frame and ends in
    // slot 151's: both frames list it.
    let links = cut_stream(&[(150, 0), (151, 1000)]);
    assert!(1000 < cut_objects()[0].len);
    assert_eq!(links[SCANNER].frames[1].objects[0], cut_objects()[0]);
    let r = verify(Plan::new(ST, links.clone()).events());
    assert!(
        found(&r, scanner()).is_empty(),
        "{:?}",
        found(&r, scanner())
    );
    assert!(sessions_found(&r).is_empty(), "{:?}", sessions_found(&r));
    let b = link_report(&r, scanner());
    assert_eq!((b.data_frames, b.objects, b.included), (2, 5, 5));
    assert_eq!(b.opaque_chunks, 0);
    assert!(station(&r).outside.is_empty());
    assert_eq!(r.connectivity().holds(), HoldSet::empty());
    // A capture of both frames puts the object together again; of one, the
    // object is not whole and is not judged.
    let c = compare_capture(
        election_world().genesis,
        r.index(),
        &capture_of(&links, &[150, 151]),
    );
    assert!(c.agrees(), "{:?}", c.findings);
    assert_eq!((c.matched, c.objects_matched), (2, 5));
    let c = compare_capture(
        election_world().genesis,
        r.index(),
        &capture_of(&links, &[151]),
    );
    assert!(c.agrees(), "{:?}", c.findings);
    assert_eq!(c.objects_matched, 4);
}

// ---------------------------------------------------------------------------
// The manifest (VC-077).

#[test]
fn a_manifest_that_breaks_a_one_way_rule_holds_the_whole_ledger() {
    // The scanner's frame link receives as well.
    let mut entries = common::uplink::standard_entries();
    let at = entries
        .iter()
        .position(|e| e.device_class == DeviceClass::CommitmentUnit)
        .unwrap();
    entries[at].direction = Direction::Both;
    let mut d = draft();
    d.manifest = common::uplink::manifest(&entries);
    let w = leak(build(&d, &TALLY_SCOPES));
    let r = verify_book(Book::new(w), Vec::new());
    let problems: Vec<(DeviceClass, Option<&[u8]>, ManifestProblem)> = r
        .connectivity()
        .manifest_findings()
        .iter()
        .map(|f| (f.class, f.port, f.problem))
        .collect();
    let scanner_port = Some(b"uplink".as_slice());
    assert_eq!(
        problems,
        [
            (
                DeviceClass::CommitmentUnit,
                scanner_port,
                ManifestProblem::TcbInbound
            ),
            (
                DeviceClass::CommitmentUnit,
                scanner_port,
                ManifestProblem::TwoWay
            ),
            (
                DeviceClass::CommitmentUnit,
                scanner_port,
                ManifestProblem::FrameLinkShape
            ),
        ]
    );
    assert_eq!(
        r.connectivity().holds(),
        only(HoldReason::ConnectivityManifest)
    );
    assert_eq!(
        r.connectivity().box_holds(b"BOX-3"),
        only(HoldReason::ConnectivityManifest)
    );
    assert!(
        r.status()
            .holds()
            .contains(HoldReason::ConnectivityManifest)
    );

    // A class left out.
    let mut entries = common::uplink::standard_entries();
    entries.retain(|e| e.device_class != DeviceClass::Printer);
    let mut d = draft();
    d.manifest = common::uplink::manifest(&entries);
    let w = leak(build(&d, &TALLY_SCOPES));
    let r = verify_book(Book::new(w), Vec::new());
    let f = r.connectivity().manifest_findings();
    assert_eq!(f.len(), 1);
    assert_eq!(
        (f[0].class, f[0].port, f[0].problem),
        (DeviceClass::Printer, None, ManifestProblem::Uncovered)
    );
}

// ---------------------------------------------------------------------------
// The capture comparison (VC-081).

/// The capture of the scanner's frames at `slots` from `links`.
fn capture_of(links: &[Link], slots: &[u64]) -> Vec<u8> {
    let l = &links[SCANNER];
    let records: Vec<Vec<u8>> = slots
        .iter()
        .flat_map(|s| l.frames.iter().filter(move |f| f.slot == *s))
        .map(|f| wire_frame(f, l.key))
        .collect();
    capture_file(&records)
}

fn capture_problems(
    c: &ityv_verify::CaptureComparison,
) -> Vec<(Option<(u64, u16)>, CaptureProblem)> {
    c.findings.iter().map(|f| (f.frame, f.problem)).collect()
}

#[test]
fn a_capture_agrees_with_the_published_frames() {
    let r = verify(Plan::new(ST, honest_links()).events());
    let file = capture_of(&day().links, &[150, 151, 152]);
    let c = compare_capture(election_world().genesis, r.index(), &file);
    assert!(c.agrees(), "{:?}", c.findings);
    assert_eq!(c.capture_hash, ityv_crypto::uplink::capture_hash(&file));
    assert_eq!(c.frames.len(), 3);
    assert_eq!(c.frames[1].slot, 151);
    assert_eq!(c.frames[1].link_id_hash, scanner());
    // The tap sees the sealed packages too: eight objects.
    assert_eq!((c.matched, c.objects_matched), (3, 8));
}

#[test]
fn a_capture_shows_frames_hidden_injected_or_changed() {
    // The gateway dropped slot 152 and declared it missing: the stage is
    // clean, the capture is not.
    let lose = |l: usize, f: &Built| {
        if l == SCANNER && f.slot == 152 {
            None
        } else {
            window(f.slot)
        }
    };
    let declare = |i: u32, e: &mut SessionLink| {
        if i == 1 && e.link_id_hash == scanner() {
            e.missing_slots = 1;
        }
    };
    let mut plan = Plan::new(ST, honest_links());
    plan.assign = Some(&lose);
    plan.tweak_link = Some(&declare);
    let hidden = verify(plan.events());
    assert_eq!(hidden.connectivity().holds(), HoldSet::empty());
    let file = capture_of(&day().links, &[151, 152, 153]);
    let c = compare_capture(election_world().genesis, hidden.index(), &file);
    assert_eq!(
        capture_problems(&c),
        [(Some((152, 0)), CaptureProblem::Hidden)]
    );
    assert!(!c.agrees());
    assert_eq!(c.matched, 2);

    // A published frame the capture lacks between frames it has.
    let r = verify(Plan::new(ST, honest_links()).events());
    let file = capture_of(&day().links, &[151, 153]);
    let c = compare_capture(election_world().genesis, r.index(), &file);
    assert_eq!(
        capture_problems(&c),
        [(Some((152, 0)), CaptureProblem::Missing)]
    );

    // A frame the device sent otherwise; a signature that does not verify;
    // a link the genesis does not know.
    let mut changed = honest_links();
    reseal(&mut changed[SCANNER], 152, |f| f.stream_offset += 1);
    changed[SCANNER].frames[1].sig[0] ^= 1;
    let mut stranger = changed[SCANNER].frames[3].clone();
    stranger.seal(999, link(999));
    let mut records = std::vec![
        wire_frame(&changed[SCANNER].frames[1], changed[SCANNER].key),
        wire_frame(&changed[SCANNER].frames[2], changed[SCANNER].key),
    ];
    records.push(wire_frame(&stranger, 999));
    let c = compare_capture(election_world().genesis, r.index(), &capture_file(&records));
    assert_eq!(
        capture_problems(&c),
        [
            (Some((151, 0)), CaptureProblem::Signature),
            (Some((152, 0)), CaptureProblem::Differs),
            (Some((153, 0)), CaptureProblem::UnknownLink),
        ]
    );
    assert_eq!(c.matched, 1);
}

#[test]
fn a_capture_shows_bytes_that_are_not_the_published_objects() {
    let r = verify(Plan::new(ST, honest_links()).events());
    // Data that are not the published objects, as the device signed them.
    let mut changed = honest_links();
    reseal(&mut changed[SCANNER], 150, |f| f.data[20] ^= 1);
    let c = compare_capture(
        election_world().genesis,
        r.index(),
        &capture_of(&changed, &[150]),
    );
    assert_eq!(
        capture_problems(&c),
        [
            (Some((150, 0)), CaptureProblem::Differs),
            (None, CaptureProblem::ObjectDiffers),
        ]
    );
    assert_eq!(c.findings[1].stream_offset, Some(0));
    assert_eq!(c.objects_matched, 7);

    // Bytes the device listed no object for.
    let mut unlisted = honest_links();
    reseal(&mut unlisted[SCANNER], 150, |f| {
        f.objects.pop();
    });
    let r2 = verify(Plan::new(ST, unlisted.clone()).events());
    let c = compare_capture(
        election_world().genesis,
        r2.index(),
        &capture_of(&unlisted, &[150]),
    );
    assert_eq!(capture_problems(&c), [(None, CaptureProblem::NotObject)]);

    // A nonzero byte in the fill after a share package: in the package's
    // sealed chunk, which the public cannot recompute; the tap sees it.
    let package = day().links[SCANNER]
        .objects
        .iter()
        .find(|o| o.schema == SCHEMA_SHARE_PACKAGE)
        .copied()
        .unwrap();
    let after = (package.stream_offset + u64::from(package.len)) as usize;
    let mut filled = honest_links();
    reseal(&mut filled[SCANNER], 150, |f| f.data[after] = 1);
    let r3 = verify(Plan::new(ST, filled.clone()).events());
    assert_eq!(r3.connectivity().holds(), HoldSet::empty());
    let c = compare_capture(
        election_world().genesis,
        r3.index(),
        &capture_of(&filled, &[150]),
    );
    assert_eq!(capture_problems(&c), [(None, CaptureProblem::NotObject)]);
    assert_eq!(c.findings[0].stream_offset, Some(after as u64));

    // A second frame that carries the whole stream again one byte on and
    // lists every object there (review 2 of 2i, J): each starts inside one
    // listed before it, so it is no object of its own and is not
    // assembled, though its bytes would hash to it.
    let l = &day().links[SCANNER];
    let mut shifted = l.frames[0].clone();
    shifted.slot = 151;
    shifted.stream_offset = 1;
    for o in &mut shifted.objects {
        o.stream_offset += 1;
    }
    shifted.seal(l.key, link(l.key));
    let file = capture_file(&[wire_frame(&l.frames[0], l.key), wire_frame(&shifted, l.key)]);
    let c = compare_capture(election_world().genesis, r.index(), &file);
    for o in &shifted.objects {
        assert!(
            c.findings
                .iter()
                .any(|f| f.problem == CaptureProblem::ObjectDiffers
                    && f.stream_offset == Some(o.stream_offset)),
            "{:?}",
            c.findings
        );
    }
    assert_eq!(c.objects_matched, 1);

    // A record that is not a canonical frame, then a length past the end.
    let mut bad = wire_frame(&day().links[SCANNER].frames[1], day().links[SCANNER].key);
    let n = bad.len();
    bad[n / 2] = 1;
    let mut file = capture_file(&[bad]);
    file.extend_from_slice(&[0, 0, 0, 9, 1, 2]);
    let c = compare_capture(election_world().genesis, r.index(), &file);
    assert_eq!(
        capture_problems(&c),
        [
            (None, CaptureProblem::NotFrame),
            (None, CaptureProblem::Truncated)
        ]
    );
    assert!(c.frames.is_empty());
}

// ---------------------------------------------------------------------------
// The carrier's records (§181-2 ⑤).

/// One interval per session window with its bytes.
fn honest_intervals(r: &Report<'static>) -> Vec<CarrierInterval> {
    station(r)
        .sessions
        .iter()
        .map(|s| CarrierInterval {
            from_slot: s.start_slot,
            to_slot: s.end_slot,
            bytes: s.wan_bytes,
        })
        .collect()
}

fn carrier(
    r: &Report<'static>,
    world: &'static World,
    station_id: &'static [u8],
    line: CarrierLine,
    intervals: Vec<CarrierInterval>,
) -> Vec<CarrierProblem> {
    let logs = [CarrierLog {
        station_id,
        line,
        intervals: leak_slice(intervals),
    }];
    compare_carrier(world.genesis, r.index(), r.connectivity(), &logs)
        .iter()
        .map(|f| f.problem)
        .collect()
}

#[test]
fn carrier_records_must_match_the_sessions() {
    let r = verify(Plan::new(ST, honest_links()).events());
    let w = election_world();
    let honest = honest_intervals(&r);
    assert_eq!(honest.iter().map(|i| i.bytes).sum::<u64>(), 66_000);
    assert!(carrier(&r, w, ST, CarrierLine::Gateway, honest.clone()).is_empty());

    // A byte more than the sessions declare.
    let mut more = honest.clone();
    more[4].bytes += 1;
    assert_eq!(
        carrier(&r, w, ST, CarrierLine::Gateway, more),
        [CarrierProblem::Bytes {
            carrier: 66_001,
            sessions: 66_000
        }]
    );

    // Traffic outside every session, the total unchanged.
    let mut moved = honest.clone();
    moved[4].bytes -= 10;
    moved.push(CarrierInterval {
        from_slot: 300,
        to_slot: 305,
        bytes: 10,
    });
    // An interval without traffic needs no session.
    moved.push(CarrierInterval {
        from_slot: 400,
        to_slot: 405,
        bytes: 0,
    });
    assert_eq!(
        carrier(&r, w, ST, CarrierLine::Gateway, moved.clone()),
        [CarrierProblem::Unexplained]
    );
    // The finding names the interval with traffic, not the quiet one.
    let logs = [CarrierLog {
        station_id: ST,
        line: CarrierLine::Gateway,
        intervals: leak_slice(moved),
    }];
    let found = compare_carrier(w.genesis, r.index(), r.connectivity(), &logs);
    assert_eq!(
        found.iter().map(|f| f.interval).collect::<Vec<_>>(),
        [Some(CarrierInterval {
            from_slot: 300,
            to_slot: 305,
            bytes: 10,
        })]
    );

    // A station the genesis does not have; a roll line at an election-day
    // station.
    assert_eq!(
        carrier(&r, w, b"ST-9", CarrierLine::Gateway, honest),
        [CarrierProblem::UnknownStation]
    );
    assert_eq!(
        carrier(&r, w, ST, CarrierLine::RollLookup, Vec::new()),
        [CarrierProblem::RollLineUndeclared]
    );
}

/// The one-box election with ST-1 an early-voting station.
fn early_world() -> &'static World {
    static WORLD: OnceLock<&'static World> = OnceLock::new();
    WORLD.get_or_init(|| {
        let mut d = draft();
        d.boxes.retain(|b| b.box_id.as_bytes() == B1.id);
        d.stations.truncate(1);
        d.stations[0] = common::station(
            ST,
            StationKind::EarlyVoting,
            common::checkin_unit(0, b"U-1A", &[b"M-U1A-P1", b"M-U1A-P2"]),
            common::checkin_unit(1, b"U-1B", &[b"M-U1B-P1", b"M-U1B-P2"]),
            &[B1.id],
            &[
                common::token(b"obs-a", b"PARTY-A", 0xC1),
                common::token(b"obs-b", b"PARTY-B", 0xC2),
            ],
        );
        d.policies.truncate(1);
        d.units.truncate(1);
        d.modules.retain(|m| {
            ELECTION_MODULES
                .iter()
                .any(|e| e.0 == m.module_id.as_bytes())
        });
        d.appointments = d.referenced_appointments();
        leak(build(&d, &TALLY_SCOPES))
    })
}

/// The one-box election with another connectivity manifest.
fn manifest_world(manifest: &'static [u8]) -> &'static World {
    let mut d = draft();
    d.boxes.retain(|b| b.box_id.as_bytes() == B1.id);
    d.stations.truncate(1);
    d.policies.truncate(1);
    d.units.truncate(1);
    d.modules.retain(|m| {
        ELECTION_MODULES
            .iter()
            .any(|e| e.0 == m.module_id.as_bytes())
    });
    for entry in &mut d.modules {
        let m = ELECTION_MODULES
            .iter()
            .find(|e| e.0 == entry.module_id.as_bytes())
            .unwrap();
        entry.provisioned_hash = ityv_crypto::object_hash(provisioning(*m));
    }
    d.appointments = d.referenced_appointments();
    d.manifest = manifest;
    leak(build(&d, &TALLY_SCOPES))
}

#[test]
fn roll_line_traffic_stays_in_the_stations_voting_window() {
    let w = early_world();
    let r = verify_book(book_in(w), Plan::new(ST, honest_links()).events());
    assert!(r.connectivity().complete());
    let inside = CarrierInterval {
        from_slot: 150,
        to_slot: 212,
        bytes: 5_000,
    };
    assert!(carrier(&r, w, ST, CarrierLine::RollLookup, std::vec![inside]).is_empty());
    let before = CarrierInterval {
        from_slot: 140,
        to_slot: 149,
        bytes: 1,
    };
    let after = CarrierInterval {
        from_slot: 212,
        to_slot: 213,
        bytes: 1,
    };
    let quiet = CarrierInterval {
        from_slot: 300,
        to_slot: 301,
        bytes: 0,
    };
    assert_eq!(
        carrier(
            &r,
            w,
            ST,
            CarrierLine::RollLookup,
            std::vec![before, after, quiet]
        ),
        [CarrierProblem::OutsideWindow, CarrierProblem::OutsideWindow]
    );
}

// ---------------------------------------------------------------------------
// The second review of 2i (A–I): each test turns a proof of concept of the
// review into the behaviour it asked for.

/// The ledger event of BOX-1's opening (a `WitnessedEvent`, scope BOX-1,
/// no device event).
fn box_opened() -> &'static [u8] {
    day()
        .events
        .iter()
        .find(|(s, e)| {
            *s == ityv_encoding::SCHEMA_WITNESSED_EVENT
                && ityv_encoding::decode_object::<ityv_encoding::WitnessedEvent<'_>>(
                    *s,
                    ityv_encoding::SCHEMA_VERSION_WITNESSED,
                    e,
                )
                .unwrap()
                .body_schema()
                    == ityv_encoding::SCHEMA_BOX_OPENED_BODY
        })
        .unwrap()
        .1
}

/// `objects` laid out as an honest device would from stream offset `at`:
/// the data and the entries.
fn part(at: u64, objects: &[&'static [u8]]) -> (Vec<u8>, Vec<StreamObject>) {
    let (bytes, mut listed, spans) = common::uplink::layout(objects, MAX_PAYLOAD_LEN, 1);
    assert_eq!(spans[0].1 as usize, bytes.len());
    for o in &mut listed {
        o.stream_offset += at;
    }
    (bytes, listed)
}

/// Pseudo-random bytes (a stand-in for exfiltrated secrets).
fn covert(n: usize) -> Vec<u8> {
    (0..n as u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8)
        .collect()
}

#[test]
fn r2_a_bytes_listed_under_a_ledger_hash_of_another_schema_are_a_finding() {
    // The scanner sends 900,000 covert bytes listed as a progress tick
    // under the hash of a ledger event of another schema: its batch
    // attestation, or its box's opening (no device event).
    let honest = &day().links[SCANNER];
    let f150 = honest.frames[0].clone();
    let end = u64::from(f150.payload_len);
    for hash in [
        ityv_crypto::object_hash(scanner_objects()[0]),
        ityv_crypto::object_hash(box_opened()),
    ] {
        let secret = covert(900_000);
        let entry = StreamObject {
            schema: SCHEMA_PROGRESS_TICK,
            object_hash: hash,
            stream_offset: end,
            len: secret.len() as u32,
        };
        let mut links = honest_links();
        links[SCANNER] = scanner_frames(
            &[
                (150, 0, f150.data.clone(), f150.objects.clone()),
                (151, end, secret, std::vec![entry]),
            ],
            &[],
        );
        let r = verify(Plan::new(ST, links).events());
        assert_eq!(found(&r, scanner()), [LinkProblem::Schema]);
        assert_eq!(box_holds(&r), only(HoldReason::UplinkObjectInvalid));
        assert!(r.status().holds().contains(HoldReason::UplinkObjectInvalid));
    }

    // A share package listed under a ledger event's hash, and a public
    // object under a package's hash: each is the other's schema.
    let o = scanner_objects();
    let package = common::uplink::package_of(o[1]).unwrap();
    for (schema, hash) in [
        (SCHEMA_SHARE_PACKAGE, ityv_crypto::object_hash(o[4])),
        (SCHEMA_PROGRESS_TICK, ityv_crypto::object_hash(package)),
    ] {
        let secret = covert(5000);
        let entry = StreamObject {
            schema,
            object_hash: hash,
            stream_offset: end,
            len: secret.len() as u32,
        };
        let mut links = honest_links();
        links[SCANNER] = scanner_frames(
            &[
                (150, 0, f150.data.clone(), f150.objects.clone()),
                (151, end, secret, std::vec![entry]),
            ],
            &[],
        );
        let r = verify(Plan::new(ST, links).events());
        assert!(
            found(&r, scanner()).contains(&LinkProblem::Schema),
            "{:?}",
            found(&r, scanner())
        );
    }

    // On U-1A's link, as an observer count under its participation set's
    // hash: the bytes are no observer count the public could check.
    let honest = &day().links[UNIT];
    let f150 = honest.frames[0].clone();
    let end = u64::from(f150.payload_len);
    let secret = covert(500_000);
    let entry = StreamObject {
        schema: ityv_encoding::SCHEMA_WITNESSED_EVENT,
        object_hash: ityv_crypto::object_hash(unit_objects()[1]),
        stream_offset: end,
        len: secret.len() as u32,
    };
    let key = honest.key;
    let mut frames = Vec::new();
    for slot in 150..=212u64 {
        let (offset, data, objects) = match slot {
            150 => (0, f150.data.clone(), f150.objects.clone()),
            151 => (end, secret.clone(), std::vec![entry]),
            _ => (end + secret.len() as u64, Vec::new(), Vec::new()),
        };
        let mut f = Built {
            slot,
            index: 0,
            kind: FrameKind::Normal,
            stream_offset: offset,
            payload_len: data.len() as u32,
            data,
            objects,
            fill: Vec::new(),
            payload_root: Hash512::ZERO,
            leaves: Vec::new(),
            sig: [0; 64],
        };
        f.seal(key, link(key));
        frames.push(f);
    }
    let mut links = honest_links();
    links[UNIT] = Link {
        key,
        frames,
        objects: Vec::new(),
    };
    let r = verify(Plan::new(ST, links).events());
    assert_eq!(found(&r, unit()), [LinkProblem::Schema]);
    assert!(
        r.connectivity()
            .holds()
            .contains(HoldReason::UplinkObjectInvalid)
    );
}

#[test]
fn r2_b_an_object_is_listed_only_as_often_as_its_kind_allows() {
    // The batch sent twice in normal frames (the closed slot and the next):
    // nothing to find.
    let o = scanner_objects();
    let once = with_packages(&o[..4]);
    let mut twice = once.clone();
    twice.extend(once.iter().copied());
    twice.push(o[4]);
    let r = verify(Plan::new(ST, with_stream(SCANNER, &twice)).events());
    assert!(
        found(&r, scanner()).is_empty(),
        "{:?}",
        found(&r, scanner())
    );
    // A third time: each of its objects once too often.
    let mut thrice = twice.clone();
    thrice.splice(once.len() * 2..once.len() * 2, once.iter().copied());
    let r = verify(Plan::new(ST, with_stream(SCANNER, &thrice)).events());
    assert_eq!(found(&r, scanner()), [LinkProblem::Repeat; 7]);
    assert_eq!(box_holds(&r), only(HoldReason::UplinkObjectInvalid));
    // A tick twice.
    let r = verify(
        Plan::new(
            ST,
            with_stream(SCANNER, &[&with_packages(&o)[..], &[o[4]]].concat()),
        )
        .events(),
    );
    assert_eq!(found(&r, scanner()), [LinkProblem::Repeat]);

    // A witnessed resend lists an object again only after a listing of it
    // there that did not arrive whole (review 3 of 2i, finding 1e). The
    // stream never arrived; a witnessed resend in slot 220 carries it, the
    // closing tick in frame (220, 1); slot 222 sends the tick again. With
    // (220, 1) lost (and slots 220 and 221 declared) that is the tick's
    // first arrival; with it kept, a repeat (and a slot more than the
    // resend's bytes and declared slots allow).
    let tick = o[4];
    let t = tick.len() as u64;
    let tick_at = day().links[SCANNER].objects.last().unwrap().stream_offset;
    for (lose, declared, problems) in [
        (&[(220u64, 1u16)][..], 2u32, &[][..]),
        (
            &[][..],
            1,
            &[
                LinkProblem::KindOrder,
                LinkProblem::KindOrder,
                LinkProblem::Repeat,
            ][..],
        ),
    ] {
        let mut links = honest_links();
        let end = stream_len(&links[SCANNER]);
        add_witnessed(
            &mut links,
            &with_packages(&o),
            end,
            (220, 220),
            tick_at as usize,
        );
        add_witnessed(
            &mut links,
            &[tick],
            end + tick_at + t,
            (222, 222),
            MAX_PAYLOAD_LEN,
        );
        let r = run_witnessed(links, resend_windows(220), lose, declared);
        assert_eq!(found(&r, scanner()), problems, "{lose:?}");
        assert!(sessions_found(&r).is_empty(), "{:?}", sessions_found(&r));
    }

    // The review's attack: a package listed sixty times, covert bytes in
    // the fill after each (the sealed allowance is per listing).
    let p1 = common::uplink::package_of(o[1]).unwrap();
    let mut sent = Vec::new();
    for _ in 0..60 {
        sent.extend([o[0], o[1], p1]);
    }
    sent.extend(with_packages(&o));
    let r = verify(Plan::new(ST, with_stream(SCANNER, &sent)).events());
    let problems = found(&r, scanner());
    assert!(
        problems
            .iter()
            .filter(|p| **p == LinkProblem::Repeat)
            .count()
            >= 58 * 3,
        "{problems:?}"
    );
    assert!(box_holds(&r).contains(HoldReason::UplinkObjectInvalid));
}

#[test]
fn r2_c_a_swapped_in_scanner_may_lose_its_first_frame() {
    // An amendment and a witnessed swap at slot 181 replace BOX-1's
    // scanner. The new one sends the batch twice and the closing tick over
    // frames of 6,000 bytes from slot 181.
    let new_key = common::uplink::BOX_FRAME_BASE + 50;
    let (w, amendment) = leak(election_amended(|d| {
        d.boxes[0].frame_key = common::uplink::frame_key(new_key);
    }));
    let old_key = day().links[SCANNER].key;
    let o = scanner_objects();
    let once = with_packages(&o[..4]);
    let mut twice = once.clone();
    twice.extend(once.iter().copied());
    // The box's ticks as [`book_swapped`] lays them: the old scanner's of
    // slot 150, the new one's closing tick of the swap's slot.
    twice.push(box_tick_in(181, ityv_encoding::BoxProgressState::Closed));
    let tick150 = box_tick_in(150, ityv_encoding::BoxProgressState::Casting);
    let (frames, listed) = device_frames_of(new_key, &twice, 181, 212, 1, 6000);
    let run = |frames: &Vec<Built>, lose_first: bool, declare: bool| {
        let book = book_swapped(w, amendment, 181);
        let mut links = honest_links();
        links[SCANNER] = Link {
            key: new_key,
            frames: frames.clone(),
            objects: listed.clone(),
        };
        links.push(Link::new(old_key, &[tick150], 150, 180, 1));
        let lose = move |l: usize, f: &Built| {
            if lose_first && l == SCANNER && f.slot == 181 {
                None
            } else {
                window(f.slot)
            }
        };
        let declare_181 = move |i: u32, e: &mut SessionLink| {
            if declare && i == 6 && e.link_id_hash == link(new_key) {
                e.missing_slots = 1;
            }
        };
        let mut plan = Plan::new(ST, links);
        plan.assign = Some(&lose);
        plan.tweak_link = Some(&declare_181);
        verify_book(book, plan.events())
    };
    // Nothing lost: clean, the whole report too (the box stage takes the
    // swap, laid while the box is open).
    let r = run(&frames, false, false);
    assert!(
        found(&r, link(new_key)).is_empty(),
        "{:?}",
        found(&r, link(new_key))
    );
    assert_eq!(r.connectivity().holds(), HoldSet::empty());
    assert!(r.status().holds().is_empty(), "{:?}", r.status().holds());
    // Its first frame lost on the line and declared, as an honest gateway
    // would: the swap's slot is a position, and nothing is held.
    let r = run(&frames, true, true);
    assert!(
        found(&r, link(new_key)).is_empty(),
        "{:?}",
        found(&r, link(new_key))
    );
    assert!(sessions_found(&r).is_empty(), "{:?}", sessions_found(&r));
    assert_eq!(r.connectivity().holds(), HoldSet::empty());
    // Not declared: a disagreement of the session, not an offset.
    let r = run(&frames, true, false);
    assert!(found(&r, link(new_key)).is_empty());
    assert_eq!(sessions_found(&r), [(6, SessionProblem::MissingSlots)]);
    // A first frame that skips with nothing lost is still an offset.
    let mut skipped = frames.clone();
    for f in &mut skipped {
        f.stream_offset += 1;
        f.objects.iter_mut().for_each(|o| o.stream_offset += 1);
        f.seal(new_key, link(new_key));
    }
    let r = run(&skipped, false, false);
    assert!(found(&r, link(new_key)).contains(&LinkProblem::Offset));
}

#[test]
fn r2_c_a_witnessed_resend_may_lose_its_first_slot() {
    // A witnessed resend of the stream (which never arrived) in slots 219
    // and 220, in a session that starts with it; all of slot 219 is lost
    // on the line too and the gateway declares it. Slot 219 is a position
    // of the resend: the next frame may start past what it carried.
    let links = witnessed_day(0, (219, 220), 3 * 4096);
    assert!(
        links[SCANNER]
            .frames
            .iter()
            .any(|f| f.slot == 220 && f.payload_len > 0)
    );
    let lost = [(219, 0), (219, 1)];
    let r = run_witnessed(links.clone(), resend_windows(219), &lost, 1);
    assert!(
        found(&r, scanner()).is_empty(),
        "{:?}",
        found(&r, scanner())
    );
    assert!(sessions_found(&r).is_empty(), "{:?}", sessions_found(&r));
    assert_eq!(
        r.connectivity().holds(),
        only(HoldReason::UplinkObjectOutside)
    );
    let r = run_witnessed(links, resend_windows(219), &lost, 0);
    assert!(
        found(&r, scanner()).is_empty(),
        "{:?}",
        found(&r, scanner())
    );
    assert_eq!(sessions_found(&r), [(12, SessionProblem::MissingSlots)]);
}

#[test]
fn r2_d_witnessed_slots_are_slots_the_device_must_send_in() {
    // A witnessed resend in slots 219 and 220; the gateway drops all of
    // slot 219. Undeclared, the session disagrees with its log; declared,
    // nothing is wrong with the link.
    let links = witnessed_day(0, (219, 220), 3 * 4096);
    let lost = [(219, 0), (219, 1)];
    let r = run_witnessed(links.clone(), resend_windows(219), &lost, 0);
    assert_eq!(sessions_found(&r), [(12, SessionProblem::MissingSlots)]);
    assert_eq!(link_report(&r, scanner()).missing_slots, 2);
    let r = run_witnessed(links.clone(), resend_windows(219), &lost, 1);
    assert!(
        found(&r, scanner()).is_empty(),
        "{:?}",
        found(&r, scanner())
    );
    assert!(sessions_found(&r).is_empty(), "{:?}", sessions_found(&r));
    // A session window that leaves slot 220 out: an undeclared gap.
    let mut windows = resend_windows(219);
    windows.last_mut().unwrap().1 = 219;
    let r = run_witnessed(links, windows, &lost, 1);
    assert!(sessions_found(&r).contains(&(12, SessionProblem::UndeclaredGap)));

    // Where the witnessed slots meet the box's, a slot no window covers is
    // one slot of the gap: no session covers slots 204 to 209, and a
    // witnessed resend in slot 206 is filed in the next session (outside
    // its window).
    let mut links = honest_links();
    for index in 0..2 {
        add(&mut links[SCANNER], 211, |f| {
            f.slot = 206;
            f.index = index;
            f.kind = FrameKind::WitnessedResend;
        });
    }
    let windows: Vec<(u64, u64)> = (150..=210)
        .step_by(6)
        .filter(|s| *s != 204)
        .map(|s| (s, s + 5))
        .collect();
    let file = |_: usize, f: &Built| {
        if f.kind == FrameKind::WitnessedResend {
            Some(9)
        } else {
            windows
                .iter()
                .position(|(a, b)| *a <= f.slot && f.slot <= *b)
        }
    };
    let mut plan = Plan::new(ST, links);
    plan.windows = windows.clone();
    plan.assign = Some(&file);
    let r = verify(plan.events());
    assert!(found(&r, scanner()).contains(&LinkProblem::Window));
    assert!(sessions_found(&r).contains(&(10, SessionProblem::UndeclaredGap)));
    assert_eq!(link_report(&r, scanner()).missing_slots, 6);
}

#[test]
fn r2_f_a_silent_slot_no_longer_makes_any_record_a_run() {
    // The review's attack: slot 150 silent; R3 alone at offset 1; slot 152
    // silent; R1; slot 154 silent; R2; slot 156 silent; the attestation and
    // the closing tick together. The attestation's run ends at once with
    // nothing lost: it holds none of its records.
    let o = scanner_objects();
    let pk = |r: &'static [u8]| common::uplink::package_of(r).unwrap();
    let send = |groups: &[(u64, Vec<&'static [u8]>)], silent: &[u64]| {
        let mut parts = Vec::new();
        let mut at = 1u64;
        for (slot, objects) in groups {
            let (data, listed) = part(at, objects);
            let len = data.len() as u64;
            parts.push((*slot, at, data, listed));
            at += len + 1;
        }
        let mut links = honest_links();
        links[SCANNER] = scanner_frames(&parts, silent);
        let declare = |i: u32, e: &mut SessionLink| {
            if e.link_id_hash == scanner() {
                e.missing_slots = match i {
                    1 => 3,
                    2 => 1,
                    _ => 0,
                };
            }
        };
        let mut plan = Plan::new(ST, links);
        plan.tweak_link = Some(&declare);
        verify(plan.events())
    };
    let r = send(
        &[
            (151, std::vec![o[3], pk(o[3])]),
            (153, std::vec![o[1], pk(o[1])]),
            (155, std::vec![o[2], pk(o[2])]),
            (157, std::vec![o[0], o[4]]),
        ],
        &[150, 152, 154, 156],
    );
    assert_eq!(found(&r, scanner()), [LinkProblem::Batch]);
    assert_eq!(box_holds(&r), only(HoldReason::UplinkObjectInvalid));
    // What remains (ADR-0041, limits): after each silent position a run
    // may start anywhere in its batch. Each costs a declared missing slot.
    let r = send(
        &[
            (151, std::vec![o[3], pk(o[3])]),
            (153, std::vec![o[1], pk(o[1])]),
            (155, std::vec![o[2], pk(o[2])]),
            (157, std::vec![o[0]]),
            (159, std::vec![o[4]]),
        ],
        &[150, 152, 154, 156, 158],
    );
    assert!(
        found(&r, scanner()).is_empty(),
        "{:?}",
        found(&r, scanner())
    );
    assert_eq!(link_report(&r, scanner()).missing_slots, 5);
}

/// A ledger of BOX-1 with six records in two batches (counters 1–3 and
/// 4–6), closed, and its station's record.
fn two_batches() -> (Book, Vec<&'static [u8]>) {
    let mut book = Book::new(election_world());
    let casts: Vec<Cast> = (1..=6).map(|i| cast(B1, i, 1)).collect();
    book.w(opened(B1));
    for c in &casts {
        book.push(ityv_encoding::SCHEMA_CAST_RECORD, c.event);
    }
    let all = codes(&casts);
    book.push(
        ityv_encoding::SCHEMA_BATCH_ATTEST,
        batch(B1, 0, 1, 3, &all[..3]),
    );
    book.push(
        ityv_encoding::SCHEMA_BATCH_ATTEST,
        batch(B1, 1, 4, 6, &all[3..]),
    );
    book.push(ityv_encoding::SCHEMA_BOX_CLOSE, close(B1, 6, 6, 0, &all));
    for (schema, event) in station_record(6) {
        book.push(schema, event);
    }
    book.push(SCHEMA_PARTICIPATION_SET, participation(6));
    let events = book.ledger.events.clone();
    let mine: Vec<&'static [u8]> = events
        .iter()
        .copied()
        .filter(|e| device_of(e) == Some((true, B1.id)))
        .collect();
    (book, box_stream(&mine))
}

/// The report over `book` with the honest links, the scanner's stream
/// replaced by `objects`.
fn verify_stream(book: Book, objects: &[&'static [u8]]) -> Report<'static> {
    let events = book.ledger.events.clone();
    let (_, mut links) = station_links(book.world.genesis, &events).remove(0);
    let l = &links[0];
    let (first, last) = (l.frames[0].slot, l.frames.last().unwrap().slot);
    links[0] = Link::new(l.key, objects, first, last, 1);
    verify_book(book, Plan::new(ST, links).events())
}

#[test]
fn r2_g_a_run_holds_its_batchs_records_in_order() {
    // The review's attack: the attestation sent again before each record,
    // so that each run holds one record, in any order.
    let o = scanner_objects();
    let sent = with_packages(&[o[0], o[3], o[0], o[1], o[0], o[2], o[4]]);
    let r = verify(Plan::new(ST, with_stream(SCANNER, &sent)).events());
    let problems = found(&r, scanner());
    assert!(problems.contains(&LinkProblem::Batch), "{problems:?}");
    assert_eq!(box_holds(&r), only(HoldReason::UplinkObjectInvalid));
    // A run that stops before its batch's last record.
    let r = verify(Plan::new(ST, with_stream(SCANNER, &[o[0], o[1], o[2], o[4]])).events());
    assert_eq!(found(&r, scanner()), [LinkProblem::Batch]);
    // Or where the stream ends, every position after it taken: the device
    // sent no more. With the last slot lost (and declared), the rest may
    // have been in it.
    let short = with_packages(&[o[0], o[1], o[2]]);
    let r = verify(Plan::new(ST, with_stream(SCANNER, &short)).events());
    assert_eq!(found(&r, scanner()), [LinkProblem::Batch]);
    let lose = |l: usize, f: &Built| {
        if l == SCANNER && f.slot == 212 {
            None
        } else {
            window(f.slot)
        }
    };
    let declare = declare_one(11);
    let mut plan = Plan::new(ST, with_stream(SCANNER, &short));
    plan.assign = Some(&lose);
    plan.tweak_link = Some(&declare);
    let r = verify(plan.events());
    assert!(
        found(&r, scanner()).is_empty(),
        "{:?}",
        found(&r, scanner())
    );
    assert!(sessions_found(&r).is_empty(), "{:?}", sessions_found(&r));

    // Two batches: each run holds its own batch's records, and the batches
    // go out in their order.
    let (book, stream) = two_batches();
    let s = with_packages(&stream);
    let r = verify_stream(book, &s);
    assert!(
        found(&r, scanner()).is_empty(),
        "{:?}",
        found(&r, scanner())
    );
    assert_eq!(r.connectivity().holds(), HoldSet::empty());
    // stream: [batch 0, its three records, batch 1, its three, tick].
    let (book, _) = two_batches();
    let swapped = [
        stream[0], stream[1], stream[2], stream[5], stream[4], stream[6], stream[7], stream[3],
        stream[8],
    ];
    let r = verify_stream(book, &with_packages(&swapped));
    assert!(
        found(&r, scanner()).contains(&LinkProblem::Batch),
        "{:?}",
        found(&r, scanner())
    );
    let (book, _) = two_batches();
    let reordered = [
        stream[4], stream[5], stream[6], stream[7], stream[0], stream[1], stream[2], stream[3],
        stream[8],
    ];
    let r = verify_stream(book, &with_packages(&reordered));
    assert_eq!(found(&r, scanner()), [LinkProblem::Batch]);
}

#[test]
fn r2_g_runs_of_what_the_ledger_does_not_show() {
    // A run after an attestation the ledger does not have: its records are
    // judged by hash order alone (and the attestation is not on the ledger
    // once the gateway closed).
    let o = scanner_objects();
    let fake = fake_object(ityv_encoding::SCHEMA_BATCH_ATTEST, &[0xBA; 200]);
    let r = verify(Plan::new(ST, with_stream(SCANNER, &[fake, o[1], o[2], o[3], o[4]])).events());
    assert_eq!(found(&r, scanner()), [LinkProblem::NotOnLedger]);
    let r = verify(Plan::new(ST, with_stream(SCANNER, &[fake, o[3], o[2], o[1], o[4]])).events());
    assert_eq!(
        found(&r, scanner()),
        [
            LinkProblem::NotOnLedger,
            LinkProblem::Batch,
            LinkProblem::Batch
        ]
    );
    // Strictly: one record twice in a row is out of order too.
    let r = verify(
        Plan::new(
            ST,
            with_stream(SCANNER, &[fake, o[1], o[1], o[2], o[3], o[4]]),
        )
        .events(),
    );
    assert_eq!(
        found(&r, scanner()),
        [LinkProblem::NotOnLedger, LinkProblem::Batch]
    );

    // After a silent slot, a record the ledger does not have starts a run
    // of its own; one the ledger has in no batch (a record refused after
    // the box's close) is no run's.
    let refused = cast(B1, 4, 1).event;
    let unknown = fake_object(ityv_encoding::SCHEMA_CAST_RECORD, &[0x77; 300]);
    let honest = &day().links[SCANNER];
    let f150 = honest.frames[0].clone();
    let end = u64::from(f150.payload_len);
    for (record, problems) in [
        (unknown, &[LinkProblem::NotOnLedger][..]),
        (refused, &[LinkProblem::Batch][..]),
    ] {
        let mut book = book_in(election_world());
        book.push(ityv_encoding::SCHEMA_CAST_RECORD, refused);
        let mut links = honest_links();
        links[SCANNER] = scanner_frames(
            &[
                (150, 0, f150.data.clone(), f150.objects.clone()),
                (
                    152,
                    end + 1,
                    record.to_vec(),
                    std::vec![entry_at(record, end + 1)],
                ),
            ],
            &[151],
        );
        let declare = declare_one(1);
        let mut plan = Plan::new(ST, links);
        plan.tweak_link = Some(&declare);
        let r = verify_book(book, plan.events());
        assert_eq!(found(&r, scanner()), problems);
        assert!(sessions_found(&r).is_empty(), "{:?}", sessions_found(&r));
    }
}

/// BOX-1's progress tick of `slot`, signed by its device.
fn box_tick(slot: u64) -> &'static [u8] {
    use ityv_encoding::{
        BoxProgressBody, BoxProgressParts, BoxProgressState, ProgressTick,
        SCHEMA_BOX_PROGRESS_BODY, SCHEMA_VERSION_1,
    };
    let body = common::object(
        SCHEMA_BOX_PROGRESS_BODY,
        SCHEMA_VERSION_1,
        &BoxProgressBody::new(&BoxProgressParts {
            election_id: common::election(),
            box_id: BoxId::new(B1.id).unwrap(),
            slot,
            sheets_in: 3,
            state: BoxProgressState::Closed,
        }),
    );
    common::object(
        SCHEMA_PROGRESS_TICK,
        SCHEMA_VERSION_1,
        &ProgressTick::new(
            body,
            common::sign(common::signing(B1.device), b"box-progress", body),
        )
        .unwrap(),
    )
}

#[test]
fn r2_g_nothing_goes_out_before_its_time() {
    // A batch closed in bucket 120 (slots 180 and 181) sent in slot 150:
    // its attestation and records go out before they exist.
    let mut book = Book::new(election_world());
    let casts: Vec<Cast> = (1..=3).map(|i| cast(B1, i, 1)).collect();
    book.w(opened(B1));
    for c in &casts {
        book.push(ityv_encoding::SCHEMA_CAST_RECORD, c.event);
    }
    let all = codes(&casts);
    book.push(
        ityv_encoding::SCHEMA_BATCH_ATTEST,
        batch_at(B1, 0, 1, 3, &all, 120),
    );
    book.push(ityv_encoding::SCHEMA_BOX_CLOSE, close(B1, 3, 3, 0, &all));
    for (schema, event) in station_record(3) {
        book.push(schema, event);
    }
    book.push(SCHEMA_PARTICIPATION_SET, participation(3));
    let events = book.ledger.events.clone();
    let (_, links) = station_links(book.world.genesis, &events).remove(0);
    let r = verify_book(book, Plan::new(ST, links).events());
    assert_eq!(found(&r, scanner()), [LinkProblem::Time; 4]);

    // A tick of slot 160 sent in slot 150, and one of slot 150 after it.
    let mut book = book_in(election_world());
    let late = box_tick(160);
    book.push(SCHEMA_PROGRESS_TICK, late);
    let o = scanner_objects();
    let mut s = with_packages(&o);
    s.insert(s.len() - 1, late);
    let r = verify_book(book, Plan::new(ST, with_stream(SCANNER, &s)).events());
    assert_eq!(found(&r, scanner()), [LinkProblem::Time; 2]);
}

#[test]
fn r2_h_catch_up_and_close_resend_groups_only_where_the_protocol_uses_them() {
    // Slot 160 sent as a catch-up group with nothing lost before it.
    let mut links = honest_links();
    reseal(&mut links[SCANNER], 160, |f| f.kind = FrameKind::CatchUp);
    add(&mut links[SCANNER], 160, |f| f.index = 1);
    let r = verify(Plan::new(ST, links).events());
    assert_eq!(found(&r, scanner()), [LinkProblem::KindOrder; 2]);
    assert_eq!(box_holds(&r), only(HoldReason::UplinkFrameInvalid));
    // Half a catch-up group there: the slot that falls short is its own,
    // not one before it.
    let mut links = honest_links();
    reseal(&mut links[SCANNER], 160, |f| f.kind = FrameKind::CatchUp);
    let declare = declare_one(2);
    let mut plan = Plan::new(ST, links);
    plan.tweak_link = Some(&declare);
    let r = verify(plan.events());
    assert_eq!(found(&r, scanner()), [LinkProblem::KindOrder]);
    assert!(sessions_found(&r).is_empty(), "{:?}", sessions_found(&r));
    // After a slot the device did not send in (and the gateway declared),
    // it may catch up.
    let mut links = honest_links();
    links[SCANNER].frames.retain(|f| f.slot != 159);
    reseal(&mut links[SCANNER], 160, |f| f.kind = FrameKind::CatchUp);
    add(&mut links[SCANNER], 160, |f| f.index = 1);
    let declare = declare_one(2);
    let mut plan = Plan::new(ST, links);
    plan.tweak_link = Some(&declare);
    let r = verify(plan.events());
    assert!(
        found(&r, scanner()).is_empty(),
        "{:?}",
        found(&r, scanner())
    );
    assert!(sessions_found(&r).is_empty(), "{:?}", sessions_found(&r));
    // A close resend group mid-day, and the rest of the day in it.
    let mut links = honest_links();
    for f in &mut links[SCANNER].frames {
        if f.slot >= 160 {
            f.kind = FrameKind::CloseResend;
        }
    }
    for s in 160..=212 {
        add(&mut links[SCANNER], s, |f| f.index = 1);
    }
    let key = links[SCANNER].key;
    for f in &mut links[SCANNER].frames {
        f.seal(key, link(key));
    }
    let r = verify(Plan::new(ST, links).events());
    // Allowed only in the close slot and the one after (what came before
    // needs one slot at the catch-up shape).
    assert_eq!(found(&r, scanner()), [LinkProblem::KindOrder; 104]);
}

#[test]
fn r2_i_a_sealed_package_on_the_ledger_is_not_foreign() {
    let mut book = book_in(election_world());
    for r in &scanner_objects()[1..4] {
        book.push(SCHEMA_SHARE_PACKAGE, common::uplink::package_of(r).unwrap());
    }
    let r = verify_book(book, Plan::new(ST, honest_links()).events());
    assert!(
        found(&r, scanner()).is_empty(),
        "{:?}",
        found(&r, scanner())
    );
    assert_eq!(r.connectivity().holds(), HoldSet::empty());
}

// ---------------------------------------------------------------------------
// The third review of 2i (findings 1–7): each test turns a proof of concept
// of the review into the behaviour it asked for; the `held_` tests are the
// review's angles the stage already closed.

/// A frame of link `key` at (`slot`, `index`) of kind `kind` carrying
/// `objects` (laid out honestly) from stream offset `at`; empty when
/// `objects` is.
fn make_frame(
    key: u16,
    slot: u64,
    index: u16,
    kind: FrameKind,
    at: u64,
    objects: &[&'static [u8]],
) -> Built {
    let (data, listed) = if objects.is_empty() {
        (Vec::new(), Vec::new())
    } else {
        part(at, objects)
    };
    let mut f = Built {
        slot,
        index,
        kind,
        stream_offset: at,
        payload_len: data.len() as u32,
        data,
        objects: listed,
        fill: Vec::new(),
        payload_root: Hash512::ZERO,
        leaves: Vec::new(),
        sig: [0; 64],
    };
    f.seal(key, link(key));
    f
}

/// A link of `key` from per-slot groups: each `(slot, kind, objects of
/// number 0)` with `per_slot` numbers (the others empty); the stream runs
/// on without a gap.
fn link_of(key: u16, groups: &[(u64, FrameKind, Vec<&'static [u8]>)], per_slot: u16) -> Link {
    let mut frames = Vec::new();
    let mut at = 0u64;
    for (slot, kind, objects) in groups {
        for index in 0..per_slot {
            let objs: &[&'static [u8]] = if index == 0 { objects } else { &[] };
            let f = make_frame(key, *slot, index, *kind, at, objs);
            at += u64::from(f.payload_len);
            frames.push(f);
        }
    }
    Link {
        key,
        frames,
        objects: Vec::new(),
    }
}

/// The honest links of `book` (each opened box's scanner and the unit).
fn links_of(book: &Book) -> Vec<Link> {
    let events = book.ledger.events.clone();
    station_links(book.world.genesis, &events).remove(0).1
}

/// `l` with every frame from `from` on turned into kind `kind`, each slot
/// filled to the catch-up shape (two numbers here) with empty frames.
fn shape_from(l: &mut Link, from: u64, kind: FrameKind) {
    let slots: Vec<u64> = l
        .frames
        .iter()
        .filter(|f| f.slot >= from)
        .map(|f| f.slot)
        .collect();
    for f in &mut l.frames {
        if f.slot >= from {
            f.kind = kind;
        }
    }
    for s in slots {
        add(l, s, |f| {
            f.index = 1;
            f.stream_offset += u64::from(f.payload_len);
            f.data.clear();
            f.payload_len = 0;
            f.objects.clear();
        });
    }
    let key = l.key;
    for f in &mut l.frames {
        f.seal(key, link(key));
    }
}

/// Session tweak: no session is final (the ledger mid-day).
fn not_final(p: &mut UplinkSessionParts<'static>) {
    p.is_final = false;
}

#[test]
fn r3_1a_a_witnessed_resend_comes_only_after_the_close() {
    // The whole day labelled a witnessed resend (kind 3) at the catch-up
    // shape: before the close, so every frame is out of its kind's place.
    let mut links = honest_links();
    shape_from(&mut links[SCANNER], 150, FrameKind::WitnessedResend);
    let r = verify(Plan::new(ST, links).events());
    let problems = found(&r, scanner());
    assert!(!problems.is_empty());
    assert!(problems.contains(&LinkProblem::KindOrder), "{problems:?}");
    assert!(box_holds(&r).contains(HoldReason::UplinkFrameInvalid));
    // The same day as catch-up groups (kind 1): out of place too.
    let mut links = honest_links();
    shape_from(&mut links[SCANNER], 150, FrameKind::CatchUp);
    let r = verify(Plan::new(ST, links).events());
    assert!(found(&r, scanner()).contains(&LinkProblem::KindOrder));
}

#[test]
fn r3_1b_one_short_slot_buys_one_catch_up_slot() {
    // Slot 151 skipped (declared), then catch-up groups to the close: the
    // first (152) follows the short slot; the next ones follow a catch-up
    // group whose frames are not full, so no backlog explains them.
    let mut links = honest_links();
    links[SCANNER].frames.retain(|f| f.slot != 151);
    shape_from(&mut links[SCANNER], 152, FrameKind::CatchUp);
    let declare = declare_one(1);
    let mut plan = Plan::new(ST, links);
    plan.tweak_link = Some(&declare);
    let r = verify(plan.events());
    // Slots 153 to 211, two frames each; 212 is the close slot.
    assert_eq!(found(&r, scanner()), [LinkProblem::KindOrder; 118]);
    assert!(sessions_found(&r).is_empty(), "{:?}", sessions_found(&r));

    // A catch-up group of full frames may be followed by another: a
    // backlog may remain. Before the gateway closed (the bytes are no
    // ledger object yet), slot 151 silent and declared, slot 152 two full
    // frames, 153 the rest: allowed; 154 is not.
    let key = day().links[SCANNER].key;
    let f150 = day().links[SCANNER].frames[0].clone();
    let end = u64::from(f150.payload_len);
    let most = MAX_PAYLOAD_LEN as u64;
    let big = fake_object(
        SCHEMA_PROGRESS_TICK,
        &std::vec![0x42; 2 * MAX_PAYLOAD_LEN + 100],
    );
    let entry = entry_at(big, end);
    let mut frames = std::vec![f150];
    let catch_up = |slot: u64, index: u16, from: u64, len: u64| {
        let mut f = make_frame(key, slot, index, FrameKind::CatchUp, from, &[]);
        f.data = big[(from - end) as usize..(from - end + len) as usize].to_vec();
        f.payload_len = len as u32;
        f.objects = std::vec![entry];
        f.seal(key, link(key));
        f
    };
    frames.push(catch_up(152, 0, end, most));
    frames.push(catch_up(152, 1, end + most, most));
    frames.push(catch_up(153, 0, end + 2 * most, 100));
    let after = end + 2 * most + 100;
    frames.push(make_frame(key, 153, 1, FrameKind::CatchUp, after, &[]));
    frames.push(make_frame(key, 154, 0, FrameKind::CatchUp, after, &[]));
    frames.push(make_frame(key, 154, 1, FrameKind::CatchUp, after, &[]));
    for slot in 155..=212 {
        frames.push(make_frame(key, slot, 0, FrameKind::Normal, after, &[]));
    }
    let mut links = honest_links();
    links[SCANNER] = Link {
        key,
        frames,
        objects: Vec::new(),
    };
    let mut plan = Plan::new(ST, links);
    plan.tweak_link = Some(&declare);
    plan.tweak_body = Some(&not_final);
    let r = verify(plan.events());
    assert_eq!(found(&r, scanner()), [LinkProblem::KindOrder; 2]);
    let kinds: Vec<u64> = link_report(&r, scanner())
        .findings
        .iter()
        .map(|f| f.slot.unwrap())
        .collect();
    assert_eq!(kinds, [154, 154]);
}

#[test]
fn r3_1c_batches_keep_their_order_in_a_witnessed_resend() {
    // Two batches; their normal frames were lost (slot 150, declared). A
    // witnessed resend after the close carries them: in order, nothing;
    // batch 1 first, `Batch`.
    for (order, problems) in [([0usize, 1], &[][..]), ([1, 0], &[LinkProblem::Batch][..])] {
        let (book, s) = two_batches();
        let batches = [with_packages(&s[..4]), with_packages(&s[4..8])];
        let mut links = links_of(&book);
        let key = links[SCANNER].key;
        let mut groups: Vec<(u64, FrameKind, Vec<&'static [u8]>)> = std::vec![(
            150,
            FrameKind::Normal,
            [batches[0].clone(), batches[1].clone(), std::vec![s[8]]].concat()
        )];
        for slot in 151..=212 {
            groups.push((slot, FrameKind::Normal, Vec::new()));
        }
        let mut l = link_of(key, &groups, 1);
        let end = l.frames.last().unwrap().stream_offset;
        let resend = [batches[order[0]].clone(), batches[order[1]].clone()].concat();
        l.frames.push(make_frame(
            key,
            220,
            0,
            FrameKind::WitnessedResend,
            end,
            &resend,
        ));
        let next = end + u64::from(l.frames.last().unwrap().payload_len);
        l.frames.push(make_frame(
            key,
            220,
            1,
            FrameKind::WitnessedResend,
            next,
            &[],
        ));
        links[SCANNER] = l;
        let mut plan = Plan::new(ST, links);
        plan.windows = resend_windows(220);
        let lose = |l: usize, f: &Built| {
            if l == SCANNER && f.slot == 150 {
                None
            } else if f.slot >= 220 {
                Some(11)
            } else {
                window(f.slot)
            }
        };
        let declare = declare_one(1);
        plan.assign = Some(&lose);
        plan.tweak_link = Some(&declare);
        let r = verify_book(book, plan.events());
        assert_eq!(found(&r, scanner()), problems, "{order:?}");
        assert!(sessions_found(&r).is_empty(), "{:?}", sessions_found(&r));
    }
}

/// A progress tick of BOX-1 for `slot` in state `state`, signed by its
/// device.
fn box_tick_in(slot: u64, state: ityv_encoding::BoxProgressState) -> &'static [u8] {
    use ityv_encoding::{
        BoxProgressBody, BoxProgressParts, ProgressTick, SCHEMA_BOX_PROGRESS_BODY, SCHEMA_VERSION_1,
    };
    let body = common::object(
        SCHEMA_BOX_PROGRESS_BODY,
        SCHEMA_VERSION_1,
        &BoxProgressBody::new(&BoxProgressParts {
            election_id: common::election(),
            box_id: BoxId::new(B1.id).unwrap(),
            slot,
            sheets_in: 3,
            state,
        }),
    );
    common::object(
        SCHEMA_PROGRESS_TICK,
        SCHEMA_VERSION_1,
        &ProgressTick::new(
            body,
            common::sign(common::signing(B1.device), b"box-progress", body),
        )
        .unwrap(),
    )
}

#[test]
fn r3_1d_a_close_resend_sends_the_boxs_batches_again_in_order() {
    // The close resend in the close slot: the box's two batches in their
    // order, nothing; batch 1 first and ticks after them, findings.
    let (mut book, s) = two_batches();
    let tick200 = box_tick_in(200, ityv_encoding::BoxProgressState::Casting);
    book.push(SCHEMA_PROGRESS_TICK, tick200);
    let normal = with_packages(&s);
    let key = links_of(&book)[SCANNER].key;
    let make = |resend: Vec<&'static [u8]>| {
        let mut groups: Vec<(u64, FrameKind, Vec<&'static [u8]>)> = Vec::new();
        for slot in 150..=211 {
            let objs = match slot {
                150 => normal.clone(),
                200 => std::vec![tick200],
                _ => Vec::new(),
            };
            groups.push((slot, FrameKind::Normal, objs));
        }
        let mut l = link_of(key, &groups, 1);
        let mut at = l
            .frames
            .last()
            .map_or(0, |f| f.stream_offset + u64::from(f.payload_len));
        let f0 = make_frame(key, 212, 0, FrameKind::CatchUp, at, &[]);
        at += u64::from(f0.payload_len);
        let f1 = make_frame(key, 212, 1, FrameKind::CloseResend, at, &resend);
        l.frames.push(f0);
        l.frames.push(f1);
        l
    };
    let honest = with_packages(&s[..8]);
    let shuffled = with_packages(&[
        s[4], s[5], s[6], s[7], s[0], s[1], s[2], s[3], tick200, s[8],
    ]);
    for (resend, clean) in [(honest, true), (shuffled, false)] {
        let (mut book, _) = two_batches();
        book.push(SCHEMA_PROGRESS_TICK, tick200);
        let mut links = links_of(&book);
        links[SCANNER] = make(resend);
        let r = verify_book(book, Plan::new(ST, links).events());
        let problems = found(&r, scanner());
        if clean {
            assert!(problems.is_empty(), "{problems:?}");
        } else {
            assert!(problems.contains(&LinkProblem::Resend), "{problems:?}");
            assert!(problems.contains(&LinkProblem::Batch), "{problems:?}");
            assert!(box_holds(&r).contains(HoldReason::UplinkObjectInvalid));
        }
    }
}

#[test]
fn r3_1e_a_witnessed_resend_carries_only_what_is_still_missing() {
    // After the close, a witnessed resend of the batch the normal frames
    // carried whole: `Resend` for each of its objects. Listed again in a
    // later witnessed slot after a whole listing: `Repeat` too.
    let o = scanner_objects();
    let run = with_packages(&o[..4]);
    let mut links = honest_links();
    let end = stream_len(&links[SCANNER]);
    add_witnessed(&mut links, &run, end, (220, 220), MAX_PAYLOAD_LEN);
    let r = run_witnessed_kept(links, resend_windows(220));
    assert_eq!(found(&r, scanner()), [LinkProblem::Resend; 7]);
    assert!(box_holds(&r).contains(HoldReason::UplinkObjectInvalid));
    // The batch listed whole in a witnessed slot and again in a later one.
    let mut links = honest_links();
    let end = stream_len(&links[SCANNER]);
    add_witnessed(&mut links, &run, end, (220, 220), MAX_PAYLOAD_LEN);
    let last = links[SCANNER].frames.last().unwrap();
    let second = last.stream_offset + u64::from(last.payload_len);
    add_witnessed(&mut links, &run, second, (222, 222), MAX_PAYLOAD_LEN);
    let r = run_witnessed_kept(links, resend_windows(220));
    let problems = found(&r, scanner());
    assert!(problems.contains(&LinkProblem::Repeat), "{problems:?}");
}

/// The report over the day with `links` and session windows `windows`
/// (the last one the witnessed resend's), nothing lost.
fn run_witnessed_kept(links: Vec<Link>, windows: Vec<(u64, u64)>) -> Report<'static> {
    let last = windows.len() - 1;
    let file = windows.clone();
    let assign = move |_: usize, f: &Built| {
        if f.kind == FrameKind::WitnessedResend {
            Some(last)
        } else {
            file.iter().position(|(a, b)| *a <= f.slot && f.slot <= *b)
        }
    };
    let mut plan = Plan::new(ST, links);
    plan.windows = windows;
    plan.assign = Some(&assign);
    verify(plan.events())
}

#[test]
fn r3_2_a_record_whose_batch_is_not_laid_yet_holds_nothing() {
    // Mid-day: three records laid, their batch's attestation not yet; the
    // device's run [attestation | records] spans slots 150 and 151, and
    // slot 150 is lost (declared). The records after the loss belong to no
    // batch the ledger has yet: no finding until the gateway closed.
    let casts: Vec<Cast> = (1..=3).map(|i| cast(B1, i, 1)).collect();
    let all = codes(&casts);
    let attestation = batch(B1, 0, 1, 3, &all);
    let mut records: Vec<&'static [u8]> = casts.iter().map(|c| c.event).collect();
    records.sort_by_key(|r| ityv_crypto::object_hash(r).0);
    let run = with_packages(&records);
    let make_book = || {
        let mut book = Book::new(election_world());
        book.w(opened(B1));
        for c in &casts {
            book.push(ityv_encoding::SCHEMA_CAST_RECORD, c.event);
        }
        book
    };
    let links = links_of(&make_book());
    let key = links[SCANNER].key;
    let unit = links[UNIT].clone();
    let last = links[SCANNER].frames.last().unwrap().slot;
    let mut groups = std::vec![
        (150u64, FrameKind::Normal, std::vec![attestation]),
        (151, FrameKind::Normal, run),
    ];
    for slot in 152..=last {
        groups.push((slot, FrameKind::Normal, Vec::new()));
    }
    let scanner_link = link_of(key, &groups, 1);
    for lose in [false, true] {
        let drop150 = move |l: usize, f: &Built| {
            if lose && l == SCANNER && f.slot == 150 {
                None
            } else {
                window(f.slot)
            }
        };
        let declare = move |i: u32, e: &mut SessionLink| {
            if lose && i == 1 && e.link_id_hash == link(key) {
                e.missing_slots = 1;
            }
        };
        let mut plan = Plan::new(ST, std::vec![scanner_link.clone(), unit.clone()]);
        plan.assign = Some(&drop150);
        plan.tweak_link = Some(&declare);
        plan.tweak_body = Some(&not_final);
        let r = verify_book(make_book(), plan.events());
        assert!(sessions_found(&r).is_empty(), "{:?}", sessions_found(&r));
        assert!(
            found(&r, link(key)).is_empty(),
            "{:?}",
            found(&r, link(key))
        );
        assert_eq!(r.connectivity().holds(), HoldSet::empty());
    }
}

#[test]
fn r3_2b_until_the_close_is_laid_the_devices_frames_state_it() {
    // The session over the close slot is laid, BOX-1's close not yet. The
    // device closed: its close slot 212 is a catch-up group, and it sends
    // nothing after. That group states the close: no `KindOrder`, and
    // slots 213 to 215 are no missing slots, for the scanner or the unit,
    // before the close is laid and after.
    let casts: Vec<Cast> = (1..=3).map(|i| cast(B1, i, 1)).collect();
    let all = codes(&casts);
    let make_book = |closed: bool| {
        let mut book = Book::new(election_world());
        book.w(opened(B1));
        for c in &casts {
            book.push(ityv_encoding::SCHEMA_CAST_RECORD, c.event);
        }
        book.push(ityv_encoding::SCHEMA_BATCH_ATTEST, batch(B1, 0, 1, 3, &all));
        if closed {
            book.push(ityv_encoding::SCHEMA_BOX_CLOSE, close(B1, 3, 3, 0, &all));
        }
        book
    };
    let events = make_book(true).ledger.events.clone();
    let mine: Vec<&'static [u8]> = events
        .iter()
        .copied()
        .filter(|e| device_of(e) == Some((true, B1.id)))
        .collect();
    let s = with_packages(&box_stream(&mine));
    let links = links_of(&make_book(true));
    let key = links[SCANNER].key;
    let mut groups: Vec<(u64, FrameKind, Vec<&'static [u8]>)> = Vec::new();
    for slot in 150..=211u64 {
        groups.push((
            slot,
            FrameKind::Normal,
            if slot == 150 { s.clone() } else { Vec::new() },
        ));
    }
    let mut l = link_of(key, &groups, 1);
    let at = l
        .frames
        .last()
        .map_or(0, |f| f.stream_offset + u64::from(f.payload_len));
    l.frames
        .push(make_frame(key, 212, 0, FrameKind::CatchUp, at, &[]));
    l.frames
        .push(make_frame(key, 212, 1, FrameKind::CatchUp, at, &[]));
    let mut unit = links[UNIT].clone();
    unit.frames.retain(|f| f.slot <= 212);
    for closed in [true, false] {
        let mut plan = Plan::new(ST, std::vec![l.clone(), unit.clone()]);
        plan.tweak_body = Some(&not_final);
        let r = verify_book(make_book(closed), plan.events());
        assert!(
            found(&r, link(key)).is_empty(),
            "{closed}: {:?}",
            found(&r, link(key))
        );
        assert!(
            sessions_found(&r).is_empty(),
            "{closed}: {:?}",
            sessions_found(&r)
        );
        assert_eq!(r.connectivity().holds(), HoldSet::empty());
    }
}

/// The one-box election with two amendments: BOX-1's frame key becomes
/// `first`, then `second`; with both signed amendments.
fn twice_amended(first: u16, second: u16) -> (&'static World, &'static [u8], &'static [u8]) {
    let d = election_draft();
    let (body, authorization) = common::legal_authorization(&TALLY_SCOPES, 20_000, 20_100);
    let built = leak(common::sign_genesis_with(&d, d.raw(), &SIGNERS, |p| {
        p.legal_authorization_hash = ityv_crypto::object_hash(body);
    }));
    let mut one = d.clone();
    one.boxes[0].frame_key = common::uplink::frame_key(first);
    one.appointments = one.referenced_appointments();
    let a1 = common::amendment(1, built.pin, &one.raw(), &SIGNERS);
    let mut two = one.clone();
    two.boxes[0].frame_key = common::uplink::frame_key(second);
    two.appointments = two.referenced_appointments();
    let a2 = common::amendment(2, common::body_hash(a1.signed), &two.raw(), &SIGNERS);
    let genesis = leak(ityv_verify::verify_genesis(&built.pin, &built.input(), &[a1, a2]).unwrap());
    (
        leak(World {
            genesis,
            pin: built.pin,
            signed: built.signed,
            authorization,
        }),
        a1.signed,
        a2.signed,
    )
}

#[test]
fn r3_3_each_frame_key_starts_with_the_event_that_brought_it() {
    // Before the opening an amendment replaces BOX-1's transmitter (key
    // 600 → 650, no swap: the box is not open); on the day a second
    // amendment and a witnessed swap at slot 181 replace it again (650 →
    // 651). Key 650 sends from the opening to 180, key 651 from 181 to the
    // close: nothing to find.
    let (k1, k2) = (
        common::uplink::BOX_FRAME_BASE + 50,
        common::uplink::BOX_FRAME_BASE + 51,
    );
    let (w, a1, a2) = twice_amended(k1, k2);
    let mut book = Book::new(w);
    book.push(ityv_encoding::SCHEMA_SIGNED_GENESIS, a1);
    for (schema, event) in &day().events {
        book.push(*schema, event);
    }
    book.push(ityv_encoding::SCHEMA_SIGNED_GENESIS, a2);
    let (schema, event) = box_swap(181);
    book.push(schema, event);
    let o = scanner_objects();
    let honest = with_packages(&o);
    let mut g1: Vec<(u64, FrameKind, Vec<&'static [u8]>)> = Vec::new();
    for slot in 150..=180u64 {
        let objs = if slot == 150 {
            honest[..honest.len() - 1].to_vec()
        } else {
            Vec::new()
        };
        g1.push((slot, FrameKind::Normal, objs));
    }
    let mut g2: Vec<(u64, FrameKind, Vec<&'static [u8]>)> = Vec::new();
    for slot in 181..=212u64 {
        let objs = if slot == 212 {
            std::vec![o[4]]
        } else {
            Vec::new()
        };
        g2.push((slot, FrameKind::Normal, objs));
    }
    let mut links = honest_links();
    links[SCANNER] = link_of(k1, &g1, 1);
    links.push(link_of(k2, &g2, 1));
    let r = verify_book(book, Plan::new(ST, links).events());
    assert!(sessions_found(&r).is_empty(), "{:?}", sessions_found(&r));
    assert!(found(&r, link(k1)).is_empty(), "{:?}", found(&r, link(k1)));
    assert!(found(&r, link(k2)).is_empty(), "{:?}", found(&r, link(k2)));
    assert_eq!(link_report(&r, link(k2)).missing_slots, 0);
    assert_eq!(r.connectivity().holds(), HoldSet::empty());
}

#[test]
fn r3_3b_a_transmitter_replaced_alone_on_the_day_has_an_honest_path() {
    // During the day BOX-1's transmitter (a part of its own, ADR-0041
    // decision 2) is replaced: an amendment gives the box frame key 650,
    // its device key unchanged. With a witnessed swap at slot 181 the box
    // stage takes the swap and nothing holds; without one, key 650 was
    // brought in by nothing on the ledger.
    let new_key = common::uplink::BOX_FRAME_BASE + 50;
    let (w, amendment) = leak(election_amended(|d| {
        d.boxes[0].frame_key = common::uplink::frame_key(new_key);
    }));
    let old_key = day().links[SCANNER].key;
    let o = scanner_objects();
    let honest = with_packages(&o);
    // The box's ticks as [`book_swapped`] lays them: casting at 150, closed
    // at the swap's slot (the day's own closing tick without a swap).
    let ticks = |swap: bool| {
        if swap {
            (
                box_tick_in(150, ityv_encoding::BoxProgressState::Casting),
                box_tick_in(181, ityv_encoding::BoxProgressState::Closed),
            )
        } else {
            (o[4], o[4])
        }
    };
    let groups = |swap: bool| {
        let (first, last) = ticks(swap);
        let mut g_old = Vec::new();
        for slot in 150..=180u64 {
            let mut objs = Vec::new();
            if slot == 150 {
                objs = honest[..honest.len() - 1].to_vec();
                if swap {
                    objs.push(first);
                }
            }
            g_old.push((slot, FrameKind::Normal, objs));
        }
        let mut g_new = Vec::new();
        for slot in 181..=212u64 {
            g_new.push((
                slot,
                FrameKind::Normal,
                if slot == 212 {
                    std::vec![last]
                } else {
                    Vec::new()
                },
            ));
        }
        (g_old, g_new)
    };
    // `catchup`: the new transmitter's slot that is a catch-up group (two
    // frames here), if any.
    let run = |swap: bool, catchup: Option<u64>| {
        let book = if swap {
            book_swapped(w, amendment, 181)
        } else {
            let mut book = book_in(w);
            book.push(ityv_encoding::SCHEMA_SIGNED_GENESIS, amendment);
            book
        };
        let (g_old, g_new) = groups(swap);
        let mut links = honest_links();
        links[SCANNER] = link_of(old_key, &g_old, 1);
        let mut new = link_of(new_key, &g_new, 1);
        if let Some(slot) = catchup {
            reseal(&mut new, slot, |f| f.kind = FrameKind::CatchUp);
            add(&mut new, slot, |f| f.index = 1);
        }
        links.push(new);
        verify_book(book, Plan::new(ST, links).events())
    };
    // Its first slot may be a catch-up group: the device could not send
    // while the old transmitter was out.
    for catchup in [None, Some(181)] {
        let r = run(true, catchup);
        assert!(sessions_found(&r).is_empty(), "{:?}", sessions_found(&r));
        assert_eq!(r.connectivity().holds(), HoldSet::empty());
        assert!(
            r.status().holds().is_empty(),
            "{:?} {:?}",
            r.status().holds(),
            r.progress()
        );
    }
    // A later one, after a whole slot: out of its kind's place.
    let r = run(true, Some(182));
    assert_eq!(found(&r, link(new_key)), [LinkProblem::KindOrder; 2]);
    let r = run(false, None);
    assert!(found(&r, link(new_key)).contains(&LinkProblem::BeforeSwap));
}

#[test]
fn r3_4_a_spare_transmitter_does_not_send_before_its_swap() {
    // An amendment and a swap at slot 181 replace BOX-1's transmitter; the
    // spare transmits from the opening, in parallel with the old one.
    let new_key = common::uplink::BOX_FRAME_BASE + 50;
    let (w, amendment) = leak(election_amended(|d| {
        d.boxes[0].frame_key = common::uplink::frame_key(new_key);
    }));
    let old_key = day().links[SCANNER].key;
    let o = scanner_objects();
    let honest = with_packages(&o);
    let mut book = book_in(w);
    book.push(ityv_encoding::SCHEMA_SIGNED_GENESIS, amendment);
    let (schema, event) = box_swap(181);
    book.push(schema, event);
    let mut g_old = Vec::new();
    for slot in 150..=180u64 {
        g_old.push((
            slot,
            FrameKind::Normal,
            if slot == 150 {
                honest[..honest.len() - 1].to_vec()
            } else {
                Vec::new()
            },
        ));
    }
    let mut g_new = Vec::new();
    for slot in 150..=212u64 {
        g_new.push((
            slot,
            FrameKind::Normal,
            match slot {
                150 => with_packages(&o[..4]),
                212 => std::vec![o[4]],
                _ => Vec::new(),
            },
        ));
    }
    let mut links = honest_links();
    links[SCANNER] = link_of(old_key, &g_old, 1);
    links.push(link_of(new_key, &g_new, 1));
    let r = verify_book(book, Plan::new(ST, links).events());
    assert_eq!(found(&r, link(new_key)), [LinkProblem::BeforeSwap; 31]);
    assert!(box_holds(&r).contains(HoldReason::UplinkFrameInvalid));
}

#[test]
fn r3_5_a_share_package_does_not_open_the_stream() {
    // A sealed package at offset 0, before the record that names it.
    let o = scanner_objects();
    let p1 = common::uplink::package_of(o[1]).unwrap();
    let mut s = std::vec![p1];
    s.extend(with_packages(&o));
    let r = verify(Plan::new(ST, with_stream(SCANNER, &s)).events());
    assert_eq!(found(&r, scanner()), [LinkProblem::Package]);
    // After a loss it may: its record may have been lost.
    let r = verify(Plan::new(ST, with_stream(SCANNER, &with_packages(&o))).events());
    assert!(found(&r, scanner()).is_empty());
}

/// The one-box election whose scanner sends four normal frames a slot
/// and eight at the catch-up shape.
fn wide_world() -> &'static World {
    static W: OnceLock<&'static World> = OnceLock::new();
    W.get_or_init(|| {
        let mut entries = common::uplink::standard_entries();
        for e in &mut entries {
            if e.device_class == DeviceClass::CommitmentUnit {
                e.frames_per_slot = 4;
                e.catchup_frames_per_slot = 8;
            }
        }
        manifest_world(common::uplink::manifest(&entries))
    })
}

/// BOX-1 in [`wide_world`] with three records in three batches of one,
/// closed, and its station's record; each batch's run (attestation,
/// record, package) and the box's closing tick.
fn three_batches() -> (Book, Vec<Vec<&'static [u8]>>, &'static [u8]) {
    let mut book = Book::new(wide_world());
    let casts: Vec<Cast> = (1..=3).map(|i| cast(B1, i, 1)).collect();
    book.w(opened(B1));
    for c in &casts {
        book.push(ityv_encoding::SCHEMA_CAST_RECORD, c.event);
    }
    let all = codes(&casts);
    for i in 0..3u32 {
        let k = i as usize;
        book.push(
            ityv_encoding::SCHEMA_BATCH_ATTEST,
            batch(B1, i, u64::from(i) + 1, u64::from(i) + 1, &all[k..=k]),
        );
    }
    book.push(ityv_encoding::SCHEMA_BOX_CLOSE, close(B1, 3, 3, 0, &all));
    for (schema, event) in station_record(3) {
        book.push(schema, event);
    }
    book.push(SCHEMA_PARTICIPATION_SET, participation(3));
    let events = book.ledger.events.clone();
    let mine: Vec<&'static [u8]> = events
        .iter()
        .copied()
        .filter(|e| device_of(e) == Some((true, B1.id)))
        .collect();
    let stream = box_stream(&mine);
    let runs = (0..3)
        .map(|i| with_packages(&stream[2 * i..2 * i + 2]))
        .collect();
    (book, runs, stream[6])
}

/// The report over [`three_batches`] with the scanner sending `slots`
/// (each slot's four normal frames, by the runs they carry: `None` empty)
/// from slot 150, the tick in (150, 3), the close slot 212 a close resend
/// of the three runs, and the frames `lost` lost on the line and declared.
fn run_copies(slots: &[[Option<usize>; 4]], lost: &[(u64, u16)]) -> Report<'static> {
    let (book, runs, tick) = three_batches();
    let mut links = links_of(&book);
    let key = links[SCANNER].key;
    let mut frames = Vec::new();
    let mut at = 0u64;
    let mut push = |slot: u64, index: u16, kind: FrameKind, objs: &[&'static [u8]]| {
        let f = make_frame(key, slot, index, kind, at, objs);
        at += u64::from(f.payload_len);
        frames.push(f);
    };
    for slot in 150..=211u64 {
        let plan = slots
            .get((slot - 150) as usize)
            .copied()
            .unwrap_or([None; 4]);
        for (index, run) in plan.iter().enumerate() {
            let objs: Vec<&'static [u8]> = match (slot, index, run) {
                (150, 3, _) => std::vec![tick],
                (_, _, Some(r)) => runs[*r].clone(),
                (_, _, None) => Vec::new(),
            };
            push(slot, index as u16, FrameKind::Normal, &objs);
        }
    }
    for index in 0..8u16 {
        let objs: Vec<&'static [u8]> = runs.get(index as usize).cloned().unwrap_or_default();
        push(212, index, FrameKind::CloseResend, &objs);
    }
    links[SCANNER] = Link {
        key,
        frames,
        objects: Vec::new(),
    };
    let lost = lost.to_vec();
    let short: BTreeSet<u64> = lost.iter().map(|(s, _)| *s).collect();
    let drop = move |l: usize, f: &Built| {
        if l == SCANNER && lost.contains(&(f.slot, f.index)) {
            None
        } else {
            window(f.slot)
        }
    };
    let declare = move |i: u32, e: &mut SessionLink| {
        if e.link_id_hash == link(key) {
            e.missing_slots = short
                .iter()
                .filter(|s| window(**s) == Some(i as usize - 1))
                .count() as u32;
        }
    };
    let mut plan = Plan::new(ST, links);
    plan.assign = Some(&drop);
    plan.tweak_link = Some(&declare);
    verify_book(book, plan.events())
}

#[test]
fn r3_6_a_lost_first_copy_comes_again_before_the_next_slots_batches() {
    // Batches 0 and 1 close in slot 150 and go out there; batch 0's first
    // copy is lost (declared). In slot 151 the device sends the second
    // copies first (batch 0, then 1), as PROTOCOL.md §5.8 item 4 has it:
    // batch 0 is first received after batch 1, across that loss: nothing.
    let honest = [
        [Some(0), Some(1), None, None],
        [Some(0), Some(1), Some(2), None],
        [Some(2), None, None, None],
    ];
    let r = run_copies(&honest, &[(150, 0)]);
    assert!(
        found(&r, scanner()).is_empty(),
        "{:?}",
        found(&r, scanner())
    );
    assert!(sessions_found(&r).is_empty(), "{:?}", sessions_found(&r));
    assert_eq!(r.connectivity().holds(), HoldSet::empty());
    // A new batch before the second copies is not the protocol's order:
    // batch 0 first received after batch 2, sent in the same slot.
    let new_first = [
        [Some(0), Some(1), None, None],
        [Some(2), Some(0), Some(1), None],
        [Some(2), None, None, None],
    ];
    let r = run_copies(&new_first, &[(150, 0)]);
    assert_eq!(found(&r, scanner()), [LinkProblem::Batch]);
    // Nothing lost, each batch is first received in its own slot, in
    // order, whatever a slot sends first.
    let r = run_copies(&new_first, &[]);
    assert!(
        found(&r, scanner()).is_empty(),
        "{:?}",
        found(&r, scanner())
    );
}

#[test]
fn r3_6_no_loss_pattern_of_three_batches_holds_an_honest_device() {
    // Batches 0 and 1 close in slot 150, batch 2 in 151; each goes out in
    // its slot and again in the next (second copies first), and the close
    // slot sends them all again. Every set of the six copies' frames lost
    // on the line and declared: nothing to find, nothing held.
    let honest = [
        [Some(0), Some(1), None, None],
        [Some(0), Some(1), Some(2), None],
        [Some(2), None, None, None],
    ];
    let copies = [
        (150u64, 0u16),
        (150, 1),
        (151, 0),
        (151, 1),
        (151, 2),
        (152, 0),
    ];
    for mask in 0..64u32 {
        let lost: Vec<(u64, u16)> = copies
            .iter()
            .enumerate()
            .filter(|(i, _)| mask & (1 << i) != 0)
            .map(|(_, c)| *c)
            .collect();
        let r = run_copies(&honest, &lost);
        assert!(
            found(&r, scanner()).is_empty(),
            "{lost:?}: {:?}",
            found(&r, scanner())
        );
        assert!(
            sessions_found(&r).is_empty(),
            "{lost:?}: {:?}",
            sessions_found(&r)
        );
        assert_eq!(r.connectivity().holds(), HoldSet::empty(), "{lost:?}");
    }
}

#[test]
fn r3_7_a_challenged_record_whose_opening_is_not_laid_yet_holds_nothing() {
    // The audit for finding 4. BOX-1's batch takes counters 1–4; one of
    // its records (the second by hash) was opened for a challenge, so no
    // batch attests it. The record and its opening go out in slot 150,
    // outside every run; the batch and the other three in 151. Until the
    // opening is laid the record stage counts the challenged record a
    // member, and the run skips it. Mid-day, with slot 150 lost (declared)
    // or the opening listed and not laid: nothing. Once the gateway closed
    // with the opening never laid: `Batch`.
    let casts: Vec<Cast> = (1..=4).map(|i| cast(B1, i, 1)).collect();
    let mut sorted = casts.clone();
    sorted.sort_by_key(|c| ityv_crypto::object_hash(c.event).0);
    let challenged = sorted[1];
    let opening = challenge(B1, &challenged);
    let rest: Vec<Cast> = sorted
        .iter()
        .copied()
        .filter(|c| c.counter != challenged.counter)
        .collect();
    let attestation = batch(B1, 0, 1, 4, &codes(&rest));
    let make_book = |laid: bool| {
        let mut book = Book::new(election_world());
        book.w(opened(B1));
        for c in &casts {
            book.push(ityv_encoding::SCHEMA_CAST_RECORD, c.event);
        }
        if laid {
            book.push(ityv_encoding::SCHEMA_CHALLENGE_OPENING, opening);
        }
        book.push(ityv_encoding::SCHEMA_BATCH_ATTEST, attestation);
        book
    };
    let mut run = std::vec![attestation];
    run.extend(rest.iter().map(|c| c.event));
    let links = links_of(&make_book(true));
    let key = links[SCANNER].key;
    let unit = links[UNIT].clone();
    let last = links[SCANNER].frames.last().unwrap().slot;
    let mut groups = std::vec![
        (
            150u64,
            FrameKind::Normal,
            with_packages(&[opening, challenged.event]),
        ),
        (151, FrameKind::Normal, with_packages(&run)),
    ];
    for slot in 152..=last {
        groups.push((slot, FrameKind::Normal, Vec::new()));
    }
    let scanner_link = link_of(key, &groups, 1);
    // (slot 150 lost, the gateway closed)
    for (lose, closed) in [(true, false), (false, false), (false, true)] {
        let drop150 = move |l: usize, f: &Built| {
            if lose && l == SCANNER && f.slot == 150 {
                None
            } else {
                window(f.slot)
            }
        };
        let declare = move |i: u32, e: &mut SessionLink| {
            if lose && i == 1 && e.link_id_hash == link(key) {
                e.missing_slots = 1;
            }
        };
        let mut plan = Plan::new(ST, std::vec![scanner_link.clone(), unit.clone()]);
        plan.assign = Some(&drop150);
        plan.tweak_link = Some(&declare);
        if !closed {
            plan.tweak_body = Some(&not_final);
        }
        let r = verify_book(make_book(false), plan.events());
        let f = found(&r, link(key));
        if closed {
            assert!(f.contains(&LinkProblem::Batch), "{f:?}");
        } else {
            assert!(f.is_empty(), "{lose}: {f:?}");
            assert_eq!(r.connectivity().holds(), HoldSet::empty());
        }
    }
}

#[test]
fn r3_8_until_a_links_start_is_laid_a_lost_first_slot_may_be_declared() {
    // The audit for finding 4. Mid-day, BOX-1's opening not laid yet: the
    // scanner's first slot (150) was lost and the first session declares
    // it. Until the ledger says where the link starts, the slots of a
    // window before its first frame may be its own: nothing. The session
    // may declare no more than those (`MissingSlots`), and once the
    // opening is laid the count is exact.
    let make_book = |laid: bool| {
        let mut book = Book::new(election_world());
        if laid {
            book.w(opened(B1));
        }
        book
    };
    let links = links_of(&make_book(true));
    let key = links[SCANNER].key;
    let unit = links[UNIT].clone();
    let last = links[SCANNER].frames.last().unwrap().slot;
    let groups: Vec<(u64, FrameKind, Vec<&'static [u8]>)> = (150..=last)
        .map(|s| (s, FrameKind::Normal, Vec::new()))
        .collect();
    let scanner_link = link_of(key, &groups, 1);
    // (the opening laid, the slots declared, refused)
    for (laid, declared, refused) in [
        (false, 1, false),
        (false, 2, true),
        (true, 1, false),
        (true, 0, true),
    ] {
        let drop150 = |l: usize, f: &Built| {
            if l == SCANNER && f.slot == 150 {
                None
            } else {
                window(f.slot)
            }
        };
        let declare = move |i: u32, e: &mut SessionLink| {
            if i == 1 && e.link_id_hash == link(key) {
                e.missing_slots = declared;
            }
        };
        let mut plan = Plan::new(ST, std::vec![scanner_link.clone(), unit.clone()]);
        plan.assign = Some(&drop150);
        plan.tweak_link = Some(&declare);
        plan.tweak_body = Some(&not_final);
        let r = verify_book(make_book(laid), plan.events());
        let s = sessions_found(&r);
        assert_eq!(
            s.contains(&(1, SessionProblem::MissingSlots)),
            refused,
            "{laid} {declared}: {s:?}"
        );
        if !refused {
            assert!(s.is_empty(), "{s:?}");
            assert_eq!(r.connectivity().holds(), HoldSet::empty());
        }
    }
}

#[test]
fn r3_9_the_stations_opening_waits_for_every_box() {
    // The audit for finding 4. ST-1 with two boxes; only BOX-2's opening
    // is laid, two buckets after the opening (BOX-1's is not laid yet). The
    // check-in unit sends from slot 150. Until every box's opening is laid
    // the station's opening is not known: mid-day, nothing is before it.
    // Once the gateway closed with BOX-1 never opened, the unit's frames
    // before BOX-2's opening are `BeforeOpening`.
    let w = two_unit_world();
    let make_book = || {
        let mut book = Book::new(w);
        book.w(opened_at(B2, OPEN_BUCKET + 2));
        book
    };
    let links = station_links(w.genesis, &make_book().ledger.events)
        .remove(0)
        .1;
    let unit_key = links[UNIT].key;
    let first = links[UNIT].frames[0].slot;
    assert!(first > 150);
    let per_slot = u16::try_from(
        links[UNIT]
            .frames
            .iter()
            .filter(|f| f.slot == first)
            .count(),
    )
    .unwrap();
    // Both links to the end of the last session's window (sessions of six
    // slots from 150), BOX-2's scanner from its opening.
    let last = links[UNIT].frames.last().unwrap().slot;
    let last = 150 + (last - 150) / 6 * 6 + 5;
    let empty = |from: u64| -> Vec<(u64, FrameKind, Vec<&'static [u8]>)> {
        (from..=last)
            .map(|s| (s, FrameKind::Normal, Vec::new()))
            .collect()
    };
    let scanner = link_of(links[SCANNER].key, &empty(first), 1);
    let unit = link_of(unit_key, &empty(150), per_slot);
    for closed in [false, true] {
        let mut plan = Plan::new(ST, std::vec![scanner.clone(), unit.clone()]);
        if !closed {
            plan.tweak_body = Some(&not_final);
        }
        let r = verify_book(make_book(), plan.events());
        let f = found(&r, link(unit_key));
        assert_eq!(f.contains(&LinkProblem::BeforeOpening), closed, "{f:?}");
        if !closed {
            assert!(f.is_empty(), "{f:?}");
            assert!(sessions_found(&r).is_empty(), "{:?}", sessions_found(&r));
            assert_eq!(r.connectivity().holds(), HoldSet::empty());
        }
    }
}

#[test]
fn r3_10_until_the_gateway_closed_a_link_may_end_unannounced() {
    // The audit for finding 4. Mid-day, BOX-1's scanner stops after slot
    // 161 (its transmitter failed, say, and the swap that replaces it is
    // not laid yet); the check-in unit sends on to 167. The session over
    // 162–167 need not count the scanner's slots: a swap that ends its
    // span may still come. Once the gateway closed they are its missing
    // slots.
    let make_book = || {
        let mut book = Book::new(election_world());
        book.w(opened(B1));
        book
    };
    let links = links_of(&make_book());
    let key = links[SCANNER].key;
    let unit_key = links[UNIT].key;
    let first = links[UNIT].frames[0].slot;
    let per_slot = u16::try_from(
        links[UNIT]
            .frames
            .iter()
            .filter(|f| f.slot == first)
            .count(),
    )
    .unwrap();
    let empty = |to: u64| -> Vec<(u64, FrameKind, Vec<&'static [u8]>)> {
        (150..=to)
            .map(|s| (s, FrameKind::Normal, Vec::new()))
            .collect()
    };
    let scanner = link_of(key, &empty(161), 1);
    let unit = link_of(unit_key, &empty(167), per_slot);
    for closed in [false, true] {
        let mut plan = Plan::new(ST, std::vec![scanner.clone(), unit.clone()]);
        if !closed {
            plan.tweak_body = Some(&not_final);
        }
        let r = verify_book(make_book(), plan.events());
        let s = sessions_found(&r);
        assert_eq!(
            s.contains(&(3, SessionProblem::MissingSlots)),
            closed,
            "{s:?}"
        );
        if !closed {
            assert!(s.is_empty(), "{s:?}");
            assert_eq!(r.connectivity().holds(), HoldSet::empty());
        }
    }
}

#[test]
fn held_a_challenged_record_cannot_ride_in_a_run_and_travels_outside() {
    // BOX-1 with four records, the fourth opened for a challenge; the
    // batch takes counters 1–3. The challenged record and its opening go
    // outside every run: nothing. Put inside the run (between two of its
    // records): `Batch`.
    let casts: Vec<Cast> = (1..=4).map(|i| cast(B1, i, 1)).collect();
    let opened_c4 = challenge(B1, &casts[3]);
    let all = codes(&casts[..3]);
    let attestation = batch(B1, 0, 1, 3, &all);
    let make_book = || {
        let mut book = Book::new(election_world());
        book.w(opened(B1));
        for c in &casts {
            book.push(ityv_encoding::SCHEMA_CAST_RECORD, c.event);
        }
        book.push(ityv_encoding::SCHEMA_CHALLENGE_OPENING, opened_c4);
        book.push(ityv_encoding::SCHEMA_BATCH_ATTEST, attestation);
        book
    };
    let mut run: Vec<&'static [u8]> = casts[..3].iter().map(|c| c.event).collect();
    run.sort_by_key(|r| ityv_crypto::object_hash(r).0);
    let c4 = casts[3].event;
    let links = links_of(&make_book());
    let key = links[SCANNER].key;
    let last = links[SCANNER].frames.last().unwrap().slot;
    for inside in [false, true] {
        let stream: Vec<&'static [u8]> = if inside {
            let mut v = std::vec![attestation, run[0], c4];
            v.extend(&run[1..]);
            v.push(opened_c4);
            v
        } else {
            let mut v = std::vec![attestation];
            v.extend(&run);
            v.extend([opened_c4, c4]);
            v
        };
        let s = with_packages(&stream);
        let mut groups = std::vec![(150u64, FrameKind::Normal, s)];
        for slot in 151..=last {
            groups.push((slot, FrameKind::Normal, Vec::new()));
        }
        let l = link_of(key, &groups, 1);
        let mut plan = Plan::new(ST, std::vec![l, links[UNIT].clone()]);
        plan.tweak_body = Some(&not_final);
        let r = verify_book(make_book(), plan.events());
        let f = found(&r, link(key));
        if inside {
            assert!(f.contains(&LinkProblem::Batch), "{f:?}");
        } else {
            assert!(f.is_empty(), "{f:?}");
        }
    }
}

#[test]
fn held_a_ledger_hash_under_another_schema_is_always_a_finding() {
    // The batch attestation's hash listed as a cast record, a record's
    // package hash as a progress tick, a public tick's hash as a share
    // package: `Schema` each time, before the gateway closed as well.
    let o = scanner_objects();
    let p1 = common::uplink::package_of(o[1]).unwrap();
    for (schema, object) in [
        (ityv_encoding::SCHEMA_CAST_RECORD, o[0]),
        (SCHEMA_PROGRESS_TICK, p1),
        (SCHEMA_SHARE_PACKAGE, o[4]),
    ] {
        let honest = &day().links[SCANNER];
        let key = honest.key;
        let f150 = honest.frames[0].clone();
        let end = u64::from(f150.payload_len);
        let entry = StreamObject {
            schema,
            object_hash: ityv_crypto::object_hash(object),
            stream_offset: end,
            len: 3000,
        };
        let mut frames = std::vec![f150];
        let mut f = make_frame(key, 151, 0, FrameKind::Normal, end, &[]);
        f.data = std::vec![0x5Au8; 3000];
        f.payload_len = 3000;
        f.objects = std::vec![entry];
        f.seal(key, link(key));
        frames.push(f);
        for slot in 152..=212u64 {
            frames.push(make_frame(key, slot, 0, FrameKind::Normal, end + 3000, &[]));
        }
        let mut links = honest_links();
        links[SCANNER] = Link {
            key,
            frames,
            objects: Vec::new(),
        };
        let mut plan = Plan::new(ST, links);
        plan.tweak_body = Some(&not_final);
        let r = verify(plan.events());
        assert!(
            found(&r, scanner()).contains(&LinkProblem::Schema),
            "{:?}",
            found(&r, scanner())
        );
    }
}
