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

use std::sync::OnceLock;
use std::vec::Vec;

use common::uplink::{
    Built, Link, Plan, box_stream, capture_file, device_frames_of, device_of, entry_at,
    fake_object, incident_body, link, log_key, relog, schema_of, station_links, stream, wire_frame,
    with_packages,
};
use common::{COMMITTEE, leak, leak_slice};
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
    // then only resends.
    let mut links = honest_links();
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

    // A witnessed resend (a slot of its own, two frames: the catch-up
    // shape, in a session that starts with it), then a close resend.
    let mut links = honest_links();
    for index in 0..2 {
        add(&mut links[SCANNER], 211, |f| {
            f.slot = 220;
            f.index = index;
            f.kind = FrameKind::WitnessedResend;
        });
    }
    let mut plan = Plan::new(ST, links.clone());
    plan.windows = resend_windows(220);
    let r = verify(plan.events());
    assert!(
        found(&r, scanner()).is_empty(),
        "{:?}",
        found(&r, scanner())
    );
    assert!(sessions_found(&r).is_empty(), "{:?}", sessions_found(&r));
    for index in 0..2 {
        add(&mut links[SCANNER], 211, |f| {
            f.slot = 221;
            f.index = index;
            f.kind = FrameKind::CloseResend;
        });
    }
    let mut plan = Plan::new(ST, links);
    plan.windows = resend_windows(220);
    let r = verify(plan.events());
    assert_eq!(
        found(&r, scanner()),
        [LinkProblem::KindOrder, LinkProblem::KindOrder]
    );
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
        sheets_in: 0,
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
    // Every frame to the closing tick's slot arrived; the gateway's session
    // of a witnessed resend of the closing tick starts with it, in slot
    // 220. Starting past the stream's end skips where no position went
    // untaken.
    let tick = *scanner_objects().last().unwrap();
    let run = |skip: u64, from: u64| {
        let mut links = honest_links();
        let end = stream_len(&links[SCANNER]);
        add_witnessed(&mut links, &[tick], end + skip, (220, 220), MAX_PAYLOAD_LEN);
        let mut plan = Plan::new(ST, links);
        plan.windows = resend_windows(from);
        verify(plan.events())
    };
    let r = run(0, 220);
    assert!(
        found(&r, scanner()).is_empty(),
        "{:?}",
        found(&r, scanner())
    );
    assert!(sessions_found(&r).is_empty(), "{:?}", sessions_found(&r));
    assert_eq!(r.connectivity().holds(), HoldSet::empty());
    let r = run(100, 220);
    assert_eq!(found(&r, scanner()), [LinkProblem::Offset]);
    assert!(sessions_found(&r).is_empty(), "{:?}", sessions_found(&r));
    // A session that starts earlier makes the slots before the resend
    // slots the device must send in: the skip is allowed across them, but
    // each is a missing slot the gateway must declare.
    let r = run(100, 217);
    assert!(
        found(&r, scanner()).is_empty(),
        "{:?}",
        found(&r, scanner())
    );
    assert_eq!(sessions_found(&r), [(12, SessionProblem::MissingSlots)]);
    assert_eq!(link_report(&r, scanner()).missing_slots, 3);
}

#[test]
fn a_lost_witnessed_resend_is_a_position_the_stream_may_skip() {
    // A witnessed resend of the batch in slots 220 and 221; frame (220, 1)
    // is lost on the line and the gateway declares slot 220 missing. The
    // next frame starts past what it carried: a position of the witnessed
    // slots went untaken. The objects after the loss go on the batch's
    // run where it was cut.
    let o = scanner_objects();
    let batch = with_packages(&o[..4]);
    let lose = |l: usize, f: &Built| {
        if l == SCANNER && f.slot == 220 && f.index == 1 {
            None
        } else {
            Some(if f.slot >= 220 {
                11
            } else {
                window(f.slot).unwrap()
            })
        }
    };
    let run = |declared: u32| {
        let mut links = honest_links();
        let end = stream_len(&links[SCANNER]);
        add_witnessed(&mut links, &batch, end, (220, 221), 3 * 4096);
        // The lost frame carries part of the stream, and a frame after it
        // carries more.
        let frames = &links[SCANNER].frames;
        let lost = frames
            .iter()
            .find(|f| f.slot == 220 && f.index == 1)
            .unwrap();
        assert!(lost.payload_len > 0);
        assert!(frames.iter().any(|f| f.slot == 221 && f.payload_len > 0));
        let declare = move |i: u32, e: &mut SessionLink| {
            if i == 12 && e.link_id_hash == scanner() {
                e.missing_slots = declared;
            }
        };
        let mut plan = Plan::new(ST, links);
        plan.windows = resend_windows(220);
        plan.assign = Some(&lose);
        plan.tweak_link = Some(&declare);
        verify(plan.events())
    };
    let r = run(1);
    assert!(
        found(&r, scanner()).is_empty(),
        "{:?}",
        found(&r, scanner())
    );
    assert!(sessions_found(&r).is_empty(), "{:?}", sessions_found(&r));
    assert_eq!(r.connectivity().holds(), HoldSet::empty());
    // The witnessed slot is a slot the device must send in: left
    // undeclared, it is a disagreement.
    let r = run(0);
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
    assert_eq!(found(&r, link(spare_key)), [LinkProblem::NotObject]);
    assert_eq!(box_holds(&r), only(HoldReason::UplinkObjectInvalid));

    // A scanner's frame key from before a swap: an amendment gave BOX-1's
    // scanner a new frame key, and the old one still sends bytes that are
    // no object.
    let new_key = common::uplink::BOX_FRAME_BASE + 50;
    let (w, amendment) = leak(election_amended(|d| {
        d.boxes[0].frame_key = common::uplink::frame_key(new_key);
    }));
    let mut book = book_in(w);
    book.push(ityv_encoding::SCHEMA_SIGNED_GENESIS, amendment);
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
    assert_eq!(found(&r, link(old_key)), [LinkProblem::NotObject]);
    assert_eq!(box_holds(&r), only(HoldReason::UplinkObjectInvalid));
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

    // A witnessed resend of the closing tick in each of two runs of
    // witnessed slots (220, then 222 after a slot sent in vain and
    // declared): once in each. In two slots of one run: once too often.
    let tick = o[4];
    let t = tick.len() as u64;
    for (second, declared, problems) in [
        (222u64, 1u32, &[][..]),
        (221, 0, &[LinkProblem::Repeat][..]),
    ] {
        let mut links = honest_links();
        let end = stream_len(&links[SCANNER]);
        add_witnessed(&mut links, &[tick], end, (220, 220), MAX_PAYLOAD_LEN);
        add_witnessed(
            &mut links,
            &[tick],
            end + t,
            (second, second),
            MAX_PAYLOAD_LEN,
        );
        let declare = move |i: u32, e: &mut SessionLink| {
            if i == 12 && e.link_id_hash == scanner() {
                e.missing_slots = declared;
            }
        };
        let mut plan = Plan::new(ST, links);
        plan.windows = resend_windows(220);
        plan.tweak_link = Some(&declare);
        let r = verify(plan.events());
        assert_eq!(found(&r, scanner()), problems, "{second}");
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
    twice.push(o[4]);
    let (frames, listed) = device_frames_of(new_key, &twice, 181, 212, 1, 6000);
    let run = |frames: &Vec<Built>, lose_first: bool, declare: bool| {
        let mut book = book_in(w);
        book.push(ityv_encoding::SCHEMA_SIGNED_GENESIS, amendment);
        let (schema, event) = box_swap(181);
        book.push(schema, event);
        let mut links = honest_links();
        links[SCANNER] = Link {
            key: new_key,
            frames: frames.clone(),
            objects: listed.clone(),
        };
        links.push(Link {
            key: old_key,
            frames: common::uplink::frames(old_key, &[], 150, 180, 1),
            objects: Vec::new(),
        });
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
    // Nothing lost: clean.
    let r = run(&frames, false, false);
    assert!(
        found(&r, link(new_key)).is_empty(),
        "{:?}",
        found(&r, link(new_key))
    );
    assert_eq!(r.connectivity().holds(), HoldSet::empty());
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
    // A witnessed resend of the batch in slots 219 and 220, in a session
    // that starts with it; all of slot 219 is lost on the line and the
    // gateway declares it. Slot 219 is a position of the resend: the next
    // frame may start past what it carried.
    let o = scanner_objects();
    let batch = with_packages(&o[..4]);
    let run = |declared: u32| {
        let mut links = honest_links();
        let end = stream_len(&links[SCANNER]);
        add_witnessed(&mut links, &batch, end, (219, 220), 3 * 4096);
        assert!(
            links[SCANNER]
                .frames
                .iter()
                .any(|f| f.slot == 220 && f.payload_len > 0)
        );
        let lose = |l: usize, f: &Built| {
            if l == SCANNER && f.slot == 219 {
                None
            } else {
                Some(if f.slot >= 219 {
                    11
                } else {
                    window(f.slot).unwrap()
                })
            }
        };
        let declare = move |i: u32, e: &mut SessionLink| {
            if i == 12 && e.link_id_hash == scanner() {
                e.missing_slots = declared;
            }
        };
        let mut plan = Plan::new(ST, links);
        plan.windows = resend_windows(219);
        plan.assign = Some(&lose);
        plan.tweak_link = Some(&declare);
        verify(plan.events())
    };
    let r = run(1);
    assert!(
        found(&r, scanner()).is_empty(),
        "{:?}",
        found(&r, scanner())
    );
    assert!(sessions_found(&r).is_empty(), "{:?}", sessions_found(&r));
    assert_eq!(r.connectivity().holds(), HoldSet::empty());
    let r = run(0);
    assert!(
        found(&r, scanner()).is_empty(),
        "{:?}",
        found(&r, scanner())
    );
    assert_eq!(sessions_found(&r), [(12, SessionProblem::MissingSlots)]);
}

#[test]
fn r2_d_witnessed_slots_are_slots_the_device_must_send_in() {
    // A witnessed resend of the batch in slots 220 to 222; the gateway
    // drops all of slot 221. Undeclared, the session disagrees with its
    // log; declared, nothing is wrong.
    let o = scanner_objects();
    let batch = with_packages(&o[..4]);
    let run = |declared: u32, windows: Vec<(u64, u64)>| {
        let mut links = honest_links();
        let end = stream_len(&links[SCANNER]);
        add_witnessed(&mut links, &batch, end, (220, 222), 2 * 4096);
        let drop = |l: usize, f: &Built| {
            if l == SCANNER && f.slot == 221 {
                None
            } else if f.slot >= 220 {
                Some(11)
            } else {
                window(f.slot)
            }
        };
        let declare = move |i: u32, e: &mut SessionLink| {
            if i == 12 && e.link_id_hash == scanner() {
                e.missing_slots = declared;
            }
        };
        let mut plan = Plan::new(ST, links);
        plan.windows = windows;
        plan.assign = Some(&drop);
        plan.tweak_link = Some(&declare);
        verify(plan.events())
    };
    let r = run(0, resend_windows(220));
    assert_eq!(sessions_found(&r), [(12, SessionProblem::MissingSlots)]);
    assert_eq!(link_report(&r, scanner()).missing_slots, 1);
    let r = run(1, resend_windows(220));
    assert!(
        found(&r, scanner()).is_empty(),
        "{:?}",
        found(&r, scanner())
    );
    assert!(sessions_found(&r).is_empty(), "{:?}", sessions_found(&r));
    assert_eq!(r.connectivity().holds(), HoldSet::empty());
    // A session window that leaves slot 222 out: an undeclared gap.
    let mut windows = resend_windows(220);
    windows.last_mut().unwrap().1 = 221;
    let r = run(1, windows);
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
