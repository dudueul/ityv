//! The connectivity stage (PROTOCOL.md §5.8, §14 11; ADR-0022, ADR-0041;
//! VC-077..081, VC-083): the manifest's one-way rules, the gateway's
//! sessions and frame logs, each link's frames and objects, inclusion,
//! incidents, and the capture and carrier comparisons. A one-box election
//! with real signatures: BOX-1 at ST-1, opened in bucket 100 (slots 150 and
//! 151) and closed in bucket 140 (slots 210 and 211); each test changes one
//! thing an honest device or gateway would do.
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
    Built, Link, Plan, box_stream, capture_file, device_of, fake_object, incident_body, link,
    log_key, relog, schema_of, station_links, wire_frame,
};
use common::{COMMITTEE, leak, leak_slice};
use ityv_encoding::{
    BoxId, DeviceClass, Direction, EventRole, FrameKind, GatewayId, Hash512, LogObjects,
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
/// the links an honest gateway records at ST-1: BOX-1's scanner from slot
/// 150 to 211, U-1A from 150 to 212, one normal frame a slot, every object
/// in the first frame.
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

/// The end of the scanner's stream: every object is in its first frame.
fn stream_len(l: &Link) -> u64 {
    u64::from(l.frames[0].payload_len)
}

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
        (62, 0, 1, 0)
    );
    assert_eq!(b.slots, Some((150, 211)));
    assert_eq!(b.stream_end, stream_len(l));
    // The batch attestation, its three records, the closing tick.
    assert_eq!((b.objects, b.included), (5, 5));
    assert_eq!((b.checked_chunks, b.opaque_chunks), (data_chunks, 0));
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
    assert_eq!(sessions_found(&r), [(11, SessionProblem::AfterFinal)]);
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
}

#[test]
fn a_log_is_taken_once_by_its_session() {
    let honest = Plan::new(ST, honest_links()).events();
    let first = honest
        .iter()
        .position(|(s, e)| *s == SCHEMA_UPLINK_FRAME_LOG && log_key(e) == (1, scanner()))
        .unwrap();
    let other = relog(honest[first].1, |p| p.objects = LogObjects::EMPTY);

    // A second log of the session and link: the first stands.
    let mut events = honest.clone();
    events.insert(first + 1, (SCHEMA_UPLINK_FRAME_LOG, other));
    let r = verify(events);
    assert_eq!(sessions_found(&r), [(1, SessionProblem::LogRepeated)]);
    assert_eq!(link_report(&r, scanner()).objects, 5);

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

    // Declared: clean, and the stream may skip across it.
    let declare = |i: u32, e: &mut SessionLink| {
        if i == 1 && e.link_id_hash == scanner() {
            e.missing_slots = 1;
        }
    };
    let mut links = honest_links();
    let end = stream_len(&links[SCANNER]);
    for f in links[SCANNER].frames.iter_mut().filter(|f| f.slot > 152) {
        f.stream_offset = end + 9;
    }
    for slot in 153..=211 {
        reseal(&mut links[SCANNER], slot, |_| {});
    }
    let mut plan = Plan::new(ST, links);
    plan.assign = Some(&lose);
    plan.tweak_link = Some(&declare);
    let r = verify(plan.events());
    assert!(sessions_found(&r).is_empty(), "{:?}", sessions_found(&r));
    let b = link_report(&r, scanner());
    assert!(b.findings.is_empty(), "{:?}", b.findings);
    assert_eq!((b.frames, b.missing_slots, b.stream_end), (61, 1, end + 9));
    assert_eq!(r.connectivity().holds(), HoldSet::empty());
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

    // A catch-up frame in a slot of normal frames.
    let mut links = honest_links();
    add(&mut links[SCANNER], 160, |f| {
        f.kind = FrameKind::CatchUp;
        f.index = 1;
    });
    let r = verify(Plan::new(ST, links).events());
    assert_eq!(found(&r, scanner()), [LinkProblem::Shape]);
    assert!(sessions_found(&r).is_empty(), "{:?}", sessions_found(&r));

    // A whole slot of catch-up frames is a shape of its own.
    let mut links = honest_links();
    reseal(&mut links[SCANNER], 160, |f| f.kind = FrameKind::CatchUp);
    add(&mut links[SCANNER], 160, |f| f.index = 1);
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
    reseal(&mut links[SCANNER], 160, |f| f.kind = FrameKind::CatchUp);
    let r = verify(Plan::new(ST, links).events());
    assert!(
        found(&r, scanner()).is_empty(),
        "{:?}",
        found(&r, scanner())
    );
    assert_eq!(sessions_found(&r), [(2, SessionProblem::MissingSlots)]);
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
    add(&mut links[SCANNER], 211, |f| f.slot = 212);
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
    // Normal frames after a close resend.
    let mut links = honest_links();
    reseal(&mut links[SCANNER], 200, |f| {
        f.kind = FrameKind::CloseResend;
    });
    add(&mut links[SCANNER], 200, |f| f.index = 1);
    let r = verify(Plan::new(ST, links).events());
    let problems = found(&r, scanner());
    assert_eq!(problems.len(), 11);
    assert!(problems.iter().all(|p| *p == LinkProblem::KindOrder));

    // A witnessed resend (a slot of its own, outside the missing-slot
    // count), then a close resend.
    let mut links = honest_links();
    add(&mut links[SCANNER], 211, |f| {
        f.slot = 220;
        f.kind = FrameKind::WitnessedResend;
    });
    let r = verify(Plan::new(ST, links.clone()).events());
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
    let r = verify(Plan::new(ST, links).events());
    assert_eq!(
        found(&r, scanner()),
        [LinkProblem::KindOrder, LinkProblem::KindOrder]
    );
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

    // A stream that does not start at zero.
    let mut links = honest_links();
    for f in &mut links[UNIT].frames {
        f.stream_offset += 1;
    }
    for slot in 150..=212 {
        reseal(&mut links[UNIT], slot, |_| {});
    }
    let r = verify(Plan::new(ST, links).events());
    assert!(found(&r, unit()).contains(&LinkProblem::Offset));
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
    assert_eq!(box_holds(&r), only(HoldReason::UplinkFrameInvalid));
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

    // The scanner carries the station's participation set.
    let mut objects = scanner_objects();
    objects.push(unit_objects()[1]);
    let r = verify(Plan::new(ST, with_stream(SCANNER, &objects)).events());
    assert_eq!(found(&r, scanner()), [LinkProblem::Kind]);
    // It is on U-1A's link too: included there.
    assert!(station(&r).outside.is_empty());
}

#[test]
fn objects_tile_the_received_stream() {
    type Change = fn(Vec<StreamObject>) -> Vec<StreamObject>;
    let cases: [(Change, &[LinkProblem], usize); 3] = [
        // A record left out: its bytes belong to no object.
        (
            |mut o| {
                o.remove(2);
                o
            },
            &[LinkProblem::NotObject],
            1,
        ),
        // The last object left out.
        (
            |mut o| {
                o.pop();
                o
            },
            &[LinkProblem::NotObject],
            1,
        ),
        // A length that is not the ledger's.
        (
            |mut o| {
                o.last_mut().unwrap().len -= 1;
                o
            },
            &[LinkProblem::Length, LinkProblem::NotObject],
            0,
        ),
    ];
    for (change, problems, outside) in cases {
        let objects_in = |k: usize, l: usize, o: Vec<StreamObject>| {
            if k == 0 && l == SCANNER { change(o) } else { o }
        };
        let mut plan = Plan::new(ST, honest_links());
        plan.objects_in = Some(&objects_in);
        let r = verify(plan.events());
        assert_eq!(found(&r, scanner()), problems);
        assert_eq!(station(&r).outside.len(), outside);
        assert!(box_holds(&r).contains(HoldReason::UplinkObjectInvalid));
    }

    // The closing tick listed again by the next session.
    let tick = day().links[SCANNER].objects[4];
    let again = |k: usize, l: usize, mut o: Vec<StreamObject>| {
        if k == 1 && l == SCANNER {
            o.push(tick);
        }
        o
    };
    let mut plan = Plan::new(ST, honest_links());
    plan.objects_in = Some(&again);
    let r = verify(plan.events());
    assert_eq!(found(&r, scanner()), [LinkProblem::Overlap]);
    assert_eq!(box_holds(&r), only(HoldReason::UplinkObjectInvalid));

    // An object listed before any of its bytes arrived.
    let end = stream_len(&day().links[SCANNER]);
    let objects_in = |k: usize, l: usize, mut o: Vec<StreamObject>| {
        if k == 0 && l == SCANNER {
            o.push(StreamObject {
                schema: SCHEMA_PROGRESS_TICK,
                object_hash: Hash512([9; 64]),
                stream_offset: end,
                len: 100,
            });
        }
        o
    };
    let mut plan = Plan::new(ST, honest_links());
    plan.objects_in = Some(&objects_in);
    let r = verify(plan.events());
    assert_eq!(found(&r, scanner()), [LinkProblem::Early]);
    assert_eq!(box_holds(&r), only(HoldReason::UplinkObjectInvalid));
}

#[test]
fn records_travel_in_closed_batches_and_packages_after_their_records() {
    // A record before its batch attestation.
    let o = scanner_objects();
    let r = verify(Plan::new(ST, with_stream(SCANNER, &[o[1], o[0], o[2], o[3], o[4]])).events());
    assert_eq!(found(&r, scanner()), [LinkProblem::Batch]);
    assert_eq!(box_holds(&r), only(HoldReason::UplinkObjectInvalid));

    // Records out of record-hash order.
    let r = verify(Plan::new(ST, with_stream(SCANNER, &[o[0], o[3], o[2], o[1], o[4]])).events());
    assert_eq!(
        found(&r, scanner()),
        [LinkProblem::Batch, LinkProblem::Batch]
    );

    // A share package after the batch attestation, not after a record.
    let package = fake_object(SCHEMA_SHARE_PACKAGE, &[0x5A; 64]);
    let r = verify(
        Plan::new(
            ST,
            with_stream(SCANNER, &[o[0], package, o[1], o[2], o[3], o[4]]),
        )
        .events(),
    );
    let problems = found(&r, scanner());
    assert!(problems.contains(&LinkProblem::Package), "{problems:?}");
    // It is sealed: its chunk is opaque.
    assert!(link_report(&r, scanner()).opaque_chunks > 0);
}

#[test]
fn every_received_object_is_on_the_ledger_once_the_gateway_closed() {
    let extra = fake_object(SCHEMA_PROGRESS_TICK, &[0x33; 40]);
    let mut objects = scanner_objects();
    objects.push(extra);
    let r = verify(Plan::new(ST, with_stream(SCANNER, &objects)).events());
    assert_eq!(found(&r, scanner()), [LinkProblem::NotOnLedger]);
    assert_eq!(box_holds(&r), only(HoldReason::UplinkObjectInvalid));

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

    // The unit sent it instead: still outside the box's link.
    let mut links = with_stream(SCANNER, &o[..4]);
    let mut unit_stream = unit_objects();
    unit_stream.push(o[4]);
    let l = &links[UNIT];
    links[UNIT] = Link::new(l.key, &unit_stream, 150, 212, 1);
    let r = verify(Plan::new(ST, links).events());
    assert_eq!(station(&r).outside.len(), 1);
    assert_eq!(link_report(&r, unit()).included, 2);

    // The participation set was never sent: the station's boxes hold.
    let r = verify(Plan::new(ST, with_stream(UNIT, &unit_objects()[..1])).events());
    assert_eq!(station(&r).outside.len(), 1);
    assert_eq!(station(&r).outside[0].schema, SCHEMA_PARTICIPATION_SET);
    assert_eq!(box_holds(&r), only(HoldReason::UplinkObjectOutside));
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
    assert_eq!((c.matched, c.objects_matched), (3, 5));
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
    assert_eq!(c.objects_matched, 4);

    // Bytes the gateway listed no object for.
    let objects_in = |k: usize, l: usize, mut o: Vec<StreamObject>| {
        if k == 0 && l == SCANNER {
            o.pop();
        }
        o
    };
    let mut plan = Plan::new(ST, honest_links());
    plan.objects_in = Some(&objects_in);
    let unlisted = verify(plan.events());
    let c = compare_capture(
        election_world().genesis,
        unlisted.index(),
        &capture_of(&day().links, &[150]),
    );
    assert_eq!(capture_problems(&c), [(None, CaptureProblem::NotObject)]);

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
        carrier(&r, w, ST, CarrierLine::Gateway, moved),
        [CarrierProblem::Unexplained]
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
