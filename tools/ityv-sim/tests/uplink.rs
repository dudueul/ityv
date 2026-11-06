//! The simulated gateways' sessions as the verifier's connectivity stage
//! reads them (ADR-0022, ADR-0041): every clean ledger's sessions are taken
//! whole, and each connectivity scenario shows the finding it injected.
// Integration tests: outside the TCB. Assertions use unwrap and indexing.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::collections::BTreeMap;

use ityv_sim::scenarios::{Group, Scenario, Set, scenarios};
use ityv_sim::{ledger, verify};
use ityv_verify::{
    IncidentProblem, LinkProblem, ManifestProblem, Report, SessionProblem, StationUplink,
};

fn by_name() -> BTreeMap<&'static str, Scenario> {
    scenarios(Set::Quick)
        .into_iter()
        .map(|s| (s.name, s))
        .collect()
}

fn report(s: &Scenario) -> Report<'static> {
    verify(s, ledger(s))
}

fn station<'r>(r: &'r Report<'static>, id: &str) -> &'r StationUplink<'static> {
    r.connectivity().station(id.as_bytes()).unwrap()
}

fn link_problems(r: &Report<'static>, id: &str) -> Vec<LinkProblem> {
    station(r, id)
        .links
        .iter()
        .flat_map(|l| l.findings.iter().map(|f| f.problem))
        .collect()
}

#[test]
fn every_clean_ledger_has_whole_sessions_from_every_gateway() {
    let all = by_name();
    for name in ["quick-clean", "quick-closed", "audit-clean"] {
        let s = &all[name];
        assert_eq!(s.group, Group::Normal);
        let r = report(s);
        let c = r.connectivity();
        assert!(c.complete(), "{name}");
        assert!(c.manifest_findings().is_empty(), "{name}");
        assert_eq!(c.holds(), ityv_state::HoldSet::empty(), "{name}");
        for st in c.stations() {
            assert!(st.final_session.is_some(), "{name}");
            assert!(st.findings.is_empty(), "{name}: {:?}", st.findings);
            assert!(st.outside.is_empty(), "{name}: {:?}", st.outside);
            assert_eq!(st.pending_logs, 0);
            // Two clerks' station: the final session carries the two
            // observers' capture statements.
            let last = st.sessions.last().unwrap();
            assert!(last.is_final);
            assert_eq!(last.observers, 2);
            assert!(
                st.sessions[..st.sessions.len() - 1]
                    .iter()
                    .all(|x| x.observers == 0)
            );
            for l in &st.links {
                assert!(l.findings.is_empty(), "{name}: {:?}", l.findings);
                assert_eq!(l.missing_slots, 0);
                assert!(l.included > 0);
                // Every slot whole: the reference shape of 16 or 4 frames;
                // a scanner's last slot (its closing tick's) is a catch-up
                // slot of 64, the close resend of its batches. Only its
                // share packages are sealed.
                let (first, last) = l.slots.unwrap();
                match l.device {
                    ityv_verify::LinkDevice::Box(_) => {
                        assert_eq!(l.frames, (last - first) * 16);
                        assert_eq!(l.catchup_frames, 64);
                        assert!(l.opaque_chunks > 0, "{name}");
                    }
                    ityv_verify::LinkDevice::Unit(_) => {
                        assert_eq!(l.frames, (last - first + 1) * 4);
                        assert_eq!(l.catchup_frames, 0);
                        assert_eq!(l.opaque_chunks, 0);
                    }
                }
            }
        }
    }
    // While voting, no gateway has closed: inclusion waits.
    let r = report(&all["quick-voting"]);
    assert!(!r.connectivity().complete());
    assert_eq!(r.connectivity().holds(), ityv_state::HoldSet::empty());
    assert!(
        r.connectivity()
            .stations()
            .iter()
            .all(|s| s.final_session.is_none() && s.outside.is_empty())
    );
}

#[test]
fn each_connectivity_scenario_shows_what_it_injected() {
    let all = by_name();
    let r = report(&all["attack-manifest-two-way"]);
    let problems: Vec<ManifestProblem> = r
        .connectivity()
        .manifest_findings()
        .iter()
        .map(|f| f.problem)
        .collect();
    assert_eq!(
        problems,
        [
            ManifestProblem::TcbInbound,
            ManifestProblem::TwoWay,
            ManifestProblem::FrameLinkShape
        ]
    );

    let r = report(&all["attack-uplink-hidden-frame"]);
    let s = station(&r, "ST-HB-1");
    assert_eq!(
        s.findings.iter().map(|f| f.problem).collect::<Vec<_>>(),
        [SessionProblem::MissingSlots]
    );
    assert_eq!(s.findings[0].session_index, 1);

    for (name, problem, count) in [
        ("attack-uplink-injected-frame", LinkProblem::Signature, 1),
        ("fault-uplink-padding", LinkProblem::Fill, 1),
        ("fault-uplink-extra-frame", LinkProblem::Index, 1),
        ("attack-uplink-covert-bytes", LinkProblem::NotObject, 1),
        ("attack-uplink-relisted-object", LinkProblem::Signature, 1),
    ] {
        let r = report(&all[name]);
        let found = link_problems(&r, "ST-HB-1");
        assert_eq!(found.len(), count, "{name}: {found:?}");
        assert!(found.iter().all(|p| *p == problem), "{name}: {found:?}");
        assert!(station(&r, "ST-HB-1").findings.is_empty(), "{name}");
    }
    // Normal frames after the close resend: after the close, and after a
    // resend.
    let r = report(&all["fault-uplink-after-close"]);
    let found = link_problems(&r, "ST-HB-1");
    assert_eq!(found.len(), 32, "{found:?}");
    assert_eq!(
        found
            .iter()
            .filter(|p| **p == LinkProblem::AfterClose)
            .count(),
        16
    );
    assert!(
        found
            .iter()
            .all(|p| matches!(p, LinkProblem::AfterClose | LinkProblem::KindOrder))
    );
    // A frame of the closing batch lost and declared: the close resend
    // brings the batch again, and nothing holds.
    let r = report(&all["fault-uplink-recovered-loss"]);
    let s = station(&r, "ST-HB-1");
    assert!(s.findings.is_empty(), "{:?}", s.findings);
    assert!(s.outside.is_empty(), "{:?}", s.outside);
    assert!(link_problems(&r, "ST-HB-1").is_empty());
    assert_eq!(s.links[0].missing_slots + s.links[1].missing_slots, 1);
    assert_eq!(r.connectivity().holds(), ityv_state::HoldSet::empty());

    let r = report(&all["attack-uplink-batch-order"]);
    let found = link_problems(&r, "ST-HB-1");
    assert!(!found.is_empty());
    assert!(found.iter().all(|p| *p == LinkProblem::Batch), "{found:?}");

    // Each record in a run of its own: the runs end early and the
    // attestation goes out too often (review 2 of 2i, G).
    let r = report(&all["attack-uplink-singled-records"]);
    let found = link_problems(&r, "ST-HB-1");
    assert!(found.contains(&LinkProblem::Batch), "{found:?}");
    assert!(found.contains(&LinkProblem::Repeat), "{found:?}");
    assert!(
        found
            .iter()
            .all(|p| matches!(p, LinkProblem::Batch | LinkProblem::Repeat)),
        "{found:?}"
    );
    assert!(station(&r, "ST-HB-1").outside.is_empty());
    // A witnessed-resend group during voting (review 3 of 2i, finding 1):
    // it and every normal frame after it are out of their kind's place.
    let r = report(&all["attack-uplink-witnessed-midday"]);
    let found = link_problems(&r, "ST-HB-1");
    assert!(found.len() > 64, "{}", found.len());
    assert!(
        found.iter().all(|p| *p == LinkProblem::KindOrder),
        "{found:?}"
    );
    assert!(station(&r, "ST-HB-1").outside.is_empty());
    // Covert bytes under the hash of a ledger event of another schema
    // (review 2 of 2i, A).
    let r = report(&all["attack-uplink-mislabeled-object"]);
    assert_eq!(link_problems(&r, "ST-HB-1"), [LinkProblem::Schema]);
    assert!(station(&r, "ST-HB-1").outside.is_empty());

    let r = report(&all["fault-uplink-lost-frame"]);
    let s = station(&r, "ST-HB-1");
    assert!(s.findings.is_empty(), "{:?}", s.findings);
    assert!(link_problems(&r, "ST-HB-1").is_empty());
    assert!(!s.outside.is_empty());
    // A record that never travelled the link: outside, and its batch's
    // runs (the closing batch and its close resend) skip it with no byte
    // lost.
    let r = report(&all["attack-hidden-path-record"]);
    let s = station(&r, "ST-HB-1");
    assert!(s.findings.is_empty(), "{:?}", s.findings);
    assert_eq!(
        link_problems(&r, "ST-HB-1"),
        [LinkProblem::Batch, LinkProblem::Batch]
    );
    let outside = &station(&r, "ST-HB-1").outside;
    assert_eq!(outside.len(), 1);
    assert_eq!(outside[0].schema, ityv_encoding::SCHEMA_CAST_RECORD);
    let r = report(&all["fault-uplink-lost-frame"]);
    assert!(
        station(&r, "ST-HB-1")
            .outside
            .iter()
            .all(|o| o.schema == ityv_encoding::SCHEMA_PROGRESS_TICK)
    );
    assert_eq!(
        station(&r, "ST-HB-1").links[0].missing_slots
            + station(&r, "ST-HB-1").links[1].missing_slots,
        1
    );

    let r = report(&all["fault-roll-line-incident"]);
    let i = &r.connectivity().incidents()[0];
    assert_eq!(i.refused, None);
    assert_eq!(i.parts.box_id, None);
    assert_eq!(i.boxes.len(), 2);
    assert!(i.full_comparison.is_empty());

    let r = report(&all["fault-capture-mismatch"]);
    let i = &r.connectivity().incidents()[0];
    assert_eq!(i.refused, None);
    assert_eq!(i.full_comparison.len(), 1);
    assert!(!i.full_comparison[0].1);

    let r = report(&all["attack-incident-forged"]);
    assert_eq!(
        r.connectivity().incidents()[0].refused,
        Some(IncidentProblem::Signers)
    );
}
