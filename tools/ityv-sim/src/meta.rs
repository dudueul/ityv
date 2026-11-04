//! `index.json`: the scenario list with each scenario's expectation and
//! the display names of its election (all fictional). The console reads
//! it to group the picker and to compare expected with actual. Nothing
//! in it is evidence: the console takes every status from the verifier.

use std::fmt::Write;

use ityv_encoding::StationKind;

use crate::day::Mark;
use crate::election::Election;
use crate::scenarios::{Group, Scenario, Set};
use crate::util::hex;

/// A JSON string literal.
#[must_use]
pub fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn election_json(e: &Election) -> String {
    let s = &e.spec;
    let mut o = String::new();
    let _ = write!(
        o,
        "{{\"id\":{},\"label\":{},",
        json_str(e.eid),
        json_str(s.label)
    );
    o.push_str("\"parties\":[");
    for (i, p) in s.parties.iter().enumerate() {
        if i > 0 {
            o.push(',');
        }
        let _ = write!(
            o,
            "{{\"chamber\":\"{:?}\",\"name\":{}}}",
            p.chamber,
            json_str(p.name)
        );
    }
    o.push_str("],\"units\":[");
    for (i, u) in s.units.iter().enumerate() {
        if i > 0 {
            o.push(',');
        }
        let _ = write!(
            o,
            "{{\"id\":{},\"label\":{}}}",
            json_str(u.id),
            json_str(u.label)
        );
    }
    o.push_str("],\"styles\":[");
    for (i, st) in s.styles.iter().enumerate() {
        if i > 0 {
            o.push(',');
        }
        let _ = write!(
            o,
            "{{\"id\":{},\"label\":{},\"candidates\":[",
            json_str(st.id),
            json_str(st.label)
        );
        for (j, c) in st.candidates.iter().enumerate() {
            if j > 0 {
                o.push(',');
            }
            let _ = write!(
                o,
                "{{\"name\":{},\"party\":{}}}",
                json_str(c.name),
                c.party.map_or_else(|| "null".to_owned(), json_str)
            );
        }
        o.push_str("]}");
    }
    o.push_str("],\"stations\":[");
    for (i, (st, info)) in s.stations.iter().zip(&e.stations).enumerate() {
        if i > 0 {
            o.push(',');
        }
        let day = &e.days[i];
        let _ = write!(
            o,
            "{{\"id\":{},\"label\":{},\"kind\":{},\"booths\":{},\"limit\":{},\"openSlot\":{},\"closeSlot\":{},\"units\":[{},{}],\"boxes\":[",
            json_str(st.id),
            json_str(st.label),
            json_str(if st.kind == StationKind::EarlyVoting {
                "early"
            } else {
                "election-day"
            }),
            st.booths,
            day.limit,
            day.open_slot,
            day.close_slot,
            json_str(info.units[0]),
            json_str(info.units[1]),
        );
        for (j, b) in st.boxes.iter().enumerate() {
            if j > 0 {
                o.push(',');
            }
            let gi = info.boxes[j];
            let style = s.style(b.style);
            let m = style.candidates.len();
            let mut by = vec![0u64; m];
            let (mut unsorted, mut total) = (0u64, 0u64);
            let marks = e.casts[gi]
                .iter()
                .map(|c| c.mark)
                .chain(day.paper_only[j].iter().copied());
            for mark in marks {
                total += 1;
                match mark {
                    Mark::Candidate(c) => by[usize::from(c) - 1] += 1,
                    Mark::Blank | Mark::Ambiguous(_) => unsorted += 1,
                }
            }
            let _ = write!(
                o,
                "{{\"id\":{},\"label\":{},\"style\":{},\"unit\":{},\"absentee\":{},\"paper\":{{\"byCandidate\":{:?},\"unsorted\":{},\"total\":{}}}}}",
                json_str(b.id),
                json_str(b.label),
                json_str(b.style),
                json_str(b.unit),
                b.absentee,
                by,
                unsorted,
                total
            );
        }
        o.push_str("]}");
    }
    o.push_str("]}");
    o
}

/// The index of the generated scenarios, with each bundle's file name,
/// size and SHA3-512 (the console attaches a scenario's metadata to a
/// bundle only when the bundle's hash is this one).
#[must_use]
pub fn index_json(set: Set, scenarios: &[(&Scenario, String, usize, String)]) -> String {
    let mut o = String::new();
    let _ = write!(
        o,
        "{{\"format\":\"ityv-sim-index/1\",\"note\":{},\"set\":\"{}\",\"seed\":{},\"elections\":[",
        json_str(
            "개발용 시연 자료. 모든 이름은 가상이고, 모든 키는 공개된 고정 씨앗에서 유도한 시험 키다. 상태는 브라우저 안의 WASM 검증기가 판정한다."
        ),
        if set == Set::Quick { "quick" } else { "full" },
        json_str(std::str::from_utf8(crate::util::SEED).unwrap_or("")),
    );
    let mut seen: Vec<&str> = Vec::new();
    for (s, _, _, _) in scenarios {
        if seen.contains(&s.election.eid) {
            continue;
        }
        if !seen.is_empty() {
            o.push(',');
        }
        seen.push(s.election.eid);
        o.push_str(&election_json(s.election));
    }
    o.push_str("],\"scenarios\":[");
    for (i, (s, file, size, sha3)) in scenarios.iter().enumerate() {
        if i > 0 {
            o.push(',');
        }
        let holds: Vec<String> = s
            .expected
            .holds
            .iter()
            .map(|h| format!("{{\"code\":{},\"name\":\"{h:?}\"}}", h.code()))
            .collect();
        let slips: Vec<String> = s
            .slips
            .iter()
            .map(|sl| {
                format!(
                    "{{\"code\":\"{}\",\"note\":{}}}",
                    hex(sl.code.as_bytes()),
                    json_str(sl.note)
                )
            })
            .collect();
        let _ = write!(
            o,
            "{{\"name\":{},\"file\":{},\"bytes\":{},\"sha3\":\"{}\",\"set\":\"{}\",\"group\":\"{}\",\"election\":{},\"title\":{},\"injected\":{},\"shows\":{},\"expected\":{{\"status\":\"{}\",\"holds\":[{}]}},\"slips\":[{}]}}",
            json_str(s.name),
            json_str(file),
            size,
            sha3,
            if s.set == Set::Quick { "quick" } else { "full" },
            if s.group == Group::Normal {
                "normal"
            } else {
                "attack"
            },
            json_str(s.election.eid),
            json_str(s.title),
            json_str(s.injected),
            json_str(s.shows),
            s.expected.status.name(),
            holds.join(","),
            slips.join(","),
        );
    }
    o.push_str("]}\n");
    o
}
