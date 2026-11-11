//! The simulated elections. Every place, party and candidate name is
//! fictional and carries "가상" so that nobody mistakes it for a real one.

use ityv_encoding::{ChamberCode, StationKind};

use crate::spec::{
    BoxSpec, CandidateSpec, DayEvent, ElectionSpec, PartySpec, StationSpec, StyleSpec, UnitSpec,
};

const FUTURE: &str = "가상미래당";
const HANBIT: &str = "가상한빛당";

fn parties() -> Vec<PartySpec> {
    vec![
        PartySpec {
            chamber: ChamberCode::P1,
            name: FUTURE,
            seats: 150,
        },
        PartySpec {
            chamber: ChamberCode::P2,
            name: HANBIT,
            seats: 120,
        },
    ]
}

fn candidate(name: &'static str, party: Option<&'static str>, weight: u64) -> CandidateSpec {
    CandidateSpec {
        name,
        party,
        weight,
    }
}

fn style(id: &'static str, label: &'static str, candidates: Vec<CandidateSpec>) -> StyleSpec {
    StyleSpec {
        id,
        label,
        candidates,
    }
}

fn unit(id: &'static str, label: &'static str, commission: &'static str) -> UnitSpec {
    UnitSpec {
        id,
        label,
        commission,
    }
}

fn in_person(
    id: &'static str,
    label: &'static str,
    style: &'static str,
    unit: &'static str,
) -> BoxSpec {
    BoxSpec {
        id,
        label,
        style,
        unit,
        absentee: false,
        share: 1,
    }
}

#[allow(clippy::too_many_arguments)]
fn station(
    id: &'static str,
    label: &'static str,
    kind: StationKind,
    day: u64,
    booths: u16,
    voters: u32,
    boxes: Vec<BoxSpec>,
    events: Vec<DayEvent>,
) -> StationSpec {
    StationSpec {
        id,
        label,
        kind,
        day,
        booths,
        voters,
        boxes,
        events,
    }
}

/// The small election of the quick set: two 구, one election-day station
/// and one early-voting station with an out-of-district box, an hour of
/// voting. `events` are the election-day station's events.
#[must_use]
pub fn quick(events: Vec<DayEvent>) -> ElectionSpec {
    ElectionSpec {
        election_id: "SIM-QUICK",
        label: "가상시 구청장 선거 (빠른 시연)",
        parties: parties(),
        styles: vec![
            style(
                "S-HB",
                "가상시 한빛구청장",
                vec![
                    candidate("김가상", Some(FUTURE), 40),
                    candidate("이가상", Some(HANBIT), 35),
                    candidate("박가상", None, 15),
                ],
            ),
            style(
                "S-NR",
                "가상시 누리구청장",
                vec![
                    candidate("최가상", Some(FUTURE), 30),
                    candidate("정가상", Some(HANBIT), 30),
                    candidate("한가상", None, 20),
                    candidate("윤가상", None, 10),
                ],
            ),
        ],
        units: vec![
            unit("RU-HB", "가상시 한빛구", "NEC-HB"),
            unit("RU-NR", "가상시 누리구", "NEC-NR"),
        ],
        stations: vec![
            station(
                "ST-NR-P",
                "누리구 사전투표소 (누리문화센터 1층)",
                StationKind::EarlyVoting,
                1,
                3,
                8,
                vec![
                    BoxSpec {
                        share: 6,
                        ..in_person("BOX-NR-P-IN", "관내 투표함", "S-NR", "RU-NR")
                    },
                    BoxSpec {
                        absentee: true,
                        share: 2,
                        ..in_person("BOX-NR-P-OUT", "관외 투표함 (한빛구 회송)", "S-HB", "RU-HB")
                    },
                ],
                Vec::new(),
            ),
            station(
                "ST-HB-1",
                "한빛초등학교 체육관",
                StationKind::ElectionDay,
                3,
                4,
                9,
                vec![in_person("BOX-HB-1", "투표함", "S-HB", "RU-HB")],
                events,
            ),
        ],
        slots: 7,
        two_way_uplink: false,
    }
}

/// The quick election with 한빛구청장 counted in two reporting units:
/// the election-day station's box, and the early-voting station's
/// out-of-district box as a unit of its own (관외 사전투표, as the
/// genesis' reporting units may be, PROTOCOL.md §4.1), both reported by
/// the 한빛구 commission. The smallest election in which one ballot style
/// has two reporting units, so that one unit's paper count can carry the
/// other's numbers. It has its own election identifier, so that the
/// console finds its units' names.
#[must_use]
pub fn quick_two_units() -> ElectionSpec {
    let mut spec = quick(Vec::new());
    spec.election_id = "SIM-QUICK-UNITS";
    spec.label = "가상시 구청장 선거 (빠른 시연, 한빛구 보고 단위 둘)";
    spec.units = vec![
        unit("RU-HB", "가상시 한빛구 선거일 투표", "NEC-HB"),
        unit("RU-HB-OUT", "가상시 한빛구 관외 사전투표", "NEC-HB"),
        unit("RU-NR", "가상시 누리구", "NEC-NR"),
    ];
    for b in spec.stations.iter_mut().flat_map(|s| s.boxes.iter_mut()) {
        if b.id == "BOX-NR-P-OUT" {
            b.unit = "RU-HB-OUT";
        }
    }
    spec
}

/// The 지방선거-shaped demonstration: three 구·군, eight stations, two of
/// them early-voting with out-of-district boxes, a full day from 06:00 to
/// 18:00. One station each raises a floor, a negative and an excess
/// alarm (each answered on site), one runs its emergency slot for an
/// hour.
///
/// Scaled down: the current genesis gives a box one ballot style and the
/// station identity counts one sheet per check-in, so each voter here
/// casts one ballot (the 구·군의 장), not the seven of a real 지방선거.
#[must_use]
pub fn local() -> ElectionSpec {
    ElectionSpec {
        election_id: "SIM-LOCAL",
        label: "가상시 동시지방선거 시연 (구·군의 장)",
        parties: parties(),
        styles: vec![
            style(
                "S-HB",
                "가상시 한빛구청장",
                vec![
                    candidate("김가상", Some(FUTURE), 42),
                    candidate("이가상", Some(HANBIT), 38),
                    candidate("박가상", None, 12),
                ],
            ),
            style(
                "S-NR",
                "가상시 누리구청장",
                vec![
                    candidate("최가상", Some(FUTURE), 33),
                    candidate("정가상", Some(HANBIT), 36),
                    candidate("한가상", None, 14),
                    candidate("윤가상", None, 7),
                ],
            ),
            style(
                "S-BD",
                "가상시 바다군수",
                vec![
                    candidate("강가상", Some(FUTURE), 30),
                    candidate("조가상", Some(HANBIT), 44),
                    candidate("서가상", None, 16),
                ],
            ),
        ],
        units: vec![
            unit("RU-HB", "가상시 한빛구", "NEC-HB"),
            unit("RU-NR", "가상시 누리구", "NEC-NR"),
            unit("RU-BD", "가상시 바다군", "NEC-BD"),
        ],
        stations: vec![
            station(
                "HB-P",
                "한빛구 사전투표소 (한빛구청 1층 로비)",
                StationKind::EarlyVoting,
                1,
                6,
                200,
                vec![
                    BoxSpec {
                        share: 85,
                        ..in_person("HB-P-IN", "관내 투표함", "S-HB", "RU-HB")
                    },
                    BoxSpec {
                        absentee: true,
                        share: 15,
                        ..in_person("HB-P-OUT", "관외 투표함 (누리구 회송)", "S-NR", "RU-NR")
                    },
                ],
                Vec::new(),
            ),
            station(
                "NR-P",
                "누리구 사전투표소 (누리문화센터 다목적홀)",
                StationKind::EarlyVoting,
                1,
                6,
                180,
                vec![
                    BoxSpec {
                        share: 85,
                        ..in_person("NR-P-IN", "관내 투표함", "S-NR", "RU-NR")
                    },
                    BoxSpec {
                        absentee: true,
                        share: 15,
                        ..in_person("NR-P-OUT", "관외 투표함 (바다군 회송)", "S-BD", "RU-BD")
                    },
                ],
                Vec::new(),
            ),
            station(
                "HB-1",
                "한빛초등학교 체육관",
                StationKind::ElectionDay,
                3,
                6,
                260,
                vec![in_person("HB-1-B", "투표함", "S-HB", "RU-HB")],
                vec![DayEvent::Floor {
                    at: 40,
                    checked: true,
                }],
            ),
            station(
                "HB-2",
                "한빛동 주민센터 2층 회의실",
                StationKind::ElectionDay,
                3,
                5,
                220,
                vec![in_person("HB-2-B", "투표함", "S-HB", "RU-HB")],
                vec![DayEvent::High { at: 15 }],
            ),
            station(
                "NR-1",
                "누리중학교 강당",
                StationKind::ElectionDay,
                3,
                6,
                240,
                vec![in_person("NR-1-B", "투표함", "S-NR", "RU-NR")],
                vec![DayEvent::Negative { at: 30 }],
            ),
            station(
                "NR-2",
                "누리도서관 다목적실",
                StationKind::ElectionDay,
                3,
                4,
                180,
                vec![in_person("NR-2-B", "투표함", "S-NR", "RU-NR")],
                vec![DayEvent::Fallback {
                    index: 0,
                    from: 50,
                    to: 56,
                }],
            ),
            station(
                "BD-1",
                "바다초등학교 체육관",
                StationKind::ElectionDay,
                3,
                4,
                150,
                vec![in_person("BD-1-B", "투표함", "S-BD", "RU-BD")],
                Vec::new(),
            ),
            station(
                "BD-2",
                "바다면 복지회관",
                StationKind::ElectionDay,
                3,
                3,
                90,
                vec![in_person("BD-2-B", "투표함", "S-BD", "RU-BD")],
                Vec::new(),
            ),
        ],
        slots: 73,
        two_way_uplink: false,
    }
}

/// The 국회의원선거-shaped demonstration: two constituencies, five
/// stations, a full day.
///
/// Scaled down: one sheet per check-in (see [`local`]), so the
/// proportional ballot is left out; each voter casts the constituency
/// ballot.
#[must_use]
pub fn national() -> ElectionSpec {
    ElectionSpec {
        election_id: "SIM-NATIONAL",
        label: "가상시 국회의원선거 시연 (지역구)",
        parties: parties(),
        styles: vec![
            style(
                "S-GAP",
                "가상시 갑 지역구",
                vec![
                    candidate("문가상", Some(FUTURE), 37),
                    candidate("송가상", Some(HANBIT), 39),
                    candidate("임가상", None, 9),
                    candidate("오가상", None, 5),
                ],
            ),
            style(
                "S-EUL",
                "가상시 을 지역구",
                vec![
                    candidate("신가상", Some(FUTURE), 41),
                    candidate("유가상", Some(HANBIT), 40),
                    candidate("장가상", None, 11),
                ],
            ),
        ],
        units: vec![
            unit("RU-GAP", "가상시 갑 선거구", "NEC-GAP"),
            unit("RU-EUL", "가상시 을 선거구", "NEC-EUL"),
        ],
        stations: vec![
            station(
                "GAP-P",
                "갑 선거구 사전투표소 (가상시청 별관)",
                StationKind::EarlyVoting,
                1,
                5,
                160,
                vec![
                    BoxSpec {
                        share: 80,
                        ..in_person("GAP-P-IN", "관내 투표함", "S-GAP", "RU-GAP")
                    },
                    BoxSpec {
                        absentee: true,
                        share: 20,
                        ..in_person(
                            "GAP-P-OUT",
                            "관외 투표함 (을 선거구 회송)",
                            "S-EUL",
                            "RU-EUL",
                        )
                    },
                ],
                Vec::new(),
            ),
            station(
                "GAP-1",
                "새솔초등학교 체육관",
                StationKind::ElectionDay,
                3,
                5,
                200,
                vec![in_person("GAP-1-B", "투표함", "S-GAP", "RU-GAP")],
                Vec::new(),
            ),
            station(
                "GAP-2",
                "새솔동 주민센터",
                StationKind::ElectionDay,
                3,
                4,
                160,
                vec![in_person("GAP-2-B", "투표함", "S-GAP", "RU-GAP")],
                vec![DayEvent::High { at: 12 }],
            ),
            station(
                "EUL-1",
                "가람중학교 강당",
                StationKind::ElectionDay,
                3,
                5,
                180,
                vec![in_person("EUL-1-B", "투표함", "S-EUL", "RU-EUL")],
                vec![DayEvent::Floor {
                    at: 46,
                    checked: true,
                }],
            ),
            station(
                "EUL-2",
                "가람동 경로당",
                StationKind::ElectionDay,
                3,
                3,
                140,
                vec![in_person("EUL-2-B", "투표함", "S-EUL", "RU-EUL")],
                Vec::new(),
            ),
        ],
        slots: 73,
        two_way_uplink: false,
    }
}
