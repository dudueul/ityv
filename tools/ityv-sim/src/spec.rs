//! What a simulated election is made of, before anything is signed.
//!
//! Every name here is fictional and visibly so ("가상시 한빛구",
//! "가상미래당"). No real person, party, place result or election is
//! represented.

use ityv_encoding::{ChamberCode, StationKind};

/// A party chamber of the genesis.
#[derive(Debug, Clone)]
pub struct PartySpec {
    /// Its chamber (`P1`, `P2`, …).
    pub chamber: ChamberCode,
    /// Fictional name, as the genesis records it.
    pub name: &'static str,
    /// Seats (the genesis's evidence of party size).
    pub seats: u16,
}

/// A candidate on a ballot style (display only; the genesis knows only
/// the number of candidates).
#[derive(Debug, Clone)]
pub struct CandidateSpec {
    /// Fictional name.
    pub name: &'static str,
    /// Fictional party name, or `None` for an independent.
    pub party: Option<&'static str>,
    /// Relative weight of the simulated voters' choice.
    pub weight: u64,
}

/// A ballot style.
#[derive(Debug, Clone)]
pub struct StyleSpec {
    /// The genesis identifier.
    pub id: &'static str,
    /// Display name (e.g. "가상시 한빛구청장").
    pub label: &'static str,
    /// Candidates, in ballot order (option `1..=m`).
    pub candidates: Vec<CandidateSpec>,
}

/// A reporting unit and its district commission.
#[derive(Debug, Clone)]
pub struct UnitSpec {
    /// The genesis identifier.
    pub id: &'static str,
    /// Display name.
    pub label: &'static str,
    /// The commission's organisation identifier.
    pub commission: &'static str,
}

/// A ballot box at a station.
#[derive(Debug, Clone)]
pub struct BoxSpec {
    /// The genesis identifier.
    pub id: &'static str,
    /// Display name.
    pub label: &'static str,
    /// Its ballot style.
    pub style: &'static str,
    /// Its reporting unit.
    pub unit: &'static str,
    /// An out-of-district (관외) envelope box.
    pub absentee: bool,
    /// Relative share of the station's voters who cast here.
    pub share: u64,
}

/// Something that happens during a station's day, to show the progress
/// alarms and the emergency insertion slot (ADR-0027, PROTOCOL.md §7.10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DayEvent {
    /// From slot offset `at`, nobody arrives for four slots while one
    /// voter holds a ballot: a floor alarm, explained on site.
    Floor {
        /// Slot offset from opening.
        at: u64,
        /// Whether the on-site check is recorded in time (`false`: the
        /// alarm stays unresolved).
        checked: bool,
    },
    /// Two issuances are not entered on the terminal for two slots, then
    /// entered: a negative alarm, corrected on site.
    Negative {
        /// Slot offset from opening.
        at: u64,
    },
    /// A group arrives at once and holds ballots for two slots: an excess
    /// alarm, explained on site.
    High {
        /// Slot offset from opening.
        at: u64,
    },
    /// The scanner of box `index` is out from slot offset `from` to `to`
    /// (exclusive): its ballots go through the emergency slot without a
    /// record, and the station's alarms stop until close.
    Fallback {
        /// Box index at the station.
        index: usize,
        /// First slot offset in fallback.
        from: u64,
        /// First slot offset back to scanning.
        to: u64,
    },
}

/// A polling station.
#[derive(Debug, Clone)]
pub struct StationSpec {
    /// The genesis identifier.
    pub id: &'static str,
    /// Display name (e.g. "누리초등학교 체육관").
    pub label: &'static str,
    /// Election day or early voting.
    pub kind: StationKind,
    /// Day offset from the election epoch day.
    pub day: u64,
    /// Booths (the progress policy).
    pub booths: u16,
    /// Voters who check in during the day.
    pub voters: u32,
    /// Its boxes (at most 8).
    pub boxes: Vec<BoxSpec>,
    /// Events of the day.
    pub events: Vec<DayEvent>,
}

/// A whole election.
#[derive(Debug, Clone)]
pub struct ElectionSpec {
    /// The genesis election identifier.
    pub election_id: &'static str,
    /// Display name.
    pub label: &'static str,
    /// Party chambers.
    pub parties: Vec<PartySpec>,
    /// Ballot styles.
    pub styles: Vec<StyleSpec>,
    /// Reporting units.
    pub units: Vec<UnitSpec>,
    /// Stations.
    pub stations: Vec<StationSpec>,
    /// 10-minute slots from opening to close, both included (73 for
    /// 06:00–18:00).
    pub slots: u64,
}

impl ElectionSpec {
    /// The style named `id`.
    #[must_use]
    pub fn style(&self, id: &str) -> &StyleSpec {
        self.styles.iter().find(|s| s.id == id).unwrap()
    }

    /// Every box with its station, in station order.
    pub fn boxes(&self) -> impl Iterator<Item = (&StationSpec, &BoxSpec)> {
        self.stations
            .iter()
            .flat_map(|s| s.boxes.iter().map(move |b| (s, b)))
    }
}
