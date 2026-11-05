//! ityv synthetic-election generator (ROADMAP M6, first part). Outside
//! the TCB (CONSTITUTION.md §0): nothing here can change evidence, and no
//! TCB crate depends on it.
//!
//! From a fixed seed it builds whole signed elections (genesis, every
//! device, person, module, trustee and witness key, every ledger event of
//! a voting day) and named scenarios over them: clean elections at each
//! rung of the status ladder, and attacks and faults the verifier must
//! catch. Each scenario is written as a development bundle (`README.md`,
//! "번들 형식") for the verification console.
//!
//! | Module | Contents |
//! |---|---|
//! | [`spec`] | What an election is made of (fictional names) |
//! | [`audit`] | The comparison audit after the tally, as plan steps |
//! | [`catalog`] | The quick, 지방선거-shaped and 국회의원선거-shaped elections |
//! | [`day`] | One station's day, slot by slot, with alarms and the emergency slot |
//! | [`election`] | The signed genesis and every event builder |
//! | [`plan`] | The ledger plan of a whole election |
//! | [`mod@ledger`] | Steps laid down as frames with witness checkpoints |
//! | [`scenarios`] | The named scenarios and their expected outcomes |
//! | [`tsa`] | Two simulated timestamp authorities and their RFC 3161 tokens |
//! | [`bundle`] | The development bundle encoder |
//! | [`meta`] | `index.json` |
//!
//! Determinism: keys come from labels hashed with [`util::SEED`];
//! hedged signatures, commitments and proofs draw from `ityv-cunit`'s
//! SHA3 counter-mode generator seeded from their inputs; collections are
//! ordered. Two runs write byte-identical files.
//!
//! What it does not do: it does not prove that the verifier is right (it
//! only checks that the verifier says what the scenario expects); its
//! elections are fictional and small; its device behaviour is a model,
//! not firmware.

pub mod audit;
pub mod bundle;
pub mod catalog;
pub mod day;
pub mod election;
pub mod ledger;
pub mod meta;
pub mod plan;
pub mod scenarios;
pub mod spec;
pub mod tsa;
pub mod util;

use ityv_encoding::TimeBucket;
use ityv_ledger::check_board;
use ityv_state::{HoldReason, Publication, Status};
use ityv_verify::{
    AuditInput, BeaconObservation, Publications, Report, VerifiedGenesis, verify_genesis,
    verify_ledger_with,
};

use crate::ledger::{Ledger, lay_down};
use crate::scenarios::Scenario;
use crate::util::{leak, leak_slice};

/// What the caller of the verifier brings for `scenario`: its current
/// time and the board deadline as `ityv-ledger` judges it. The anchor
/// deadline is the verifier's own, from the timestamp tokens on the
/// ledger (ADR-0039).
#[must_use]
pub fn publications(scenario: &Scenario) -> Publications {
    let p = &scenario.publications;
    Publications {
        now: TimeBucket::new(p.now),
        board: Publication::from_ledger(&check_board(
            TimeBucket::new(p.close),
            p.published.map(TimeBucket::new),
            TimeBucket::new(p.now),
        )),
    }
}

/// Lays down `scenario`'s ledger.
#[must_use]
pub fn ledger(scenario: &Scenario) -> &'static Ledger {
    leak(lay_down(scenario.election, &scenario.steps))
}

/// The verified genesis of `scenario` (with its amendments).
///
/// # Panics
/// If the simulated genesis does not verify (a generator bug).
#[must_use]
pub fn genesis(scenario: &Scenario) -> &'static VerifiedGenesis<'static> {
    leak(
        verify_genesis(
            &scenario.election.pin,
            &scenario.election.input(),
            &scenario.amendments,
        )
        .unwrap_or_else(|e| panic!("{}: genesis refused: {e:?}", scenario.name)),
    )
}

/// The beacon observation of `scenario` (fixture data), as the console
/// passes it.
#[must_use]
pub fn observation(scenario: &Scenario) -> Option<BeaconObservation<'static>> {
    scenario.beacon.map(|b| BeaconObservation {
        round: b.round,
        output: b.output,
        published: TimeBucket::new(b.published),
    })
}

/// Runs the verifier over `scenario` laid down as `ledger`, with the
/// scenario's beacon observation (as the console does) and without any
/// restricted opening (as the public verifier).
#[must_use]
pub fn verify(scenario: &Scenario, ledger: &'static Ledger) -> Report<'static> {
    verify_with(
        scenario,
        ledger,
        &AuditInput {
            beacon: observation(scenario),
            openings: &[],
        },
    )
}

/// Runs the verifier over `scenario` laid down as `ledger` with `input`.
#[must_use]
pub fn verify_with(
    scenario: &Scenario,
    ledger: &'static Ledger,
    input: &AuditInput<'_>,
) -> Report<'static> {
    let events: &'static [&'static [u8]] = leak_slice(ledger.events.clone());
    let frames: &'static [u8] = leak_slice(ledger.frames.clone());
    verify_ledger_with(
        genesis(scenario),
        frames,
        events,
        publications(scenario),
        input,
    )
}

/// The status and hold reasons (in code order) the verifier gives.
#[must_use]
pub fn outcome(report: &Report<'_>) -> (Status, Vec<HoldReason>) {
    let s = report.status();
    (s.status(), s.holds().iter().collect())
}
