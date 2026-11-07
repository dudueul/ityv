//! The development bundle: one scenario in one file (format in
//! `README.md`, "번들 형식"). This is a development container for the
//! console and the tests until the mirror format of ADR-0018 exists; it is
//! not part of `ENCODING.md` and no TCB crate reads it.

use ityv_verify::AmendableSets;

use crate::ledger::Ledger;
use crate::scenarios::Scenario;

/// The magic bytes.
pub const MAGIC: &[u8; 8] = b"ITYVSIMB";
/// The format version: 4 carries the connectivity manifest the genesis
/// pins in the genesis section, after the signed genesis (ADR-0041); 3 had
/// the beacon observation section and the timestamp and roll authority
/// sets (genesis sets 12 and 13, ADR-0039, ADR-0040).
pub const VERSION: u16 = 4;

/// Section tags, in the order they appear.
pub mod tag {
    /// Scenario name (UTF-8).
    pub const NAME: u16 = 0x0001;
    /// The genesis pin (64 bytes) the caller trusts.
    pub const PIN: u16 = 0x0002;
    /// The signed genesis and every set.
    pub const GENESIS: u16 = 0x0003;
    /// Amendments with the sets of the state each creates.
    pub const AMENDMENTS: u16 = 0x0004;
    /// The frame stream.
    pub const FRAMES: u16 = 0x0005;
    /// The event objects published beside the frames.
    pub const EVENTS: u16 = 0x0006;
    /// The publication deadlines' inputs.
    pub const PUBLICATIONS: u16 = 0x0007;
    /// The beacon publication observed (fixture data), for an audited
    /// ledger: round, publication bucket, output.
    pub const BEACON: u16 = 0x0008;
}

fn blob(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&u32::try_from(bytes.len()).unwrap().to_be_bytes());
    out.extend_from_slice(bytes);
}

fn list(out: &mut Vec<u8>, items: &[&[u8]]) {
    out.extend_from_slice(&u32::try_from(items.len()).unwrap().to_be_bytes());
    for i in items {
        blob(out, i);
    }
}

fn amendable(out: &mut Vec<u8>, s: &AmendableSets<'_>) {
    list(out, s.boxes);
    list(out, s.stations);
    list(out, s.progress_policies);
    list(out, s.reporting_units);
    list(out, s.routes);
    list(out, s.roster);
    list(out, s.modules);
    out.extend_from_slice(&u32::try_from(s.appointments.len()).unwrap().to_be_bytes());
    for h in s.appointments {
        out.extend_from_slice(h.as_bytes());
    }
}

fn section(out: &mut Vec<u8>, tag: u16, payload: &[u8]) {
    out.extend_from_slice(&tag.to_be_bytes());
    blob(out, payload);
}

/// Encodes `scenario` laid down as `ledger`.
#[must_use]
pub fn encode(scenario: &Scenario, ledger: &Ledger) -> Vec<u8> {
    let e = scenario.election;
    let mut sections: Vec<(u16, Vec<u8>)> = Vec::new();
    sections.push((tag::NAME, scenario.name.as_bytes().to_vec()));
    sections.push((tag::PIN, e.pin.as_bytes().to_vec()));
    let mut g = Vec::new();
    blob(&mut g, e.signed);
    blob(&mut g, e.manifest);
    amendable(&mut g, &e.sets);
    list(&mut g, e.fixed.ballot_styles);
    list(&mut g, e.fixed.trustees);
    list(&mut g, e.fixed.witnesses);
    list(&mut g, e.fixed.timestamp_authorities);
    list(&mut g, e.fixed.roll_authorities);
    sections.push((tag::GENESIS, g));
    if !scenario.amendments.is_empty() {
        let mut a = Vec::new();
        a.extend_from_slice(
            &u32::try_from(scenario.amendments.len())
                .unwrap()
                .to_be_bytes(),
        );
        for m in &scenario.amendments {
            blob(&mut a, m.signed);
            amendable(&mut a, &m.sets);
        }
        sections.push((tag::AMENDMENTS, a));
    }
    sections.push((tag::FRAMES, ledger.frames.clone()));
    let mut ev = Vec::new();
    list(&mut ev, &ledger.events);
    sections.push((tag::EVENTS, ev));
    let p = &scenario.publications;
    let mut pb = Vec::new();
    pb.extend_from_slice(&p.checkpoint.to_be_bytes());
    pb.extend_from_slice(&u32::try_from(p.receipts.len()).unwrap().to_be_bytes());
    for r in &p.receipts {
        pb.extend_from_slice(&r.to_be_bytes());
    }
    pb.extend_from_slice(&p.close.to_be_bytes());
    pb.push(u8::from(p.published.is_some()));
    pb.extend_from_slice(&p.published.unwrap_or(0).to_be_bytes());
    pb.extend_from_slice(&p.now.to_be_bytes());
    sections.push((tag::PUBLICATIONS, pb));
    if let Some(b) = &scenario.beacon {
        let mut bb = Vec::new();
        bb.extend_from_slice(&b.round.to_be_bytes());
        bb.extend_from_slice(&b.published.to_be_bytes());
        blob(&mut bb, b.output);
        sections.push((tag::BEACON, bb));
    }

    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&VERSION.to_be_bytes());
    out.extend_from_slice(&u16::try_from(sections.len()).unwrap().to_be_bytes());
    for (t, payload) in &sections {
        section(&mut out, *t, payload);
    }
    out
}
