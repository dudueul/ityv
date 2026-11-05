//! The voter roll of the verifier's tests (ADR-0033, ADR-0040): the
//! genesis's roll authorities (the court administration, the Ministry of
//! the Interior, the committee and two parties as custodians; a district
//! head, the Ministry's snapshot, deaths, disqualifications, overseas
//! voters and an appeal court as sources), and the roll's events signed
//! with real hybrid signatures under the keys the genesis registers.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    dead_code,
    unreachable_pub
)]

use std::vec::Vec;

use ityv_crypto::object_hash;
use ityv_encoding::{
    AuthorityId, Day, EventRole, EventSig, Hash512, OrgId, RollAmendmentBody, RollAmendmentParts,
    RollAmendmentReason, RollAuthorityEntry, RollAuthorityKind, RollCustodyReceiptBody,
    RollCustodyReceiptParts, RollFreezeBody, RollFreezeParts, RollSourceExtractBody,
    RollSourceExtractParts, RollSourceKind, RollState, SCHEMA_ROLL_AMENDMENT_BODY,
    SCHEMA_ROLL_CUSTODY_RECEIPT_BODY, SCHEMA_ROLL_FREEZE_BODY, SCHEMA_ROLL_SOURCE_EXTRACT_BODY,
    SCHEMA_VERSION_1, SCHEMA_VERSION_WITNESSED, SCHEMA_WITNESSED_EVENT, SchemaId, SignerId,
    StationId, TimeBucket, WitnessedEvent, purpose_of,
};
use ityv_ledger::sorted_set_root;

use super::{COMMISSION, COMMITTEE, election, object, registered, sign, sign_seeded, signing};

/// The first key number of the roll authorities.
pub const ROLL_BASE: u16 = 700;

/// A roll authority of the standard genesis: identifier, organisation,
/// function and key number (offset from [`ROLL_BASE`]), in key order.
pub const AUTHORITIES: [(&[u8], &[u8], RollAuthorityKind, u16); 11] = [
    (
        b"R-APPEAL",
        b"SEOUL-COURT",
        RollAuthorityKind::AppealCourt,
        0,
    ),
    (b"R-C-INT", b"MOIS", RollAuthorityKind::CustodianInterior, 1),
    (b"R-C-IVC", b"IVC", RollAuthorityKind::CustodianCommittee, 2),
    (
        b"R-C-JUD",
        b"COURT-ADMIN",
        RollAuthorityKind::CustodianJudiciary,
        3,
    ),
    (b"R-C-PA", b"PARTY-A", RollAuthorityKind::CustodianParty, 4),
    (b"R-C-PB", b"PARTY-B", RollAuthorityKind::CustodianParty, 5),
    (b"R-DEATHS", b"COURT-ADMIN", RollAuthorityKind::Deaths, 6),
    (
        b"R-DISQ",
        b"PROSECUTION",
        RollAuthorityKind::Disqualification,
        7,
    ),
    (
        b"R-GU-1",
        b"JONGNO-GU",
        RollAuthorityKind::ResidentExtract,
        8,
    ),
    (b"R-OVERSEAS", b"MOFA", RollAuthorityKind::Overseas, 9),
    (
        b"R-SNAPSHOT",
        b"MOIS",
        RollAuthorityKind::ResidentSnapshot,
        10,
    ),
];

pub const APPEAL: &[u8] = b"R-APPEAL";
pub const C_INT: &[u8] = b"R-C-INT";
pub const C_IVC: &[u8] = b"R-C-IVC";
pub const C_JUD: &[u8] = b"R-C-JUD";
pub const C_PA: &[u8] = b"R-C-PA";
pub const C_PB: &[u8] = b"R-C-PB";
pub const DEATHS: &[u8] = b"R-DEATHS";
pub const DISQ: &[u8] = b"R-DISQ";
pub const GU: &[u8] = b"R-GU-1";
pub const OVERSEAS: &[u8] = b"R-OVERSEAS";
pub const SNAPSHOT: &[u8] = b"R-SNAPSHOT";

/// The entry of authority `(id, org, kind, n)`.
pub fn entry(
    (id, org, kind, n): (&'static [u8], &'static [u8], RollAuthorityKind, u16),
) -> RollAuthorityEntry<'static> {
    RollAuthorityEntry {
        authority_id: AuthorityId::new(id).unwrap(),
        org_id: OrgId::new(org).unwrap(),
        kind,
        key: registered(ROLL_BASE + n),
    }
}

/// The standard genesis's roll authorities.
pub fn authorities() -> Vec<RollAuthorityEntry<'static>> {
    AUTHORITIES.iter().map(|a| entry(*a)).collect()
}

/// A signer of a roll event: identifier, role, organisation, key number.
pub type Who = (&'static [u8], EventRole, &'static [u8], u16);

/// The commission, signing a freeze or an amendment.
pub const NEC: Who = (b"nec", EventRole::Commission, b"NEC", COMMISSION);

/// The committee, signing a freeze or an amendment.
pub const IVC: Who = (b"ivc", EventRole::Committee, b"IVC", COMMITTEE);

/// Authority `id` signing in the role its function gives.
pub fn by(id: &'static [u8]) -> Who {
    let (id, org, kind, n) = *AUTHORITIES.iter().find(|a| a.0 == id).unwrap();
    let role = if kind.is_custodian() {
        EventRole::RollCustodian
    } else {
        EventRole::RollSource
    };
    (id, role, org, ROLL_BASE + n)
}

/// A `WitnessedEvent` over `body` signed by `who`, sorted here; with
/// `seed`, other signature bytes over the same body.
pub fn witnessed(body: &'static [u8], who: &[Who], seed: Option<u64>) -> &'static [u8] {
    let schema = ityv_encoding::ObjectHeader::read(&mut ityv_encoding::Reader::new(body))
        .unwrap()
        .schema_id();
    let purpose = purpose_of(schema).unwrap();
    let mut who = who.to_vec();
    who.sort_by(|a, b| a.0.cmp(b.0));
    let sigs: Vec<EventSig<'static>> = who
        .iter()
        .map(|&(signer, role, o, n)| EventSig {
            signer_id: SignerId::new(signer).unwrap(),
            role,
            org_id: OrgId::new(o).unwrap(),
            sig: match seed {
                Some(seed) => sign_seeded(signing(n), purpose, body, seed),
                None => sign(signing(n), purpose, body),
            },
        })
        .collect();
    object(
        SCHEMA_WITNESSED_EVENT,
        SCHEMA_VERSION_WITNESSED,
        &WitnessedEvent::new(body, &sigs).unwrap(),
    )
}

fn h(seed: u8) -> Hash512 {
    let mut b = [seed; 64];
    b[0] = 0xEE;
    Hash512(b)
}

/// An extract body by source `authority` of `kind` (with `precinct` for
/// residents), its root drawn from `seed`, listing `1000 + seed` entries.
pub fn extract(
    authority: &'static [u8],
    kind: RollSourceKind,
    precinct: Option<&'static [u8]>,
    seed: u8,
) -> &'static [u8] {
    listing(authority, kind, precinct, seed, 1_000 + u64::from(seed))
}

/// As [`extract`], listing `entries` entries.
pub fn listing(
    authority: &'static [u8],
    kind: RollSourceKind,
    precinct: Option<&'static [u8]>,
    seed: u8,
    entries: u64,
) -> &'static [u8] {
    object(
        SCHEMA_ROLL_SOURCE_EXTRACT_BODY,
        SCHEMA_VERSION_1,
        &RollSourceExtractBody::new(&RollSourceExtractParts {
            election_id: election(),
            authority_id: AuthorityId::new(authority).unwrap(),
            kind,
            precinct: precinct.map(|p| StationId::new(p).unwrap()),
            reference_day: Day::new(19_990),
            entry_count: entries,
            entries_root: h(seed),
        })
        .unwrap(),
    )
}

/// A roll state drawn from `seed`.
pub fn state(seed: u8) -> RollState {
    RollState {
        entries_root: h(seed),
        entry_count: 3_000 + u64::from(seed),
        counts_hash: h(seed.wrapping_add(1)),
        pseudonym_root: h(seed.wrapping_add(2)),
    }
}

/// `state(seed)` with the entry count the merge of the extract bodies
/// `extracts` gives: their resident extracts' sum (there is no removal
/// list in these rolls).
pub fn merged(seed: u8, extracts: &[&'static [u8]]) -> RollState {
    let entries = extracts
        .iter()
        .map(|b| {
            ityv_encoding::decode_object::<RollSourceExtractBody<'_>>(
                SCHEMA_ROLL_SOURCE_EXTRACT_BODY,
                SCHEMA_VERSION_1,
                b,
            )
            .unwrap()
        })
        .filter(|e| e.parts().kind == RollSourceKind::Residents)
        .map(|e| e.parts().entry_count)
        .sum();
    RollState {
        entry_count: entries,
        ..state(seed)
    }
}

/// The sources root and count of the extract bodies `extracts`.
pub fn sources(extracts: &[&'static [u8]]) -> (Hash512, u32) {
    let mut hashes: Vec<Hash512> = extracts.iter().map(|b| object_hash(b)).collect();
    hashes.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    (sorted_set_root(&hashes).unwrap(), extracts.len() as u32)
}

/// A freeze body of `state` with sources root and count `(root, count)`.
pub fn freeze(state: RollState, (root, count): (Hash512, u32)) -> &'static [u8] {
    object(
        SCHEMA_ROLL_FREEZE_BODY,
        SCHEMA_VERSION_1,
        &RollFreezeBody::new(&RollFreezeParts {
            election_id: election(),
            state,
            sources_root: root,
            source_count: count,
            time_bucket: TimeBucket::new(50),
        })
        .unwrap(),
    )
}

/// A receipt body by `custodian` answering the body `subject`, giving
/// `state` and `sources_root`, with the pseudonym root when `pseudonyms`.
pub fn receipt(
    custodian: &'static [u8],
    subject: &[u8],
    state: RollState,
    sources_root: Option<Hash512>,
    pseudonyms: bool,
) -> &'static [u8] {
    object(
        SCHEMA_ROLL_CUSTODY_RECEIPT_BODY,
        SCHEMA_VERSION_1,
        &RollCustodyReceiptBody::new(&RollCustodyReceiptParts {
            election_id: election(),
            custodian: AuthorityId::new(custodian).unwrap(),
            subject_hash: object_hash(subject),
            entries_root: state.entries_root,
            entry_count: state.entry_count,
            counts_hash: state.counts_hash,
            sources_root,
            pseudonym_root: pseudonyms.then_some(state.pseudonym_root),
            time_bucket: TimeBucket::new(60),
        })
        .unwrap(),
    )
}

/// An amendment body numbered `seq` after the body `previous`, for
/// `reason` by source `authority`, giving `state`.
pub fn amendment(
    seq: u64,
    previous: &[u8],
    reason: RollAmendmentReason,
    authority: &'static [u8],
    state: RollState,
) -> &'static [u8] {
    object(
        SCHEMA_ROLL_AMENDMENT_BODY,
        SCHEMA_VERSION_1,
        &RollAmendmentBody::new(&RollAmendmentParts {
            election_id: election(),
            seq,
            previous_hash: object_hash(previous),
            reason,
            authority_id: AuthorityId::new(authority).unwrap(),
            basis_hash: h(0x5B),
            state,
            time_bucket: TimeBucket::new(70),
        })
        .unwrap(),
    )
}

/// The resident extract of `precinct` by the district head.
pub fn residents(precinct: &'static [u8], seed: u8) -> &'static [u8] {
    extract(GU, RollSourceKind::Residents, Some(precinct), seed)
}

/// The national snapshot by the Ministry.
pub fn snapshot() -> &'static [u8] {
    extract(SNAPSHOT, RollSourceKind::Snapshot, None, 0x30)
}

/// The custodians that confirm the standard roll: the court
/// administration (with the pseudonym root), the Ministry and the
/// committee.
pub const CONFIRMING: [&[u8]; 3] = [C_JUD, C_INT, C_IVC];

/// A complete roll for the election-day stations `precincts`: their
/// resident extracts and the snapshot, the freeze of their merge
/// (`merged(0x40, ..)`) and the receipts of [`CONFIRMING`], each signed by
/// its authority.
pub fn standard(precincts: &[&'static [u8]]) -> Vec<(SchemaId, &'static [u8])> {
    let mut extracts: Vec<&'static [u8]> = precincts
        .iter()
        .enumerate()
        .map(|(i, p)| residents(p, 0x10 + i as u8))
        .collect();
    extracts.push(snapshot());
    let mut events: Vec<(SchemaId, &'static [u8])> = extracts
        .iter()
        .map(|b| {
            let author = if *b == snapshot() { SNAPSHOT } else { GU };
            (SCHEMA_WITNESSED_EVENT, witnessed(b, &[by(author)], None))
        })
        .collect();
    let s = merged(0x40, &extracts);
    let (root, count) = sources(&extracts);
    let body = freeze(s, (root, count));
    events.push((SCHEMA_WITNESSED_EVENT, witnessed(body, &[NEC, IVC], None)));
    for (i, c) in CONFIRMING.iter().enumerate() {
        let r = receipt(c, body, s, Some(root), i == 0);
        events.push((SCHEMA_WITNESSED_EVENT, witnessed(r, &[by(c)], None)));
    }
    events
}
