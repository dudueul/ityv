//! The genesis body (`GenesisBody`, schema `0x0002`, version 7), the
//! amendment body (`GenesisAmendmentBody`, schema `0x0034`) and their
//! signed wrapper (`SignedGenesis`, schema `0x0033`) (ADR-0028;
//! PROTOCOL.md §4.1–§4.3; ENCODING.md §8.54–§8.56).
//!
//! The body holds what fits in one bounded object: the scalar fields and
//! pins, the keys of the election commission and the Independent
//! Verification Committee, the witness quorum and diversity rule, the
//! party roster, the chamber thresholds, and for each entry set of
//! [`crate::schema::genesis`] its count and Merkle root. The genesis hash
//! that is pinned out of band (VC-005) is the object hash of the body.
//!
//! Versions 1–5 of schema `0x0002` were specification drafts that listed
//! the contents without an encoding; version 6 is the first canonical
//! encoding, with eleven entry sets. Version 7 (ADR-0039) adds the twelfth,
//! the timestamp authorities; a version 6 body is not a version 7 body.

use core::str;

use crate::codec::{Decode, Encode};
use crate::envelope::{Header, decode as decode_object};
use crate::error::{Error, Kind};
use crate::primitives::{Day, ElectionId, Hash512, IDENT_MAX_STANDARD, Ident, TimeBucket};
use crate::reader::Reader;
use crate::schema::genesis::{AMENDABLE_SET_COUNT, ENTRY_SET_COUNT, EntrySet, read_nonzero_hash};
use crate::schema::share_package::ChamberCode;
use crate::schema::util::{
    HYBRID_SIG_LEN, HYBRID_VK_LEN, ascending_by, keys_share_half, read_fixed,
};
use crate::schema::{SCHEMA_GENESIS_AMENDMENT_BODY, SCHEMA_GENESIS_BODY, SCHEMA_VERSION_1};
use crate::writer::Writer;

/// The version of schema `0x0002` this crate encodes: 7, twelve entry
/// sets (ADR-0039).
pub const SCHEMA_VERSION_GENESIS: u16 = 7;

/// Maximum length of an embedded genesis or amendment body object.
pub const MAX_GENESIS_BODY_LEN: usize = 16_384;

/// Minimum number of party chambers (ADR-0019).
pub const MIN_PARTIES: usize = 2;

/// Maximum number of party chambers (ADR-0019).
pub const MAX_PARTIES: usize = 4;

/// Maximum length of a party name in UTF-8 bytes.
pub const MAX_PARTY_NAME_LEN: usize = 128;

/// Maximum number of chambers: P1…P4, J, A, C, N.
pub const MAX_CHAMBERS: usize = 8;

/// Minimum size of the witness roster (PROTOCOL.md §4.1).
pub const MIN_WITNESSES: u8 = 13;

/// Maximum number of witnesses and of witness signatures.
pub const MAX_GENESIS_WITNESSES: usize = 64;

/// Minimum witness quorum (PROTOCOL.md §5.4).
pub const MIN_QUORUM: u8 = 9;

/// Minimum distinct organisations, providers and regions among a quorum
/// (PROTOCOL.md §5.4, VC-014).
pub const MIN_DIVERSITY: [u8; 3] = [7, 4, 3];

/// Signature purpose of a genesis body.
pub const PURPOSE_GENESIS: &[u8] = b"genesis";

/// Signature purpose of a genesis amendment body.
pub const PURPOSE_GENESIS_AMENDMENT: &[u8] = b"genesis-amendment";

/// The count and Merkle root of one entry set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SetCommitment {
    /// Number of entries.
    pub count: u64,
    /// The tree root over the entries' object hashes in key order (the
    /// empty tree's root for no entries).
    pub root: Hash512,
}

impl Encode for SetCommitment {
    fn encoded_len(&self) -> usize {
        8 + 64
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        w.write_u64(self.count)?;
        self.root.encode(w)
    }
}

impl<'a> Decode<'a> for SetCommitment {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        Ok(Self {
            count: r.read_u64()?,
            root: Hash512::decode(r)?,
        })
    }
}

fn write_sets(w: &mut Writer<'_>, sets: &[SetCommitment]) -> Result<(), Error> {
    for s in sets {
        s.encode(w)?;
    }
    Ok(())
}

fn read_sets<const N: usize>(r: &mut Reader<'_>) -> Result<[SetCommitment; N], Error> {
    let mut sets = [SetCommitment {
        count: 0,
        root: Hash512([0; 64]),
    }; N];
    for slot in &mut sets {
        *slot = SetCommitment::decode(r)?;
    }
    Ok(sets)
}

/// One party chamber of the party roster (ADR-0019).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PartyEntry<'a> {
    /// The chamber code (`P1`…`P4` in order).
    pub chamber: ChamberCode,
    /// The party's registered name.
    pub name: &'a str,
    /// Seats in the National Assembly at genesis.
    pub seats: u16,
    /// Hash of the eligibility evidence (the previous election's
    /// proportional vote share and constituency seats, with sources).
    pub evidence_hash: Hash512,
}

/// The threshold of one chamber: `k_c` of `n_c` members.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChamberThreshold {
    /// The chamber.
    pub chamber: ChamberCode,
    /// `k_c`.
    pub threshold: u8,
    /// `n_c`.
    pub members: u8,
}

/// The witness quorum profile `(n, q, f)` and the diversity a quorum must
/// show (PROTOCOL.md §5.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WitnessQuorum {
    /// Witnesses on the roster, `n`.
    pub witnesses: u8,
    /// Signatures needed, `q`.
    pub quorum: u8,
    /// Faulty witnesses tolerated, `f`.
    pub byzantine_max: u8,
    /// Distinct organisations needed among the signers.
    pub min_orgs: u8,
    /// Distinct infrastructure providers needed.
    pub min_providers: u8,
    /// Distinct regions needed.
    pub min_regions: u8,
}

impl WitnessQuorum {
    /// Whether the profile is allowed: `13 ≤ n ≤ 64`, `9 ≤ q ≤ n`,
    /// `2q − n > f`, and diversity at least `7/4/3` and at most `q`.
    #[must_use]
    pub fn is_valid(self) -> bool {
        let [orgs, providers, regions] = MIN_DIVERSITY;
        let size_ok = self.witnesses >= MIN_WITNESSES
            && usize::from(self.witnesses) <= MAX_GENESIS_WITNESSES
            && self.quorum >= MIN_QUORUM
            && self.quorum <= self.witnesses;
        let twice = u16::from(self.quorum).saturating_mul(2);
        let bound = u16::from(self.witnesses).saturating_add(u16::from(self.byzantine_max));
        let diversity_ok = [
            (self.min_orgs, orgs),
            (self.min_providers, providers),
            (self.min_regions, regions),
        ]
        .iter()
        .all(|(value, floor)| value >= floor && *value <= self.quorum);
        size_ok && twice > bound && diversity_ok
    }
}

impl Encode for WitnessQuorum {
    fn encoded_len(&self) -> usize {
        6
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        for v in [
            self.witnesses,
            self.quorum,
            self.byzantine_max,
            self.min_orgs,
            self.min_providers,
            self.min_regions,
        ] {
            w.write_u8(v)?;
        }
        Ok(())
    }
}

impl<'a> Decode<'a> for WitnessQuorum {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let at = r.position();
        let [
            witnesses,
            quorum,
            byzantine_max,
            min_orgs,
            min_providers,
            min_regions,
        ] = r.read_array::<6>()?;
        let q = Self {
            witnesses,
            quorum,
            byzantine_max,
            min_orgs,
            min_providers,
            min_regions,
        };
        if q.is_valid() {
            Ok(q)
        } else {
            Err(Error::new(Kind::ValueOutOfRange, at))
        }
    }
}

/// Unvalidated inputs for [`GenesisBody::new`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GenesisParts<'a> {
    /// The election.
    pub election_id: ElectionId<'a>,
    /// The day from which time buckets count.
    pub election_epoch_day: Day,
    /// Hash of the bundle of statutes, rules and counting rules.
    pub policy_hash: Hash512,
    /// The proof system.
    pub proof_system_id: Ident<'a>,
    /// Object hash of the `LegalAuthorization` body (PROTOCOL.md §4.4).
    pub legal_authorization_hash: Hash512,
    /// Object hash of the `ConnectivityManifest` (§5.8).
    pub connectivity_manifest_hash: Hash512,
    /// Object hash of the `ReleaseManifest` (§4.6).
    pub release_manifest_hash: Hash512,
    /// The election commission's hybrid verifying key.
    pub commission_key: &'a [u8; HYBRID_VK_LEN],
    /// The Independent Verification Committee's hybrid verifying key.
    pub committee_key: &'a [u8; HYBRID_VK_LEN],
    /// The witness quorum and diversity rule.
    pub quorum: WitnessQuorum,
    /// The party chambers, `P1`…`Pn` in order.
    pub parties: &'a [PartyEntry<'a>],
    /// The chamber thresholds: `P1`…`Pn`, `J`, `A`, `C`, `N`.
    pub chambers: &'a [ChamberThreshold],
    /// The entry sets in [`EntrySet`] order.
    pub sets: [SetCommitment; ENTRY_SET_COUNT],
}

/// The expected chamber at position `index` of a genesis with `parties`
/// party chambers: `P1`…`Pn`, then `J`, `A`, `C`, `N` (`None` past `N`).
#[must_use]
pub fn expected_chamber(index: usize, parties: usize) -> Option<ChamberCode> {
    let code = if index < parties {
        index.checked_add(1)?
    } else {
        index.checked_sub(parties)?.checked_add(5)?
    };
    ChamberCode::from_code(u8::try_from(code).ok()?)
}

fn party_valid(index: usize, party: &PartyEntry<'_>, previous_seats: Option<u16>) -> bool {
    expected_chamber(index, MAX_CHAMBERS) == Some(party.chamber)
        && !party.name.is_empty()
        && party.name.len() <= MAX_PARTY_NAME_LEN
        && previous_seats.is_none_or(|before| party.seats <= before)
}

fn chamber_valid(index: usize, parties: usize, chamber: ChamberThreshold) -> bool {
    expected_chamber(index, parties) == Some(chamber.chamber)
        && chamber.threshold >= 1
        && chamber.threshold <= chamber.members
}

/// The genesis body (schema `0x0002`, version 7).
///
/// Rules: the four document hashes are nonzero (`InvalidPreviousHash`);
/// the two authority keys share no half (`InvariantViolation`, VC-006);
/// the quorum profile is valid (`ValueOutOfRange`); two to four party
/// chambers `P1`…`Pn` in order with non-increasing seats and a non-empty
/// UTF-8 name (`InvariantViolation`, `ValueOutOfRange` for bad UTF-8,
/// VC-067); the chamber thresholds list exactly `P1`…`Pn`, `J`, `A`, `C`,
/// `N` with `1 ≤ k_c ≤ n_c` (`InvariantViolation`); the witness set has
/// exactly `n` entries (`InvariantViolation`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GenesisBody<'a> {
    election_id: ElectionId<'a>,
    election_epoch_day: Day,
    policy_hash: Hash512,
    proof_system_id: Ident<'a>,
    legal_authorization_hash: Hash512,
    connectivity_manifest_hash: Hash512,
    release_manifest_hash: Hash512,
    commission_key: &'a [u8; HYBRID_VK_LEN],
    committee_key: &'a [u8; HYBRID_VK_LEN],
    quorum: WitnessQuorum,
    parties: [Option<PartyEntry<'a>>; MAX_PARTIES],
    party_count: u8,
    chambers: [Option<ChamberThreshold>; MAX_CHAMBERS],
    chamber_count: u8,
    sets: [SetCommitment; ENTRY_SET_COUNT],
}

fn witness_count_matches(quorum: WitnessQuorum, sets: &[SetCommitment]) -> bool {
    sets.get(EntrySet::Witnesses.index())
        .is_some_and(|s| s.count == u64::from(quorum.witnesses))
}

impl<'a> GenesisBody<'a> {
    /// Builds the body.
    ///
    /// # Errors
    /// `InvariantViolation` at 0 if a rule is broken.
    pub fn new(parts: &GenesisParts<'a>) -> Result<Self, Error> {
        let bad = Error::new(Kind::InvariantViolation, 0);
        let hashes_ok = [
            &parts.policy_hash,
            &parts.legal_authorization_hash,
            &parts.connectivity_manifest_hash,
            &parts.release_manifest_hash,
        ]
        .iter()
        .all(|h| !h.is_zero());
        let n = parts.parties.len();
        let parties_ok = (MIN_PARTIES..=MAX_PARTIES).contains(&n)
            && parts.parties.iter().enumerate().all(|(i, p)| {
                let before = i
                    .checked_sub(1)
                    .and_then(|j| parts.parties.get(j))
                    .map(|q| q.seats);
                party_valid(i, p, before)
            });
        let chambers_ok = n.checked_add(4) == Some(parts.chambers.len())
            && parts
                .chambers
                .iter()
                .enumerate()
                .all(|(i, c)| chamber_valid(i, n, *c));
        if !hashes_ok
            || keys_share_half(parts.commission_key, parts.committee_key)
            || !parts.quorum.is_valid()
            || !parties_ok
            || !chambers_ok
            || !witness_count_matches(parts.quorum, &parts.sets)
        {
            return Err(bad);
        }
        let mut parties = [None; MAX_PARTIES];
        for (slot, p) in parties.iter_mut().zip(parts.parties) {
            *slot = Some(*p);
        }
        let mut chambers = [None; MAX_CHAMBERS];
        for (slot, c) in chambers.iter_mut().zip(parts.chambers) {
            *slot = Some(*c);
        }
        Ok(Self {
            election_id: parts.election_id,
            election_epoch_day: parts.election_epoch_day,
            policy_hash: parts.policy_hash,
            proof_system_id: parts.proof_system_id,
            legal_authorization_hash: parts.legal_authorization_hash,
            connectivity_manifest_hash: parts.connectivity_manifest_hash,
            release_manifest_hash: parts.release_manifest_hash,
            commission_key: parts.commission_key,
            committee_key: parts.committee_key,
            quorum: parts.quorum,
            parties,
            party_count: u8::try_from(n).map_err(|_| bad)?,
            chambers,
            chamber_count: u8::try_from(parts.chambers.len()).map_err(|_| bad)?,
            sets: parts.sets,
        })
    }

    /// The election.
    #[must_use]
    pub const fn election_id(&self) -> ElectionId<'a> {
        self.election_id
    }

    /// The day from which time buckets count.
    #[must_use]
    pub const fn election_epoch_day(&self) -> Day {
        self.election_epoch_day
    }

    /// Hash of the policy bundle.
    #[must_use]
    pub const fn policy_hash(&self) -> &Hash512 {
        &self.policy_hash
    }

    /// The proof system.
    #[must_use]
    pub const fn proof_system_id(&self) -> Ident<'a> {
        self.proof_system_id
    }

    /// Object hash of the `LegalAuthorization` body.
    #[must_use]
    pub const fn legal_authorization_hash(&self) -> &Hash512 {
        &self.legal_authorization_hash
    }

    /// Object hash of the `ConnectivityManifest`.
    #[must_use]
    pub const fn connectivity_manifest_hash(&self) -> &Hash512 {
        &self.connectivity_manifest_hash
    }

    /// Object hash of the `ReleaseManifest`.
    #[must_use]
    pub const fn release_manifest_hash(&self) -> &Hash512 {
        &self.release_manifest_hash
    }

    /// The election commission's key.
    #[must_use]
    pub const fn commission_key(&self) -> &'a [u8; HYBRID_VK_LEN] {
        self.commission_key
    }

    /// The Independent Verification Committee's key.
    #[must_use]
    pub const fn committee_key(&self) -> &'a [u8; HYBRID_VK_LEN] {
        self.committee_key
    }

    /// The witness quorum and diversity rule.
    #[must_use]
    pub const fn quorum(&self) -> &WitnessQuorum {
        &self.quorum
    }

    /// The party chambers in order.
    pub fn parties(&self) -> impl Iterator<Item = PartyEntry<'a>> + '_ {
        self.parties
            .iter()
            .take(usize::from(self.party_count))
            .flatten()
            .copied()
    }

    /// The chamber thresholds in order.
    pub fn chambers(&self) -> impl Iterator<Item = ChamberThreshold> + '_ {
        self.chambers
            .iter()
            .take(usize::from(self.chamber_count))
            .flatten()
            .copied()
    }

    /// The entry-set commitments in [`EntrySet`] order.
    #[must_use]
    pub const fn sets(&self) -> &[SetCommitment; ENTRY_SET_COUNT] {
        &self.sets
    }
}

impl Encode for GenesisBody<'_> {
    fn encoded_len(&self) -> usize {
        let parties = self.parties().fold(4usize, |acc, p| {
            acc.saturating_add(1 + 4 + 2 + 64)
                .saturating_add(p.name.len())
        });
        let chambers = self.chambers().count().saturating_mul(3).saturating_add(4);
        self.election_id
            .encoded_len()
            .saturating_add(8 + 64)
            .saturating_add(self.proof_system_id.byte_len().saturating_add(4))
            .saturating_add(3 * 64)
            .saturating_add(2 * HYBRID_VK_LEN)
            .saturating_add(self.quorum.encoded_len())
            .saturating_add(parties)
            .saturating_add(chambers)
            .saturating_add(ENTRY_SET_COUNT.saturating_mul(72))
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        self.election_id.encode(w)?;
        self.election_epoch_day.encode(w)?;
        self.policy_hash.encode(w)?;
        w.write_ident(&self.proof_system_id, IDENT_MAX_STANDARD)?;
        self.legal_authorization_hash.encode(w)?;
        self.connectivity_manifest_hash.encode(w)?;
        self.release_manifest_hash.encode(w)?;
        w.write_array(self.commission_key)?;
        w.write_array(self.committee_key)?;
        self.quorum.encode(w)?;
        w.write_count(usize::from(self.party_count), MAX_PARTIES)?;
        for p in self.parties() {
            w.write_u8(p.chamber.code())?;
            w.write_bytes(p.name.as_bytes(), MAX_PARTY_NAME_LEN)?;
            w.write_u16(p.seats)?;
            p.evidence_hash.encode(w)?;
        }
        w.write_count(usize::from(self.chamber_count), MAX_CHAMBERS)?;
        for c in self.chambers() {
            w.write_u8(c.chamber.code())?;
            w.write_u8(c.threshold)?;
            w.write_u8(c.members)?;
        }
        write_sets(w, &self.sets)
    }
}

fn read_party<'a>(
    r: &mut Reader<'a>,
    index: usize,
    previous_seats: Option<u16>,
) -> Result<PartyEntry<'a>, Error> {
    let at = r.position();
    let chamber = ChamberCode::from_code(r.read_u8()?)
        .ok_or_else(|| Error::new(Kind::ValueOutOfRange, at))?;
    let name_at = r.position();
    let name = str::from_utf8(r.read_bytes(MAX_PARTY_NAME_LEN)?)
        .map_err(|_| Error::new(Kind::ValueOutOfRange, name_at))?;
    let party = PartyEntry {
        chamber,
        name,
        seats: r.read_u16()?,
        evidence_hash: read_nonzero_hash(r)?,
    };
    if party_valid(index, &party, previous_seats) {
        Ok(party)
    } else {
        Err(Error::new(Kind::InvariantViolation, at))
    }
}

impl<'a> Decode<'a> for GenesisBody<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let election_id = ElectionId::decode(r)?;
        let election_epoch_day = Day::decode(r)?;
        let policy_hash = read_nonzero_hash(r)?;
        let proof_system_id = r.read_ident(IDENT_MAX_STANDARD)?;
        let legal_authorization_hash = read_nonzero_hash(r)?;
        let connectivity_manifest_hash = read_nonzero_hash(r)?;
        let release_manifest_hash = read_nonzero_hash(r)?;
        let commission_key = read_fixed::<HYBRID_VK_LEN>(r)?;
        let committee_at = r.position();
        let committee_key = read_fixed::<HYBRID_VK_LEN>(r)?;
        if keys_share_half(commission_key, committee_key) {
            return Err(Error::new(Kind::InvariantViolation, committee_at));
        }
        let quorum = WitnessQuorum::decode(r)?;
        let parties_at = r.position();
        let party_count = r.read_count(MAX_PARTIES)?;
        if party_count < MIN_PARTIES {
            return Err(Error::new(Kind::InvariantViolation, parties_at));
        }
        let mut parties = [None; MAX_PARTIES];
        let mut previous_seats = None;
        for (index, slot) in parties.iter_mut().enumerate().take(party_count) {
            let party = read_party(r, index, previous_seats)?;
            previous_seats = Some(party.seats);
            *slot = Some(party);
        }
        let chambers_at = r.position();
        let chamber_count = r.read_count(MAX_CHAMBERS)?;
        if party_count.checked_add(4) != Some(chamber_count) {
            return Err(Error::new(Kind::InvariantViolation, chambers_at));
        }
        let mut chambers = [None; MAX_CHAMBERS];
        for (index, slot) in chambers.iter_mut().enumerate().take(chamber_count) {
            let at = r.position();
            let [code, threshold, members] = r.read_array::<3>()?;
            let chamber = ChamberCode::from_code(code)
                .map(|chamber| ChamberThreshold {
                    chamber,
                    threshold,
                    members,
                })
                .filter(|c| chamber_valid(index, party_count, *c))
                .ok_or_else(|| Error::new(Kind::InvariantViolation, at))?;
            *slot = Some(chamber);
        }
        let sets_at = r.position();
        let sets = read_sets::<ENTRY_SET_COUNT>(r)?;
        if !witness_count_matches(quorum, &sets) {
            return Err(Error::new(Kind::InvariantViolation, sets_at));
        }
        Ok(Self {
            election_id,
            election_epoch_day,
            policy_hash,
            proof_system_id,
            legal_authorization_hash,
            connectivity_manifest_hash,
            release_manifest_hash,
            commission_key,
            committee_key,
            quorum,
            parties,
            party_count: u8::try_from(party_count)
                .map_err(|_| Error::new(Kind::CountExceedsMax, parties_at))?,
            chambers,
            chamber_count: u8::try_from(chamber_count)
                .map_err(|_| Error::new(Kind::CountExceedsMax, chambers_at))?,
            sets,
        })
    }
}

/// Why a genesis was amended (PROTOCOL.md §4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum AmendmentReason {
    /// A device replaced by a spare that was not registered before.
    DeviceReplacement = 1,
    /// A roster change (a clerk, observer or custodian replaced).
    RosterChange = 2,
    /// A re-certified release (§4.6, VC-085).
    ReleaseChange = 3,
    /// Any other unavoidable change, stated in the reason document.
    Other = 4,
}

impl AmendmentReason {
    /// The wire code.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Returns the reason with wire code `code`, if defined.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::DeviceReplacement),
            2 => Some(Self::RosterChange),
            3 => Some(Self::ReleaseChange),
            4 => Some(Self::Other),
            _ => None,
        }
    }
}

/// The fields of a genesis amendment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GenesisAmendmentParts<'a> {
    /// The election.
    pub election_id: ElectionId<'a>,
    /// One-based amendment number.
    pub seq: u64,
    /// Object hash of the genesis body (for `seq` 1) or of the previous
    /// amendment body.
    pub previous_hash: Hash512,
    /// Why.
    pub reason: AmendmentReason,
    /// Hash of the published reason document.
    pub reason_hash: Hash512,
    /// When it takes effect.
    pub time_bucket: TimeBucket,
    /// The release manifest from now on (unchanged unless the reason is a
    /// release change).
    pub release_manifest_hash: Hash512,
    /// The new commitments of the amendable sets (codes 1–8), unchanged
    /// sets repeated.
    pub sets: [SetCommitment; AMENDABLE_SET_COUNT],
}

/// A genesis amendment body (schema `0x0034`).
///
/// Rules: `seq ≥ 1` (`ValueOutOfRange`); the three hashes are nonzero
/// (`InvalidPreviousHash`). The ballot styles, trustees, witnesses, keys
/// and quorum cannot be amended: the body has no field for them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GenesisAmendmentBody<'a> {
    parts: GenesisAmendmentParts<'a>,
}

impl<'a> GenesisAmendmentBody<'a> {
    /// Builds the body.
    ///
    /// # Errors
    /// `InvariantViolation` at 0 if a rule is broken.
    pub fn new(parts: &GenesisAmendmentParts<'a>) -> Result<Self, Error> {
        let ok = parts.seq >= 1
            && !parts.previous_hash.is_zero()
            && !parts.reason_hash.is_zero()
            && !parts.release_manifest_hash.is_zero();
        if ok {
            Ok(Self { parts: *parts })
        } else {
            Err(Error::new(Kind::InvariantViolation, 0))
        }
    }

    /// The fields.
    #[must_use]
    pub const fn parts(&self) -> &GenesisAmendmentParts<'a> {
        &self.parts
    }
}

impl Encode for GenesisAmendmentBody<'_> {
    fn encoded_len(&self) -> usize {
        self.parts
            .election_id
            .encoded_len()
            .saturating_add(8 + 64 + 1 + 64 + 8 + 64)
            .saturating_add(AMENDABLE_SET_COUNT.saturating_mul(72))
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        let p = &self.parts;
        p.election_id.encode(w)?;
        w.write_u64(p.seq)?;
        p.previous_hash.encode(w)?;
        w.write_u8(p.reason.code())?;
        p.reason_hash.encode(w)?;
        p.time_bucket.encode(w)?;
        p.release_manifest_hash.encode(w)?;
        write_sets(w, &p.sets)
    }
}

impl<'a> Decode<'a> for GenesisAmendmentBody<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let election_id = ElectionId::decode(r)?;
        let seq_at = r.position();
        let seq = r.read_u64()?;
        if seq == 0 {
            return Err(Error::new(Kind::ValueOutOfRange, seq_at));
        }
        let previous_hash = read_nonzero_hash(r)?;
        let reason_at = r.position();
        let reason = AmendmentReason::from_code(r.read_u8()?)
            .ok_or_else(|| Error::new(Kind::ValueOutOfRange, reason_at))?;
        Ok(Self {
            parts: GenesisAmendmentParts {
                election_id,
                seq,
                previous_hash,
                reason,
                reason_hash: read_nonzero_hash(r)?,
                time_bucket: TimeBucket::decode(r)?,
                release_manifest_hash: read_nonzero_hash(r)?,
                sets: read_sets::<AMENDABLE_SET_COUNT>(r)?,
            },
        })
    }
}

/// Which body a [`SignedGenesis`] carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GenesisKind {
    /// The genesis itself (`GenesisBody`).
    Genesis,
    /// An amendment (`GenesisAmendmentBody`).
    Amendment,
}

impl GenesisKind {
    /// The signature purpose of the body.
    #[must_use]
    pub const fn purpose(self) -> &'static [u8] {
        match self {
            Self::Genesis => PURPOSE_GENESIS,
            Self::Amendment => PURPOSE_GENESIS_AMENDMENT,
        }
    }
}

/// Decodes `bytes` as a complete genesis or amendment body and returns its
/// kind with the fewest witness signatures the body itself allows: its
/// quorum for a genesis, the protocol minimum for an amendment (whose
/// quorum is the genesis's).
fn classify(bytes: &[u8]) -> Result<(GenesisKind, u8), Error> {
    if bytes.len() > MAX_GENESIS_BODY_LEN {
        return Err(Error::new(Kind::LengthExceedsMax, 0));
    }
    let header = Header::read(&mut Reader::new(bytes))?;
    match header.schema_id() {
        SCHEMA_GENESIS_BODY => {
            decode_object::<GenesisBody<'_>>(SCHEMA_GENESIS_BODY, SCHEMA_VERSION_GENESIS, bytes)
                .map(|body| (GenesisKind::Genesis, body.quorum.quorum))
        }
        SCHEMA_GENESIS_AMENDMENT_BODY => decode_object::<GenesisAmendmentBody<'_>>(
            SCHEMA_GENESIS_AMENDMENT_BODY,
            SCHEMA_VERSION_1,
            bytes,
        )
        .map(|_| (GenesisKind::Amendment, MIN_QUORUM)),
        _ => Err(Error::new(Kind::SchemaMismatch, 4)),
    }
}

/// One witness signature on a genesis or amendment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GenesisWitnessSig<'a> {
    /// The witness, as on the witness roster.
    pub witness_id: Ident<'a>,
    /// The hybrid signature over the body bytes.
    pub sig: &'a [u8; HYBRID_SIG_LEN],
}

/// A signed genesis or amendment (schema `0x0033`): the body object bytes,
/// the election commission's and the committee's signatures and the
/// witness signatures, all over exactly the body bytes with the body's
/// purpose (PROTOCOL.md §4.2, §4.3).
///
/// Rules: the body is a complete `GenesisBody` (version 7) or
/// `GenesisAmendmentBody` (`SchemaMismatch` otherwise); the witness
/// signatures are strictly ascending by `witness_id` (`NotSorted`,
/// `Duplicate`) and at least the genesis quorum `q`, or nine for an
/// amendment (`InvariantViolation`). Whether each signature
/// verifies under the registered key, and the diversity of the signers,
/// are checked by the consumer of the `Verified` tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SignedGenesis<'a> {
    body_bytes: &'a [u8],
    kind: GenesisKind,
    commission_sig: &'a [u8; HYBRID_SIG_LEN],
    committee_sig: &'a [u8; HYBRID_SIG_LEN],
    witnesses: [Option<GenesisWitnessSig<'a>>; MAX_GENESIS_WITNESSES],
    count: u8,
}

impl<'a> SignedGenesis<'a> {
    /// Builds the object.
    ///
    /// # Errors
    /// The body's decoding error, `LengthExceedsMax` or `SchemaMismatch`
    /// for the body, `InvariantViolation` at 0 if the witness signatures
    /// are out of order or too few.
    pub fn new(
        body_bytes: &'a [u8],
        commission_sig: &'a [u8; HYBRID_SIG_LEN],
        committee_sig: &'a [u8; HYBRID_SIG_LEN],
        witnesses: &[GenesisWitnessSig<'a>],
    ) -> Result<Self, Error> {
        let (kind, min) = classify(body_bytes)?;
        let ok = witnesses.len() <= MAX_GENESIS_WITNESSES
            && ascending_by(witnesses, |s| s.witness_id.as_bytes())
            && witnesses.len() >= usize::from(min);
        if !ok {
            return Err(Error::new(Kind::InvariantViolation, 0));
        }
        let mut slots = [None; MAX_GENESIS_WITNESSES];
        for (slot, s) in slots.iter_mut().zip(witnesses) {
            *slot = Some(*s);
        }
        Ok(Self {
            body_bytes,
            kind,
            commission_sig,
            committee_sig,
            witnesses: slots,
            count: u8::try_from(witnesses.len())
                .map_err(|_| Error::new(Kind::InvariantViolation, 0))?,
        })
    }

    /// The body object bytes (the signed message).
    #[must_use]
    pub const fn body_bytes(&self) -> &'a [u8] {
        self.body_bytes
    }

    /// Which body it carries.
    #[must_use]
    pub const fn kind(&self) -> GenesisKind {
        self.kind
    }

    /// The genesis body, if it carries one.
    #[must_use]
    pub fn genesis(&self) -> Option<GenesisBody<'a>> {
        decode_object(SCHEMA_GENESIS_BODY, SCHEMA_VERSION_GENESIS, self.body_bytes).ok()
    }

    /// The amendment body, if it carries one.
    #[must_use]
    pub fn amendment(&self) -> Option<GenesisAmendmentBody<'a>> {
        decode_object(
            SCHEMA_GENESIS_AMENDMENT_BODY,
            SCHEMA_VERSION_1,
            self.body_bytes,
        )
        .ok()
    }

    /// The signature purpose.
    #[must_use]
    pub const fn purpose(&self) -> &'static [u8] {
        self.kind.purpose()
    }

    /// The election commission's signature.
    #[must_use]
    pub const fn commission_sig(&self) -> &'a [u8; HYBRID_SIG_LEN] {
        self.commission_sig
    }

    /// The committee's signature.
    #[must_use]
    pub const fn committee_sig(&self) -> &'a [u8; HYBRID_SIG_LEN] {
        self.committee_sig
    }

    /// The witness signatures in ascending witness order.
    pub fn witness_sigs(&self) -> impl Iterator<Item = GenesisWitnessSig<'a>> + '_ {
        self.witnesses
            .iter()
            .take(usize::from(self.count))
            .flatten()
            .copied()
    }

    /// Number of witness signatures.
    #[must_use]
    pub fn witness_count(&self) -> usize {
        usize::from(self.count)
    }
}

impl Encode for SignedGenesis<'_> {
    fn encoded_len(&self) -> usize {
        let witnesses = self.witness_sigs().fold(4usize, |acc, s| {
            acc.saturating_add(s.witness_id.byte_len())
                .saturating_add(4 + HYBRID_SIG_LEN)
        });
        self.body_bytes
            .len()
            .saturating_add(4)
            .saturating_add(2 * HYBRID_SIG_LEN)
            .saturating_add(witnesses)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        w.write_bytes(self.body_bytes, MAX_GENESIS_BODY_LEN)?;
        w.write_array(self.commission_sig)?;
        w.write_array(self.committee_sig)?;
        w.write_count(usize::from(self.count), MAX_GENESIS_WITNESSES)?;
        for s in self.witness_sigs() {
            w.write_ident(&s.witness_id, IDENT_MAX_STANDARD)?;
            w.write_array(s.sig)?;
        }
        Ok(())
    }
}

impl<'a> Decode<'a> for SignedGenesis<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let at = r.position();
        let body_bytes = r.read_bytes(MAX_GENESIS_BODY_LEN)?;
        let (kind, min) = classify(body_bytes).map_err(|inner| {
            let offset = at
                .checked_add(4)
                .and_then(|p| p.checked_add(inner.offset()))
                .unwrap_or(at);
            Error::new(inner.kind(), offset)
        })?;
        let commission_sig = read_fixed::<HYBRID_SIG_LEN>(r)?;
        let committee_sig = read_fixed::<HYBRID_SIG_LEN>(r)?;
        let count_at = r.position();
        let count = r.read_count(MAX_GENESIS_WITNESSES)?;
        if count < usize::from(min) {
            return Err(Error::new(Kind::InvariantViolation, count_at));
        }
        let mut witnesses = [None; MAX_GENESIS_WITNESSES];
        let mut previous: Option<&[u8]> = None;
        for slot in witnesses.iter_mut().take(count) {
            let id_at = r.position();
            let witness_id = r.read_ident(IDENT_MAX_STANDARD)?;
            Reader::check_ascending(previous, witness_id.as_bytes(), id_at)?;
            previous = Some(witness_id.as_bytes());
            *slot = Some(GenesisWitnessSig {
                witness_id,
                sig: read_fixed::<HYBRID_SIG_LEN>(r)?,
            });
        }
        Ok(Self {
            body_bytes,
            kind,
            commission_sig,
            committee_sig,
            witnesses,
            count: u8::try_from(count).map_err(|_| Error::new(Kind::CountExceedsMax, count_at))?,
        })
    }
}
