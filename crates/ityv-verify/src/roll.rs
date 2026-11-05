//! The voter roll (PROTOCOL.md §6.1, §6.2, §14 6; ADR-0033, ADR-0040;
//! VC-107..111).
//!
//! [`verify_roll`] reads the roll's ledger events in frame order, each in a
//! `WitnessedEvent`, against the genesis's roll authorities (set 13, fixed)
//! and its custody quorum:
//!
//! * **Source extracts** (`RollSourceExtractBody`), before the freeze, each
//!   signed by the source it names, whose function is the extract's kind
//!   (`ityv_state::admit_extract`). A resident extract names its precinct,
//!   an election-day station of the genesis state in force at its frame.
//!   One extract per precinct, one national snapshot, one list per kind
//!   and source: the same body again is a repeat, another body a conflict.
//! * **The freeze** (`RollFreezeBody`), one per election, signed by the
//!   commission and the committee. It merges the extracts taken before it
//!   (VC-107): its sources root and count are those of their bodies'
//!   object hashes, every election-day station of the state in force has
//!   its resident extract, and the national snapshot is among them. Which
//!   entries the merge gives is recomputed by the custodians, who hold the
//!   extracts.
//! * **Custody receipts** (`RollCustodyReceiptBody`), each signed by the
//!   custodian it names, answering the freeze or an amendment taken in an
//!   earlier frame, once per custodian and subject. A receipt for the
//!   freeze names the sources root it merged; one for an amendment names
//!   none. A receipt whose recomputed values (entries root and count,
//!   counts table, sources root, a pseudonym root it gives) differ from
//!   its subject's is a custody mismatch ([`CustodyMismatch`],
//!   `RollCustodyMismatch`): it does not count, and the custodians' copies
//!   are compared in a dispute (ADR-0033 decision 2).
//! * **Amendments** (`RollAmendmentBody`), after the freeze, numbered from
//!   1 and chained to the freeze body, then to the previous amendment
//!   body, signed by the commission, the committee and the source the
//!   reason needs (`ityv_state::admit_amendment`, VC-111).
//!
//! A roll state (the freeze, each amendment) takes effect when the distinct
//! custodians whose receipts agree with it reach the genesis's custody
//! quorum with the court administration and the Ministry of the Interior
//! among them (`ityv_state::custody_quorum`, VC-108), and one of those
//! receipts gives the pseudonym root, which the custodian computed
//! (VC-109). The stage is complete when the freeze and every amendment
//! took effect; the participation step of the status ladder waits for it
//! (§14 6). Its legal effect is that alone: without it the electronic
//! verification status is not confirmed (`LEGAL_ANNEX.md` amendment 14, §44-3
//! ④ and ⑤); whether the roll is lawful is not the verifier's to say.
//!
//! **Contested check-ins** (`ContestedCheckin`, restricted, §6.2): the
//! public ledger carries their frames by hash only, and the public
//! verifier counts them. A verifier with access supplies the bodies
//! ([`RollInput::contested`]); each whose object hash a frame names is
//! checked like a participation set (the station of the state at its
//! frame, the check-in unit it names in service or spare in a state up to
//! that frame, one party module of that unit per party in chamber order,
//! over the field group) and its pseudonym looked up in the accepted
//! participation sets: found means a second attempt, excluded and passed
//! to investigators; absent, once every station's set is in, means the
//! "already voted" mark was false and the envelope may be counted by a
//! legal decision (ADR-0033 decision 6). Check-ins are one per message, the
//! pair (pseudonym, envelope label), not per object: hybrid signatures are
//! hedged, so the same message signed again is another object and another
//! frame, and it counts once ([`ContestedFinding::Copy`]). A pseudonym in
//! two messages (two envelopes) is a voter who voted twice under protest,
//! and a label in two messages is one envelope for two voters: every such
//! check-in is excluded ([`ContestedFinding::Repeated`],
//! [`ContestedFinding::LabelReused`]) and holds the ledger
//! (`ContestedRepeated`). The stage reports the finding; the counting is
//! the law's.
//!
//! Every event the stage cannot take is listed ([`RollRefused`]) and holds
//! the ledger (`RollEventRefused`); a supplied check-in of the ledger that
//! does not verify holds it too (`ContestedCheckinInvalid`).
//!
//! What this stage does not prove: that the extracts are true of the
//! registers (their sources sign them), which entries their merge gives,
//! that the extracts and the snapshot name one reference day, that a
//! district head signs only for precincts of its district (the genesis
//! maps no precinct to a head), that the pseudonym root was computed on a
//! certified unit with every party module before observers (the
//! custodians recompute and attest it), the counts table against the
//! Ministry's statistics (published for anyone to compare), the subset
//! of the participation multiset in the roll's (once the roll's pseudonym
//! set is published), or the published per-station count of contested
//! check-ins (VC-112).

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use ityv_crypto::hash::object_hash;
use ityv_crypto::{Purpose, Sha3Hasher};
use ityv_encoding::{
    AuthorityId, CheckinUnit, ContestedCheckin, EntrySet, EventRole, HYBRID_VK_LEN, Hash512, OrgId,
    PSEUDONYM_LEN, PURPOSE_CONTESTED_CHECKIN, RollAmendmentBody, RollAmendmentReason,
    RollAuthorityEntry, RollAuthorityKind, RollCustodyReceiptBody, RollFreezeBody,
    RollSourceExtractBody, RollSourceKind, RollState, SCHEMA_CONTESTED_CHECKIN,
    SCHEMA_ROLL_AMENDMENT_BODY, SCHEMA_ROLL_CUSTODY_RECEIPT_BODY, SCHEMA_ROLL_FREEZE_BODY,
    SCHEMA_ROLL_SOURCE_EXTRACT_BODY, SCHEMA_WITNESSED_EVENT, Seq, StationEntry, StationId,
    StationKind, WitnessedEvent, decode_object, schema_version,
};
use ityv_ledger::{InclusionProof, sorted_set_root, verify_inclusion};
use ityv_state::{
    Error as StateError, HoldReason, HoldSet, Signed, admit_amendment, admit_extract, admit_freeze,
    admit_receipt, custody_quorum,
};

use crate::error::{Error, Rule};
use crate::genesis::VerifiedGenesis;
use crate::index::LedgerIndex;
use crate::org::same_org;
use crate::participation::ParticipationStage;
use crate::sets::Set;
use crate::sigs::Material;

/// The label of a roll entry commitment (PROTOCOL.md §6.1).
const ROLL_LABEL: &[u8] = b"ityv:roll:v1";

/// `C_i = SHA3-512("ityv:roll:v1" ‖ 0x00 ‖ s_i ‖ canonical(e_i))`, the
/// commitment of one roll entry under its 32-byte salt (PROTOCOL.md §6.1,
/// VC-110). `entry` is the entry's canonical encoding, whose form the
/// sub-regulation fixes (`LEGAL_ANNEX.md` amendment 14).
#[must_use]
pub fn roll_entry_commitment(salt: &[u8; 32], entry: &[u8]) -> Hash512 {
    let mut h = Sha3Hasher::new();
    h.absorb(ROLL_LABEL);
    h.absorb(&[0x00]);
    h.absorb(salt);
    h.absorb(entry);
    Hash512(h.finish())
}

/// Whether `commitment` is entry `index` of the roll whose entries root is
/// `root` over `count` entries, by the inclusion proof `proof` a voter
/// receives through the inspection channel (PROTOCOL.md §6.1, VC-110):
/// the root is the sorted-set root of the commitments. The root to compare
/// with is the one the custodians confirmed ([`RollStage::roll`]).
#[must_use]
pub fn roll_entry_included(
    root: &Hash512,
    count: u64,
    index: u64,
    commitment: &Hash512,
    proof: &InclusionProof,
) -> bool {
    verify_inclusion(root, count, index, commitment, proof).is_ok()
}

/// Checks the genesis's roll authorities (set 13) against its custody
/// quorum `quorum` (ADR-0040): no two custodians of one organisation, at
/// least `quorum` custodians with the court administration and the
/// Ministry of the Interior among them, exactly one custodian each of
/// the court administration, the Ministry and the committee, a district
/// head and exactly one source of the national snapshot. Otherwise no roll could ever take
/// effect, or one organisation would count twice. The keys are checked
/// with every other key of the genesis (valid, no shared half).
///
/// # Errors
/// [`Rule::RollCustodians`] at the second custodian of an organisation or
/// for the set, [`Rule::RollSources`] for the set.
pub(crate) fn check_authorities(
    state: u64,
    set: &Set<'_, RollAuthorityEntry<'_>>,
    quorum: u8,
) -> Result<(), Error> {
    // Organisations as names compare (`same_org`): one body under two
    // spellings would count twice toward the quorum.
    let mut orgs: Vec<OrgId<'_>> = Vec::new();
    let mut kinds: Vec<RollAuthorityKind> = Vec::new();
    for (index, item) in set.items().iter().enumerate() {
        let entry = &item.value;
        let repeated = orgs.iter().any(|o| same_org(*o, entry.org_id));
        if entry.kind.is_custodian() {
            orgs.push(entry.org_id);
        }
        if entry.kind.is_custodian() && repeated {
            return Err(Error::entry(
                state,
                EntrySet::RollAuthorities,
                index,
                Rule::RollCustodians,
            ));
        }
        kinds.push(entry.kind);
    }
    if !custody_quorum(&kinds, quorum) {
        return Err(Error::set(
            state,
            EntrySet::RollAuthorities,
            Rule::RollCustodians,
        ));
    }
    let count = |kind| kinds.iter().filter(|k| **k == kind).count();
    // One court administration, one Ministry, one committee: a second
    // entry of one of those kinds (another organisation calling itself
    // the court administration) would stand in for it in the quorum
    // (`custody_quorum` asks for each kind, not for an authority).
    let branches = [
        RollAuthorityKind::CustodianJudiciary,
        RollAuthorityKind::CustodianInterior,
        RollAuthorityKind::CustodianCommittee,
    ];
    if branches.iter().any(|kind| count(*kind) != 1) {
        return Err(Error::set(
            state,
            EntrySet::RollAuthorities,
            Rule::RollCustodians,
        ));
    }
    if count(RollAuthorityKind::ResidentExtract) == 0
        || count(RollAuthorityKind::ResidentSnapshot) != 1
    {
        return Err(Error::set(
            state,
            EntrySet::RollAuthorities,
            Rule::RollSources,
        ));
    }
    Ok(())
}

/// Which roll event a refusal concerns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RollEvent {
    /// A source extract.
    Extract,
    /// The freeze.
    Freeze,
    /// A custody receipt.
    Receipt,
    /// An amendment.
    Amendment,
}

/// Why the roll stage refused an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RollRefusal {
    /// It names an authority the genesis does not have or whose function
    /// is not the event's (an extract of another kind, an amendment reason
    /// another source decides, a receipt of no custodian), or a signer is
    /// not the authority, organisation and role it names.
    Authority,
    /// A signature does not verify under the key the genesis registers
    /// for its signer, or two signers share a key half.
    Signature,
    /// A resident extract names no election-day station of the genesis
    /// state in force at its frame.
    Precinct,
    /// An extract after the freeze: after the freeze only an amendment
    /// changes the roll (ADR-0033 decision 5).
    AfterFreeze,
    /// The freeze's sources root or count is not that of the extracts
    /// taken before it (VC-107).
    Sources,
    /// At the freeze, an election-day station of the state in force has
    /// no resident extract, or the national snapshot is missing: a roll
    /// fact without its source (VC-107).
    Incomplete,
    /// The freeze's entry count is not one the extracts taken before it
    /// can give: above the resident extracts' sum plus the overseas lists'
    /// entries, or below that sum less the entries of every removal list
    /// (deaths, disqualifications, overseas and loss of nationality). The
    /// exact count is the custodians' to recompute (VC-107).
    Count,
    /// A receipt answers no freeze or amendment taken in an earlier
    /// frame, or names a sources root for an amendment or none for the
    /// freeze.
    Subject,
    /// An amendment before the freeze, not the next number, or not
    /// chained to the freeze body or the previous amendment body.
    Chain,
    /// The body already taken for its subject (a precinct or list, the
    /// freeze, an amendment number, a custodian's receipt for a subject),
    /// again under other signature bytes.
    Repeated,
    /// Another body for a subject already taken: two signed answers to
    /// one question.
    Conflict,
}

/// A roll event that was not taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RollRefused {
    /// The frame that carries it.
    pub seq: Seq,
    /// Which event.
    pub event: RollEvent,
    /// Why.
    pub refusal: RollRefusal,
}

/// A custody receipt whose recomputed values differ from its subject's
/// (`RollCustodyMismatch`, ADR-0033 decision 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CustodyMismatch<'a> {
    /// The frame of the receipt.
    pub seq: Seq,
    /// The custodian.
    pub custodian: AuthorityId<'a>,
    /// The object hash of the freeze or amendment body it answers.
    pub subject: Hash512,
}

/// A roll state (the freeze or an amendment) and its custody.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Custody<'a> {
    /// The frame that carries it.
    pub seq: Seq,
    /// The object hash of its body.
    pub hash: Hash512,
    /// Its values.
    pub state: RollState,
    /// The sources root it merges: the freeze's; `None` for an
    /// amendment.
    pub sources_root: Option<Hash512>,
    /// The custodians whose receipts agree with it, in frame order.
    pub custodians: Vec<AuthorityId<'a>>,
    /// Whether one of those receipts gives the pseudonym root (VC-109).
    pub pseudonym_confirmed: bool,
    /// Whether it took effect: the agreeing custodians reach the quorum
    /// with the court administration and the Ministry of the Interior,
    /// and one of them gave the pseudonym root (VC-108, VC-109).
    pub effective: bool,
}

/// A source extract taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TakenExtract<'a> {
    /// The frame that carries it.
    pub seq: Seq,
    /// The object hash of its body.
    pub hash: Hash512,
    /// What it lists.
    pub kind: RollSourceKind,
    /// The source that signed it.
    pub authority: AuthorityId<'a>,
    /// Its precinct, for a resident extract.
    pub precinct: Option<StationId<'a>>,
    /// How many entries it lists.
    pub entries: u64,
}

/// An amendment taken, with its custody.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TakenAmendment<'a> {
    /// Its number.
    pub number: u64,
    /// Why.
    pub reason: RollAmendmentReason,
    /// The source that signed it.
    pub authority: AuthorityId<'a>,
    /// The hash of the source's decision or notice.
    pub basis_hash: Hash512,
    /// Its custody.
    pub custody: Custody<'a>,
}

/// What the stage found of one supplied contested check-in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContestedFinding<'a> {
    /// No frame of the ledger names its object hash.
    NotOnLedger,
    /// It is the ledger's and does not verify: not a canonical body,
    /// another election, a station the genesis state at its frame lacks,
    /// no unit of the station it names (in a state up to its frame) whose
    /// key verifies it, or module signatures that are not one per party
    /// from that unit's modules in chamber order.
    Invalid,
    /// The pseudonym is in the accepted participation set of the station:
    /// a second attempt, excluded and passed to investigators.
    Elsewhere(StationId<'a>),
    /// The pseudonym is in no accepted participation set, and every
    /// station's set is in: the mark was false, and the envelope may be
    /// counted by a legal decision.
    Absent,
    /// The pseudonym is in no participation set taken so far, and some
    /// station's set is still missing.
    Undetermined,
    /// The same message (pseudonym and envelope label) as the check-in of
    /// the frame given, an earlier frame or the same: a copy, signed again
    /// or supplied twice, that counts once with it.
    Copy(Seq),
    /// Its pseudonym is in another check-in with another envelope label:
    /// the voter voted twice under protest. Every envelope of the pseudonym
    /// is excluded and the fact passed to investigators (ADR-0033 decision
    /// 6). Takes precedence over the participation lookup.
    Repeated,
    /// Its envelope label is in another check-in with another pseudonym:
    /// one envelope cannot be two voters'. Every check-in with the label is
    /// excluded.
    LabelReused,
}

/// One supplied contested check-in and what the stage found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ContestedReport<'a> {
    /// The frame that names it, if any.
    pub seq: Option<Seq>,
    /// Its station, if it decodes.
    pub station: Option<StationId<'a>>,
    /// The finding.
    pub finding: ContestedFinding<'a>,
}

/// What a verifier with access brings to the roll stage.
#[derive(Clone, Copy, Default)]
pub struct RollInput<'i> {
    /// Restricted `ContestedCheckin` objects (schema `0x0056`), in any
    /// order; empty for the public verifier.
    pub contested: &'i [&'i [u8]],
}

/// Shows the number of restricted bodies only.
impl core::fmt::Debug for RollInput<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RollInput")
            .field("contested", &self.contested.len())
            .finish()
    }
}

/// The roll stage of a ledger.
#[derive(Debug, Clone)]
pub struct RollStage<'a> {
    extracts: Vec<TakenExtract<'a>>,
    freeze: Option<Custody<'a>>,
    amendments: Vec<TakenAmendment<'a>>,
    refused: Vec<RollRefused>,
    mismatches: Vec<CustodyMismatch<'a>>,
    contested_frames: usize,
    contested: Vec<ContestedReport<'a>>,
    close: Option<Seq>,
    late: Vec<Seq>,
    missing: Vec<StationId<'a>>,
    holds: HoldSet,
}

impl<'a> RollStage<'a> {
    /// The frame at which voting had closed, as the ledger shows it: the
    /// first accepted participation set of an election-day station of the
    /// genesis's last state. `None` while there is none.
    #[must_use]
    pub const fn poll_close(&self) -> Option<Seq> {
        self.close
    }

    /// The frames of the amendments recorded after the poll close: taken
    /// into the chain, holding the ledger (`RollIncomplete`), and left out
    /// of [`RollStage::roll`].
    #[must_use]
    pub fn late_amendments(&self) -> &[Seq] {
        &self.late
    }

    /// The election-day stations of the genesis's last state without a
    /// resident extract (stations added after the freeze), in station
    /// order: each holds the ledger (`RollIncomplete`).
    #[must_use]
    pub fn missing_extracts(&self) -> &[StationId<'a>] {
        &self.missing
    }

    /// The source extracts taken, in frame order.
    #[must_use]
    pub fn extracts(&self) -> &[TakenExtract<'a>] {
        &self.extracts
    }

    /// The freeze taken, with its custody.
    #[must_use]
    pub const fn freeze(&self) -> Option<&Custody<'a>> {
        self.freeze.as_ref()
    }

    /// The amendments taken, in number order.
    #[must_use]
    pub fn amendments(&self) -> &[TakenAmendment<'a>] {
        &self.amendments
    }

    /// The number of amendments taken for `reason` (ADR-0033 decision 5:
    /// the changes per reason are public).
    #[must_use]
    pub fn amendments_for(&self, reason: RollAmendmentReason) -> usize {
        self.amendments
            .iter()
            .filter(|a| a.reason == reason)
            .count()
    }

    /// The roll in force when voting closed, which the individual check
    /// (VC-110) compares with: the last amendment recorded before the poll
    /// close ([`RollStage::poll_close`]; all of them while it is not known)
    /// or the freeze, when the freeze and every such amendment took
    /// effect; else `None`. An amendment after the close does not change
    /// it, and a missing extract does not withdraw it: both hold
    /// (`RollIncomplete`) and keep the stage from [`RollStage::complete`].
    #[must_use]
    pub fn roll(&self) -> Option<&RollState> {
        let in_time: Vec<&TakenAmendment<'a>> = self
            .amendments
            .iter()
            .filter(|a| self.close.is_none_or(|c| a.custody.seq.get() < c.get()))
            .collect();
        let freeze = self.freeze.as_ref().filter(|f| f.effective)?;
        if !in_time.iter().all(|a| a.custody.effective) {
            return None;
        }
        Some(in_time.last().map_or(&freeze.state, |a| &a.custody.state))
    }

    /// The events not taken, in frame order.
    #[must_use]
    pub fn refused(&self) -> &[RollRefused] {
        &self.refused
    }

    /// The receipts that disagree with their subject, in frame order.
    #[must_use]
    pub fn mismatches(&self) -> &[CustodyMismatch<'a>] {
        &self.mismatches
    }

    /// The number of contested check-in frames on the ledger, whose
    /// bodies are restricted.
    #[must_use]
    pub const fn contested_frames(&self) -> usize {
        self.contested_frames
    }

    /// The supplied contested check-ins, in the order given.
    #[must_use]
    pub fn contested(&self) -> &[ContestedReport<'a>] {
        &self.contested
    }

    /// The number of contested check-ins per station among those supplied
    /// (VC-112, for a verifier with access): the messages that verify, a
    /// copy counted once, in station order. The public verifier has
    /// [`RollStage::contested_frames`] only.
    #[must_use]
    pub fn contested_counts(&self) -> Vec<(StationId<'a>, usize)> {
        let mut counts: BTreeMap<&'a [u8], (StationId<'a>, usize)> = BTreeMap::new();
        for c in &self.contested {
            let counted = !matches!(
                c.finding,
                ContestedFinding::NotOnLedger
                    | ContestedFinding::Invalid
                    | ContestedFinding::Copy(_)
            );
            if let (true, Some(station)) = (counted, c.station) {
                let entry = counts.entry(station.as_bytes()).or_insert((station, 0));
                entry.1 = entry.1.saturating_add(1);
            }
        }
        counts.into_values().collect()
    }

    /// Whether the freeze and every amendment took effect and every
    /// election-day station of the genesis's last state has its resident
    /// extract.
    #[must_use]
    pub fn complete(&self) -> bool {
        self.freeze.as_ref().is_some_and(|f| f.effective)
            && self.amendments.iter().all(|a| a.custody.effective)
            && self.missing.is_empty()
    }

    /// The hold reasons the stage puts on the whole ledger.
    #[must_use]
    pub const fn holds(&self) -> HoldSet {
        self.holds
    }
}

/// The key that signs in `role` as `signer` for a roll event: the genesis
/// body's for the commission and the committee, the named roll
/// authority's for a source or a custodian.
fn signer_key<'g>(
    genesis: &'g VerifiedGenesis<'_>,
    role: EventRole,
    signer: &[u8],
) -> Option<&'g [u8; HYBRID_VK_LEN]> {
    match role {
        EventRole::Commission => Some(genesis.genesis().commission_key()),
        EventRole::Committee => Some(genesis.genesis().committee_key()),
        EventRole::RollSource | EventRole::RollCustodian => {
            genesis.roll_authority(signer).map(|a| a.key)
        }
        EventRole::Clerk
        | EventRole::Observer
        | EventRole::Sender
        | EventRole::Receiver
        | EventRole::Authority
        | EventRole::Device
        | EventRole::Chair
        | EventRole::Auditor => None,
    }
}

/// Verifies every signature of `event` under the key its signer's role
/// gives, and runs `check` on the tokens; `ityv-state`'s `NotRegistered`
/// is an authority refusal, its other errors a signature refusal.
fn signed_by<F>(
    genesis: &VerifiedGenesis<'_>,
    event: &WitnessedEvent<'_>,
    check: F,
) -> Result<(), RollRefusal>
where
    F: FnOnce(&Signed<'_>) -> Result<(), StateError>,
{
    let purpose = Purpose::new(event.purpose()).ok_or(RollRefusal::Signature)?;
    let pairs: Option<Vec<_>> = event
        .sigs()
        .map(|s| signer_key(genesis, s.role, s.signer_id.as_bytes()).map(|k| (s.sig, k)))
        .collect();
    let pairs = pairs.ok_or(RollRefusal::Authority)?;
    let material = Material::new(pairs.into_iter()).ok_or(RollRefusal::Signature)?;
    let tokens = material
        .verify(&purpose, event.body_bytes())
        .ok_or(RollRefusal::Signature)?;
    check(&Signed {
        event,
        tokens: &tokens,
    })
    .map_err(|e| {
        if e == StateError::NotRegistered {
            RollRefusal::Authority
        } else {
            RollRefusal::Signature
        }
    })
}

/// What an extract stands for: a resident extract its precinct, any other
/// its kind and source. The genesis has exactly one snapshot source, so
/// this is one snapshot per election.
fn extract_subject<'a>(e: &TakenExtract<'a>) -> (u8, &'a [u8]) {
    match e.precinct {
        Some(p) => (e.kind.code(), p.as_bytes()),
        None => (e.kind.code(), e.authority.as_bytes()),
    }
}

/// The same body again (`Repeated`) or another body (`Conflict`) for a
/// subject taken with body hash `taken`.
fn again(taken: &Hash512, body: &[u8]) -> RollRefusal {
    if object_hash(body) == *taken {
        RollRefusal::Repeated
    } else {
        RollRefusal::Conflict
    }
}

/// A roll state before any receipt.
fn custody<'a>(seq: Seq, body: &[u8], state: RollState, sources: Option<Hash512>) -> Custody<'a> {
    Custody {
        seq,
        hash: object_hash(body),
        state,
        sources_root: sources,
        custodians: Vec::new(),
        pseudonym_confirmed: false,
        effective: false,
    }
}

/// The stage while it runs.
struct Work<'g, 'a> {
    genesis: &'g VerifiedGenesis<'a>,
    index: &'g LedgerIndex<'a>,
    stage: RollStage<'a>,
    /// The receipt body taken per (subject, custodian).
    receipts: BTreeMap<([u8; 64], &'a [u8]), Hash512>,
    /// The kinds of the agreeing custodians per subject.
    agreeing: BTreeMap<[u8; 64], Vec<RollAuthorityKind>>,
}

impl<'a> Work<'_, 'a> {
    fn take_extract(
        &mut self,
        seq: Seq,
        event: &WitnessedEvent<'a>,
        body: &RollSourceExtractBody<'a>,
    ) -> Result<(), RollRefusal> {
        let p = body.parts();
        let source = self
            .genesis
            .roll_authority_entry(p.authority_id.as_bytes())
            .ok_or(RollRefusal::Authority)?;
        signed_by(self.genesis, event, |s| admit_extract(s, &source))?;
        if self.stage.freeze.is_some() {
            return Err(RollRefusal::AfterFreeze);
        }
        if let Some(precinct) = p.precinct {
            let election_day = self
                .genesis
                .station_at(self.index.state_at(seq), precinct.as_bytes())
                .is_some_and(|s| s.kind() == StationKind::ElectionDay);
            if !election_day {
                return Err(RollRefusal::Precinct);
            }
        }
        let taken = TakenExtract {
            seq,
            hash: object_hash(event.body_bytes()),
            kind: p.kind,
            authority: p.authority_id,
            precinct: p.precinct,
            entries: p.entry_count,
        };
        let subject = extract_subject(&taken);
        if let Some(first) = self
            .stage
            .extracts
            .iter()
            .find(|e| extract_subject(e) == subject)
        {
            return Err(again(&first.hash, event.body_bytes()));
        }
        self.stage.extracts.push(taken);
        Ok(())
    }

    fn take_freeze(
        &mut self,
        seq: Seq,
        event: &WitnessedEvent<'a>,
        body: &RollFreezeBody<'a>,
    ) -> Result<(), RollRefusal> {
        let g = self.genesis.genesis();
        signed_by(self.genesis, event, |s| {
            admit_freeze(s, g.commission_key(), g.committee_key())
        })?;
        if let Some(taken) = &self.stage.freeze {
            return Err(again(&taken.hash, event.body_bytes()));
        }
        let p = body.parts();
        let precincts: BTreeSet<&[u8]> = self
            .stage
            .extracts
            .iter()
            .filter_map(|e| e.precinct.map(|s| s.as_bytes()))
            .collect();
        let every_precinct = self
            .genesis
            .stations_at(self.index.state_at(seq))
            .filter(|s| s.kind() == StationKind::ElectionDay)
            .all(|s| precincts.contains(s.station_id().as_bytes()));
        let snapshot = self
            .stage
            .extracts
            .iter()
            .any(|e| e.kind == RollSourceKind::Snapshot);
        if !every_precinct || !snapshot {
            return Err(RollRefusal::Incomplete);
        }
        let mut hashes: Vec<Hash512> = self.stage.extracts.iter().map(|e| e.hash).collect();
        hashes.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        let count_ok = u32::try_from(hashes.len()).ok() == Some(p.source_count);
        if !count_ok || sorted_set_root(&hashes).ok() != Some(p.sources_root) {
            return Err(RollRefusal::Sources);
        }
        if !merge_allows(&self.stage.extracts, p.state.entry_count) {
            return Err(RollRefusal::Count);
        }
        self.stage.freeze = Some(custody(
            seq,
            event.body_bytes(),
            p.state,
            Some(p.sources_root),
        ));
        Ok(())
    }

    fn take_amendment(
        &mut self,
        seq: Seq,
        event: &WitnessedEvent<'a>,
        body: &RollAmendmentBody<'a>,
    ) -> Result<(), RollRefusal> {
        let p = body.parts();
        let source = self
            .genesis
            .roll_authority_entry(p.authority_id.as_bytes())
            .ok_or(RollRefusal::Authority)?;
        let g = self.genesis.genesis();
        signed_by(self.genesis, event, |s| {
            admit_amendment(s, g.commission_key(), g.committee_key(), &source)
        })?;
        let freeze = self.stage.freeze.as_ref().ok_or(RollRefusal::Chain)?;
        let taken = usize::try_from(p.seq)
            .ok()
            .and_then(|n| n.checked_sub(1))
            .and_then(|i| self.stage.amendments.get(i));
        if let Some(taken) = taken {
            return Err(again(&taken.custody.hash, event.body_bytes()));
        }
        let previous = self
            .stage
            .amendments
            .last()
            .map_or(freeze.hash, |a| a.custody.hash);
        let next = u64::try_from(self.stage.amendments.len())
            .ok()
            .and_then(|n| n.checked_add(1));
        if next != Some(p.seq) || p.previous_hash != previous {
            return Err(RollRefusal::Chain);
        }
        self.stage.amendments.push(TakenAmendment {
            number: p.seq,
            reason: p.reason,
            authority: p.authority_id,
            basis_hash: p.basis_hash,
            custody: custody(seq, event.body_bytes(), p.state, None),
        });
        Ok(())
    }

    /// The roll state with body hash `hash` taken before frame `seq`. (A
    /// receipt and the state it answers are two events and never share a
    /// frame, so `<` and `<=` agree here.)
    fn subject(&mut self, hash: &Hash512, seq: Seq) -> Option<&mut Custody<'a>> {
        let freeze = self.stage.freeze.iter_mut();
        let amendments = self.stage.amendments.iter_mut().map(|a| &mut a.custody);
        freeze
            .chain(amendments)
            .find(|c| c.hash == *hash && c.seq.get() < seq.get())
    }

    fn take_receipt(
        &mut self,
        seq: Seq,
        event: &WitnessedEvent<'a>,
        body: &RollCustodyReceiptBody<'a>,
    ) -> Result<(), RollRefusal> {
        let p = *body.parts();
        let custodian = self
            .genesis
            .roll_authority_entry(p.custodian.as_bytes())
            .ok_or(RollRefusal::Authority)?;
        let kind = custodian.get().kind;
        signed_by(self.genesis, event, |s| admit_receipt(s, &custodian))?;
        let key = (p.subject_hash.0, p.custodian.as_bytes());
        let taken = self.receipts.get(&key).copied();
        let subject = self
            .subject(&p.subject_hash, seq)
            .ok_or(RollRefusal::Subject)?;
        if p.sources_root.is_some() != subject.sources_root.is_some() {
            return Err(RollRefusal::Subject);
        }
        if let Some(taken) = taken {
            return Err(again(&taken, event.body_bytes()));
        }
        let state = subject.state;
        let agrees = p.entries_root == state.entries_root
            && p.entry_count == state.entry_count
            && p.counts_hash == state.counts_hash
            && p.sources_root == subject.sources_root
            && p.pseudonym_root.is_none_or(|r| r == state.pseudonym_root);
        if agrees {
            subject.custodians.push(p.custodian);
            subject.pseudonym_confirmed |= p.pseudonym_root.is_some();
        }
        self.receipts.insert(key, object_hash(event.body_bytes()));
        if agrees {
            self.agreeing
                .entry(p.subject_hash.0)
                .or_default()
                .push(kind);
        } else {
            self.stage.mismatches.push(CustodyMismatch {
                seq,
                custodian: p.custodian,
                subject: p.subject_hash,
            });
        }
        Ok(())
    }
}

/// A roll event of the index, decoded.
enum Item<'a> {
    Extract(WitnessedEvent<'a>, RollSourceExtractBody<'a>),
    Freeze(WitnessedEvent<'a>, RollFreezeBody<'a>),
    Receipt(WitnessedEvent<'a>, RollCustodyReceiptBody<'a>),
    Amendment(WitnessedEvent<'a>, RollAmendmentBody<'a>),
}

/// The roll events of `index`, in frame order.
fn items<'a>(index: &LedgerIndex<'a>) -> Vec<(Seq, Item<'a>)> {
    index
        .events()
        .iter()
        .filter(|e| e.schema == SCHEMA_WITNESSED_EVENT)
        .filter_map(|e| {
            let w: WitnessedEvent<'a> = decode_object(
                SCHEMA_WITNESSED_EVENT,
                schema_version(SCHEMA_WITNESSED_EVENT),
                e.bytes?,
            )
            .ok()?;
            let s = w.body_schema();
            let item = if s == SCHEMA_ROLL_SOURCE_EXTRACT_BODY {
                Item::Extract(w, w.body(s).ok()?)
            } else if s == SCHEMA_ROLL_FREEZE_BODY {
                Item::Freeze(w, w.body(s).ok()?)
            } else if s == SCHEMA_ROLL_CUSTODY_RECEIPT_BODY {
                Item::Receipt(w, w.body(s).ok()?)
            } else if s == SCHEMA_ROLL_AMENDMENT_BODY {
                Item::Amendment(w, w.body(s).ok()?)
            } else {
                return None;
            };
            Some((e.seq, item))
        })
        .collect()
}

/// Whether `sig` over `message` verifies under `key` for `purpose`.
fn verifies(
    sig: &[u8; ityv_encoding::HYBRID_SIG_LEN],
    key: &[u8; HYBRID_VK_LEN],
    purpose: &Purpose<'_>,
    message: &[u8],
) -> bool {
    Material::new(core::iter::once((sig, key)))
        .is_some_and(|m| m.verify(purpose, message).is_some())
}

/// Whether the module signatures of `checkin` are one per party of the
/// genesis, in chamber order, each from a module of `unit` in state
/// `state` and verifying.
fn modules_signed(
    genesis: &VerifiedGenesis<'_>,
    state: usize,
    unit: &CheckinUnit<'_>,
    checkin: &ContestedCheckin<'_>,
    purpose: &Purpose<'_>,
) -> bool {
    let parties: Vec<_> = genesis
        .genesis()
        .body()
        .parties()
        .map(|p| p.chamber)
        .collect();
    checkin.module_sig_count() == parties.len()
        && checkin.module_sigs().zip(&parties).all(|(sig, party)| {
            unit.modules.contains(sig.module_id)
                && genesis
                    .module_at(state, sig.module_id.as_bytes())
                    .is_some_and(|m| {
                        m.chamber == *party
                            && verifies(sig.sig, m.key, purpose, checkin.message_bytes())
                    })
        })
}

/// Whether `checkin`, on the ledger at frame `seq`, verifies: this
/// election, its station in the state at `seq`, signed by the unit it
/// names (in service or spare at that station, in a state up to `seq`)
/// and that unit's party modules.
fn contested_valid(
    genesis: &VerifiedGenesis<'_>,
    index: &LedgerIndex<'_>,
    seq: Seq,
    checkin: &ContestedCheckin<'_>,
) -> bool {
    let m = checkin.message();
    let last = index.state_at(seq);
    let Some(purpose) = Purpose::new(PURPOSE_CONTESTED_CHECKIN) else {
        return false;
    };
    m.election_id.as_bytes() == genesis.election_id().as_bytes()
        && genesis.station_at(last, m.station_id.as_bytes()).is_some()
        && (0..=last).any(|state| {
            genesis
                .station_at(state, m.station_id.as_bytes())
                .into_iter()
                .flat_map(|s| [s.primary(), s.spare()])
                .filter(|u| u.unit_id.as_bytes() == m.unit_id.as_bytes())
                .any(|u| {
                    verifies(checkin.unit_sig(), u.key, &purpose, checkin.message_bytes())
                        && modules_signed(genesis, state, u, checkin, &purpose)
                })
        })
}

/// Whether the merge of `extracts` can give a roll of `entries`: at most
/// the resident extracts' sum plus the overseas lists' entries (which may
/// add), at least that sum less every removal list's entries (deaths,
/// disqualifications, overseas and loss of nationality). The snapshot is
/// the Ministry's national cross-check, not a count of the roll.
fn merge_allows(extracts: &[TakenExtract<'_>], entries: u64) -> bool {
    let sum = |kinds: &[RollSourceKind]| {
        extracts
            .iter()
            .filter(|e| kinds.contains(&e.kind))
            .fold(0u64, |total, e| total.saturating_add(e.entries))
    };
    let residents = sum(&[RollSourceKind::Residents]);
    let removals = sum(&[
        RollSourceKind::Deaths,
        RollSourceKind::Disqualifications,
        RollSourceKind::Overseas,
    ]);
    let additions = sum(&[RollSourceKind::Overseas]);
    residents.saturating_sub(removals) <= entries && entries <= residents.saturating_add(additions)
}

/// The message of a verified check-in: its pseudonym and envelope label.
type MessageKey<'a> = (&'a [u8; PSEUDONYM_LEN], [u8; 24]);

/// What the stage finds of one supplied body, and its message if it
/// verifies.
fn contested_report<'a>(
    genesis: &VerifiedGenesis<'a>,
    index: &LedgerIndex<'a>,
    participation: &ParticipationStage<'a>,
    frames: &BTreeMap<[u8; 64], Seq>,
    bytes: &'a [u8],
) -> (ContestedReport<'a>, Option<MessageKey<'a>>) {
    let Some(seq) = frames.get(&object_hash(bytes).0).copied() else {
        return (
            ContestedReport {
                seq: None,
                station: None,
                finding: ContestedFinding::NotOnLedger,
            },
            None,
        );
    };
    let decoded: Option<ContestedCheckin<'a>> = decode_object(
        SCHEMA_CONTESTED_CHECKIN,
        schema_version(SCHEMA_CONTESTED_CHECKIN),
        bytes,
    )
    .ok();
    let station = decoded.map(|c| c.message().station_id);
    let Some(checkin) = decoded.filter(|c| contested_valid(genesis, index, seq, c)) else {
        return (
            ContestedReport {
                seq: Some(seq),
                station,
                finding: ContestedFinding::Invalid,
            },
            None,
        );
    };
    let all_sets = participation.stations().iter().all(|s| s.set.is_some());
    let m = checkin.message();
    let finding = match participation.pseudonym_station(m.pseudonym) {
        Some(found) => ContestedFinding::Elsewhere(found),
        None if all_sets => ContestedFinding::Absent,
        None => ContestedFinding::Undetermined,
    };
    (
        ContestedReport {
            seq: Some(seq),
            station,
            finding,
        },
        Some((m.pseudonym, m.envelope_label.0)),
    )
}

/// Applies the repetition rules to the reports of the supplied check-ins
/// (module documentation): a message seen in an earlier frame (or earlier
/// in the same frame) is a copy of the first; among the first of each
/// message, a pseudonym under two labels is repeated, else a label under
/// two pseudonyms is reused.
fn settle_contested<'a>(reports: &mut [(ContestedReport<'a>, Option<MessageKey<'a>>)]) {
    let mut order: Vec<usize> = (0..reports.len())
        .filter(|&i| reports.get(i).is_some_and(|r| r.1.is_some()))
        .collect();
    order.sort_by_key(|&i| reports.get(i).and_then(|r| r.0.seq).map(Seq::get));
    let mut first: BTreeMap<MessageKey<'a>, Seq> = BTreeMap::new();
    let mut labels: BTreeMap<&'a [u8; PSEUDONYM_LEN], BTreeSet<[u8; 24]>> = BTreeMap::new();
    let mut pseudonyms: BTreeMap<[u8; 24], BTreeSet<&'a [u8; PSEUDONYM_LEN]>> = BTreeMap::new();
    for &i in &order {
        let Some((report, Some(key))) = reports.get_mut(i) else {
            continue;
        };
        let Some(seq) = report.seq else { continue };
        if let Some(&earlier) = first.get(key) {
            report.finding = ContestedFinding::Copy(earlier);
            continue;
        }
        first.insert(*key, seq);
        labels.entry(key.0).or_default().insert(key.1);
        pseudonyms.entry(key.1).or_default().insert(key.0);
    }
    for (report, key) in reports.iter_mut() {
        let Some((pseudonym, label)) = key else {
            continue;
        };
        if matches!(report.finding, ContestedFinding::Copy(_)) {
            continue;
        }
        if labels.get(*pseudonym).is_some_and(|l| l.len() > 1) {
            report.finding = ContestedFinding::Repeated;
        } else if pseudonyms.get(label).is_some_and(|p| p.len() > 1) {
            report.finding = ContestedFinding::LabelReused;
        }
    }
}

/// Settles `stage` against the genesis's last state: every election-day
/// station needs its resident extract once there is a freeze (a station
/// added after the freeze has none), and the first participation set of
/// such a station marks the poll close, after which an amendment is late.
fn settle_close<'a>(
    genesis: &VerifiedGenesis<'a>,
    participation: &ParticipationStage<'a>,
    stage: &mut RollStage<'a>,
) {
    let last = genesis.state_count().saturating_sub(1);
    let election_day: Vec<StationId<'a>> = genesis
        .stations_at(last)
        .filter(|s| s.kind() == StationKind::ElectionDay)
        .map(StationEntry::station_id)
        .collect();
    if stage.freeze.is_some() {
        stage.missing = election_day
            .iter()
            .filter(|station| {
                !stage.extracts.iter().any(|e| {
                    e.kind == RollSourceKind::Residents
                        && e.precinct
                            .is_some_and(|p| p.as_bytes() == station.as_bytes())
                })
            })
            .copied()
            .collect();
    }
    stage.close = participation
        .stations()
        .iter()
        .filter(|s| {
            election_day
                .iter()
                .any(|d| d.as_bytes() == s.station_id.as_bytes())
        })
        .filter_map(|s| s.set)
        .min_by_key(|seq| seq.get());
    stage.late = stage
        .amendments
        .iter()
        .map(|a| a.custody.seq)
        .filter(|seq| stage.close.is_some_and(|c| seq.get() > c.get()))
        .collect();
}

/// Verifies the roll of `index` against `genesis` (module documentation),
/// with the participation stage's accepted sets for the contested
/// check-ins a verifier with access supplies in `input`.
#[must_use]
pub fn verify_roll<'a>(
    genesis: &VerifiedGenesis<'a>,
    index: &LedgerIndex<'a>,
    participation: &ParticipationStage<'a>,
    input: &RollInput<'a>,
) -> RollStage<'a> {
    let mut work = Work {
        genesis,
        index,
        stage: RollStage {
            extracts: Vec::new(),
            freeze: None,
            amendments: Vec::new(),
            refused: Vec::new(),
            mismatches: Vec::new(),
            contested_frames: 0,
            contested: Vec::new(),
            close: None,
            late: Vec::new(),
            missing: Vec::new(),
            holds: HoldSet::empty(),
        },
        receipts: BTreeMap::new(),
        agreeing: BTreeMap::new(),
    };
    for (seq, item) in items(index) {
        let (event, taken) = match &item {
            Item::Extract(w, b) => (RollEvent::Extract, work.take_extract(seq, w, b)),
            Item::Freeze(w, b) => (RollEvent::Freeze, work.take_freeze(seq, w, b)),
            Item::Receipt(w, b) => (RollEvent::Receipt, work.take_receipt(seq, w, b)),
            Item::Amendment(w, b) => (RollEvent::Amendment, work.take_amendment(seq, w, b)),
        };
        if let Err(refusal) = taken {
            work.stage.refused.push(RollRefused {
                seq,
                event,
                refusal,
            });
        }
    }
    let quorum = genesis.genesis().body().custody_quorum();
    let agreeing = &work.agreeing;
    let settle = |c: &mut Custody<'a>| {
        let kinds = agreeing.get(&c.hash.0).map_or(&[][..], Vec::as_slice);
        c.effective = custody_quorum(kinds, quorum) && c.pseudonym_confirmed;
    };
    let stage = &mut work.stage;
    if let Some(f) = stage.freeze.as_mut() {
        settle(f);
    }
    for a in &mut stage.amendments {
        settle(&mut a.custody);
    }
    settle_close(genesis, participation, stage);

    let frames: BTreeMap<[u8; 64], Seq> = index
        .events()
        .iter()
        .filter(|e| e.schema == SCHEMA_CONTESTED_CHECKIN)
        .map(|e| (e.hash.0, e.seq))
        .collect();
    stage.contested_frames = frames.len();
    let mut reports: Vec<(ContestedReport<'a>, Option<MessageKey<'a>>)> = input
        .contested
        .iter()
        .map(|bytes| contested_report(genesis, index, participation, &frames, bytes))
        .collect();
    settle_contested(&mut reports);
    stage.contested = reports.into_iter().map(|(r, _)| r).collect();
    stage.holds = HoldSet::empty()
        .with_if(!stage.refused.is_empty(), HoldReason::RollEventRefused)
        .with_if(
            !stage.mismatches.is_empty(),
            HoldReason::RollCustodyMismatch,
        )
        .with_if(
            stage
                .contested
                .iter()
                .any(|c| c.finding == ContestedFinding::Invalid),
            HoldReason::ContestedCheckinInvalid,
        )
        .with_if(
            stage.contested.iter().any(|c| {
                matches!(
                    c.finding,
                    ContestedFinding::Repeated | ContestedFinding::LabelReused
                )
            }),
            HoldReason::ContestedRepeated,
        )
        .with_if(
            !stage.late.is_empty() || !stage.missing.is_empty(),
            HoldReason::RollIncomplete,
        );
    work.stage
}
