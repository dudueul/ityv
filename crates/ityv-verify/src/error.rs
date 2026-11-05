//! Refusals of the genesis stage.
//!
//! A genesis is all or nothing: one broken rule in the body, a signature,
//! any entry of any set, or any amendment means there is no verified
//! genesis, and nothing later in the verifier runs (PROTOCOL.md §14 1).
//! The error names the first rule found broken and where.

use ityv_encoding::EntrySet;

/// A reference from one entry to an entry of another set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Reference {
    /// A station (`StationEntry`).
    Station,
    /// A custody route (`CustodyRoute`).
    Route,
    /// A ballot style (`BallotStyleEntry`).
    BallotStyle,
    /// A reporting unit (`ReportingUnitEntry`).
    ReportingUnit,
    /// A chamber module (`ModuleEntry`).
    Module,
    /// An expected box (`GenesisBox`).
    Box,
    /// A roster signer (`RosterSigner`) in the role the reference needs.
    Signer,
}

/// The rule a genesis or amendment broke (VC-005, VC-009, VC-014,
/// VC-067, VC-104, VC-105, VC-114).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Rule {
    /// An object is not the canonical encoding of its schema.
    Decode,
    /// A genesis was expected and an amendment given, or the reverse.
    Kind,
    /// The body's object hash is not the pin (VC-005).
    Pin,
    /// A key is not a valid key, or a signature does not verify under the
    /// key the genesis registers for its signer (VC-002, VC-004).
    Signature,
    /// A witness signed who is not in the witness set.
    WitnessUnknown,
    /// The signatures fall short of the quorum, the diversity, or share a
    /// key half (`ityv-state` refused the seal; VC-014, VC-098).
    Seal(ityv_state::Error),
    /// An amendment is not the next one of this election, or does not
    /// chain to the previous body (VC-105).
    Chain(ityv_state::Error),
    /// A set is not strictly ascending by key.
    NotSorted,
    /// A key appears twice in one set.
    Duplicate,
    /// The number of entries differs from the body's count.
    Count,
    /// The recomputed root differs from the body's root.
    Root,
    /// An entry names an entry another set does not have.
    Missing(Reference),
    /// A station's box list differs from the boxes that name the station.
    StationBoxes,
    /// A station has no progress policy, or a policy names no station.
    StationPolicy,
    /// A reporting unit's box count differs from the boxes that name it.
    UnitBoxCount,
    /// An appointment hash is not in the appointment set (VC-009).
    Appointment,
    /// Two roster, trustee or witness entries name one appointment: an
    /// appointment event appoints one person (PROTOCOL.md §4.5).
    AppointmentReused,
    /// A device's modules are not one module of each party chamber (with,
    /// for a box, at most one each of `J`, `A`, `C` and none of `N`), or
    /// a module belongs to a chamber the genesis has no place for
    /// (VC-067, VC-017).
    Chambers,
    /// A module is listed by two devices (boxes or check-in units): a
    /// module is provisioned for the one device it plugs into.
    SharedModule,
    /// A chamber's trustees are not exactly its `n_c` members (VC-067).
    Trustees,
    /// A chamber has more members than threshold sharing can serve
    /// (`n_c` ≤ 8, `ityv_crypto::MAX_MEMBERS`): no quorum of it could ever
    /// be checked, so every tally event would be refused.
    ChamberSize,
    /// An observer token names someone who is not an observer of the
    /// token's organisation at the token's station on the roster, or its
    /// check key is another token's.
    ObserverToken,
    /// A registered key is not a valid key (its Ed25519 half does not
    /// decode or is a weak key): nothing could ever verify under it.
    InvalidKey,
    /// Two keys in one genesis state share a half.
    SharedKey,
    /// Two devices of one genesis state share an identifier: a check-in
    /// unit and another unit, a box or a module, or a box and a module.
    /// A device attestation names its device by this identifier alone.
    DeviceId,
    /// A timestamp authority's pin is not a valid `ityv-tsa` pin, or does
    /// not allow SHA-512, the digest every imprint uses (ADR-0034 §3): no
    /// token of it could ever verify.
    TimestampPin,
    /// Two pins of the timestamp authority set name one signing
    /// certificate: one authority would count as two.
    TimestampCertificate,
    /// Two timestamp authorities of one operator differ in kind: an
    /// operator is either the government or not (VC-114).
    TimestampOperator,
    /// The timestamp authority set lacks a government-run or a
    /// non-government authority (VC-114).
    TimestampAuthorities,
}

/// Where in the genesis a rule was broken.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Error {
    /// The genesis state: 0 for the genesis, `k` for the state after
    /// amendment `k`.
    pub state: u64,
    /// The set, if the rule concerns an entry or a set.
    pub set: Option<EntrySet>,
    /// The entry's position in its set, if the rule concerns one entry.
    pub index: Option<u64>,
    /// The rule.
    pub rule: Rule,
}

impl Error {
    /// A rule broken by the body, its signatures or the chain.
    pub(crate) const fn body(state: u64, rule: Rule) -> Self {
        Self {
            state,
            set: None,
            index: None,
            rule,
        }
    }

    /// A rule broken by a whole set.
    pub(crate) const fn set(state: u64, set: EntrySet, rule: Rule) -> Self {
        Self {
            state,
            set: Some(set),
            index: None,
            rule,
        }
    }

    /// A rule broken by one entry.
    pub(crate) fn entry(state: u64, set: EntrySet, index: usize, rule: Rule) -> Self {
        Self {
            state,
            set: Some(set),
            // A set never holds more than `u64::MAX` entries; saturating
            // only affects the reported position, never a decision.
            index: Some(u64::try_from(index).unwrap_or(u64::MAX)),
            rule,
        }
    }
}
