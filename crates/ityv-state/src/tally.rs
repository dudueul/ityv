//! Gates and checks of the cryptographic tally (PROTOCOL.md §11.1, §11.2,
//! §11.5; ADR-0035).
//!
//! Both gates require the `CRYPTO_TALLY_AID` capability (VC-007) of the
//! same election. A tally scope is recorded only after every box of the
//! ballot style is closed, after the receipt resolution when there are
//! out-of-district records, after a legal decision with a tally effect for
//! every damaged or wrong-district record (VC-099), and after the
//! late-close window counted from the last close of the ballot style, so
//! that `UNATTESTED` is final (VC-057). An aggregate opening is recorded
//! only after its tally scope is in a witness checkpoint recorded before
//! the opening (VC-063, [`checkpointed_before`]).
//!
//! Both events are signed by a quorum of trustees ([`check_quorum`]): every
//! signer is a trustee of the genesis, every signature is bound to a token
//! from that trustee's key, no two signers share a key half, and the
//! signers form a qualified set of the chamber access structure Γ
//! (PROTOCOL.md §9.2, [`access_structure`]): at least `k_c` members of
//! every party chamber `P1`…`Pn` and of at least three of `J`, `A`, `C`,
//! `N`. A set outside Γ learns nothing from the shares (VC-031), so it
//! cannot have made an opening; and the scope is what that same body
//! certifies before it opens anything.
//!
//! The paper count of a reporting unit ([`PaperCount`]) is signed by the
//! chair of the district commission and observers of two or more
//! organisations, each bound to the roster. [`compare_paper`] is the check
//! of PROTOCOL.md §11.5 (VC-075): for every candidate the paper has at
//! least the machine's confirmed votes, and the totals agree once blank,
//! unreadable, emergency-slot and excluded-but-present ballots are counted.
//! A violation holds the unit; it is not evidence of fraud by itself (the
//! person may judge stricter than the machine, §12.3).

use ityv_crypto::hash::object_hash;
use ityv_crypto::{
    AccessStructure, CHAMBER_COUNT, HybridSigned, Threshold, Verified, is_qualified,
};
use ityv_encoding::{
    ChamberThreshold, ElectionId, EventRole, MAX_QUORUM_MESSAGE_LEN, MAX_QUORUM_SIGS,
    PaperCountParts, PaperCountReportBody, QuorumSigned, ReportingUnitEntry, RosterRole,
    SCHEMA_PAPER_COUNT_REPORT_BODY, TimeBucket, TrusteeEntry, Writer, expected_chamber,
};

use crate::auth::{Cap, CryptoTallyAid};
use crate::close::{RosterEntry, roster_key};
use crate::error::Error;
use crate::genesis::{Entry, one_head};
use crate::sig::{Signed, check_event, check_pairs};

/// Buckets after the last box close during which a late batch close may
/// still attest records (24 hours, PROTOCOL.md §7.2.1).
pub const LATE_CLOSE_WINDOW: u64 = 96;

/// What a tally scope waits for. The verifier computes each field from
/// the stages it verified (ADR-0035).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TallyReadiness {
    /// Every box of the ballot style has a `BoxClose` or `BoxCloseManual`.
    pub boxes_closed: bool,
    /// The receipt resolution is recorded, or there are no out-of-district
    /// records.
    pub receipts_resolved: bool,
    /// Every record awaiting the law (`RECEIVED_DAMAGED`,
    /// `WRONG_DISTRICT`) has a legal decision with a tally effect, or there
    /// is none ([`crate::record::Disposition::PendingLegal`]).
    pub legal_resolved: bool,
    /// The bucket of the last box close of the ballot style.
    pub last_close: TimeBucket,
    /// The current bucket.
    pub now: TimeBucket,
}

/// Admits a `TallyScope` event.
///
/// # Errors
/// [`Error::Mismatch`] if the capability belongs to another election,
/// [`Error::TallyPremature`] if a box is open, the receipts are
/// unresolved, a record still waits for the law, or the late-close window
/// has not passed; [`Error::Overflow`].
pub fn admit_tally_scope(
    cap: &Cap<'_, CryptoTallyAid>,
    election_id: ElectionId<'_>,
    readiness: &TallyReadiness,
) -> Result<(), Error> {
    cap.check_election(election_id)?;
    let deadline = readiness
        .last_close
        .get()
        .checked_add(LATE_CLOSE_WINDOW)
        .ok_or(Error::Overflow)?;
    if readiness.boxes_closed
        && readiness.receipts_resolved
        && readiness.legal_resolved
        && readiness.now.get() > deadline
    {
        Ok(())
    } else {
        Err(Error::TallyPremature)
    }
}

/// Admits an `AggregateOpening` event.
///
/// # Errors
/// [`Error::Mismatch`] if the capability belongs to another election,
/// [`Error::TallyPremature`] if the tally scope is not yet in a witness
/// checkpoint (VC-063).
pub fn admit_aggregate_opening(
    cap: &Cap<'_, CryptoTallyAid>,
    election_id: ElectionId<'_>,
    scope_checkpointed: bool,
) -> Result<(), Error> {
    cap.check_election(election_id)?;
    if scope_checkpointed {
        Ok(())
    } else {
        Err(Error::TallyPremature)
    }
}

/// Whether some witness checkpoint recorded before frame `opening` covers
/// frame `scope` (VC-063): a checkpoint carried by a frame `c < opening`
/// whose tree size is at least `scope` (frames `1..=tree_size`).
/// `checkpoints` gives each valid checkpoint as (its frame, its tree size).
/// Frames count from 1: frame 0 is no frame, and nothing covers it.
#[must_use]
pub fn checkpointed_before<I>(checkpoints: I, scope: u64, opening: u64) -> bool
where
    I: IntoIterator<Item = (u64, u64)>,
{
    scope != 0
        && checkpoints
            .into_iter()
            .any(|(frame, tree_size)| frame < opening && tree_size >= scope)
}

/// The chamber access structure Γ of a genesis (PROTOCOL.md §9.2;
/// ADR-0019) with `parties` party chambers and the chamber thresholds
/// `chambers` (the genesis body's party count and `chambers`): every
/// chamber's `k_c`-of-`n_c` threshold. The thresholds must name exactly
/// `P1`…`Pn`, `J`, `A`, `C`, `N`, once each and in that order
/// ([`ityv_encoding::expected_chamber`]); a chamber missing, repeated or
/// out of order gives `None` rather than a default. `None` also if a
/// threshold is not one `ityv-crypto` can share (more than eight members)
/// or the party count is out of range. The party chambers the genesis
/// does not have stay unused placeholders (`1`-of-`1`).
#[must_use]
pub fn access_structure<I>(parties: usize, chambers: I) -> Option<AccessStructure>
where
    I: IntoIterator<Item = ChamberThreshold>,
{
    let count = u8::try_from(parties).ok()?;
    let mut inner = [Threshold::new(1, 1)?; CHAMBER_COUNT];
    let mut seen = 0usize;
    for (index, c) in chambers.into_iter().enumerate() {
        if expected_chamber(index, parties) != Some(c.chamber) {
            return None;
        }
        let slot = usize::from(c.chamber.code())
            .checked_sub(1)
            .and_then(|i| inner.get_mut(i))?;
        *slot = Threshold::new(c.threshold, c.members)?;
        seen = index.checked_add(1)?;
    }
    if seen != parties.checked_add(4)? {
        return None;
    }
    AccessStructure::new(count, inner)
}

/// The message every trustee of `event` signs (ENCODING.md §8.63): the
/// object hash of the body and the participating trustees, written into
/// `buf`.
///
/// # Errors
/// [`Error::Decode`] cannot occur for a decoded event (the message always
/// fits); it keeps the function total.
pub fn quorum_message<'b>(
    event: &QuorumSigned<'_>,
    buf: &'b mut [u8; MAX_QUORUM_MESSAGE_LEN],
) -> Result<&'b [u8], Error> {
    let mut w = Writer::new(buf);
    event
        .write_message(&object_hash(event.body_bytes()), &mut w)
        .map_err(|_| Error::Decode)?;
    let len = w.finish();
    buf.get(..len).ok_or(Error::Decode)
}

/// A quorum-signed event and the verification tokens of its signatures,
/// one per signature in the event's (ascending trustee) order, each over
/// the event's quorum message ([`quorum_message`]).
#[derive(Debug, Clone, Copy)]
pub struct QuorumTokens<'s> {
    /// The event.
    pub event: &'s QuorumSigned<'s>,
    /// The tokens, in signature order.
    pub tokens: &'s [Verified<HybridSigned<'s>>],
}

/// Checks the trustee quorum of a tally scope, aggregate opening or receipt
/// resolution: every signer is one of `trustees` (proved against one
/// genesis), every signature has a token from that trustee's key over the
/// quorum message (the body's hash and the participating trustees, so that
/// the list of participants is what each of them signed) under the body's
/// purpose, no two signers' keys share a half, and the signers form a
/// qualified set of `structure` (PROTOCOL.md §9.2, §11.2).
///
/// What it does not prove: that the members did reconstruct anything; the
/// verifier checks an opening against the commitments.
///
/// # Errors
/// [`Error::StaleEntry`] if the trustee entries come from different
/// genesis states, [`Error::NotRegistered`] for a signer who is not a
/// trustee, the errors of [`crate::sig::check_event`] for a token that does
/// not bind, [`Error::SignersShort`] if the signers are not a qualified set.
pub fn check_quorum(
    signed: &QuorumTokens<'_>,
    trustees: &[Entry<TrusteeEntry<'_>>],
    structure: &AccessStructure,
) -> Result<(), Error> {
    one_head(trustees)?;
    let event = signed.event;
    let mut buf = [0u8; MAX_QUORUM_MESSAGE_LEN];
    let message = quorum_message(event, &mut buf)?;
    let trustee = |id: &[u8]| {
        trustees
            .iter()
            .map(Entry::get)
            .find(|t| t.trustee_id.as_bytes() == id)
            .ok_or(Error::NotRegistered)
    };
    let pairs = event
        .sigs()
        .map(|s| trustee(s.trustee_id.as_bytes()).map(|t| (s.sig, t.key)));
    check_pairs::<MAX_QUORUM_SIGS, _>(
        message,
        event.purpose(),
        signed.tokens,
        event.sig_count(),
        pairs,
    )?;
    let mut counts = [0u8; CHAMBER_COUNT];
    for s in event.sigs() {
        let chamber = trustee(s.trustee_id.as_bytes())?.chamber;
        let index = usize::from(chamber.code())
            .checked_sub(1)
            .ok_or(Error::NotRegistered)?;
        let count = counts.get_mut(index).ok_or(Error::NotRegistered)?;
        *count = count.checked_add(1).ok_or(Error::Overflow)?;
    }
    if is_qualified(structure, counts) {
        Ok(())
    } else {
        Err(Error::SignersShort)
    }
}

/// A paper count report whose signatures were bound to the roster: the
/// chair of the district commission that reports the unit, once, and
/// observers of two or more organisations (PROTOCOL.md §11.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PaperCount<'a> {
    parts: PaperCountParts<'a>,
}

impl<'a> PaperCount<'a> {
    /// Checks a signed paper count report of the reporting unit `unit`:
    /// the body schema and unit, and a matching token for each signature
    /// from the key the roster registers for that signer as a chair or an
    /// observer of the organisation the signature names, the chair's being
    /// the unit's commission (`ReportingUnitEntry::commission_org`), so
    /// that a chair of another district cannot report the unit. The
    /// envelope already admits exactly one chair and observers of two or
    /// more organisations and nothing else
    /// (`ityv_encoding::roles_satisfied`).
    ///
    /// # Errors
    /// [`Error::Decode`] if the event is not a paper count report,
    /// [`Error::Mismatch`] if it reports another unit,
    /// [`Error::StaleEntry`] if the unit and the roster come from different
    /// genesis states, [`Error::NotRegistered`] for a signer the roster
    /// does not register in that role and organisation or a chair of
    /// another commission, and the errors of [`crate::sig::check_event`].
    pub fn check(
        signed: &Signed<'a>,
        roster: &[RosterEntry<'_>],
        unit: &Entry<ReportingUnitEntry<'_>>,
    ) -> Result<Self, Error> {
        let body: PaperCountReportBody<'a> = signed
            .event
            .body(SCHEMA_PAPER_COUNT_REPORT_BODY)
            .map_err(|_| Error::Decode)?;
        let u = unit.get();
        if u.unit_id().as_bytes() != body.parts().reporting_unit_id.as_bytes() {
            return Err(Error::Mismatch);
        }
        if roster.iter().any(|r| r.head() != unit.head()) {
            return Err(Error::StaleEntry);
        }
        let commission = u.commission_org();
        check_event(signed, |s| {
            let role = match s.role {
                EventRole::Chair if s.org_id.as_bytes() == commission.as_bytes() => {
                    RosterRole::Chair
                }
                EventRole::Observer => RosterRole::Observer,
                EventRole::Chair
                | EventRole::Clerk
                | EventRole::Commission
                | EventRole::Committee
                | EventRole::Sender
                | EventRole::Receiver
                | EventRole::Authority
                | EventRole::Device => return Err(Error::NotRegistered),
            };
            roster_key(roster, s.signer_id, role, s.org_id)
        })?;
        Ok(Self {
            parts: *body.parts(),
        })
    }

    /// The fields.
    #[must_use]
    pub const fn parts(&self) -> &PaperCountParts<'a> {
        &self.parts
    }
}

/// What the cryptographic tally gives for one ballot style in one
/// reporting unit, in the terms of PROTOCOL.md §11.5.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MachineCount<'c> {
    /// `D_t`, the confirmed votes of candidates `1..=m`, candidate 1 first.
    pub candidates: &'c [u64],
    /// `B`, records read as `BLANK`.
    pub blank: u64,
    /// `U`, records read as `UNREADABLE`.
    pub unreadable: u64,
    /// `F`, ballots cast in the unit's boxes without a record.
    pub without_record: u64,
    /// `X`, records the tally scope leaves out whose paper is in the unit
    /// (`UNATTESTED`, `SHARE_MISSING`).
    pub excluded_with_paper: u64,
}

/// A paper count compared with the machine count (VC-075).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PaperComparison {
    /// The first candidate (from 1) whose paper votes are below the
    /// machine's confirmed votes, if any: `P_t < D_t`.
    pub first_below: Option<u16>,
    /// Whether `Σ P_t + I = Σ D_t + B + U + F + X`.
    pub totals_agree: bool,
}

impl PaperComparison {
    /// Whether the paper agrees: no candidate below, totals equal.
    #[must_use]
    pub const fn agrees(self) -> bool {
        self.first_below.is_none() && self.totals_agree
    }
}

/// Compares the paper count `paper` with the machine count `machine`
/// (PROTOCOL.md §11.5, VC-075): every candidate's paper votes are at least
/// its confirmed votes, and `Σ P_t + I = Σ D_t + B + U + F + X`.
///
/// # Errors
/// [`Error::Mismatch`] if the paper and the machine count name a different
/// number of candidates, [`Error::Overflow`] if a sum overflows.
pub fn compare_paper(
    machine: &MachineCount<'_>,
    paper: &PaperCountParts<'_>,
) -> Result<PaperComparison, Error> {
    let votes = paper.votes.as_slice();
    if votes.len() != machine.candidates.len() {
        return Err(Error::Mismatch);
    }
    let mut first_below = None;
    let mut paper_total = paper.invalid;
    let mut machine_total = machine.blank;
    for (index, (p, d)) in votes.iter().zip(machine.candidates).enumerate() {
        if first_below.is_none() && p < d {
            let candidate = index.checked_add(1).ok_or(Error::Overflow)?;
            first_below = Some(u16::try_from(candidate).map_err(|_| Error::Overflow)?);
        }
        paper_total = paper_total.checked_add(*p).ok_or(Error::Overflow)?;
        machine_total = machine_total.checked_add(*d).ok_or(Error::Overflow)?;
    }
    let machine_total = [
        machine.unreadable,
        machine.without_record,
        machine.excluded_with_paper,
    ]
    .iter()
    .try_fold(machine_total, |acc, v| acc.checked_add(*v))
    .ok_or(Error::Overflow)?;
    Ok(PaperComparison {
        first_below,
        totals_agree: paper_total == machine_total,
    })
}

#[cfg(test)]
mod tests {
    use ityv_crypto::hash::object_hash;
    use ityv_crypto::{
        AccessStructure, Chamber, HybridSigningKey, Purpose, Threshold, sign_hybrid, verify_hybrid,
    };
    use ityv_encoding::{
        AggregateOpeningBody, AggregateOpeningParts, BallotStyleId, BoxId, ChamberCode,
        ChamberThreshold, Day, ElectionId, EventRole, EventSig, HYBRID_SIG_LEN, Hash512,
        ImprintAuditBody, ImprintAuditParts, MAX_QUORUM_MESSAGE_LEN, OrgId, PaperCountParts,
        PaperCountReportBody, PaperVotes, QuorumSig, QuorumSigned, ReportingUnitEntry,
        ReportingUnitId, RosterRole, RosterSigner, SCHEMA_AGGREGATE_OPENING_BODY,
        SCHEMA_IMPRINT_AUDIT_BODY, SCHEMA_PAPER_COUNT_REPORT_BODY, SCHEMA_VERSION_1, Scalar32,
        Scope, ScopeSet, SignerId, TimeBucket, TrusteeEntry, TrusteeId, WitnessedEvent, Writer,
        encode_object, write_quorum_message,
    };
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;
    use std::boxed::Box;
    use std::vec::Vec;

    use super::{
        LATE_CLOSE_WINDOW, MachineCount, PaperComparison, PaperCount, QuorumTokens, TallyReadiness,
        access_structure, admit_aggregate_opening, admit_tally_scope, check_quorum,
        checkpointed_before, compare_paper, quorum_message,
    };
    use crate::auth::{Authorization, CryptoTallyAid};
    use crate::close::RosterEntry;
    use crate::error::Error;
    use crate::genesis::{Entry, TEST_HEAD};
    use crate::sig::Key;
    use crate::sig::Signed;

    #[test]
    fn gates() {
        let auth = Authorization::unsigned(
            ElectionId::new(b"E1").unwrap(),
            ScopeSet::from_slice(&[
                Scope::PublicBoard,
                Scope::TrusteeBody,
                Scope::CryptoTallyAid,
            ]),
            Day::new(0),
            Day::new(9),
        );
        let cap = auth.grant::<CryptoTallyAid>(Day::new(1)).unwrap();
        let e1 = ElectionId::new(b"E1").unwrap();
        let e2 = ElectionId::new(b"E2").unwrap();
        let ready = TallyReadiness {
            boxes_closed: true,
            receipts_resolved: true,
            legal_resolved: true,
            last_close: TimeBucket::new(100),
            now: TimeBucket::new(100 + LATE_CLOSE_WINDOW + 1),
        };
        assert_eq!(admit_tally_scope(&cap, e1, &ready), Ok(()));
        let at_deadline = TallyReadiness {
            now: TimeBucket::new(100 + LATE_CLOSE_WINDOW),
            ..ready
        };
        assert_eq!(
            admit_tally_scope(&cap, e1, &at_deadline),
            Err(Error::TallyPremature)
        );
        let open = TallyReadiness {
            boxes_closed: false,
            ..ready
        };
        assert_eq!(
            admit_tally_scope(&cap, e1, &open),
            Err(Error::TallyPremature)
        );
        let unresolved = TallyReadiness {
            receipts_resolved: false,
            ..ready
        };
        assert_eq!(
            admit_tally_scope(&cap, e1, &unresolved),
            Err(Error::TallyPremature)
        );
        let undecided = TallyReadiness {
            legal_resolved: false,
            ..ready
        };
        assert_eq!(
            admit_tally_scope(&cap, e1, &undecided),
            Err(Error::TallyPremature)
        );
        let overflow = TallyReadiness {
            last_close: TimeBucket::new(u64::MAX),
            ..ready
        };
        assert_eq!(admit_tally_scope(&cap, e1, &overflow), Err(Error::Overflow));
        assert_eq!(admit_aggregate_opening(&cap, e1, true), Ok(()));
        assert_eq!(
            admit_aggregate_opening(&cap, e1, false),
            Err(Error::TallyPremature)
        );
        assert_eq!(admit_tally_scope(&cap, e2, &ready), Err(Error::Mismatch));
        assert_eq!(
            admit_aggregate_opening(&cap, e2, true),
            Err(Error::Mismatch)
        );
        assert_eq!(LATE_CLOSE_WINDOW, 96);
    }

    #[test]
    fn a_checkpoint_before_the_opening_must_cover_the_scope() {
        // A checkpoint at frame 12 covering frames 1..=10.
        let one = [(12u64, 10u64)];
        assert!(checkpointed_before(one, 10, 13));
        assert!(checkpointed_before(one, 9, 13));
        // It does not cover frame 11.
        assert!(!checkpointed_before(one, 11, 13));
        // It is not before an opening at its own frame or earlier.
        assert!(!checkpointed_before(one, 10, 12));
        assert!(!checkpointed_before(one, 10, 11));
        // Any one of several will do; none is nothing.
        assert!(checkpointed_before([(5, 3), (12, 10)], 10, 13));
        assert!(!checkpointed_before([(5, 3), (14, 12)], 10, 13));
        assert!(!checkpointed_before([], 1, 2));
        // Frame 0 is no frame: nothing covers it.
        assert!(!checkpointed_before([(5, 3)], 0, 13));
        assert!(checkpointed_before([(5, 3)], 1, 13));
    }

    fn key(seed: u8) -> (&'static HybridSigningKey, &'static Key) {
        let sk = Box::leak(Box::new(HybridSigningKey::from_seeds(
            [seed; 32],
            [seed.wrapping_add(1); 32],
        )));
        let vk = sk.verifying_key();
        let mut bytes = [0u8; ityv_encoding::HYBRID_VK_LEN];
        let (ml, ed) = bytes.split_at_mut(ityv_encoding::MLDSA87_VK_HALF);
        ml.copy_from_slice(vk.mldsa87());
        ed.copy_from_slice(vk.ed25519());
        (sk, Box::leak(Box::new(bytes)))
    }

    /// A trustee entry of `chamber` with key `seed`.
    fn trustee(
        id: &'static [u8],
        chamber: ChamberCode,
        seed: u8,
    ) -> (Entry<TrusteeEntry<'static>>, &'static HybridSigningKey) {
        let (sk, vk) = key(seed);
        let entry = Entry::unproved(TrusteeEntry {
            trustee_id: TrusteeId::new(id).unwrap(),
            chamber,
            org_id: OrgId::new(b"TRUST").unwrap(),
            key: vk,
            appointment_hash: Hash512([1; 64]),
        });
        (entry, sk)
    }

    /// Two parties, every chamber one member and threshold one, but `P1`
    /// two members of whom one suffices.
    fn structure() -> AccessStructure {
        let one = Threshold::new(1, 1).unwrap();
        let mut inner = [one; 8];
        inner[0] = Threshold::new(1, 2).unwrap();
        AccessStructure::new(2, inner).unwrap()
    }

    fn opening_body() -> &'static [u8] {
        let body = AggregateOpeningBody::new(&AggregateOpeningParts {
            election_id: ElectionId::new(b"E1").unwrap(),
            ballot_style_id: BallotStyleId::new(b"S-1").unwrap(),
            reporting_unit_id: ReportingUnitId::new(b"RU-1").unwrap(),
            scope_hash: Hash512([5; 64]),
            chunk: 0,
            packed_sum: Scalar32([0; 32]),
            rand_sum: Scalar32([0; 32]),
            id_sum: Scalar32([0; 32]),
            time_bucket: TimeBucket::new(1),
        })
        .unwrap();
        let mut buf = std::vec![0u8; 1024];
        let n = encode_object(
            SCHEMA_AGGREGATE_OPENING_BODY,
            SCHEMA_VERSION_1,
            &body,
            &mut buf,
        )
        .unwrap();
        buf.truncate(n);
        Box::leak(buf.into_boxed_slice())
    }

    /// Checks the quorum of `who` (trustee, its key) signing the opening
    /// under `purpose`, against `entries`.
    fn quorum_of(
        who: &[(Entry<TrusteeEntry<'static>>, &'static HybridSigningKey)],
        entries: &[Entry<TrusteeEntry<'static>>],
        purpose: &[u8],
    ) -> Result<(), Error> {
        quorum_wrapped(who, who.len(), entries, purpose)
    }

    /// As [`quorum_of`], but every trustee of `who` signs the quorum
    /// message naming all of them, and the event carries only the first
    /// `kept` signatures (in trustee order): re-wrapped with fewer
    /// participants than signed.
    fn quorum_wrapped(
        who: &[(Entry<TrusteeEntry<'static>>, &'static HybridSigningKey)],
        kept: usize,
        entries: &[Entry<TrusteeEntry<'static>>],
        purpose: &[u8],
    ) -> Result<(), Error> {
        let body = opening_body();
        let purpose = Box::leak(Box::new(Purpose::new(purpose).unwrap()));
        let mut who = who.to_vec();
        who.sort_by(|a, b| {
            a.0.get()
                .trustee_id
                .as_bytes()
                .cmp(b.0.get().trustee_id.as_bytes())
        });
        let ids: Vec<TrusteeId<'static>> = who.iter().map(|t| t.0.get().trustee_id).collect();
        let mut message = std::vec![0u8; MAX_QUORUM_MESSAGE_LEN];
        let mut w = Writer::new(&mut message);
        write_quorum_message(&object_hash(body), &ids, &mut w).unwrap();
        let n = w.finish();
        message.truncate(n);
        let message: &'static [u8] = Box::leak(message.into_boxed_slice());
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        let signed: Vec<_> = who
            .iter()
            .take(kept)
            .map(|(t, sk)| {
                let sig = sign_hybrid(sk, purpose, message, &mut rng).unwrap();
                (t.get().trustee_id, sk.verifying_key(), sig)
            })
            .collect();
        let signed = Box::leak(signed.into_boxed_slice());
        let sigs: Vec<QuorumSig<'static>> = signed
            .iter()
            .map(|(id, _, sig)| {
                let mut out = [0u8; HYBRID_SIG_LEN];
                let (ml, ed) = out.split_at_mut(sig.mldsa87().len());
                ml.copy_from_slice(sig.mldsa87());
                ed.copy_from_slice(sig.ed25519());
                QuorumSig {
                    trustee_id: *id,
                    sig: Box::leak(Box::new(out)),
                }
            })
            .collect();
        let event = Box::leak(Box::new(QuorumSigned::new(body, &sigs).unwrap()));
        let tokens: Vec<_> = signed
            .iter()
            .map(|(_, vk, sig)| verify_hybrid(vk, purpose, message, sig).unwrap())
            .collect();
        let tokens = Box::leak(tokens.into_boxed_slice());
        check_quorum(&QuorumTokens { event, tokens }, entries, &structure())
    }

    #[test]
    fn the_quorum_message_is_the_body_hash_and_the_trustees() {
        let body = opening_body();
        let sig = Box::leak(Box::new([7u8; HYBRID_SIG_LEN]));
        let ids = [
            TrusteeId::new(b"T-A").unwrap(),
            TrusteeId::new(b"T-J").unwrap(),
        ];
        let sigs: Vec<QuorumSig<'static>> = ids
            .iter()
            .map(|t| QuorumSig {
                trustee_id: *t,
                sig,
            })
            .collect();
        let event = QuorumSigned::new(body, &sigs).unwrap();
        let mut buf = [0u8; MAX_QUORUM_MESSAGE_LEN];
        let message = quorum_message(&event, &mut buf).unwrap().to_vec();
        let mut expected = std::vec![0u8; MAX_QUORUM_MESSAGE_LEN];
        let mut w = Writer::new(&mut expected);
        write_quorum_message(&object_hash(body), &ids, &mut w).unwrap();
        let n = w.finish();
        assert_eq!(message, &expected[..n]);
        assert_eq!(message.len(), 64 + 4 + 2 * (4 + 3));
    }

    #[test]
    fn a_quorum_is_a_qualified_set_of_trustees_with_bound_tokens() {
        let p1a = trustee(b"T-P1-1", ChamberCode::P1, 10);
        let p1b = trustee(b"T-P1-2", ChamberCode::P1, 12);
        let p2 = trustee(b"T-P2", ChamberCode::P2, 14);
        let j = trustee(b"T-J", ChamberCode::J, 16);
        let a = trustee(b"T-A", ChamberCode::A, 18);
        let c = trustee(b"T-C", ChamberCode::C, 20);
        let n = trustee(b"T-N", ChamberCode::N, 22);
        let all: Vec<_> = [p1a, p1b, p2, j, a, c, n].iter().map(|t| t.0).collect();
        let purpose = b"aggregate-opening";
        // Both parties and three of J, A, C, N: qualified (any three).
        assert_eq!(quorum_of(&[a, p1a, p2, j, c], &all, purpose), Ok(()));
        assert_eq!(quorum_of(&[a, p1b, p2, n, c], &all, purpose), Ok(()));
        assert_eq!(
            quorum_of(&[a, p1a, p1b, p2, j, c, n], &all, purpose),
            Ok(())
        );
        // A party missing, or only two of J, A, C, N: not qualified.
        assert_eq!(
            quorum_of(&[a, p1a, j, c, n], &all, purpose),
            Err(Error::SignersShort)
        );
        assert_eq!(
            quorum_of(&[a, p1a, p2, j], &all, purpose),
            Err(Error::SignersShort)
        );
        // A signer who is not a trustee.
        assert_eq!(
            quorum_of(&[a, p1a, p2, j, c], &all[1..], purpose),
            Err(Error::NotRegistered)
        );
        // Six signed a message naming six; re-wrapped with five of their
        // signatures, still a qualified set, the list is not what they
        // signed.
        assert_eq!(
            quorum_wrapped(&[a, c, j, n, p1a, p2], 5, &all, purpose),
            Err(Error::SignatureObject)
        );
        assert_eq!(
            quorum_wrapped(&[a, c, j, n, p1a, p2], 6, &all, purpose),
            Ok(())
        );
        // Tokens over another purpose do not bind.
        assert_eq!(
            quorum_of(&[a, p1a, p2, j, c], &all, b"tally-scope"),
            Err(Error::SignatureObject)
        );
        // A trustee entry under another key: the token's key is not it.
        let (forged, _) = trustee(b"T-J", ChamberCode::J, 40);
        let swapped: Vec<_> = all
            .iter()
            .map(|t| {
                if t.get().trustee_id.as_bytes() == b"T-J" {
                    forged
                } else {
                    *t
                }
            })
            .collect();
        assert_eq!(
            quorum_of(&[a, p1a, p2, j, c], &swapped, purpose),
            Err(Error::SignatureSigner)
        );
        // Two trustees sharing a key half are not two signers.
        let (_, shared_vk) = key(16);
        let twin = (
            Entry::unproved(TrusteeEntry {
                key: shared_vk,
                ..*a.0.get()
            }),
            j.1,
        );
        let twins: Vec<_> = all
            .iter()
            .map(|t| {
                if t.get().trustee_id.as_bytes() == b"T-A" {
                    twin.0
                } else {
                    *t
                }
            })
            .collect();
        assert_eq!(
            quorum_of(&[twin, p1a, p2, j, c], &twins, purpose),
            Err(Error::SignatureSigner)
        );
        // Entries proved against different genesis states.
        let mut stale = all.clone();
        stale[0] = stale[0].with_head(Hash512([9; 64]));
        assert_ne!(stale[0].head(), &TEST_HEAD);
        assert_eq!(
            quorum_of(&[a, p1a, p2, j, c], &stale, purpose),
            Err(Error::StaleEntry)
        );
    }

    const fn threshold(chamber: ChamberCode, threshold: u8, members: u8) -> ChamberThreshold {
        ChamberThreshold {
            chamber,
            threshold,
            members,
        }
    }

    #[test]
    fn the_access_structure_comes_from_the_genesis_chambers() {
        let chambers = [
            threshold(ChamberCode::P1, 2, 3),
            threshold(ChamberCode::P2, 1, 2),
            threshold(ChamberCode::J, 1, 1),
            threshold(ChamberCode::A, 2, 2),
            threshold(ChamberCode::C, 1, 4),
            threshold(ChamberCode::N, 3, 8),
        ];
        let s = access_structure(2, chambers).unwrap();
        assert_eq!(s.parties(), 2);
        for c in chambers {
            let chamber = Chamber::ALL[usize::from(c.chamber.code()) - 1];
            let t = s.threshold(chamber);
            assert_eq!((t.k(), t.n()), (c.threshold, c.members));
        }
        // A party chamber the genesis does not list keeps a placeholder.
        assert_eq!(s.threshold(Chamber::P3), Threshold::new(1, 1).unwrap());
        // Nine members cannot be shared; a threshold above the members is
        // not one.
        let mut nine = chambers;
        nine[2] = threshold(ChamberCode::J, 1, 9);
        assert!(access_structure(2, nine).is_none());
        let mut above = chambers;
        above[2] = threshold(ChamberCode::J, 2, 1);
        assert!(access_structure(2, above).is_none());
        // One or five parties are out of range; the party count must be
        // the chambers'.
        assert!(access_structure(1, chambers).is_none());
        assert!(access_structure(5, chambers).is_none());
        assert!(access_structure(258, chambers).is_none());
        assert!(access_structure(3, chambers).is_none());
        // Every chamber exactly once, in order: none missing (no 1-of-1
        // default), none twice (no later entry winning), none swapped,
        // none extra.
        assert!(access_structure(2, chambers[..5].iter().copied()).is_none());
        assert!(access_structure(2, chambers[1..].iter().copied()).is_none());
        let mut twice = chambers.to_vec();
        twice.insert(3, threshold(ChamberCode::J, 1, 1));
        assert!(access_structure(2, twice).is_none());
        let mut swapped = chambers;
        swapped.swap(2, 3);
        assert!(access_structure(2, swapped).is_none());
        let mut extra = chambers.to_vec();
        extra.push(threshold(ChamberCode::N, 1, 1));
        assert!(access_structure(2, extra).is_none());
        assert!(access_structure(2, []).is_none());
        // Four parties with all eight chambers.
        let four = [
            threshold(ChamberCode::P1, 1, 1),
            threshold(ChamberCode::P2, 1, 1),
            threshold(ChamberCode::P3, 1, 2),
            threshold(ChamberCode::P4, 2, 2),
            threshold(ChamberCode::J, 1, 1),
            threshold(ChamberCode::A, 1, 1),
            threshold(ChamberCode::C, 1, 1),
            threshold(ChamberCode::N, 1, 1),
        ];
        let s = access_structure(4, four).unwrap();
        assert_eq!(s.parties(), 4);
        assert_eq!(s.threshold(Chamber::P4), Threshold::new(2, 2).unwrap());
        assert!(access_structure(4, chambers).is_none());
    }

    fn paper(votes: &[u64], invalid: u64) -> PaperCountParts<'static> {
        PaperCountParts {
            election_id: ElectionId::new(b"E1").unwrap(),
            reporting_unit_id: ReportingUnitId::new(b"RU-1").unwrap(),
            ballot_style_id: BallotStyleId::new(b"S-1").unwrap(),
            votes: PaperVotes::new(votes).unwrap(),
            invalid,
            time_bucket: TimeBucket::new(1),
        }
    }

    #[test]
    fn paper_at_least_the_machine_and_totals_equal() {
        let machine = MachineCount {
            candidates: &[10, 5, 0],
            blank: 2,
            unreadable: 1,
            without_record: 3,
            excluded_with_paper: 1,
        };
        // 22 = 10 + 5 + 0 + 2 + 1 + 3 + 1.
        let agrees = PaperComparison {
            first_below: None,
            totals_agree: true,
        };
        assert_eq!(compare_paper(&machine, &paper(&[12, 7, 0], 3)), Ok(agrees));
        assert!(agrees.agrees());
        assert_eq!(compare_paper(&machine, &paper(&[10, 5, 0], 7)), Ok(agrees));
        // A candidate below the machine, totals still equal.
        let below = compare_paper(&machine, &paper(&[9, 8, 0], 5)).unwrap();
        assert_eq!(below.first_below, Some(1));
        assert!(below.totals_agree);
        assert!(!below.agrees());
        let below = compare_paper(&machine, &paper(&[10, 4, 0], 8)).unwrap();
        assert_eq!(below.first_below, Some(2));
        // The first candidate below is named even when a later one is too.
        let below = compare_paper(&machine, &paper(&[9, 4, 0], 9)).unwrap();
        assert_eq!(below.first_below, Some(1));
        // Totals off by one, either way.
        for invalid in [2, 4] {
            let off = compare_paper(&machine, &paper(&[12, 7, 0], invalid)).unwrap();
            assert_eq!(off.first_below, None);
            assert!(!off.totals_agree);
            assert!(!off.agrees());
        }
        // Each machine term counts.
        for (b, u, f, x) in [(3, 1, 3, 1), (2, 2, 3, 1), (2, 1, 4, 1), (2, 1, 3, 2)] {
            let m = MachineCount {
                blank: b,
                unreadable: u,
                without_record: f,
                excluded_with_paper: x,
                ..machine
            };
            assert!(
                !compare_paper(&m, &paper(&[12, 7, 0], 3))
                    .unwrap()
                    .totals_agree
            );
            assert!(
                compare_paper(&m, &paper(&[12, 7, 0], 4))
                    .unwrap()
                    .totals_agree
            );
        }
        // The candidate lists must have the same length.
        assert_eq!(
            compare_paper(&machine, &paper(&[12, 7], 3)),
            Err(Error::Mismatch)
        );
        // Sums that overflow.
        let huge = MachineCount {
            candidates: &[u64::MAX, 0, 0],
            ..machine
        };
        assert_eq!(
            compare_paper(&huge, &paper(&[12, 7, 0], 3)),
            Err(Error::Overflow)
        );
        for (b, u, f, x) in [
            (u64::MAX, 0, 0, 0),
            (0, u64::MAX, 0, 0),
            (0, 0, u64::MAX, 0),
            (0, 0, 0, u64::MAX),
        ] {
            let m = MachineCount {
                blank: b,
                unreadable: u,
                without_record: f,
                excluded_with_paper: x,
                ..machine
            };
            assert_eq!(
                compare_paper(&m, &paper(&[12, 7, 0], 3)),
                Err(Error::Overflow)
            );
        }
    }

    /// A roster entry for `id` with key `seed`.
    fn person(
        id: &'static [u8],
        role: RosterRole,
        org: &'static [u8],
        seed: u8,
    ) -> (RosterEntry<'static>, &'static HybridSigningKey) {
        let (sk, vk) = key(seed);
        let entry = Entry::unproved(RosterSigner {
            signer_id: SignerId::new(id).unwrap(),
            role,
            org_id: OrgId::new(org).unwrap(),
            station_id: None,
            key: vk,
            appointment_hash: Hash512([1; 64]),
        });
        (entry, sk)
    }

    /// Checks a witnessed event over `body` signed by `who` (signer, role,
    /// organisation, key) against `roster`.
    fn checked(
        body: &'static [u8],
        who: &[(
            &'static [u8],
            EventRole,
            &'static [u8],
            &'static HybridSigningKey,
        )],
        roster: &[RosterEntry<'static>],
        unit: &Entry<ReportingUnitEntry<'static>>,
    ) -> Result<PaperCount<'static>, Error> {
        let mut rng = ChaCha20Rng::seed_from_u64(11);
        let purpose = Box::leak(Box::new(Purpose::new(b"paper-count").unwrap()));
        let signed: Vec<_> = who
            .iter()
            .map(|(id, role, org, sk)| {
                let sig = sign_hybrid(sk, purpose, body, &mut rng).unwrap();
                (*id, *role, *org, sk.verifying_key(), sig)
            })
            .collect();
        let signed = Box::leak(signed.into_boxed_slice());
        let sigs: Vec<EventSig<'static>> = signed
            .iter()
            .map(|(id, role, org, _, sig)| {
                let mut out = [0u8; HYBRID_SIG_LEN];
                let (ml, ed) = out.split_at_mut(sig.mldsa87().len());
                ml.copy_from_slice(sig.mldsa87());
                ed.copy_from_slice(sig.ed25519());
                EventSig {
                    signer_id: SignerId::new(id).unwrap(),
                    role: *role,
                    org_id: OrgId::new(org).unwrap(),
                    sig: Box::leak(Box::new(out)),
                }
            })
            .collect();
        let event = Box::leak(Box::new(WitnessedEvent::new(body, &sigs).unwrap()));
        let tokens: Vec<_> = signed
            .iter()
            .map(|(_, _, _, vk, sig)| verify_hybrid(vk, purpose, body, sig).unwrap())
            .collect();
        let tokens = Box::leak(tokens.into_boxed_slice());
        PaperCount::check(&Signed { event, tokens }, roster, unit)
    }

    /// The paper count body object of `parts`.
    fn paper_object(parts: &PaperCountParts<'static>) -> &'static [u8] {
        let body = PaperCountReportBody::new(parts).unwrap();
        let mut buf = std::vec![0u8; 512];
        let n = encode_object(
            SCHEMA_PAPER_COUNT_REPORT_BODY,
            SCHEMA_VERSION_1,
            &body,
            &mut buf,
        )
        .unwrap();
        buf.truncate(n);
        Box::leak(buf.into_boxed_slice())
    }

    /// Unit `RU-1` reported by commission `NEC-11`.
    fn unit_of(id: &'static [u8]) -> Entry<ReportingUnitEntry<'static>> {
        Entry::unproved(
            ReportingUnitEntry::new(
                ReportingUnitId::new(id).unwrap(),
                1,
                OrgId::new(b"NEC-11").unwrap(),
            )
            .unwrap(),
        )
    }

    #[test]
    fn a_paper_count_is_bound_to_its_units_commission() {
        let body = paper_object(&paper(&[3, 1], 2));
        let chair = person(b"chair", RosterRole::Chair, b"NEC-11", 50);
        let obs_a = person(b"obs-a", RosterRole::Observer, b"PARTY-A", 52);
        let obs_b = person(b"obs-b", RosterRole::Observer, b"PARTY-B", 54);
        let other_chair = person(b"chair-12", RosterRole::Chair, b"NEC-12", 60);
        let roster = [chair.0, obs_a.0, obs_b.0, other_chair.0];
        let unit = unit_of(b"RU-1");
        let signers = [
            (&b"chair"[..], EventRole::Chair, &b"NEC-11"[..], chair.1),
            (b"obs-a", EventRole::Observer, b"PARTY-A", obs_a.1),
            (b"obs-b", EventRole::Observer, b"PARTY-B", obs_b.1),
        ];
        assert!(checked(body, &signers, &roster, &unit).is_ok());
        // The chair of another district, registered as a chair, cannot
        // report this unit.
        let other_district = [
            (
                &b"chair-12"[..],
                EventRole::Chair,
                &b"NEC-12"[..],
                other_chair.1,
            ),
            signers[1],
            signers[2],
        ];
        assert_eq!(
            checked(body, &other_district, &roster, &unit),
            Err(Error::NotRegistered)
        );
        // The unit must be the report's, from the roster's genesis state.
        assert_eq!(
            checked(body, &signers, &roster, &unit_of(b"RU-2")),
            Err(Error::Mismatch)
        );
        let stale = unit.with_head(Hash512([9; 64]));
        assert_eq!(
            checked(body, &signers, &roster, &stale),
            Err(Error::StaleEntry)
        );
    }

    #[test]
    fn a_paper_count_is_bound_to_the_chair_and_the_observers_on_the_roster() {
        let parts = paper(&[3, 1], 2);
        let body = paper_object(&parts);
        let chair = person(b"chair", RosterRole::Chair, b"NEC-11", 50);
        let obs_a = person(b"obs-a", RosterRole::Observer, b"PARTY-A", 52);
        let obs_b = person(b"obs-b", RosterRole::Observer, b"PARTY-B", 54);
        let clerk = person(b"clerk", RosterRole::Clerk, b"NEC-11", 56);
        let roster = [chair.0, obs_a.0, obs_b.0, clerk.0];
        let unit = unit_of(b"RU-1");
        let signers = [
            (&b"chair"[..], EventRole::Chair, &b"NEC-11"[..], chair.1),
            (b"obs-a", EventRole::Observer, b"PARTY-A", obs_a.1),
            (b"obs-b", EventRole::Observer, b"PARTY-B", obs_b.1),
        ];
        let taken = checked(body, &signers, &roster, &unit).unwrap();
        assert_eq!(taken.parts(), &parts);
        // The chair must be registered as a chair, of that organisation.
        let as_chair = [
            (&b"clerk"[..], EventRole::Chair, &b"NEC-11"[..], clerk.1),
            signers[1],
            signers[2],
        ];
        assert_eq!(
            checked(body, &as_chair, &roster, &unit),
            Err(Error::NotRegistered)
        );
        let other_org = [
            (&b"chair"[..], EventRole::Chair, &b"NEC-12"[..], chair.1),
            signers[1],
            signers[2],
        ];
        assert_eq!(
            checked(body, &other_org, &roster, &unit),
            Err(Error::NotRegistered)
        );
        // An observer must be registered as an observer.
        let as_observer = [
            signers[0],
            (&b"clerk"[..], EventRole::Observer, &b"PARTY-C"[..], clerk.1),
            signers[2],
        ];
        assert_eq!(
            checked(body, &as_observer, &roster, &unit),
            Err(Error::NotRegistered)
        );
        // A signature under another key does not bind.
        let forged = [
            signers[0],
            (&b"obs-a"[..], EventRole::Observer, &b"PARTY-A"[..], obs_b.1),
            signers[2],
        ];
        assert_eq!(
            checked(body, &forged, &roster, &unit),
            Err(Error::SignatureSigner)
        );
        // Another body is not a paper count.
        let audit = ImprintAuditBody::new(&ImprintAuditParts {
            election_id: ElectionId::new(b"E1").unwrap(),
            box_id: BoxId::new(b"BOX-1").unwrap(),
            unimprinted: 0,
            duplicate_cast_ids: 0,
            time_bucket: TimeBucket::new(1),
        });
        let mut buf = std::vec![0u8; 256];
        let n = encode_object(
            SCHEMA_IMPRINT_AUDIT_BODY,
            SCHEMA_VERSION_1,
            &audit,
            &mut buf,
        )
        .unwrap();
        buf.truncate(n);
        let audit: &'static [u8] = Box::leak(buf.into_boxed_slice());
        let clerk2 = person(b"clerk-2", RosterRole::Clerk, b"NEC-11", 58);
        let witnesses = [
            (&b"clerk"[..], EventRole::Clerk, &b"NEC-11"[..], clerk.1),
            (b"clerk-2", EventRole::Clerk, b"NEC-11", clerk2.1),
            signers[1],
            signers[2],
        ];
        assert_eq!(
            checked(audit, &witnesses, &roster, &unit),
            Err(Error::Decode)
        );
    }
}
