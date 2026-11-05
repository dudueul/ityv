//! Gates, signers and the escalation rule of the paper audit (PROTOCOL.md
//! §12; ADR-0036).
//!
//! * The freeze, the commit, the seed and a finding need the `RLA`
//!   capability (VC-007) of the same election ([`admit_audit_freeze`],
//!   [`admit_audit_commit`], [`admit_audit_seed`], [`admit_audit_finding`]);
//!   the commit waits for every style's freeze and the seed for the commit
//!   and its binding checkpoint (ADR-0036); a sample
//!   opening reference needs `OBSERVER_ACCESS` for the seed's day, because
//!   the restricted opening is shown to the auditors and observers under
//!   that scope (§12.3, [`admit_sample_opening`]).
//! * The freeze, the commit and the seed are signed by the committee and
//!   observers of
//!   two or more organisations; a comparison and a finding by auditors of
//!   two or more organisations and observers of two or more organisations
//!   ([`check_audit_signers`]); a hand count, like a paper count, by the
//!   chair of the unit's district commission and observers ([`HandCount`]).
//!   The envelope fixes the roles each body admits
//!   (`ityv_encoding::roles_satisfied`); here every signature is bound to
//!   the key the roster registers for that signer, role and organisation.
//! * [`audit_phase`] is the escalation rule of §12.4 over the declared
//!   rounds: a round concludes the audit when every record of its sample
//!   is compared and the nonzero codes among them are at most its
//!   threshold; more nonzero codes than the threshold, even before the
//!   round's sample is all compared, expand the sample to the next round;
//!   past the last round the whole ballot style is counted by hand.
//! * [`follow_up`] is the table of §12.3: what each reason code calls for.
//!
//! What this module does not prove: that the declared sample sizes and
//! thresholds are what the rule document's formula gives for the style's
//! margin and risk limit (the verifier holds no formula, ADR-0036); that
//! the dice and the beacon were what their public records say.

use ityv_encoding::{
    AuditRounds, ComparisonCode, ElectionId, EventRole, HandCountReportBody, MAX_AUDIT_ROUNDS,
    PaperCountParts, ReportingUnitEntry, RosterRole, SCHEMA_HAND_COUNT_REPORT_BODY,
};

use crate::auth::{Cap, ObserverAccess, Rla};
use crate::close::{RosterEntry, roster_key};
use crate::error::Error;
use crate::genesis::Entry;
use crate::sig::{Key, Signed, check_event};
use crate::tally::{check_chair_report, signing_key};

/// Where a ballot style's audit stands under its rule (PROTOCOL.md §12.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuditPhase {
    /// Round `round` (0 is the first sample) is being compared.
    Sampling {
        /// The round.
        round: u8,
    },
    /// Every record of round `round`'s sample was compared and the nonzero
    /// codes among them were at most its threshold: the audit concluded.
    Concluded {
        /// The round.
        round: u8,
    },
    /// Every round's threshold was exceeded: the ballot style is counted by
    /// hand, and the hand count is the legal result.
    HandCount,
}

/// The comparisons so far among the records of one round's sample (the
/// first `min(sample_size, frame)` records drawn).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct RoundCount {
    /// Records of the round's sample with a comparison.
    pub compared: u64,
    /// Of those, the comparisons with a nonzero reason code.
    pub nonzero: u64,
}

/// The phase of an audit with rounds `rounds`, a sample frame of
/// `frame_len` records and `counts[r]` the comparisons among round `r`'s
/// sample (PROTOCOL.md §12.4). The rounds are taken in order: a round
/// whose nonzero codes exceed its threshold escalates to the next (or to a
/// hand count after the last); the first that does not is concluded once
/// its whole sample is compared, and sampled until then. A round's sample
/// is never larger than the frame, so a frame of no record concludes at
/// once.
#[must_use]
pub fn audit_phase(
    rounds: &AuditRounds,
    frame_len: u64,
    counts: &[RoundCount; MAX_AUDIT_ROUNDS],
) -> AuditPhase {
    for (index, (round, count)) in rounds.as_slice().iter().zip(counts).enumerate() {
        let Ok(round_index) = u8::try_from(index) else {
            break;
        };
        if count.nonzero > u64::from(round.threshold) {
            continue;
        }
        let size = round.sample_size.min(frame_len);
        return if count.compared >= size {
            AuditPhase::Concluded { round: round_index }
        } else {
            AuditPhase::Sampling { round: round_index }
        };
    }
    AuditPhase::HandCount
}

/// What a comparison's reason code calls for (PROTOCOL.md §12.3, §12.5).
/// Every code but 0 is a discrepancy and counts toward the escalation rule
/// of §12.4 ([`FollowUp::is_discrepancy`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FollowUp {
    /// Code 0: nothing.
    Nothing,
    /// Codes 1 and 2: every record of the device is compared and an
    /// `AuditFinding` is recorded (VC-074).
    FullComparison,
    /// Codes 3 and 4: counted in the device's (and model's) published rate.
    Rate,
    /// Codes 5 and 6: the box is held and its custody investigated.
    Custody,
}

impl FollowUp {
    /// Whether the code is a discrepancy (every code but 0).
    #[must_use]
    pub const fn is_discrepancy(self) -> bool {
        !matches!(self, Self::Nothing)
    }
}

/// The follow-up of reason code `code`.
#[must_use]
pub const fn follow_up(code: ComparisonCode) -> FollowUp {
    match code {
        ComparisonCode::Match => FollowUp::Nothing,
        ComparisonCode::OtherCandidate | ComparisonCode::CandidateInvalid => {
            FollowUp::FullComparison
        }
        ComparisonCode::UnreadableValid | ComparisonCode::BlankValid => FollowUp::Rate,
        ComparisonCode::BallotMissing | ComparisonCode::ImprintMismatch => FollowUp::Custody,
    }
}

/// Admits an `AuditManifestFreeze`: the `RLA` capability of the same
/// election, and every tally scope of the ballot style already taken
/// (the sample frame is the style's included records, PROTOCOL.md §12.1).
///
/// # Errors
/// [`Error::Mismatch`] if the capability belongs to another election,
/// [`Error::AuditOutOfOrder`] if a scope of the style is still missing.
pub fn admit_audit_freeze(
    cap: &Cap<'_, Rla>,
    election_id: ElectionId<'_>,
    scopes_taken: bool,
) -> Result<(), Error> {
    cap.check_election(election_id)?;
    if scopes_taken {
        Ok(())
    } else {
        Err(Error::AuditOutOfOrder)
    }
}

/// Admits an `AuditCommit`: the `RLA` capability of the same election, and
/// every ballot style audited frozen in an earlier frame (the commit fixes
/// the dice record and the freezes before the beacon value can be known,
/// PROTOCOL.md §12.1, ADR-0036).
///
/// # Errors
/// [`Error::Mismatch`] if the capability belongs to another election,
/// [`Error::AuditOutOfOrder`] if a style's freeze is still missing.
pub fn admit_audit_commit(
    cap: &Cap<'_, Rla>,
    election_id: ElectionId<'_>,
    styles_frozen: bool,
) -> Result<(), Error> {
    cap.check_election(election_id)?;
    if styles_frozen {
        Ok(())
    } else {
        Err(Error::AuditOutOfOrder)
    }
}

/// What an audit seed waits for (ADR-0036).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SeedReadiness {
    /// The election's audit commit is in an earlier frame.
    pub committed: bool,
    /// Its binding checkpoint (the first valid checkpoint that covers the
    /// commit) is in an earlier frame.
    pub bound: bool,
}

/// Admits an `AuditSeed`: the `RLA` capability of the same election, the
/// audit commit and its binding checkpoint before the seed (PROTOCOL.md
/// §12.1).
///
/// # Errors
/// [`Error::Mismatch`] if the capability belongs to another election,
/// [`Error::AuditOutOfOrder`] if the commit or its binding checkpoint is
/// still missing.
pub fn admit_audit_seed(
    cap: &Cap<'_, Rla>,
    election_id: ElectionId<'_>,
    readiness: SeedReadiness,
) -> Result<(), Error> {
    cap.check_election(election_id)?;
    if readiness.committed && readiness.bound {
        Ok(())
    } else {
        Err(Error::AuditOutOfOrder)
    }
}

/// Admits an `AuditFinding`: the `RLA` capability of the same election.
///
/// # Errors
/// [`Error::Mismatch`] if the capability belongs to another election.
pub fn admit_audit_finding(cap: &Cap<'_, Rla>, election_id: ElectionId<'_>) -> Result<(), Error> {
    cap.check_election(election_id)
}

/// Admits a sample opening reference: `OBSERVER_ACCESS` of the same
/// election for the seed's day (the opening is shown under that scope,
/// PROTOCOL.md §12.3), and a record the audit calls for (`called`: in the
/// sample drawn so far, or of a device under full comparison).
///
/// # Errors
/// [`Error::Mismatch`] if the capability belongs to another election,
/// [`Error::AuditOutOfOrder`] for a record the audit does not call for.
pub fn admit_sample_opening(
    cap: &Cap<'_, ObserverAccess>,
    election_id: ElectionId<'_>,
    called: bool,
) -> Result<(), Error> {
    cap.check_election(election_id)?;
    if called {
        Ok(())
    } else {
        Err(Error::AuditOutOfOrder)
    }
}

/// Checks the people of an audit freeze, seed, comparison or finding:
/// every signer is the committee (under `committee`, the genesis key) or
/// registered in `roster` (the genesis state in force at the event's frame)
/// as an observer or an auditor of the organisation the signature names,
/// with a matching token from the key of `keys` registered for the same
/// signer, role and organisation (of the state in force or an earlier one,
/// newest first, as the caller found it). The envelope already admits
/// exactly the roles each body needs (`ityv_encoding::roles_satisfied`).
///
/// # Errors
/// [`Error::NotRegistered`] for a signer of another role or one the roster
/// does not register in that role and organisation or `keys` does not
/// hold, [`Error::StaleEntry`] for a roster of mixed genesis states, and
/// the errors of [`crate::sig::check_event`].
pub fn check_audit_signers(
    signed: &Signed<'_>,
    roster: &[RosterEntry<'_>],
    keys: &[RosterEntry<'_>],
    committee: &Key,
) -> Result<(), Error> {
    check_event(signed, |s| {
        let role = match s.role {
            EventRole::Committee => return Ok(committee),
            EventRole::Observer => RosterRole::Observer,
            EventRole::Auditor => RosterRole::Auditor,
            EventRole::Clerk
            | EventRole::Commission
            | EventRole::Sender
            | EventRole::Receiver
            | EventRole::Authority
            | EventRole::Device
            | EventRole::Chair => return Err(Error::NotRegistered),
        };
        roster_key(roster, s.signer_id, role, s.org_id)?;
        signing_key(keys, s, role)
    })
}

/// A full hand count report whose signatures were bound to the roster: the
/// chair of the district commission that reports the unit, once, and
/// observers of two or more organisations, as for the paper count
/// (PROTOCOL.md §11.5, §12.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandCount<'a> {
    parts: PaperCountParts<'a>,
}

impl<'a> HandCount<'a> {
    /// Checks a signed hand count report of the reporting unit `unit`, with
    /// the rules of [`crate::PaperCount::check`].
    ///
    /// # Errors
    /// [`Error::Decode`] if the event is not a hand count report, and the
    /// errors of [`crate::PaperCount::check`].
    pub fn check(
        signed: &Signed<'a>,
        roster: &[RosterEntry<'_>],
        keys: &[RosterEntry<'_>],
        unit: &Entry<ReportingUnitEntry<'_>>,
    ) -> Result<Self, Error> {
        let body: HandCountReportBody<'a> = signed
            .event
            .body(SCHEMA_HAND_COUNT_REPORT_BODY)
            .map_err(|_| Error::Decode)?;
        check_chair_report(signed, roster, keys, unit, body.parts())?;
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

#[cfg(test)]
mod tests {

    use ityv_crypto::{HybridSigningKey, Purpose, sign_hybrid, verify_hybrid};
    use ityv_encoding::{
        AuditFindingBody, AuditFindingParts, BallotStyleId, BoxId, Day, ElectionId, EventRole,
        EventSig, HYBRID_SIG_LEN, HandCountReportBody, Hash512, OrgId, PaperCountParts,
        PaperCountReportBody, PaperVotes, ReportingUnitEntry, ReportingUnitId, RosterRole,
        RosterSigner, SCHEMA_AUDIT_FINDING_BODY, SCHEMA_HAND_COUNT_REPORT_BODY,
        SCHEMA_PAPER_COUNT_REPORT_BODY, SCHEMA_VERSION_1, Scope, ScopeSet, SignerId, TimeBucket,
        WitnessedEvent, encode_object,
    };
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;
    use std::boxed::Box;
    use std::vec::Vec;

    use super::{
        HandCount, SeedReadiness, admit_audit_commit, admit_audit_finding, admit_audit_freeze,
        admit_audit_seed, admit_sample_opening, check_audit_signers,
    };
    use crate::auth::{Authorization, ObserverAccess, Rla};
    use crate::close::RosterEntry;
    use crate::error::Error;
    use crate::genesis::Entry;
    use crate::sig::{Key, Signed};

    #[test]
    fn the_gates_need_their_capability_and_their_order() {
        let e1 = ElectionId::new(b"E1").unwrap();
        let e2 = ElectionId::new(b"E2").unwrap();
        let auth = Authorization::unsigned(
            e1,
            ScopeSet::from_slice(&[
                Scope::PublicBoard,
                Scope::TrusteeBody,
                Scope::CryptoTallyAid,
                Scope::Rla,
                Scope::ObserverAccess,
            ]),
            Day::new(0),
            Day::new(9),
        );
        let rla = auth.grant::<Rla>(Day::new(1)).unwrap();
        let view = auth.grant::<ObserverAccess>(Day::new(1)).unwrap();
        assert_eq!(admit_audit_freeze(&rla, e1, true), Ok(()));
        assert_eq!(
            admit_audit_freeze(&rla, e1, false),
            Err(Error::AuditOutOfOrder)
        );
        assert_eq!(admit_audit_freeze(&rla, e2, true), Err(Error::Mismatch));
        assert_eq!(admit_audit_commit(&rla, e1, true), Ok(()));
        assert_eq!(
            admit_audit_commit(&rla, e1, false),
            Err(Error::AuditOutOfOrder)
        );
        assert_eq!(admit_audit_commit(&rla, e2, true), Err(Error::Mismatch));
        assert_eq!(admit_audit_finding(&rla, e1), Ok(()));
        assert_eq!(admit_audit_finding(&rla, e2), Err(Error::Mismatch));
        let ready = SeedReadiness {
            committed: true,
            bound: true,
        };
        assert_eq!(admit_audit_seed(&rla, e1, ready), Ok(()));
        for not_ready in [
            SeedReadiness {
                committed: false,
                ..ready
            },
            SeedReadiness {
                bound: false,
                ..ready
            },
        ] {
            assert_eq!(
                admit_audit_seed(&rla, e1, not_ready),
                Err(Error::AuditOutOfOrder)
            );
        }
        assert_eq!(admit_audit_seed(&rla, e2, ready), Err(Error::Mismatch));
        assert_eq!(admit_sample_opening(&view, e1, true), Ok(()));
        assert_eq!(
            admit_sample_opening(&view, e1, false),
            Err(Error::AuditOutOfOrder)
        );
        assert_eq!(admit_sample_opening(&view, e2, true), Err(Error::Mismatch));
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

    type Who = (
        &'static [u8],
        EventRole,
        &'static [u8],
        &'static HybridSigningKey,
    );

    /// The event over `body` signed by `who` under `purpose`, with its
    /// tokens.
    fn signed(body: &'static [u8], purpose: &'static [u8], who: &[Who]) -> Signed<'static> {
        let mut rng = ChaCha20Rng::seed_from_u64(17);
        let purpose = Box::leak(Box::new(Purpose::new(purpose).unwrap()));
        let mut who = who.to_vec();
        who.sort_by(|a, b| a.0.cmp(b.0));
        let made: Vec<_> = who
            .iter()
            .map(|(id, role, org, sk)| {
                let sig = sign_hybrid(sk, purpose, body, &mut rng).unwrap();
                (*id, *role, *org, sk.verifying_key(), sig)
            })
            .collect();
        let made = Box::leak(made.into_boxed_slice());
        let sigs: Vec<EventSig<'static>> = made
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
        let tokens: Vec<_> = made
            .iter()
            .map(|(_, _, _, vk, sig)| verify_hybrid(vk, purpose, body, sig).unwrap())
            .collect();
        Signed {
            event,
            tokens: Box::leak(tokens.into_boxed_slice()),
        }
    }

    fn object<T: ityv_encoding::Encode>(
        schema: ityv_encoding::SchemaId,
        value: &T,
    ) -> &'static [u8] {
        let mut buf = std::vec![0u8; value.encoded_len().saturating_add(16)];
        let n = encode_object(schema, SCHEMA_VERSION_1, value, &mut buf).unwrap();
        buf.truncate(n);
        Box::leak(buf.into_boxed_slice())
    }

    fn finding() -> &'static [u8] {
        object(
            SCHEMA_AUDIT_FINDING_BODY,
            &AuditFindingBody::new(&AuditFindingParts {
                election_id: ElectionId::new(b"E1").unwrap(),
                ballot_style_id: BallotStyleId::new(b"S-1").unwrap(),
                device_id: BoxId::new(b"BOX-1").unwrap(),
                finding_hash: Hash512([4; 64]),
                time_bucket: TimeBucket::new(1),
            })
            .unwrap(),
        )
    }

    #[test]
    fn audit_signers_are_bound_to_the_roster_and_the_committee() {
        let aud_1 = person(b"aud-1", RosterRole::Auditor, b"AUDIT-A", 80);
        let aud_2 = person(b"aud-2", RosterRole::Auditor, b"AUDIT-B", 82);
        let obs_a = person(b"obs-a", RosterRole::Observer, b"PARTY-A", 84);
        let obs_b = person(b"obs-b", RosterRole::Observer, b"PARTY-B", 86);
        let clerk = person(b"clerk", RosterRole::Clerk, b"AUDIT-C", 88);
        let roster = [aud_1.0, aud_2.0, obs_a.0, obs_b.0, clerk.0];
        let (_, committee_key) = key(90);
        let body = finding();
        let who = [
            (&b"aud-1"[..], EventRole::Auditor, &b"AUDIT-A"[..], aud_1.1),
            (b"aud-2", EventRole::Auditor, b"AUDIT-B", aud_2.1),
            (b"obs-a", EventRole::Observer, b"PARTY-A", obs_a.1),
            (b"obs-b", EventRole::Observer, b"PARTY-B", obs_b.1),
        ];
        let ok = signed(body, b"audit-finding", &who);
        assert_eq!(
            check_audit_signers(&ok, &roster, &roster, committee_key),
            Ok(())
        );
        // An auditor must be registered as an auditor of that organisation.
        let as_auditor = [
            (&b"clerk"[..], EventRole::Auditor, &b"AUDIT-C"[..], clerk.1),
            who[1],
            who[2],
            who[3],
        ];
        assert_eq!(
            check_audit_signers(
                &signed(body, b"audit-finding", &as_auditor),
                &roster,
                &roster,
                committee_key
            ),
            Err(Error::NotRegistered)
        );
        let other_org = [
            (&b"aud-1"[..], EventRole::Auditor, &b"AUDIT-C"[..], aud_1.1),
            who[1],
            who[2],
            who[3],
        ];
        assert_eq!(
            check_audit_signers(
                &signed(body, b"audit-finding", &other_org),
                &roster,
                &roster,
                committee_key
            ),
            Err(Error::NotRegistered)
        );
        // An observer must be registered as an observer.
        let impostor = person(b"aud-9", RosterRole::Auditor, b"PARTY-A", 92);
        let as_observer = [
            who[0],
            who[1],
            (
                &b"aud-9"[..],
                EventRole::Observer,
                &b"PARTY-A"[..],
                impostor.1,
            ),
            who[3],
        ];
        let roster_with = [aud_1.0, aud_2.0, obs_a.0, obs_b.0, impostor.0];
        assert_eq!(
            check_audit_signers(
                &signed(body, b"audit-finding", &as_observer),
                &roster_with,
                &roster_with,
                committee_key
            ),
            Err(Error::NotRegistered)
        );
        // A signature under another key does not bind.
        let forged = [
            who[0],
            (&b"aud-2"[..], EventRole::Auditor, &b"AUDIT-B"[..], aud_1.1),
            who[2],
            who[3],
        ];
        assert_eq!(
            check_audit_signers(
                &signed(body, b"audit-finding", &forged),
                &roster,
                &roster,
                committee_key
            ),
            Err(Error::SignatureSigner)
        );
    }

    #[test]
    fn audit_signers_may_sign_under_an_earlier_key_and_the_committee_under_its_own() {
        let aud_1 = person(b"aud-1", RosterRole::Auditor, b"AUDIT-A", 80);
        let aud_2 = person(b"aud-2", RosterRole::Auditor, b"AUDIT-B", 82);
        let obs_a = person(b"obs-a", RosterRole::Observer, b"PARTY-A", 84);
        let obs_b = person(b"obs-b", RosterRole::Observer, b"PARTY-B", 86);
        let roster = [aud_1.0, aud_2.0, obs_a.0, obs_b.0];
        let (committee_sk, committee_key) = key(90);
        let body = finding();
        let who = [
            (&b"aud-1"[..], EventRole::Auditor, &b"AUDIT-A"[..], aud_1.1),
            (b"aud-2", EventRole::Auditor, b"AUDIT-B", aud_2.1),
            (b"obs-a", EventRole::Observer, b"PARTY-A", obs_a.1),
            (b"obs-b", EventRole::Observer, b"PARTY-B", obs_b.1),
        ];
        // A key of an earlier state binds when `keys` holds it, and the
        // signer is still on the roster in force.
        let aud_2_before = person(b"aud-2", RosterRole::Auditor, b"AUDIT-B", 94);
        let old = [
            who[0],
            (
                &b"aud-2"[..],
                EventRole::Auditor,
                &b"AUDIT-B"[..],
                aud_2_before.1,
            ),
            who[2],
            who[3],
        ];
        let old = signed(body, b"audit-finding", &old);
        let keys = [aud_1.0, aud_2_before.0, obs_a.0, obs_b.0];
        assert_eq!(
            check_audit_signers(&old, &roster, &keys, committee_key),
            Ok(())
        );
        assert_eq!(
            check_audit_signers(&old, &roster, &roster, committee_key),
            Err(Error::SignatureSigner)
        );
        let gone = [aud_1.0, obs_a.0, obs_b.0];
        assert_eq!(
            check_audit_signers(&old, &gone, &keys, committee_key),
            Err(Error::NotRegistered)
        );
        // A key entry of another role does not bind.
        let as_clerk_before = person(b"aud-2", RosterRole::Clerk, b"AUDIT-B", 94);
        assert_eq!(
            check_audit_signers(
                &old,
                &roster,
                &[aud_1.0, as_clerk_before.0, obs_a.0, obs_b.0],
                committee_key
            ),
            Err(Error::NotRegistered)
        );
        // The committee signs with the genesis key, not a roster entry.
        let freeze_body = finding_like_freeze();
        let committee_who = [
            (
                &b"committee"[..],
                EventRole::Committee,
                &b"IVC"[..],
                committee_sk,
            ),
            who[2],
            who[3],
        ];
        let committee_signed = signed(freeze_body, b"audit-freeze", &committee_who);
        assert_eq!(
            check_audit_signers(&committee_signed, &roster, &roster, committee_key),
            Ok(())
        );
        let (_, other_key) = key(96);
        assert_eq!(
            check_audit_signers(&committee_signed, &roster, &roster, other_key),
            Err(Error::SignatureSigner)
        );
        // Roles an audit event never has.
        let chair = person(b"chair", RosterRole::Chair, b"NEC-1", 98);
        let hand = hand_object(b"RU-1");
        let chair_who = [
            (&b"chair"[..], EventRole::Chair, &b"NEC-1"[..], chair.1),
            who[2],
            who[3],
        ];
        let roster_chair = [chair.0, obs_a.0, obs_b.0];
        assert_eq!(
            check_audit_signers(
                &signed(hand, b"hand-count", &chair_who),
                &roster_chair,
                &roster_chair,
                committee_key
            ),
            Err(Error::NotRegistered)
        );
    }

    fn finding_like_freeze() -> &'static [u8] {
        let rounds = ityv_encoding::AuditRounds::new(&[ityv_encoding::AuditRound {
            sample_size: 2,
            threshold: 0,
        }])
        .unwrap();
        object(
            ityv_encoding::SCHEMA_AUDIT_FREEZE_BODY,
            &ityv_encoding::AuditManifestFreezeBody::new(&ityv_encoding::AuditFreezeParts {
                election_id: ElectionId::new(b"E1").unwrap(),
                ballot_style_id: BallotStyleId::new(b"S-1").unwrap(),
                frame_count: 3,
                frame_root: Hash512([5; 64]),
                rule_hash: Hash512([6; 64]),
                risk_limit_ppm: 10_000,
                beacon_source: Hash512([7; 64]),
                beacon_round: 1,
                rounds,
                time_bucket: TimeBucket::new(1),
            })
            .unwrap(),
        )
    }

    fn hand_parts(unit: &'static [u8]) -> PaperCountParts<'static> {
        PaperCountParts {
            election_id: ElectionId::new(b"E1").unwrap(),
            reporting_unit_id: ReportingUnitId::new(unit).unwrap(),
            ballot_style_id: BallotStyleId::new(b"S-1").unwrap(),
            votes: PaperVotes::new(&[3, 1]).unwrap(),
            invalid: 1,
            time_bucket: TimeBucket::new(5),
        }
    }

    fn hand_object(unit: &'static [u8]) -> &'static [u8] {
        object(
            SCHEMA_HAND_COUNT_REPORT_BODY,
            &HandCountReportBody::new(&hand_parts(unit)).unwrap(),
        )
    }

    fn unit_of(id: &'static [u8]) -> Entry<ReportingUnitEntry<'static>> {
        Entry::unproved(
            ReportingUnitEntry::new(
                ReportingUnitId::new(id).unwrap(),
                1,
                OrgId::new(b"NEC-1").unwrap(),
            )
            .unwrap(),
        )
    }

    #[test]
    fn a_hand_count_is_bound_like_a_paper_count() {
        let chair = person(b"chair", RosterRole::Chair, b"NEC-1", 100);
        let obs_a = person(b"obs-a", RosterRole::Observer, b"PARTY-A", 102);
        let obs_b = person(b"obs-b", RosterRole::Observer, b"PARTY-B", 104);
        let roster = [chair.0, obs_a.0, obs_b.0];
        let who = [
            (&b"chair"[..], EventRole::Chair, &b"NEC-1"[..], chair.1),
            (b"obs-a", EventRole::Observer, b"PARTY-A", obs_a.1),
            (b"obs-b", EventRole::Observer, b"PARTY-B", obs_b.1),
        ];
        let ok = signed(hand_object(b"RU-1"), b"hand-count", &who);
        let taken = HandCount::check(&ok, &roster, &roster, &unit_of(b"RU-1")).unwrap();
        assert_eq!(taken.parts(), &hand_parts(b"RU-1"));
        assert_eq!(
            HandCount::check(&ok, &roster, &roster, &unit_of(b"RU-2")),
            Err(Error::Mismatch)
        );
        // A paper count is not a hand count.
        let paper = object(
            SCHEMA_PAPER_COUNT_REPORT_BODY,
            &PaperCountReportBody::new(&hand_parts(b"RU-1")).unwrap(),
        );
        let paper = signed(paper, b"paper-count", &who);
        assert_eq!(
            HandCount::check(&paper, &roster, &roster, &unit_of(b"RU-1")),
            Err(Error::Decode)
        );
        // The chair of another commission does not bind.
        let other = person(b"chair-2", RosterRole::Chair, b"NEC-2", 106);
        let other_who = [
            (&b"chair-2"[..], EventRole::Chair, &b"NEC-2"[..], other.1),
            who[1],
            who[2],
        ];
        let roster2 = [other.0, obs_a.0, obs_b.0];
        assert_eq!(
            HandCount::check(
                &signed(hand_object(b"RU-1"), b"hand-count", &other_who),
                &roster2,
                &roster2,
                &unit_of(b"RU-1")
            ),
            Err(Error::NotRegistered)
        );
    }

    use ityv_encoding::{AuditRound, AuditRounds, ComparisonCode, MAX_AUDIT_ROUNDS};

    use super::{AuditPhase, FollowUp, RoundCount, audit_phase, follow_up};

    fn count(compared: u64, nonzero: u64) -> RoundCount {
        RoundCount { compared, nonzero }
    }

    fn counts(list: &[RoundCount]) -> [RoundCount; MAX_AUDIT_ROUNDS] {
        let mut out = [RoundCount::default(); MAX_AUDIT_ROUNDS];
        out[..list.len()].copy_from_slice(list);
        out
    }

    fn rule() -> AuditRounds {
        AuditRounds::new(&[
            AuditRound {
                sample_size: 3,
                threshold: 0,
            },
            AuditRound {
                sample_size: 6,
                threshold: 1,
            },
        ])
        .unwrap()
    }

    #[test]
    fn a_round_concludes_when_compared_within_its_threshold() {
        let r = rule();
        let phase = |list: &[RoundCount], frame| audit_phase(&r, frame, &counts(list));
        assert_eq!(phase(&[], 10), AuditPhase::Sampling { round: 0 });
        assert_eq!(
            phase(&[count(2, 0), count(2, 0)], 10),
            AuditPhase::Sampling { round: 0 }
        );
        assert_eq!(
            phase(&[count(3, 0), count(3, 0)], 10),
            AuditPhase::Concluded { round: 0 }
        );
        // One discrepancy escalates at once, before the round is compared.
        assert_eq!(
            phase(&[count(1, 1), count(1, 1)], 10),
            AuditPhase::Sampling { round: 1 }
        );
        assert_eq!(
            phase(&[count(3, 1), count(6, 1)], 10),
            AuditPhase::Concluded { round: 1 }
        );
        assert_eq!(
            phase(&[count(3, 1), count(5, 1)], 10),
            AuditPhase::Sampling { round: 1 }
        );
        assert_eq!(
            phase(&[count(2, 2), count(2, 2)], 10),
            AuditPhase::HandCount
        );
        // The sample is never larger than the frame.
        assert_eq!(
            phase(&[count(2, 0), count(2, 0)], 2),
            AuditPhase::Concluded { round: 0 }
        );
        assert_eq!(phase(&[], 0), AuditPhase::Concluded { round: 0 });
        assert_eq!(
            phase(&[count(1, 1), count(4, 1)], 4),
            AuditPhase::Concluded { round: 1 }
        );
    }

    #[test]
    fn the_follow_up_of_each_code() {
        let all = [
            (ComparisonCode::Match, FollowUp::Nothing),
            (ComparisonCode::OtherCandidate, FollowUp::FullComparison),
            (ComparisonCode::CandidateInvalid, FollowUp::FullComparison),
            (ComparisonCode::UnreadableValid, FollowUp::Rate),
            (ComparisonCode::BlankValid, FollowUp::Rate),
            (ComparisonCode::BallotMissing, FollowUp::Custody),
            (ComparisonCode::ImprintMismatch, FollowUp::Custody),
        ];
        for (code, expected) in all {
            assert_eq!(follow_up(code), expected, "{code:?}");
            assert_eq!(
                follow_up(code).is_discrepancy(),
                code != ComparisonCode::Match,
                "{code:?}"
            );
        }
    }
}
