//! Connectivity incidents (PROTOCOL.md §5.8 item 10; ADR-0022 decision
//! 11, ADR-0041 decision 11; VC-083).
//!
//! [`check_incident_signers`] binds the signatures of a
//! `ConnectivityIncident` to the genesis: the committee under the key of
//! the genesis body, every clerk and observer under the key the roster
//! registers for that signer, role and organisation. The envelope already
//! admits exactly the two signer sets (`ityv_encoding::roles_satisfied`):
//! two clerks and observers of two organisations for a finding on site, or
//! the committee and observers of two organisations for one made afterwards
//! (a capture or carrier comparison, a teardown).
//!
//! What this module does not decide: which boxes the incident holds and
//! whether its box and station exist (`ityv-verify`'s connectivity stage),
//! or whether its statement is true (the people who sign it say so).

use ityv_encoding::{EventRole, RosterRole, SCHEMA_CONNECTIVITY_INCIDENT_BODY};

use crate::close::{RosterEntry, roster_key};
use crate::error::Error;
use crate::sig::{Key, Signed, check_event};
use crate::tally::signing_key;

/// Checks the people of a connectivity incident: every signer is the
/// committee (under `committee`, the genesis key) or registered in `roster`
/// (the genesis state in force at the event's frame) as a clerk or an
/// observer of the organisation the signature names, with a matching token
/// from the key of `keys` registered for the same signer, role and
/// organisation (of the state in force or an earlier one, as the caller
/// found it).
///
/// # Errors
/// [`Error::Decode`] if the event does not carry an incident body,
/// [`Error::NotRegistered`] for a signer of another role or one the roster
/// does not register in that role and organisation or `keys` does not
/// hold, [`Error::StaleEntry`] for a roster of mixed genesis states, and
/// the errors of [`crate::sig::check_event`].
pub fn check_incident_signers(
    signed: &Signed<'_>,
    roster: &[RosterEntry<'_>],
    keys: &[RosterEntry<'_>],
    committee: &Key,
) -> Result<(), Error> {
    if signed.event.body_schema() != SCHEMA_CONNECTIVITY_INCIDENT_BODY {
        return Err(Error::Decode);
    }
    check_event(signed, |s| {
        let role = match s.role {
            EventRole::Committee => return Ok(committee),
            EventRole::Clerk => RosterRole::Clerk,
            EventRole::Observer => RosterRole::Observer,
            EventRole::Commission
            | EventRole::Sender
            | EventRole::Receiver
            | EventRole::Authority
            | EventRole::Device
            | EventRole::Chair
            | EventRole::Auditor
            | EventRole::RollSource
            | EventRole::RollCustodian => return Err(Error::NotRegistered),
        };
        roster_key(roster, s.signer_id, role, s.org_id)?;
        signing_key(keys, s, role)
    })
}

#[cfg(test)]
mod tests {
    use ityv_crypto::{HybridSigningKey, Purpose, sign_hybrid, verify_hybrid};
    use ityv_encoding::{
        AuditFindingBody, AuditFindingParts, BallotStyleId, BoxId, ConnectivityIncidentBody,
        ConnectivityIncidentParts, ElectionId, EventRole, EventSig, HYBRID_SIG_LEN, Hash512,
        IncidentKind, OrgId, RosterRole, RosterSigner, SCHEMA_AUDIT_FINDING_BODY,
        SCHEMA_CONNECTIVITY_INCIDENT_BODY, SCHEMA_VERSION_1, SignerId, StationId, TimeBucket,
        WitnessedEvent, encode_object,
    };
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;
    use std::boxed::Box;
    use std::vec::Vec;

    use super::check_incident_signers;
    use crate::close::RosterEntry;
    use crate::error::Error;
    use crate::genesis::Entry;
    use crate::sig::{Key, Signed};

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

    fn incident() -> &'static [u8] {
        object(
            SCHEMA_CONNECTIVITY_INCIDENT_BODY,
            &ConnectivityIncidentBody::new(&ConnectivityIncidentParts {
                election_id: ElectionId::new(b"E1").unwrap(),
                station_id: Some(StationId::new(b"ST-1").unwrap()),
                box_id: None,
                kind: IncidentKind::UndeclaredConnection,
                from_slot: 3,
                to_slot: 4,
                commitment_unit: false,
                evidence_hash: Hash512([5; 64]),
            })
            .unwrap(),
        )
    }

    #[test]
    #[allow(clippy::too_many_lines)] // One scenario per signer rule.
    fn incident_signers_are_bound_to_the_roster_and_the_committee() {
        let clerk_1 = person(b"clerk-1", RosterRole::Clerk, b"NEC", 60);
        let clerk_2 = person(b"clerk-2", RosterRole::Clerk, b"NEC", 62);
        let obs_a = person(b"obs-a", RosterRole::Observer, b"PARTY-A", 64);
        let obs_b = person(b"obs-b", RosterRole::Observer, b"PARTY-B", 66);
        let roster = [clerk_1.0, clerk_2.0, obs_a.0, obs_b.0];
        let (committee_sk, committee_key) = key(70);
        let body = incident();
        let observers = [
            (&b"obs-a"[..], EventRole::Observer, &b"PARTY-A"[..], obs_a.1),
            (b"obs-b", EventRole::Observer, b"PARTY-B", obs_b.1),
        ];
        let purpose = b"connectivity-incident";
        // On site: two clerks and two observers.
        let on_site = [
            (&b"clerk-1"[..], EventRole::Clerk, &b"NEC"[..], clerk_1.1),
            (b"clerk-2", EventRole::Clerk, b"NEC", clerk_2.1),
            observers[0],
            observers[1],
        ];
        assert_eq!(
            check_incident_signers(
                &signed(body, purpose, &on_site),
                &roster,
                &roster,
                committee_key
            ),
            Ok(())
        );
        // Afterwards: the committee and two observers.
        let after = [
            (
                &b"committee"[..],
                EventRole::Committee,
                &b"IVC"[..],
                committee_sk,
            ),
            observers[0],
            observers[1],
        ];
        let after = signed(body, purpose, &after);
        assert_eq!(
            check_incident_signers(&after, &roster, &roster, committee_key),
            Ok(())
        );
        // The committee signs under the genesis key, nothing else.
        let (_, other_key) = key(72);
        assert_eq!(
            check_incident_signers(&after, &roster, &roster, other_key),
            Err(Error::SignatureSigner)
        );
        // A clerk must be registered as a clerk, an observer as an observer.
        let as_clerk = [
            (&b"obs-a"[..], EventRole::Clerk, &b"PARTY-A"[..], obs_a.1),
            on_site[1],
            observers[1],
            (&b"obs-c"[..], EventRole::Observer, &b"PARTY-C"[..], obs_b.1),
        ];
        assert_eq!(
            check_incident_signers(
                &signed(body, purpose, &as_clerk),
                &roster,
                &roster,
                committee_key
            ),
            Err(Error::NotRegistered)
        );
        let clerk_3 = person(b"clerk-3", RosterRole::Clerk, b"NEC", 68);
        let with_third = [clerk_1.0, clerk_2.0, clerk_3.0, obs_a.0, obs_b.0];
        let as_observer = [
            on_site[0],
            (&b"clerk-3"[..], EventRole::Clerk, &b"NEC"[..], clerk_3.1),
            (&b"clerk-2"[..], EventRole::Observer, &b"NEC"[..], clerk_2.1),
            observers[1],
        ];
        assert_eq!(
            check_incident_signers(
                &signed(body, purpose, &as_observer),
                &with_third,
                &with_third,
                committee_key
            ),
            Err(Error::NotRegistered)
        );
        // Another body is not an incident.
        let finding = object(
            SCHEMA_AUDIT_FINDING_BODY,
            &AuditFindingBody::new(&AuditFindingParts {
                election_id: ElectionId::new(b"E1").unwrap(),
                ballot_style_id: BallotStyleId::new(b"S-1").unwrap(),
                device_id: BoxId::new(b"BOX-1").unwrap(),
                finding_hash: Hash512([4; 64]),
                time_bucket: TimeBucket::new(1),
            })
            .unwrap(),
        );
        let auditor_a = person(b"aud-a", RosterRole::Auditor, b"AUD-A", 74);
        let auditor_b = person(b"aud-b", RosterRole::Auditor, b"AUD-B", 76);
        let audited = signed(
            finding,
            b"audit-finding",
            &[
                (
                    &b"aud-a"[..],
                    EventRole::Auditor,
                    &b"AUD-A"[..],
                    auditor_a.1,
                ),
                (b"aud-b", EventRole::Auditor, b"AUD-B", auditor_b.1),
                observers[0],
                observers[1],
            ],
        );
        let with_auditors = [auditor_a.0, auditor_b.0, obs_a.0, obs_b.0];
        assert_eq!(
            check_incident_signers(&audited, &with_auditors, &with_auditors, committee_key),
            Err(Error::Decode)
        );
    }
}
