//! Voter-roll custody (PROTOCOL.md §6.1; ADR-0033, ADR-0040; VC-107,
//! VC-108, VC-111).
//!
//! This module binds the signatures of the four roll events to the keys the
//! genesis registers, and decides the custody quorum:
//!
//! * [`admit_extract`]: a source extract is signed by the one source it
//!   names, whose function is the extract's kind (VC-107);
//! * [`admit_freeze`]: the freeze is signed by the commission and the
//!   committee under the genesis body's keys;
//! * [`admit_receipt`]: a custody receipt is signed by the one custodian it
//!   names;
//! * [`admit_amendment`]: an amendment is signed by the commission, the
//!   committee and the source its reason needs (VC-111);
//! * [`custody_quorum`]: the distinct custodians that confirmed one roll
//!   state reach the genesis's quorum and include the court administration
//!   and the Ministry of the Interior (VC-108).
//!
//! A roll authority is taken only as an [`Entry`] proved against a pinned
//! genesis (the fixed set 13). What this module does not decide: whether
//! the extracts merge into the freeze, whether a receipt's values are its
//! subject's, the order of events on the ledger (the verifier's,
//! `ityv-verify`'s roll stage).

use ityv_encoding::{
    EventRole, RollAmendmentBody, RollAuthorityEntry, RollAuthorityKind, RollCustodyReceiptBody,
    RollSourceExtractBody, SCHEMA_ROLL_AMENDMENT_BODY, SCHEMA_ROLL_CUSTODY_RECEIPT_BODY,
    SCHEMA_ROLL_FREEZE_BODY, SCHEMA_ROLL_SOURCE_EXTRACT_BODY,
};

use crate::error::Error;
use crate::genesis::Entry;
use crate::sig::{Key, Signed, check_event};

/// The key of `authority` for a signature in `role` naming `signer` of
/// `org`: the entry's own, when the identifier and organisation are the
/// entry's and its function fits the role (a source signs as a roll
/// source, a custodian as a custodian).
fn authority_key<'k>(
    authority: &'k Entry<RollAuthorityEntry<'_>>,
    role: EventRole,
    signer: &[u8],
    org: &[u8],
) -> Result<&'k Key, Error> {
    let a = authority.get();
    let role_fits = match role {
        EventRole::RollSource => !a.kind.is_custodian(),
        EventRole::RollCustodian => a.kind.is_custodian(),
        EventRole::Clerk
        | EventRole::Observer
        | EventRole::Commission
        | EventRole::Committee
        | EventRole::Sender
        | EventRole::Receiver
        | EventRole::Authority
        | EventRole::Device
        | EventRole::Chair
        | EventRole::Auditor => false,
    };
    if role_fits && a.authority_id.as_bytes() == signer && a.org_id.as_bytes() == org {
        Ok(a.key)
    } else {
        Err(Error::NotRegistered)
    }
}

/// Checks every signature of `signed` with the commission's and the
/// committee's keys of the genesis body, when the event takes them, and the
/// key of `authority` for the other role.
fn check_signers(
    signed: &Signed<'_>,
    bodies: Option<(&Key, &Key)>,
    authority: Option<&Entry<RollAuthorityEntry<'_>>>,
) -> Result<(), Error> {
    check_event(signed, |s| match s.role {
        EventRole::Commission => bodies.map(|(c, _)| c).ok_or(Error::NotRegistered),
        EventRole::Committee => bodies.map(|(_, c)| c).ok_or(Error::NotRegistered),
        role @ (EventRole::RollSource | EventRole::RollCustodian) => {
            let authority = authority.ok_or(Error::NotRegistered)?;
            authority_key(authority, role, s.signer_id.as_bytes(), s.org_id.as_bytes())
        }
        EventRole::Clerk
        | EventRole::Observer
        | EventRole::Sender
        | EventRole::Receiver
        | EventRole::Authority
        | EventRole::Device
        | EventRole::Chair
        | EventRole::Auditor => Err(Error::NotRegistered),
    })
}

/// Admits a source extract signed by `source`: the body names `source`,
/// whose function is the one that signs the extract's kind, and the one
/// signature is `source`'s (VC-107).
///
/// # Errors
/// [`Error::Decode`] for another body, [`Error::NotRegistered`] for an
/// extract of another source or kind, and the errors of
/// [`crate::sig::check_event`].
pub fn admit_extract(
    signed: &Signed<'_>,
    source: &Entry<RollAuthorityEntry<'_>>,
) -> Result<(), Error> {
    let body: RollSourceExtractBody<'_> = signed
        .event
        .body(SCHEMA_ROLL_SOURCE_EXTRACT_BODY)
        .map_err(|_| Error::Decode)?;
    let p = body.parts();
    let a = source.get();
    if p.authority_id.as_bytes() != a.authority_id.as_bytes() || p.kind.authority() != a.kind {
        return Err(Error::NotRegistered);
    }
    check_signers(signed, None, Some(source))
}

/// Admits the roll freeze: signed by the commission and the committee under
/// the keys of the genesis body (PROTOCOL.md Appendix A).
///
/// # Errors
/// [`Error::Decode`] for another body and the errors of
/// [`crate::sig::check_event`].
pub fn admit_freeze(signed: &Signed<'_>, commission: &Key, committee: &Key) -> Result<(), Error> {
    if signed.event.body_schema() != SCHEMA_ROLL_FREEZE_BODY {
        return Err(Error::Decode);
    }
    check_signers(signed, Some((commission, committee)), None)
}

/// Admits a custody receipt signed by `custodian`: the body names it and
/// the one signature is its.
///
/// # Errors
/// [`Error::Decode`] for another body, [`Error::NotRegistered`] for a
/// receipt naming another custodian or an authority that is no custodian,
/// and the errors of [`crate::sig::check_event`].
pub fn admit_receipt(
    signed: &Signed<'_>,
    custodian: &Entry<RollAuthorityEntry<'_>>,
) -> Result<(), Error> {
    let body: RollCustodyReceiptBody<'_> = signed
        .event
        .body(SCHEMA_ROLL_CUSTODY_RECEIPT_BODY)
        .map_err(|_| Error::Decode)?;
    let a = custodian.get();
    if body.parts().custodian.as_bytes() != a.authority_id.as_bytes() || !a.kind.is_custodian() {
        return Err(Error::NotRegistered);
    }
    check_signers(signed, None, Some(custodian))
}

/// Admits a roll amendment: signed by the commission, the committee and
/// `source`, which the body names and whose function is the one its reason
/// needs (an objection decision its district head, an appeal the court, a
/// death the court administration, VC-111).
///
/// # Errors
/// [`Error::Decode`] for another body, [`Error::NotRegistered`] for a source
/// of another function or identifier, and the errors of
/// [`crate::sig::check_event`].
pub fn admit_amendment(
    signed: &Signed<'_>,
    commission: &Key,
    committee: &Key,
    source: &Entry<RollAuthorityEntry<'_>>,
) -> Result<(), Error> {
    let body: RollAmendmentBody<'_> = signed
        .event
        .body(SCHEMA_ROLL_AMENDMENT_BODY)
        .map_err(|_| Error::Decode)?;
    let p = body.parts();
    let a = source.get();
    if p.authority_id.as_bytes() != a.authority_id.as_bytes() || p.reason.source() != a.kind {
        return Err(Error::NotRegistered);
    }
    check_signers(signed, Some((commission, committee)), Some(source))
}

/// Whether the custodians that confirmed one roll state, `kinds` (one per
/// distinct custodian), reach `quorum` and include the court
/// administration and the Ministry of the Interior (PROTOCOL.md §6.1,
/// VC-108; `LEGAL_ANNEX.md` amendment 14, §44-3 ④). Kinds that are no
/// custodian's are not counted.
#[must_use]
pub fn custody_quorum(kinds: &[RollAuthorityKind], quorum: u8) -> bool {
    let custodians = kinds.iter().filter(|k| k.is_custodian()).count();
    let has = |kind| kinds.contains(&kind);
    custodians >= usize::from(quorum)
        && has(RollAuthorityKind::CustodianJudiciary)
        && has(RollAuthorityKind::CustodianInterior)
}

#[cfg(test)]
mod tests {
    use ityv_crypto::{HybridSigningKey, Purpose, sign_hybrid, verify_hybrid};
    use ityv_encoding::{
        AuthorityId, Day, ElectionId, EventRole, EventSig, HYBRID_SIG_LEN, HYBRID_VK_LEN, Hash512,
        OrgId, RollAmendmentBody, RollAmendmentParts, RollAmendmentReason, RollAuthorityEntry,
        RollAuthorityKind as K, RollCustodyReceiptBody, RollCustodyReceiptParts, RollFreezeBody,
        RollFreezeParts, RollSourceExtractBody, RollSourceExtractParts, RollSourceKind, RollState,
        SCHEMA_ROLL_AMENDMENT_BODY, SCHEMA_ROLL_CUSTODY_RECEIPT_BODY, SCHEMA_ROLL_FREEZE_BODY,
        SCHEMA_ROLL_SOURCE_EXTRACT_BODY, SCHEMA_VERSION_1, SchemaId, SignerId, StationId,
        TimeBucket, WitnessedEvent, encode_object,
    };
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;
    use std::boxed::Box;
    use std::vec::Vec;

    use super::{admit_amendment, admit_extract, admit_freeze, admit_receipt, custody_quorum};
    use crate::error::Error;
    use crate::genesis::Entry;
    use crate::sig::{Key, Signed};

    #[test]
    fn the_quorum_needs_its_number_and_both_branches() {
        let full = [
            K::CustodianJudiciary,
            K::CustodianInterior,
            K::CustodianCommittee,
        ];
        assert!(custody_quorum(&full, 3));
        assert!(!custody_quorum(&full, 4));
        assert!(custody_quorum(&full, 2));
        assert!(!custody_quorum(
            &[
                K::CustodianInterior,
                K::CustodianCommittee,
                K::CustodianParty
            ],
            3
        ));
        assert!(!custody_quorum(
            &[
                K::CustodianJudiciary,
                K::CustodianCommittee,
                K::CustodianParty
            ],
            3
        ));
        // A source's kind is not a custodian's.
        assert!(!custody_quorum(
            &[K::CustodianJudiciary, K::CustodianInterior, K::Deaths],
            3
        ));
        assert!(custody_quorum(
            &[
                K::CustodianJudiciary,
                K::CustodianInterior,
                K::CustodianParty,
                K::CustodianParty
            ],
            4
        ));
        assert!(!custody_quorum(&[], 0));
    }

    fn key(seed: u8) -> (&'static HybridSigningKey, &'static Key) {
        let sk = Box::leak(Box::new(HybridSigningKey::from_seeds(
            [seed; 32],
            [seed.wrapping_add(1); 32],
        )));
        let vk = sk.verifying_key();
        let mut bytes = [0u8; HYBRID_VK_LEN];
        let (ml, ed) = bytes.split_at_mut(ityv_encoding::MLDSA87_VK_HALF);
        ml.copy_from_slice(vk.mldsa87());
        ed.copy_from_slice(vk.ed25519());
        (sk, Box::leak(Box::new(bytes)))
    }

    fn authority(
        id: &'static [u8],
        org: &'static [u8],
        kind: K,
        seed: u8,
    ) -> (
        Entry<RollAuthorityEntry<'static>>,
        &'static HybridSigningKey,
    ) {
        let (sk, vk) = key(seed);
        let entry = Entry::unproved(RollAuthorityEntry {
            authority_id: AuthorityId::new(id).unwrap(),
            org_id: OrgId::new(org).unwrap(),
            kind,
            key: vk,
        });
        (entry, sk)
    }

    type Who = (
        &'static [u8],
        EventRole,
        &'static [u8],
        &'static HybridSigningKey,
    );

    /// The event over `body` signed by `who`, with its tokens.
    fn signed(body: &'static [u8], purpose: &'static [u8], who: &[Who]) -> Signed<'static> {
        let mut rng = ChaCha20Rng::seed_from_u64(23);
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

    fn object<T: ityv_encoding::Encode>(schema: SchemaId, value: &T) -> &'static [u8] {
        let mut buf = std::vec![0u8; value.encoded_len().saturating_add(16)];
        let n = encode_object(schema, SCHEMA_VERSION_1, value, &mut buf).unwrap();
        buf.truncate(n);
        Box::leak(buf.into_boxed_slice())
    }

    fn e() -> ElectionId<'static> {
        ElectionId::new(b"E1").unwrap()
    }

    fn state() -> RollState {
        RollState {
            entries_root: Hash512([1; 64]),
            entry_count: 10,
            counts_hash: Hash512([2; 64]),
            pseudonym_root: Hash512([3; 64]),
        }
    }

    fn extract(id: &'static [u8], kind: RollSourceKind) -> &'static [u8] {
        let precinct =
            (kind == RollSourceKind::Residents).then(|| StationId::new(b"ST-1").unwrap());
        object(
            SCHEMA_ROLL_SOURCE_EXTRACT_BODY,
            &RollSourceExtractBody::new(&RollSourceExtractParts {
                election_id: e(),
                authority_id: AuthorityId::new(id).unwrap(),
                kind,
                precinct,
                reference_day: Day::new(1),
                entry_count: 10,
                entries_root: Hash512([4; 64]),
            })
            .unwrap(),
        )
    }

    fn receipt(custodian: &'static [u8]) -> &'static [u8] {
        object(
            SCHEMA_ROLL_CUSTODY_RECEIPT_BODY,
            &RollCustodyReceiptBody::new(&RollCustodyReceiptParts {
                election_id: e(),
                custodian: AuthorityId::new(custodian).unwrap(),
                subject_hash: Hash512([5; 64]),
                entries_root: Hash512([1; 64]),
                entry_count: 10,
                counts_hash: Hash512([2; 64]),
                sources_root: None,
                pseudonym_root: None,
                time_bucket: TimeBucket::new(1),
            })
            .unwrap(),
        )
    }

    fn amendment(id: &'static [u8], reason: RollAmendmentReason) -> &'static [u8] {
        object(
            SCHEMA_ROLL_AMENDMENT_BODY,
            &RollAmendmentBody::new(&RollAmendmentParts {
                election_id: e(),
                seq: 1,
                previous_hash: Hash512([5; 64]),
                reason,
                authority_id: AuthorityId::new(id).unwrap(),
                basis_hash: Hash512([6; 64]),
                state: state(),
                time_bucket: TimeBucket::new(2),
            })
            .unwrap(),
        )
    }

    #[test]
    fn an_extract_is_its_source_s_alone() {
        let (gu, gu_sk) = authority(b"GU-1", b"JONGNO", K::ResidentExtract, 10);
        let (deaths, deaths_sk) = authority(b"DEATHS", b"COURT-ADMIN", K::Deaths, 12);
        let (other_sk, _) = key(14);
        let body = extract(b"GU-1", RollSourceKind::Residents);
        let by = |who: Who| signed(body, b"roll-source", &[who]);
        let ok = by((b"GU-1", EventRole::RollSource, b"JONGNO", gu_sk));
        assert_eq!(admit_extract(&ok, &gu), Ok(()));
        // Under another source's entry: the body names GU-1.
        assert_eq!(admit_extract(&ok, &deaths), Err(Error::NotRegistered));
        // Another signer, another organisation, another key.
        let other_signer = by((b"GU-2", EventRole::RollSource, b"JONGNO", gu_sk));
        assert_eq!(admit_extract(&other_signer, &gu), Err(Error::NotRegistered));
        let other_org = by((b"GU-1", EventRole::RollSource, b"MAPO", gu_sk));
        assert_eq!(admit_extract(&other_org, &gu), Err(Error::NotRegistered));
        let other_key = by((b"GU-1", EventRole::RollSource, b"JONGNO", other_sk));
        assert_eq!(admit_extract(&other_key, &gu), Err(Error::SignatureSigner));
        // Another district head signs, as itself, an extract naming GU-1.
        let (mapo, mapo_sk) = authority(b"GU-2", b"MAPO", K::ResidentExtract, 18);
        let as_other_head = by((b"GU-2", EventRole::RollSource, b"MAPO", mapo_sk));
        assert_eq!(
            admit_extract(&as_other_head, &mapo),
            Err(Error::NotRegistered)
        );
        // A list of deaths is the court administration's, not a district
        // head's: a district head's entry may not sign one.
        let deaths_by_gu = signed(
            extract(b"GU-1", RollSourceKind::Deaths),
            b"roll-source",
            &[(b"GU-1", EventRole::RollSource, b"JONGNO", gu_sk)],
        );
        assert_eq!(admit_extract(&deaths_by_gu, &gu), Err(Error::NotRegistered));
        let by_deaths = signed(
            extract(b"DEATHS", RollSourceKind::Deaths),
            b"roll-source",
            &[(b"DEATHS", EventRole::RollSource, b"COURT-ADMIN", deaths_sk)],
        );
        assert_eq!(admit_extract(&by_deaths, &deaths), Ok(()));
        // A custodian's entry signs no extract, even of its own name.
        let (custodian, custodian_sk) = authority(b"GU-1", b"JONGNO", K::CustodianJudiciary, 16);
        let as_custodian = by((b"GU-1", EventRole::RollSource, b"JONGNO", custodian_sk));
        assert_eq!(
            admit_extract(&as_custodian, &custodian),
            Err(Error::NotRegistered)
        );
        // Another body is not an extract.
        let not_extract = signed(
            receipt(b"GU-1"),
            b"roll-receipt",
            &[(b"GU-1", EventRole::RollCustodian, b"JONGNO", gu_sk)],
        );
        assert_eq!(admit_extract(&not_extract, &gu), Err(Error::Decode));
    }

    #[test]
    fn a_freeze_is_the_commission_s_and_the_committee_s() {
        let (commission_sk, commission) = key(20);
        let (committee_sk, committee) = key(22);
        let body = object(
            SCHEMA_ROLL_FREEZE_BODY,
            &RollFreezeBody::new(&RollFreezeParts {
                election_id: e(),
                state: state(),
                sources_root: Hash512([7; 64]),
                source_count: 1,
                time_bucket: TimeBucket::new(1),
            })
            .unwrap(),
        );
        let ok = signed(
            body,
            b"roll-freeze",
            &[
                (b"a-nec", EventRole::Commission, b"NEC", commission_sk),
                (b"b-ivc", EventRole::Committee, b"IVC", committee_sk),
            ],
        );
        assert_eq!(admit_freeze(&ok, commission, committee), Ok(()));
        assert_eq!(
            admit_freeze(&ok, committee, commission),
            Err(Error::SignatureSigner)
        );
        let not_freeze = signed(
            amendment(b"DEATHS", RollAmendmentReason::Death),
            b"roll-amendment",
            &[
                (b"a-nec", EventRole::Commission, b"NEC", commission_sk),
                (b"b-ivc", EventRole::Committee, b"IVC", committee_sk),
                (
                    b"c-src",
                    EventRole::RollSource,
                    b"COURT-ADMIN",
                    commission_sk,
                ),
            ],
        );
        assert_eq!(
            admit_freeze(&not_freeze, commission, committee),
            Err(Error::Decode)
        );
    }

    #[test]
    fn a_receipt_is_its_custodian_s_alone() {
        let (jud, jud_sk) = authority(b"ROLL-JUD", b"COURT-ADMIN", K::CustodianJudiciary, 30);
        let (int, int_sk) = authority(b"ROLL-INT", b"MOIS", K::CustodianInterior, 32);
        let (deaths, deaths_sk) = authority(b"ROLL-JUD", b"COURT-ADMIN", K::Deaths, 34);
        let body = receipt(b"ROLL-JUD");
        let ok = signed(
            body,
            b"roll-receipt",
            &[(
                b"ROLL-JUD",
                EventRole::RollCustodian,
                b"COURT-ADMIN",
                jud_sk,
            )],
        );
        assert_eq!(admit_receipt(&ok, &jud), Ok(()));
        assert_eq!(admit_receipt(&ok, &int), Err(Error::NotRegistered));
        // The Ministry signs, as itself, a receipt naming the court
        // administration.
        let as_other = signed(
            body,
            b"roll-receipt",
            &[(b"ROLL-INT", EventRole::RollCustodian, b"MOIS", int_sk)],
        );
        assert_eq!(admit_receipt(&as_other, &int), Err(Error::NotRegistered));
        // A source's entry of the same name keeps no copy.
        let by_source = signed(
            body,
            b"roll-receipt",
            &[(
                b"ROLL-JUD",
                EventRole::RollCustodian,
                b"COURT-ADMIN",
                deaths_sk,
            )],
        );
        assert_eq!(
            admit_receipt(&by_source, &deaths),
            Err(Error::NotRegistered)
        );
        let other_org = signed(
            body,
            b"roll-receipt",
            &[(b"ROLL-JUD", EventRole::RollCustodian, b"MOIS", jud_sk)],
        );
        assert_eq!(admit_receipt(&other_org, &jud), Err(Error::NotRegistered));
        let not_receipt = signed(
            extract(b"ROLL-JUD", RollSourceKind::Deaths),
            b"roll-source",
            &[(b"ROLL-JUD", EventRole::RollSource, b"COURT-ADMIN", jud_sk)],
        );
        assert_eq!(admit_receipt(&not_receipt, &jud), Err(Error::Decode));
    }

    #[test]
    fn an_amendment_needs_the_source_its_reason_names() {
        let (commission_sk, commission) = key(40);
        let (committee_sk, committee) = key(42);
        let (deaths, deaths_sk) = authority(b"DEATHS", b"COURT-ADMIN", K::Deaths, 44);
        let (court, court_sk) = authority(b"APPEAL", b"SEOUL-COURT", K::AppealCourt, 46);
        let three = |body: &'static [u8],
                     id: &'static [u8],
                     org: &'static [u8],
                     sk: &'static HybridSigningKey| {
            signed(
                body,
                b"roll-amendment",
                &[
                    (b"a-nec", EventRole::Commission, b"NEC", commission_sk),
                    (b"b-ivc", EventRole::Committee, b"IVC", committee_sk),
                    (id, EventRole::RollSource, org, sk),
                ],
            )
        };
        let death = amendment(b"DEATHS", RollAmendmentReason::Death);
        let ok = three(death, b"DEATHS", b"COURT-ADMIN", deaths_sk);
        assert_eq!(admit_amendment(&ok, commission, committee, &deaths), Ok(()));
        // The body names DEATHS: the appeal court's entry does not fit.
        assert_eq!(
            admit_amendment(&ok, commission, committee, &court),
            Err(Error::NotRegistered)
        );
        // Another source of deaths signs, as itself, an amendment naming
        // DEATHS.
        let (second, second_sk) = authority(b"DEATHS-2", b"COURT-2", K::Deaths, 48);
        let as_other = three(death, b"DEATHS-2", b"COURT-2", second_sk);
        assert_eq!(
            admit_amendment(&as_other, commission, committee, &second),
            Err(Error::NotRegistered)
        );
        // A death signed by the appeal court: each reason has its source.
        let wrong = three(
            amendment(b"APPEAL", RollAmendmentReason::Death),
            b"APPEAL",
            b"SEOUL-COURT",
            court_sk,
        );
        assert_eq!(
            admit_amendment(&wrong, commission, committee, &court),
            Err(Error::NotRegistered)
        );
        let appeal = three(
            amendment(b"APPEAL", RollAmendmentReason::AppealDecision),
            b"APPEAL",
            b"SEOUL-COURT",
            court_sk,
        );
        assert_eq!(
            admit_amendment(&appeal, commission, committee, &court),
            Ok(())
        );
        // The commission's key where the committee's belongs.
        assert_eq!(
            admit_amendment(&ok, commission, commission, &deaths),
            Err(Error::SignatureSigner)
        );
        // The source signed under another key.
        let forged = three(death, b"DEATHS", b"COURT-ADMIN", court_sk);
        assert_eq!(
            admit_amendment(&forged, commission, committee, &deaths),
            Err(Error::SignatureSigner)
        );
        let not_amendment = signed(
            receipt(b"DEATHS"),
            b"roll-receipt",
            &[(
                b"DEATHS",
                EventRole::RollCustodian,
                b"COURT-ADMIN",
                deaths_sk,
            )],
        );
        assert_eq!(
            admit_amendment(&not_amendment, commission, committee, &deaths),
            Err(Error::Decode)
        );
    }
}
