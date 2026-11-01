//! Field attestation (ADR-0023; PROTOCOL.md §7.9; ENCODING.md §8.19,
//! §8.28–§8.30; VC-088).
//!
//! An observer challenges the scanner at any time between visits, with a
//! check card read by the interpretation unit or with an observer token;
//! either way the unit receives an [`AttestChallenge`]. The [`Attestor`]
//! accepts it only if no visit is open, 30 seconds have passed since its
//! last attestation by the host's clock, the observer is on the station's
//! token list in genesis and the observer's signature verifies. It then
//! asks every chamber module for its statement over the same challenge
//! (verified with the module's genesis attestation key), builds the
//! `DeviceAttestationBody` from the host's boot measurements, signs it with
//! the device's attestation key (hybrid, purpose `device-attestation`) and
//! signs the field QR summary with that key's Ed25519 half (purpose
//! `attest-summary`).
//!
//! The attestor reads the box only to see whether a visit is open; it
//! changes no ballot, visit or box state and nothing it writes holds a
//! value about votes. Its own state is the time of its last attestation.
//!
//! The host's seconds value is untrusted: it serves only the 30-second rate
//! limit and is never written into any object. A clock that runs back
//! (`now` before the last attestation) is refused like one that is too
//! early; the state is in memory, so a restart clears it.

use ityv_crypto::{
    HybridVerifyingKey, RecordPurpose, RecordSignature, RecordVerifyingKey, Sha3Hasher,
    object_hash, verify_hybrid, verify_record,
};
use ityv_encoding::{
    AttestationChallenge, AttestationSummary, ChallengeMessage, ChallengePath, DeviceAttestation,
    DeviceAttestationBody, DeviceAttestationParts, ED25519_SIG_LEN, Encode, HEADER_LEN,
    HYBRID_SIG_LEN, Hash512, Ident, MAX_ATTESTATION_BODY_LEN, MAX_DEVICE_ID_LEN, MAX_MODULES,
    MeasuredImage, ModuleStatement, ModuleStatementMessage, ObserverId, SCHEMA_ATTESTATION_SUMMARY,
    SCHEMA_DEVICE_ATTESTATION, SCHEMA_DEVICE_ATTESTATION_BODY, SCHEMA_VERSION_1, SummaryParts,
    TimeBucket, Writer, decode_object, encode_object,
};

use crate::boxstate::{OpenBox, Signer, purpose, write_hybrid};
use crate::config::{ElectionConfig, chamber_code};
use crate::error::Error;
use crate::link::{AttestChallenge, SCHEMA_ATTEST_CHALLENGE};
use crate::port::ModulePort;

/// The device class of a commitment unit (ENCODING.md §8.26).
pub const DEVICE_CLASS_COMMITMENT_UNIT: u8 = 2;

/// The least spacing between two attestations, in the host's seconds.
pub const ATTEST_SPACING_SECONDS: u64 = 30;

/// Most observer tokens on one station's list.
pub const MAX_OBSERVERS: usize = 64;

/// Purpose of the device's attestation signature.
pub const PURPOSE_DEVICE_ATTESTATION: &[u8] = b"device-attestation";

/// Purpose of a module's statement signature.
pub const PURPOSE_MODULE_ATTESTATION: &[u8] = b"module-attestation";

/// Label of the bundle hash (ENCODING.md §8.26).
pub const LABEL_BUNDLE: &[u8] = b"ityv:bundle:v1";

/// The largest `DeviceAttestation` object: header, the body field and the
/// signature.
pub const MAX_DEVICE_ATTESTATION_LEN: usize =
    HEADER_LEN + 4 + MAX_ATTESTATION_BODY_LEN + HYBRID_SIG_LEN;

/// The largest `AttestationSummary` object: header, two 64-byte
/// identifiers, nonce, bucket, boot count, two hashes, signature.
pub const MAX_SUMMARY_LEN: usize = HEADER_LEN + 68 + 68 + 32 + 8 + 4 + 64 + 64 + ED25519_SIG_LEN;

/// The work buffer [`Attestor::attest`] needs: the module signatures, the
/// body object, the attestation object and the summary object.
pub const ATTEST_WORK_LEN: usize = MAX_MODULES * HYBRID_SIG_LEN
    + MAX_ATTESTATION_BODY_LEN
    + MAX_DEVICE_ATTESTATION_LEN
    + MAX_SUMMARY_LEN;

/// The challenge field: path, 64-byte observer identifier, nonce,
/// signature.
const CHALLENGE_FIELD_LEN: usize = 1 + 68 + 32 + 64;
/// The observer's signed message: three 64-byte identifiers and the nonce.
const CHALLENGE_MESSAGE_LEN: usize = 3 * 68 + 32;
/// A module's signed message: device, challenge, module, build, hash,
/// boot count.
const MODULE_MESSAGE_LEN: usize = 68 + CHALLENGE_FIELD_LEN + 68 + 8 + 64 + 4;
/// The summary's signed fields.
const SUMMARY_SIGNED_LEN: usize = 68 + 68 + 32 + 8 + 4 + 64 + 64;

/// An observer's check key from the station's token list in genesis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObserverKey<'a> {
    observer_id: ObserverId<'a>,
    key: RecordVerifyingKey,
}

impl<'a> ObserverKey<'a> {
    /// Pairs an observer with its Ed25519 check key.
    #[must_use]
    pub const fn new(observer_id: ObserverId<'a>, key: RecordVerifyingKey) -> Self {
        Self { observer_id, key }
    }

    /// The observer.
    #[must_use]
    pub const fn observer_id(&self) -> ObserverId<'a> {
        self.observer_id
    }

    /// The check key.
    #[must_use]
    pub const fn key(&self) -> &RecordVerifyingKey {
        &self.key
    }
}

/// What a field attestation needs from genesis beyond the box
/// configuration.
#[derive(Debug, Clone, Copy)]
pub struct AttestationSetup<'a> {
    /// The device's identifier in genesis (at most 64 bytes).
    pub device_id: Ident<'a>,
    /// The station's observer tokens, strictly ascending by identifier, at
    /// most [`MAX_OBSERVERS`].
    pub observers: &'a [ObserverKey<'a>],
    /// Each configured module's attestation key, in configuration order.
    pub module_keys: &'a [HybridVerifyingKey],
}

/// What the boot ROM measured: the device's boot counter and its images,
/// strictly ascending by component identifier (1–16).
#[derive(Debug, Clone, Copy)]
pub struct BootMeasurements<'a> {
    /// The device's boot counter.
    pub boot_count: u32,
    /// The measured images.
    pub components: &'a [MeasuredImage<'a>],
}

/// One attestation request from the host.
#[derive(Debug, Clone, Copy)]
pub struct AttestRequest<'a> {
    /// The `AttestChallenge` object (schema 0x0105).
    pub challenge: &'a [u8],
    /// How the challenge arrived.
    pub path: ChallengePath,
    /// The boot measurements.
    pub boot: BootMeasurements<'a>,
    /// The host's monotonic seconds: untrusted, used only for the
    /// 30-second spacing and never written anywhere.
    pub now_seconds: u64,
    /// The time bucket written into the attestation.
    pub time_bucket: TimeBucket,
}

/// The two objects of an attestation, in the caller's work buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Attested<'w> {
    attestation: &'w [u8],
    summary: &'w [u8],
}

impl<'w> Attested<'w> {
    /// The `DeviceAttestation` object (the public event).
    #[must_use]
    pub const fn attestation(&self) -> &'w [u8] {
        self.attestation
    }

    /// The `AttestationSummary` object (the field QR).
    #[must_use]
    pub const fn summary(&self) -> &'w [u8] {
        self.summary
    }
}

/// Answers observers' challenges. Holds only the time of its last
/// attestation.
#[derive(Debug, Clone, Copy)]
pub struct Attestor<'c> {
    config: &'c ElectionConfig<'c>,
    setup: AttestationSetup<'c>,
    last_seconds: Option<u64>,
}

impl<'c> Attestor<'c> {
    /// Checks `setup` against `config`.
    ///
    /// # Errors
    /// [`Error::AttestationSetup`] if the device identifier is longer than
    /// 64 bytes, the observers are not strictly ascending or more than
    /// [`MAX_OBSERVERS`], or there is not exactly one attestation key per
    /// configured module.
    pub fn new(config: &'c ElectionConfig<'c>, setup: AttestationSetup<'c>) -> Result<Self, Error> {
        let ascending = setup.observers.windows(2).all(|pair| match pair {
            [a, b] => a.observer_id.as_bytes() < b.observer_id.as_bytes(),
            _ => true,
        });
        if setup.device_id.byte_len() > MAX_DEVICE_ID_LEN
            || setup.observers.len() > MAX_OBSERVERS
            || !ascending
            || setup.module_keys.len() != config.modules().len()
        {
            return Err(Error::AttestationSetup);
        }
        Ok(Self {
            config,
            setup,
            last_seconds: None,
        })
    }

    /// The host second of the last attestation, if any.
    #[must_use]
    pub const fn last_attestation(&self) -> Option<u64> {
        self.last_seconds
    }

    /// Answers one challenge (PROTOCOL.md §7.9 steps 3–4). Every check
    /// comes before any module is asked, in this order: the work buffer and
    /// the port count, the challenge's decoding and election, no visit
    /// open in `open_box`, the 30-second spacing, the observer's place on
    /// the token list, the observer's signature. Then each module's
    /// statement is asked in chamber code order and verified, the body is
    /// built and signed by `signer` (the device's attestation key), and
    /// the summary is signed by the key's Ed25519 half. Only a complete
    /// attestation moves the spacing clock.
    ///
    /// # Errors
    /// [`Error::BufferTooSmall`], [`Error::PortCount`], the decoder's
    /// error, [`Error::WrongElection`], [`Error::VisitOpen`],
    /// [`Error::AttestTooSoon`], [`Error::UnknownObserver`],
    /// [`Error::ChallengeSignature`], a port error,
    /// [`Error::ModuleStatement`], [`Error::BootMeasurements`], a signing
    /// or encoding error.
    pub fn attest<'w>(
        &mut self,
        open_box: &OpenBox<'c>,
        request: &AttestRequest<'_>,
        modules: &mut [&mut dyn ModulePort],
        signer: Signer<'_>,
        work: &'w mut [u8],
    ) -> Result<Attested<'w>, Error> {
        if work.len() < ATTEST_WORK_LEN {
            return Err(Error::BufferTooSmall);
        }
        if modules.len() != self.config.modules().len() {
            return Err(Error::PortCount);
        }
        let challenge = self.admit(open_box, request)?;
        let field = AttestationChallenge {
            path: request.path,
            observer_id: challenge.observer_id(),
            nonce: challenge.nonce(),
            challenge_sig: challenge.challenge_sig(),
        };
        let (sig_area, rest) = work.split_at_mut(MAX_MODULES * HYBRID_SIG_LEN);
        let (body_area, rest) = rest.split_at_mut(MAX_ATTESTATION_BODY_LEN);
        let (attestation_area, summary_area) = rest.split_at_mut(MAX_DEVICE_ATTESTATION_LEN);
        let measured = self.collect_statements(&field, modules, sig_area)?;
        let sigs: &[u8] = sig_area;
        let (statements, count) = assemble(&measured, sigs)?;
        let body = DeviceAttestationBody::new(&DeviceAttestationParts {
            election_id: self.config.election_id(),
            device_id: self.setup.device_id,
            device_class: DEVICE_CLASS_COMMITMENT_UNIT,
            challenge: field,
            time_bucket: request.time_bucket,
            boot_count: request.boot.boot_count,
            components: request.boot.components,
            bundle_hash: bundle_hash(request.boot.components),
            modules: statements.get(..count).unwrap_or(&[]),
        })
        .ok_or(Error::BootMeasurements)?;
        let body_len = encode_object(
            SCHEMA_DEVICE_ATTESTATION_BODY,
            SCHEMA_VERSION_1,
            &body,
            body_area,
        )?;
        let body_bytes: &[u8] = body_area.get(..body_len).ok_or(Error::BufferTooSmall)?;
        let attestation_len = sign_attestation(body_bytes, signer, attestation_area)?;
        let summary = SummaryParts {
            device_id: self.setup.device_id,
            observer_id: challenge.observer_id(),
            nonce: challenge.nonce(),
            time_bucket: request.time_bucket,
            boot_count: request.boot.boot_count,
            bundle_hash: *body.bundle_hash(),
            body_hash: object_hash(body_bytes),
        };
        let summary_len = sign_summary(&summary, signer, summary_area)?;
        self.last_seconds = Some(request.now_seconds);
        let attestation_out: &'w [u8] = attestation_area;
        let summary_out: &'w [u8] = summary_area;
        Ok(Attested {
            attestation: attestation_out
                .get(..attestation_len)
                .ok_or(Error::BufferTooSmall)?,
            summary: summary_out
                .get(..summary_len)
                .ok_or(Error::BufferTooSmall)?,
        })
    }

    /// The checks before any module is asked: the challenge decodes and
    /// names this election, no visit is open, the spacing holds, the
    /// observer is on the list and signed it.
    fn admit<'r>(
        &self,
        open_box: &OpenBox<'c>,
        request: &AttestRequest<'r>,
    ) -> Result<AttestChallenge<'r>, Error> {
        let challenge: AttestChallenge<'r> =
            decode_object(SCHEMA_ATTEST_CHALLENGE, SCHEMA_VERSION_1, request.challenge)?;
        if challenge.election_id().as_bytes() != self.config.election_id().as_bytes() {
            return Err(Error::WrongElection);
        }
        if open_box.has_visit_open() {
            return Err(Error::VisitOpen);
        }
        if !spaced(self.last_seconds, request.now_seconds) {
            return Err(Error::AttestTooSoon);
        }
        let observer = self.observer(challenge.observer_id())?;
        self.check_challenge(&challenge, observer)?;
        Ok(challenge)
    }

    /// The observer's check key from the token list.
    fn observer(&self, observer_id: ObserverId<'_>) -> Result<&'c ObserverKey<'c>, Error> {
        let observers: &'c [ObserverKey<'c>] = self.setup.observers;
        observers
            .binary_search_by(|o| o.observer_id.as_bytes().cmp(observer_id.as_bytes()))
            .ok()
            .and_then(|index| observers.get(index))
            .ok_or(Error::UnknownObserver)
    }

    /// Verifies the observer's signature over the challenge message.
    fn check_challenge(
        &self,
        challenge: &AttestChallenge<'_>,
        observer: &ObserverKey<'_>,
    ) -> Result<(), Error> {
        let message = ChallengeMessage {
            election_id: self.config.election_id(),
            station_id: self.config.station_id(),
            observer_id: challenge.observer_id(),
            nonce: challenge.nonce(),
        };
        let mut buf = [0u8; CHALLENGE_MESSAGE_LEN];
        let bytes = encode_fields(&message, &mut buf)?;
        let sig = RecordSignature::from_bytes(*challenge.challenge_sig());
        verify_record(&observer.key, RecordPurpose::AttestChallenge, bytes, &sig)
            .map(|_| ())
            .map_err(|_| Error::ChallengeSignature)
    }

    /// Asks every module, in chamber code order, for its statement and
    /// verifies it; the signatures land in `sig_area`, one slot per
    /// position in that order. Returns the statements' other fields.
    fn collect_statements(
        &self,
        challenge: &AttestationChallenge<'_>,
        modules: &mut [&mut dyn ModulePort],
        sig_area: &mut [u8],
    ) -> Result<[Option<StatementFields<'c>>; MAX_MODULES], Error> {
        let mut challenge_buf = [0u8; CHALLENGE_FIELD_LEN];
        let challenge_bytes = encode_fields(challenge, &mut challenge_buf)?;
        let device_id = self.setup.device_id;
        let module_purpose = purpose(PURPOSE_MODULE_ATTESTATION)?;
        let mut out = [None; MAX_MODULES];
        let order = chamber_order(self.config);
        let configured = self.config.modules();
        for ((&index, slot), chunk) in order
            .iter()
            .take(configured.len())
            .zip(out.iter_mut())
            .zip(sig_area.chunks_exact_mut(HYBRID_SIG_LEN))
        {
            let module = configured.get(index).ok_or(Error::Capacity)?;
            let key = self.setup.module_keys.get(index).ok_or(Error::Capacity)?;
            let port = modules.get_mut(index).ok_or(Error::PortCount)?;
            let reply = port.attest(device_id.as_bytes(), challenge_bytes)?;
            let message = ModuleStatementMessage {
                device_id,
                challenge: *challenge,
                module_id: module.module_id(),
                build: reply.build,
                image_hash: reply.image_hash,
                boot_count: reply.boot_count,
            };
            let mut buf = [0u8; MODULE_MESSAGE_LEN];
            let bytes = encode_fields(&message, &mut buf)?;
            let verified = verify_hybrid(key, &module_purpose, bytes, &reply.sig)
                .map_err(|_| Error::ModuleStatement)?;
            let target: &mut [u8; HYBRID_SIG_LEN] =
                chunk.try_into().map_err(|_| Error::BufferTooSmall)?;
            write_hybrid(verified.get().signature(), target)?;
            *slot = Some((
                module.module_id(),
                reply.build,
                reply.image_hash,
                reply.boot_count,
            ));
        }
        Ok(out)
    }
}

/// A verified statement's fields but its signature.
type StatementFields<'c> = (ityv_encoding::ModuleId<'c>, u64, Hash512, u32);

/// `true` if an attestation at `now` keeps the spacing after `last`.
pub(crate) const fn spaced(last: Option<u64>, now: u64) -> bool {
    match last {
        None => true,
        Some(last) => match last.checked_add(ATTEST_SPACING_SECONDS) {
            Some(earliest) => now >= earliest,
            None => false,
        },
    }
}

/// The configured modules' indices in chamber code order.
fn chamber_order(config: &ElectionConfig<'_>) -> [usize; MAX_MODULES] {
    let modules = config.modules();
    let mut order = [0usize; MAX_MODULES];
    for (i, slot) in order.iter_mut().enumerate() {
        *slot = i;
    }
    let code = |index: usize| {
        modules
            .get(index)
            .map_or(u8::MAX, |m| chamber_code(m.chamber()).code())
    };
    if let Some(prefix) = order.get_mut(..modules.len()) {
        prefix.sort_unstable_by_key(|&index| code(index));
    }
    order
}

/// `SHA3-512("ityv:bundle:v1" ‖ 0x00 ‖ image_hash_1 ‖ …)` over the
/// components in their (identifier) order.
fn bundle_hash(components: &[MeasuredImage<'_>]) -> Hash512 {
    let mut hasher = Sha3Hasher::new();
    hasher.absorb(LABEL_BUNDLE);
    hasher.absorb(&[0x00]);
    for component in components {
        hasher.absorb(&component.image_hash.0);
    }
    Hash512(hasher.finish())
}

/// Writes the field encoding of `value` (no object header) into `buf`.
fn encode_fields<'b, T: Encode>(value: &T, buf: &'b mut [u8]) -> Result<&'b [u8], Error> {
    let mut w = Writer::new(buf);
    value.encode(&mut w)?;
    let len = w.finish();
    let written: &'b [u8] = buf;
    written.get(..len).ok_or(Error::BufferTooSmall)
}

/// A filler statement for the unused tail of a fixed array; never written.
fn placeholder(sigs: &[u8]) -> Result<ModuleStatement<'_>, Error> {
    let sig: &[u8; HYBRID_SIG_LEN] = sigs
        .get(..HYBRID_SIG_LEN)
        .and_then(|s| s.try_into().ok())
        .ok_or(Error::BufferTooSmall)?;
    Ok(ModuleStatement {
        module_id: ityv_encoding::ModuleId::new(b"-").ok_or(Error::Capacity)?,
        build: 0,
        image_hash: Hash512::ZERO,
        boot_count: 0,
        sig,
    })
}

/// The verified statements as body entries, in chamber code order, and
/// their number.
fn assemble<'s>(
    measured: &[Option<StatementFields<'s>>; MAX_MODULES],
    sigs: &'s [u8],
) -> Result<([ModuleStatement<'s>; MAX_MODULES], usize), Error> {
    let mut statements = [placeholder(sigs)?; MAX_MODULES];
    let mut count = 0usize;
    for ((slot, reply), chunk) in statements
        .iter_mut()
        .zip(measured.iter())
        .zip(sigs.chunks_exact(HYBRID_SIG_LEN))
    {
        if let Some((module_id, build, image_hash, boot_count)) = *reply {
            let sig: &[u8; HYBRID_SIG_LEN] = chunk.try_into().map_err(|_| Error::BufferTooSmall)?;
            *slot = ModuleStatement {
                module_id,
                build,
                image_hash,
                boot_count,
                sig,
            };
            count = count.checked_add(1).ok_or(Error::Overflow)?;
        }
    }
    Ok((statements, count))
}

/// Signs the body with the attestation key (purpose `device-attestation`)
/// and writes the `DeviceAttestation` object into `out`.
fn sign_attestation(body_bytes: &[u8], signer: Signer<'_>, out: &mut [u8]) -> Result<usize, Error> {
    let mut sig = [0u8; HYBRID_SIG_LEN];
    signer.sign_into(PURPOSE_DEVICE_ATTESTATION, body_bytes, &mut sig)?;
    let attestation = DeviceAttestation::new(body_bytes, &sig)?;
    Ok(encode_object(
        SCHEMA_DEVICE_ATTESTATION,
        SCHEMA_VERSION_1,
        &attestation,
        out,
    )?)
}

/// Signs the summary's fields with the attestation key's Ed25519 half
/// (purpose `attest-summary`) and writes the `AttestationSummary` object
/// into `out`.
fn sign_summary(
    parts: &SummaryParts<'_>,
    signer: Signer<'_>,
    out: &mut [u8],
) -> Result<usize, Error> {
    let mut fields = [0u8; SUMMARY_SIGNED_LEN];
    let field_bytes = encode_fields(parts, &mut fields)?;
    let sig: RecordSignature =
        signer.sign_ed25519_half(RecordPurpose::AttestSummary, field_bytes)?;
    let summary = AttestationSummary::new(parts, sig.as_bytes()).ok_or(Error::AttestationSetup)?;
    Ok(encode_object(
        SCHEMA_ATTESTATION_SUMMARY,
        SCHEMA_VERSION_1,
        &summary,
        out,
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ityv_encoding::{ElectionId, ModuleId, StationId};

    /// Each buffer is exactly as long as the largest field group it holds;
    /// a larger one would only hide a wrong length.
    #[test]
    fn buffer_lengths_are_exact() {
        let long = [b'L'; 64];
        let nonce = [0u8; 32];
        let sig = [0u8; 64];
        let observer_id = ObserverId::new(&long).unwrap();
        let challenge = AttestationChallenge {
            path: ChallengePath::Token,
            observer_id,
            nonce: &nonce,
            challenge_sig: &sig,
        };
        assert_eq!(challenge.encoded_len(), CHALLENGE_FIELD_LEN);
        let message = ChallengeMessage {
            election_id: ElectionId::new(&long).unwrap(),
            station_id: StationId::new(&long).unwrap(),
            observer_id,
            nonce: &nonce,
        };
        assert_eq!(message.encoded_len(), CHALLENGE_MESSAGE_LEN);
        let device_id = Ident::new(&long, 64).unwrap();
        let statement = ModuleStatementMessage {
            device_id,
            challenge,
            module_id: ModuleId::new(&long).unwrap(),
            build: 0,
            image_hash: Hash512::ZERO,
            boot_count: 0,
        };
        assert_eq!(statement.encoded_len(), MODULE_MESSAGE_LEN);
        let parts = SummaryParts {
            device_id,
            observer_id,
            nonce: &nonce,
            time_bucket: TimeBucket::new(0),
            boot_count: 0,
            bundle_hash: Hash512::ZERO,
            body_hash: Hash512::ZERO,
        };
        assert_eq!(parts.encoded_len(), SUMMARY_SIGNED_LEN);
        let summary = AttestationSummary::new(&parts, &sig).unwrap();
        assert_eq!(HEADER_LEN + summary.encoded_len(), MAX_SUMMARY_LEN);
        assert_eq!(
            (
                CHALLENGE_FIELD_LEN,
                CHALLENGE_MESSAGE_LEN,
                MODULE_MESSAGE_LEN
            ),
            (165, 236, 377)
        );
        assert_eq!((SUMMARY_SIGNED_LEN, MAX_SUMMARY_LEN), (308, 388));
        assert_eq!(MAX_DEVICE_ATTESTATION_LEN, 16 + 4 + 40_960 + 4691);
        assert_eq!(ATTEST_WORK_LEN, 7 * 4691 + 40_960 + 45_671 + 388);
        assert_eq!(ATTEST_WORK_LEN, 119_856);
    }
}
