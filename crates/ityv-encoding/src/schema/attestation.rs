//! Field attestation (ADR-0023, PROTOCOL.md §7.9, ENCODING.md §8.19,
//! §8.28–§8.30): `DeviceAttestationBody` (schema `0x0023`),
//! `DeviceAttestation` (`0x0024`) and `AttestationSummary` (`0x0025`), all
//! version 1, and the two field groups that are signed without an object
//! header: the observer's challenge message and a module's statement.
//!
//! `DeviceAttestationBody` field order: `election_id`, `device_id`,
//! `device_class`, `challenge` (`path`, `observer_id`, `nonce`,
//! `challenge_sig`), `time_bucket`, `boot_count`, `components` (1–16,
//! strictly ascending by `component_id`), `bundle_hash`, `modules` (0–7,
//! distinct `module_id`, chamber code order). `DeviceAttestation`: `body`,
//! `attestation_sig`. `AttestationSummary`: `device_id`, `observer_id`,
//! `nonce`, `time_bucket`, `boot_count`, `bundle_hash`, `body_hash`,
//! `summary_sig`; the signature covers the encoding of the first seven
//! fields ([`SummaryParts`]).
//!
//! The encoding checks form only: it does not verify a signature, and it
//! cannot recompute `bundle_hash` (that needs SHA3-512, which lives in the
//! cryptographic crate). Verifiers recompute it.

use crate::codec::{Decode, Encode};
use crate::error::{Error, Kind};
use crate::primitives::{ElectionId, Hash512, Ident, ModuleId, ObserverId, StationId, TimeBucket};
use crate::reader::Reader;
use crate::schema::SCHEMA_DEVICE_ATTESTATION_BODY;
use crate::schema::util::{
    ED25519_SIG_LEN, HYBRID_SIG_LEN, MAX_MODULES, check_embedded, decode_embedded, read_fixed,
};
use crate::writer::Writer;

/// Maximum length of a device or component identifier.
pub const MAX_DEVICE_ID_LEN: usize = 64;

/// Maximum length of a component version string.
pub const MAX_VERSION_LEN: usize = 32;

/// Most measured components in one attestation.
pub const MAX_COMPONENTS: usize = 16;

/// Length of an attestation nonce.
pub const NONCE_LEN: usize = 32;

/// Maximum length of the embedded `DeviceAttestationBody` object bytes.
pub const MAX_ATTESTATION_BODY_LEN: usize = 40960;

/// The largest device class (ENCODING.md §8.26: 1 interpretation unit … 10
/// observer and voter apps).
pub const MAX_DEVICE_CLASS: u8 = 10;

/// How a challenge reached the device (ENCODING.md §8.28 field 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChallengePath {
    /// An observer token touched the device (code 1).
    Token,
    /// A check card went through the scanner slot (code 2).
    Card,
}

impl ChallengePath {
    /// The wire code.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Token => 1,
            Self::Card => 2,
        }
    }

    /// The path with wire code `code`, if defined.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Token),
            2 => Some(Self::Card),
            _ => None,
        }
    }
}

/// An observer's challenge as the attestation carries it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AttestationChallenge<'a> {
    /// How it arrived.
    pub path: ChallengePath,
    /// The observer whose check key signed it.
    pub observer_id: ObserverId<'a>,
    /// The observer's fresh random value.
    pub nonce: &'a [u8; NONCE_LEN],
    /// The observer's Ed25519 signature (purpose `attest-challenge`) over
    /// the [`ChallengeMessage`].
    pub challenge_sig: &'a [u8; ED25519_SIG_LEN],
}

impl Encode for AttestationChallenge<'_> {
    fn encoded_len(&self) -> usize {
        1usize
            .saturating_add(self.observer_id.encoded_len())
            .saturating_add(NONCE_LEN)
            .saturating_add(ED25519_SIG_LEN)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        w.write_u8(self.path.code())?;
        self.observer_id.encode(w)?;
        w.write_array(self.nonce)?;
        w.write_array(self.challenge_sig)
    }
}

impl<'a> Decode<'a> for AttestationChallenge<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let at = r.position();
        let path = ChallengePath::from_code(r.read_u8()?)
            .ok_or_else(|| Error::new(Kind::ValueOutOfRange, at))?;
        Ok(Self {
            path,
            observer_id: ObserverId::decode(r)?,
            nonce: read_fixed::<NONCE_LEN>(r)?,
            challenge_sig: read_fixed::<ED25519_SIG_LEN>(r)?,
        })
    }
}

/// The bytes an observer signs for a challenge (purpose `attest-challenge`,
/// Ed25519 only; ENCODING.md §8.19): the field encodings of
/// `election_id ‖ station_id ‖ observer_id ‖ nonce`, no object header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChallengeMessage<'a> {
    /// The election.
    pub election_id: ElectionId<'a>,
    /// The polling station of the device (from its own configuration).
    pub station_id: StationId<'a>,
    /// The observer.
    pub observer_id: ObserverId<'a>,
    /// The nonce.
    pub nonce: &'a [u8; NONCE_LEN],
}

impl Encode for ChallengeMessage<'_> {
    fn encoded_len(&self) -> usize {
        self.election_id
            .encoded_len()
            .saturating_add(self.station_id.encoded_len())
            .saturating_add(self.observer_id.encoded_len())
            .saturating_add(NONCE_LEN)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        self.election_id.encode(w)?;
        self.station_id.encode(w)?;
        self.observer_id.encode(w)?;
        w.write_array(self.nonce)
    }
}

/// The bytes a chamber module signs for its statement (purpose
/// `module-attestation`, hybrid, with its attestation key; ENCODING.md
/// §8.28): the field encodings of `device_id ‖ challenge ‖ module_id ‖
/// build ‖ image_hash ‖ boot_count`, no object header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ModuleStatementMessage<'a> {
    /// The device the module serves.
    pub device_id: Ident<'a>,
    /// The challenge, as the attestation carries it.
    pub challenge: AttestationChallenge<'a>,
    /// The module.
    pub module_id: ModuleId<'a>,
    /// The module image's build number.
    pub build: u64,
    /// The module image's hash, measured at its boot.
    pub image_hash: Hash512,
    /// The module's boot counter.
    pub boot_count: u32,
}

impl Encode for ModuleStatementMessage<'_> {
    fn encoded_len(&self) -> usize {
        ident_len(&self.device_id)
            .saturating_add(self.challenge.encoded_len())
            .saturating_add(self.module_id.encoded_len())
            .saturating_add(8)
            .saturating_add(64)
            .saturating_add(4)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        w.write_ident(&self.device_id, MAX_DEVICE_ID_LEN)?;
        self.challenge.encode(w)?;
        self.module_id.encode(w)?;
        w.write_u64(self.build)?;
        self.image_hash.encode(w)?;
        w.write_u32(self.boot_count)
    }
}

/// One measured image (ENCODING.md §8.28 field 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MeasuredImage<'a> {
    /// The component, as the release manifest names it.
    pub component_id: Ident<'a>,
    /// Its version string.
    pub version: Ident<'a>,
    /// Its build number.
    pub build: u64,
    /// The image hash measured at boot.
    pub image_hash: Hash512,
}

impl Encode for MeasuredImage<'_> {
    fn encoded_len(&self) -> usize {
        ident_len(&self.component_id)
            .saturating_add(ident_len(&self.version))
            .saturating_add(8)
            .saturating_add(64)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        w.write_ident(&self.component_id, MAX_DEVICE_ID_LEN)?;
        w.write_ident(&self.version, MAX_VERSION_LEN)?;
        w.write_u64(self.build)?;
        self.image_hash.encode(w)
    }
}

impl<'a> Decode<'a> for MeasuredImage<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        Ok(Self {
            component_id: r.read_ident(MAX_DEVICE_ID_LEN)?,
            version: r.read_ident(MAX_VERSION_LEN)?,
            build: r.read_u64()?,
            image_hash: Hash512::decode(r)?,
        })
    }
}

/// A chamber module's statement in an attestation (ENCODING.md §8.28
/// field 9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ModuleStatement<'a> {
    /// The module.
    pub module_id: ModuleId<'a>,
    /// Its image's build number.
    pub build: u64,
    /// Its image hash.
    pub image_hash: Hash512,
    /// Its boot counter.
    pub boot_count: u32,
    /// Its hybrid signature over the [`ModuleStatementMessage`].
    pub sig: &'a [u8; HYBRID_SIG_LEN],
}

impl Encode for ModuleStatement<'_> {
    fn encoded_len(&self) -> usize {
        self.module_id
            .encoded_len()
            .saturating_add(8)
            .saturating_add(64)
            .saturating_add(4)
            .saturating_add(HYBRID_SIG_LEN)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        self.module_id.encode(w)?;
        w.write_u64(self.build)?;
        self.image_hash.encode(w)?;
        w.write_u32(self.boot_count)?;
        w.write_array(self.sig)
    }
}

impl<'a> Decode<'a> for ModuleStatement<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        Ok(Self {
            module_id: ModuleId::decode(r)?,
            build: r.read_u64()?,
            image_hash: Hash512::decode(r)?,
            boot_count: r.read_u32()?,
            sig: read_fixed::<HYBRID_SIG_LEN>(r)?,
        })
    }
}

fn ident_len(ident: &Ident<'_>) -> usize {
    ident.byte_len().saturating_add(4)
}

/// `true` if the component identifiers are strictly ascending.
fn components_ascending(components: &[MeasuredImage<'_>]) -> bool {
    components.windows(2).all(|pair| match pair {
        [a, b] => a.component_id.as_bytes() < b.component_id.as_bytes(),
        _ => true,
    })
}

/// `true` if no two statements name the same module.
fn modules_distinct(modules: &[ModuleStatement<'_>]) -> bool {
    modules.iter().enumerate().all(|(i, m)| {
        modules
            .iter()
            .take(i)
            .all(|other| other.module_id != m.module_id)
    })
}

/// The parts of a [`DeviceAttestationBody`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeviceAttestationParts<'a, 's> {
    /// The election.
    pub election_id: ElectionId<'a>,
    /// The attesting device, as genesis registers it.
    pub device_id: Ident<'a>,
    /// Its class (ENCODING.md §8.26, 1–10).
    pub device_class: u8,
    /// The challenge answered.
    pub challenge: AttestationChallenge<'a>,
    /// The time bucket.
    pub time_bucket: TimeBucket,
    /// The device's boot counter.
    pub boot_count: u32,
    /// The images measured at boot, strictly ascending by identifier.
    pub components: &'s [MeasuredImage<'a>],
    /// The bundle hash of the components (ENCODING.md §8.26).
    pub bundle_hash: Hash512,
    /// The chamber modules' statements, in chamber code order.
    pub modules: &'s [ModuleStatement<'a>],
}

/// The body of a field attestation. It holds no value about votes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeviceAttestationBody<'a> {
    election_id: ElectionId<'a>,
    device_id: Ident<'a>,
    device_class: u8,
    challenge: AttestationChallenge<'a>,
    time_bucket: TimeBucket,
    boot_count: u32,
    components: [Option<MeasuredImage<'a>>; MAX_COMPONENTS],
    component_count: u8,
    bundle_hash: Hash512,
    modules: [Option<ModuleStatement<'a>>; MAX_MODULES],
    module_count: u8,
}

impl<'a> DeviceAttestationBody<'a> {
    /// Builds a body. `None` if the device identifier is longer than 64
    /// bytes, the class is not 1–10, there are no components or more than
    /// sixteen, they are not strictly ascending, there are more than seven
    /// module statements, or two name the same module.
    #[must_use]
    pub fn new(parts: &DeviceAttestationParts<'a, '_>) -> Option<Self> {
        if parts.device_id.byte_len() > MAX_DEVICE_ID_LEN
            || parts.device_class == 0
            || parts.device_class > MAX_DEVICE_CLASS
            || parts.components.is_empty()
            || parts.components.len() > MAX_COMPONENTS
            || !components_ascending(parts.components)
            || parts.modules.len() > MAX_MODULES
            || !modules_distinct(parts.modules)
        {
            return None;
        }
        let mut components = [None; MAX_COMPONENTS];
        for (slot, component) in components.iter_mut().zip(parts.components) {
            *slot = Some(*component);
        }
        let mut modules = [None; MAX_MODULES];
        for (slot, module) in modules.iter_mut().zip(parts.modules) {
            *slot = Some(*module);
        }
        Some(Self {
            election_id: parts.election_id,
            device_id: parts.device_id,
            device_class: parts.device_class,
            challenge: parts.challenge,
            time_bucket: parts.time_bucket,
            boot_count: parts.boot_count,
            components,
            component_count: u8::try_from(parts.components.len()).ok()?,
            bundle_hash: parts.bundle_hash,
            modules,
            module_count: u8::try_from(parts.modules.len()).ok()?,
        })
    }

    /// The election.
    #[must_use]
    pub const fn election_id(&self) -> ElectionId<'a> {
        self.election_id
    }

    /// The attesting device.
    #[must_use]
    pub const fn device_id(&self) -> Ident<'a> {
        self.device_id
    }

    /// The device class.
    #[must_use]
    pub const fn device_class(&self) -> u8 {
        self.device_class
    }

    /// The challenge answered.
    #[must_use]
    pub const fn challenge(&self) -> &AttestationChallenge<'a> {
        &self.challenge
    }

    /// The time bucket.
    #[must_use]
    pub const fn time_bucket(&self) -> TimeBucket {
        self.time_bucket
    }

    /// The device's boot counter.
    #[must_use]
    pub const fn boot_count(&self) -> u32 {
        self.boot_count
    }

    /// The measured components, ascending by identifier.
    pub fn components(&self) -> impl Iterator<Item = &MeasuredImage<'a>> {
        self.components
            .iter()
            .take(usize::from(self.component_count))
            .flatten()
    }

    /// The bundle hash.
    #[must_use]
    pub const fn bundle_hash(&self) -> &Hash512 {
        &self.bundle_hash
    }

    /// The module statements, in chamber code order.
    pub fn modules(&self) -> impl Iterator<Item = &ModuleStatement<'a>> {
        self.modules
            .iter()
            .take(usize::from(self.module_count))
            .flatten()
    }
}

impl Encode for DeviceAttestationBody<'_> {
    fn encoded_len(&self) -> usize {
        let components = self
            .components()
            .fold(0usize, |acc, c| acc.saturating_add(c.encoded_len()));
        let modules = self
            .modules()
            .fold(0usize, |acc, m| acc.saturating_add(m.encoded_len()));
        self.election_id
            .encoded_len()
            .saturating_add(ident_len(&self.device_id))
            .saturating_add(1)
            .saturating_add(self.challenge.encoded_len())
            .saturating_add(8)
            .saturating_add(4)
            .saturating_add(4)
            .saturating_add(components)
            .saturating_add(64)
            .saturating_add(4)
            .saturating_add(modules)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        self.election_id.encode(w)?;
        w.write_ident(&self.device_id, MAX_DEVICE_ID_LEN)?;
        w.write_u8(self.device_class)?;
        self.challenge.encode(w)?;
        self.time_bucket.encode(w)?;
        w.write_u32(self.boot_count)?;
        w.write_count(usize::from(self.component_count), MAX_COMPONENTS)?;
        for component in self.components() {
            component.encode(w)?;
        }
        self.bundle_hash.encode(w)?;
        w.write_count(usize::from(self.module_count), MAX_MODULES)?;
        for module in self.modules() {
            module.encode(w)?;
        }
        Ok(())
    }
}

impl<'a> Decode<'a> for DeviceAttestationBody<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let election_id = ElectionId::decode(r)?;
        let device_id = r.read_ident(MAX_DEVICE_ID_LEN)?;
        let class_at = r.position();
        let device_class = r.read_u8()?;
        if device_class == 0 || device_class > MAX_DEVICE_CLASS {
            return Err(Error::new(Kind::ValueOutOfRange, class_at));
        }
        let challenge = AttestationChallenge::decode(r)?;
        let time_bucket = TimeBucket::decode(r)?;
        let boot_count = r.read_u32()?;
        let count_at = r.position();
        let component_count = r.read_count(MAX_COMPONENTS)?;
        if component_count == 0 {
            return Err(Error::new(Kind::ValueOutOfRange, count_at));
        }
        let mut components: [Option<MeasuredImage<'a>>; MAX_COMPONENTS] = [None; MAX_COMPONENTS];
        let mut previous: Option<&'a [u8]> = None;
        for slot in components.iter_mut().take(component_count) {
            let at = r.position();
            let component = MeasuredImage::decode(r)?;
            let id = component.component_id.as_bytes();
            if previous.is_some_and(|p| p >= id) {
                return Err(Error::new(Kind::NotSorted, at));
            }
            previous = Some(id);
            *slot = Some(component);
        }
        let bundle_hash = Hash512::decode(r)?;
        let module_count = r.read_count(MAX_MODULES)?;
        let mut modules: [Option<ModuleStatement<'a>>; MAX_MODULES] = [None; MAX_MODULES];
        for i in 0..module_count {
            let at = r.position();
            let module = ModuleStatement::decode(r)?;
            let seen = modules
                .iter()
                .take(i)
                .flatten()
                .any(|m| m.module_id == module.module_id);
            if seen {
                return Err(Error::new(Kind::Duplicate, at));
            }
            if let Some(slot) = modules.get_mut(i) {
                *slot = Some(module);
            }
        }
        Ok(Self {
            election_id,
            device_id,
            device_class,
            challenge,
            time_bucket,
            boot_count,
            components,
            component_count: u8::try_from(component_count)
                .map_err(|_| Error::new(Kind::CountExceedsMax, count_at))?,
            bundle_hash,
            modules,
            module_count: u8::try_from(module_count)
                .map_err(|_| Error::new(Kind::CountExceedsMax, count_at))?,
        })
    }
}

/// A field attestation: the body object bytes with the device's hybrid
/// signature by its attestation key (purpose `device-attestation`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceAttestation<'a> {
    body_bytes: &'a [u8],
    body: DeviceAttestationBody<'a>,
    attestation_sig: &'a [u8; HYBRID_SIG_LEN],
}

impl<'a> DeviceAttestation<'a> {
    /// Builds an attestation from a complete body object and the
    /// signature.
    ///
    /// # Errors
    /// The body's decoding error, or `LengthExceedsMax` at 0 if too long.
    pub fn new(
        body_bytes: &'a [u8],
        attestation_sig: &'a [u8; HYBRID_SIG_LEN],
    ) -> Result<Self, Error> {
        let body = check_embedded(
            body_bytes,
            MAX_ATTESTATION_BODY_LEN,
            SCHEMA_DEVICE_ATTESTATION_BODY,
        )?;
        Ok(Self {
            body_bytes,
            body,
            attestation_sig,
        })
    }

    /// The body object bytes (the signed message).
    #[must_use]
    pub const fn body_bytes(&self) -> &'a [u8] {
        self.body_bytes
    }

    /// The decoded body.
    #[must_use]
    pub const fn body(&self) -> &DeviceAttestationBody<'a> {
        &self.body
    }

    /// The attestation key's hybrid signature.
    #[must_use]
    pub const fn attestation_sig(&self) -> &'a [u8; HYBRID_SIG_LEN] {
        self.attestation_sig
    }
}

impl Encode for DeviceAttestation<'_> {
    fn encoded_len(&self) -> usize {
        self.body_bytes
            .len()
            .saturating_add(4)
            .saturating_add(HYBRID_SIG_LEN)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        w.write_bytes(self.body_bytes, MAX_ATTESTATION_BODY_LEN)?;
        w.write_array(self.attestation_sig)
    }
}

impl<'a> Decode<'a> for DeviceAttestation<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let (body_bytes, body) =
            decode_embedded(r, MAX_ATTESTATION_BODY_LEN, SCHEMA_DEVICE_ATTESTATION_BODY)?;
        let attestation_sig = read_fixed::<HYBRID_SIG_LEN>(r)?;
        Ok(Self {
            body_bytes,
            body,
            attestation_sig,
        })
    }
}

/// The field QR summary of an attestation (not a ledger event). Its
/// signature is the Ed25519 half of the attestation key (purpose
/// `attest-summary`) over the encoding of the first seven fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AttestationSummary<'a> {
    device_id: Ident<'a>,
    observer_id: ObserverId<'a>,
    nonce: &'a [u8; NONCE_LEN],
    time_bucket: TimeBucket,
    boot_count: u32,
    bundle_hash: Hash512,
    body_hash: Hash512,
    summary_sig: &'a [u8; ED25519_SIG_LEN],
}

/// The fields of an [`AttestationSummary`] but its signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SummaryParts<'a> {
    /// The attesting device.
    pub device_id: Ident<'a>,
    /// The observer whose challenge was answered.
    pub observer_id: ObserverId<'a>,
    /// The challenge nonce.
    pub nonce: &'a [u8; NONCE_LEN],
    /// The time bucket.
    pub time_bucket: TimeBucket,
    /// The device's boot counter.
    pub boot_count: u32,
    /// The bundle hash.
    pub bundle_hash: Hash512,
    /// The object hash of the attestation's `DeviceAttestationBody`.
    pub body_hash: Hash512,
}

impl Encode for SummaryParts<'_> {
    fn encoded_len(&self) -> usize {
        ident_len(&self.device_id)
            .saturating_add(self.observer_id.encoded_len())
            .saturating_add(NONCE_LEN)
            .saturating_add(8)
            .saturating_add(4)
            .saturating_add(64)
            .saturating_add(64)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        w.write_ident(&self.device_id, MAX_DEVICE_ID_LEN)?;
        self.observer_id.encode(w)?;
        w.write_array(self.nonce)?;
        self.time_bucket.encode(w)?;
        w.write_u32(self.boot_count)?;
        self.bundle_hash.encode(w)?;
        self.body_hash.encode(w)
    }
}

impl<'a> AttestationSummary<'a> {
    /// Builds a summary. `None` if the device identifier is longer than 64
    /// bytes.
    #[must_use]
    pub fn new(parts: &SummaryParts<'a>, summary_sig: &'a [u8; ED25519_SIG_LEN]) -> Option<Self> {
        if parts.device_id.byte_len() > MAX_DEVICE_ID_LEN {
            return None;
        }
        Some(Self {
            device_id: parts.device_id,
            observer_id: parts.observer_id,
            nonce: parts.nonce,
            time_bucket: parts.time_bucket,
            boot_count: parts.boot_count,
            bundle_hash: parts.bundle_hash,
            body_hash: parts.body_hash,
            summary_sig,
        })
    }

    /// The signed fields.
    #[must_use]
    pub const fn parts(&self) -> SummaryParts<'a> {
        SummaryParts {
            device_id: self.device_id,
            observer_id: self.observer_id,
            nonce: self.nonce,
            time_bucket: self.time_bucket,
            boot_count: self.boot_count,
            bundle_hash: self.bundle_hash,
            body_hash: self.body_hash,
        }
    }

    /// The Ed25519 signature.
    #[must_use]
    pub const fn summary_sig(&self) -> &'a [u8; ED25519_SIG_LEN] {
        self.summary_sig
    }
}

impl Encode for AttestationSummary<'_> {
    fn encoded_len(&self) -> usize {
        self.parts().encoded_len().saturating_add(ED25519_SIG_LEN)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        self.parts().encode(w)?;
        w.write_array(self.summary_sig)
    }
}

impl<'a> Decode<'a> for AttestationSummary<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        Ok(Self {
            device_id: r.read_ident(MAX_DEVICE_ID_LEN)?,
            observer_id: ObserverId::decode(r)?,
            nonce: read_fixed::<NONCE_LEN>(r)?,
            time_bucket: TimeBucket::decode(r)?,
            boot_count: r.read_u32()?,
            bundle_hash: Hash512::decode(r)?,
            body_hash: Hash512::decode(r)?,
            summary_sig: read_fixed::<ED25519_SIG_LEN>(r)?,
        })
    }
}
