//! The participation ledger and the two key ceremonies behind it
//! (PROTOCOL.md §6.4, §6.5, §9.4.2; ENCODING.md §8.25, §8.31, §8.32):
//! `ParticipationSet` (schema `0x0020`), `ModuleProvisioned` (`0x0026`) and
//! `PartyKeyCeremony` (`0x0027`), all version 1.
//!
//! Each object is a field group followed by its signatures, and the
//! signatures cover the field group's encoding without an object header
//! (ENCODING.md §4, header-less field groups): fields 1–4 of a
//! participation set (purpose `participation-set`), fields 1–14 of a
//! module provisioning (`module-provisioned`), fields 1–8 of a party key
//! ceremony (`party-key`). The decoders keep those bytes as they came,
//! borrowed ([`ParticipationSet::message_bytes`] and the like), so a
//! verifier checks a signature without encoding anything again; a
//! participation set can hold 65 536 pseudonyms (about 4.2 MB).
//!
//! `ParticipationSet` field order: `election_id`, `station_id`, `count`,
//! `pseudonyms` (non-decreasing, a repeated pseudonym repeated), then
//! `counter_sig` and `module_sigs` (at most four, distinct modules).
//! `ModuleProvisioned`: `election_id`, `module_id`, `device_id`, `chamber`
//! (1–7), `member_count` (1–8), `pad_length`, `chassis_id`, `pad_card_id`,
//! `reprovision_count`, `chassis_check_hash`, `kem_ek`,
//! `entropy_commitment`, `se_present`, `prf_key_check`, then `signatures`.
//! `PartyKeyCeremony`: `election_id`, `chamber` (1–4), `wrapped_module_count`,
//! `share_threshold`, `share_count` (`1 ≤ share_threshold ≤ share_count ≤
//! 8`), `share_holders` (`share_count` of them, ascending by trustee),
//! `prf_key_check`, `time_bucket`, then `signatures`. Signature arrays are
//! strictly ascending by `actor_id`.
//!
//! The encoding checks form only. It does not verify a signature, resolve
//! an actor to a registered key, or compare a field with the genesis; the
//! verifier does (PROTOCOL.md §14 6).

use crate::codec::{Decode, Encode};
use crate::error::{Error, Kind};
use crate::primitives::{
    ElectionId, Hash512, IDENT_MAX_STANDARD, Ident, ModuleId, StationId, TimeBucket, TrusteeId,
};
use crate::reader::Reader;
use crate::schema::share_package::ChamberCode;
use crate::schema::util::{HYBRID_SIG_LEN, ascending_by, read_fixed};
use crate::writer::Writer;

/// Purpose of the signatures on a participation set.
pub const PURPOSE_PARTICIPATION_SET: &[u8] = b"participation-set";

/// Purpose of the signatures on a module provisioning record.
pub const PURPOSE_MODULE_PROVISIONED: &[u8] = b"module-provisioned";

/// Purpose of the signatures on a party key ceremony record.
pub const PURPOSE_PARTY_KEY: &[u8] = b"party-key";

/// The `actor_id` under which the committee (독립검증위원회) signs a
/// provisioning or ceremony record, with the committee key of the genesis.
/// The committee has no roster entry, so its identifier is reserved here.
pub const COMMITTEE_ACTOR: &[u8] = b"committee";

/// Length of one pseudonym.
pub const PSEUDONYM_LEN: usize = 64;

/// Most pseudonyms in one participation set (and the largest `count`).
pub const MAX_PSEUDONYMS: usize = 65_536;

/// Most party module signatures on a participation set (P1–P4).
pub const MAX_PARTY_MODULES: usize = 4;

/// Most actor signatures on a provisioning or ceremony record.
pub const MAX_ACTOR_SIGS: usize = 16;

/// Most share holders of a party key (and the largest `share_count`).
pub const MAX_SHARE_HOLDERS: usize = 8;

/// The largest number of chamber members a module makes pads for.
pub const MAX_MEMBER_COUNT: u8 = 8;

/// Length of a module's hybrid KEM public key (`mlkem1024_ek ‖ x25519`).
pub const KEM_EK_LEN: usize = 1600;

/// Length of a party PRF key check value (`HMAC-SHA-256(key_c,
/// "ityv:prfcheck:v2")`).
pub const PRF_KEY_CHECK_LEN: usize = 32;

fn invalid(at: usize) -> Error {
    Error::new(Kind::InvariantViolation, at)
}

const fn ident_len(ident: &Ident<'_>) -> usize {
    ident.byte_len().saturating_add(4)
}

/// Whether `chamber` is a party chamber (`P1`–`P4`).
#[must_use]
pub const fn is_party_chamber(chamber: ChamberCode) -> bool {
    matches!(
        chamber,
        ChamberCode::P1 | ChamberCode::P2 | ChamberCode::P3 | ChamberCode::P4
    )
}

fn read_chamber(r: &mut Reader<'_>, party_only: bool) -> Result<ChamberCode, Error> {
    let at = r.position();
    match ChamberCode::from_code(r.read_u8()?) {
        Some(c) if is_party_chamber(c) || (!party_only && c != ChamberCode::N) => Ok(c),
        Some(_) | None => Err(Error::new(Kind::ValueOutOfRange, at)),
    }
}

// ---------------------------------------------------------------------------
// ParticipationSet (0x0020)
// ---------------------------------------------------------------------------

/// A participation set's pseudonyms: 64-byte values in non-decreasing byte
/// order, a repeated pseudonym repeated, borrowed as one slice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Pseudonyms<'a> {
    bytes: &'a [u8],
}

impl<'a> Pseudonyms<'a> {
    /// The pseudonyms in `bytes`. `None` unless `bytes` is a whole number,
    /// at most [`MAX_PSEUDONYMS`], of 64-byte values in non-decreasing
    /// order.
    #[must_use]
    pub fn new(bytes: &'a [u8]) -> Option<Self> {
        let whole = bytes.len().checked_rem(PSEUDONYM_LEN) == Some(0);
        let count = bytes.len().checked_div(PSEUDONYM_LEN)?;
        let ordered = bytes
            .chunks_exact(PSEUDONYM_LEN)
            .zip(bytes.chunks_exact(PSEUDONYM_LEN).skip(1))
            .all(|(a, b)| a <= b);
        (whole && count <= MAX_PSEUDONYMS && ordered).then_some(Self { bytes })
    }

    /// The pseudonyms as one slice of `64 · len` bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// The number of pseudonyms.
    #[must_use]
    pub const fn len(&self) -> usize {
        // `bytes` holds whole pseudonyms; the divisor is not zero.
        match self.bytes.len().checked_div(PSEUDONYM_LEN) {
            Some(n) => n,
            None => 0,
        }
    }

    /// Whether there are none.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// The pseudonyms in order.
    pub fn iter(&self) -> impl Iterator<Item = &'a [u8; PSEUDONYM_LEN]> + use<'a> {
        self.bytes
            .chunks_exact(PSEUDONYM_LEN)
            .filter_map(|c| c.try_into().ok())
    }
}

/// The signed field group of a participation set (fields 1–4): what the
/// counter unit and the party modules sign, without an object header.
/// `count` is the number of pseudonyms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ParticipationMessage<'a> {
    /// The election.
    pub election_id: ElectionId<'a>,
    /// The polling station.
    pub station_id: StationId<'a>,
    /// The pseudonyms.
    pub pseudonyms: Pseudonyms<'a>,
}

impl ParticipationMessage<'_> {
    /// The `count` field.
    #[must_use]
    pub fn count(&self) -> u32 {
        // At most 65 536 pseudonyms (`Pseudonyms::new`), so this fits.
        u32::try_from(self.pseudonyms.len()).unwrap_or(u32::MAX)
    }
}

impl Encode for ParticipationMessage<'_> {
    fn encoded_len(&self) -> usize {
        self.election_id
            .encoded_len()
            .saturating_add(self.station_id.encoded_len())
            .saturating_add(8)
            .saturating_add(self.pseudonyms.bytes.len())
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        self.election_id.encode(w)?;
        self.station_id.encode(w)?;
        w.write_u32(self.count())?;
        w.write_count(self.pseudonyms.len(), MAX_PSEUDONYMS)?;
        w.write_slice(self.pseudonyms.bytes)
    }
}

impl<'a> Decode<'a> for ParticipationMessage<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let election_id = ElectionId::decode(r)?;
        let station_id = StationId::decode(r)?;
        let count_at = r.position();
        let count = r.read_u32()?;
        if usize::try_from(count).map_or(true, |c| c > MAX_PSEUDONYMS) {
            return Err(Error::new(Kind::ValueOutOfRange, count_at));
        }
        let array_at = r.position();
        let n = r.read_count(MAX_PSEUDONYMS)?;
        if u32::try_from(n).ok() != Some(count) {
            return Err(invalid(array_at));
        }
        let start = r.position();
        let mut previous: Option<&[u8]> = None;
        for _ in 0..n {
            let at = r.position();
            let pseudonym = r.take(PSEUDONYM_LEN)?;
            if previous.is_some_and(|p| p > pseudonym) {
                return Err(Error::new(Kind::NotSorted, at));
            }
            previous = Some(pseudonym);
        }
        Ok(Self {
            election_id,
            station_id,
            pseudonyms: Pseudonyms {
                bytes: r.consumed_from(start)?,
            },
        })
    }
}

/// A party module's signature on a participation set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ParticipationModuleSig<'a> {
    /// The party module.
    pub module_id: ModuleId<'a>,
    /// Its hybrid signature over the message (purpose `participation-set`).
    pub sig: &'a [u8; HYBRID_SIG_LEN],
}

/// Decodes a complete header-less field group of type `T` from `bytes`.
fn decode_message<'a, T: Decode<'a>>(bytes: &'a [u8]) -> Result<T, Error> {
    let mut r = Reader::new(bytes);
    let value = T::decode(&mut r)?;
    r.finish()?;
    Ok(value)
}

/// A station's participation set: the pseudonym multiset the check-in
/// unit publishes after close, signed by the unit and by each party module
/// P1…Pn (PROTOCOL.md §6.5, VC-084).
///
/// Rules: the message is canonical (`count` equals the number of
/// pseudonyms, `InvariantViolation`; non-decreasing, `NotSorted`); at most
/// four module signatures (`CountExceedsMax`) of distinct modules
/// (`Duplicate`). Their order (chamber code order) and number (one per
/// party) need the genesis and are the verifier's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ParticipationSet<'a> {
    message_bytes: &'a [u8],
    message: ParticipationMessage<'a>,
    counter_sig: &'a [u8; HYBRID_SIG_LEN],
    module_sigs: [Option<ParticipationModuleSig<'a>>; MAX_PARTY_MODULES],
    module_sig_count: u8,
}

/// The module signatures in slots, or the error of the first bad one.
fn module_slots<'a>(
    sigs: &[ParticipationModuleSig<'a>],
) -> Result<[Option<ParticipationModuleSig<'a>>; MAX_PARTY_MODULES], Error> {
    if sigs.len() > MAX_PARTY_MODULES {
        return Err(Error::new(Kind::CountExceedsMax, 0));
    }
    let mut slots = [None; MAX_PARTY_MODULES];
    for (i, (slot, sig)) in slots.iter_mut().zip(sigs).enumerate() {
        if sigs
            .iter()
            .take(i)
            .any(|s| s.module_id.as_bytes() == sig.module_id.as_bytes())
        {
            return Err(Error::new(Kind::Duplicate, 0));
        }
        *slot = Some(*sig);
    }
    Ok(slots)
}

impl<'a> ParticipationSet<'a> {
    /// Builds a set from its signed field group (the encoding of a
    /// [`ParticipationMessage`]) and its signatures.
    ///
    /// # Errors
    /// The decoding error of `message_bytes` (with `TrailingBytes` for
    /// bytes after it), `CountExceedsMax` at 0 for more than four module
    /// signatures, `Duplicate` at 0 for two of one module.
    pub fn new(
        message_bytes: &'a [u8],
        counter_sig: &'a [u8; HYBRID_SIG_LEN],
        module_sigs: &[ParticipationModuleSig<'a>],
    ) -> Result<Self, Error> {
        let message = decode_message(message_bytes)?;
        let slots = module_slots(module_sigs)?;
        Ok(Self {
            message_bytes,
            message,
            counter_sig,
            module_sigs: slots,
            module_sig_count: u8::try_from(module_sigs.len())
                .map_err(|_| Error::new(Kind::CountExceedsMax, 0))?,
        })
    }

    /// The signed field group (fields 1–4), as it came.
    #[must_use]
    pub const fn message_bytes(&self) -> &'a [u8] {
        self.message_bytes
    }

    /// The decoded field group.
    #[must_use]
    pub const fn message(&self) -> &ParticipationMessage<'a> {
        &self.message
    }

    /// The election.
    #[must_use]
    pub const fn election_id(&self) -> ElectionId<'a> {
        self.message.election_id
    }

    /// The polling station.
    #[must_use]
    pub const fn station_id(&self) -> StationId<'a> {
        self.message.station_id
    }

    /// The number of pseudonyms (`count`).
    #[must_use]
    pub fn count(&self) -> u32 {
        self.message.count()
    }

    /// The pseudonyms.
    #[must_use]
    pub const fn pseudonyms(&self) -> Pseudonyms<'a> {
        self.message.pseudonyms
    }

    /// The check-in unit's signature.
    #[must_use]
    pub const fn counter_sig(&self) -> &'a [u8; HYBRID_SIG_LEN] {
        self.counter_sig
    }

    /// The party modules' signatures, in the order given.
    pub fn module_sigs(&self) -> impl Iterator<Item = ParticipationModuleSig<'a>> + '_ {
        self.module_sigs
            .iter()
            .take(usize::from(self.module_sig_count))
            .flatten()
            .copied()
    }

    /// The number of module signatures.
    #[must_use]
    pub fn module_sig_count(&self) -> usize {
        usize::from(self.module_sig_count)
    }
}

impl Encode for ParticipationSet<'_> {
    fn encoded_len(&self) -> usize {
        let sigs = self.module_sigs().fold(4usize, |acc, s| {
            acc.saturating_add(s.module_id.encoded_len())
                .saturating_add(HYBRID_SIG_LEN)
        });
        self.message_bytes
            .len()
            .saturating_add(HYBRID_SIG_LEN)
            .saturating_add(sigs)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        w.write_slice(self.message_bytes)?;
        w.write_array(self.counter_sig)?;
        w.write_count(self.module_sig_count(), MAX_PARTY_MODULES)?;
        for sig in self.module_sigs() {
            sig.module_id.encode(w)?;
            w.write_array(sig.sig)?;
        }
        Ok(())
    }
}

impl<'a> Decode<'a> for ParticipationSet<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let start = r.position();
        let message = ParticipationMessage::decode(r)?;
        let message_bytes = r.consumed_from(start)?;
        let counter_sig = read_fixed::<HYBRID_SIG_LEN>(r)?;
        let sigs_at = r.position();
        let count = r.read_count(MAX_PARTY_MODULES)?;
        let mut module_sigs: [Option<ParticipationModuleSig<'a>>; MAX_PARTY_MODULES] =
            [None; MAX_PARTY_MODULES];
        for i in 0..count {
            let at = r.position();
            let module_id = ModuleId::decode(r)?;
            if module_sigs
                .iter()
                .take(i)
                .flatten()
                .any(|s| s.module_id.as_bytes() == module_id.as_bytes())
            {
                return Err(Error::new(Kind::Duplicate, at));
            }
            let sig = read_fixed::<HYBRID_SIG_LEN>(r)?;
            if let Some(slot) = module_sigs.get_mut(i) {
                *slot = Some(ParticipationModuleSig { module_id, sig });
            }
        }
        Ok(Self {
            message_bytes,
            message,
            counter_sig,
            module_sigs,
            module_sig_count: u8::try_from(count)
                .map_err(|_| Error::new(Kind::CountExceedsMax, sigs_at))?,
        })
    }
}

// ---------------------------------------------------------------------------
// Actor signatures (shared by 0x0026 and 0x0027)
// ---------------------------------------------------------------------------

/// One attendee's hybrid signature on a provisioning or ceremony record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ActorSig<'a> {
    /// The signer: [`COMMITTEE_ACTOR`], a trustee or a roster observer.
    pub actor_id: Ident<'a>,
    /// The signature over the record's field group.
    pub sig: &'a [u8; HYBRID_SIG_LEN],
}

/// The signatures of a provisioning or ceremony record: at most sixteen,
/// strictly ascending by `actor_id` (`NotSorted`, `Duplicate`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ActorSigs<'a> {
    items: [Option<ActorSig<'a>>; MAX_ACTOR_SIGS],
    count: u8,
}

impl<'a> ActorSigs<'a> {
    /// The signatures in `sigs`. `None` if there are more than sixteen, an
    /// identifier is longer than 64 bytes, or they are not strictly
    /// ascending.
    #[must_use]
    pub fn new(sigs: &[ActorSig<'a>]) -> Option<Self> {
        if sigs.len() > MAX_ACTOR_SIGS
            || sigs
                .iter()
                .any(|s| s.actor_id.byte_len() > IDENT_MAX_STANDARD)
            || !ascending_by(sigs, |s| s.actor_id.as_bytes())
        {
            return None;
        }
        let mut items = [None; MAX_ACTOR_SIGS];
        for (slot, sig) in items.iter_mut().zip(sigs) {
            *slot = Some(*sig);
        }
        Some(Self {
            items,
            count: u8::try_from(sigs.len()).ok()?,
        })
    }

    /// The signatures in ascending actor order.
    pub fn iter(&self) -> impl Iterator<Item = ActorSig<'a>> + '_ {
        self.items
            .iter()
            .take(usize::from(self.count))
            .flatten()
            .copied()
    }

    /// The number of signatures.
    #[must_use]
    pub fn len(&self) -> usize {
        usize::from(self.count)
    }

    /// Whether there are none.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Encode for ActorSigs<'_> {
    fn encoded_len(&self) -> usize {
        self.iter().fold(4usize, |acc, s| {
            acc.saturating_add(ident_len(&s.actor_id))
                .saturating_add(HYBRID_SIG_LEN)
        })
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        w.write_count(self.len(), MAX_ACTOR_SIGS)?;
        for sig in self.iter() {
            w.write_ident(&sig.actor_id, IDENT_MAX_STANDARD)?;
            w.write_array(sig.sig)?;
        }
        Ok(())
    }
}

impl<'a> Decode<'a> for ActorSigs<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let at = r.position();
        let count = r.read_count(MAX_ACTOR_SIGS)?;
        let mut items: [Option<ActorSig<'a>>; MAX_ACTOR_SIGS] = [None; MAX_ACTOR_SIGS];
        let mut previous: Option<&[u8]> = None;
        for slot in items.iter_mut().take(count) {
            let id_at = r.position();
            let actor_id = r.read_ident(IDENT_MAX_STANDARD)?;
            Reader::check_ascending(previous, actor_id.as_bytes(), id_at)?;
            previous = Some(actor_id.as_bytes());
            let sig = read_fixed::<HYBRID_SIG_LEN>(r)?;
            *slot = Some(ActorSig { actor_id, sig });
        }
        Ok(Self {
            items,
            count: u8::try_from(count).map_err(|_| Error::new(Kind::CountExceedsMax, at))?,
        })
    }
}

// ---------------------------------------------------------------------------
// ModuleProvisioned (0x0026)
// ---------------------------------------------------------------------------

/// The fields of a module provisioning record (fields 1–14).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ModuleProvisionedParts<'a> {
    /// The election.
    pub election_id: ElectionId<'a>,
    /// The module.
    pub module_id: ModuleId<'a>,
    /// The device the module is made for: a box, or a check-in unit.
    pub device_id: Ident<'a>,
    /// The module's chamber (`P1`…`C`; `N` has no module).
    pub chamber: ChamberCode,
    /// The chamber members it makes pads for, 1–8.
    pub member_count: u8,
    /// Pad bytes per member.
    pub pad_length: u64,
    /// The reused chassis.
    pub chassis_id: Ident<'a>,
    /// The pad card.
    pub pad_card_id: Ident<'a>,
    /// How many times the chassis was provisioned before.
    pub reprovision_count: u32,
    /// Hash of the chassis tamper check and firmware measurement report.
    pub chassis_check_hash: Hash512,
    /// The module's hybrid KEM public key, for the party key.
    pub kem_ek: &'a [u8; KEM_EK_LEN],
    /// `SHA3-512("ityv:entropy:v1" ‖ 0x00 ‖ chamber entropy)` (VC-095).
    pub entropy_commitment: Hash512,
    /// Whether the module has a secure element.
    pub se_present: bool,
    /// For a check-in unit's party module, its party key check (VC-093);
    /// absent otherwise.
    pub prf_key_check: Option<&'a [u8; PRF_KEY_CHECK_LEN]>,
}

/// The signed field group of a module provisioning record.
///
/// Rules: identifiers of at most 64 bytes; chamber 1–7
/// (`ValueOutOfRange`); 1–8 members (`ValueOutOfRange`); a
/// `prf_key_check` only on a party module with a secure element
/// (`InvariantViolation`: only a check-in unit's party module carries one,
/// and such a module must have the secure element).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ModuleProvisionedMessage<'a> {
    parts: ModuleProvisionedParts<'a>,
}

const fn prf_allowed(parts: &ModuleProvisionedParts<'_>) -> bool {
    parts.prf_key_check.is_none() || (parts.se_present && is_party_chamber(parts.chamber))
}

impl<'a> ModuleProvisionedMessage<'a> {
    /// Builds the field group. `None` if a rule above does not hold.
    #[must_use]
    pub fn new(parts: &ModuleProvisionedParts<'a>) -> Option<Self> {
        let ids_ok = [parts.device_id, parts.chassis_id, parts.pad_card_id]
            .iter()
            .all(|i| i.byte_len() <= IDENT_MAX_STANDARD);
        let members_ok = (1..=MAX_MEMBER_COUNT).contains(&parts.member_count);
        (ids_ok && members_ok && parts.chamber != ChamberCode::N && prf_allowed(parts))
            .then_some(Self { parts: *parts })
    }

    /// The fields.
    #[must_use]
    pub const fn parts(&self) -> &ModuleProvisionedParts<'a> {
        &self.parts
    }
}

impl Encode for ModuleProvisionedMessage<'_> {
    fn encoded_len(&self) -> usize {
        let p = &self.parts;
        let prf = if p.prf_key_check.is_some() {
            1 + PRF_KEY_CHECK_LEN
        } else {
            1
        };
        p.election_id
            .encoded_len()
            .saturating_add(p.module_id.encoded_len())
            .saturating_add(ident_len(&p.device_id))
            .saturating_add(2)
            .saturating_add(8)
            .saturating_add(ident_len(&p.chassis_id))
            .saturating_add(ident_len(&p.pad_card_id))
            .saturating_add(4)
            .saturating_add(64)
            .saturating_add(KEM_EK_LEN)
            .saturating_add(64)
            .saturating_add(1)
            .saturating_add(prf)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        let p = &self.parts;
        p.election_id.encode(w)?;
        p.module_id.encode(w)?;
        w.write_ident(&p.device_id, IDENT_MAX_STANDARD)?;
        w.write_u8(p.chamber.code())?;
        w.write_u8(p.member_count)?;
        w.write_u64(p.pad_length)?;
        w.write_ident(&p.chassis_id, IDENT_MAX_STANDARD)?;
        w.write_ident(&p.pad_card_id, IDENT_MAX_STANDARD)?;
        w.write_u32(p.reprovision_count)?;
        p.chassis_check_hash.encode(w)?;
        w.write_array(p.kem_ek)?;
        p.entropy_commitment.encode(w)?;
        w.write_bool(p.se_present)?;
        w.write_presence(p.prf_key_check.is_some())?;
        if let Some(check) = p.prf_key_check {
            w.write_array(check)?;
        }
        Ok(())
    }
}

impl<'a> Decode<'a> for ModuleProvisionedMessage<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let election_id = ElectionId::decode(r)?;
        let module_id = ModuleId::decode(r)?;
        let device_id = r.read_ident(IDENT_MAX_STANDARD)?;
        let chamber = read_chamber(r, false)?;
        let members_at = r.position();
        let member_count = r.read_u8()?;
        if !(1..=MAX_MEMBER_COUNT).contains(&member_count) {
            return Err(Error::new(Kind::ValueOutOfRange, members_at));
        }
        let pad_length = r.read_u64()?;
        let chassis_id = r.read_ident(IDENT_MAX_STANDARD)?;
        let pad_card_id = r.read_ident(IDENT_MAX_STANDARD)?;
        let reprovision_count = r.read_u32()?;
        let chassis_check_hash = Hash512::decode(r)?;
        let kem_ek = read_fixed::<KEM_EK_LEN>(r)?;
        let entropy_commitment = Hash512::decode(r)?;
        let se_present = r.read_bool()?;
        let prf_at = r.position();
        let prf_key_check = if r.read_presence()? {
            Some(read_fixed::<PRF_KEY_CHECK_LEN>(r)?)
        } else {
            None
        };
        let parts = ModuleProvisionedParts {
            election_id,
            module_id,
            device_id,
            chamber,
            member_count,
            pad_length,
            chassis_id,
            pad_card_id,
            reprovision_count,
            chassis_check_hash,
            kem_ek,
            entropy_commitment,
            se_present,
            prf_key_check,
        };
        if !prf_allowed(&parts) {
            return Err(invalid(prf_at));
        }
        Ok(Self { parts })
    }
}

/// A module provisioning record (PROTOCOL.md §9.4.2): the field group and
/// the signatures of the committee, the chamber and observers. The genesis
/// pins its object hash in the module's entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ModuleProvisioned<'a> {
    message_bytes: &'a [u8],
    message: ModuleProvisionedMessage<'a>,
    signatures: ActorSigs<'a>,
}

impl<'a> ModuleProvisioned<'a> {
    /// Builds a record from its signed field group (the encoding of a
    /// [`ModuleProvisionedMessage`]) and its signatures.
    ///
    /// # Errors
    /// The decoding error of `message_bytes` (with `TrailingBytes` for
    /// bytes after it), `InvariantViolation` at 0 if the signatures break
    /// a rule of [`ActorSigs::new`].
    pub fn new(message_bytes: &'a [u8], signatures: &[ActorSig<'a>]) -> Result<Self, Error> {
        Ok(Self {
            message_bytes,
            message: decode_message(message_bytes)?,
            signatures: ActorSigs::new(signatures).ok_or_else(|| invalid(0))?,
        })
    }

    /// The signed field group (fields 1–14), as it came.
    #[must_use]
    pub const fn message_bytes(&self) -> &'a [u8] {
        self.message_bytes
    }

    /// The fields.
    #[must_use]
    pub const fn parts(&self) -> &ModuleProvisionedParts<'a> {
        self.message.parts()
    }

    /// The signatures, ascending by actor.
    #[must_use]
    pub const fn signatures(&self) -> &ActorSigs<'a> {
        &self.signatures
    }
}

impl Encode for ModuleProvisioned<'_> {
    fn encoded_len(&self) -> usize {
        self.message_bytes
            .len()
            .saturating_add(self.signatures.encoded_len())
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        w.write_slice(self.message_bytes)?;
        self.signatures.encode(w)
    }
}

impl<'a> Decode<'a> for ModuleProvisioned<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let start = r.position();
        let message = ModuleProvisionedMessage::decode(r)?;
        let message_bytes = r.consumed_from(start)?;
        Ok(Self {
            message_bytes,
            message,
            signatures: ActorSigs::decode(r)?,
        })
    }
}

// ---------------------------------------------------------------------------
// PartyKeyCeremony (0x0027)
// ---------------------------------------------------------------------------

/// A member who holds a share of the party key, and the device it is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ShareHolder<'a> {
    /// The party chamber member.
    pub trustee_id: TrusteeId<'a>,
    /// The USB HSM's product.
    pub hsm_model: Ident<'a>,
    /// Hash of the HSM's serial number.
    pub hsm_serial_hash: Hash512,
}

impl ShareHolder<'_> {
    fn len(&self) -> usize {
        self.trustee_id
            .encoded_len()
            .saturating_add(ident_len(&self.hsm_model))
            .saturating_add(64)
    }
}

/// Unvalidated inputs for [`PartyKeyMessage::new`]. `share_count` is the
/// number of share holders.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PartyKeyParts<'a, 's> {
    /// The election.
    pub election_id: ElectionId<'a>,
    /// The party chamber (`P1`–`P4`).
    pub chamber: ChamberCode,
    /// The check-in modules `key_c` was wrapped for.
    pub wrapped_module_count: u32,
    /// The share threshold `k`.
    pub share_threshold: u8,
    /// The share holders, ascending by trustee.
    pub share_holders: &'s [ShareHolder<'a>],
    /// `HMAC-SHA-256(key_c, "ityv:prfcheck:v2")` (VC-093).
    pub prf_key_check: &'a [u8; PRF_KEY_CHECK_LEN],
    /// The time bucket.
    pub time_bucket: TimeBucket,
}

/// The signed field group of a party key ceremony record (fields 1–8). It
/// holds no key, share or entropy (VC-092).
///
/// Rules: a party chamber (`ValueOutOfRange`); `1 ≤ share_threshold`
/// (`ValueOutOfRange` at the threshold) and `share_threshold ≤
/// share_count ≤ 8` (`ValueOutOfRange` at the count); exactly
/// `share_count` holders (`InvariantViolation`), strictly ascending by
/// trustee (`NotSorted`, `Duplicate`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PartyKeyMessage<'a> {
    election_id: ElectionId<'a>,
    chamber: ChamberCode,
    wrapped_module_count: u32,
    share_threshold: u8,
    holders: [Option<ShareHolder<'a>>; MAX_SHARE_HOLDERS],
    holder_count: u8,
    prf_key_check: &'a [u8; PRF_KEY_CHECK_LEN],
    time_bucket: TimeBucket,
}

impl<'a> PartyKeyMessage<'a> {
    /// Builds the field group. `None` if a rule above does not hold or an
    /// HSM model identifier is longer than 64 bytes.
    #[must_use]
    pub fn new(parts: &PartyKeyParts<'a, '_>) -> Option<Self> {
        let n = parts.share_holders.len();
        let shares_ok = parts.share_threshold >= 1
            && usize::from(parts.share_threshold) <= n
            && n <= MAX_SHARE_HOLDERS;
        let holders_ok = ascending_by(parts.share_holders, |h| h.trustee_id.as_bytes())
            && parts
                .share_holders
                .iter()
                .all(|h| h.hsm_model.byte_len() <= IDENT_MAX_STANDARD);
        if !shares_ok || !holders_ok || !is_party_chamber(parts.chamber) {
            return None;
        }
        let mut holders = [None; MAX_SHARE_HOLDERS];
        for (slot, holder) in holders.iter_mut().zip(parts.share_holders) {
            *slot = Some(*holder);
        }
        Some(Self {
            election_id: parts.election_id,
            chamber: parts.chamber,
            wrapped_module_count: parts.wrapped_module_count,
            share_threshold: parts.share_threshold,
            holders,
            holder_count: u8::try_from(n).ok()?,
            prf_key_check: parts.prf_key_check,
            time_bucket: parts.time_bucket,
        })
    }

    /// The election.
    #[must_use]
    pub const fn election_id(&self) -> ElectionId<'a> {
        self.election_id
    }

    /// The party chamber.
    #[must_use]
    pub const fn chamber(&self) -> ChamberCode {
        self.chamber
    }

    /// The check-in modules `key_c` was wrapped for.
    #[must_use]
    pub const fn wrapped_module_count(&self) -> u32 {
        self.wrapped_module_count
    }

    /// The share threshold `k`.
    #[must_use]
    pub const fn share_threshold(&self) -> u8 {
        self.share_threshold
    }

    /// The number of shares `n` (`share_count`).
    #[must_use]
    pub const fn share_count(&self) -> u8 {
        self.holder_count
    }

    /// The share holders, ascending by trustee.
    pub fn share_holders(&self) -> impl Iterator<Item = &ShareHolder<'a>> {
        self.holders
            .iter()
            .take(usize::from(self.holder_count))
            .flatten()
    }

    /// The party key check value.
    #[must_use]
    pub const fn prf_key_check(&self) -> &'a [u8; PRF_KEY_CHECK_LEN] {
        self.prf_key_check
    }

    /// The time bucket.
    #[must_use]
    pub const fn time_bucket(&self) -> TimeBucket {
        self.time_bucket
    }
}

impl Encode for PartyKeyMessage<'_> {
    fn encoded_len(&self) -> usize {
        let holders = self
            .share_holders()
            .fold(4usize, |acc, h| acc.saturating_add(h.len()));
        self.election_id
            .encoded_len()
            .saturating_add(1)
            .saturating_add(4)
            .saturating_add(2)
            .saturating_add(holders)
            .saturating_add(PRF_KEY_CHECK_LEN)
            .saturating_add(8)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        self.election_id.encode(w)?;
        w.write_u8(self.chamber.code())?;
        w.write_u32(self.wrapped_module_count)?;
        w.write_u8(self.share_threshold)?;
        w.write_u8(self.holder_count)?;
        w.write_count(usize::from(self.holder_count), MAX_SHARE_HOLDERS)?;
        for h in self.share_holders() {
            h.trustee_id.encode(w)?;
            w.write_ident(&h.hsm_model, IDENT_MAX_STANDARD)?;
            h.hsm_serial_hash.encode(w)?;
        }
        w.write_array(self.prf_key_check)?;
        self.time_bucket.encode(w)
    }
}

impl<'a> Decode<'a> for PartyKeyMessage<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let election_id = ElectionId::decode(r)?;
        let chamber = read_chamber(r, true)?;
        let wrapped_module_count = r.read_u32()?;
        let threshold_at = r.position();
        let share_threshold = r.read_u8()?;
        if share_threshold == 0 {
            return Err(Error::new(Kind::ValueOutOfRange, threshold_at));
        }
        let count_at = r.position();
        let share_count = r.read_u8()?;
        if share_count < share_threshold || usize::from(share_count) > MAX_SHARE_HOLDERS {
            return Err(Error::new(Kind::ValueOutOfRange, count_at));
        }
        let holders_at = r.position();
        let n = r.read_count(MAX_SHARE_HOLDERS)?;
        if n != usize::from(share_count) {
            return Err(invalid(holders_at));
        }
        let mut holders: [Option<ShareHolder<'a>>; MAX_SHARE_HOLDERS] = [None; MAX_SHARE_HOLDERS];
        let mut previous: Option<&[u8]> = None;
        for slot in holders.iter_mut().take(n) {
            let at = r.position();
            let trustee_id = TrusteeId::decode(r)?;
            Reader::check_ascending(previous, trustee_id.as_bytes(), at)?;
            previous = Some(trustee_id.as_bytes());
            *slot = Some(ShareHolder {
                trustee_id,
                hsm_model: r.read_ident(IDENT_MAX_STANDARD)?,
                hsm_serial_hash: Hash512::decode(r)?,
            });
        }
        Ok(Self {
            election_id,
            chamber,
            wrapped_module_count,
            share_threshold,
            holders,
            holder_count: share_count,
            prf_key_check: read_fixed::<PRF_KEY_CHECK_LEN>(r)?,
            time_bucket: TimeBucket::decode(r)?,
        })
    }
}

/// A party key ceremony record (PROTOCOL.md §6.4): the field group and the
/// signatures of the committee, the attending party members and observers
/// of two or more organisations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PartyKeyCeremony<'a> {
    message_bytes: &'a [u8],
    message: PartyKeyMessage<'a>,
    signatures: ActorSigs<'a>,
}

impl<'a> PartyKeyCeremony<'a> {
    /// Builds a record from its signed field group (the encoding of a
    /// [`PartyKeyMessage`]) and its signatures.
    ///
    /// # Errors
    /// The decoding error of `message_bytes` (with `TrailingBytes` for
    /// bytes after it), `InvariantViolation` at 0 if the signatures break
    /// a rule of [`ActorSigs::new`].
    pub fn new(message_bytes: &'a [u8], signatures: &[ActorSig<'a>]) -> Result<Self, Error> {
        Ok(Self {
            message_bytes,
            message: decode_message(message_bytes)?,
            signatures: ActorSigs::new(signatures).ok_or_else(|| invalid(0))?,
        })
    }

    /// The signed field group (fields 1–8), as it came.
    #[must_use]
    pub const fn message_bytes(&self) -> &'a [u8] {
        self.message_bytes
    }

    /// The fields.
    #[must_use]
    pub const fn message(&self) -> &PartyKeyMessage<'a> {
        &self.message
    }

    /// The signatures, ascending by actor.
    #[must_use]
    pub const fn signatures(&self) -> &ActorSigs<'a> {
        &self.signatures
    }
}

impl Encode for PartyKeyCeremony<'_> {
    fn encoded_len(&self) -> usize {
        self.message_bytes
            .len()
            .saturating_add(self.signatures.encoded_len())
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        w.write_slice(self.message_bytes)?;
        self.signatures.encode(w)
    }
}

impl<'a> Decode<'a> for PartyKeyCeremony<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let start = r.position();
        let message = PartyKeyMessage::decode(r)?;
        let message_bytes = r.consumed_from(start)?;
        Ok(Self {
            message_bytes,
            message,
            signatures: ActorSigs::decode(r)?,
        })
    }
}
