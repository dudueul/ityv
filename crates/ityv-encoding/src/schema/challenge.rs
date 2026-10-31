//! `ChallengeOpeningBody` (schema `0x0006`) and `ChallengeOpening`
//! (schema `0x0018`), version 1: the public opening of a ballot spoiled by a
//! pre-cast challenge (PROTOCOL.md §8, ENCODING.md §8.8–§8.9).
//!
//! `ChallengeOpeningBody` field order: `election_id`, `box_id`,
//! `ballot_style_id`, `record_hash`, `option_index`, `cast_id`, `rand`,
//! `modules`. `ChallengeOpening` field order: `body`, `device_sig`.

use crate::codec::{Decode, Encode};
use crate::error::{Error, Kind};
use crate::primitives::{BallotStyleId, BoxId, ElectionId, Hash512, ModuleId, Token192};
use crate::reader::Reader;
use crate::schema::SCHEMA_CHALLENGE_OPENING_BODY;
use crate::schema::util::{
    HYBRID_SIG_LEN, MAX_CHUNKS, MAX_MODULES, Scalars, ascending_by, check_embedded,
    decode_embedded, read_fixed,
};
use crate::writer::Writer;

/// Largest option index the proof system supports (`m + 1 <= 63`).
pub const MAX_OPTION_INDEX: u16 = 63;

/// Maximum length of the embedded `ChallengeOpeningBody` object bytes.
pub const MAX_CHALLENGE_BODY_LEN: usize = 4096;

/// One module's contribution to the opened ballot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ModuleOpening<'a> {
    /// The module.
    pub module_id: ModuleId<'a>,
    /// The module's counter for this ballot.
    pub counter: u64,
    /// The module's randomness contributions `r_{c,0..k−1}`.
    pub rand: Scalars<MAX_CHUNKS>,
    /// The module's cast-id contribution.
    pub cid: Token192,
}

/// Unvalidated inputs for [`ChallengeOpeningBody::new`].
#[derive(Debug, Clone, Copy)]
pub struct ChallengeOpeningParts<'a> {
    /// The election.
    pub election_id: ElectionId<'a>,
    /// The ballot box.
    pub box_id: BoxId<'a>,
    /// The ballot style.
    pub ballot_style_id: BallotStyleId<'a>,
    /// The tracking code of the spoiled record.
    pub record_hash: Hash512,
    /// The opened option index (`0..=63`).
    pub option_index: u16,
    /// The opened cast id.
    pub cast_id: Token192,
    /// The summed randomness (`k >= 1` scalars).
    pub rand: &'a Scalars<MAX_CHUNKS>,
    /// The per-module contributions, ascending by identifier.
    pub modules: &'a [ModuleOpening<'a>],
}

/// The body of a challenge opening.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChallengeOpeningBody<'a> {
    election_id: ElectionId<'a>,
    box_id: BoxId<'a>,
    ballot_style_id: BallotStyleId<'a>,
    record_hash: Hash512,
    option_index: u16,
    cast_id: Token192,
    rand: Scalars<MAX_CHUNKS>,
    modules: [Option<ModuleOpening<'a>>; MAX_MODULES],
    module_count: u8,
}

impl<'a> ChallengeOpeningBody<'a> {
    /// Builds a body. Returns `None` if `option_index > 63`, `rand` is
    /// empty, `modules` is not strictly ascending by identifier, has more
    /// than six entries, or any module's `rand` count differs from `rand`'s.
    #[must_use]
    pub fn new(parts: &ChallengeOpeningParts<'a>) -> Option<Self> {
        let modules = parts.modules;
        let rand = *parts.rand;
        if parts.option_index > MAX_OPTION_INDEX || rand.count() == 0 || modules.len() > MAX_MODULES
        {
            return None;
        }
        let ascending = ascending_by(modules, |x| x.module_id.as_bytes());
        if !ascending || modules.iter().any(|m| m.rand.count() != rand.count()) {
            return None;
        }
        let mut slots = [None; MAX_MODULES];
        for (slot, module) in slots.iter_mut().zip(modules) {
            *slot = Some(*module);
        }
        Some(Self {
            election_id: parts.election_id,
            box_id: parts.box_id,
            ballot_style_id: parts.ballot_style_id,
            record_hash: parts.record_hash,
            option_index: parts.option_index,
            cast_id: parts.cast_id,
            rand,
            modules: slots,
            module_count: u8::try_from(modules.len()).ok()?,
        })
    }

    /// The election.
    #[must_use]
    pub const fn election_id(&self) -> ElectionId<'a> {
        self.election_id
    }

    /// The ballot box.
    #[must_use]
    pub const fn box_id(&self) -> BoxId<'a> {
        self.box_id
    }

    /// The ballot style.
    #[must_use]
    pub const fn ballot_style_id(&self) -> BallotStyleId<'a> {
        self.ballot_style_id
    }

    /// The tracking code of the spoiled record.
    #[must_use]
    pub const fn record_hash(&self) -> &Hash512 {
        &self.record_hash
    }

    /// The opened option index.
    #[must_use]
    pub const fn option_index(&self) -> u16 {
        self.option_index
    }

    /// The opened cast id.
    #[must_use]
    pub const fn cast_id(&self) -> &Token192 {
        &self.cast_id
    }

    /// The summed randomness `r_0..r_{k−1}`.
    #[must_use]
    pub const fn rand(&self) -> &Scalars<MAX_CHUNKS> {
        &self.rand
    }

    /// The per-module contributions in ascending identifier order.
    pub fn modules(&self) -> impl Iterator<Item = ModuleOpening<'a>> + '_ {
        self.modules
            .iter()
            .take(usize::from(self.module_count))
            .flatten()
            .copied()
    }
}

fn module_len(m: &ModuleOpening<'_>) -> usize {
    m.module_id
        .encoded_len()
        .saturating_add(8)
        .saturating_add(m.rand.encoded_len())
        .saturating_add(24)
}

impl Encode for ChallengeOpeningBody<'_> {
    fn encoded_len(&self) -> usize {
        let modules = self
            .modules()
            .fold(4usize, |acc, m| acc.saturating_add(module_len(&m)));
        self.election_id
            .encoded_len()
            .saturating_add(self.box_id.encoded_len())
            .saturating_add(self.ballot_style_id.encoded_len())
            .saturating_add(64)
            .saturating_add(2)
            .saturating_add(24)
            .saturating_add(self.rand.encoded_len())
            .saturating_add(modules)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        self.election_id.encode(w)?;
        self.box_id.encode(w)?;
        self.ballot_style_id.encode(w)?;
        self.record_hash.encode(w)?;
        w.write_u16(self.option_index)?;
        self.cast_id.encode(w)?;
        self.rand.encode(w)?;
        w.write_count(usize::from(self.module_count), MAX_MODULES)?;
        for m in self.modules() {
            m.module_id.encode(w)?;
            w.write_u64(m.counter)?;
            m.rand.encode(w)?;
            m.cid.encode(w)?;
        }
        Ok(())
    }
}

impl<'a> Decode<'a> for ChallengeOpeningBody<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let election_id = ElectionId::decode(r)?;
        let box_id = BoxId::decode(r)?;
        let ballot_style_id = BallotStyleId::decode(r)?;
        let record_hash = Hash512::decode(r)?;
        let index_at = r.position();
        let option_index = r.read_u16()?;
        if option_index > MAX_OPTION_INDEX {
            return Err(Error::new(Kind::ValueOutOfRange, index_at));
        }
        let cast_id = Token192::decode(r)?;
        let rand_at = r.position();
        let rand = Scalars::<MAX_CHUNKS>::decode(r)?;
        if rand.count() == 0 {
            return Err(Error::new(Kind::ValueOutOfRange, rand_at));
        }
        let modules_at = r.position();
        let count = r.read_count(MAX_MODULES)?;
        let mut modules = [None; MAX_MODULES];
        let mut previous: Option<&[u8]> = None;
        for slot in modules.iter_mut().take(count) {
            let id_at = r.position();
            let module_id = ModuleId::decode(r)?;
            Reader::check_ascending(previous, module_id.as_bytes(), id_at)?;
            previous = Some(module_id.as_bytes());
            let counter = r.read_u64()?;
            let mrand_at = r.position();
            let mrand = Scalars::<MAX_CHUNKS>::decode(r)?;
            if mrand.count() != rand.count() {
                return Err(Error::new(Kind::InvariantViolation, mrand_at));
            }
            let cid = Token192::decode(r)?;
            *slot = Some(ModuleOpening {
                module_id,
                counter,
                rand: mrand,
                cid,
            });
        }
        Ok(Self {
            election_id,
            box_id,
            ballot_style_id,
            record_hash,
            option_index,
            cast_id,
            rand,
            modules,
            module_count: u8::try_from(count)
                .map_err(|_| Error::new(Kind::CountExceedsMax, modules_at))?,
        })
    }
}

/// A challenge opening event: the body object bytes with the device's
/// hybrid signature (purpose `challenge`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChallengeOpening<'a> {
    body_bytes: &'a [u8],
    body: ChallengeOpeningBody<'a>,
    device_sig: &'a [u8; HYBRID_SIG_LEN],
}

impl<'a> ChallengeOpening<'a> {
    /// Builds the event from a complete body object and the signature.
    ///
    /// # Errors
    /// The body's decoding error, or `LengthExceedsMax` at 0 if too long.
    pub fn new(body_bytes: &'a [u8], device_sig: &'a [u8; HYBRID_SIG_LEN]) -> Result<Self, Error> {
        let body = check_embedded(
            body_bytes,
            MAX_CHALLENGE_BODY_LEN,
            SCHEMA_CHALLENGE_OPENING_BODY,
        )?;
        Ok(Self {
            body_bytes,
            body,
            device_sig,
        })
    }

    /// The body object bytes (the signed message).
    #[must_use]
    pub const fn body_bytes(&self) -> &'a [u8] {
        self.body_bytes
    }

    /// The decoded body.
    #[must_use]
    pub const fn body(&self) -> &ChallengeOpeningBody<'a> {
        &self.body
    }

    /// The device's hybrid signature.
    #[must_use]
    pub const fn device_sig(&self) -> &'a [u8; HYBRID_SIG_LEN] {
        self.device_sig
    }
}

impl Encode for ChallengeOpening<'_> {
    fn encoded_len(&self) -> usize {
        self.body_bytes
            .len()
            .saturating_add(4)
            .saturating_add(HYBRID_SIG_LEN)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        w.write_bytes(self.body_bytes, MAX_CHALLENGE_BODY_LEN)?;
        w.write_array(self.device_sig)
    }
}

impl<'a> Decode<'a> for ChallengeOpening<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let (body_bytes, body) =
            decode_embedded(r, MAX_CHALLENGE_BODY_LEN, SCHEMA_CHALLENGE_OPENING_BODY)?;
        let device_sig = read_fixed::<HYBRID_SIG_LEN>(r)?;
        Ok(Self {
            body_bytes,
            body,
            device_sig,
        })
    }
}
