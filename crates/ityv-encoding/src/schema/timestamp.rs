//! Timestamp authorities and timestamp records (ADR-0034, ADR-0037,
//! ADR-0039; PROTOCOL.md §5.5; ENCODING.md §8.74, §8.75).
//!
//! * [`TimestampAuthorityEntry`] (schema `0x0050`, genesis set 12, fixed
//!   for the election): one RFC 3161 timestamp authority the genesis pins,
//!   with its operator, whether the government runs it, the accuracy its
//!   policy guarantees for tokens that state none, and one to four pins in
//!   the byte form of `ityv-tsa` (one per signing certificate, so that an
//!   authority may rotate its certificate during the election, ADR-0037
//!   §9). This crate checks the form only; the verifier reads each pin with
//!   `ityv-tsa`.
//! * [`TimestampRecord`] (schema `0x004F`, a ledger event): one
//!   authority's DER token over one earlier ledger event, or the note that
//!   the authority did not answer (ADR-0034 §3). It carries no signature of
//!   its own: the token is the authority's signed statement, and the
//!   witnesses' checkpoints cover the frame.

use crate::codec::{Decode, Encode};
use crate::error::{Error, Kind};
use crate::primitives::{AuthorityId, ElectionId, Hash512, OrgId, SchemaId};
use crate::reader::Reader;
use crate::schema::genesis::{EntrySet, GenesisEntry, read_nonzero_hash};
use crate::writer::Writer;

/// The longest pin a genesis entry carries: `ityv-tsa`'s fixed part (36
/// octets), its two length fields (4), eight policies of at most 66 octets
/// each (tag, length, a 64-octet arc string) and a certificate of at most
/// 16 384 octets (`ityv_tsa::MAX_TOKEN_LEN`).
pub const MAX_PIN_LEN: usize = 40 + 8 * 66 + 16_384;

/// The most pins one authority carries (one per signing certificate).
pub const MAX_TSA_PINS: usize = 4;

/// The longest token a timestamp record carries (`ityv_tsa::MAX_TOKEN_LEN`).
pub const MAX_TIMESTAMP_TOKEN_LEN: usize = 16_384;

/// The largest policy accuracy, in milliseconds: one hour, the largest
/// accuracy `ityv-tsa` accepts in a token (`MAX_ACCURACY_SECONDS`).
pub const MAX_POLICY_ACCURACY_MS: u32 = 3_600_000;

/// The ledger event schemas a timestamp record may stamp (ADR-0034 §2,
/// VC-117): a signed checkpoint (`0x0010`), a witnessed event (`0x0028`,
/// whose body the verifier checks: a legal decision or a voter-roll event)
/// and a signed genesis or amendment (`0x0033`). Records, check-in counters
/// and progress ticks are never stamped one by one.
pub const TIMESTAMP_TARGET_SCHEMAS: [SchemaId; 3] = [
    SchemaId::new(0x0010),
    SchemaId::new(0x0028),
    SchemaId::new(0x0033),
];

/// Whether a timestamp record may stamp an event of `schema`.
#[must_use]
pub const fn timestamp_target_allowed(schema: SchemaId) -> bool {
    matches!(schema.get(), 0x0010 | 0x0028 | 0x0033)
}

/// Who runs a timestamp authority (ADR-0034 §1, VC-114).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum TimestampAuthorityKind {
    /// Run by the Korean government (for example the timestamping of the
    /// administrative PKI).
    Government = 1,
    /// Not run by the government.
    NonGovernment = 2,
}

impl TimestampAuthorityKind {
    /// The wire code.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Returns the kind with wire code `code`, if defined.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Government),
            2 => Some(Self::NonGovernment),
            _ => None,
        }
    }
}

/// The accuracy an authority's policy guarantees for a token that states
/// none (RFC 3161 §2.4.2; ADR-0037 §9), in milliseconds, at most
/// [`MAX_POLICY_ACCURACY_MS`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PolicyAccuracy(u32);

impl PolicyAccuracy {
    /// `None` above [`MAX_POLICY_ACCURACY_MS`].
    #[must_use]
    pub const fn from_millis(millis: u32) -> Option<Self> {
        if millis <= MAX_POLICY_ACCURACY_MS {
            Some(Self(millis))
        } else {
            None
        }
    }

    /// The accuracy in milliseconds.
    #[must_use]
    pub const fn millis(self) -> u32 {
        self.0
    }
}

/// One to [`MAX_TSA_PINS`] pins, each one to [`MAX_PIN_LEN`] octets, in
/// strictly ascending byte order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TimestampPins<'a> {
    pins: [Option<&'a [u8]>; MAX_TSA_PINS],
    count: u8,
}

impl<'a> TimestampPins<'a> {
    /// `None` for no pin, more than [`MAX_TSA_PINS`], an empty or too long
    /// pin, or pins out of order or repeated.
    #[must_use]
    pub fn new(pins: &[&'a [u8]]) -> Option<Self> {
        let in_order = pins.windows(2).all(|w| match w {
            [a, b] => a < b,
            _ => true,
        });
        let sized = pins.iter().all(|p| !p.is_empty() && p.len() <= MAX_PIN_LEN);
        if pins.is_empty() || pins.len() > MAX_TSA_PINS || !in_order || !sized {
            return None;
        }
        let mut slots = [None; MAX_TSA_PINS];
        for (slot, p) in slots.iter_mut().zip(pins) {
            *slot = Some(*p);
        }
        Some(Self {
            pins: slots,
            count: u8::try_from(pins.len()).ok()?,
        })
    }

    /// The pins in order.
    pub fn iter(&self) -> impl Iterator<Item = &'a [u8]> + '_ {
        self.pins
            .iter()
            .take(usize::from(self.count))
            .flatten()
            .copied()
    }

    /// Number of pins (one to four).
    #[must_use]
    pub fn len(&self) -> usize {
        usize::from(self.count)
    }

    /// Always `false`: a valid list has at least one pin.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Encode for TimestampPins<'_> {
    fn encoded_len(&self) -> usize {
        self.iter().fold(4usize, |acc, p| {
            acc.saturating_add(4).saturating_add(p.len())
        })
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        w.write_count(self.len(), MAX_TSA_PINS)?;
        for p in self.iter() {
            w.write_bytes(p, MAX_PIN_LEN)?;
        }
        Ok(())
    }
}

impl<'a> Decode<'a> for TimestampPins<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let count_at = r.position();
        let count = r.read_count(MAX_TSA_PINS)?;
        if count == 0 {
            return Err(Error::new(Kind::InvariantViolation, count_at));
        }
        let mut pins = [None; MAX_TSA_PINS];
        let mut previous: Option<&[u8]> = None;
        for slot in pins.iter_mut().take(count) {
            let at = r.position();
            let pin = r.read_bytes(MAX_PIN_LEN)?;
            if pin.is_empty() {
                return Err(Error::new(Kind::InvariantViolation, at));
            }
            Reader::check_ascending(previous, pin, at)?;
            previous = Some(pin);
            *slot = Some(pin);
        }
        Ok(Self {
            pins,
            count: u8::try_from(count).map_err(|_| Error::new(Kind::CountExceedsMax, count_at))?,
        })
    }
}

/// One timestamp authority of the genesis (schema `0x0050`, set 12, key
/// `tsa_id`; ADR-0034 §1, ADR-0039).
///
/// Rules: the kind is 1 or 2 and the policy accuracy at most one hour
/// (`ValueOutOfRange`); one to four pins (`InvariantViolation` for none,
/// `CountExceedsMax`), none empty (`InvariantViolation`), strictly
/// ascending (`NotSorted`, `Duplicate`). That each pin is a valid
/// `ityv-tsa` pin allowing SHA-512 imprints, carrying its certificate and
/// an algorithm its key makes; that no certificate or key is pinned twice;
/// that the accuracy is one second to one minute; that one operator's
/// authorities are of one kind; that the set has a government and a
/// non-government authority (VC-114); and that no operator is a witness's
/// or a commission's organisation are the verifier's genesis rules
/// (ADR-0039 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TimestampAuthorityEntry<'a> {
    /// The authority, as timestamp records name it.
    pub tsa_id: AuthorityId<'a>,
    /// The organisation that runs it. Two authorities of one operator
    /// count as one toward the anchor rule (VC-115).
    pub operator: OrgId<'a>,
    /// Whether the government runs it.
    pub kind: TimestampAuthorityKind,
    /// The accuracy its policy guarantees for a token without an accuracy
    /// field.
    pub policy_accuracy: PolicyAccuracy,
    /// Its pins, one per signing certificate.
    pub pins: TimestampPins<'a>,
}

impl Encode for TimestampAuthorityEntry<'_> {
    fn encoded_len(&self) -> usize {
        self.tsa_id
            .encoded_len()
            .saturating_add(self.operator.encoded_len())
            .saturating_add(1 + 4)
            .saturating_add(self.pins.encoded_len())
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        self.tsa_id.encode(w)?;
        self.operator.encode(w)?;
        w.write_u8(self.kind.code())?;
        w.write_u32(self.policy_accuracy.millis())?;
        self.pins.encode(w)
    }
}

impl<'a> Decode<'a> for TimestampAuthorityEntry<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let tsa_id = AuthorityId::decode(r)?;
        let operator = OrgId::decode(r)?;
        let kind_at = r.position();
        let kind = TimestampAuthorityKind::from_code(r.read_u8()?)
            .ok_or_else(|| Error::new(Kind::ValueOutOfRange, kind_at))?;
        let accuracy_at = r.position();
        let policy_accuracy = PolicyAccuracy::from_millis(r.read_u32()?)
            .ok_or_else(|| Error::new(Kind::ValueOutOfRange, accuracy_at))?;
        Ok(Self {
            tsa_id,
            operator,
            kind,
            policy_accuracy,
            pins: TimestampPins::decode(r)?,
        })
    }
}

impl<'a> GenesisEntry<'a> for TimestampAuthorityEntry<'a> {
    const SET: EntrySet = EntrySet::TimestampAuthorities;

    fn key(&self) -> &'a [u8] {
        self.tsa_id.as_bytes()
    }
}

/// The fields of a timestamp record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TimestampRecordParts<'a> {
    /// The election.
    pub election_id: ElectionId<'a>,
    /// The schema of the stamped ledger event, as its frame names it.
    pub target_schema: SchemaId,
    /// The stamped event's object hash, the frame's `event_hash`: the
    /// token's imprint is its SHA-512 (ADR-0034 §3).
    pub target_hash: Hash512,
    /// The authority, as the genesis's timestamp authority set names it.
    pub authority_id: AuthorityId<'a>,
    /// The DER `TimeStampToken`, or `None` when the authority did not
    /// answer and the operator asked another (ADR-0034 §3).
    pub token: Option<&'a [u8]>,
}

/// A timestamp record (schema `0x004F`, a ledger event; ADR-0034 §3,
/// ADR-0039).
///
/// Rules: the target schema is one of [`TIMESTAMP_TARGET_SCHEMAS`]
/// (`ValueOutOfRange`, VC-117); the target hash is nonzero
/// (`InvalidPreviousHash`); a token is one to 16 384 octets
/// (`InvariantViolation` for an empty one, `LengthExceedsMax`). Whether the
/// token verifies, under which pin, over which event and at what time is
/// the verifier's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TimestampRecord<'a> {
    parts: TimestampRecordParts<'a>,
}

impl<'a> TimestampRecord<'a> {
    /// Builds the record.
    ///
    /// # Errors
    /// `InvariantViolation` at 0 if a rule is broken.
    pub fn new(parts: &TimestampRecordParts<'a>) -> Result<Self, Error> {
        let token_ok = parts
            .token
            .is_none_or(|t| !t.is_empty() && t.len() <= MAX_TIMESTAMP_TOKEN_LEN);
        if !timestamp_target_allowed(parts.target_schema)
            || parts.target_hash.is_zero()
            || !token_ok
        {
            return Err(Error::new(Kind::InvariantViolation, 0));
        }
        Ok(Self { parts: *parts })
    }

    /// The fields.
    #[must_use]
    pub const fn parts(&self) -> &TimestampRecordParts<'a> {
        &self.parts
    }
}

impl Encode for TimestampRecord<'_> {
    fn encoded_len(&self) -> usize {
        let p = &self.parts;
        let token = p
            .token
            .map_or(1, |t| t.len().saturating_add(4).saturating_add(1));
        p.election_id
            .encoded_len()
            .saturating_add(4 + 64)
            .saturating_add(p.authority_id.encoded_len())
            .saturating_add(token)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        let p = &self.parts;
        p.election_id.encode(w)?;
        p.target_schema.encode(w)?;
        p.target_hash.encode(w)?;
        p.authority_id.encode(w)?;
        match p.token {
            None => w.write_presence(false),
            Some(token) => {
                w.write_presence(true)?;
                w.write_bytes(token, MAX_TIMESTAMP_TOKEN_LEN)
            }
        }
    }
}

impl<'a> Decode<'a> for TimestampRecord<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let election_id = ElectionId::decode(r)?;
        let schema_at = r.position();
        let target_schema = SchemaId::decode(r)?;
        if !timestamp_target_allowed(target_schema) {
            return Err(Error::new(Kind::ValueOutOfRange, schema_at));
        }
        let target_hash = read_nonzero_hash(r)?;
        let authority_id = AuthorityId::decode(r)?;
        let token = if r.read_presence()? {
            let at = r.position();
            let token = r.read_bytes(MAX_TIMESTAMP_TOKEN_LEN)?;
            if token.is_empty() {
                return Err(Error::new(Kind::InvariantViolation, at));
            }
            Some(token)
        } else {
            None
        };
        Ok(Self {
            parts: TimestampRecordParts {
                election_id,
                target_schema,
                target_hash,
                authority_id,
                token,
            },
        })
    }
}
