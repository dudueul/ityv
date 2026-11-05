//! Newtypes for every value that appears in an ityv object.
//!
//! Raw integers and byte slices never cross the public API (CONSTITUTION.md
//! §1.5). Constructors parse: a value that violates its invariant cannot be
//! constructed (§1.6), so decoders map a `None` to an [`Error`](crate::Error)
//! with the offending offset.

/// Standard maximum length, in bytes, of an identifier field.
pub const IDENT_MAX_STANDARD: usize = 64;

/// A SHA3-512 digest, 64 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Hash512(pub [u8; 64]);

impl Hash512 {
    /// The all-zero digest, used as the "no predecessor" marker.
    pub const ZERO: Self = Self([0u8; 64]);

    /// Returns the digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    /// Returns `true` if every byte is zero.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|b| *b == 0)
    }
}

/// A Ristretto255 scalar, 32 bytes. Only the length is checked here; the
/// cryptographic crate checks canonical form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Scalar32(pub [u8; 32]);

/// A compressed Ristretto255 point, 32 bytes. Only the length is checked here;
/// the cryptographic crate checks that it decompresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Point32(pub [u8; 32]);

/// A 192-bit random token (cast id, envelope label), 24 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Token192(pub [u8; 24]);

/// Identifier of an object schema (ENCODING.md §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SchemaId(u32);

impl SchemaId {
    /// Wraps a raw schema identifier.
    #[must_use]
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    /// Returns the raw identifier.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// A one-based sequence number. Zero is not representable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Seq(u64);

impl Seq {
    /// The first sequence number.
    pub const FIRST: Self = Self(1);

    /// Returns `Some` if `raw >= 1`.
    #[must_use]
    pub const fn new(raw: u64) -> Option<Self> {
        if raw == 0 { None } else { Some(Self(raw)) }
    }

    /// Returns the raw value, always `>= 1`.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Returns `true` if this is the first sequence number.
    #[must_use]
    pub const fn is_first(self) -> bool {
        self.0 == 1
    }
}

/// Number of leaves in a Merkle tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TreeSize(u64);

impl TreeSize {
    /// Wraps a raw leaf count.
    #[must_use]
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// Returns the raw leaf count.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// A coarse time bucket: the fifteen-minute index from 00:00 UTC of the
/// genesis's `election_epoch_day` (days since the Unix epoch), as the
/// protocol specification fixes it (PROTOCOL.md §2, ENCODING.md §8.3);
/// this crate treats the value as opaque.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TimeBucket(u64);

impl TimeBucket {
    /// Wraps a raw bucket index.
    #[must_use]
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// Returns the raw bucket index.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// A calendar day expressed as days since the Unix epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Day(u64);

impl Day {
    /// Wraps a raw day number.
    #[must_use]
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// Returns the raw day number.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// A length-prefixed byte string bounded by a schema maximum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Bytes<'a> {
    bytes: &'a [u8],
}

impl<'a> Bytes<'a> {
    /// Returns `Some` if `bytes.len() <= max`.
    #[must_use]
    pub const fn new(bytes: &'a [u8], max: usize) -> Option<Self> {
        if bytes.len() > max {
            None
        } else {
            Some(Self { bytes })
        }
    }

    /// Returns the underlying bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the length in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns `true` if the byte string is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// An identifier: one to `max` bytes drawn from `[A-Za-z0-9._:-]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ident<'a> {
    bytes: &'a [u8],
}

impl<'a> Ident<'a> {
    /// Returns `true` if `byte` is in the identifier alphabet.
    #[must_use]
    pub const fn is_valid_byte(byte: u8) -> bool {
        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-')
    }

    /// Returns `Some` if `1 <= bytes.len() <= max` and every byte is in the
    /// identifier alphabet.
    #[must_use]
    pub const fn new(bytes: &'a [u8], max: usize) -> Option<Self> {
        if bytes.is_empty() || bytes.len() > max {
            return None;
        }
        let mut cursor = bytes;
        while let Some((first, rest)) = cursor.split_first() {
            if !Self::is_valid_byte(*first) {
                return None;
            }
            cursor = rest;
        }
        Some(Self { bytes })
    }

    /// Returns the identifier bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the length in bytes, always `>= 1`. Named `byte_len` rather
    /// than `len` because an identifier can never be empty, so there is no
    /// meaningful `is_empty` to pair it with.
    #[must_use]
    pub const fn byte_len(&self) -> usize {
        self.bytes.len()
    }
}

/// Identifier of an election; the first field of every object body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ElectionId<'a>(Ident<'a>);

/// Identifier of an evidence ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LedgerId<'a>(Ident<'a>);

/// Identifier of a witness key set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeysetId<'a>(Ident<'a>);

/// Identifier of a ballot box (PROTOCOL.md §7.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BoxId<'a>(Ident<'a>);

/// Identifier of a ballot style (PROTOCOL.md §7.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BallotStyleId<'a>(Ident<'a>);

/// Identifier of a polling station (PROTOCOL.md §7.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StationId<'a>(Ident<'a>);

/// Identifier of a chamber module (PROTOCOL.md §7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ModuleId<'a>(Ident<'a>);

/// Identifier of a trustee member (PROTOCOL.md §9.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TrusteeId<'a>(Ident<'a>);

/// Identifier of an observer (PROTOCOL.md §7.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ObserverId<'a>(Ident<'a>);

/// Identifier of an organization (observer or clerk affiliation).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OrgId<'a>(Ident<'a>);

/// Identifier of a human signer of a box-close event (PROTOCOL.md §10.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SignerId<'a>(Ident<'a>);

/// Identifier of a custody route in the genesis (PROTOCOL.md §4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RouteId<'a>(Ident<'a>);

/// Identifier of a check-in unit (카운터·가명 유닛, PROTOCOL.md §6.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UnitId<'a>(Ident<'a>);

/// Identifier of a reporting unit: the unit in which paper results are
/// published by law (PROTOCOL.md §4.1 `reporting_units[]`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReportingUnitId<'a>(Ident<'a>);

/// Identifier of an external authority the genesis pins: a timestamp
/// authority (PROTOCOL.md §5.5) or a voter-roll source or custodian
/// (§6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AuthorityId<'a>(Ident<'a>);

/// Identifier of a station gateway (PROTOCOL.md §5.8; ADR-0041).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GatewayId<'a>(Ident<'a>);

macro_rules! ident_newtype {
    ($name:ident) => {
        impl<'a> $name<'a> {
            /// Maximum length in bytes.
            pub const MAX_LEN: usize = IDENT_MAX_STANDARD;

            /// Returns `Some` if `bytes` is a valid identifier of at most
            /// [`Self::MAX_LEN`] bytes.
            #[must_use]
            pub const fn new(bytes: &'a [u8]) -> Option<Self> {
                match Ident::new(bytes, Self::MAX_LEN) {
                    Some(ident) => Some(Self(ident)),
                    None => None,
                }
            }

            /// Wraps an already validated identifier, rejecting it if it is
            /// longer than [`Self::MAX_LEN`].
            #[must_use]
            pub const fn from_ident(ident: Ident<'a>) -> Option<Self> {
                if ident.byte_len() > Self::MAX_LEN {
                    None
                } else {
                    Some(Self(ident))
                }
            }

            /// Returns the underlying identifier.
            #[must_use]
            pub const fn ident(&self) -> Ident<'a> {
                self.0
            }

            /// Returns the identifier bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &'a [u8] {
                self.0.as_bytes()
            }
        }
    };
}

ident_newtype!(ElectionId);
ident_newtype!(LedgerId);
ident_newtype!(KeysetId);
ident_newtype!(BoxId);
ident_newtype!(BallotStyleId);
ident_newtype!(StationId);
ident_newtype!(ModuleId);
ident_newtype!(TrusteeId);
ident_newtype!(ObserverId);
ident_newtype!(OrgId);
ident_newtype!(SignerId);
ident_newtype!(RouteId);
ident_newtype!(UnitId);
ident_newtype!(ReportingUnitId);
ident_newtype!(AuthorityId);
ident_newtype!(GatewayId);

/// Whether `byte` is a separator an organisation name may be written with
/// or without.
const fn org_separator(byte: u8) -> bool {
    matches!(byte, b'.' | b'_' | b':' | b'-')
}

/// Whether `a` and `b` name one organisation, as every rule that counts
/// organisations or keeps them apart compares them (witness and observer
/// diversity, custody hand-offs, the roll custodians, the timestamp
/// operators; ADR-0039 2, ADR-0040).
///
/// An organisation identifier is ASCII letters, digits and `.`, `_`, `:`,
/// `-`, and two spellings of one name are one organisation: `MOIS-GPKI`,
/// `mois-gpki`, `MOIS_GPKI` and `MOISGPKI` compare equal (letters lowered,
/// separators dropped). This guards against a typo or a second spelling
/// counting one body twice; it is not an identity check. Names that only
/// look alike (`M0IS` and `MOIS`) are different names, and which body a
/// name stands for is the genesis reviewers' to check.
#[must_use]
pub fn same_org(a: OrgId<'_>, b: OrgId<'_>) -> bool {
    let (left, right) = (a.as_bytes(), b.as_bytes());
    let (mut at_left, mut at_right) = (0usize, 0usize);
    // One loop, one step per byte of either name (at most the two lengths
    // and one more): skip a separator on either side, else compare one
    // letter of each. A single loop keeps the model checker's unwinding
    // of the rules that call this small.
    loop {
        match (left.get(at_left), right.get(at_right)) {
            (Some(l), _) if org_separator(*l) => at_left = at_left.saturating_add(1),
            (_, Some(r)) if org_separator(*r) => at_right = at_right.saturating_add(1),
            (Some(l), Some(r)) => {
                if !l.eq_ignore_ascii_case(r) {
                    return false;
                }
                at_left = at_left.saturating_add(1);
                at_right = at_right.saturating_add(1);
            }
            (None, None) => return true,
            (Some(_), None) | (None, Some(_)) => return false,
        }
    }
}
