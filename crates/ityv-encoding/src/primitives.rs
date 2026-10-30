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

/// A coarse time bucket. The width of a bucket is fixed by the protocol
/// specification (fifteen minutes for check-in events); this crate treats
/// the value as opaque.
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

    /// Returns the length in bytes, always `>= 1`.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Always `false`: identifiers cannot be empty. Provided for API symmetry.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
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
                if ident.len() > Self::MAX_LEN {
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
