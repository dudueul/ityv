//! `SharePackage` (schema `0x000B`) and `MemberShare` (schema `0x0015`),
//! version 1: the sealed per-record bundle of encrypted trustee shares and
//! one member's plaintext (PROTOCOL.md §9.3, ENCODING.md §8.10–§8.11).
//!
//! `SharePackage` field order: `election_id`, `box_id`, `commitments`,
//! `entries`. It carries no signature: the signed cast record binds it by
//! `share_package_hash`.
//!
//! `MemberShare` field order: `shares`, `has_module`, `cid`, `lab`, `tag`.
//! Its length is fixed by the election configuration; the pad consumption
//! per member is the object length plus 64 (PROTOCOL.md §9.4.3).

use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::codec::{Decode, Encode};
use crate::error::{Error, Kind};
use crate::primitives::{BoxId, ElectionId, Token192, TrusteeId};
use crate::reader::Reader;
use crate::schema::util::{Commitments, Scalars, TAG_LEN, ascending_by, read_fixed};
use crate::writer::Writer;

/// Maximum number of trustee entries in one package (eight chambers of at
/// most eight members).
pub const MAX_ENTRIES: usize = 64;

/// Maximum length of one entry's ciphertext.
pub const MAX_CIPHERTEXT_LEN: usize = 4096;

/// Maximum number of secrets shared with one member (7 modules × 8 chunks + 2).
pub const MAX_SECRETS: usize = 58;

/// Chamber code of a share entry (PROTOCOL.md §4.1, ADR-0019).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum ChamberCode {
    /// Party chamber 1.
    P1 = 1,
    /// Party chamber 2.
    P2 = 2,
    /// Party chamber 3.
    P3 = 3,
    /// Party chamber 4.
    P4 = 4,
    /// Judiciary.
    J = 5,
    /// Academia.
    A = 6,
    /// Civil society.
    C = 7,
    /// National Election Commission (no module; always KEM transport).
    N = 8,
}

impl ChamberCode {
    /// The wire code.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Returns the chamber with wire code `code`, if defined.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::P1),
            2 => Some(Self::P2),
            3 => Some(Self::P3),
            4 => Some(Self::P4),
            5 => Some(Self::J),
            6 => Some(Self::A),
            7 => Some(Self::C),
            8 => Some(Self::N),
            _ => None,
        }
    }
}

/// How one entry's ciphertext was produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Transport {
    /// One-time pad from the chamber module: `pad_id` and `pad_index` locate
    /// the consumed pad range.
    Pad {
        /// The pad identifier.
        pad_id: u32,
        /// The byte offset of the consumed range.
        pad_index: u64,
    },
    /// Hybrid KEM fallback (PROTOCOL.md §9.6); `pad_id = pad_index = 0`.
    Kem,
}

/// Returns `true` if `code` is a defined transport code (0 pad, 1 KEM).
#[must_use]
pub const fn transport_code_valid(code: u8) -> bool {
    code <= 1
}

/// Returns `true` if the pad fields are admissible for `code`: any value
/// for pad transport, both zero for KEM transport.
#[must_use]
pub const fn pad_fields_valid(code: u8, pad_id: u32, pad_index: u64) -> bool {
    code == 0 || (pad_id == 0 && pad_index == 0)
}

impl Transport {
    const fn code(self) -> u8 {
        match self {
            Self::Pad { .. } => 0,
            Self::Kem => 1,
        }
    }

    const fn pad_fields(self) -> (u32, u64) {
        match self {
            Self::Pad { pad_id, pad_index } => (pad_id, pad_index),
            Self::Kem => (0, 0),
        }
    }
}

/// One trustee member's entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ShareEntry<'a> {
    /// The member.
    pub trustee_id: TrusteeId<'a>,
    /// The member's chamber.
    pub chamber: ChamberCode,
    /// The transport used.
    pub transport: Transport,
    /// `MemberShare` ⊕ pad, or the §9.6 KEM layout.
    pub ciphertext: &'a [u8],
    /// Poly1305 or AEAD tag.
    pub tag: &'a [u8; TAG_LEN],
}

fn entry_len(e: &ShareEntry<'_>) -> usize {
    e.trustee_id
        .encoded_len()
        .saturating_add(1)
        .saturating_add(1)
        .saturating_add(4)
        .saturating_add(8)
        .saturating_add(e.ciphertext.len().saturating_add(4))
        .saturating_add(TAG_LEN)
}

/// A share package.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SharePackage<'a> {
    election_id: ElectionId<'a>,
    box_id: BoxId<'a>,
    commitments: Commitments,
    entries: [Option<ShareEntry<'a>>; MAX_ENTRIES],
    count: u8,
}

impl<'a> SharePackage<'a> {
    /// Builds a package. Returns `None` if the entries are not strictly
    /// ascending by trustee identifier, number more than 64, or any
    /// ciphertext is longer than 4096 bytes.
    #[must_use]
    pub fn new(
        election_id: ElectionId<'a>,
        box_id: BoxId<'a>,
        commitments: &Commitments,
        entries: &[ShareEntry<'a>],
    ) -> Option<Self> {
        if entries.len() > MAX_ENTRIES {
            return None;
        }
        let ascending = ascending_by(entries, |x| x.trustee_id.as_bytes());
        if !ascending
            || entries
                .iter()
                .any(|e| e.ciphertext.len() > MAX_CIPHERTEXT_LEN)
        {
            return None;
        }
        let mut slots = [None; MAX_ENTRIES];
        for (slot, entry) in slots.iter_mut().zip(entries) {
            *slot = Some(*entry);
        }
        Some(Self {
            election_id,
            box_id,
            commitments: *commitments,
            entries: slots,
            count: u8::try_from(entries.len()).ok()?,
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

    /// The commitments of the record this package belongs to.
    #[must_use]
    pub const fn commitments(&self) -> &Commitments {
        &self.commitments
    }

    /// Number of entries.
    #[must_use]
    pub fn entry_count(&self) -> usize {
        usize::from(self.count)
    }

    /// The entries in ascending trustee order.
    pub fn entries(&self) -> impl Iterator<Item = ShareEntry<'a>> + '_ {
        self.entries
            .iter()
            .take(usize::from(self.count))
            .flatten()
            .copied()
    }
}

impl Encode for SharePackage<'_> {
    fn encoded_len(&self) -> usize {
        let entries = self
            .entries()
            .fold(4usize, |acc, e| acc.saturating_add(entry_len(&e)));
        self.election_id
            .encoded_len()
            .saturating_add(self.box_id.encoded_len())
            .saturating_add(self.commitments.encoded_len())
            .saturating_add(entries)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        self.election_id.encode(w)?;
        self.box_id.encode(w)?;
        self.commitments.encode(w)?;
        w.write_count(usize::from(self.count), MAX_ENTRIES)?;
        for e in self.entries() {
            e.trustee_id.encode(w)?;
            w.write_u8(e.chamber.code())?;
            w.write_u8(e.transport.code())?;
            let (pad_id, pad_index) = e.transport.pad_fields();
            w.write_u32(pad_id)?;
            w.write_u64(pad_index)?;
            w.write_bytes(e.ciphertext, MAX_CIPHERTEXT_LEN)?;
            w.write_array(e.tag)?;
        }
        Ok(())
    }
}

impl<'a> Decode<'a> for SharePackage<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let election_id = ElectionId::decode(r)?;
        let box_id = BoxId::decode(r)?;
        let commitments = Commitments::decode(r)?;
        let entries_at = r.position();
        let count = r.read_count(MAX_ENTRIES)?;
        let mut entries = [None; MAX_ENTRIES];
        let mut previous: Option<&[u8]> = None;
        for slot in entries.iter_mut().take(count) {
            let id_at = r.position();
            let trustee_id = TrusteeId::decode(r)?;
            Reader::check_ascending(previous, trustee_id.as_bytes(), id_at)?;
            previous = Some(trustee_id.as_bytes());
            let chamber_at = r.position();
            let chamber = ChamberCode::from_code(r.read_u8()?)
                .ok_or_else(|| Error::new(Kind::ValueOutOfRange, chamber_at))?;
            let transport_at = r.position();
            let transport_code = r.read_u8()?;
            if !transport_code_valid(transport_code) {
                return Err(Error::new(Kind::ValueOutOfRange, transport_at));
            }
            let pad_id_at = r.position();
            let pad_id = r.read_u32()?;
            // Only `pad_id` is known yet (ENCODING §8.20: check each field
            // as soon as it is read); a zero index is admissible either way.
            if !pad_fields_valid(transport_code, pad_id, 0) {
                return Err(Error::new(Kind::ValueOutOfRange, pad_id_at));
            }
            let pad_index_at = r.position();
            let pad_index = r.read_u64()?;
            if !pad_fields_valid(transport_code, pad_id, pad_index) {
                return Err(Error::new(Kind::ValueOutOfRange, pad_index_at));
            }
            let transport = if transport_code == 0 {
                Transport::Pad { pad_id, pad_index }
            } else {
                Transport::Kem
            };
            let ciphertext = r.read_bytes(MAX_CIPHERTEXT_LEN)?;
            let tag = read_fixed::<TAG_LEN>(r)?;
            *slot = Some(ShareEntry {
                trustee_id,
                chamber,
                transport,
                ciphertext,
                tag,
            });
        }
        Ok(Self {
            election_id,
            box_id,
            commitments,
            entries,
            count: u8::try_from(count)
                .map_err(|_| Error::new(Kind::CountExceedsMax, entries_at))?,
        })
    }
}

/// The tag a member share points to while it is being decoded.
static NO_TAG: [u8; TAG_LEN] = [0; TAG_LEN];

/// One member's share plaintext. Neither `Clone` nor `Copy`: it holds up
/// to fifty secret shares and the module's private contributions. `Debug`
/// shows only `has_module`; the shares, `cid` and `lab` are zeroized on
/// drop (the tag is borrowed and left to its owner).
#[derive(PartialEq, Eq, Hash)]
pub struct MemberShare<'a> {
    shares: Scalars<MAX_SECRETS>,
    has_module: bool,
    cid: Token192,
    lab: Option<Token192>,
    tag: &'a [u8; TAG_LEN],
}

impl<'a> MemberShare<'a> {
    /// Builds a member share. Returns `None` if `shares` is empty, or if
    /// `has_module` is false and `cid`, `lab` or `tag` is not zero/absent.
    #[must_use]
    pub fn new(
        shares: &Scalars<MAX_SECRETS>,
        has_module: bool,
        cid: Token192,
        lab: Option<Token192>,
        tag: &'a [u8; TAG_LEN],
    ) -> Option<Self> {
        if shares.count() == 0 {
            return None;
        }
        if !has_module && (cid.0 != [0; 24] || lab.is_some() || *tag != [0; TAG_LEN]) {
            return None;
        }
        Some(Self {
            shares: shares.duplicate(),
            has_module,
            cid,
            lab,
            tag,
        })
    }

    /// The member's shares in the PROTOCOL.md §9.3 secret order.
    #[must_use]
    pub const fn shares(&self) -> &Scalars<MAX_SECRETS> {
        &self.shares
    }

    /// Whether the member's chamber has a module.
    #[must_use]
    pub const fn has_module(&self) -> bool {
        self.has_module
    }

    /// The chamber module's cast-id contribution (zero without a module).
    #[must_use]
    pub const fn cid(&self) -> &Token192 {
        &self.cid
    }

    /// The chamber module's envelope-label contribution, if any.
    #[must_use]
    pub const fn lab(&self) -> Option<&Token192> {
        self.lab.as_ref()
    }

    /// The module's one-time MAC tag for this member (zero without a module).
    #[must_use]
    pub const fn tag(&self) -> &'a [u8; TAG_LEN] {
        self.tag
    }
}

impl Zeroize for MemberShare<'_> {
    fn zeroize(&mut self) {
        self.shares.zeroize();
        self.cid.0.zeroize();
        if let Some(lab) = self.lab.as_mut() {
            lab.0.zeroize();
        }
        self.lab = None;
    }
}

impl Drop for MemberShare<'_> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for MemberShare<'_> {}

impl fmt::Debug for MemberShare<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemberShare")
            .field("has_module", &self.has_module)
            .finish_non_exhaustive()
    }
}

impl Encode for MemberShare<'_> {
    fn encoded_len(&self) -> usize {
        self.shares
            .encoded_len()
            .saturating_add(1)
            .saturating_add(24)
            .saturating_add(self.lab.encoded_len())
            .saturating_add(TAG_LEN)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        self.shares.encode(w)?;
        w.write_bool(self.has_module)?;
        self.cid.encode(w)?;
        self.lab.encode(w)?;
        w.write_array(self.tag)
    }
}

impl<'a> Decode<'a> for MemberShare<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let shares_at = r.position();
        // Built in place: an error drops (and wipes) what was read.
        let mut share = Self {
            shares: Scalars::<MAX_SECRETS>::decode(r)?,
            has_module: false,
            cid: Token192([0; 24]),
            lab: None,
            tag: &NO_TAG,
        };
        if share.shares.count() == 0 {
            return Err(Error::new(Kind::ValueOutOfRange, shares_at));
        }
        share.has_module = r.read_bool()?;
        let cid_at = r.position();
        share.cid = Token192::decode(r)?;
        if !share.has_module && share.cid.0 != [0; 24] {
            return Err(Error::new(Kind::InvariantViolation, cid_at));
        }
        let lab_at = r.position();
        share.lab = Option::<Token192>::decode(r)?;
        if !share.has_module && share.lab.is_some() {
            return Err(Error::new(Kind::InvariantViolation, lab_at));
        }
        let tag_at = r.position();
        share.tag = read_fixed::<TAG_LEN>(r)?;
        if !share.has_module && *share.tag != [0; TAG_LEN] {
            return Err(Error::new(Kind::InvariantViolation, tag_at));
        }
        Ok(share)
    }
}
