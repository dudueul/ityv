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

use crate::codec::{Decode, Encode};
use crate::error::{Error, Kind};
use crate::primitives::{BoxId, ElectionId, Token192, TrusteeId};
use crate::reader::Reader;
use crate::schema::util::{Commitments, Scalars, TAG_LEN, ascending_by, read_fixed};
use crate::writer::Writer;

/// Maximum number of trustee entries in one package.
pub const MAX_ENTRIES: usize = 64;

/// Maximum length of one entry's ciphertext.
pub const MAX_CIPHERTEXT_LEN: usize = 4096;

/// Maximum number of secrets shared with one member (6 modules × 8 chunks + 2).
pub const MAX_SECRETS: usize = 50;

/// Chamber code of a share entry (PROTOCOL.md §4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum ChamberCode {
    /// Chamber X.
    X = 1,
    /// Chamber Y.
    Y = 2,
    /// Chamber J.
    J = 3,
    /// Chamber A.
    A = 4,
    /// Chamber C.
    C = 5,
    /// Chamber N (no module; always KEM transport).
    N = 6,
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
            1 => Some(Self::X),
            2 => Some(Self::Y),
            3 => Some(Self::J),
            4 => Some(Self::A),
            5 => Some(Self::C),
            6 => Some(Self::N),
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
            let pad_id_at = r.position();
            let pad_id = r.read_u32()?;
            let pad_index_at = r.position();
            let pad_index = r.read_u64()?;
            let transport = match transport_code {
                0 => Transport::Pad { pad_id, pad_index },
                1 => {
                    if pad_id != 0 {
                        return Err(Error::new(Kind::ValueOutOfRange, pad_id_at));
                    }
                    if pad_index != 0 {
                        return Err(Error::new(Kind::ValueOutOfRange, pad_index_at));
                    }
                    Transport::Kem
                }
                _ => return Err(Error::new(Kind::ValueOutOfRange, transport_at)),
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

/// One member's share plaintext.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
            shares: *shares,
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
        let shares = Scalars::<MAX_SECRETS>::decode(r)?;
        if shares.count() == 0 {
            return Err(Error::new(Kind::InvariantViolation, shares_at));
        }
        let has_module = r.read_bool()?;
        let cid_at = r.position();
        let cid = Token192::decode(r)?;
        let lab_at = r.position();
        let lab = Option::<Token192>::decode(r)?;
        let tag_at = r.position();
        let tag = read_fixed::<TAG_LEN>(r)?;
        if !has_module {
            if cid.0 != [0; 24] {
                return Err(Error::new(Kind::InvariantViolation, cid_at));
            }
            if lab.is_some() {
                return Err(Error::new(Kind::InvariantViolation, lab_at));
            }
            if *tag != [0; TAG_LEN] {
                return Err(Error::new(Kind::InvariantViolation, tag_at));
            }
        }
        Ok(Self {
            shares,
            has_module,
            cid,
            lab,
            tag,
        })
    }
}
