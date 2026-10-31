//! `CastRecordBody` (schema `0x0005`) and `CastRecord` (schema `0x0016`),
//! version 1: the public record of one cast ballot (PROTOCOL.md §7.6,
//! ENCODING.md §8.6–§8.7).
//!
//! `CastRecordBody` field order: `election_id`, `box_id`, `ballot_style_id`,
//! `proof_system_id`, `commitments`, `proof`, `module_counters`,
//! `share_package_hash`, `transport_flags`.
//!
//! `CastRecord` field order: `body` (the complete encoded body object),
//! `device_sig_ed25519`, `module_sigs`.
//!
//! Decoding proves well-formedness only. The proof's scalars, the
//! commitments' group validity and every signature are checked by the
//! cryptographic and verifier crates; this module checks the proof header
//! against the commitment count so that a record whose proof could never
//! verify is rejected at the encoding layer.

use crate::codec::{Decode, Encode};
use crate::error::{Error, Kind};
use crate::primitives::{BallotStyleId, BoxId, ElectionId, Hash512, ModuleId};
use crate::reader::Reader;
use crate::schema::util::{
    Commitments, ED25519_SIG_LEN, MAX_MODULES, ModuleCounters, ascending_by, check_embedded,
    decode_embedded, read_fixed,
};
use crate::schema::{SCHEMA_CAST_RECORD_BODY, SCHEMA_VERSION_1};
use crate::writer::Writer;

/// The only proof system identifier defined in version 1 (`or-rep:v1`).
pub const PROOF_SYSTEM_OR_REP_V1: u16 = 1;

/// Maximum length of the `proof` field (PROTOCOL.md §7.5, `m+2 = 64`, `k = 8`).
pub const MAX_PROOF_LEN: usize = 20_483;

/// Maximum length of the embedded `CastRecordBody` object bytes.
pub const MAX_CAST_RECORD_BODY_LEN: usize = 22_528;

/// Largest option count the proof system supports (`m + 2`).
const MAX_OPTION_COUNT: u16 = 64;

/// Bit 0 of `transport_flags`: at least one member used the KEM fallback.
pub const TRANSPORT_KEM_FALLBACK: u8 = 0b01;

/// Bit 1 of `transport_flags`: a neutral module served delegated chambers.
pub const TRANSPORT_NEUTRAL_MODULE: u8 = 0b10;

/// The bits of `transport_flags` that may be set (bits 0 and 1).
pub const TRANSPORT_FLAGS_MASK: u8 = 0b11;

/// The proof header parsed from the first three bytes of the `proof` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProofHeader {
    /// `m + 2`.
    pub option_count: u16,
    /// `k`.
    pub chunk_count: u8,
}

impl ProofHeader {
    /// Parses the header and checks the PROTOCOL.md §7.5 length formula
    /// `3 + option_count·(chunk_count+2)·32` and `chunk_count = ⌈option_count/9⌉`.
    #[must_use]
    pub fn parse(proof: &[u8]) -> Option<Self> {
        let (head, _) = proof.split_first_chunk::<3>()?;
        Self::parse_with_len(*head, proof.len())
    }

    /// The pure form of [`Self::parse`]: the three header bytes and the
    /// total proof length.
    #[must_use]
    pub fn parse_with_len(head: [u8; 3], proof_len: usize) -> Option<Self> {
        let [hi, lo, chunk_count] = head;
        let option_count = u16::from_be_bytes([hi, lo]);
        if option_count == 0 || option_count > MAX_OPTION_COUNT {
            return None;
        }
        let expected_chunks = option_count.div_ceil(9);
        if u16::from(chunk_count) != expected_chunks {
            return None;
        }
        let per_option = usize::from(chunk_count).checked_add(2)?.checked_mul(32)?;
        let expected_len = usize::from(option_count)
            .checked_mul(per_option)?
            .checked_add(3)?;
        if proof_len != expected_len {
            return None;
        }
        Some(Self {
            option_count,
            chunk_count,
        })
    }
}

/// Unvalidated inputs for [`CastRecordBody::new`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CastRecordParts<'a> {
    /// The election.
    pub election_id: ElectionId<'a>,
    /// The ballot box.
    pub box_id: BoxId<'a>,
    /// The ballot style.
    pub ballot_style_id: BallotStyleId<'a>,
    /// The proof system identifier (must be 1).
    pub proof_system_id: u16,
    /// The commitment vector.
    pub commitments: Commitments,
    /// The proof bytes (PROTOCOL.md §7.5 encoding).
    pub proof: &'a [u8],
    /// The module counters (at least one).
    pub module_counters: ModuleCounters<'a>,
    /// Hash of the share package.
    pub share_package_hash: Hash512,
    /// Transport flags (bits 0 and 1 only).
    pub transport_flags: u8,
}

/// The body of a cast record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CastRecordBody<'a> {
    election_id: ElectionId<'a>,
    box_id: BoxId<'a>,
    ballot_style_id: BallotStyleId<'a>,
    proof_system_id: u16,
    commitments: Commitments,
    proof: &'a [u8],
    module_counters: ModuleCounters<'a>,
    share_package_hash: Hash512,
    transport_flags: u8,
}

impl<'a> CastRecordBody<'a> {
    /// Builds a body. Returns `None` if `proof_system_id` is not 1, the
    /// proof is longer than [`MAX_PROOF_LEN`], the proof header is malformed
    /// or names a chunk count other than the number of commitments,
    /// `module_counters` is empty, or `transport_flags` has bits above bit 1
    /// set.
    #[must_use]
    pub fn new(parts: &CastRecordParts<'a>) -> Option<Self> {
        if parts.proof_system_id != PROOF_SYSTEM_OR_REP_V1 {
            return None;
        }
        if parts.proof.len() > MAX_PROOF_LEN {
            return None;
        }
        let header = ProofHeader::parse(parts.proof)?;
        if header.chunk_count != parts.commitments.chunk_count() {
            return None;
        }
        if parts.module_counters.is_empty() {
            return None;
        }
        if parts.transport_flags & !TRANSPORT_FLAGS_MASK != 0 {
            return None;
        }
        Some(Self {
            election_id: parts.election_id,
            box_id: parts.box_id,
            ballot_style_id: parts.ballot_style_id,
            proof_system_id: parts.proof_system_id,
            commitments: parts.commitments,
            proof: parts.proof,
            module_counters: parts.module_counters,
            share_package_hash: parts.share_package_hash,
            transport_flags: parts.transport_flags,
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

    /// The proof system identifier (always 1 in version 1).
    #[must_use]
    pub const fn proof_system_id(&self) -> u16 {
        self.proof_system_id
    }

    /// The commitment vector.
    #[must_use]
    pub const fn commitments(&self) -> &Commitments {
        &self.commitments
    }

    /// The proof bytes (PROTOCOL.md §7.5 encoding).
    #[must_use]
    pub const fn proof(&self) -> &'a [u8] {
        self.proof
    }

    /// The parsed proof header.
    #[must_use]
    pub fn proof_header(&self) -> ProofHeader {
        // The constructor checked the header; the fallback cannot be reached.
        ProofHeader::parse(self.proof).unwrap_or(ProofHeader {
            option_count: 0,
            chunk_count: 0,
        })
    }

    /// The module counters.
    #[must_use]
    pub const fn module_counters(&self) -> &ModuleCounters<'a> {
        &self.module_counters
    }

    /// Hash of the share package bound to this record.
    #[must_use]
    pub const fn share_package_hash(&self) -> &Hash512 {
        &self.share_package_hash
    }

    /// The transport flags (bits 0 and 1 only).
    #[must_use]
    pub const fn transport_flags(&self) -> u8 {
        self.transport_flags
    }
}

impl Encode for CastRecordBody<'_> {
    fn encoded_len(&self) -> usize {
        self.election_id
            .encoded_len()
            .saturating_add(self.box_id.encoded_len())
            .saturating_add(self.ballot_style_id.encoded_len())
            .saturating_add(2)
            .saturating_add(self.commitments.encoded_len())
            .saturating_add(self.proof.len().saturating_add(4))
            .saturating_add(self.module_counters.encoded_len())
            .saturating_add(self.share_package_hash.encoded_len())
            .saturating_add(1)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        self.election_id.encode(w)?;
        self.box_id.encode(w)?;
        self.ballot_style_id.encode(w)?;
        w.write_u16(self.proof_system_id)?;
        self.commitments.encode(w)?;
        w.write_bytes(self.proof, MAX_PROOF_LEN)?;
        self.module_counters.encode(w)?;
        self.share_package_hash.encode(w)?;
        w.write_u8(self.transport_flags)
    }
}

impl<'a> Decode<'a> for CastRecordBody<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let election_id = ElectionId::decode(r)?;
        let box_id = BoxId::decode(r)?;
        let ballot_style_id = BallotStyleId::decode(r)?;
        let psid_at = r.position();
        let proof_system_id = r.read_u16()?;
        if proof_system_id != PROOF_SYSTEM_OR_REP_V1 {
            return Err(Error::new(Kind::ValueOutOfRange, psid_at));
        }
        let commitments = Commitments::decode(r)?;
        let proof_at = r.position();
        let proof = r.read_bytes(MAX_PROOF_LEN)?;
        let header = ProofHeader::parse(proof)
            .ok_or_else(|| Error::new(Kind::InvariantViolation, proof_at))?;
        if header.chunk_count != commitments.chunk_count() {
            return Err(Error::new(Kind::InvariantViolation, proof_at));
        }
        let counters_at = r.position();
        let module_counters = ModuleCounters::decode(r)?;
        if module_counters.is_empty() {
            return Err(Error::new(Kind::InvariantViolation, counters_at));
        }
        let share_package_hash = Hash512::decode(r)?;
        let flags_at = r.position();
        let transport_flags = r.read_u8()?;
        if transport_flags & !TRANSPORT_FLAGS_MASK != 0 {
            return Err(Error::new(Kind::ValueOutOfRange, flags_at));
        }
        Ok(Self {
            election_id,
            box_id,
            ballot_style_id,
            proof_system_id,
            commitments,
            proof,
            module_counters,
            share_package_hash,
            transport_flags,
        })
    }
}

/// One module's Ed25519 record signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ModuleRecordSig<'a> {
    /// The module.
    pub module_id: ModuleId<'a>,
    /// Signature over `body_hash ‖ module_id ‖ counter` (PROTOCOL.md §7.2.1).
    pub ed25519: &'a [u8; ED25519_SIG_LEN],
}

/// A cast record: the body object bytes with the device and module record
/// signatures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CastRecord<'a> {
    body_bytes: &'a [u8],
    body: CastRecordBody<'a>,
    device_sig_ed25519: &'a [u8; ED25519_SIG_LEN],
    module_sigs: [Option<ModuleRecordSig<'a>>; MAX_MODULES],
    sig_count: u8,
}

impl<'a> CastRecord<'a> {
    /// Builds a record from a complete `CastRecordBody` object and the
    /// signatures, which must be ascending by module identifier and name
    /// exactly the modules of the body's `module_counters`.
    ///
    /// # Errors
    /// The body's decoding error if `body_bytes` is not a canonical body
    /// object, `LengthExceedsMax` at 0 if it is too long, and
    /// `InvariantViolation` at 0 if the signature set is malformed.
    pub fn new(
        body_bytes: &'a [u8],
        device_sig_ed25519: &'a [u8; ED25519_SIG_LEN],
        module_sigs: &[ModuleRecordSig<'a>],
    ) -> Result<Self, Error> {
        let body: CastRecordBody<'a> = check_embedded(
            body_bytes,
            MAX_CAST_RECORD_BODY_LEN,
            SCHEMA_CAST_RECORD_BODY,
        )?;
        if module_sigs.len() > MAX_MODULES {
            return Err(Error::new(Kind::InvariantViolation, 0));
        }
        let ascending = ascending_by(module_sigs, |x| x.module_id.as_bytes());
        if !ascending
            || !body
                .module_counters()
                .same_ids(module_sigs.iter().map(|s| s.module_id))
        {
            return Err(Error::new(Kind::InvariantViolation, 0));
        }
        let mut sigs = [None; MAX_MODULES];
        for (slot, sig) in sigs.iter_mut().zip(module_sigs) {
            *slot = Some(*sig);
        }
        Ok(Self {
            body_bytes,
            body,
            device_sig_ed25519,
            module_sigs: sigs,
            sig_count: u8::try_from(module_sigs.len())
                .map_err(|_| Error::new(Kind::InvariantViolation, 0))?,
        })
    }

    /// The body object bytes; their object hash is the tracking code.
    #[must_use]
    pub const fn body_bytes(&self) -> &'a [u8] {
        self.body_bytes
    }

    /// The decoded body.
    #[must_use]
    pub const fn body(&self) -> &CastRecordBody<'a> {
        &self.body
    }

    /// The device's Ed25519 record signature over the body bytes.
    #[must_use]
    pub const fn device_sig_ed25519(&self) -> &'a [u8; ED25519_SIG_LEN] {
        self.device_sig_ed25519
    }

    /// The module record signatures in ascending identifier order.
    pub fn module_sigs(&self) -> impl Iterator<Item = ModuleRecordSig<'a>> + '_ {
        self.module_sigs
            .iter()
            .take(usize::from(self.sig_count))
            .flatten()
            .copied()
    }
}

impl Encode for CastRecord<'_> {
    fn encoded_len(&self) -> usize {
        let sigs = self.module_sigs().fold(4usize, |acc, s| {
            acc.saturating_add(s.module_id.encoded_len())
                .saturating_add(ED25519_SIG_LEN)
        });
        self.body_bytes
            .len()
            .saturating_add(4)
            .saturating_add(ED25519_SIG_LEN)
            .saturating_add(sigs)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        w.write_bytes(self.body_bytes, MAX_CAST_RECORD_BODY_LEN)?;
        w.write_array(self.device_sig_ed25519)?;
        w.write_count(usize::from(self.sig_count), MAX_MODULES)?;
        for sig in self.module_sigs() {
            sig.module_id.encode(w)?;
            w.write_array(sig.ed25519)?;
        }
        Ok(())
    }
}

impl<'a> Decode<'a> for CastRecord<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let (body_bytes, body): (&'a [u8], CastRecordBody<'a>) =
            decode_embedded(r, MAX_CAST_RECORD_BODY_LEN, SCHEMA_CAST_RECORD_BODY)?;
        let device_sig_ed25519 = read_fixed::<ED25519_SIG_LEN>(r)?;
        let sigs_at = r.position();
        let count = r.read_count(MAX_MODULES)?;
        let mut module_sigs = [None; MAX_MODULES];
        let mut previous: Option<&[u8]> = None;
        for slot in module_sigs.iter_mut().take(count) {
            let id_at = r.position();
            let module_id = ModuleId::decode(r)?;
            Reader::check_ascending(previous, module_id.as_bytes(), id_at)?;
            previous = Some(module_id.as_bytes());
            let ed25519 = read_fixed::<ED25519_SIG_LEN>(r)?;
            *slot = Some(ModuleRecordSig { module_id, ed25519 });
        }
        let ids = module_sigs
            .iter()
            .take(count)
            .flatten()
            .map(|s| s.module_id);
        if !body.module_counters().same_ids(ids) {
            return Err(Error::new(Kind::InvariantViolation, sigs_at));
        }
        Ok(Self {
            body_bytes,
            body,
            device_sig_ed25519,
            module_sigs,
            sig_count: u8::try_from(count)
                .map_err(|_| Error::new(Kind::CountExceedsMax, sigs_at))?,
        })
    }
}

// Keep the schema-version constant referenced from this module so the
// embedded decoders cannot silently drift to another version.
const _: () = assert!(SCHEMA_VERSION_1 == 1);
