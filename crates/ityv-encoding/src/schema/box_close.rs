//! `BoxCloseBody` (schema `0x0007`) and `BoxClose` (schema `0x001A`),
//! version 1: the close of a ballot box (PROTOCOL.md §10.2, ENCODING.md
//! §8.16–§8.17).
//!
//! `BoxCloseBody` field order: `election_id`, `box_id`, `paper_count`,
//! `record_count`, `attested_count`, `no_record_count`, `challenge_count`,
//! `quarantine_count`, `visit_count`, `envelope_count`, `sticker_count`,
//! `spoil_envelope_count`, `record_set_root`, `journal_head`,
//! `seal_digest`, `module_counters`, `open_batches`, `time_bucket`. `BoxClose` field
//! order: `body`, `device_sig`, `attestations`.
//!
//! The close invariants of PROTOCOL.md §10.2 (VC-038) are not encoding
//! rules: a close that violates them is still recorded and goes to
//! `HOLD_REVIEW`; the commitment-unit and verifier crates judge them.

use crate::codec::{Decode, Encode};
use crate::error::{Error, Kind};
use crate::primitives::{BoxId, ElectionId, Hash512, OrgId, SignerId, TimeBucket};
use crate::reader::Reader;
use crate::schema::SCHEMA_BOX_CLOSE_BODY;
use crate::schema::util::{
    HYBRID_SIG_LEN, ModuleCounters, ascending_by, check_embedded, decode_embedded, read_fixed,
};
use crate::writer::Writer;

/// Maximum length of the embedded `BoxCloseBody` object bytes.
pub const MAX_BOX_CLOSE_BODY_LEN: usize = 1024;

/// Maximum number of human attestations.
pub const MAX_ATTESTATIONS: usize = 8;

/// Minimum number of clerk attestations.
pub const MIN_CLERKS: usize = 2;

/// Minimum number of observer attestations, from distinct organizations.
pub const MIN_OBSERVERS: usize = 2;

/// The counts a box close reports (`paper_count`, `record_count`,
/// `attested_count`, `no_record_count`, `challenge_count`,
/// `quarantine_count`, `visit_count`, `envelope_count`, `sticker_count` in
/// ENCODING.md §8.16).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CloseCounts {
    /// Physical ballots counted independently by two clerks.
    pub paper: u64,
    /// Cast records produced.
    pub records: u64,
    /// Records covered by a batch attestation.
    pub attested: u64,
    /// Ballots received through the emergency slot without a record.
    pub without_record: u64,
    /// Ballots spoiled by a pre-cast challenge.
    pub challenged: u64,
    /// Ballots quarantined.
    pub quarantined: u64,
    /// Visits that cast at least one ballot (ADR-0021).
    pub visits: u64,
    /// Out-of-district boxes: physical return envelopes (0 in a polling
    /// station box).
    pub envelopes: u64,
    /// Out-of-district boxes: label stickers on the envelopes, emergency
    /// marks excluded (0 in a polling station box).
    pub stickers: u64,
    /// Envelopes in the spoil and quarantine bag, counted by people
    /// (`challenge_count + quarantine_count` when nothing is missing).
    pub spoil_envelopes: u64,
}

/// Unvalidated inputs for [`BoxCloseBody::new`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BoxCloseParts<'a> {
    /// The election.
    pub election_id: ElectionId<'a>,
    /// The ballot box.
    pub box_id: BoxId<'a>,
    /// The reported counts.
    pub counts: CloseCounts,
    /// Sorted-set root of the box's record hashes.
    pub record_set_root: Hash512,
    /// The sealed journal head at close.
    pub journal_head: Hash512,
    /// Hash of the applied seal numbers.
    pub seal_digest: Hash512,
    /// Each module's final counter.
    pub module_counters: ModuleCounters<'a>,
    /// Number of batches still open at close.
    pub open_batches: u8,
    /// The time bucket of the close.
    pub time_bucket: TimeBucket,
}

/// The body of a box close.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BoxCloseBody<'a> {
    election_id: ElectionId<'a>,
    box_id: BoxId<'a>,
    counts: CloseCounts,
    record_set_root: Hash512,
    journal_head: Hash512,
    seal_digest: Hash512,
    module_counters: ModuleCounters<'a>,
    open_batches: u8,
    time_bucket: TimeBucket,
}

impl<'a> BoxCloseBody<'a> {
    /// Builds a body. All invariants are carried by the field types.
    #[must_use]
    pub const fn new(parts: &BoxCloseParts<'a>) -> Self {
        Self {
            election_id: parts.election_id,
            box_id: parts.box_id,
            counts: parts.counts,
            record_set_root: parts.record_set_root,
            journal_head: parts.journal_head,
            seal_digest: parts.seal_digest,
            module_counters: parts.module_counters,
            open_batches: parts.open_batches,
            time_bucket: parts.time_bucket,
        }
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

    /// The reported counts.
    #[must_use]
    pub const fn counts(&self) -> &CloseCounts {
        &self.counts
    }

    /// Sorted-set root of the box's record hashes.
    #[must_use]
    pub const fn record_set_root(&self) -> &Hash512 {
        &self.record_set_root
    }

    /// The sealed journal head at close.
    #[must_use]
    pub const fn journal_head(&self) -> &Hash512 {
        &self.journal_head
    }

    /// Hash of the applied seal numbers.
    #[must_use]
    pub const fn seal_digest(&self) -> &Hash512 {
        &self.seal_digest
    }

    /// Each module's final counter.
    #[must_use]
    pub const fn module_counters(&self) -> &ModuleCounters<'a> {
        &self.module_counters
    }

    /// Number of batches still open at close.
    #[must_use]
    pub const fn open_batches(&self) -> u8 {
        self.open_batches
    }

    /// The time bucket of the close.
    #[must_use]
    pub const fn time_bucket(&self) -> TimeBucket {
        self.time_bucket
    }
}

impl Encode for BoxCloseBody<'_> {
    fn encoded_len(&self) -> usize {
        self.election_id
            .encoded_len()
            .saturating_add(self.box_id.encoded_len())
            .saturating_add(80)
            .saturating_add(192)
            .saturating_add(self.module_counters.encoded_len())
            .saturating_add(1)
            .saturating_add(8)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        self.election_id.encode(w)?;
        self.box_id.encode(w)?;
        w.write_u64(self.counts.paper)?;
        w.write_u64(self.counts.records)?;
        w.write_u64(self.counts.attested)?;
        w.write_u64(self.counts.without_record)?;
        w.write_u64(self.counts.challenged)?;
        w.write_u64(self.counts.quarantined)?;
        w.write_u64(self.counts.visits)?;
        w.write_u64(self.counts.envelopes)?;
        w.write_u64(self.counts.stickers)?;
        w.write_u64(self.counts.spoil_envelopes)?;
        self.record_set_root.encode(w)?;
        self.journal_head.encode(w)?;
        self.seal_digest.encode(w)?;
        self.module_counters.encode(w)?;
        w.write_u8(self.open_batches)?;
        self.time_bucket.encode(w)
    }
}

impl<'a> Decode<'a> for BoxCloseBody<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let election_id = ElectionId::decode(r)?;
        let box_id = BoxId::decode(r)?;
        let counts = CloseCounts {
            paper: r.read_u64()?,
            records: r.read_u64()?,
            attested: r.read_u64()?,
            without_record: r.read_u64()?,
            challenged: r.read_u64()?,
            quarantined: r.read_u64()?,
            visits: r.read_u64()?,
            envelopes: r.read_u64()?,
            stickers: r.read_u64()?,
            spoil_envelopes: r.read_u64()?,
        };
        let record_set_root = Hash512::decode(r)?;
        let journal_head = Hash512::decode(r)?;
        let seal_digest = Hash512::decode(r)?;
        let module_counters = ModuleCounters::decode(r)?;
        let open_batches = r.read_u8()?;
        let time_bucket = TimeBucket::decode(r)?;
        Ok(Self {
            election_id,
            box_id,
            counts,
            record_set_root,
            journal_head,
            seal_digest,
            module_counters,
            open_batches,
            time_bucket,
        })
    }
}

/// The role of a human signer of a box close.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum SignerRole {
    /// A polling clerk.
    Clerk = 1,
    /// An observer.
    Observer = 2,
}

impl SignerRole {
    /// The wire code.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Returns the role with wire code `code`, if defined.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Clerk),
            2 => Some(Self::Observer),
            _ => None,
        }
    }
}

/// One human attestation of a box close (purpose `box-close`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Attestation<'a> {
    /// The signer.
    pub signer_id: SignerId<'a>,
    /// The signer's role.
    pub role: SignerRole,
    /// The signer's organization.
    pub org_id: OrgId<'a>,
    /// The signature.
    pub sig: &'a [u8; HYBRID_SIG_LEN],
}

/// Returns `true` if the attestations include at least [`MIN_CLERKS`]
/// clerks and observers from at least [`MIN_OBSERVERS`] distinct
/// organizations.
fn roles_satisfied<'a, I>(attestations: I) -> bool
where
    I: IntoIterator<Item = Attestation<'a>>,
{
    let mut clerks = 0usize;
    let mut orgs: [Option<&[u8]>; MAX_ATTESTATIONS] = [None; MAX_ATTESTATIONS];
    let mut distinct = 0usize;
    for a in attestations {
        match a.role {
            SignerRole::Clerk => clerks = clerks.saturating_add(1),
            SignerRole::Observer => {
                let org = a.org_id.as_bytes();
                let seen = orgs.iter().take(distinct).flatten().any(|o| *o == org);
                if !seen {
                    if let Some(slot) = orgs.get_mut(distinct) {
                        *slot = Some(org);
                    }
                    distinct = distinct.saturating_add(1);
                }
            }
        }
    }
    clerks >= MIN_CLERKS && distinct >= MIN_OBSERVERS
}

/// A box-close event: the body object bytes, the device's hybrid signature
/// if the device was alive, and the human attestations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoxClose<'a> {
    body_bytes: &'a [u8],
    body: BoxCloseBody<'a>,
    device_sig: Option<&'a [u8; HYBRID_SIG_LEN]>,
    attestations: [Option<Attestation<'a>>; MAX_ATTESTATIONS],
    count: u8,
}

impl<'a> BoxClose<'a> {
    /// Builds the event. The attestations must be ascending by signer
    /// identifier, at most eight, with two clerks and two observers from
    /// distinct organizations.
    ///
    /// # Errors
    /// The body's decoding error, `LengthExceedsMax` at 0 if the body is too
    /// long, or `InvariantViolation` at 0 if the attestation set is malformed.
    pub fn new(
        body_bytes: &'a [u8],
        device_sig: Option<&'a [u8; HYBRID_SIG_LEN]>,
        attestations: &[Attestation<'a>],
    ) -> Result<Self, Error> {
        let body = check_embedded(body_bytes, MAX_BOX_CLOSE_BODY_LEN, SCHEMA_BOX_CLOSE_BODY)?;
        let ascending = ascending_by(attestations, |x| x.signer_id.as_bytes());
        if attestations.len() > MAX_ATTESTATIONS
            || !ascending
            || !roles_satisfied(attestations.iter().copied())
        {
            return Err(Error::new(Kind::InvariantViolation, 0));
        }
        let mut slots = [None; MAX_ATTESTATIONS];
        for (slot, a) in slots.iter_mut().zip(attestations) {
            *slot = Some(*a);
        }
        Ok(Self {
            body_bytes,
            body,
            device_sig,
            attestations: slots,
            count: u8::try_from(attestations.len())
                .map_err(|_| Error::new(Kind::InvariantViolation, 0))?,
        })
    }

    /// The body object bytes (the signed message).
    #[must_use]
    pub const fn body_bytes(&self) -> &'a [u8] {
        self.body_bytes
    }

    /// The decoded body.
    #[must_use]
    pub const fn body(&self) -> &BoxCloseBody<'a> {
        &self.body
    }

    /// The device signature, absent for a `BoxCloseManual`.
    #[must_use]
    pub const fn device_sig(&self) -> Option<&'a [u8; HYBRID_SIG_LEN]> {
        self.device_sig
    }

    /// The attestations in ascending signer order.
    pub fn attestations(&self) -> impl Iterator<Item = Attestation<'a>> + '_ {
        self.attestations
            .iter()
            .take(usize::from(self.count))
            .flatten()
            .copied()
    }
}

impl Encode for BoxClose<'_> {
    fn encoded_len(&self) -> usize {
        let attestations = self.attestations().fold(4usize, |acc, a| {
            acc.saturating_add(a.signer_id.encoded_len())
                .saturating_add(1)
                .saturating_add(a.org_id.encoded_len())
                .saturating_add(HYBRID_SIG_LEN)
        });
        let device = match self.device_sig {
            None => 1,
            Some(_) => HYBRID_SIG_LEN.saturating_add(1),
        };
        self.body_bytes
            .len()
            .saturating_add(4)
            .saturating_add(device)
            .saturating_add(attestations)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        w.write_bytes(self.body_bytes, MAX_BOX_CLOSE_BODY_LEN)?;
        match self.device_sig {
            None => w.write_presence(false)?,
            Some(sig) => {
                w.write_presence(true)?;
                w.write_array(sig)?;
            }
        }
        w.write_count(usize::from(self.count), MAX_ATTESTATIONS)?;
        for a in self.attestations() {
            a.signer_id.encode(w)?;
            w.write_u8(a.role.code())?;
            a.org_id.encode(w)?;
            w.write_array(a.sig)?;
        }
        Ok(())
    }
}

impl<'a> Decode<'a> for BoxClose<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let (body_bytes, body) = decode_embedded(r, MAX_BOX_CLOSE_BODY_LEN, SCHEMA_BOX_CLOSE_BODY)?;
        let device_sig = if r.read_presence()? {
            Some(read_fixed::<HYBRID_SIG_LEN>(r)?)
        } else {
            None
        };
        let att_at = r.position();
        let count = r.read_count(MAX_ATTESTATIONS)?;
        let mut attestations = [None; MAX_ATTESTATIONS];
        let mut previous: Option<&[u8]> = None;
        for slot in attestations.iter_mut().take(count) {
            let id_at = r.position();
            let signer_id = SignerId::decode(r)?;
            Reader::check_ascending(previous, signer_id.as_bytes(), id_at)?;
            previous = Some(signer_id.as_bytes());
            let role_at = r.position();
            let role = SignerRole::from_code(r.read_u8()?)
                .ok_or_else(|| Error::new(Kind::ValueOutOfRange, role_at))?;
            let org_id = OrgId::decode(r)?;
            let sig = read_fixed::<HYBRID_SIG_LEN>(r)?;
            *slot = Some(Attestation {
                signer_id,
                role,
                org_id,
                sig,
            });
        }
        if !roles_satisfied(attestations.iter().take(count).flatten().copied()) {
            return Err(Error::new(Kind::InvariantViolation, att_at));
        }
        Ok(Self {
            body_bytes,
            body,
            device_sig,
            attestations,
            count: u8::try_from(count).map_err(|_| Error::new(Kind::CountExceedsMax, att_at))?,
        })
    }
}
