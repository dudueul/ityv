//! The host contract: chamber-module ports, the journal sink and the
//! journal source read back at resume.
//!
//! The commitment unit owns no I/O. The host implements [`ModulePort`] once
//! per configured module (over the physical link of PROTOCOL.md §7.1) and
//! [`JournalSink`] over its durable storage (PROTOCOL.md §7.8). Everything
//! the unit needs from the outside world passes through these two traits
//! and the time buckets it receives as arguments.
//!
//! The pure rule a module applies before signing a batch
//! ([`module_may_sign_batch`], VC-021) lives here so that module firmware
//! (M8) and the unit's tests use the same function.

use core::fmt;

use ityv_crypto::{HybridSignature, RecordSignature};

/// Why a module port call failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PortError {
    /// The module's pad is exhausted; the unit falls back to KEM transport
    /// (PROTOCOL.md §9.4.5).
    Exhausted,
    /// The module refused the request (a batch refusal found by the dry
    /// run is `Ok(false)` from [`ModulePort::check_batch`] instead).
    Refused,
    /// The link failed or the module answered with malformed bytes.
    Transport,
    /// The host buffer handed to the port was too small.
    BufferTooSmall,
}

impl fmt::Display for PortError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Exhausted => "pad exhausted",
            Self::Refused => "request refused",
            Self::Transport => "link failure or malformed answer",
            Self::BufferTooSmall => "buffer too small",
        })
    }
}

impl core::error::Error for PortError {}

/// Why the journal sink failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JournalError {
    /// The entry could not be made durable (the host must not report
    /// success before the write is on stable storage).
    NotDurable,
    /// The storage is full.
    Full,
    /// The storage could not be read back, or a host buffer was too small
    /// for an item.
    Unreadable,
}

impl fmt::Display for JournalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotDurable => "entry not durable",
            Self::Full => "journal storage full",
            Self::Unreadable => "journal storage unreadable",
        })
    }
}

impl core::error::Error for JournalError {}

/// What a module returns after sealing one member's plaintext with its pad
/// (PROTOCOL.md §9.4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Sealed {
    /// The pad identifier of the member's copy.
    pub pad_id: u32,
    /// The byte offset of the consumed range, `counter × b`.
    pub pad_index: u64,
    /// The Poly1305 tag over the plaintext under the pad's MAC key.
    pub tag: [u8; 16],
}

/// One chamber module as seen by the unit.
///
/// The host implements the link transport; the unit decodes and checks the
/// answers. Per ballot the unit calls [`Self::issue`] once, then
/// [`Self::seal_member`] once per member of the module's chamber, then
/// [`Self::sign_record`] once (PROTOCOL.md §7.3). Per batch it calls
/// [`Self::check_batch`] once and, if the module consented,
/// [`Self::sign_batch`] once (PROTOCOL.md §7.2.1).
pub trait ModulePort {
    /// Requests a `ModuleIssue` object (schema 0x0103) for the next ballot,
    /// whose style has `chunk_count` chunks (the module returns that many
    /// randomness contributions), and writes it into `out`, returning its
    /// length.
    ///
    /// # Errors
    /// [`PortError`] on link failure or a too-small buffer.
    fn issue(&mut self, chunk_count: u8, out: &mut [u8]) -> Result<usize, PortError>;

    /// Seals `buffer` in place for chamber member `member_index` with the
    /// pad region of the current counter `n` (PROTOCOL.md §9.4.3): the
    /// module XORs the plaintext with the pad bytes at
    /// `n·b + PAD_PLAINTEXT_OFFSET`, tags the plaintext with the Poly1305
    /// key at `n·b + PAD_MAC_KEY_OFFSET`, and returns the pad location and
    /// the tag. `b` is the box's per-record consumption
    /// ([`crate::config::ElectionConfig::pad_consumption`]). On
    /// [`PortError::Exhausted`] the buffer must be left unchanged.
    ///
    /// # Errors
    /// [`PortError::Exhausted`] when the pad is used up; other variants on
    /// link failure.
    fn seal_member(&mut self, member_index: u8, buffer: &mut [u8]) -> Result<Sealed, PortError>;

    /// Signs the record message `body_hash ‖ module_id ‖ counter`
    /// (PROTOCOL.md §7.2.1) with the module's Ed25519 key. The unit verifies
    /// the signature with the module's genesis key before using it.
    ///
    /// # Errors
    /// [`PortError`] on link failure.
    fn sign_record(&mut self, message: &[u8]) -> Result<RecordSignature, PortError>;

    /// Dry run of the batch rule ([`module_may_sign_batch`]): `true` if the
    /// module's issued-but-unattested counters are exactly
    /// `counter_first..=counter_last`. No signature and no state change.
    ///
    /// # Errors
    /// [`PortError`] on link failure.
    fn check_batch(&mut self, counter_first: u64, counter_last: u64) -> Result<bool, PortError>;

    /// Signs a final `BatchAttestBody` object with the module's hybrid key
    /// and marks the counters of its range attested (the module clears them
    /// from its pending list). The unit asks only modules whose
    /// [`Self::check_batch`] returned `true`, once per batch, and verifies
    /// the signature with the module's genesis key.
    ///
    /// # Errors
    /// [`PortError::Refused`] if the module's rule rejects the body after
    /// all; other variants on link failure.
    fn sign_batch(&mut self, body: &[u8]) -> Result<HybridSignature, PortError>;
}

/// The sealed journal's durable storage.
pub trait JournalSink {
    /// Appends `entry` (a `JournalEntry` object) and, for a record entry,
    /// the `SharePackage` object bytes, returning only after both are on
    /// stable storage (fsync). The unit creates the `Durable` state only
    /// after this returns `Ok` (VC-054).
    ///
    /// # Errors
    /// [`JournalError`] if the write could not be made durable.
    fn append(&mut self, entry: &[u8], share_package: Option<&[u8]>) -> Result<(), JournalError>;
}

/// One item of the journal stream read back at resume.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct JournalItem {
    /// Length of the `JournalEntry` object written into the entry buffer.
    pub entry_len: usize,
    /// Length of the `SharePackage` object written into the package buffer,
    /// present exactly when the stream stores one after the entry.
    pub package_len: Option<usize>,
}

/// The sealed journal read back from storage, from the first entry on
/// (PROTOCOL.md §7.8). The host removes the stream framing
/// (`u32_be length ‖ object`); the unit checks everything else.
pub trait JournalSource {
    /// Reads the next entry into `entry` and, if the stream stores a share
    /// package after it, the package into `package`. Returns `None` after
    /// the last entry.
    ///
    /// # Errors
    /// [`JournalError`] if storage cannot be read or a buffer is too small.
    fn next_item(
        &mut self,
        entry: &mut [u8],
        package: &mut [u8],
    ) -> Result<Option<JournalItem>, JournalError>;
}

/// The module-side rule for signing a batch (PROTOCOL.md §7.2.1 step 3):
/// the module's list of issued-but-unattested counters must be exactly the
/// contiguous range `counter_first..=counter_last`, in order, with no gap
/// and nothing outside the range.
#[must_use]
pub fn module_may_sign_batch(
    pending_counters: &[u64],
    counter_first: u64,
    counter_last: u64,
) -> bool {
    if counter_first > counter_last {
        return false;
    }
    let Some(span) = counter_last
        .checked_sub(counter_first)
        .and_then(|d| d.checked_add(1))
    else {
        return false;
    };
    if u64::try_from(pending_counters.len()).ok() != Some(span) {
        return false;
    }
    pending_counters.iter().enumerate().all(|(i, &c)| {
        u64::try_from(i)
            .ok()
            .and_then(|i| counter_first.checked_add(i))
            == Some(c)
    })
}
