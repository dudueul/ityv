//! The host contract: chamber-module ports and the journal sink.
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
    /// The module refused the request (not used for batch refusals, which
    /// are `Ok(None)` from [`ModulePort::sign_batch`]).
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
}

impl fmt::Display for JournalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotDurable => "entry not durable",
            Self::Full => "journal storage full",
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
/// The host implements the link transport; the unit decodes the answers.
/// Every method is called at most once per ballot or batch for a given
/// purpose, in the order of PROTOCOL.md §7.3.
pub trait ModulePort {
    /// Requests a `ModuleIssue` object (schema 0x0103) for the next ballot
    /// and writes it into `out`, returning its length.
    ///
    /// # Errors
    /// [`PortError`] on link failure or a too-small buffer.
    fn issue(&mut self, out: &mut [u8]) -> Result<usize, PortError>;

    /// Seals `buffer` in place for chamber member `member_index`: the
    /// module XORs the plaintext with the member's pad range for the
    /// current counter and returns the pad location and the Poly1305 tag.
    /// On [`PortError::Exhausted`] the buffer must be left unchanged.
    ///
    /// # Errors
    /// [`PortError::Exhausted`] when the pad is used up; other variants on
    /// link failure.
    fn seal_member(&mut self, member_index: u8, buffer: &mut [u8]) -> Result<Sealed, PortError>;

    /// Signs the record message `body_hash ‖ module_id ‖ counter`
    /// (PROTOCOL.md §7.2.1) with the module's Ed25519 key.
    ///
    /// # Errors
    /// [`PortError`] on link failure.
    fn sign_record(&mut self, message: &[u8]) -> Result<RecordSignature, PortError>;

    /// Signs a `BatchAttestBody` object with the module's hybrid key, or
    /// returns `Ok(None)` when the module refuses because its pending
    /// counters do not match the body's range (VC-021).
    ///
    /// # Errors
    /// [`PortError`] on link failure.
    fn sign_batch(&mut self, body: &[u8]) -> Result<Option<HybridSignature>, PortError>;
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

/// The module-side rule for signing a batch (PROTOCOL.md §7.2.1 step 3):
/// the module's list of issued-but-unattested counters must be exactly the
/// contiguous range `counter_first..=counter_last`, in order, with no gap
/// and nothing outside the range.
#[must_use]
pub fn module_may_sign_batch(pending_counters: &[u64], counter_first: u64, counter_last: u64) -> bool {
    if counter_first > counter_last {
        return false;
    }
    let Some(span) = counter_last
        .checked_sub(counter_first)
        .and_then(|d| d.checked_add(1))
    else {
        return false;
    };
    if u64::try_from(pending_counters.len()).map_or(true, |n| n != span) {
        return false;
    }
    pending_counters
        .iter()
        .enumerate()
        .all(|(i, &c)| u64::try_from(i).ok().and_then(|i| counter_first.checked_add(i)) == Some(c))
}
