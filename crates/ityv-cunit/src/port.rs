//! The host contract: chamber-module ports, the journal sink and the
//! journal source read back at resume, and the staging store for a visit's
//! public objects.
//!
//! The commitment unit owns no I/O. The host implements [`ModulePort`] once
//! per configured module (over the physical link of PROTOCOL.md §7.1),
//! [`JournalSink`] over its durable storage (PROTOCOL.md §7.8) and
//! [`StagingPort`] over whatever memory holds a visit's records and share
//! packages until the decision (PROTOCOL.md §7.3). Everything the unit
//! needs from the outside world passes through these traits and the time
//! buckets it receives as arguments.
//!
//! The pure rules a module applies before signing a batch
//! ([`module_may_sign_batch`], VC-021) and a record
//! ([`module_may_sign_record`], VC-068) live here so that module firmware
//! (M8) and the unit's tests use the same functions.

use core::fmt;

use ityv_crypto::{HybridSignature, RecordSignature};
use ityv_encoding::Hash512;

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
    /// (PROTOCOL.md §7.2.1) with the module's Ed25519 key. The module signs
    /// at most one body hash per counter ([`module_may_sign_record`]) and
    /// keeps it until the counter is attested, so the unit cannot change a
    /// record after the visit's decision (VC-068). The unit verifies the
    /// signature with the module's genesis key before using it.
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

    /// The module's statement for a field attestation of the device
    /// `device_id` answering `challenge` (the field encoding of the
    /// attestation's `challenge`, ENCODING.md §8.28): the module's own boot
    /// measurements and its hybrid signature by its attestation key
    /// (purpose `module-attestation`) over the field encodings of
    /// `device_id ‖ challenge ‖ module_id ‖ build ‖ image_hash ‖
    /// boot_count` (PROTOCOL.md §7.9 step 4). No counter or pad changes.
    /// The unit verifies the signature with the module's genesis
    /// attestation key.
    ///
    /// # Errors
    /// [`PortError`] on link failure or refusal.
    fn attest(
        &mut self,
        device_id: &[u8],
        challenge: &[u8],
    ) -> Result<ModuleAttestation, PortError>;
}

/// A chamber module's answer to [`ModulePort::attest`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleAttestation {
    /// The module image's build number.
    pub build: u64,
    /// The module image's hash, measured at the module's boot.
    pub image_hash: Hash512,
    /// The module's boot counter.
    pub boot_count: u32,
    /// The module's hybrid signature over its statement.
    pub sig: HybridSignature,
}

/// The sealed journal's durable storage.
pub trait JournalSink {
    /// Appends `entry` (a `JournalEntry` object) and, for a record entry,
    /// the `SharePackage` object bytes, returning only after they and every
    /// entry appended before them are on stable storage (fsync). The unit
    /// lets a paper be imprinted or move only after this returns `Ok`
    /// (VC-054).
    ///
    /// # Errors
    /// [`JournalError`] if the write could not be made durable.
    fn append(&mut self, entry: &[u8], share_package: Option<&[u8]>) -> Result<(), JournalError>;

    /// Appends like [`Self::append`] without waiting for stable storage; the
    /// next [`Self::append`] makes it durable together with its own entry.
    /// A visit's position entries use it, so the decision costs one fsync,
    /// at its decision entry (PROTOCOL.md §7.3 step 7); each bound entry
    /// before it is durable on its own. The default waits anyway, which is
    /// correct and only slower.
    ///
    /// # Errors
    /// [`JournalError`] if the write failed.
    fn append_deferred(
        &mut self,
        entry: &[u8],
        share_package: Option<&[u8]>,
    ) -> Result<(), JournalError> {
        self.append(entry, share_package)
    }
}

/// Which public object of a visit position the host stages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Staged {
    /// The signed `CastRecord` object.
    Record,
    /// The `SharePackage` object.
    Package,
}

/// The host's store for a visit's finished public objects (PROTOCOL.md
/// §7.3 step 5): once a position's record is bound, the unit hands its
/// `CastRecord` and `SharePackage` here and keeps only their hashes, so
/// that a visit of eight ballots does not hold eight packages in the
/// unit's memory. Whatever the host gives back is checked against those
/// hashes before it is journaled or published; a swapped object is
/// refused ([`crate::Error::StagedMismatch`]).
pub trait StagingPort {
    /// Stores `bytes` as the `kind` object of position `position`
    /// (0-based) of the open visit, replacing any earlier one.
    ///
    /// # Errors
    /// [`PortError`] if the store failed.
    fn stage(&mut self, position: u8, kind: Staged, bytes: &[u8]) -> Result<(), PortError>;

    /// Copies the staged `kind` object of `position` into `out` and
    /// returns its length.
    ///
    /// # Errors
    /// [`PortError::BufferTooSmall`] if `out` is too small; other variants
    /// if the object is missing or unreadable.
    fn fetch(&mut self, position: u8, kind: Staged, out: &mut [u8]) -> Result<usize, PortError>;
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

/// The module-side rule for signing a record (PROTOCOL.md §7.2.1, VC-068):
/// a module signs the record message of a counter only if it has not
/// signed that counter yet (`signed` is `None`) or signed the same body
/// hash before (signing again is harmless). A second body for the same
/// counter is refused, so a record cannot change after the decision. The
/// module keeps the hash it signed until the counter is attested.
#[must_use]
pub fn module_may_sign_record(signed: Option<&[u8; 64]>, body_hash: &[u8; 64]) -> bool {
    signed.is_none_or(|previous| previous == body_hash)
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

#[cfg(test)]
mod tests {
    use super::{JournalError, JournalSink};

    /// A sink that implements only [`JournalSink::append`].
    struct Durable {
        appended: Option<(usize, bool)>,
        fail: bool,
    }

    impl JournalSink for Durable {
        fn append(
            &mut self,
            entry: &[u8],
            share_package: Option<&[u8]>,
        ) -> Result<(), JournalError> {
            if self.fail {
                return Err(JournalError::Full);
            }
            self.appended = Some((entry.len(), share_package.is_some()));
            Ok(())
        }
    }

    /// Without its own deferred write a sink appends durably, and its
    /// errors pass through.
    #[test]
    fn a_deferred_append_defaults_to_a_durable_one() {
        let mut sink = Durable {
            appended: None,
            fail: false,
        };
        sink.append_deferred(b"entry", Some(b"package")).unwrap();
        assert_eq!(sink.appended, Some((5, true)));
        sink.fail = true;
        assert_eq!(
            sink.append_deferred(b"entry", None),
            Err(JournalError::Full)
        );
    }
}
