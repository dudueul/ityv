//! Publication deadlines (PROTOCOL.md §5.5, ADR-0016 §7).
//!
//! Time in the TCB is a fifteen-minute bucket index, never a wall clock. A
//! checkpoint must be received and receipted by at least [`REQUIRED_ANCHORS`]
//! designated public verifiers within [`ANCHOR_WINDOW`] buckets (one hour),
//! and the whole board must be published within [`BOARD_WINDOW`] buckets
//! (24 hours) of the close of voting. The caller supplies every time; this
//! module only does the bounded arithmetic and the comparison.

use ityv_encoding::TimeBucket;

use crate::error::Error;

/// Buckets allowed between a checkpoint and its third anchor receipt.
pub const ANCHOR_WINDOW: u64 = 4;
/// Buckets allowed between the close of voting and board publication.
pub const BOARD_WINDOW: u64 = 96;
/// Designated public verifiers whose receipts anchor a checkpoint.
pub const REQUIRED_ANCHORS: usize = 3;

/// A missed publication deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Breach {
    /// Fewer anchor receipts than required by the deadline.
    AnchorsShort {
        /// Receipts received by the deadline.
        have: usize,
        /// Receipts required.
        need: usize,
    },
    /// The board was not published by the deadline.
    BoardUnpublished,
    /// The board was published after the deadline.
    BoardLate {
        /// When it was published.
        published: TimeBucket,
        /// When it was due.
        deadline: TimeBucket,
    },
}

impl core::fmt::Display for Breach {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::AnchorsShort { have, need } => write!(f, "anchors short: {have} of {need}"),
            Self::BoardUnpublished => f.write_str("board not published by the deadline"),
            Self::BoardLate {
                published,
                deadline,
            } => write!(
                f,
                "board published in bucket {} after deadline {}",
                published.get(),
                deadline.get()
            ),
        }
    }
}

/// Whether a deadline is met or still open.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Status {
    /// The requirement is met.
    Satisfied,
    /// Not yet met, and the deadline has not passed.
    Pending,
}

fn add(bucket: TimeBucket, window: u64) -> Result<TimeBucket, Error> {
    bucket
        .get()
        .checked_add(window)
        .map(TimeBucket::new)
        .ok_or(Error::Overflow)
}

/// The last bucket in which a checkpoint proposed in `checkpoint` may still
/// receive its anchors.
///
/// # Errors
/// [`Error::Overflow`].
pub fn anchor_deadline(checkpoint: TimeBucket) -> Result<TimeBucket, Error> {
    add(checkpoint, ANCHOR_WINDOW)
}

/// The last bucket in which the board of an election closed in `close` may
/// still be published.
///
/// # Errors
/// [`Error::Overflow`].
pub fn board_deadline(close: TimeBucket) -> Result<TimeBucket, Error> {
    add(close, BOARD_WINDOW)
}

/// Checks the anchor rule for a checkpoint proposed in `checkpoint`, given
/// the buckets of the receipts received so far and the current bucket.
/// Receipts after the deadline do not count.
///
/// # Errors
/// [`Error::Breach`] with [`Breach::AnchorsShort`] once the deadline has
/// passed with fewer than `required` timely receipts, [`Error::Overflow`].
pub fn check_anchor(
    checkpoint: TimeBucket,
    receipts: &[TimeBucket],
    required: usize,
    now: TimeBucket,
) -> Result<Status, Error> {
    let deadline = anchor_deadline(checkpoint)?;
    let have = receipts.iter().filter(|r| **r <= deadline).count();
    if have >= required {
        Ok(Status::Satisfied)
    } else if now > deadline {
        Err(Error::Breach(Breach::AnchorsShort {
            have,
            need: required,
        }))
    } else {
        Ok(Status::Pending)
    }
}

/// Checks the board publication rule for an election closed in `close`.
///
/// # Errors
/// [`Error::Breach`] with [`Breach::BoardLate`] if published after the
/// deadline, [`Breach::BoardUnpublished`] if unpublished past the deadline,
/// [`Error::Overflow`].
pub fn check_board(
    close: TimeBucket,
    published: Option<TimeBucket>,
    now: TimeBucket,
) -> Result<Status, Error> {
    let deadline = board_deadline(close)?;
    match published {
        Some(published) if published <= deadline => Ok(Status::Satisfied),
        Some(published) => Err(Error::Breach(Breach::BoardLate {
            published,
            deadline,
        })),
        None if now > deadline => Err(Error::Breach(Breach::BoardUnpublished)),
        None => Ok(Status::Pending),
    }
}
