//! Publication deadlines (PROTOCOL.md §5.5, ADR-0016 §7, ADR-0039 7).
//!
//! Time in the TCB is a fifteen-minute bucket index, never a wall clock. A
//! checkpoint must be anchored by timestamp tokens within [`ANCHOR_WINDOW`]
//! buckets after its own (one hour; the verifier decides that from the
//! tokens on the ledger, `ityv-verify`'s `CheckpointChain::anchor_deadline`),
//! and the whole board must be published within [`BOARD_WINDOW`] buckets
//! (24 hours) of the close of voting. The caller supplies every time; this
//! module only does the bounded arithmetic and the board comparison.
//!
//! An earlier rule counted the receipts of three designated public
//! verifiers, supplied by the caller. Since ADR-0039 the verifier counts
//! signed timestamp tokens instead, and that rule and its count are gone:
//! a caller's receipt list could only have made the status read as more
//! anchored than the ledger shows.

use ityv_encoding::TimeBucket;

use crate::error::Error;

/// Buckets after a checkpoint's own within which timestamp tokens anchor
/// it (VC-115): a token anchors it when its latest instant is in bucket
/// `checkpoint + ANCHOR_WINDOW` at the latest.
pub const ANCHOR_WINDOW: u64 = 4;
/// Buckets allowed between the close of voting and board publication.
pub const BOARD_WINDOW: u64 = 96;

/// A missed publication deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Breach {
    /// The last valid checkpoint's anchor window passed without timestamp
    /// tokens of both authority kinds (a government-run and a
    /// non-government authority of two operators; VC-115, ADR-0039 7).
    AnchorsShort {
        /// The authority kinds present among the tokens within the
        /// window, 0 to 2.
        have: usize,
        /// The kinds required: 2.
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
