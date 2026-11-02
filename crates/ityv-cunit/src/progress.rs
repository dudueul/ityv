//! Per-slot progress ticks (ADR-0027; PROTOCOL.md §7.10 item 1).
//!
//! Every 10-minute uplink slot the unit signs a `BoxProgressBody`: the
//! election, the box, the slot, the sheets that entered the box (records +
//! challenged + quarantined) and the box state. Nothing else goes in: no
//! journal head, no order, no time bucket, no per-style count, no record
//! (VC-102). The host's clock supplies the slot; the unit refuses a slot
//! that is not after the last one it ticked, and a closed box gives exactly
//! one closing tick.

use ityv_encoding::{
    BoxProgressBody, BoxProgressParts, BoxProgressState, HYBRID_SIG_LEN, MAX_PROGRESS_BODY_LEN,
    PURPOSE_BOX_PROGRESS, SCHEMA_BOX_PROGRESS_BODY, SCHEMA_VERSION_1, encode_object,
};

use crate::boxstate::{ClosedBox, OpenBox, Signer, Totals};
use crate::config::ElectionConfig;
use crate::error::Error;

/// Bytes of host work buffer a tick body needs.
pub const PROGRESS_WORK_LEN: usize = MAX_PROGRESS_BODY_LEN;

/// A signed tick in the host's buffers.
#[derive(Debug)]
pub struct ProgressOutput<'w> {
    /// The `BoxProgressBody` object (schema `0x002F`).
    pub body: &'w [u8],
    /// The device's hybrid signature over `body` (purpose `box-progress`).
    pub device_sig: &'w [u8; HYBRID_SIG_LEN],
}

/// Sheets that entered the box.
fn sheets_in(totals: &Totals) -> Result<u64, Error> {
    totals
        .records
        .checked_add(totals.challenged)
        .and_then(|v| v.checked_add(totals.quarantined))
        .ok_or(Error::Overflow)
}

/// Refuses a slot that is not after `last`.
const fn after(last: Option<u64>, slot: u64) -> Result<(), Error> {
    match last {
        Some(last) if slot <= last => Err(Error::TimeRegression),
        Some(_) | None => Ok(()),
    }
}

fn write_tick<'w>(
    config: &ElectionConfig<'_>,
    slot: u64,
    sheets_in: u64,
    state: BoxProgressState,
    signer: Signer<'_>,
    work: &'w mut [u8],
    sig: &'w mut [u8; HYBRID_SIG_LEN],
) -> Result<ProgressOutput<'w>, Error> {
    let body = BoxProgressBody::new(&BoxProgressParts {
        election_id: config.election_id(),
        box_id: config.box_id(),
        slot,
        sheets_in,
        state,
    });
    let len = encode_object(SCHEMA_BOX_PROGRESS_BODY, SCHEMA_VERSION_1, &body, work)?;
    let body = work.get(..len).ok_or(Error::BufferTooSmall)?;
    signer.sign_into(PURPOSE_BOX_PROGRESS, body, sig)?;
    Ok(ProgressOutput {
        body,
        device_sig: sig,
    })
}

impl OpenBox<'_> {
    /// Signs the tick of `slot` (state `Casting`, or `Fallback` while the
    /// host reports a declared fallback). Ticks go out even while a visit
    /// is open: the count holds only decided ballots, so it says nothing
    /// about the visit.
    ///
    /// # Errors
    /// [`Error::BoxClosed`] or [`Error::JournalMismatch`] if the box does
    /// not accept work, [`Error::TimeRegression`] for a slot not after the
    /// last tick, [`Error::Overflow`], an encoding or signing error. On
    /// error the last tick slot is unchanged.
    pub fn progress_tick<'w>(
        &mut self,
        slot: u64,
        fallback: bool,
        signer: Signer<'_>,
        work: &'w mut [u8],
        sig: &'w mut [u8; HYBRID_SIG_LEN],
    ) -> Result<ProgressOutput<'w>, Error> {
        self.usable()?;
        after(self.last_tick, slot)?;
        let state = if fallback {
            BoxProgressState::Fallback
        } else {
            BoxProgressState::Casting
        };
        let out = write_tick(
            self.config,
            slot,
            sheets_in(&self.totals)?,
            state,
            signer,
            work,
            sig,
        )?;
        self.last_tick = Some(slot);
        Ok(out)
    }

    /// The slot of the last tick, if any.
    #[must_use]
    pub const fn last_tick(&self) -> Option<u64> {
        self.last_tick
    }
}

impl ClosedBox<'_> {
    /// Signs the box's closing tick (state `Closed`, the final count). A
    /// closed box gives exactly one.
    ///
    /// # Errors
    /// [`Error::BoxClosed`] for a second closing tick,
    /// [`Error::TimeRegression`] for a slot not after the last tick,
    /// [`Error::Overflow`], an encoding or signing error.
    pub fn closing_tick<'w>(
        &mut self,
        slot: u64,
        signer: Signer<'_>,
        work: &'w mut [u8],
        sig: &'w mut [u8; HYBRID_SIG_LEN],
    ) -> Result<ProgressOutput<'w>, Error> {
        if self.closing_ticked {
            return Err(Error::BoxClosed);
        }
        after(self.last_tick, slot)?;
        let totals = self.totals();
        let out = write_tick(
            self.config(),
            slot,
            sheets_in(&totals)?,
            BoxProgressState::Closed,
            signer,
            work,
            sig,
        )?;
        self.last_tick = Some(slot);
        self.closing_ticked = true;
        Ok(out)
    }
}
