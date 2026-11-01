//! Resume after a power loss (PROTOCOL.md §7.3 재개, §7.8; ADR-0017 개정
//! 11 as amended by ADR-0021; VC-069).
//!
//! [`OpenBox::resume`] reads the sealed journal from its first entry,
//! checks every link and rebuilds the box: the high-water marks, the open
//! batch, the batch index, the totals, the incidents, and the state of
//! the last visit. The attested waiting area then decides, with that
//! visit, what happens to the papers left ([`rules::resume_plan`]); the
//! entries the decision needs are appended and the plan is returned to
//! the host, which moves the papers accordingly. Cast ids and envelope
//! labels are never stored durably (CONSTITUTION §4.4), so nothing is
//! imprinted, printed or opened after a resume.

use ityv_crypto::object_hash;
use ityv_encoding::{Hash512, SCHEMA_VERSION_1, TimeBucket, decode_object};

use crate::boxstate::{EntryFields, NO_COUNTERS, OpenBox, Phase};
use crate::config::{ElectionConfig, MAX_MODULES, Profile};
use crate::error::Error;
use crate::link::{
    JournalEntry, JournalKind, MAX_JOURNAL_ENTRY_LEN, SCHEMA_JOURNAL_ENTRY, visit_digest,
};
use crate::port::{JournalSink, JournalSource};
use crate::rules::{
    self, Choice, CounterCheck, ResumePlan, Settlement, VISIT_POSITIONS, VisitStage, VisitState,
    WaitingArea,
};

/// What the host knows when it resumes a box after a power loss.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResumeInputs {
    /// The bucket of the box's `BoxOpened` event.
    pub opened: TimeBucket,
    /// What two clerks and two observers found in the waiting area.
    pub waiting_area: WaitingArea,
    /// The current bucket, used for any entry the resume appends.
    pub time_bucket: TimeBucket,
}

/// One position of the journal's last visit while it is replayed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TrailPosition {
    choice: Choice,
    record: Hash512,
    counters: [u64; MAX_MODULES],
    include: [bool; MAX_MODULES],
    settled: Settlement,
}

impl TrailPosition {
    const EMPTY: Self = Self {
        choice: Choice::Cast,
        record: Hash512::ZERO,
        counters: [0; MAX_MODULES],
        include: [false; MAX_MODULES],
        settled: Settlement::Open,
    };

    /// `true` if `counters`/`include` are this position's.
    fn same_counters(&self, counters: &[u64; MAX_MODULES], include: [bool; MAX_MODULES]) -> bool {
        self.counters == *counters && self.include == include
    }
}

/// The journal's last visit while it is replayed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Trail {
    stage: VisitStage,
    count: u8,
    positions: [TrailPosition; VISIT_POSITIONS],
    digest: Hash512,
    live: u8,
    label_printed: bool,
}

impl Trail {
    const NONE: Self = Self {
        stage: VisitStage::None,
        count: 0,
        positions: [TrailPosition::EMPTY; VISIT_POSITIONS],
        digest: Hash512::ZERO,
        live: 0,
        label_printed: false,
    };

    fn bound(&self) -> impl Iterator<Item = &TrailPosition> {
        self.positions.iter().take(usize::from(self.count))
    }

    /// `true` while the visit still owes something: a cast position not
    /// settled, or (out of district) the sticker entry for its cast ballots.
    fn owes(&self, absentee: bool) -> bool {
        let unsettled = self
            .bound()
            .any(|p| matches!(p.choice, Choice::Cast) && matches!(p.settled, Settlement::Open));
        unsettled || (absentee && self.live > 0 && !self.label_printed)
    }

    /// The position whose record is `record`.
    fn find(&mut self, record: &Hash512) -> Result<(usize, &mut TrailPosition), Error> {
        self.positions
            .iter_mut()
            .take(usize::from(self.count))
            .enumerate()
            .find(|(_, p)| p.record == *record)
            .ok_or(Error::JournalCorrupt)
    }

    /// The summary [`rules::resume_plan`] reads.
    fn state(&self) -> VisitState {
        let mut state = VisitState::NONE;
        state.stage = self.stage;
        state.positions = self.count;
        state.label_printed = self.label_printed;
        for ((choice, settled), position) in state
            .choices
            .iter_mut()
            .zip(state.settled.iter_mut())
            .zip(self.bound())
        {
            *choice = position.choice;
            *settled = position.settled;
        }
        state
    }
}

impl<'c> OpenBox<'c> {
    /// Rebuilds a box from its journal after a power loss (PROTOCOL.md
    /// §7.3 재개, §7.8). Every entry is decoded and checked: the head chain
    /// from zero, non-decreasing time buckets, a share package exactly
    /// after record entries and matching their package hash, consumed
    /// counters that each follow the module's mark, and the visit order of
    /// VC-069: position entries (kinds 1, 2), then the decision entry
    /// (kind 7, whose digest must match them), then per cast position an
    /// imprint (kind 6, in position order) or a quarantine naming it (kind
    /// 3, with its counters), then out of district the sticker entry (kind
    /// 8, repeating the digest). Visit entries carry no counters. Batch
    /// closes must match the replayed batch, nothing may follow a box
    /// close. A decided visit that still owed something when another visit
    /// or a batch began lost its papers at an earlier resume and counts as
    /// one paper incident. Positions of an undecided visit may only be
    /// followed by more positions, the decision, or quarantines naming
    /// them.
    ///
    /// Then the attested waiting area decides, with the last visit, what
    /// happens to the papers left ([`rules::resume_plan`]): the imprint and
    /// quarantine entries it needs are appended (with
    /// `inputs.time_bucket`), and the plan tells the host where each paper
    /// goes. No visit is open afterwards and a scan count is due at once.
    /// `package` must hold the largest share package of the box.
    ///
    /// # Errors
    /// [`Error::JournalCorrupt`] for any broken or inconsistent entry,
    /// [`Error::BoxClosed`] if the journal ends with a box close, the
    /// source's and the sink's errors, [`Error::TimeRegression`].
    pub fn resume(
        config: &'c ElectionConfig<'c>,
        source: &mut dyn JournalSource,
        sink: &mut dyn JournalSink,
        inputs: &ResumeInputs,
        package: &mut [u8],
    ) -> Result<(Self, ResumePlan), Error> {
        let mut open_box = Self::open(config, inputs.opened);
        let mut entry = [0u8; MAX_JOURNAL_ENTRY_LEN];
        let mut trail = Trail::NONE;
        while let Some(item) = source.next_item(&mut entry, package)? {
            let entry_bytes = entry.get(..item.entry_len).ok_or(Error::JournalCorrupt)?;
            let package_bytes = match item.package_len {
                Some(len) => Some(package.get(..len).ok_or(Error::JournalCorrupt)?),
                None => None,
            };
            open_box
                .replay(entry_bytes, package_bytes, &mut trail)
                .map_err(|_| Error::JournalCorrupt)?;
        }
        open_box.usable()?;
        let absentee = matches!(config.profile(), Profile::Absentee);
        let plan = rules::resume_plan(&trail.state(), inputs.waiting_area, absentee);
        open_box.apply_plan(&mut trail, &plan, sink, inputs.time_bucket)?;
        open_box.scan.pending = true;
        Ok((open_box, plan))
    }

    /// Appends what the resume plan needs: the front paper's imprint entry,
    /// the quarantines naming records (position order), the quarantines
    /// without record; and counts the incident.
    fn apply_plan(
        &mut self,
        trail: &mut Trail,
        plan: &ResumePlan,
        sink: &mut dyn JournalSink,
        time_bucket: TimeBucket,
    ) -> Result<(), Error> {
        if let Some(index) = plan.imprint {
            let position = trail
                .positions
                .get(usize::from(index))
                .copied()
                .ok_or(Error::Capacity)?;
            self.append_naming(sink, JournalKind::Imprinted, &position, time_bucket)?;
        }
        let positions = trail.positions;
        for (position, quarantine) in positions
            .iter()
            .take(usize::from(trail.count))
            .zip(plan.quarantine)
        {
            if !quarantine {
                continue;
            }
            self.append_naming(sink, JournalKind::Quarantine, position, time_bucket)?;
            match trail.stage {
                VisitStage::Decided => self.withdraw_cast(trail, &position.record)?,
                VisitStage::Undecided | VisitStage::None => self.count_quarantine()?,
            }
        }
        for _ in 0..plan.unjournaled {
            self.journal(
                sink,
                &EntryFields {
                    kind: JournalKind::Quarantine,
                    record_hash: Hash512::ZERO,
                    share_package_hash: Hash512::ZERO,
                    counters: &NO_COUNTERS,
                    include: [false; MAX_MODULES],
                    time_bucket,
                },
                None,
            )?;
            self.count_quarantine()?;
        }
        if plan.incident {
            self.count_paper_incident()?;
        }
        Ok(())
    }

    /// Appends an imprint or quarantine entry naming `position`'s record
    /// and repeating its counters.
    fn append_naming(
        &mut self,
        sink: &mut dyn JournalSink,
        kind: JournalKind,
        position: &TrailPosition,
        time_bucket: TimeBucket,
    ) -> Result<(), Error> {
        self.journal(
            sink,
            &EntryFields {
                kind,
                record_hash: position.record,
                share_package_hash: Hash512::ZERO,
                counters: &position.counters,
                include: position.include,
                time_bucket,
            },
            None,
        )
    }

    /// Counts one paper incident.
    pub(crate) fn count_paper_incident(&mut self) -> Result<(), Error> {
        self.paper_incidents = self.paper_incidents.checked_add(1).ok_or(Error::Overflow)?;
        Ok(())
    }

    /// Withdraws a cast record of the decided trail: out of the batch and
    /// the records, into the quarantines; the visit stops counting once
    /// nothing of it is cast.
    fn withdraw_cast(&mut self, trail: &mut Trail, record: &Hash512) -> Result<(), Error> {
        self.withdraw_record(record)?;
        trail.live = trail.live.checked_sub(1).ok_or(Error::JournalCorrupt)?;
        if trail.live == 0 {
            self.totals.visits = self.totals.visits.checked_sub(1).ok_or(Error::Overflow)?;
        }
        Ok(())
    }

    /// Ends the trail before an entry that does not belong to it. A decided
    /// visit that still owed something counts one paper incident; an
    /// undecided one cannot be left (its positions must be quarantined).
    fn close_trail(&mut self, trail: &mut Trail) -> Result<(), Error> {
        let absentee = matches!(self.config.profile(), Profile::Absentee);
        match trail.stage {
            VisitStage::None => {}
            VisitStage::Undecided => return Err(Error::JournalCorrupt),
            VisitStage::Decided => {
                if trail.owes(absentee) {
                    self.count_paper_incident()?;
                }
            }
        }
        *trail = Trail::NONE;
        Ok(())
    }

    /// The counters an entry lists, as arrays in configuration order.
    fn entry_counters(
        &self,
        entry: &JournalEntry<'_>,
    ) -> Result<([u64; MAX_MODULES], [bool; MAX_MODULES]), Error> {
        let mut counters = [0u64; MAX_MODULES];
        let mut include = [false; MAX_MODULES];
        let mut found = 0usize;
        for ((module, counter), included) in self
            .config
            .modules()
            .iter()
            .zip(counters.iter_mut())
            .zip(include.iter_mut())
        {
            if let Some(value) = entry.module_counters().get(module.module_id()) {
                *counter = value;
                *included = true;
                found = found.checked_add(1).ok_or(Error::Overflow)?;
            }
        }
        if found != entry.module_counters().len() {
            return Err(Error::JournalCorrupt);
        }
        Ok((counters, include))
    }

    /// Advances the marks over the counters an entry consumed; each must be
    /// its module's mark plus one.
    fn replay_consumed(
        &mut self,
        counters: &[u64; MAX_MODULES],
        include: [bool; MAX_MODULES],
    ) -> Result<(), Error> {
        for ((mark, &counter), included) in self.marks.iter_mut().zip(counters).zip(include) {
            if included && rules::advance_mark(mark, counter) != CounterCheck::Next {
                return Err(Error::JournalCorrupt);
            }
        }
        Ok(())
    }

    /// `Ok` if a batch or box close entry lists every module at its mark.
    fn replay_marks(
        &self,
        counters: &[u64; MAX_MODULES],
        include: [bool; MAX_MODULES],
    ) -> Result<(), Error> {
        let modules = self.config.modules().len();
        let all = include.iter().take(modules).all(|&i| i);
        let same = counters.get(..modules) == self.marks.get(..modules);
        if all && same {
            Ok(())
        } else {
            Err(Error::JournalCorrupt)
        }
    }

    /// Applies one journal entry read back at resume.
    fn replay(
        &mut self,
        bytes: &[u8],
        package: Option<&[u8]>,
        trail: &mut Trail,
    ) -> Result<(), Error> {
        self.usable()?;
        let entry: JournalEntry<'_> = decode_object(SCHEMA_JOURNAL_ENTRY, SCHEMA_VERSION_1, bytes)?;
        if *entry.prev_head() != self.journal_head {
            return Err(Error::JournalCorrupt);
        }
        let time_bucket = entry.time_bucket();
        self.check_time(time_bucket)?;
        let kind = entry.kind();
        let package_hash = package.map_or(Hash512::ZERO, object_hash);
        if package.is_some() != (kind == JournalKind::Record)
            || *entry.share_package_hash() != package_hash
        {
            return Err(Error::JournalCorrupt);
        }
        let (counters, include) = self.entry_counters(&entry)?;
        let record = *entry.record_hash();
        let absentee = matches!(self.config.profile(), Profile::Absentee);
        match kind {
            JournalKind::Record | JournalKind::Challenge => {
                if trail.stage != VisitStage::Undecided {
                    self.close_trail(trail)?;
                }
                self.replay_consumed(&counters, include)?;
                replay_position(trail, kind, record, &counters, include)?;
            }
            JournalKind::VisitDecision => {
                if include.contains(&true) {
                    return Err(Error::JournalCorrupt);
                }
                self.replay_decision(trail, &record, time_bucket)?;
            }
            JournalKind::Imprinted => replay_imprint(trail, &record, &counters, include)?,
            JournalKind::Quarantine if record != Hash512::ZERO => {
                self.replay_quarantine(trail, &record, &counters, include, absentee)?;
            }
            JournalKind::Quarantine => {
                self.close_trail(trail)?;
                self.replay_consumed(&counters, include)?;
                self.count_quarantine()?;
            }
            JournalKind::LabelPrinted => {
                if include.contains(&true) {
                    return Err(Error::JournalCorrupt);
                }
                replay_label(trail, &record, absentee)?;
            }
            JournalKind::BatchClose => {
                self.close_trail(trail)?;
                self.replay_marks(&counters, include)?;
                if self.batch.count == 0 || self.batch.root()? != record {
                    return Err(Error::JournalCorrupt);
                }
                self.settle_batch()?;
            }
            JournalKind::BoxClose => {
                self.close_trail(trail)?;
                self.replay_marks(&counters, include)?;
                self.phase = Phase::Closed {
                    close_body: Hash512::ZERO,
                };
            }
        }
        self.journal_head = object_hash(bytes);
        self.last_bucket = time_bucket.get();
        Ok(())
    }

    /// A decision entry: it closes the undecided trail, whose positions'
    /// digest it must carry; the records join the batch and the totals.
    fn replay_decision(
        &mut self,
        trail: &mut Trail,
        digest: &Hash512,
        time_bucket: TimeBucket,
    ) -> Result<(), Error> {
        let quarantined = trail
            .bound()
            .any(|p| matches!(p.settled, Settlement::Quarantined));
        if trail.stage != VisitStage::Undecided || trail.count == 0 || quarantined {
            return Err(Error::JournalCorrupt);
        }
        let mut entries = [(0u8, Hash512::ZERO); VISIT_POSITIONS];
        for (slot, position) in entries.iter_mut().zip(trail.bound()) {
            let kind = match position.choice {
                Choice::Cast => JournalKind::Record,
                Choice::Check => JournalKind::Challenge,
            };
            *slot = (kind.code(), position.record);
        }
        let expected = visit_digest(entries.get(..usize::from(trail.count)).unwrap_or(&[]));
        if expected != *digest {
            return Err(Error::JournalCorrupt);
        }
        let mut cast = 0u8;
        let positions = trail.positions;
        for position in positions.iter().take(usize::from(trail.count)) {
            match position.choice {
                Choice::Cast => {
                    self.push_record(position.record, time_bucket)?;
                    cast = cast.checked_add(1).ok_or(Error::Overflow)?;
                }
                Choice::Check => {
                    self.totals.challenged = self
                        .totals
                        .challenged
                        .checked_add(1)
                        .ok_or(Error::Overflow)?;
                }
            }
        }
        if cast > 0 {
            self.totals.visits = self.totals.visits.checked_add(1).ok_or(Error::Overflow)?;
        }
        trail.stage = VisitStage::Decided;
        trail.digest = *digest;
        trail.live = cast;
        Ok(())
    }

    /// A quarantine naming a record: a position of the undecided trail (the
    /// machine stopped before the decision, or the decision failed), or a
    /// cast position of the decided trail not yet imprinted (imprint
    /// failure, a resume, an abandoned visit) or, out of district without
    /// a sticker entry, an imprinted one.
    fn replay_quarantine(
        &mut self,
        trail: &mut Trail,
        record: &Hash512,
        counters: &[u64; MAX_MODULES],
        include: [bool; MAX_MODULES],
        absentee: bool,
    ) -> Result<(), Error> {
        match trail.stage {
            VisitStage::None => Err(Error::JournalCorrupt),
            VisitStage::Undecided => {
                let (_, position) = trail.find(record)?;
                if matches!(position.settled, Settlement::Quarantined)
                    || !position.same_counters(counters, include)
                {
                    return Err(Error::JournalCorrupt);
                }
                position.settled = Settlement::Quarantined;
                self.count_quarantine()?;
                let done = trail
                    .bound()
                    .all(|p| matches!(p.settled, Settlement::Quarantined));
                if done {
                    *trail = Trail::NONE;
                }
                Ok(())
            }
            VisitStage::Decided => {
                let label_printed = trail.label_printed;
                let (_, position) = trail.find(record)?;
                let allowed = match position.settled {
                    Settlement::Open => true,
                    Settlement::Imprinted => absentee && !label_printed,
                    Settlement::Quarantined => false,
                };
                if !matches!(position.choice, Choice::Cast)
                    || !allowed
                    || !position.same_counters(counters, include)
                {
                    return Err(Error::JournalCorrupt);
                }
                position.settled = Settlement::Quarantined;
                self.withdraw_cast(trail, record)
            }
        }
    }
}

/// A position entry: one more position of the undecided trail.
fn replay_position(
    trail: &mut Trail,
    kind: JournalKind,
    record: Hash512,
    counters: &[u64; MAX_MODULES],
    include: [bool; MAX_MODULES],
) -> Result<(), Error> {
    let quarantined = trail
        .bound()
        .any(|p| matches!(p.settled, Settlement::Quarantined));
    if quarantined || trail.bound().any(|p| p.record == record) {
        return Err(Error::JournalCorrupt);
    }
    let slot = trail
        .positions
        .get_mut(usize::from(trail.count))
        .ok_or(Error::JournalCorrupt)?;
    *slot = TrailPosition {
        choice: if kind == JournalKind::Record {
            Choice::Cast
        } else {
            Choice::Check
        },
        record,
        counters: *counters,
        include,
        settled: Settlement::Open,
    };
    trail.count = trail.count.checked_add(1).ok_or(Error::Overflow)?;
    trail.stage = VisitStage::Undecided;
    Ok(())
}

/// An imprint entry: the first unsettled cast position of the decided
/// trail, with its counters.
fn replay_imprint(
    trail: &mut Trail,
    record: &Hash512,
    counters: &[u64; MAX_MODULES],
    include: [bool; MAX_MODULES],
) -> Result<(), Error> {
    if trail.stage != VisitStage::Decided {
        return Err(Error::JournalCorrupt);
    }
    let (index, position) = trail.find(record)?;
    if !matches!(position.choice, Choice::Cast)
        || !matches!(position.settled, Settlement::Open)
        || !position.same_counters(counters, include)
    {
        return Err(Error::JournalCorrupt);
    }
    position.settled = Settlement::Imprinted;
    let earlier_open = trail
        .bound()
        .take(index)
        .any(|p| matches!(p.choice, Choice::Cast) && matches!(p.settled, Settlement::Open));
    if earlier_open {
        return Err(Error::JournalCorrupt);
    }
    Ok(())
}

/// A sticker entry: out of district, once every cast position is settled
/// and something is still cast; it repeats the decision digest.
fn replay_label(trail: &mut Trail, digest: &Hash512, absentee: bool) -> Result<(), Error> {
    let unsettled = trail
        .bound()
        .any(|p| matches!(p.choice, Choice::Cast) && matches!(p.settled, Settlement::Open));
    if trail.stage != VisitStage::Decided
        || !absentee
        || unsettled
        || trail.live == 0
        || trail.label_printed
        || *digest != trail.digest
    {
        return Err(Error::JournalCorrupt);
    }
    trail.label_printed = true;
    Ok(())
}
