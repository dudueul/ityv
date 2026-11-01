//! The per-ballot typestate: one position of a visit, from its
//! interpretation to its binding (PROTOCOL.md §7.3 steps 1–5, §9; ADR-0017
//! §5 and 개정 3–5, ADR-0021).
//!
//! ```text
//! OpenBox::interpret ─▶ Interpreted ─issue─▶ Issued ─commit─▶ Committed ─build─▶ Built ─bind─▶ Bound
//! ```
//!
//! Each transition consumes the ballot. [`Ballot::bind`] hands the built
//! record and share package to the host's staging store, keeps their
//! hashes in the box and the position's small secrets in the caller's
//! [`VisitWork`]; what happens next (the decision, the journal, the
//! imprint, the opening of a checked ballot) belongs to the visit
//! ([`crate::visit`]). A built ballot cannot be imprinted, opened or
//! journaled on its own:
//!
//! ```compile_fail
//! # use ityv_cunit::ballot::{Ballot, Built};
//! # use ityv_cunit::boxstate::OpenBox;
//! fn no_imprint_before_the_decision<'c>(ballot: &Ballot<'c, '_, Built<'_>>, open: &OpenBox<'c>) {
//!     let _ = ballot.imprint_command(open);
//! }
//! ```
//!
//! ```compile_fail
//! # use ityv_cunit::ballot::{Ballot, Built};
//! # use ityv_cunit::boxstate::OpenBox;
//! # use ityv_cunit::port::JournalSink;
//! # use ityv_encoding::TimeBucket;
//! fn no_cast_without_the_visit<'c>(
//!     ballot: Ballot<'c, '_, Built<'_>>,
//!     open: &mut OpenBox<'c>,
//!     sink: &mut dyn JournalSink,
//! ) {
//!     let _ = ballot.cast(open, sink, TimeBucket::new(0));
//! }
//! ```
//!
//! What a built ballot can do:
//!
//! ```
//! # use ityv_cunit::ballot::{Ballot, Built};
//! # use ityv_cunit::boxstate::OpenBox;
//! # use ityv_cunit::port::StagingPort;
//! # use ityv_cunit::visit::VisitWork;
//! fn bind<'c>(
//!     ballot: Ballot<'c, '_, Built<'_>>,
//!     open: &mut OpenBox<'c>,
//!     staging: &mut dyn StagingPort,
//!     visit: &mut VisitWork,
//! ) {
//!     let _ = ballot.bind(open, staging, visit);
//! }
//! ```
//!
//! # The work area
//!
//! Every per-ballot secret lives in one place while the ballot is built:
//! the caller's [`BallotWork`]. It holds the choice, each module's
//! contribution, the summed randomness, the cast id, the envelope label,
//! the ballot generator, the secret values shared with the trustees, each
//! member's share plaintext and the proof. A ballot borrows the work area
//! for its whole life, and transitions work on it in place instead of
//! moving secrets from state to state. The work area is wiped when a
//! ballot is created, when the shares are sealed, when the ballot is bound
//! (its small secrets move to the visit's [`VisitWork`] slot first),
//! whenever a transition fails (the consumed ballot drops), when a ballot
//! value is dropped, and when the work area itself is dropped.

use core::fmt;

use ityv_crypto::{
    CastId, ChunkIndex, Commitment, MemberId, Opening, OptionIndex, Proof, RecordPurpose,
    RecordSigningKey, Scalar, Sha3Hasher, Statement, encapsulate, object_hash, prove_into, seal,
    sign_record, split, verify_record,
};
use ityv_encoding::{
    CastRecord, CastRecordBody, CastRecordParts, Commitments, Encode, Hash512, MAX_SECRETS,
    MemberShare, ModuleRecordSig, PROOF_SYSTEM_OR_REP_V1, Point32, SCHEMA_CAST_RECORD,
    SCHEMA_CAST_RECORD_BODY, SCHEMA_MEMBER_SHARE, SCHEMA_SHARE_PACKAGE, SCHEMA_VERSION_1, Scalar32,
    Scalars, ShareEntry, SharePackage, TAG_LEN, TRANSPORT_KEM_FALLBACK, TRANSPORT_NEUTRAL_MODULE,
    Token192, Transport, Writer, decode_object, encode_object,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::boxstate::OpenBox;
use crate::config::{
    BallotStyle, ElectionConfig, MAX_MODULES, MAX_TRUSTEES, ModuleConfig, TrusteeConfig,
    chamber_code,
};
use crate::error::Error;
use crate::link::{
    Interpretation, MAX_MODULE_ISSUE_LEN, MAX_TAGS, ModuleIssue, SCHEMA_INTERPRETATION,
    SCHEMA_MODULE_ISSUE,
};
use crate::port::{ModulePort, PortError};
use crate::port::{Staged, StagingPort};
use crate::rng::{DeviceRng, LABEL_BALLOT_RNG};
use crate::rules;
use crate::visit::{ModuleRand, PositionHashes, PositionSecrets, VisitWork};

/// Label of the cast-id derivation (PROTOCOL.md §7.3 step 2).
pub const LABEL_CAST_ID: &[u8] = b"ityv:castid:v1";
/// Label of the envelope-label derivation.
pub const LABEL_ENVELOPE_LABEL: &[u8] = b"ityv:envlabel:v1";
/// Fork domain of the per-secret share-splitting streams.
pub const LABEL_SPLIT: &[u8] = b"ityv:split:v1";
/// Purpose of the challenge-opening signature.
pub const PURPOSE_CHALLENGE: &[u8] = b"challenge";
/// Purpose of the slip signature.
pub const PURPOSE_SLIP: &[u8] = b"slip";
/// Bytes of a hybrid KEM ciphertext header (`ct_mlkem ‖ ct_x25519`).
pub const KEM_CIPHERTEXT_LEN: usize = 1600;
/// Bytes of a `MemberShare` object at most, header included.
pub const MAX_MEMBER_SHARE_LEN: usize = member_share_len(MAX_SECRETS, true);
/// Scratch bytes reserved per trustee: room for a KEM ciphertext.
pub const SCRATCH_SLOT_LEN: usize = KEM_CIPHERTEXT_LEN + MAX_MEMBER_SHARE_LEN;
/// Bytes of a `Slip` object at most, header included: 16 + (4 + 676) +
/// 4691, the body holding eight tracking codes (ADR-0021).
pub const MAX_SLIP_LEN: usize = 5387;
/// Bytes of a `ChallengeOpening` object at most, header included: 16 +
/// (4 + 3094) + 4691, the body holding seven modules of eight scalars.
pub const MAX_CHALLENGE_OPENING_LEN: usize = 7805;
/// Bytes of a module record-signature message at most:
/// `body_hash: Hash512 ‖ module_id: Ident<64> ‖ counter: u64`.
pub const MODULE_RECORD_MESSAGE_LEN: usize = 64 + 4 + ityv_encoding::IDENT_MAX_STANDARD + 8;
/// Bytes of the KEM associated data at most (PROTOCOL.md §9.6).
const MAX_KEM_AAD_LEN: usize = 512;

/// Length of a `MemberShare` object, header included, for `secrets`
/// shares, with an envelope-label contribution when `label`:
/// `16 + (4 + 32·secrets) + 1 + 24 + (1 [+ 24]) + 16`.
#[must_use]
pub const fn member_share_len(secrets: usize, label: bool) -> usize {
    let base = 62usize.saturating_add(secrets.saturating_mul(32));
    if label { base.saturating_add(24) } else { base }
}

/// Scratch bytes [`Ballot::build`] needs for `trustees` trustees: one
/// [`SCRATCH_SLOT_LEN`] slot each.
#[must_use]
pub const fn scratch_len(trustees: usize) -> usize {
    trustees.saturating_mul(SCRATCH_SLOT_LEN)
}

/// One module's private per-ballot contribution.
struct Contribution {
    counter: u64,
    rand: [Scalar; ityv_crypto::MAX_CHUNKS],
    cid: [u8; 24],
    lab: Option<[u8; 24]>,
    tags: [[u8; TAG_LEN]; MAX_TAGS],
}

impl Contribution {
    fn is_clear(&self) -> bool {
        self.counter == 0
            && self.rand.iter().all(Scalar::is_zero)
            && self.cid == [0; 24]
            && self.lab.is_none()
            && self.tags.iter().flatten().all(|&b| b == 0)
    }

    const fn empty() -> Self {
        Self {
            counter: 0,
            rand: [Scalar::ZERO; ityv_crypto::MAX_CHUNKS],
            cid: [0; 24],
            lab: None,
            tags: [[0; TAG_LEN]; MAX_TAGS],
        }
    }
}

impl Zeroize for Contribution {
    fn zeroize(&mut self) {
        self.counter.zeroize();
        self.rand.zeroize();
        self.cid.zeroize();
        self.lab.zeroize();
        self.tags.zeroize();
    }
}

/// The ballot-level secrets: the cast id, the envelope label and the summed
/// randomness `r_j`.
struct Secrets {
    cast_id: CastId,
    env_label: Option<[u8; 24]>,
    rand: [Scalar; ityv_crypto::MAX_CHUNKS],
}

impl Zeroize for Secrets {
    fn zeroize(&mut self) {
        self.cast_id.zeroize();
        self.env_label.zeroize();
        self.rand.zeroize();
    }
}

pub(crate) fn scalars_clear(scalars: &[Scalar32]) -> bool {
    scalars.iter().all(|s| s.0 == [0; 32])
}

pub(crate) fn wipe_scalars(scalars: &mut [Scalar32]) {
    for scalar in scalars {
        scalar.0.zeroize();
    }
}

/// The caller-provided work area of one ballot (ADR-0017 개정 4): every
/// per-ballot secret and the proof while the ballot is built. About 30 KB;
/// a host on a small target keeps one in a `static` (the constructor is
/// `const`) and lends it to each position of a visit in turn. Not `Clone`;
/// `Debug` shows nothing; wiped on drop.
///
/// The proof is public once the record is published (it is
/// zero-knowledge); it sits here so that no ballot state carries its 20 KB,
/// and `ityv_crypto::prove_into` writes it in place. Its encoding is staged
/// in the host's record buffer while the body is written.
pub struct BallotWork {
    option: u16,
    contributions: [Contribution; MAX_MODULES],
    secrets: Secrets,
    rng: DeviceRng,
    issue: [u8; MAX_MODULE_ISSUE_LEN],
    values: [Scalar; MAX_SECRETS],
    member: [Scalar32; MAX_SECRETS],
    plaintext: [u8; MAX_MEMBER_SHARE_LEN],
    proof: Proof,
}

impl BallotWork {
    /// An empty work area.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            option: 0,
            contributions: [const { Contribution::empty() }; MAX_MODULES],
            secrets: Secrets {
                cast_id: CastId::new(Token192([0; 24])),
                env_label: None,
                rand: [Scalar::ZERO; ityv_crypto::MAX_CHUNKS],
            },
            rng: DeviceRng::empty(),
            issue: [0; MAX_MODULE_ISSUE_LEN],
            values: [Scalar::ZERO; MAX_SECRETS],
            member: [Scalar32([0; 32]); MAX_SECRETS],
            plaintext: [0; MAX_MEMBER_SHARE_LEN],
            proof: Proof::EMPTY,
        }
    }

    /// `true` if nothing is left in the work area: every secret field is
    /// zero, the generator is unkeyed and no proof is held. A host may
    /// check it after each ballot; the tests use it to observe the wipes.
    #[must_use]
    pub fn is_clear(&self) -> bool {
        self.option == 0
            && self.contributions.iter().all(Contribution::is_clear)
            && self.secrets.cast_id.token().0 == [0; 24]
            && self.secrets.env_label.is_none()
            && self.secrets.rand.iter().all(Scalar::is_zero)
            && self.rng.is_wiped()
            && self.issue.iter().all(|&b| b == 0)
            && self.values.iter().all(Scalar::is_zero)
            && scalars_clear(&self.member)
            && self.plaintext.iter().all(|&b| b == 0)
            && self.proof.is_empty()
    }

    /// Wipes the secret values and the member-share scratch once every
    /// share is sealed.
    fn wipe_shares(&mut self) {
        self.values.zeroize();
        wipe_scalars(&mut self.member);
        self.plaintext.zeroize();
    }

    /// Moves what the visit keeps of a bound position into `slot`: the
    /// choice, the cast id, the envelope label, the summed randomness and
    /// each module's randomness and cast-id part (PROTOCOL.md §8 needs them
    /// to open a checked ballot; the imprint and the sticker need the cast
    /// id and the label). The tags, the generator, the shares and the proof
    /// stay behind and are wiped with the work area.
    fn move_secrets(&mut self, slot: &mut PositionSecrets, module_rand: &mut ModuleRand) {
        slot.option = self.option;
        slot.cast_id = self.secrets.cast_id;
        slot.env_label = self.secrets.env_label;
        slot.rand = self.secrets.rand;
        for ((cid, rand), src) in slot
            .cids
            .iter_mut()
            .zip(module_rand.iter_mut())
            .zip(self.contributions.iter())
        {
            *cid = src.cid;
            *rand = src.rand;
        }
        self.zeroize();
    }
}

impl Default for BallotWork {
    fn default() -> Self {
        Self::new()
    }
}

impl Zeroize for BallotWork {
    fn zeroize(&mut self) {
        self.option.zeroize();
        self.contributions.zeroize();
        self.secrets.zeroize();
        self.rng.wipe();
        self.issue.zeroize();
        self.wipe_shares();
        self.proof.clear();
    }
}

impl Drop for BallotWork {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for BallotWork {}

impl fmt::Debug for BallotWork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BallotWork(..)")
    }
}

/// The work area as lent to one ballot: wiped when the ballot takes it and
/// when the ballot is dropped, whatever its state.
struct WorkGuard<'w>(&'w mut BallotWork);

impl<'w> WorkGuard<'w> {
    fn take(work: &'w mut BallotWork) -> Self {
        work.zeroize();
        Self(work)
    }
}

impl Drop for WorkGuard<'_> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// A ballot in state `S`, borrowing its work area for `'w`. Only the
/// [`OpenBox`] creates one.
pub struct Ballot<'c, 'w, S> {
    config: &'c ElectionConfig<'c>,
    style: &'c BallotStyle<'c>,
    ticket: u64,
    work: WorkGuard<'w>,
    state: S,
}

impl<S> fmt::Debug for Ballot<'_, '_, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ballot")
            .field("ticket", &self.ticket)
            .finish_non_exhaustive()
    }
}

impl<'c, S> Ballot<'c, '_, S> {
    /// The ballot style.
    #[must_use]
    pub const fn style(&self) -> &'c BallotStyle<'c> {
        self.style
    }
}

/// Interpreted: the option index is known, in range, and in the work area.
#[derive(Debug)]
pub struct Interpreted(());

/// Issued: every module contributed randomness, a cast-id part and tags,
/// and the ballot generator is seeded (all in the work area).
#[derive(Debug)]
pub struct Issued(());

/// Committed: the commitments are public; the secrets and the encoded
/// proof are in the work area.
#[derive(Debug)]
pub struct Committed {
    commitments: Commitments,
}

/// Built: the share package, the record body and the signed record exist
/// in the host's buffers; nothing is journaled yet.
#[derive(Debug, Clone, Copy)]
pub struct Built<'b> {
    record_hash: Hash512,
    package: &'b [u8],
    body: &'b [u8],
    record: &'b [u8],
}

/// The host buffers one ballot's public objects are written into.
#[derive(Debug)]
pub struct BuildBuffers<'b> {
    /// The ciphertexts: at least [`scratch_len`] bytes.
    pub scratch: &'b mut [u8],
    /// The `SharePackage` object.
    pub package: &'b mut [u8],
    /// The `CastRecordBody` object.
    pub body: &'b mut [u8],
    /// The `CastRecord` object.
    pub record: &'b mut [u8],
}

impl<'c> OpenBox<'c> {
    /// Accepts the bytes the interpretation unit sent: they must be one
    /// `Interpretation` object (schema 0x0101) naming this election, a
    /// configured ballot style and an option `0..=m+1` (ITYV-BEH-013). The
    /// ballot is the next position of the open visit, or opens a new visit
    /// (which needs room for eight records in the open batch). The ballot
    /// borrows `work`, which is wiped first.
    ///
    /// # Errors
    /// The decoder's error, [`Error::WrongElection`],
    /// [`Error::UnknownBallotStyle`], [`Error::OptionOutOfRange`],
    /// [`Error::BoxClosed`], [`Error::JournalMismatch`],
    /// [`Error::BallotInFlight`], [`Error::BatchFull`],
    /// [`Error::VisitFull`], [`Error::VisitInProgress`].
    pub fn interpret<'w>(
        &mut self,
        link: &[u8],
        work: &'w mut BallotWork,
    ) -> Result<Ballot<'c, 'w, Interpreted>, Error> {
        let work = WorkGuard::take(work);
        let config = self.config();
        let interpretation: Interpretation<'_> =
            decode_object(SCHEMA_INTERPRETATION, SCHEMA_VERSION_1, link)?;
        if interpretation.election_id().as_bytes() != config.election_id().as_bytes() {
            return Err(Error::WrongElection);
        }
        let (_, style) = config
            .style(interpretation.ballot_style_id())
            .ok_or(Error::UnknownBallotStyle)?;
        let index = interpretation.option_index();
        if !rules::option_in_range(style.option_count().get(), index) {
            return Err(Error::OptionOutOfRange);
        }
        let ticket = self.begin_ballot()?;
        work.0.option = index;
        Ok(Ballot {
            config,
            style,
            ticket,
            work,
            state: Interpreted(()),
        })
    }
}

/// Checks one decoded issue against the configuration and stores its
/// private part in `slot`.
fn accept_issue(
    config: &ElectionConfig<'_>,
    style: &BallotStyle<'_>,
    module: &ModuleConfig<'_>,
    issue: &ModuleIssue<'_>,
    slot: &mut Contribution,
) -> Result<(), Error> {
    if issue.chamber() != chamber_code(module.chamber()).code() {
        return Err(Error::WrongChamber);
    }
    if issue.rand().len() != usize::from(style.chunk_count()) {
        return Err(Error::ChunkCountMismatch);
    }
    if issue.lab().is_some() != config.profile().has_label() {
        return Err(Error::LabelPresence);
    }
    let members = config.access().threshold(module.chamber()).n();
    if issue.tags().len() != usize::from(members) {
        return Err(Error::TagCount);
    }
    for (dst, src) in slot.rand.iter_mut().zip(issue.rand()) {
        *dst = Scalar::from_canonical_bytes(src.0)?;
    }
    slot.counter = issue.counter();
    slot.cid = issue.cid().0;
    slot.lab = issue.lab().map(|lab| lab.0);
    for (dst, src) in slot.tags.iter_mut().zip(issue.tags()) {
        *dst = *src;
    }
    Ok(())
}

impl<'c, 'w> Ballot<'c, 'w, Interpreted> {
    /// Requests a `ModuleIssue` for the style's `k` from every module
    /// (PROTOCOL.md §7.3 step 2) and seeds the ballot generator from
    /// `device_seed` and every module's private contribution. A module's
    /// counter is accepted (and consumed) only if it is the module's
    /// high-water mark plus one; a later check failing then leaves the
    /// visit to be abandoned ([`OpenBox::abandon_visit`]).
    ///
    /// # Errors
    /// [`Error::StaleBallot`], [`Error::PortCount`], port errors, decoding
    /// errors, [`Error::WrongModule`], [`Error::CounterRegression`],
    /// [`Error::CounterGap`], [`Error::WrongChamber`],
    /// [`Error::ChunkCountMismatch`], [`Error::LabelPresence`],
    /// [`Error::TagCount`], a non-canonical scalar. The work area is wiped.
    pub fn issue(
        self,
        open_box: &mut OpenBox<'c>,
        ports: &mut [&mut dyn ModulePort],
        device_seed: &[u8; 32],
    ) -> Result<Ballot<'c, 'w, Issued>, Error> {
        let Ballot {
            config,
            style,
            ticket,
            work,
            state: Interpreted(()),
        } = self;
        open_box.check_ticket(ticket)?;
        let modules = config.modules();
        if ports.len() != modules.len() {
            return Err(Error::PortCount);
        }
        let w = &mut *work.0;
        for (index, ((module, port), slot)) in modules
            .iter()
            .zip(ports.iter_mut())
            .zip(w.contributions.iter_mut())
            .enumerate()
        {
            w.issue.zeroize();
            let len = port.issue(style.chunk_count(), &mut w.issue)?;
            let bytes = w.issue.get(..len).ok_or(Error::BufferTooSmall)?;
            let issue: ModuleIssue<'_> =
                decode_object(SCHEMA_MODULE_ISSUE, SCHEMA_VERSION_1, bytes)?;
            if issue.module_id().as_bytes() != module.module_id().as_bytes() {
                return Err(Error::WrongModule);
            }
            open_box.note_issue(ticket, index, issue.counter())?;
            accept_issue(config, style, module, &issue, slot)?;
        }
        w.issue.zeroize();
        let k = usize::from(style.chunk_count());
        let mut hasher = Sha3Hasher::new();
        hasher.absorb(LABEL_BALLOT_RNG);
        hasher.absorb(&[0x00]);
        hasher.absorb(device_seed);
        for contribution in w.contributions.iter().take(modules.len()) {
            for scalar in contribution.rand.iter().take(k) {
                hasher.absorb(&scalar.to_bytes());
            }
            hasher.absorb(&contribution.cid);
            if let Some(lab) = &contribution.lab {
                hasher.absorb(lab);
            }
        }
        w.rng.reseed(hasher);
        Ok(Ballot {
            config,
            style,
            ticket,
            work,
            state: Issued(()),
        })
    }
}

/// `SHA3-512(label ‖ 0x00 ‖ parts in module order)[0..24]` into `out`.
fn derive_token<'p>(label: &[u8], parts: impl Iterator<Item = &'p [u8; 24]>, out: &mut [u8; 24]) {
    let mut hasher = Sha3Hasher::new();
    hasher.absorb(label);
    hasher.absorb(&[0x00]);
    for part in parts {
        hasher.absorb(part);
    }
    let mut digest = hasher.finish();
    if let Some((head, _)) = digest.split_first_chunk::<24>() {
        *out = *head;
    }
    digest.zeroize();
}

impl<'c, 'w> Ballot<'c, 'w, Issued> {
    /// Derives the cast id (and the envelope label), sums the randomness,
    /// computes the commitments (PROTOCOL.md §7.4) and the OR proof (§7.5),
    /// all into the work area.
    ///
    /// # Errors
    /// [`Error::StaleBallot`] and the cryptographic errors of the proof.
    /// The work area is wiped.
    pub fn commit(self, open_box: &OpenBox<'c>) -> Result<Ballot<'c, 'w, Committed>, Error> {
        let Ballot {
            config,
            style,
            ticket,
            work,
            state: Issued(()),
        } = self;
        open_box.check_ticket(ticket)?;
        let w = &mut *work.0;
        let modules = config.modules().len();
        let k = usize::from(style.chunk_count());
        let mut token = [0u8; 24];
        derive_token(
            LABEL_CAST_ID,
            w.contributions.iter().take(modules).map(|c| &c.cid),
            &mut token,
        );
        w.secrets.cast_id = CastId::new(Token192(token));
        if config.profile().has_label() {
            let label = w.secrets.env_label.insert([0; 24]);
            derive_token(
                LABEL_ENVELOPE_LABEL,
                w.contributions
                    .iter()
                    .take(modules)
                    .filter_map(|c| c.lab.as_ref()),
                label,
            );
        }
        token.zeroize();
        for (j, sum) in w.secrets.rand.iter_mut().enumerate().take(k) {
            for contribution in w.contributions.iter().take(modules) {
                let part = contribution.rand.get(j).ok_or(Error::Capacity)?;
                *sum = sum.add(part);
            }
        }
        let option = OptionIndex::new(w.option).ok_or(Error::OptionOutOfRange)?;
        let bases = open_box.bases();
        let mut points = [Point32([0; 32]); ityv_crypto::MAX_CHUNKS];
        let chunk0 = ChunkIndex::new(0).ok_or(Error::Capacity)?;
        let first_rand = w.secrets.rand.first().ok_or(Error::Capacity)?;
        let first = ityv_crypto::commit(bases, option, &w.secrets.cast_id, first_rand, chunk0);
        let mut commitments: [Commitment; ityv_crypto::MAX_CHUNKS] =
            [first; ityv_crypto::MAX_CHUNKS];
        for (j, ((slot, point), rand)) in commitments
            .iter_mut()
            .zip(points.iter_mut())
            .zip(w.secrets.rand.iter())
            .enumerate()
            .take(k)
        {
            let chunk = ChunkIndex::new(u8::try_from(j).map_err(|_| Error::Capacity)?)
                .ok_or(Error::Capacity)?;
            *slot = ityv_crypto::commit(bases, option, &w.secrets.cast_id, rand, chunk);
            *point = slot.to_point32();
        }
        let statement = Statement::new(
            config.election_id(),
            config.box_id().ident(),
            style.id().ident(),
            style.option_count(),
            commitments.get(..k).ok_or(Error::Capacity)?,
        )?;
        let opening = Opening::new(option, w.secrets.cast_id, w.secrets.rand);
        let proved = prove_into(&mut w.proof, bases, &statement, &opening, &mut w.rng);
        drop(opening);
        proved?;
        let encoded =
            Commitments::new(points.get(..k).ok_or(Error::Capacity)?).ok_or(Error::Capacity)?;
        Ok(Ballot {
            config,
            style,
            ticket,
            work,
            state: Committed {
                commitments: encoded,
            },
        })
    }
}

/// The ciphertext length, transport and tag of one share-package entry.
#[derive(Debug, Clone, Copy)]
struct EntryMeta {
    len: usize,
    transport: Transport,
    tag: [u8; TAG_LEN],
}

const EMPTY_META: EntryMeta = EntryMeta {
    len: 0,
    transport: Transport::Kem,
    tag: [0; TAG_LEN],
};

/// The public facts the share transport reads for one ballot.
struct ShareContext<'x, 'c> {
    config: &'x ElectionConfig<'c>,
    commitments: &'x Commitments,
    counters: &'x [u64; MAX_MODULES],
}

/// The parts of the work area the share transport uses.
struct ShareWork<'x> {
    contributions: &'x [Contribution; MAX_MODULES],
    values: &'x [Scalar],
    rng: &'x mut DeviceRng,
    member: &'x mut [Scalar32; MAX_SECRETS],
    plaintext: &'x mut [u8; MAX_MEMBER_SHARE_LEN],
}

/// Writes trustee `trustee`'s `MemberShare` object (ENCODING.md §8.11)
/// into the work area's plaintext; returns its length and the index of the
/// chamber's module.
fn member_plaintext(
    ctx: &ShareContext<'_, '_>,
    work: &mut ShareWork<'_>,
    trustee: &TrusteeConfig<'_>,
) -> Result<(usize, Option<usize>), Error> {
    let member = MemberId::new(trustee.chamber(), trustee.member_index()).ok_or(Error::Capacity)?;
    for (index, (value, slot)) in work.values.iter().zip(work.member.iter_mut()).enumerate() {
        let mut stream = work.rng.fork(
            LABEL_SPLIT,
            u64::try_from(index).map_err(|_| Error::Overflow)?,
        );
        let shares = split(value, ctx.config.access(), &mut stream);
        slot.0 = shares.value(member).to_bytes();
    }
    let set = Scalars::<MAX_SECRETS>::new(
        work.member
            .get(..work.values.len())
            .ok_or(Error::Capacity)?,
    )
    .ok_or(Error::Capacity)?;
    let module = ctx
        .config
        .module_for(trustee.chamber())
        .map(|(index, _)| index);
    let (has_module, cid, lab, tag) = match module {
        Some(index) => {
            let contribution = work.contributions.get(index).ok_or(Error::Capacity)?;
            let tag = contribution
                .tags
                .get(usize::from(trustee.member_index()))
                .ok_or(Error::Capacity)?;
            (
                true,
                Token192(contribution.cid),
                contribution.lab.map(Token192),
                *tag,
            )
        }
        None => (false, Token192([0; 24]), None, [0; TAG_LEN]),
    };
    let share = MemberShare::new(&set, has_module, cid, lab, &tag).ok_or(Error::Capacity)?;
    let len = encode_object(
        SCHEMA_MEMBER_SHARE,
        SCHEMA_VERSION_1,
        &share,
        work.plaintext.as_mut_slice(),
    )?;
    Ok((len, module))
}

/// The associated data of a KEM entry (PROTOCOL.md §9.6 as amended: the
/// package's commitments stand for the record hash, which depends on the
/// package).
fn kem_aad(
    ctx: &ShareContext<'_, '_>,
    trustee: &TrusteeConfig<'_>,
    out: &mut [u8; MAX_KEM_AAD_LEN],
) -> Result<usize, Error> {
    let mut w = Writer::new(out);
    ctx.config.election_id().encode(&mut w)?;
    ctx.config.box_id().encode(&mut w)?;
    ctx.commitments.encode(&mut w)?;
    trustee.trustee_id().encode(&mut w)?;
    w.write_u8(1)?;
    w.write_u32(0)?;
    w.write_u64(0)?;
    Ok(w.finish())
}

/// Seals `plaintext` for `trustee` into `slot` through the chamber's module
/// pad, checking the pad identifier and that the pad index is
/// `counter × b` (VC-034). `Ok(None)` when the pad is exhausted.
fn seal_with_pad(
    ctx: &ShareContext<'_, '_>,
    trustee: &TrusteeConfig<'_>,
    module: usize,
    plaintext: &[u8],
    slot: &mut [u8],
    ports: &mut [&mut dyn ModulePort],
) -> Result<Option<EntryMeta>, Error> {
    let counter = ctx.counters.get(module).copied().ok_or(Error::Capacity)?;
    let expected =
        rules::pad_index(counter, ctx.config.pad_consumption()).ok_or(Error::Overflow)?;
    let port = ports.get_mut(module).ok_or(Error::PortCount)?;
    let dst = slot
        .get_mut(..plaintext.len())
        .ok_or(Error::BufferTooSmall)?;
    dst.copy_from_slice(plaintext);
    let result = match port.seal_member(trustee.member_index(), dst) {
        Ok(sealed) if sealed.pad_id != trustee.pad_id() => Err(Error::PadIdMismatch),
        Ok(sealed) if sealed.pad_index != expected => Err(Error::PadIndexMismatch),
        Ok(sealed) => Ok(Some(EntryMeta {
            len: plaintext.len(),
            transport: Transport::Pad {
                pad_id: sealed.pad_id,
                pad_index: sealed.pad_index,
            },
            tag: sealed.tag,
        })),
        Err(PortError::Exhausted) => Ok(None),
        Err(error) => Err(error.into()),
    };
    if !matches!(result, Ok(Some(_))) {
        dst.zeroize();
    }
    result
}

/// Seals `plaintext` for `trustee` into `slot` with the hybrid KEM. The
/// associated data is computed before the plaintext enters the slot.
fn seal_with_kem(
    ctx: &ShareContext<'_, '_>,
    trustee: &TrusteeConfig<'_>,
    plaintext: &[u8],
    slot: &mut [u8],
    rng: &mut DeviceRng,
) -> Result<EntryMeta, Error> {
    let mut aad = [0u8; MAX_KEM_AAD_LEN];
    let aad_len = kem_aad(ctx, trustee, &mut aad)?;
    let aad = aad.get(..aad_len).ok_or(Error::BufferTooSmall)?;
    let (ciphertext, key) = encapsulate(trustee.kem_public_key(), rng)?;
    let (head, rest) = slot
        .split_at_mut_checked(KEM_CIPHERTEXT_LEN)
        .ok_or(Error::BufferTooSmall)?;
    let mut w = Writer::new(head);
    ciphertext.encode(&mut w)?;
    if w.finish() != KEM_CIPHERTEXT_LEN {
        return Err(Error::Overflow);
    }
    let dst = rest
        .get_mut(..plaintext.len())
        .ok_or(Error::BufferTooSmall)?;
    dst.copy_from_slice(plaintext);
    let tag = match seal(key, aad, dst) {
        Ok(tag) => tag,
        Err(error) => {
            dst.zeroize();
            return Err(error.into());
        }
    };
    Ok(EntryMeta {
        len: KEM_CIPHERTEXT_LEN
            .checked_add(plaintext.len())
            .ok_or(Error::Overflow)?,
        transport: Transport::Kem,
        tag: *tag.as_bytes(),
    })
}

/// Fills the work area's secret values in the `MemberShare` order: each
/// module's `r_{c,0..k−1}` in module order, the cast id, the envelope
/// label. Returns how many.
fn secret_values(
    config: &ElectionConfig<'_>,
    style: &BallotStyle<'_>,
    work: &mut BallotWork,
) -> Result<usize, Error> {
    let k = usize::from(style.chunk_count());
    let BallotWork {
        contributions,
        secrets,
        values,
        ..
    } = work;
    let mut slots = values.iter_mut();
    let mut n = 0usize;
    let mut push = |value: Scalar| -> Result<(), Error> {
        *slots.next().ok_or(Error::Capacity)? = value;
        n = n.checked_add(1).ok_or(Error::Overflow)?;
        Ok(())
    };
    for contribution in contributions.iter().take(config.modules().len()) {
        for rand in contribution.rand.iter().take(k) {
            push(*rand)?;
        }
    }
    push(secrets.cast_id.to_scalar())?;
    if let Some(label) = secrets.env_label {
        push(CastId::new(Token192(label)).to_scalar())?;
    }
    if n != config.secret_count(style) {
        return Err(Error::Capacity);
    }
    Ok(n)
}

/// Seals every trustee's member share into its scratch slot.
fn seal_all(
    ctx: &ShareContext<'_, '_>,
    work: &mut ShareWork<'_>,
    ports: &mut [&mut dyn ModulePort],
    ct_region: &mut [u8],
) -> Result<([EntryMeta; MAX_TRUSTEES], u8), Error> {
    let mut flags = if ctx.config.uses_neutral_module() {
        TRANSPORT_NEUTRAL_MODULE
    } else {
        0
    };
    let mut metas = [EMPTY_META; MAX_TRUSTEES];
    for ((trustee, slot), meta) in ctx
        .config
        .trustees()
        .iter()
        .zip(ct_region.chunks_exact_mut(SCRATCH_SLOT_LEN))
        .zip(metas.iter_mut())
    {
        let (len, module) = member_plaintext(ctx, work, trustee)?;
        let plaintext = work.plaintext.get(..len).ok_or(Error::BufferTooSmall)?;
        let padded = match module {
            Some(index) => seal_with_pad(ctx, trustee, index, plaintext, slot, ports)?,
            None => None,
        };
        *meta = if let Some(entry) = padded {
            entry
        } else {
            if module.is_some() {
                flags |= TRANSPORT_KEM_FALLBACK;
            }
            seal_with_kem(ctx, trustee, plaintext, slot, work.rng)?
        };
        work.plaintext.zeroize();
    }
    Ok((metas, flags))
}

/// Writes the `SharePackage` object (ENCODING.md §8.10).
fn write_package<'b>(
    config: &ElectionConfig<'_>,
    commitments: &Commitments,
    metas: &[EntryMeta; MAX_TRUSTEES],
    ciphertexts: &'b [u8],
    out: &'b mut [u8],
) -> Result<&'b [u8], Error> {
    let trustees = config.trustees();
    let first = trustees.first().ok_or(Error::Capacity)?;
    let placeholder = ShareEntry {
        trustee_id: first.trustee_id(),
        chamber: chamber_code(first.chamber()),
        transport: Transport::Kem,
        ciphertext: &[],
        tag: &[0; TAG_LEN],
    };
    let mut entries = [placeholder; MAX_TRUSTEES];
    for (index, ((entry, trustee), meta)) in entries.iter_mut().zip(trustees).zip(metas).enumerate()
    {
        let start = index.checked_mul(SCRATCH_SLOT_LEN).ok_or(Error::Overflow)?;
        let end = start.checked_add(meta.len).ok_or(Error::Overflow)?;
        *entry = ShareEntry {
            trustee_id: trustee.trustee_id(),
            chamber: chamber_code(trustee.chamber()),
            transport: meta.transport,
            ciphertext: ciphertexts.get(start..end).ok_or(Error::BufferTooSmall)?,
            tag: &meta.tag,
        };
    }
    let package = SharePackage::new(
        config.election_id(),
        config.box_id(),
        commitments,
        entries.get(..trustees.len()).ok_or(Error::Capacity)?,
    )
    .ok_or(Error::Capacity)?;
    let len = encode_object(SCHEMA_SHARE_PACKAGE, SCHEMA_VERSION_1, &package, out)?;
    let written: &'b [u8] = out;
    written.get(..len).ok_or(Error::BufferTooSmall)
}

/// Signs the record body (device Ed25519 over the body object bytes, each
/// module Ed25519 over `body_hash ‖ module_id ‖ counter`, verified with
/// the module's genesis key) and writes the `CastRecord` object
/// (ENCODING.md §8.7).
fn sign_and_wrap<'b>(
    config: &ElectionConfig<'_>,
    counters: &[u64; MAX_MODULES],
    ports: &mut [&mut dyn ModulePort],
    device_key: &RecordSigningKey,
    body: &'b [u8],
    out: &'b mut [u8],
) -> Result<&'b [u8], Error> {
    let record_hash = object_hash(body);
    let device = sign_record(device_key, RecordPurpose::CastRecord, body)?;
    let device_bytes = *device.as_bytes();
    let modules = config.modules();
    let mut module_bytes = [[0u8; 64]; MAX_MODULES];
    for (((module, port), slot), &counter) in modules
        .iter()
        .zip(ports.iter_mut())
        .zip(module_bytes.iter_mut())
        .zip(counters)
    {
        let mut message = [0u8; MODULE_RECORD_MESSAGE_LEN];
        let mut w = Writer::new(&mut message);
        record_hash.encode(&mut w)?;
        module.module_id().encode(&mut w)?;
        w.write_u64(counter)?;
        let len = w.finish();
        let message = message.get(..len).ok_or(Error::BufferTooSmall)?;
        let sig = port.sign_record(message)?;
        let verified = verify_record(
            module.record_key(),
            RecordPurpose::ModuleRecord,
            message,
            &sig,
        )
        .map_err(|_| Error::RecordSignature)?;
        *slot = *verified.get().signature().as_bytes();
    }
    let first = modules.first().ok_or(Error::Capacity)?;
    let first_bytes = module_bytes.first().ok_or(Error::Capacity)?;
    let mut sigs = [ModuleRecordSig {
        module_id: first.module_id(),
        ed25519: first_bytes,
    }; MAX_MODULES];
    for ((entry, module), bytes) in sigs.iter_mut().zip(modules).zip(module_bytes.iter()) {
        *entry = ModuleRecordSig {
            module_id: module.module_id(),
            ed25519: bytes,
        };
    }
    let record = CastRecord::new(
        body,
        &device_bytes,
        sigs.get(..modules.len()).ok_or(Error::Capacity)?,
    )?;
    let len = encode_object(SCHEMA_CAST_RECORD, SCHEMA_VERSION_1, &record, out)?;
    let written: &'b [u8] = out;
    written.get(..len).ok_or(Error::BufferTooSmall)
}

impl<'c, 'w> Ballot<'c, 'w, Committed> {
    /// Builds every public object of the ballot into the host's buffers
    /// (PROTOCOL.md §7.3 steps 4–5, §9): the member shares of every secret,
    /// sealed through the module pads or the KEM; the `SharePackage`; the
    /// `CastRecordBody` naming the package hash; the device and module
    /// record signatures; the `CastRecord`. Nothing is journaled yet. The
    /// share plaintexts are wiped from the work area once sealed.
    ///
    /// # Errors
    /// [`Error::StaleBallot`], [`Error::PortCount`],
    /// [`Error::BufferTooSmall`], [`Error::PadIdMismatch`],
    /// [`Error::PadIndexMismatch`], [`Error::RecordSignature`], port,
    /// cryptographic and encoding errors. The work area is wiped.
    pub fn build<'b>(
        self,
        open_box: &OpenBox<'c>,
        ports: &mut [&mut dyn ModulePort],
        device_key: &RecordSigningKey,
        buffers: BuildBuffers<'b>,
    ) -> Result<Ballot<'c, 'w, Built<'b>>, Error> {
        let Ballot {
            config,
            style,
            ticket,
            work,
            state: Committed { commitments },
        } = self;
        let flight = open_box.check_ticket(ticket)?;
        if ports.len() != config.modules().len() {
            return Err(Error::PortCount);
        }
        let BuildBuffers {
            scratch,
            package,
            body,
            record,
        } = buffers;
        let w = &mut *work.0;
        let n_values = secret_values(config, style, w)?;
        let ctx = ShareContext {
            config,
            commitments: &commitments,
            counters: &flight.counters,
        };
        let mut share_work = ShareWork {
            contributions: &w.contributions,
            values: w.values.get(..n_values).ok_or(Error::Capacity)?,
            rng: &mut w.rng,
            member: &mut w.member,
            plaintext: &mut w.plaintext,
        };
        let (metas, flags) = seal_all(&ctx, &mut share_work, ports, scratch)?;
        w.wipe_shares();
        let ciphertexts: &'b [u8] = scratch;
        let package = write_package(config, &commitments, &metas, ciphertexts, package)?;
        let package_hash = object_hash(package);

        let module_counters = open_box.counter_list(&flight.counters, flight.issued)?;
        // The record buffer stages the proof encoding until the record is
        // written over it.
        let mut writer = Writer::new(record);
        w.proof.encode(&mut writer)?;
        let proof_len = writer.finish();
        let body_object = CastRecordBody::new(&CastRecordParts {
            election_id: config.election_id(),
            box_id: config.box_id(),
            ballot_style_id: style.id(),
            proof_system_id: PROOF_SYSTEM_OR_REP_V1,
            commitments,
            proof: record.get(..proof_len).ok_or(Error::BufferTooSmall)?,
            module_counters,
            share_package_hash: package_hash,
            transport_flags: flags,
        })
        .ok_or(Error::Capacity)?;
        let body_len = encode_object(
            SCHEMA_CAST_RECORD_BODY,
            SCHEMA_VERSION_1,
            &body_object,
            body,
        )?;
        let body: &'b [u8] = body;
        let body = body.get(..body_len).ok_or(Error::BufferTooSmall)?;
        let record_hash = object_hash(body);
        let record = sign_and_wrap(config, &flight.counters, ports, device_key, body, record)?;
        Ok(Ballot {
            config,
            style,
            ticket,
            work,
            state: Built {
                record_hash,
                package,
                body,
                record,
            },
        })
    }
}

impl<'c, 'b> Ballot<'c, '_, Built<'b>> {
    /// The tracking code: the object hash of the record body.
    #[must_use]
    pub const fn tracking_code(&self) -> &Hash512 {
        &self.state.record_hash
    }

    /// The `CastRecord` object.
    #[must_use]
    pub const fn record_bytes(&self) -> &'b [u8] {
        self.state.record
    }

    /// The `CastRecordBody` object.
    #[must_use]
    pub const fn body_bytes(&self) -> &'b [u8] {
        self.state.body
    }

    /// The `SharePackage` object.
    #[must_use]
    pub const fn package_bytes(&self) -> &'b [u8] {
        self.state.package
    }

    /// Binds the built position to its visit (PROTOCOL.md §7.3 step 5,
    /// VC-068): the `CastRecord` and the `SharePackage` go to the host's
    /// staging store, the box keeps their hashes (and the record's
    /// tracking code and counters), and the position's small secrets move
    /// from the work area into the visit's slot. The work area is wiped.
    /// The first position of a visit takes `visit` (wiping it); later
    /// positions must bring the same one. Nothing is journaled: the visit's
    /// decision does that for every position at once.
    ///
    /// # Errors
    /// [`Error::StaleBallot`], [`Error::NoBallotInFlight`],
    /// [`Error::StaleVisit`] if `visit` belongs to another visit, the
    /// staging port's error. On error the ballot is dropped and the visit
    /// must be abandoned ([`OpenBox::abandon_visit`]).
    pub fn bind(
        self,
        open_box: &mut OpenBox<'c>,
        staging: &mut dyn StagingPort,
        visit: &mut VisitWork,
    ) -> Result<Bound, Error> {
        let Ballot {
            style,
            ticket,
            work,
            state,
            ..
        } = self;
        open_box.check_ticket(ticket)?;
        let (visit_ticket, position) = open_box.next_position()?;
        let (slot, module_rand) = visit.slot_for(visit_ticket, position)?;
        staging.stage(position, Staged::Record, state.record)?;
        staging.stage(position, Staged::Package, state.package)?;
        work.0.move_secrets(slot, module_rand);
        let bound = open_box.bind_position(
            ticket,
            style,
            &PositionHashes {
                record: state.record_hash,
                record_object: object_hash(state.record),
                package: object_hash(state.package),
            },
        );
        if bound.is_err() {
            slot.zeroize();
            for row in module_rand {
                row.zeroize();
            }
            return Err(Error::StaleBallot);
        }
        visit.note_bound();
        drop(work);
        Ok(Bound {
            position,
            tracking_code: state.record_hash,
        })
    }
}

/// A position bound to its visit: its index and its tracking code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bound {
    position: u8,
    tracking_code: Hash512,
}

impl Bound {
    /// The position in the visit, 0-based, in the order the ballots came.
    #[must_use]
    pub const fn position(&self) -> u8 {
        self.position
    }

    /// The tracking code (the record body's object hash).
    #[must_use]
    pub const fn tracking_code(&self) -> &Hash512 {
        &self.tracking_code
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::boxed::Box;

    fn filled() -> Box<BallotWork> {
        let mut work = Box::new(BallotWork::new());
        work.option = 7;
        for c in &mut work.contributions {
            c.counter = 3;
            c.rand = [Scalar::from_u64(5); ityv_crypto::MAX_CHUNKS];
            c.cid = [7; 24];
            c.lab = Some([8; 24]);
            c.tags = [[9; TAG_LEN]; MAX_TAGS];
        }
        work.secrets = Secrets {
            cast_id: CastId::new(Token192([4; 24])),
            env_label: Some([6; 24]),
            rand: [Scalar::from_u64(9); ityv_crypto::MAX_CHUNKS],
        };
        work.rng.reseed(Sha3Hasher::new());
        work.issue = [1; MAX_MODULE_ISSUE_LEN];
        work.values = [Scalar::from_u64(2); MAX_SECRETS];
        work.member = [Scalar32([3; 32]); MAX_SECRETS];
        work.plaintext = [4; MAX_MEMBER_SHARE_LEN];
        work.proof = sample_proof().expect("a well-formed proof");
        assert!(!work.proof.is_empty());
        work
    }

    /// A wiped generator (zero key, counter zero) yields the same stream
    /// as an empty one; a keyed one does not.
    fn rng_is_empty(rng: &mut DeviceRng) -> bool {
        let mut expected = [0u8; 16];
        let mut got = [0u8; 16];
        let Ok(()) = rand_core::TryRng::try_fill_bytes(&mut DeviceRng::empty(), &mut expected);
        let Ok(()) = rand_core::TryRng::try_fill_bytes(rng, &mut got);
        expected == got
    }

    /// A decodable proof for a three-option set (one chunk).
    fn sample_proof() -> Option<Proof> {
        let mut bytes = std::vec![0u8, 3, 1];
        bytes.resize(3 + 3 * (64 + 32), 0);
        <Proof as ityv_encoding::Decode>::decode(&mut ityv_encoding::Reader::new(&bytes)).ok()
    }

    fn shares_are_wiped(work: &BallotWork) -> bool {
        work.values.iter().all(Scalar::is_zero)
            && work.member.iter().all(|s| s.0 == [0; 32])
            && work.plaintext.iter().all(|&b| b == 0)
    }

    #[test]
    fn zeroize_clears_every_field() {
        let mut work = filled();
        work.zeroize();
        assert_eq!(work.option, 0);
        for c in &work.contributions {
            assert_eq!(c.counter, 0);
            assert!(c.rand.iter().all(Scalar::is_zero));
            assert_eq!(c.cid, [0; 24]);
            assert!(c.lab.is_none());
            assert_eq!(c.tags, [[0; TAG_LEN]; MAX_TAGS]);
        }
        assert_eq!(work.secrets.cast_id.token().0, [0; 24]);
        assert!(work.secrets.env_label.is_none());
        assert!(work.secrets.rand.iter().all(Scalar::is_zero));
        assert!(rng_is_empty(&mut work.rng));
        assert!(work.issue.iter().all(|&b| b == 0));
        assert!(shares_are_wiped(&work));
        assert!(work.proof.is_empty());
    }

    #[test]
    fn is_clear_sees_every_field_on_its_own() {
        let clear = Box::new(BallotWork::new());
        assert!(clear.is_clear());
        let dirty: [fn(&mut BallotWork); 15] = [
            |w| w.option = 1,
            |w| w.contributions[5].counter = 1,
            |w| w.contributions[0].rand[7] = Scalar::from_u64(1),
            |w| w.contributions[1].cid[23] = 1,
            |w| w.contributions[2].lab = Some([0; 24]),
            |w| w.contributions[3].tags[7][15] = 1,
            |w| w.secrets.cast_id = CastId::new(Token192([1; 24])),
            |w| w.secrets.env_label = Some([0; 24]),
            |w| w.secrets.rand[7] = Scalar::from_u64(1),
            |w| w.rng.reseed(Sha3Hasher::new()),
            |w| w.issue[MAX_MODULE_ISSUE_LEN - 1] = 1,
            |w| w.values[MAX_SECRETS - 1] = Scalar::from_u64(1),
            |w| w.member[MAX_SECRETS - 1].0[31] = 1,
            |w| w.plaintext[MAX_MEMBER_SHARE_LEN - 1] = 1,
            |w| w.proof = sample_proof().expect("a well-formed proof"),
        ];
        for (i, make_dirty) in dirty.iter().enumerate() {
            let mut work = Box::new(BallotWork::new());
            make_dirty(&mut work);
            assert!(!work.is_clear(), "field {i}");
            work.zeroize();
            assert!(work.is_clear(), "field {i} after zeroize");
        }
        let mut counter_only = DeviceRng::empty();
        let mut byte = [0u8; 65];
        let Ok(()) = rand_core::TryRng::try_fill_bytes(&mut counter_only, &mut byte);
        assert!(!counter_only.is_wiped(), "a used generator is not wiped");
        assert!(filled().contributions.iter().all(|c| !c.is_clear()));
    }

    #[test]
    fn binding_moves_the_small_secrets_and_wipes_the_rest() {
        let mut work = filled();
        let mut slot = crate::visit::tests::empty_slot();
        let mut module_rand = [[Scalar::ZERO; ityv_crypto::MAX_CHUNKS]; MAX_MODULES];
        work.move_secrets(&mut slot, &mut module_rand);
        assert!(work.is_clear(), "everything is wiped from the work area");
        assert_eq!(slot.option, 7);
        assert_eq!(slot.cast_id.token().0, [4; 24]);
        assert_eq!(slot.env_label, Some([6; 24]));
        assert!(slot.rand.iter().all(|s| *s == Scalar::from_u64(9)));
        assert!(slot.cids.iter().all(|c| *c == [7; 24]));
        assert!(
            module_rand
                .iter()
                .flatten()
                .all(|s| *s == Scalar::from_u64(5))
        );
    }

    #[test]
    fn wipe_shares_clears_only_the_share_scratch() {
        let mut work = filled();
        work.wipe_shares();
        assert!(shares_are_wiped(&work));
        assert!(!work.proof.is_empty());
        assert_eq!(work.secrets.cast_id.token().0, [4; 24]);
    }

    #[test]
    fn guard_wipes_on_take_and_on_drop() {
        let mut work = filled();
        {
            let guard = WorkGuard::take(&mut work);
            assert_eq!(guard.0.option, 0);
            guard.0.option = 5;
        }
        assert_eq!(work.option, 0);
        let mut work = filled();
        drop(WorkGuard(&mut work));
        assert!(work.proof.is_empty());
    }

    #[test]
    fn a_keyed_generator_is_not_empty() {
        let mut work = filled();
        assert!(!rng_is_empty(&mut work.rng));
    }

    #[test]
    fn sizes_follow_the_member_share_formula() {
        assert_eq!(member_share_len(5, false), 222);
        assert_eq!(member_share_len(6, true), 278);
        assert_eq!(MAX_MEMBER_SHARE_LEN, 1942);
        assert_eq!(SCRATCH_SLOT_LEN, 3542);
        assert_eq!(scratch_len(2), 2 * 3542);
        assert_eq!(MODULE_RECORD_MESSAGE_LEN, 140);
        assert_eq!(KEM_CIPHERTEXT_LEN, 1600);
        assert_eq!(
            std::format!("{:?}", BallotWork::default()),
            "BallotWork(..)"
        );
        // Stack guard: no ballot state carries a secret array or the proof;
        // the work area (about 30 KB with seven modules) lives with the
        // caller.
        assert!(core::mem::size_of::<BallotWork>() <= 30 * 1024);
        assert!(core::mem::size_of::<Ballot<'static, 'static, Committed>>() <= 512);
        assert!(core::mem::size_of::<Ballot<'static, 'static, Built<'static>>>() <= 256);
    }
}
