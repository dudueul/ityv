//! The per-ballot typestate (PROTOCOL.md §7.3–§7.7, §8, §9; ADR-0017 §5).
//!
//! ```text
//! OpenBox::interpret ─▶ Interpreted ─issue─▶ Issued ─commit─▶ Committed ─build─▶ Built
//!                                                               Built ─cast─▶ Durable ─imprinted / imprint_failed─▶ Done
//!                                                               Built ─challenge─▶ Challenged
//! ```
//!
//! Each transition consumes the ballot. An imprint command and a slip exist
//! only on [`Durable`], which only [`Ballot::cast`] creates, after the
//! journal sink reported the record and its share package durable
//! (VC-054):
//!
//! ```compile_fail
//! # use ityv_cunit::ballot::{Ballot, Built};
//! fn no_imprint_before_cast(ballot: &Ballot<'_, Built<'_>>) {
//!     let _ = ballot.imprint_command();
//! }
//! ```
//!
//! ```compile_fail
//! # use ityv_cunit::ballot::{Ballot, Built};
//! # use ityv_encoding::TimeBucket;
//! fn no_slip_before_cast(ballot: &Ballot<'_, Built<'_>>, key: &ityv_crypto::HybridSigningKey) {
//!     let mut work = [0u8; 8];
//!     let _ = ballot.slip(key, &[0; 32], TimeBucket::new(0), &mut work);
//! }
//! ```
//!
//! The same calls compile on a durable ballot:
//!
//! ```
//! # use ityv_cunit::ballot::{Ballot, Durable};
//! # use ityv_encoding::TimeBucket;
//! fn after_cast(ballot: &Ballot<'_, Durable<'_>>, key: &ityv_crypto::HybridSigningKey) {
//!     let _ = ballot.imprint_command();
//!     let mut work = [0u8; 8];
//!     let _ = ballot.slip(key, &[0; 32], TimeBucket::new(0), &mut work);
//! }
//! ```
//!
//! Secrets (the module contributions, the cast id, the envelope label, the
//! summed randomness and every member share plaintext) live in zeroizing
//! containers: they are wiped when the ballot reaches a terminal state, on
//! every error path, and when a ballot value is dropped.

use core::fmt;

use ityv_crypto::{
    CastId, ChunkIndex, Commitment, HybridSigningKey, MemberId, Opening, Proof, RecordPurpose,
    RecordSigningKey, Scalar, Statement, encapsulate, object_hash, prove, seal, sign_hybrid,
    sign_record, split,
};
use ityv_encoding::{
    CastRecord, CastRecordBody, CastRecordParts, ChallengeOpening, ChallengeOpeningBody,
    ChallengeOpeningParts, Commitments, Encode, HYBRID_SIG_LEN, Hash512, MAX_CHALLENGE_BODY_LEN,
    MAX_SECRETS, MAX_SLIP_BODY_LEN, MemberShare, ModuleOpening, ModuleRecordSig,
    PROOF_SYSTEM_OR_REP_V1, Point32, SCHEMA_CAST_RECORD, SCHEMA_CAST_RECORD_BODY,
    SCHEMA_CHALLENGE_OPENING, SCHEMA_CHALLENGE_OPENING_BODY, SCHEMA_MEMBER_SHARE,
    SCHEMA_SHARE_PACKAGE, SCHEMA_SLIP, SCHEMA_SLIP_BODY, SCHEMA_VERSION_1, Scalar32, Scalars,
    ShareEntry, SharePackage, Slip, SlipBody, TAG_LEN, TRANSPORT_KEM_FALLBACK,
    TRANSPORT_NEUTRAL_MODULE, TimeBucket, Token192, Transport, Writer, decode_object,
    encode_object,
};
use zeroize::{Zeroize, Zeroizing};

use crate::boxstate::{OpenBox, purpose, write_hybrid};
use crate::config::{
    BallotStyle, ElectionConfig, MAX_MODULES, MAX_TRUSTEES, TrusteeConfig, chamber_code,
};
use crate::error::Error;
use crate::link::{
    Interpretation, JournalKind, MAX_MODULE_ISSUE_LEN, MAX_TAGS, ModuleIssue,
    SCHEMA_INTERPRETATION, SCHEMA_MODULE_ISSUE,
};
use crate::port::{JournalSink, ModulePort, PortError};
use crate::rng::{DeviceRng, LABEL_BALLOT_RNG};
use crate::rules;

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
/// Bytes of a `Slip` object at most, header included.
pub const MAX_SLIP_LEN: usize = 4935;
/// Bytes of a `ChallengeOpening` object at most, header included.
pub const MAX_CHALLENGE_OPENING_LEN: usize = 7445;
/// Bytes of a module record-signature message at most:
/// `body_hash: Hash512 ‖ module_id: Ident<64> ‖ counter: u64`.
pub const MODULE_RECORD_MESSAGE_LEN: usize = 64 + 4 + ityv_encoding::IDENT_MAX_STANDARD + 8;

/// Length of a `MemberShare` object, header included, for `secrets`
/// shares, with an envelope-label contribution when `label`:
/// `16 + (4 + 32·secrets) + 1 + 24 + (1 [+ 24]) + 16`.
#[must_use]
pub const fn member_share_len(secrets: usize, label: bool) -> usize {
    let base = 62usize.saturating_add(secrets.saturating_mul(32));
    if label { base.saturating_add(24) } else { base }
}

/// Scratch bytes [`Ballot::build`] needs for `trustees` trustees: one
/// [`SCRATCH_SLOT_LEN`] slot each plus the proof.
#[must_use]
pub const fn scratch_len(trustees: usize) -> usize {
    trustees
        .saturating_mul(SCRATCH_SLOT_LEN)
        .saturating_add(ityv_encoding::MAX_PROOF_LEN)
}

/// One module's private per-ballot contribution. Wiped on drop.
struct Contribution {
    counter: u64,
    rand: [Scalar; ityv_crypto::MAX_CHUNKS],
    cid: [u8; 24],
    lab: Option<[u8; 24]>,
    tags: [[u8; TAG_LEN]; MAX_TAGS],
}

impl Contribution {
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

impl Contribution {
    /// Overwrites every secret field with zeros.
    fn wipe(&mut self) {
        self.rand.zeroize();
        self.cid.zeroize();
        self.lab.zeroize();
        self.tags.zeroize();
    }
}

impl Drop for Contribution {
    fn drop(&mut self) {
        self.wipe();
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

/// A ballot in state `S`. Only the [`OpenBox`] creates one.
pub struct Ballot<'c, S> {
    config: &'c ElectionConfig<'c>,
    style: &'c BallotStyle<'c>,
    ticket: u64,
    option: ityv_crypto::OptionIndex,
    state: S,
}

impl<S> fmt::Debug for Ballot<'_, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ballot")
            .field("ticket", &self.ticket)
            .finish_non_exhaustive()
    }
}

impl<'c, S> Ballot<'c, S> {
    fn with<T>(self, state: T) -> (Ballot<'c, T>, S) {
        (
            Ballot {
                config: self.config,
                style: self.style,
                ticket: self.ticket,
                option: self.option,
                state,
            },
            self.state,
        )
    }

    /// The ballot style.
    #[must_use]
    pub const fn style(&self) -> &'c BallotStyle<'c> {
        self.style
    }
}

/// Interpreted: the option index is known and in range.
#[derive(Debug)]
pub struct Interpreted(());

/// Issued: every module contributed randomness, a cast-id part, tags.
pub struct Issued {
    contributions: [Contribution; MAX_MODULES],
    rng: DeviceRng,
}

/// Committed: the commitments and the OR proof exist.
pub struct Committed {
    contributions: [Contribution; MAX_MODULES],
    rng: DeviceRng,
    secrets: Zeroizing<Secrets>,
    commitments: Commitments,
    proof: Proof,
}

/// Built: the share package, the record body and the signed record exist
/// in the host's buffers; nothing is journaled yet.
pub struct Built<'b> {
    contributions: [Contribution; MAX_MODULES],
    secrets: Zeroizing<Secrets>,
    record_hash: Hash512,
    package_hash: Hash512,
    package: &'b [u8],
    body: &'b [u8],
    record: &'b [u8],
}

/// Durable: the record and its share package are in the journal.
pub struct Durable<'b> {
    secrets: Zeroizing<Secrets>,
    record_hash: Hash512,
    record: &'b [u8],
}

/// Done: imprinted, or quarantined after an imprint failure.
#[derive(Debug)]
pub struct Done(());

/// Challenged: spoiled by a pre-cast challenge; the opening was published.
#[derive(Debug)]
pub struct Challenged(());

/// What the imprinter prints (PROTOCOL.md §7.3 step 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImprintCommand {
    /// The cast id, printed as digits and a 2-D barcode.
    pub cast_id: [u8; 24],
    /// The envelope label (absentee profile), printed on the sticker.
    pub env_label: Option<[u8; 24]>,
}

/// The host buffers one ballot's objects are written into.
#[derive(Debug)]
pub struct BuildBuffers<'b> {
    /// Ciphertexts and the proof: at least [`scratch_len`] bytes.
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
    /// configured ballot style and an option `0..=m+1` (ITYV-BEH-013).
    ///
    /// # Errors
    /// The decoder's error, [`Error::WrongElection`],
    /// [`Error::UnknownBallotStyle`], [`Error::OptionOutOfRange`],
    /// [`Error::BoxClosed`], [`Error::BallotInFlight`], [`Error::BatchFull`].
    pub fn interpret(&mut self, link: &[u8]) -> Result<Ballot<'c, Interpreted>, Error> {
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
        let option = ityv_crypto::OptionIndex::new(index).ok_or(Error::OptionOutOfRange)?;
        let ticket = self.begin_ballot()?;
        Ok(Ballot {
            config,
            style,
            ticket,
            option,
            state: Interpreted(()),
        })
    }
}

/// Checks one decoded issue against the configuration and stores its
/// private part in `slot`.
fn accept_issue(
    config: &ElectionConfig<'_>,
    style: &BallotStyle<'_>,
    module: &crate::config::ModuleConfig<'_>,
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

impl<'c> Ballot<'c, Interpreted> {
    /// Requests a `ModuleIssue` from every module (PROTOCOL.md §7.3 step 2)
    /// and seeds the ballot generator from `device_seed` and every module's
    /// private contribution. A module counter is recorded as consumed as
    /// soon as the module answers with its own identifier, even if a later
    /// check fails; the ballot then has to be quarantined
    /// ([`OpenBox::quarantine_in_flight`]).
    ///
    /// # Errors
    /// [`Error::PortCount`], port errors, decoding errors,
    /// [`Error::WrongModule`], [`Error::CounterGap`], [`Error::WrongChamber`],
    /// [`Error::ChunkCountMismatch`], [`Error::LabelPresence`],
    /// [`Error::TagCount`], a non-canonical scalar.
    pub fn issue(
        self,
        open_box: &mut OpenBox<'c>,
        ports: &mut [&mut dyn ModulePort],
        device_seed: &[u8; 32],
    ) -> Result<Ballot<'c, Issued>, Error> {
        open_box.check_ticket(self.ticket)?;
        let modules = self.config.modules();
        if ports.len() != modules.len() {
            return Err(Error::PortCount);
        }
        let mut contributions: [Contribution; MAX_MODULES] =
            core::array::from_fn(|_| Contribution::empty());
        let mut buf = Zeroizing::new([0u8; MAX_MODULE_ISSUE_LEN]);
        for (index, ((module, port), slot)) in modules
            .iter()
            .zip(ports.iter_mut())
            .zip(contributions.iter_mut())
            .enumerate()
        {
            buf.zeroize();
            let len = port.issue(buf.as_mut_slice())?;
            let bytes = buf.get(..len).ok_or(Error::BufferTooSmall)?;
            let issue: ModuleIssue<'_> =
                decode_object(SCHEMA_MODULE_ISSUE, SCHEMA_VERSION_1, bytes)?;
            if issue.module_id().as_bytes() != module.module_id().as_bytes() {
                return Err(Error::WrongModule);
            }
            let previous = open_box
                .counters
                .get(index)
                .copied()
                .ok_or(Error::Capacity)?;
            open_box.note_issue(self.ticket, index, issue.counter())?;
            if !rules::counter_follows(previous, issue.counter()) {
                return Err(Error::CounterGap);
            }
            accept_issue(self.config, self.style, module, &issue, slot)?;
        }
        let k = usize::from(self.style.chunk_count());
        let mut hasher = ityv_crypto::Sha3Hasher::new();
        hasher.absorb(LABEL_BALLOT_RNG);
        hasher.absorb(&[0x00]);
        hasher.absorb(device_seed);
        for contribution in contributions.iter().take(modules.len()) {
            for scalar in contribution.rand.iter().take(k) {
                hasher.absorb(&scalar.to_bytes());
            }
            hasher.absorb(&contribution.cid);
            if let Some(lab) = &contribution.lab {
                hasher.absorb(lab);
            }
        }
        let rng = DeviceRng::from_hasher(hasher);
        let (ballot, Interpreted(())) = self.with(Issued { contributions, rng });
        Ok(ballot)
    }
}

/// `SHA3-512(label ‖ 0x00 ‖ parts in module order)[0..24]`.
fn derive_token<'p>(label: &[u8], parts: impl Iterator<Item = &'p [u8; 24]>) -> [u8; 24] {
    let mut hasher = ityv_crypto::Sha3Hasher::new();
    hasher.absorb(label);
    hasher.absorb(&[0x00]);
    for part in parts {
        hasher.absorb(part);
    }
    let mut digest = Zeroizing::new(hasher.finish());
    let mut out = [0u8; 24];
    if let Some((head, _)) = digest.split_first_chunk::<24>() {
        out = *head;
    }
    digest.zeroize();
    out
}

impl<'c> Ballot<'c, Issued> {
    /// Derives the cast id (and the envelope label), sums the randomness,
    /// computes the commitments (PROTOCOL.md §7.4) and the OR proof (§7.5).
    ///
    /// # Errors
    /// [`Error::StaleBallot`] and the cryptographic errors of the proof.
    pub fn commit(self, open_box: &OpenBox<'c>) -> Result<Ballot<'c, Committed>, Error> {
        open_box.check_ticket(self.ticket)?;
        let Ballot {
            config,
            style,
            ticket,
            option,
            state: Issued {
                contributions,
                mut rng,
            },
        } = self;
        let modules = config.modules().len();
        let k = usize::from(style.chunk_count());
        let mut secrets = Zeroizing::new(Secrets {
            cast_id: CastId::new(Token192(derive_token(
                LABEL_CAST_ID,
                contributions.iter().take(modules).map(|c| &c.cid),
            ))),
            env_label: None,
            rand: [Scalar::ZERO; ityv_crypto::MAX_CHUNKS],
        });
        if config.profile().has_label() {
            secrets.env_label = Some(derive_token(
                LABEL_ENVELOPE_LABEL,
                contributions
                    .iter()
                    .take(modules)
                    .filter_map(|c| c.lab.as_ref()),
            ));
        }
        for (j, sum) in secrets.rand.iter_mut().enumerate().take(k) {
            for contribution in contributions.iter().take(modules) {
                let part = contribution.rand.get(j).ok_or(Error::Capacity)?;
                *sum = sum.add(part);
            }
        }
        let bases = open_box.bases();
        let mut points = [Point32([0; 32]); ityv_crypto::MAX_CHUNKS];
        let first_rand = secrets.rand.first().ok_or(Error::Capacity)?;
        let chunk0 = ChunkIndex::new(0).ok_or(Error::Capacity)?;
        let first = ityv_crypto::commit(bases, option, &secrets.cast_id, first_rand, chunk0);
        let mut commitments: [Commitment; ityv_crypto::MAX_CHUNKS] =
            [first; ityv_crypto::MAX_CHUNKS];
        for (j, ((slot, point), rand)) in commitments
            .iter_mut()
            .zip(points.iter_mut())
            .zip(secrets.rand.iter())
            .enumerate()
            .take(k)
        {
            let chunk = ChunkIndex::new(u8::try_from(j).map_err(|_| Error::Capacity)?)
                .ok_or(Error::Capacity)?;
            *slot = ityv_crypto::commit(bases, option, &secrets.cast_id, rand, chunk);
            *point = slot.to_point32();
        }
        let statement = Statement::new(
            config.election_id(),
            config.box_id().ident(),
            style.id().ident(),
            style.option_count(),
            commitments.get(..k).ok_or(Error::Capacity)?,
        )?;
        let opening = Opening::new(option, secrets.cast_id, secrets.rand);
        let proof = prove(bases, &statement, &opening, &mut rng)?;
        drop(opening);
        let encoded =
            Commitments::new(points.get(..k).ok_or(Error::Capacity)?).ok_or(Error::Capacity)?;
        Ok(Ballot {
            config,
            style,
            ticket,
            option,
            state: Committed {
                contributions,
                rng,
                secrets,
                commitments: encoded,
                proof,
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

/// Everything the share transport reads for one ballot.
struct ShareContext<'x, 'c> {
    config: &'x ElectionConfig<'c>,
    commitments: &'x Commitments,
    contributions: &'x [Contribution; MAX_MODULES],
    counters: &'x [u64; MAX_MODULES],
    module_share_len: usize,
    pad_consumption: u64,
}

/// A scalar array wiped on drop.
struct WipedScalars([Scalar32; MAX_SECRETS]);

impl WipedScalars {
    /// Overwrites every scalar with zeros.
    fn wipe(&mut self) {
        for scalar in &mut self.0 {
            scalar.0.zeroize();
        }
    }
}

impl Drop for WipedScalars {
    fn drop(&mut self) {
        self.wipe();
    }
}

/// Writes trustee `trustee`'s `MemberShare` object (ENCODING.md §8.11)
/// into `out`; returns its length and the index of the chamber's module.
fn member_plaintext(
    ctx: &ShareContext<'_, '_>,
    values: &[Scalar],
    trustee: &TrusteeConfig<'_>,
    rng: &DeviceRng,
    out: &mut [u8; MAX_MEMBER_SHARE_LEN],
) -> Result<(usize, Option<usize>), Error> {
    let member = MemberId::new(trustee.chamber(), trustee.member_index()).ok_or(Error::Capacity)?;
    let mut scalars = WipedScalars([Scalar32([0; 32]); MAX_SECRETS]);
    for (index, (value, slot)) in values.iter().zip(scalars.0.iter_mut()).enumerate() {
        let mut stream = rng.fork(
            LABEL_SPLIT,
            u64::try_from(index).map_err(|_| Error::Overflow)?,
        );
        let shares = split(value, ctx.config.access(), &mut stream);
        slot.0 = shares.value(member).to_bytes();
    }
    let set = Scalars::<MAX_SECRETS>::new(scalars.0.get(..values.len()).ok_or(Error::Capacity)?)
        .ok_or(Error::Capacity)?;
    let module = ctx
        .config
        .module_for(trustee.chamber())
        .map(|(index, _)| index);
    let (has_module, cid, lab, tag) = match module {
        Some(index) => {
            let contribution = ctx.contributions.get(index).ok_or(Error::Capacity)?;
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
        out.as_mut_slice(),
    )?;
    Ok((len, module))
}

/// The associated data of a KEM entry (PROTOCOL.md §9.6, with the package's
/// commitments standing for the record hash, which depends on the package).
fn kem_aad(
    ctx: &ShareContext<'_, '_>,
    trustee: &TrusteeConfig<'_>,
    out: &mut [u8; 512],
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

/// Seals `plaintext` for `trustee` into `slot`: through the chamber's
/// module pad when it has one (checking the pad identifier and that the pad
/// index is `counter × b`, VC-034), otherwise or when the pad is exhausted
/// with the hybrid KEM. Returns the entry and whether the KEM was a
/// fallback for an exhausted pad.
fn seal_entry(
    ctx: &ShareContext<'_, '_>,
    trustee: &TrusteeConfig<'_>,
    module: Option<usize>,
    plaintext: &[u8],
    slot: &mut [u8],
    ports: &mut [&mut dyn ModulePort],
    rng: &mut DeviceRng,
) -> Result<(EntryMeta, bool), Error> {
    let len = plaintext.len();
    let mut fallback = false;
    if let Some(index) = module {
        if len != ctx.module_share_len {
            return Err(Error::Overflow);
        }
        let counter = ctx.counters.get(index).copied().ok_or(Error::Capacity)?;
        let dst = slot.get_mut(..len).ok_or(Error::BufferTooSmall)?;
        dst.copy_from_slice(plaintext);
        let port = ports.get_mut(index).ok_or(Error::PortCount)?;
        match port.seal_member(trustee.member_index(), dst) {
            Ok(sealed) => {
                let expected =
                    rules::pad_index(counter, ctx.pad_consumption).ok_or(Error::Overflow)?;
                if sealed.pad_id != trustee.pad_id() {
                    dst.zeroize();
                    return Err(Error::PadIdMismatch);
                }
                if sealed.pad_index != expected {
                    dst.zeroize();
                    return Err(Error::PadIndexMismatch);
                }
                let transport = Transport::Pad {
                    pad_id: sealed.pad_id,
                    pad_index: sealed.pad_index,
                };
                return Ok((
                    EntryMeta {
                        len,
                        transport,
                        tag: sealed.tag,
                    },
                    false,
                ));
            }
            Err(PortError::Exhausted) => {
                dst.zeroize();
                fallback = true;
            }
            Err(error) => {
                dst.zeroize();
                return Err(error.into());
            }
        }
    }
    let (ciphertext, key) = encapsulate(trustee.kem_public_key(), rng)?;
    let (head, rest) = slot
        .split_at_mut_checked(KEM_CIPHERTEXT_LEN)
        .ok_or(Error::BufferTooSmall)?;
    let mut w = Writer::new(head);
    ciphertext.encode(&mut w)?;
    if w.finish() != KEM_CIPHERTEXT_LEN {
        return Err(Error::Overflow);
    }
    let dst = rest.get_mut(..len).ok_or(Error::BufferTooSmall)?;
    dst.copy_from_slice(plaintext);
    let mut aad = [0u8; 512];
    let aad_len = kem_aad(ctx, trustee, &mut aad)?;
    let tag = match seal(key, aad.get(..aad_len).unwrap_or(&[]), dst) {
        Ok(tag) => tag,
        Err(error) => {
            dst.zeroize();
            return Err(error.into());
        }
    };
    let total = KEM_CIPHERTEXT_LEN.checked_add(len).ok_or(Error::Overflow)?;
    Ok((
        EntryMeta {
            len: total,
            transport: Transport::Kem,
            tag: *tag.as_bytes(),
        },
        fallback,
    ))
}

/// The secrets every member receives a share of, in the `MemberShare`
/// order: each module's `r_{c,0..k−1}` in module order, the cast id, the
/// envelope label.
fn secret_values(
    config: &ElectionConfig<'_>,
    style: &BallotStyle<'_>,
    contributions: &[Contribution; MAX_MODULES],
    secrets: &Secrets,
) -> Result<(Zeroizing<[Scalar; MAX_SECRETS]>, usize), Error> {
    let k = usize::from(style.chunk_count());
    let mut values = Zeroizing::new([Scalar::ZERO; MAX_SECRETS]);
    let mut n = 0usize;
    let mut push = |value: Scalar| -> Result<(), Error> {
        *values
            .get_mut(n)
            .ok_or(Error::Config(crate::error::ConfigFault::SecretCapacity))? = value;
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
    Ok((values, n))
}

/// Seals every trustee's member share into its scratch slot.
fn seal_all(
    ctx: &ShareContext<'_, '_>,
    values: &[Scalar],
    ports: &mut [&mut dyn ModulePort],
    rng: &mut DeviceRng,
    ct_region: &mut [u8],
) -> Result<([EntryMeta; MAX_TRUSTEES], u8), Error> {
    let mut flags = if ctx.config.uses_neutral_module() {
        TRANSPORT_NEUTRAL_MODULE
    } else {
        0
    };
    let mut metas = [EMPTY_META; MAX_TRUSTEES];
    let mut plaintext = Zeroizing::new([0u8; MAX_MEMBER_SHARE_LEN]);
    for ((trustee, slot), meta) in ctx
        .config
        .trustees()
        .iter()
        .zip(ct_region.chunks_exact_mut(SCRATCH_SLOT_LEN))
        .zip(metas.iter_mut())
    {
        let (len, module) = member_plaintext(ctx, values, trustee, rng, &mut plaintext)?;
        let text = plaintext.get(..len).ok_or(Error::BufferTooSmall)?;
        let (entry, fallback) = seal_entry(ctx, trustee, module, text, slot, ports, rng)?;
        plaintext.zeroize();
        *meta = entry;
        if fallback {
            flags |= TRANSPORT_KEM_FALLBACK;
        }
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
/// module Ed25519 over `body_hash ‖ module_id ‖ counter`) and writes the
/// `CastRecord` object (ENCODING.md §8.7).
fn sign_and_wrap<'b>(
    config: &ElectionConfig<'_>,
    counters: &[u64; MAX_MODULES],
    ports: &mut [&mut dyn ModulePort],
    device_key: &RecordSigningKey,
    body: &'b [u8],
    record_hash: &Hash512,
    out: &'b mut [u8],
) -> Result<&'b [u8], Error> {
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
        let sig = port.sign_record(message.get(..len).ok_or(Error::BufferTooSmall)?)?;
        *slot = *sig.as_bytes();
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

/// Writes the proof's canonical encoding (PROTOCOL.md §7.5) into `region`.
fn encode_proof<'b>(proof: &Proof, region: &'b mut [u8]) -> Result<&'b [u8], Error> {
    let mut w = Writer::new(region);
    proof.encode(&mut w)?;
    let len = w.finish();
    let written: &'b [u8] = region;
    written.get(..len).ok_or(Error::BufferTooSmall)
}

impl<'c> Ballot<'c, Committed> {
    /// Builds every object of the ballot into the host's buffers
    /// (PROTOCOL.md §7.3 steps 4–5, §9): the member shares of every secret,
    /// sealed through the module pads or the KEM; the `SharePackage`; the
    /// `CastRecordBody` naming the package hash; the device and module
    /// record signatures; the `CastRecord`. Nothing is journaled yet.
    ///
    /// # Errors
    /// [`Error::StaleBallot`], [`Error::PortCount`],
    /// [`Error::BufferTooSmall`], [`Error::PadIdMismatch`],
    /// [`Error::PadIndexMismatch`], port, cryptographic and encoding errors.
    pub fn build<'b>(
        self,
        open_box: &OpenBox<'c>,
        ports: &mut [&mut dyn ModulePort],
        device_key: &RecordSigningKey,
        buffers: BuildBuffers<'b>,
    ) -> Result<Ballot<'c, Built<'b>>, Error> {
        let flight = open_box.check_ticket(self.ticket)?;
        let Ballot {
            config,
            style,
            ticket,
            option,
            state:
                Committed {
                    contributions,
                    mut rng,
                    secrets,
                    commitments,
                    proof,
                },
        } = self;
        if ports.len() != config.modules().len() {
            return Err(Error::PortCount);
        }
        let BuildBuffers {
            scratch,
            package,
            body,
            record,
        } = buffers;
        let ct_len = config
            .trustees()
            .len()
            .checked_mul(SCRATCH_SLOT_LEN)
            .ok_or(Error::Overflow)?;
        let (ct_region, proof_region) = scratch
            .split_at_mut_checked(ct_len)
            .ok_or(Error::BufferTooSmall)?;
        let proof_bytes = encode_proof(&proof, proof_region)?;

        let (values, n_values) = secret_values(config, style, &contributions, &secrets)?;
        let module_share_len = member_share_len(n_values, config.profile().has_label());
        let ctx = ShareContext {
            config,
            commitments: &commitments,
            contributions: &contributions,
            counters: &flight.counters,
            module_share_len,
            pad_consumption: rules::pad_consumption(module_share_len).ok_or(Error::Overflow)?,
        };
        let values_used = values.get(..n_values).ok_or(Error::Capacity)?;
        let (metas, flags) = seal_all(&ctx, values_used, ports, &mut rng, ct_region)?;
        drop(values);
        let ciphertexts: &'b [u8] = ct_region;
        let package = write_package(config, &commitments, &metas, ciphertexts, package)?;
        let package_hash = object_hash(package);

        let module_counters = open_box
            .counter_list(&flight.counters, flight.issued)?
            .ok_or(Error::Capacity)?;
        let body_object = CastRecordBody::new(&CastRecordParts {
            election_id: config.election_id(),
            box_id: config.box_id(),
            ballot_style_id: style.id(),
            proof_system_id: PROOF_SYSTEM_OR_REP_V1,
            commitments,
            proof: proof_bytes,
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
        let record = sign_and_wrap(
            config,
            &flight.counters,
            ports,
            device_key,
            body,
            &record_hash,
            record,
        )?;
        Ok(Ballot {
            config,
            style,
            ticket,
            option,
            state: Built {
                contributions,
                secrets,
                record_hash,
                package_hash,
                package,
                body,
                record,
            },
        })
    }
}

impl<'c, 'b> Ballot<'c, Built<'b>> {
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

    /// Casts the ballot (PROTOCOL.md §7.3 step 7): appends the record entry
    /// with its share package to the journal and only then returns the
    /// [`Durable`] ballot that can imprint (VC-054). On a journal error the
    /// ballot is consumed and must be quarantined with
    /// [`OpenBox::quarantine_in_flight`]; the paper goes to the quarantine
    /// envelope.
    ///
    /// # Errors
    /// [`Error::StaleBallot`], [`Error::TimeRegression`], the journal's error.
    pub fn cast(
        self,
        open_box: &mut OpenBox<'c>,
        sink: &mut dyn JournalSink,
        time_bucket: TimeBucket,
    ) -> Result<Ballot<'c, Durable<'b>>, Error> {
        let flight = open_box.check_ticket(self.ticket)?;
        open_box.journal(
            sink,
            JournalKind::Record,
            self.state.record_hash,
            self.state.package_hash,
            &flight.counters,
            flight.issued,
            time_bucket,
            Some(self.state.package),
        )?;
        open_box.push_record(self.state.record_hash, time_bucket)?;
        let Ballot {
            config,
            style,
            ticket,
            option,
            state:
                Built {
                    secrets,
                    record_hash,
                    record,
                    ..
                },
        } = self;
        Ok(Ballot {
            config,
            style,
            ticket,
            option,
            state: Durable {
                secrets,
                record_hash,
                record,
            },
        })
    }

    /// Writes the `ChallengeOpening` object (PROTOCOL.md §8) into `work`
    /// and returns its length.
    fn write_opening(
        &self,
        device_key: &HybridSigningKey,
        signing_seed: &[u8; 32],
        work: &mut [u8],
    ) -> Result<usize, Error> {
        let k = usize::from(self.style.chunk_count());
        let secrets = &self.state.secrets;
        let mut rand32 = [Scalar32([0; 32]); ityv_crypto::MAX_CHUNKS];
        for (dst, src) in rand32.iter_mut().zip(secrets.rand.iter()).take(k) {
            dst.0 = src.to_bytes();
        }
        let rand = Scalars::new(rand32.get(..k).ok_or(Error::Capacity)?).ok_or(Error::Capacity)?;
        let modules = self.config.modules();
        let first = modules.first().ok_or(Error::Capacity)?;
        let mut openings = [ModuleOpening {
            module_id: first.module_id(),
            counter: 0,
            rand,
            cid: Token192([0; 24]),
        }; MAX_MODULES];
        for ((slot, module), contribution) in openings
            .iter_mut()
            .zip(modules)
            .zip(&self.state.contributions)
        {
            let mut module_rand = [Scalar32([0; 32]); ityv_crypto::MAX_CHUNKS];
            for (dst, src) in module_rand.iter_mut().zip(contribution.rand.iter()).take(k) {
                dst.0 = src.to_bytes();
            }
            *slot = ModuleOpening {
                module_id: module.module_id(),
                counter: contribution.counter,
                rand: Scalars::new(module_rand.get(..k).ok_or(Error::Capacity)?)
                    .ok_or(Error::Capacity)?,
                cid: Token192(contribution.cid),
            };
        }
        let body = ChallengeOpeningBody::new(&ChallengeOpeningParts {
            election_id: self.config.election_id(),
            box_id: self.config.box_id(),
            ballot_style_id: self.style.id(),
            record_hash: self.state.record_hash,
            option_index: self.option.get(),
            cast_id: secrets.cast_id.token(),
            rand: &rand,
            modules: openings.get(..modules.len()).ok_or(Error::Capacity)?,
        })
        .ok_or(Error::Capacity)?;
        let mut body_buf = [0u8; MAX_CHALLENGE_BODY_LEN];
        let body_len = encode_object(
            SCHEMA_CHALLENGE_OPENING_BODY,
            SCHEMA_VERSION_1,
            &body,
            &mut body_buf,
        )?;
        let body_bytes = body_buf.get(..body_len).ok_or(Error::BufferTooSmall)?;
        let sig = sign_hybrid(
            device_key,
            &purpose(PURPOSE_CHALLENGE)?,
            body_bytes,
            &mut DeviceRng::for_signing(signing_seed),
        )?;
        let mut sig_bytes = [0u8; HYBRID_SIG_LEN];
        write_hybrid(&sig, &mut sig_bytes)?;
        let opening = ChallengeOpening::new(body_bytes, &sig_bytes)?;
        Ok(encode_object(
            SCHEMA_CHALLENGE_OPENING,
            SCHEMA_VERSION_1,
            &opening,
            work,
        )?)
    }

    /// Spoils the ballot by a pre-cast challenge (PROTOCOL.md §8): writes
    /// the signed `ChallengeOpening` into `work`, then journals the
    /// challenge (kind 2). If the journal fails, `work` is wiped and nothing
    /// is returned.
    ///
    /// # Errors
    /// [`Error::StaleBallot`], signing, encoding and journal errors.
    pub fn challenge<'w>(
        self,
        open_box: &mut OpenBox<'c>,
        sink: &mut dyn JournalSink,
        device_key: &HybridSigningKey,
        signing_seed: &[u8; 32],
        time_bucket: TimeBucket,
        work: &'w mut [u8],
    ) -> Result<(Ballot<'c, Challenged>, &'w [u8]), Error> {
        let flight = open_box.check_ticket(self.ticket)?;
        let len = self.write_opening(device_key, signing_seed, work)?;
        if let Err(error) = open_box.journal(
            sink,
            JournalKind::Challenge,
            self.state.record_hash,
            Hash512::ZERO,
            &flight.counters,
            flight.issued,
            time_bucket,
            None,
        ) {
            work.zeroize();
            return Err(error);
        }
        open_box.totals.challenged = open_box
            .totals
            .challenged
            .checked_add(1)
            .ok_or(Error::Overflow)?;
        open_box.end_ballot(self.ticket)?;
        let (ballot, _spoiled) = self.with(Challenged(()));
        let written: &'w [u8] = work;
        Ok((ballot, written.get(..len).ok_or(Error::BufferTooSmall)?))
    }
}

impl<'c, 'b> Ballot<'c, Durable<'b>> {
    /// The tracking code.
    #[must_use]
    pub const fn tracking_code(&self) -> &Hash512 {
        &self.state.record_hash
    }

    /// The `CastRecord` object.
    #[must_use]
    pub const fn record_bytes(&self) -> &'b [u8] {
        self.state.record
    }

    /// What the imprinter prints. Exists only after the journal write.
    #[must_use]
    pub fn imprint_command(&self) -> ImprintCommand {
        ImprintCommand {
            cast_id: self.state.secrets.cast_id.token().0,
            env_label: self.state.secrets.env_label,
        }
    }

    /// Writes the signed `Slip` object (PROTOCOL.md §7.7) into `work`.
    ///
    /// # Errors
    /// [`Error::VoterCodeDisabled`], signing and encoding errors.
    pub fn slip<'w>(
        &self,
        device_key: &HybridSigningKey,
        signing_seed: &[u8; 32],
        time_bucket: TimeBucket,
        work: &'w mut [u8],
    ) -> Result<&'w [u8], Error> {
        if !self.config.voter_code_enabled() {
            return Err(Error::VoterCodeDisabled);
        }
        let body = SlipBody::new(
            self.config.election_id(),
            self.config.station_id(),
            time_bucket,
            self.state.record_hash,
        );
        let mut body_buf = [0u8; MAX_SLIP_BODY_LEN];
        let body_len = encode_object(SCHEMA_SLIP_BODY, SCHEMA_VERSION_1, &body, &mut body_buf)?;
        let body_bytes = body_buf.get(..body_len).ok_or(Error::BufferTooSmall)?;
        let sig = sign_hybrid(
            device_key,
            &purpose(PURPOSE_SLIP)?,
            body_bytes,
            &mut DeviceRng::for_signing(signing_seed),
        )?;
        let mut sig_bytes = [0u8; HYBRID_SIG_LEN];
        write_hybrid(&sig, &mut sig_bytes)?;
        let slip = Slip::new(body_bytes, &sig_bytes)?;
        let len = encode_object(SCHEMA_SLIP, SCHEMA_VERSION_1, &slip, work)?;
        let written: &'w [u8] = work;
        written.get(..len).ok_or(Error::BufferTooSmall)
    }

    /// The imprinter printed the cast id and the paper dropped into the box.
    ///
    /// # Errors
    /// [`Error::StaleBallot`].
    pub fn imprinted(self, open_box: &mut OpenBox<'c>) -> Result<Ballot<'c, Done>, Error> {
        open_box.end_ballot(self.ticket)?;
        Ok(self.with(Done(())).0)
    }

    /// The imprint failed (PROTOCOL.md §7.3 step 8, VC-023): journals a
    /// quarantine entry naming the record, withdraws the record from the
    /// open batch and counts the ballot as quarantined.
    ///
    /// # Errors
    /// [`Error::StaleBallot`], the journal's error.
    pub fn imprint_failed(
        self,
        open_box: &mut OpenBox<'c>,
        sink: &mut dyn JournalSink,
        time_bucket: TimeBucket,
    ) -> Result<Ballot<'c, Done>, Error> {
        let flight = open_box.check_ticket(self.ticket)?;
        open_box.journal(
            sink,
            JournalKind::Quarantine,
            self.state.record_hash,
            Hash512::ZERO,
            &flight.counters,
            flight.issued,
            time_bucket,
            None,
        )?;
        open_box.withdraw_record(&self.state.record_hash)?;
        open_box.totals.quarantined = open_box
            .totals
            .quarantined
            .checked_add(1)
            .ok_or(Error::Overflow)?;
        open_box.end_ballot(self.ticket)?;
        Ok(self.with(Done(())).0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contribution_wipe_clears_every_secret_field() {
        let mut c = Contribution {
            counter: 3,
            rand: [Scalar::from_u64(5); ityv_crypto::MAX_CHUNKS],
            cid: [7; 24],
            lab: Some([8; 24]),
            tags: [[9; TAG_LEN]; MAX_TAGS],
        };
        c.wipe();
        assert!(c.rand.iter().all(Scalar::is_zero));
        assert_eq!(c.cid, [0; 24]);
        assert!(c.lab.is_none());
        assert_eq!(c.tags, [[0; TAG_LEN]; MAX_TAGS]);
        assert_eq!(c.counter, 3, "the counter is public");
    }

    #[test]
    fn secrets_zeroize_clears_every_field() {
        let mut s = Secrets {
            cast_id: CastId::new(Token192([4; 24])),
            env_label: Some([6; 24]),
            rand: [Scalar::from_u64(9); ityv_crypto::MAX_CHUNKS],
        };
        s.zeroize();
        assert_eq!(s.cast_id.token().0, [0; 24]);
        assert!(s.env_label.is_none());
        assert!(s.rand.iter().all(Scalar::is_zero));
    }

    #[test]
    fn wiped_scalars_wipe_clears_every_scalar() {
        let mut w = WipedScalars([Scalar32([1; 32]); MAX_SECRETS]);
        w.wipe();
        assert!(w.0.iter().all(|s| s.0 == [0; 32]));
    }

    #[test]
    fn sizes_follow_the_member_share_formula() {
        assert_eq!(member_share_len(5, false), 222);
        assert_eq!(member_share_len(6, true), 278);
        assert_eq!(MAX_MEMBER_SHARE_LEN, 1686);
        assert_eq!(SCRATCH_SLOT_LEN, 3286);
        assert_eq!(scratch_len(2), 2 * 3286 + 20_483);
        assert_eq!(MODULE_RECORD_MESSAGE_LEN, 140);
        assert_eq!(KEM_CIPHERTEXT_LEN, 1600);
    }
}
