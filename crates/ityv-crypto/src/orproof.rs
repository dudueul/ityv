//! The 1-of-(m+2) OR proof of representation (PROTOCOL.md §7.5).
//!
//! Statement: for commitments `C_0..C_{k−1}` there exist `t ∈ [0, m+2)` and
//! `(x, y_0..y_{k−1})` such that for every chunk `j`,
//! `C_j − val_j(t)·G_val = x·G_id + y_j·H`. The proof is a Fiat-Shamir
//! transformed Σ-protocol with one simulated branch per wrong option and one
//! real branch, with perfect witness indistinguishability (every branch has
//! the same distribution), which the everlasting-privacy argument needs.
//!
//! # Transcript byte layout
//!
//! The challenge is `fiat_shamir_challenge("ityv:proof:or-rep:v1", transcript)`
//! where `transcript` is the canonical fixed-width encoding (ENCODING.md) of,
//! in order:
//!
//! 1. `election_id`: `u32` length ‖ bytes (at most 64)
//! 2. `box_id`: `u32` length ‖ bytes (at most 64)
//! 3. `ballot_style_id`: `u32` length ‖ bytes (at most 64)
//! 4. `proof_system_id: u16`
//! 5. `option_count: u16` (`m + 2`)
//! 6. `chunk_count: u8` (`k`)
//! 7. `commitments`: `u32` count (`k`) ‖ `k` compressed points
//! 8. `announcements`: `u32` count (`(m+2)·k`) ‖ the points `a_{t,j}` for
//!    `t = 0..m+2`, `j = 0..k` (`t` outer, `j` inner)
//!
//! All integers are big-endian. The counts in items 5–8 make the split
//! between commitments and announcements unambiguous.
//!
//! # Proof encoding
//!
//! A 3-byte header followed by `(m+2)·(k+2)` scalars:
//!
//! | offset | width | field |
//! |---|---|---|
//! | 0 | 2 | `option_count` (`m + 2`), big-endian `u16`, `1..=64` |
//! | 2 | 1 | `chunk_count` (`k`), `u8`, must equal `⌈option_count / 9⌉` |
//! | 3 | `32·(k+2)` per option | for `t = 0..m+2`: `c_t` ‖ `z_{t,x}` ‖ `z_{t,0}` ‖ … ‖ `z_{t,k−1}` |
//!
//! Every scalar is 32 bytes little-endian and must be canonical (below the
//! group order). The decoder rejects a header whose chunk count does not
//! match its option count, because no statement could ever verify such a
//! proof (ENCODING.md §1.2). Total length `3 + (m+2)·(64 + 32k)`.

use core::fmt;

use ityv_encoding::{
    Decode, ElectionId, Encode, Error as EncodingError, ErrorKind, IDENT_MAX_STANDARD, Ident,
    Reader, Writer,
};
use rand_core::CryptoRng;
use subtle::{ConditionallySelectable, ConstantTimeEq, ConstantTimeGreater};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::backend::ristretto::Point;
use crate::commit::{
    Bases, ChunkIndex, Commitment, MAX_CHUNKS, MAX_OPTIONS, Opening, OptionCount, OptionIndex,
    packed_value, verify_opening,
};
use crate::error::Error;
use crate::hash::Transcript;
use crate::scalar::Scalar;
use crate::verified::Verified;

/// Fiat-Shamir label of this proof system.
pub const FS_LABEL_OR_REP_V1: &[u8] = b"ityv:proof:or-rep:v1";
/// Numeric identifier of this proof system in cast records.
pub const PROOF_SYSTEM_OR_REP_V1: u16 = 1;

/// Capacity of one identifier field in the transcript: `u32` prefix plus
/// the standard maximum identifier length.
const IDENT_FIELD_MAX_LEN: usize = IDENT_MAX_STANDARD + 4;

/// Length of an identifier field in the transcript: `u32` prefix plus bytes.
fn ident_field_len(ident: &Ident<'_>) -> usize {
    ident.byte_len().saturating_add(4)
}

/// Absorbs an identifier as its canonical length-prefixed encoding.
fn absorb_ident(transcript: &mut Transcript, ident: &Ident<'_>) -> Result<(), Error> {
    let mut buffer = [0u8; IDENT_FIELD_MAX_LEN];
    let mut writer = Writer::new(&mut buffer);
    writer.write_ident(ident, IDENT_MAX_STANDARD)?;
    let written = writer.finish();
    let bytes = buffer.get(..written).ok_or(Error::CapacityExceeded)?;
    transcript.absorb(bytes);
    Ok(())
}

/// Absorbs a big-endian `u32` count.
fn absorb_count(transcript: &mut Transcript, count: usize) -> Result<(), Error> {
    let raw = u32::try_from(count).map_err(|_| Error::CapacityExceeded)?;
    transcript.absorb(&raw.to_be_bytes());
    Ok(())
}

/// The public statement of one record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Statement<'a> {
    election_id: ElectionId<'a>,
    box_id: Ident<'a>,
    ballot_style_id: Ident<'a>,
    proof_system_id: u16,
    option_count: OptionCount,
    commitments: [Commitment; MAX_CHUNKS],
}

impl<'a> Statement<'a> {
    /// Builds a statement for `commitments` (chunk `j` at index `j`) with
    /// the option set `option_count` (`m + 2` options).
    ///
    /// # Errors
    /// [`Error::InvalidStatement`] if an identifier is longer than 64 bytes
    /// or the number of commitments is not the chunk count of
    /// `option_count`.
    pub fn new(
        election_id: ElectionId<'a>,
        box_id: Ident<'a>,
        ballot_style_id: Ident<'a>,
        option_count: OptionCount,
        commitments: &[Commitment],
    ) -> Result<Self, Error> {
        if box_id.byte_len() > IDENT_MAX_STANDARD || ballot_style_id.byte_len() > IDENT_MAX_STANDARD
        {
            return Err(Error::InvalidStatement);
        }
        if commitments.len() != usize::from(option_count.chunk_count()) {
            return Err(Error::InvalidStatement);
        }
        let mut stored = [Commitment::from_point(&Point::identity()); MAX_CHUNKS];
        for (slot, commitment) in stored.iter_mut().zip(commitments.iter()) {
            *slot = *commitment;
        }
        Ok(Self {
            election_id,
            box_id,
            ballot_style_id,
            proof_system_id: PROOF_SYSTEM_OR_REP_V1,
            option_count,
            commitments: stored,
        })
    }

    /// The election identifier.
    #[must_use]
    pub const fn election_id(&self) -> ElectionId<'a> {
        self.election_id
    }

    /// The box identifier.
    #[must_use]
    pub const fn box_id(&self) -> Ident<'a> {
        self.box_id
    }

    /// The ballot style identifier.
    #[must_use]
    pub const fn ballot_style_id(&self) -> Ident<'a> {
        self.ballot_style_id
    }

    /// The proof system identifier.
    #[must_use]
    pub const fn proof_system_id(&self) -> u16 {
        self.proof_system_id
    }

    /// The option set (`m + 2`).
    #[must_use]
    pub const fn option_count(&self) -> OptionCount {
        self.option_count
    }

    /// `k`.
    #[must_use]
    pub fn chunk_count(&self) -> u8 {
        self.option_count.chunk_count()
    }

    /// The commitments `C_0..C_{k−1}`.
    #[must_use]
    pub fn commitments(&self) -> &[Commitment] {
        self.commitments
            .get(..usize::from(self.chunk_count()))
            .unwrap_or(&[])
    }

    fn announcement_count(&self) -> usize {
        usize::from(self.option_count.get()).saturating_mul(usize::from(self.chunk_count()))
    }

    /// Total transcript length in bytes (see the module documentation).
    fn transcript_len(&self) -> usize {
        ident_field_len(&self.election_id.ident())
            .saturating_add(ident_field_len(&self.box_id))
            .saturating_add(ident_field_len(&self.ballot_style_id))
            .saturating_add(2) // proof_system_id
            .saturating_add(2) // option_count
            .saturating_add(1) // chunk_count
            .saturating_add(4) // commitment count
            .saturating_add(usize::from(self.chunk_count()).saturating_mul(32))
            .saturating_add(4) // announcement count
            .saturating_add(self.announcement_count().saturating_mul(32))
    }

    /// Absorbs items 1–7 and the announcement count of item 8.
    fn absorb_header(&self, transcript: &mut Transcript) -> Result<(), Error> {
        absorb_ident(transcript, &self.election_id.ident())?;
        absorb_ident(transcript, &self.box_id)?;
        absorb_ident(transcript, &self.ballot_style_id)?;
        transcript.absorb(&self.proof_system_id.to_be_bytes());
        transcript.absorb(&self.option_count.get().to_be_bytes());
        transcript.absorb(&[self.chunk_count()]);
        absorb_count(transcript, usize::from(self.chunk_count()))?;
        for commitment in self.commitments() {
            transcript.absorb(commitment.as_bytes());
        }
        absorb_count(transcript, self.announcement_count())
    }

    /// Decompressed commitments; unused slots hold the identity.
    fn points(&self) -> Result<[Point; MAX_CHUNKS], Error> {
        let mut points = [Point::identity(); MAX_CHUNKS];
        for (point, commitment) in points.iter_mut().zip(self.commitments()) {
            *point = commitment.point()?;
        }
        Ok(points)
    }
}

/// A proof: `(m+2)·(k+2)` scalars. Unused slots are zero.
#[derive(Clone, PartialEq, Eq)]
pub struct Proof {
    option_count: OptionCount,
    challenges: [Scalar; MAX_OPTIONS],
    resp_id: [Scalar; MAX_OPTIONS],
    resp_rand: [[Scalar; MAX_CHUNKS]; MAX_OPTIONS],
}

impl Proof {
    /// The empty proof: one option, every scalar zero. Evaluated at compile
    /// time, so a caller can keep a proof in its own memory (a `static`, a
    /// work area) and let [`prove_into`] overwrite it in place.
    pub const EMPTY: Self = Self {
        option_count: OptionCount::ONE,
        challenges: [Scalar::ZERO; MAX_OPTIONS],
        resp_id: [Scalar::ZERO; MAX_OPTIONS],
        resp_rand: [[Scalar::ZERO; MAX_CHUNKS]; MAX_OPTIONS],
    };

    /// Resets the proof in place to the empty proof of `option_count`.
    fn reset(&mut self, option_count: OptionCount) {
        self.option_count = option_count;
        self.challenges.fill(Scalar::ZERO);
        self.resp_id.fill(Scalar::ZERO);
        for row in &mut self.resp_rand {
            row.fill(Scalar::ZERO);
        }
    }

    /// Resets the proof in place to [`Self::EMPTY`].
    pub fn clear(&mut self) {
        self.reset(Self::EMPTY.option_count);
    }

    /// `true` if the proof is [`Self::EMPTY`] (one option, every scalar
    /// zero).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.option_count == OptionCount::ONE
            && self
                .challenges
                .iter()
                .chain(self.resp_id.iter())
                .chain(self.resp_rand.iter().flatten())
                .all(Scalar::is_zero)
    }

    /// The option set (`m + 2`).
    #[must_use]
    pub const fn option_count(&self) -> OptionCount {
        self.option_count
    }

    /// `k`, derived from the option set.
    #[must_use]
    pub fn chunk_count(&self) -> u8 {
        self.option_count.chunk_count()
    }

    /// `c_t`.
    #[must_use]
    pub fn challenge(&self, option: OptionIndex) -> Option<&Scalar> {
        self.challenges.get(usize::from(option.get()))
    }

    /// `z_{t,x}`.
    #[must_use]
    pub fn response_id(&self, option: OptionIndex) -> Option<&Scalar> {
        self.resp_id.get(usize::from(option.get()))
    }

    /// `z_{t,j}`.
    #[must_use]
    pub fn response_rand(&self, option: OptionIndex, chunk: ChunkIndex) -> Option<&Scalar> {
        self.resp_rand
            .get(usize::from(option.get()))
            .and_then(|row| row.get(usize::from(chunk.get())))
    }

    /// Encoded length for an option set: `3 + (m+2)·(64 + 32k)`.
    #[must_use]
    pub fn encoded_len_for(option_count: OptionCount) -> usize {
        let per_option = usize::from(option_count.chunk_count())
            .saturating_mul(Scalar::LEN)
            .saturating_add(Scalar::LEN.saturating_mul(2));
        usize::from(option_count.get())
            .saturating_mul(per_option)
            .saturating_add(3)
    }
}

impl fmt::Debug for Proof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Proof")
            .field("option_count", &self.option_count)
            .finish_non_exhaustive()
    }
}

impl Encode for Proof {
    fn encoded_len(&self) -> usize {
        Self::encoded_len_for(self.option_count)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodingError> {
        w.write_u16(self.option_count.get())?;
        w.write_u8(self.chunk_count())?;
        let options = usize::from(self.option_count.get());
        let chunks = usize::from(self.chunk_count());
        let rows = self
            .challenges
            .iter()
            .zip(self.resp_id.iter())
            .zip(self.resp_rand.iter())
            .take(options);
        for ((challenge, resp_id), resp_rand) in rows {
            challenge.encode(w)?;
            resp_id.encode(w)?;
            for scalar in resp_rand.iter().take(chunks) {
                scalar.encode(w)?;
            }
        }
        Ok(())
    }
}

impl<'a> Decode<'a> for Proof {
    fn decode(r: &mut Reader<'a>) -> Result<Self, EncodingError> {
        let at = r.position();
        let option_count = OptionCount::new(r.read_u16()?)
            .ok_or_else(|| EncodingError::new(ErrorKind::CountExceedsMax, at))?;
        let at = r.position();
        let chunk_count = r.read_u8()?;
        if chunk_count == 0 || usize::from(chunk_count) > MAX_CHUNKS {
            return Err(EncodingError::new(ErrorKind::CountExceedsMax, at));
        }
        if chunk_count != option_count.chunk_count() {
            return Err(EncodingError::new(ErrorKind::InvariantViolation, at));
        }
        let mut proof = Self::EMPTY;
        proof.reset(option_count);
        let options = usize::from(option_count.get());
        let chunks = usize::from(chunk_count);
        let rows = proof
            .challenges
            .iter_mut()
            .zip(proof.resp_id.iter_mut())
            .zip(proof.resp_rand.iter_mut())
            .take(options);
        for ((challenge, resp_id), resp_rand) in rows {
            *challenge = Scalar::decode(r)?;
            *resp_id = Scalar::decode(r)?;
            for scalar in resp_rand.iter_mut().take(chunks) {
                *scalar = Scalar::decode(r)?;
            }
        }
        Ok(proof)
    }
}

/// `D_{t,j} = C_j − val_j(t)·G_val`.
fn shifted(bases: &Bases, point: &Point, option: OptionIndex, chunk: ChunkIndex) -> Point {
    point.sub(&bases.value_part(&packed_value(option, chunk)))
}

/// `a_{t,j} = z_{t,x}·G_id + z_{t,j}·H − c_t·D_{t,j}`.
fn announcement(
    bases: &Bases,
    resp_id: &Scalar,
    resp_rand: &Scalar,
    challenge: &Scalar,
    shifted_point: &Point,
) -> Point {
    bases
        .represent(resp_id, resp_rand)
        .sub(&shifted_point.mul(challenge))
}

fn option_at(index: usize) -> Result<OptionIndex, Error> {
    u16::try_from(index)
        .ok()
        .and_then(OptionIndex::new)
        .ok_or(Error::OptionOutOfRange)
}

fn chunk_at(index: usize) -> Result<ChunkIndex, Error> {
    u8::try_from(index)
        .ok()
        .and_then(ChunkIndex::new)
        .ok_or(Error::ChunkOutOfRange)
}

/// The option `t` of a loop index (`t < 64`).
fn option_u16(index: usize) -> Result<u16, Error> {
    u16::try_from(index).map_err(|_| Error::OptionOutOfRange)
}

/// Draws the proof's randomness in the order of PROTOCOL.md §7.5 as written:
/// `α`, `β_0..β_{k−1}`, then for each wrong option in option order
/// `c_t, z_{t,x}, z_{t,0..k−1}`. The wrong options are not known when the
/// draws are made, so the `m + 1` blocks are stored in order (block `b` in
/// row `b`) and placed later by [`place_blocks`]: block `b` belongs to
/// option `b` if `b < t*` and to option `b + 1` otherwise. The stream is the
/// same whatever `t*` is, so the result is byte-identical to drawing per
/// option.
fn draw_blocks<R: CryptoRng + ?Sized>(
    rows: Rows<'_>,
    alpha: &mut Scalar,
    beta: &mut [Scalar; MAX_CHUNKS],
    options: usize,
    chunks: usize,
    rng: &mut R,
) {
    *alpha = Scalar::random(rng);
    for slot in beta.iter_mut().take(chunks) {
        *slot = Scalar::random(rng);
    }
    let blocks = options.saturating_sub(1);
    for ((challenge, resp_id), resp_rand) in rows.take(blocks) {
        *challenge = Scalar::random(rng);
        *resp_id = Scalar::random(rng);
        for cell in resp_rand.iter_mut().take(chunks) {
            *cell = Scalar::random(rng);
        }
    }
}

/// Mutable rows of `(c_t, z_{t,x}, z_{t,·})`.
type Rows<'r> = core::iter::Zip<
    core::iter::Zip<core::slice::IterMut<'r, Scalar>, core::slice::IterMut<'r, Scalar>>,
    core::slice::IterMut<'r, [Scalar; MAX_CHUNKS]>,
>;

/// Rows of a table of challenges and responses.
fn rows<'r>(
    challenges: &'r mut [Scalar],
    resp_id: &'r mut [Scalar],
    resp_rand: &'r mut [[Scalar; MAX_CHUNKS]],
) -> Rows<'r> {
    challenges
        .iter_mut()
        .zip(resp_id.iter_mut())
        .zip(resp_rand.iter_mut())
}

/// Moves every row above the true option one row up, in constant time:
/// afterwards row `t` holds block `t` for `t < t*` and block `t − 1` for
/// `t > t*`; row `t*` holds a stale block, overwritten by [`finish_rows`].
fn place_blocks(proof: &mut Proof, options: usize, true_option: u16) -> Result<(), Error> {
    for t in (1..options).rev() {
        let later = option_u16(t)?.ct_gt(&true_option);
        let (lower, upper) = proof.challenges.split_at_mut(t);
        if let (Some(prev), Some(cell)) = (lower.last(), upper.first_mut()) {
            cell.conditional_assign(prev, later);
        }
        let (lower, upper) = proof.resp_id.split_at_mut(t);
        if let (Some(prev), Some(cell)) = (lower.last(), upper.first_mut()) {
            cell.conditional_assign(prev, later);
        }
        let (lower, upper) = proof.resp_rand.split_at_mut(t);
        if let (Some(prev), Some(row)) = (lower.last(), upper.first_mut()) {
            for (cell, value) in row.iter_mut().zip(prev.iter()) {
                cell.conditional_assign(value, later);
            }
        }
    }
    Ok(())
}

/// Writes the true option's challenge `c_{t*} = c − Σ_{t≠t*} c_t` and
/// responses `z_{t*,x} = α + c_{t*}·x`, `z_{t*,j} = β_j + c_{t*}·y_j` into
/// row `t*`, touching every row in constant time.
fn finish_rows(
    proof: &mut Proof,
    options: usize,
    true_option: u16,
    true_challenge: &Scalar,
    alpha: &Scalar,
    beta: &[Scalar; MAX_CHUNKS],
    witness: &Opening,
) -> Result<(), Error> {
    let id = Zeroizing::new(witness.cast_id().to_scalar());
    let resp_id = Zeroizing::new(alpha.add(&true_challenge.mul(&id)));
    let mut resp_rand = Zeroizing::new([Scalar::ZERO; MAX_CHUNKS]);
    for ((cell, beta_j), rand_j) in resp_rand.iter_mut().zip(beta.iter()).zip(witness.rand()) {
        *cell = beta_j.add(&true_challenge.mul(rand_j));
    }
    let table = rows(
        &mut proof.challenges,
        &mut proof.resp_id,
        &mut proof.resp_rand,
    );
    for (t, ((challenge, id_cell), rand_row)) in table.enumerate().take(options) {
        let here = option_u16(t)?.ct_eq(&true_option);
        challenge.conditional_assign(true_challenge, here);
        id_cell.conditional_assign(&resp_id, here);
        for (cell, value) in rand_row.iter_mut().zip(resp_rand.iter()) {
            cell.conditional_assign(value, here);
        }
    }
    Ok(())
}

/// Proves that `witness` opens the commitments of `statement` to some
/// option, without revealing which. The witness is first checked with
/// [`verify_opening`] against the statement's option set, so an opening
/// that does not open the commitments, or names an option outside the set,
/// is rejected before any randomness is drawn.
///
/// The computation does not branch on, or index by, the witness option: it
/// draws every block first, places them with constant-time selects, and
/// computes every announcement the same way (the true option's with a zero
/// challenge). The randomness drawn and the proof are those of the order
/// written in PROTOCOL.md §7.5.
///
/// # Errors
/// [`Error::OptionOutOfRange`] if the witness option is not in the
/// statement's option set; [`Error::OpeningInvalid`] if the witness does
/// not open the commitments; [`Error::LengthMismatch`] on an internal
/// transcript length error.
pub fn prove<R: CryptoRng + ?Sized>(
    bases: &Bases,
    statement: &Statement<'_>,
    witness: &Opening,
    rng: &mut R,
) -> Result<Proof, Error> {
    let mut proof = Proof::EMPTY;
    prove_into(&mut proof, bases, statement, witness, rng)?;
    Ok(proof)
}

/// [`prove`] writing into `out` in place, so no proof-sized temporary is
/// made; the result and the randomness drawn are the same. On error `out`
/// is the empty proof of the statement's option set.
///
/// # Errors
/// As [`prove`].
pub fn prove_into<R: CryptoRng + ?Sized>(
    out: &mut Proof,
    bases: &Bases,
    statement: &Statement<'_>,
    witness: &Opening,
    rng: &mut R,
) -> Result<(), Error> {
    out.reset(statement.option_count);
    let result = fill_proof(out, bases, statement, witness, rng);
    if result.is_err() {
        out.reset(statement.option_count);
    }
    result
}

/// The body of [`prove_into`]; `proof` is empty on entry.
fn fill_proof<R: CryptoRng + ?Sized>(
    proof: &mut Proof,
    bases: &Bases,
    statement: &Statement<'_>,
    witness: &Opening,
    rng: &mut R,
) -> Result<(), Error> {
    let opened = verify_opening(
        bases,
        statement.option_count,
        statement.commitments(),
        witness,
    )?;
    let options = usize::from(statement.option_count.get());
    let chunks = usize::from(statement.chunk_count());
    let true_option = opened.get().option().get();
    let points = statement.points()?;

    let mut alpha = Zeroizing::new(Scalar::ZERO);
    let mut beta = Zeroizing::new([Scalar::ZERO; MAX_CHUNKS]);
    draw_blocks(
        rows(
            &mut proof.challenges,
            &mut proof.resp_id,
            &mut proof.resp_rand,
        ),
        &mut alpha,
        &mut beta,
        options,
        chunks,
        rng,
    );
    place_blocks(proof, options, true_option)?;

    let mut transcript = Transcript::begin(FS_LABEL_OR_REP_V1, statement.transcript_len());
    statement.absorb_header(&mut transcript)?;
    let mut others = Scalar::ZERO;
    let table = proof
        .challenges
        .iter()
        .zip(proof.resp_id.iter())
        .zip(proof.resp_rand.iter())
        .take(options)
        .enumerate();
    for (t, ((challenge, resp_id), resp_rand)) in table {
        let option = option_at(t)?;
        let here = option_u16(t)?.ct_eq(&true_option);
        // The true option's announcement is α·G_id + β_j·H: the same
        // formula with (α, β_j) for the responses and a zero challenge.
        let simulated = Scalar::conditional_select(challenge, &Scalar::ZERO, here);
        let id = Zeroizing::new(Scalar::conditional_select(resp_id, &alpha, here));
        let cells = resp_rand
            .iter()
            .zip(beta.iter())
            .zip(points.iter())
            .enumerate()
            .take(chunks);
        for (j, ((cell, beta_j), point)) in cells {
            let rand = Zeroizing::new(Scalar::conditional_select(cell, beta_j, here));
            let shifted_point = shifted(bases, point, option, chunk_at(j)?);
            let a = announcement(bases, &id, &rand, &simulated, &shifted_point);
            transcript.absorb(&a.compress());
        }
        others = others.add(&simulated);
    }
    let true_challenge = transcript.finish()?.sub(&others);
    finish_rows(
        proof,
        options,
        true_option,
        &true_challenge,
        &alpha,
        &beta,
        witness,
    )
}

/// The vote-independent half of a proof for one option set (ADR-0020
/// 결정 8, P6): every random scalar of [`prove_into`], drawn in the same
/// order, and every announcement part that does not depend on the
/// commitments, `z_{b,x}·G_id + z_{b,j}·H` for each block `b` and
/// `α·G_id + β_j·H`, stored compressed. A device makes it while idle;
/// [`prove_precomputed`] then needs one scalar multiplication per
/// announcement instead of three. Single use: `prove_precomputed` clears
/// it, and a cleared one is refused. About 37 KB; not `Clone`; `Debug`
/// shows nothing; zeroized on drop.
pub struct ProofPrecomputation {
    ready: bool,
    option_count: OptionCount,
    alpha: Scalar,
    beta: [Scalar; MAX_CHUNKS],
    challenges: [Scalar; MAX_BLOCKS],
    resp_id: [Scalar; MAX_BLOCKS],
    resp_rand: [[Scalar; MAX_CHUNKS]; MAX_BLOCKS],
    simulated: [[[u8; 32]; MAX_CHUNKS]; MAX_BLOCKS],
    real: [[u8; 32]; MAX_CHUNKS],
}

/// Blocks of a precomputation: one per wrong option.
const MAX_BLOCKS: usize = MAX_OPTIONS - 1;

impl ProofPrecomputation {
    /// The empty precomputation. Evaluated at compile time, so a caller can
    /// keep one in its own memory and refill it in place.
    pub const EMPTY: Self = Self {
        ready: false,
        option_count: OptionCount::ONE,
        alpha: Scalar::ZERO,
        beta: [Scalar::ZERO; MAX_CHUNKS],
        challenges: [Scalar::ZERO; MAX_BLOCKS],
        resp_id: [Scalar::ZERO; MAX_BLOCKS],
        resp_rand: [[Scalar::ZERO; MAX_CHUNKS]; MAX_BLOCKS],
        simulated: [[[0; 32]; MAX_CHUNKS]; MAX_BLOCKS],
        real: [[0; 32]; MAX_CHUNKS],
    };

    /// Fills `self` for proofs over `option_count` options, drawing from
    /// `rng` exactly what [`prove_into`] would draw.
    pub fn precompute<R: CryptoRng + ?Sized>(
        &mut self,
        bases: &Bases,
        option_count: OptionCount,
        rng: &mut R,
    ) {
        self.clear();
        self.option_count = option_count;
        let options = usize::from(option_count.get());
        let chunks = usize::from(option_count.chunk_count());
        draw_blocks(
            rows(&mut self.challenges, &mut self.resp_id, &mut self.resp_rand),
            &mut self.alpha,
            &mut self.beta,
            options,
            chunks,
            rng,
        );
        for (slot, beta_j) in self.real.iter_mut().zip(self.beta.iter()).take(chunks) {
            *slot = bases.represent(&self.alpha, beta_j).compress();
        }
        let blocks = self
            .simulated
            .iter_mut()
            .zip(self.resp_id.iter())
            .zip(self.resp_rand.iter())
            .take(options.saturating_sub(1));
        for ((row, resp_id), resp_rand) in blocks {
            for (slot, cell) in row.iter_mut().zip(resp_rand.iter()).take(chunks) {
                *slot = bases.represent(resp_id, cell).compress();
            }
        }
        self.ready = true;
    }

    /// The option set it was made for (a single option when empty).
    #[must_use]
    pub const fn option_count(&self) -> OptionCount {
        self.option_count
    }

    /// `true` if nothing is held (the state of [`Self::EMPTY`]).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        !self.ready
            && self.option_count == OptionCount::ONE
            && self.alpha.is_zero()
            && self.beta.iter().all(Scalar::is_zero)
            && self
                .challenges
                .iter()
                .chain(self.resp_id.iter())
                .chain(self.resp_rand.iter().flatten())
                .all(Scalar::is_zero)
            && self.simulated.iter().flatten().flatten().all(|&b| b == 0)
            && self.real.iter().flatten().all(|&b| b == 0)
    }

    /// Wipes everything and returns to [`Self::EMPTY`].
    pub fn clear(&mut self) {
        self.zeroize();
    }
}

impl Default for ProofPrecomputation {
    fn default() -> Self {
        Self::EMPTY
    }
}

impl Zeroize for ProofPrecomputation {
    fn zeroize(&mut self) {
        self.ready = false;
        self.option_count = OptionCount::ONE;
        self.alpha.zeroize();
        self.beta.zeroize();
        self.challenges.zeroize();
        self.resp_id.zeroize();
        for row in &mut self.resp_rand {
            row.zeroize();
        }
        self.simulated.zeroize();
        self.real.zeroize();
    }
}

impl Drop for ProofPrecomputation {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for ProofPrecomputation {}

impl fmt::Debug for ProofPrecomputation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProofPrecomputation(..)")
    }
}

/// The compressed announcement part of row `t`: block `t` below the true
/// option, block `t − 1` above it, `α·G_id + β_j·H` at it, chosen in
/// constant time. The two block candidates are clamped to existing blocks;
/// a clamped candidate is never the one chosen.
fn precomputed_part(
    pre: &ProofPrecomputation,
    t: usize,
    j: usize,
    true_option: u16,
) -> Result<[u8; 32], Error> {
    let options = usize::from(pre.option_count.get());
    let last_block = options.saturating_sub(2);
    let same = pre
        .simulated
        .get(t.min(last_block))
        .and_then(|row| row.get(j))
        .ok_or(Error::CapacityExceeded)?;
    let previous = pre
        .simulated
        .get(t.saturating_sub(1))
        .and_then(|row| row.get(j))
        .ok_or(Error::CapacityExceeded)?;
    let real = pre.real.get(j).ok_or(Error::CapacityExceeded)?;
    let t16 = option_u16(t)?;
    let later = t16.ct_gt(&true_option);
    let here = t16.ct_eq(&true_option);
    let mut part = *same;
    for ((byte, &prev), &real_byte) in part.iter_mut().zip(previous).zip(real) {
        byte.conditional_assign(&prev, later);
        byte.conditional_assign(&real_byte, here);
    }
    Ok(part)
}

/// [`prove_into`] from a precomputation made for the statement's option
/// set: the proof is the one `prove_into` would have written with the
/// generator `pre` was filled from. Only the commitment-dependent work is
/// left: per announcement, one decompression and one scalar
/// multiplication. Constant time in the witness option like
/// [`prove_into`]. `pre` is cleared whatever the outcome, so it is never
/// used twice.
///
/// # Errors
/// [`Error::PrecomputationMismatch`] if `pre` is empty or was made for
/// another option set; otherwise as [`prove`]. On error `out` is the empty
/// proof of the statement's option set.
pub fn prove_precomputed(
    out: &mut Proof,
    pre: &mut ProofPrecomputation,
    bases: &Bases,
    statement: &Statement<'_>,
    witness: &Opening,
) -> Result<(), Error> {
    out.reset(statement.option_count);
    let result = if pre.ready && pre.option_count == statement.option_count {
        fill_from_precomputation(out, pre, bases, statement, witness)
    } else {
        Err(Error::PrecomputationMismatch)
    };
    pre.clear();
    if result.is_err() {
        out.reset(statement.option_count);
    }
    result
}

/// The body of [`prove_precomputed`]; `proof` is empty on entry.
fn fill_from_precomputation(
    proof: &mut Proof,
    pre: &ProofPrecomputation,
    bases: &Bases,
    statement: &Statement<'_>,
    witness: &Opening,
) -> Result<(), Error> {
    let opened = verify_opening(
        bases,
        statement.option_count,
        statement.commitments(),
        witness,
    )?;
    let options = usize::from(statement.option_count.get());
    let chunks = usize::from(statement.chunk_count());
    let true_option = opened.get().option().get();
    let points = statement.points()?;
    let blocks = options.saturating_sub(1);
    for (dst, src) in proof
        .challenges
        .iter_mut()
        .zip(&pre.challenges)
        .take(blocks)
    {
        *dst = *src;
    }
    for (dst, src) in proof.resp_id.iter_mut().zip(&pre.resp_id).take(blocks) {
        *dst = *src;
    }
    for (dst, src) in proof.resp_rand.iter_mut().zip(&pre.resp_rand).take(blocks) {
        *dst = *src;
    }
    place_blocks(proof, options, true_option)?;

    let mut transcript = Transcript::begin(FS_LABEL_OR_REP_V1, statement.transcript_len());
    statement.absorb_header(&mut transcript)?;
    let mut others = Scalar::ZERO;
    for (t, challenge) in proof.challenges.iter().enumerate().take(options) {
        let option = option_at(t)?;
        let here = option_u16(t)?.ct_eq(&true_option);
        let simulated = Scalar::conditional_select(challenge, &Scalar::ZERO, here);
        for (j, point) in points.iter().enumerate().take(chunks) {
            let part = Zeroizing::new(precomputed_part(pre, t, j, true_option)?);
            let part = Point::decompress(&part).ok_or(Error::Backend)?;
            let shifted_point = shifted(bases, point, option, chunk_at(j)?);
            let a = part.sub(&shifted_point.mul(&simulated));
            transcript.absorb(&a.compress());
        }
        others = others.add(&simulated);
    }
    let true_challenge = transcript.finish()?.sub(&others);
    finish_rows(
        proof,
        options,
        true_option,
        &true_challenge,
        &pre.alpha,
        &pre.beta,
        witness,
    )
}

/// What [`verify`] verified: the statement and the proof that proves it.
#[derive(Debug, Clone, Copy)]
pub struct ProvenStatement<'a> {
    statement: &'a Statement<'a>,
    proof: &'a Proof,
}

impl<'a> ProvenStatement<'a> {
    /// The statement.
    #[must_use]
    pub const fn statement(&self) -> &'a Statement<'a> {
        self.statement
    }

    /// The proof.
    #[must_use]
    pub const fn proof(&self) -> &'a Proof {
        self.proof
    }
}

/// Verifies `proof` against `statement` (VC-025, VC-026).
///
/// # Errors
/// [`Error::ProofInvalid`] if the proof's option set differs from the
/// statement's or the challenge equation does not hold;
/// [`Error::LengthMismatch`] on an internal transcript length error.
pub fn verify<'a>(
    bases: &Bases,
    statement: &'a Statement<'a>,
    proof: &'a Proof,
) -> Result<Verified<ProvenStatement<'a>>, Error> {
    if proof.option_count != statement.option_count {
        return Err(Error::ProofInvalid);
    }
    let options = usize::from(statement.option_count.get());
    let chunks = usize::from(statement.chunk_count());
    let points = statement.points()?;
    let mut transcript = Transcript::begin(FS_LABEL_OR_REP_V1, statement.transcript_len());
    statement.absorb_header(&mut transcript)?;

    let mut sum = Scalar::ZERO;
    let rows = proof
        .challenges
        .iter()
        .zip(proof.resp_id.iter())
        .zip(proof.resp_rand.iter())
        .take(options)
        .enumerate();
    for (t, ((challenge, resp_id), resp_rand)) in rows {
        let option = option_at(t)?;
        sum = sum.add(challenge);
        let cells = resp_rand.iter().zip(points.iter()).enumerate().take(chunks);
        for (j, (cell, point)) in cells {
            let shifted_point = shifted(bases, point, option, chunk_at(j)?);
            let a = announcement(bases, resp_id, cell, challenge, &shifted_point);
            transcript.absorb(&a.compress());
        }
    }
    let total = transcript.finish()?;
    if bool::from(sum.ct_eq(&total)) {
        Ok(Verified::new(ProvenStatement { statement, proof }))
    } else {
        Err(Error::ProofInvalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commit::{CastId, commit};
    use ityv_encoding::Token192;
    use rand_chacha::ChaCha20Rng;
    use rand_core::{Rng, SeedableRng};
    use std::vec::Vec;

    /// The prover as PROTOCOL.md §7.5 writes it, branching on the true
    /// option: the reference the constant-time and precomputed provers
    /// must reproduce byte for byte from the same generator.
    fn reference_prove(
        bases: &Bases,
        statement: &Statement<'_>,
        witness: &Opening,
        rng: &mut ChaCha20Rng,
    ) -> Proof {
        let mut proof = Proof::EMPTY;
        proof.reset(statement.option_count);
        let options = usize::from(statement.option_count.get());
        let chunks = usize::from(statement.chunk_count());
        let true_option = usize::from(witness.option().get());
        let points = statement.points().unwrap();
        let mut transcript = Transcript::begin(FS_LABEL_OR_REP_V1, statement.transcript_len());
        statement.absorb_header(&mut transcript).unwrap();
        let alpha = Scalar::random(rng);
        let beta: Vec<Scalar> = (0..chunks).map(|_| Scalar::random(rng)).collect();
        for t in 0..options {
            let option = option_at(t).unwrap();
            if t == true_option {
                for beta_j in &beta {
                    transcript.absorb(&bases.represent(&alpha, beta_j).compress());
                }
            } else {
                proof.challenges[t] = Scalar::random(rng);
                proof.resp_id[t] = Scalar::random(rng);
                for (j, point) in points.iter().enumerate().take(chunks) {
                    proof.resp_rand[t][j] = Scalar::random(rng);
                    let d = shifted(bases, point, option, chunk_at(j).unwrap());
                    let a = announcement(
                        bases,
                        &proof.resp_id[t],
                        &proof.resp_rand[t][j],
                        &proof.challenges[t],
                        &d,
                    );
                    transcript.absorb(&a.compress());
                }
            }
        }
        let total = transcript.finish().unwrap();
        let mut others = Scalar::ZERO;
        for t in (0..options).filter(|&t| t != true_option) {
            others = others.add(&proof.challenges[t]);
        }
        let c = total.sub(&others);
        let id = witness.cast_id().to_scalar();
        proof.challenges[true_option] = c;
        proof.resp_id[true_option] = alpha.add(&c.mul(&id));
        for (j, beta_j) in beta.iter().enumerate() {
            proof.resp_rand[true_option][j] = beta_j.add(&c.mul(&witness.rand()[j]));
        }
        proof
    }

    /// Commitments and an opening of `option` out of `option_count`.
    fn ballot(
        bases: &Bases,
        option_count: OptionCount,
        option: u16,
        rng: &mut ChaCha20Rng,
    ) -> (Opening, Vec<Commitment>) {
        let mut token = [0u8; 24];
        rng.fill_bytes(&mut token);
        let cast_id = CastId::new(Token192(token));
        let chunks = usize::from(option_count.chunk_count());
        let mut rand = [Scalar::ZERO; MAX_CHUNKS];
        for slot in rand.iter_mut().take(chunks) {
            *slot = Scalar::random(rng);
        }
        let option = OptionIndex::new(option).unwrap();
        let commitments = (0..chunks)
            .map(|j| commit(bases, option, &cast_id, &rand[j], chunk_at(j).unwrap()))
            .collect();
        (Opening::new(option, cast_id, rand), commitments)
    }

    fn statement(option_count: OptionCount, commitments: &[Commitment]) -> Statement<'_> {
        Statement::new(
            ElectionId::new(b"KR-2030-PRES").unwrap(),
            Ident::new(b"BOX-0001", 64).unwrap(),
            Ident::new(b"PRES", 64).unwrap(),
            option_count,
            commitments,
        )
        .unwrap()
    }

    /// Every option position of several option sets: the one-shot prover
    /// and the precomputed prover give the reference's bytes, the proofs
    /// verify, and the precomputation is spent.
    #[test]
    fn provers_match_the_reference_for_every_true_option() {
        let bases = Bases::derive();
        let mut setup = ChaCha20Rng::seed_from_u64(1);
        let mut pre = ProofPrecomputation::EMPTY;
        for raw in [1u16, 2, 3, 4, 9, 10, 12, 18, 19] {
            let option_count = OptionCount::new(raw).unwrap();
            for option in 0..raw {
                let (opening, commitments) = ballot(&bases, option_count, option, &mut setup);
                let st = statement(option_count, &commitments);
                let seed = u64::from(raw) * 1000 + u64::from(option);
                let expected =
                    reference_prove(&bases, &st, &opening, &mut ChaCha20Rng::seed_from_u64(seed));
                let mut one_shot = Proof::EMPTY;
                prove_into(
                    &mut one_shot,
                    &bases,
                    &st,
                    &opening,
                    &mut ChaCha20Rng::seed_from_u64(seed),
                )
                .unwrap();
                assert!(
                    one_shot == expected,
                    "one-shot, {raw} options, t* = {option}"
                );
                pre.precompute(&bases, option_count, &mut ChaCha20Rng::seed_from_u64(seed));
                assert_eq!(pre.option_count(), option_count);
                assert!(!pre.is_empty());
                let mut precomputed = Proof::EMPTY;
                prove_precomputed(&mut precomputed, &mut pre, &bases, &st, &opening).unwrap();
                assert!(
                    precomputed == expected,
                    "precomputed, {raw} options, t* = {option}"
                );
                assert!(pre.is_empty(), "the precomputation is spent");
                assert!(verify(&bases, &st, &precomputed).is_ok());
            }
        }
    }

    /// The largest option set (eight chunks), a few true options.
    #[test]
    fn provers_match_the_reference_at_the_largest_option_set() {
        let bases = Bases::derive();
        let option_count = OptionCount::new(64).unwrap();
        let mut setup = ChaCha20Rng::seed_from_u64(2);
        let mut pre = ProofPrecomputation::default();
        for option in [0u16, 8, 9, 35, 62, 63] {
            let (opening, commitments) = ballot(&bases, option_count, option, &mut setup);
            let st = statement(option_count, &commitments);
            let seed = 77 + u64::from(option);
            let expected =
                reference_prove(&bases, &st, &opening, &mut ChaCha20Rng::seed_from_u64(seed));
            let one_shot = prove(&bases, &st, &opening, &mut ChaCha20Rng::seed_from_u64(seed));
            assert!(one_shot.unwrap() == expected, "one-shot, t* = {option}");
            pre.precompute(&bases, option_count, &mut ChaCha20Rng::seed_from_u64(seed));
            let mut precomputed = Proof::EMPTY;
            prove_precomputed(&mut precomputed, &mut pre, &bases, &st, &opening).unwrap();
            assert!(precomputed == expected, "precomputed, t* = {option}");
        }
    }

    /// A precomputation is refused when empty, spent or made for another
    /// option set; it is cleared either way, and the output stays empty.
    #[test]
    fn a_precomputation_is_single_use_and_bound_to_its_option_set() {
        let bases = Bases::derive();
        let four = OptionCount::new(4).unwrap();
        let five = OptionCount::new(5).unwrap();
        let mut setup = ChaCha20Rng::seed_from_u64(3);
        let (opening, commitments) = ballot(&bases, four, 2, &mut setup);
        let st = statement(four, &commitments);
        let mut out = Proof::EMPTY;
        let mut pre = ProofPrecomputation::EMPTY;
        assert!(pre.is_empty());
        assert_eq!(pre.option_count(), OptionCount::ONE);
        assert_eq!(
            prove_precomputed(&mut out, &mut pre, &bases, &st, &opening),
            Err(Error::PrecomputationMismatch)
        );
        assert_eq!(out.option_count(), four);
        assert!(out.challenges.iter().all(Scalar::is_zero));
        // the empty precomputation's option set is one option, but it is
        // still refused for a one-option statement
        let one = OptionCount::ONE;
        let (single, single_commitments) = ballot(&bases, one, 0, &mut setup);
        let single_st = statement(one, &single_commitments);
        assert_eq!(
            prove_precomputed(&mut out, &mut pre, &bases, &single_st, &single),
            Err(Error::PrecomputationMismatch)
        );
        pre.precompute(&bases, five, &mut setup);
        assert_eq!(
            prove_precomputed(&mut out, &mut pre, &bases, &st, &opening),
            Err(Error::PrecomputationMismatch)
        );
        assert!(pre.is_empty(), "a refused precomputation is cleared too");
        pre.precompute(&bases, four, &mut setup);
        prove_precomputed(&mut out, &mut pre, &bases, &st, &opening).unwrap();
        assert!(verify(&bases, &st, &out).is_ok());
        assert_eq!(
            prove_precomputed(&mut out, &mut pre, &bases, &st, &opening),
            Err(Error::PrecomputationMismatch),
            "a spent precomputation cannot prove again"
        );
        // a witness that does not open the commitments: refused, cleared
        let (other, _) = ballot(&bases, four, 1, &mut setup);
        pre.precompute(&bases, four, &mut setup);
        assert_eq!(
            prove_precomputed(&mut out, &mut pre, &bases, &st, &other),
            Err(Error::OpeningInvalid)
        );
        assert!(pre.is_empty());
        assert!(out.resp_id.iter().all(Scalar::is_zero));
        assert_eq!(std::format!("{pre:?}"), "ProofPrecomputation(..)");
    }

    /// Each part of a precomputation is seen by `is_empty` and wiped by
    /// `clear`.
    #[test]
    fn clear_wipes_every_part() {
        let bases = Bases::derive();
        let mut rng = ChaCha20Rng::seed_from_u64(4);
        let fill = |pre: &mut ProofPrecomputation, rng: &mut ChaCha20Rng| {
            pre.precompute(&bases, OptionCount::new(12).unwrap(), rng);
        };
        let parts: [fn(&mut ProofPrecomputation); 9] = [
            |p| p.ready = true,
            |p| p.option_count = OptionCount::new(3).unwrap(),
            |p| p.alpha = Scalar::ONE,
            |p| p.beta[1] = Scalar::ONE,
            |p| p.challenges[5] = Scalar::ONE,
            |p| p.resp_id[5] = Scalar::ONE,
            |p| p.resp_rand[5][1] = Scalar::ONE,
            |p| p.simulated[5][1][0] = 1,
            |p| p.real[1][0] = 1,
        ];
        for set in parts {
            let mut pre = ProofPrecomputation::EMPTY;
            set(&mut pre);
            assert!(!pre.is_empty());
            pre.clear();
            assert!(pre.is_empty());
        }
        let mut pre = ProofPrecomputation::EMPTY;
        fill(&mut pre, &mut rng);
        assert!(!pre.is_empty());
        pre.zeroize();
        assert!(pre.is_empty());
    }

    /// A precomputation holds one block per wrong option of the largest
    /// option set; a larger one would only hide a wrong count.
    #[test]
    fn precomputation_block_count_is_exact() {
        assert_eq!(MAX_BLOCKS, 63);
        assert_eq!(MAX_BLOCKS, MAX_OPTIONS - 1);
    }

    /// The identifier field capacity is exactly the prefix plus the standard
    /// maximum; a larger buffer would only hide a wrong capacity computation.
    #[test]
    fn ident_field_capacity_is_exact() {
        assert_eq!(IDENT_FIELD_MAX_LEN, 68);
        assert_eq!(IDENT_FIELD_MAX_LEN, IDENT_MAX_STANDARD + 4);
    }
}
