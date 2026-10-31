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
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

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

/// Length of an identifier field in the transcript: `u32` prefix plus bytes.
fn ident_field_len(ident: &Ident<'_>) -> usize {
    ident.byte_len().saturating_add(4)
}

/// Absorbs an identifier as its canonical length-prefixed encoding.
fn absorb_ident(transcript: &mut Transcript, ident: &Ident<'_>) -> Result<(), Error> {
    let mut buffer = [0u8; IDENT_MAX_STANDARD + 4];
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
    fn empty(option_count: OptionCount) -> Self {
        Self {
            option_count,
            challenges: [Scalar::ZERO; MAX_OPTIONS],
            resp_id: [Scalar::ZERO; MAX_OPTIONS],
            resp_rand: core::array::from_fn(|_| [Scalar::ZERO; MAX_CHUNKS]),
        }
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
        let mut proof = Self::empty(option_count);
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

/// Proves that `witness` opens the commitments of `statement` to some
/// option, without revealing which. The witness is first checked with
/// [`verify_opening`] against the statement's option set, so an opening
/// that does not open the commitments, or names an option outside the set,
/// is rejected before any randomness is drawn.
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
    let opened = verify_opening(
        bases,
        statement.option_count,
        statement.commitments(),
        witness,
    )?;
    let options = usize::from(statement.option_count.get());
    let chunks = usize::from(statement.chunk_count());
    let true_option = usize::from(opened.get().option().get());
    let points = statement.points()?;
    let mut proof = Proof::empty(statement.option_count);
    let mut transcript = Transcript::begin(FS_LABEL_OR_REP_V1, statement.transcript_len());
    statement.absorb_header(&mut transcript)?;

    let alpha = Zeroizing::new(Scalar::random(rng));
    let mut beta = Zeroizing::new([Scalar::ZERO; MAX_CHUNKS]);
    for slot in beta.iter_mut().take(chunks) {
        *slot = Scalar::random(rng);
    }

    let rows = proof
        .challenges
        .iter_mut()
        .zip(proof.resp_id.iter_mut())
        .zip(proof.resp_rand.iter_mut())
        .take(options)
        .enumerate();
    for (t, ((challenge, resp_id), resp_rand)) in rows {
        let option = option_at(t)?;
        if t == true_option {
            for (j, beta_j) in beta.iter().enumerate().take(chunks) {
                let _chunk = chunk_at(j)?;
                let a = bases.represent(&alpha, beta_j);
                transcript.absorb(&a.compress());
            }
        } else {
            *challenge = Scalar::random(rng);
            *resp_id = Scalar::random(rng);
            let cells = resp_rand
                .iter_mut()
                .zip(points.iter())
                .enumerate()
                .take(chunks);
            for (j, (cell, point)) in cells {
                *cell = Scalar::random(rng);
                let shifted_point = shifted(bases, point, option, chunk_at(j)?);
                let a = announcement(bases, resp_id, cell, challenge, &shifted_point);
                transcript.absorb(&a.compress());
            }
        }
    }

    let total = transcript.finish()?;
    let mut others = Scalar::ZERO;
    for (t, challenge) in proof.challenges.iter().enumerate().take(options) {
        if t != true_option {
            others = others.add(challenge);
        }
    }
    let true_challenge = total.sub(&others);
    let id = Zeroizing::new(witness.cast_id().to_scalar());
    let challenge = proof
        .challenges
        .get_mut(true_option)
        .ok_or(Error::OptionOutOfRange)?;
    *challenge = true_challenge;
    let resp_id = proof
        .resp_id
        .get_mut(true_option)
        .ok_or(Error::OptionOutOfRange)?;
    *resp_id = alpha.add(&true_challenge.mul(&id));
    let row = proof
        .resp_rand
        .get_mut(true_option)
        .ok_or(Error::OptionOutOfRange)?;
    let cells = row
        .iter_mut()
        .zip(beta.iter())
        .zip(witness.rand().iter())
        .take(chunks);
    for ((cell, beta_j), rand_j) in cells {
        *cell = beta_j.add(&true_challenge.mul(rand_j));
    }
    Ok(proof)
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
