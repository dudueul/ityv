//! Linear secret sharing over the chamber access structure (PROTOCOL.md
//! §9.2; ADR-0019).
//!
//! The chambers are the party chambers `P1..Pn` (`2 ≤ n ≤ 4`, fixed by
//! genesis) and `J, A, C, N`. Γ = { S : {P1, …, Pn} ⊆ S ∧ |S ∩ {J, A, C, N}|
//! ≥ 3 }, realized as `s = s_P1 + … + s_Pn + s_rest` with every `s_Pi`
//! random and `s_rest` shared 3-of-4 over the chambers `J = 1, A = 2, C = 3,
//! N = 4` by Shamir's scheme; every chamber secret is then shared
//! `k_c`-of-`n_c` among the chamber's members (member `i` at point `i + 1`).
//! Party chambers beyond `n` take no part and get no shares. Every step is
//! linear, so member shares of several secrets add to member shares of the
//! sum (aggregate-only reconstruction).
//!
//! [`reconstruct`] checks qualification before touching any share value and
//! returns nothing for an unqualified subset (VC-031). When more shares than
//! the threshold are supplied, the extra shares are checked against the
//! interpolated polynomial so that an inconsistent share is reported rather
//! than silently averaged in.

use core::fmt;

use rand_core::CryptoRng;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::Error;
use crate::scalar::Scalar;

/// Number of chambers: four party chambers and J, A, C, N.
pub const CHAMBER_COUNT: usize = 8;
/// Party chambers at most (ADR-0019 §1).
pub const MAX_PARTIES: u8 = 4;
/// Party chambers at least.
pub const MIN_PARTIES: u8 = 2;
/// Maximum members per chamber (fixed capacity, ADR-0015 §6).
pub const MAX_MEMBERS: usize = 8;
/// Chambers sharing `s_rest`.
pub const REST_CHAMBERS: usize = 4;
/// Threshold among the chambers sharing `s_rest`.
pub const REST_THRESHOLD: usize = 3;

const MAX_PARTY_SLOTS: usize = MAX_PARTIES as usize;

/// A trustee chamber.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Chamber {
    /// Party chamber 1 (the party with the most seats).
    P1,
    /// Party chamber 2.
    P2,
    /// Party chamber 3 (present when genesis lists three or more parties).
    P3,
    /// Party chamber 4 (present when genesis lists four parties).
    P4,
    /// Judiciary.
    J,
    /// Academia.
    A,
    /// Civil society.
    C,
    /// National Election Commission.
    N,
}

impl Chamber {
    /// All chambers in index order (the order of their wire codes 1..=8).
    pub const ALL: [Self; CHAMBER_COUNT] = [
        Self::P1,
        Self::P2,
        Self::P3,
        Self::P4,
        Self::J,
        Self::A,
        Self::C,
        Self::N,
    ];

    /// Position in [`Self::ALL`].
    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            Self::P1 => 0,
            Self::P2 => 1,
            Self::P3 => 2,
            Self::P4 => 3,
            Self::J => 4,
            Self::A => 5,
            Self::C => 6,
            Self::N => 7,
        }
    }

    /// The party number `0..4` of a party chamber, `None` for J, A, C, N.
    #[must_use]
    pub const fn party(self) -> Option<u8> {
        match self {
            Self::P1 => Some(0),
            Self::P2 => Some(1),
            Self::P3 => Some(2),
            Self::P4 => Some(3),
            Self::J | Self::A | Self::C | Self::N => None,
        }
    }

    /// `true` for a party chamber.
    #[must_use]
    pub const fn is_party(self) -> bool {
        self.party().is_some()
    }

    /// The Shamir evaluation point of a chamber sharing `s_rest`, or `None`
    /// for a party chamber.
    #[must_use]
    pub const fn rest_point(self) -> Option<u8> {
        match self {
            Self::P1 | Self::P2 | Self::P3 | Self::P4 => None,
            Self::J => Some(1),
            Self::A => Some(2),
            Self::C => Some(3),
            Self::N => Some(4),
        }
    }
}

/// A `k`-of-`n` threshold with `1 ≤ k ≤ n ≤ MAX_MEMBERS`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Threshold {
    k: u8,
    n: u8,
}

impl Threshold {
    /// Returns `Some` if `1 ≤ k ≤ n ≤ MAX_MEMBERS`.
    #[must_use]
    pub fn new(k: u8, n: u8) -> Option<Self> {
        if k >= 1 && k <= n && usize::from(n) <= MAX_MEMBERS {
            Some(Self { k, n })
        } else {
            None
        }
    }

    /// The threshold.
    #[must_use]
    pub const fn k(self) -> u8 {
        self.k
    }

    /// The member count.
    #[must_use]
    pub const fn n(self) -> u8 {
        self.n
    }
}

/// The number of party chambers and one threshold per chamber.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessStructure {
    parties: u8,
    inner: [Threshold; CHAMBER_COUNT],
}

impl AccessStructure {
    /// Builds a structure with the party chambers `P1..P{parties}` and the
    /// per-chamber thresholds in [`Chamber::ALL`] order; the thresholds of
    /// party chambers beyond `parties` are ignored. `None` unless
    /// `MIN_PARTIES ≤ parties ≤ MAX_PARTIES`.
    #[must_use]
    pub const fn new(parties: u8, inner: [Threshold; CHAMBER_COUNT]) -> Option<Self> {
        if parties < MIN_PARTIES || parties > MAX_PARTIES {
            None
        } else {
            Some(Self { parties, inner })
        }
    }

    /// The same threshold for every chamber.
    #[must_use]
    pub const fn uniform(parties: u8, threshold: Threshold) -> Option<Self> {
        Self::new(parties, [threshold; CHAMBER_COUNT])
    }

    /// The number of party chambers `n`.
    #[must_use]
    pub const fn parties(&self) -> u8 {
        self.parties
    }

    /// `true` if `chamber` takes part: every chamber but the party chambers
    /// beyond `n`.
    #[must_use]
    pub const fn includes(&self, chamber: Chamber) -> bool {
        match chamber.party() {
            Some(party) => party < self.parties,
            None => true,
        }
    }

    /// The threshold of `chamber`.
    #[must_use]
    pub fn threshold(&self, chamber: Chamber) -> Threshold {
        self.inner
            .get(chamber.index())
            .copied()
            .unwrap_or(Threshold { k: 1, n: 1 })
    }

    /// The thresholds in [`Chamber::ALL`] order.
    #[must_use]
    pub const fn thresholds(&self) -> &[Threshold; CHAMBER_COUNT] {
        &self.inner
    }
}

/// A member of a chamber: `index < MAX_MEMBERS`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MemberId {
    chamber: Chamber,
    index: u8,
}

impl MemberId {
    /// Returns `Some` if `index < MAX_MEMBERS`.
    #[must_use]
    pub fn new(chamber: Chamber, index: u8) -> Option<Self> {
        if usize::from(index) < MAX_MEMBERS {
            Some(Self { chamber, index })
        } else {
            None
        }
    }

    /// The chamber.
    #[must_use]
    pub const fn chamber(self) -> Chamber {
        self.chamber
    }

    /// The member index within the chamber.
    #[must_use]
    pub const fn index(self) -> u8 {
        self.index
    }

    /// The Shamir evaluation point `index + 1`.
    #[must_use]
    pub const fn point(self) -> u8 {
        self.index.saturating_add(1)
    }
}

/// One share: a member and its value. Zeroized on drop.
#[derive(Clone)]
pub struct Share {
    member: MemberId,
    value: Scalar,
}

impl Share {
    /// Builds a share.
    #[must_use]
    pub const fn new(member: MemberId, value: Scalar) -> Self {
        Self { member, value }
    }

    /// The member.
    #[must_use]
    pub const fn member(&self) -> MemberId {
        self.member
    }

    /// The share value.
    #[must_use]
    pub const fn value(&self) -> &Scalar {
        &self.value
    }
}

impl Drop for Share {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

impl ZeroizeOnDrop for Share {}

impl fmt::Debug for Share {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Share")
            .field("member", &self.member)
            .finish_non_exhaustive()
    }
}

/// The shares of one secret for every member of every chamber. Slots beyond
/// a chamber's `n` are zero. Zeroized on drop.
pub struct MemberShares {
    values: [[Scalar; MAX_MEMBERS]; CHAMBER_COUNT],
}

impl MemberShares {
    fn zeroed() -> Self {
        Self {
            values: [[Scalar::ZERO; MAX_MEMBERS]; CHAMBER_COUNT],
        }
    }

    /// The share value of `member`.
    #[must_use]
    pub fn value(&self, member: MemberId) -> Scalar {
        self.values
            .get(member.chamber.index())
            .and_then(|row| row.get(usize::from(member.index)))
            .copied()
            .unwrap_or(Scalar::ZERO)
    }

    /// The share of `member`.
    #[must_use]
    pub fn share(&self, member: MemberId) -> Share {
        Share::new(member, self.value(member))
    }

    /// Element-wise sum: the shares of the sum of the two secrets.
    #[must_use]
    pub fn add(&self, other: &Self) -> Self {
        let mut out = Self::zeroed();
        let rows = out
            .values
            .iter_mut()
            .zip(self.values.iter())
            .zip(other.values.iter());
        for ((out_row, left_row), right_row) in rows {
            for ((out_cell, left), right) in out_row.iter_mut().zip(left_row).zip(right_row) {
                *out_cell = left.add(right);
            }
        }
        out
    }
}

impl Drop for MemberShares {
    fn drop(&mut self) {
        for row in &mut self.values {
            row.zeroize();
        }
    }
}

impl ZeroizeOnDrop for MemberShares {}

impl fmt::Debug for MemberShares {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MemberShares(..)")
    }
}

/// Horner evaluation of `coefficients[0] + coefficients[1]·x + …` at `x`.
pub(crate) fn eval_poly(coefficients: &[Scalar], x: &Scalar) -> Scalar {
    coefficients
        .iter()
        .rev()
        .fold(Scalar::ZERO, |acc, coefficient| acc.mul(x).add(coefficient))
}

/// Lagrange interpolation of the polynomial through `points` evaluated at
/// `x`.
///
/// # Errors
/// [`Error::DuplicateShare`] if two points share an abscissa.
pub(crate) fn lagrange_at(points: &[(Scalar, Scalar)], x: &Scalar) -> Result<Scalar, Error> {
    let mut total = Scalar::ZERO;
    for (i, (x_i, y_i)) in points.iter().enumerate() {
        let mut numerator = Scalar::ONE;
        let mut denominator = Scalar::ONE;
        for (j, (x_j, _)) in points.iter().enumerate() {
            if i == j {
                continue;
            }
            numerator = numerator.mul(&x.sub(x_j));
            denominator = denominator.mul(&x_i.sub(x_j));
        }
        let inverse = denominator.invert().ok_or(Error::DuplicateShare)?;
        total = total.add(&y_i.mul(&numerator).mul(&inverse));
    }
    Ok(total)
}

/// The scalar evaluation point of a member index (`index + 1`).
pub(crate) fn member_point(index: usize) -> Result<Scalar, Error> {
    let raw = u64::try_from(index)
        .ok()
        .and_then(|i| i.checked_add(1))
        .ok_or(Error::InvalidMember)?;
    Ok(Scalar::from_u64(raw))
}

/// Shares `secret` to every member of every chamber taking part under
/// `structure`; party chambers beyond `n` get no shares (their slots stay
/// zero) and draw no randomness.
pub fn split<R: CryptoRng + ?Sized>(
    secret: &Scalar,
    structure: &AccessStructure,
    rng: &mut R,
) -> MemberShares {
    let parties = usize::from(structure.parties);
    let mut party_shares = Zeroizing::new([Scalar::ZERO; MAX_PARTY_SLOTS]);
    let mut rest_secret = Zeroizing::new(*secret);
    for share in party_shares.iter_mut().take(parties) {
        *share = Scalar::random(rng);
        *rest_secret = rest_secret.sub(share);
    }
    let rest_poly = Zeroizing::new([*rest_secret, Scalar::random(rng), Scalar::random(rng)]);
    let mut chamber_secrets = Zeroizing::new([Scalar::ZERO; CHAMBER_COUNT]);
    for (chamber, slot) in Chamber::ALL.iter().zip(chamber_secrets.iter_mut()) {
        *slot = match (chamber.party(), chamber.rest_point()) {
            (Some(party), _) => party_shares
                .get(usize::from(party))
                .copied()
                .unwrap_or(Scalar::ZERO),
            (None, Some(point)) => {
                eval_poly(rest_poly.as_ref(), &Scalar::from_u64(u64::from(point)))
            }
            (None, None) => Scalar::ZERO,
        };
    }

    let mut out = MemberShares::zeroed();
    let rows = Chamber::ALL
        .iter()
        .zip(structure.inner.iter())
        .zip(chamber_secrets.iter())
        .zip(out.values.iter_mut())
        .filter(|(((chamber, _), _), _)| structure.includes(**chamber));
    for (((_, threshold), chamber_secret), row) in rows {
        let degree_plus_one = usize::from(threshold.k);
        let mut poly = Zeroizing::new([Scalar::ZERO; MAX_MEMBERS]);
        for (position, coefficient) in poly.iter_mut().enumerate().take(degree_plus_one) {
            *coefficient = if position == 0 {
                *chamber_secret
            } else {
                Scalar::random(rng)
            };
        }
        let coefficients = poly.get(..degree_plus_one).unwrap_or(&[]);
        for (index, cell) in row.iter_mut().enumerate().take(usize::from(threshold.n)) {
            *cell = member_point(index).map_or(Scalar::ZERO, |x| eval_poly(coefficients, &x));
        }
    }
    out
}

/// Which chambers reach their member threshold, given the number of
/// distinct members present per chamber (in [`Chamber::ALL`] order). A
/// party chamber beyond `n` never reaches.
#[must_use]
pub fn reached(
    structure: &AccessStructure,
    member_counts: [u8; CHAMBER_COUNT],
) -> [bool; CHAMBER_COUNT] {
    let mut out = [false; CHAMBER_COUNT];
    let cells = out
        .iter_mut()
        .zip(Chamber::ALL.iter())
        .zip(structure.inner.iter())
        .zip(member_counts.iter());
    for (((flag, chamber), threshold), count) in cells {
        *flag = structure.includes(*chamber) && *count >= threshold.k;
    }
    out
}

/// `true` if the chambers that reach their thresholds form a set in Γ:
/// every party chamber `P1..Pn` reaches, and at least three of J, A, C, N
/// reach.
#[must_use]
pub fn is_qualified(structure: &AccessStructure, member_counts: [u8; CHAMBER_COUNT]) -> bool {
    let flags = reached(structure, member_counts);
    let mut parties = true;
    let mut rest = 0usize;
    for (chamber, flag) in Chamber::ALL.iter().zip(flags.iter()) {
        if chamber.is_party() {
            if structure.includes(*chamber) {
                parties &= *flag;
            }
        } else if *flag {
            rest = rest.saturating_add(1);
        }
    }
    parties && rest >= REST_THRESHOLD
}

/// The `(x, y)` points of one chamber's present members, zeroized when
/// dropped.
type ChamberPoints = Zeroizing<[(Scalar, Scalar); MAX_MEMBERS]>;

/// Points of the present members of one chamber, in member order, and how
/// many there are.
fn chamber_points(row: &[Option<Scalar>; MAX_MEMBERS]) -> Result<(ChamberPoints, usize), Error> {
    let mut points = Zeroizing::new([(Scalar::ZERO, Scalar::ZERO); MAX_MEMBERS]);
    let mut count = 0usize;
    let present = row
        .iter()
        .enumerate()
        .filter_map(|(index, slot)| slot.map(|value| (index, value)));
    for (slot, (index, value)) in points.iter_mut().zip(present) {
        *slot = (member_point(index)?, value);
        count = count.saturating_add(1);
    }
    Ok((points, count))
}

/// Interpolates at zero from the first `threshold` points and checks that
/// every further point (up to `count`) lies on the same polynomial.
fn interpolate_checked(
    points: &[(Scalar, Scalar)],
    count: usize,
    threshold: usize,
) -> Result<Scalar, Error> {
    let (used, rest) = points
        .split_at_checked(threshold)
        .ok_or(Error::NotQualified)?;
    let secret = lagrange_at(used, &Scalar::ZERO)?;
    let extra = count.saturating_sub(threshold);
    for (x, y) in rest.iter().take(extra) {
        if lagrange_at(used, x)? != *y {
            return Err(Error::InconsistentShares);
        }
    }
    Ok(secret)
}

/// Reconstructs the secret from `shares`. Every intermediate value (the
/// collected shares, the chamber secrets, the rest points and the party
/// shares) is zeroized on every return path.
///
/// # Errors
/// [`Error::InvalidMember`] if a member's chamber takes no part or its
/// index is at or above its chamber's `n`; [`Error::DuplicateShare`] if a
/// member appears twice;
/// [`Error::NotQualified`] if the members present do not form a set in Γ
/// (checked before any share value is used); [`Error::InconsistentShares`]
/// if shares beyond a threshold disagree with the interpolated polynomial.
pub fn reconstruct(structure: &AccessStructure, shares: &[Share]) -> Result<Scalar, Error> {
    let mut present: Zeroizing<[[Option<Scalar>; MAX_MEMBERS]; CHAMBER_COUNT]> =
        Zeroizing::new([[None; MAX_MEMBERS]; CHAMBER_COUNT]);
    for share in shares {
        let member = share.member;
        if !structure.includes(member.chamber)
            || member.index >= structure.threshold(member.chamber).n
        {
            return Err(Error::InvalidMember);
        }
        let slot = present
            .get_mut(member.chamber.index())
            .and_then(|row| row.get_mut(usize::from(member.index)))
            .ok_or(Error::InvalidMember)?;
        if slot.is_some() {
            return Err(Error::DuplicateShare);
        }
        *slot = Some(share.value);
    }

    let mut member_counts = [0u8; CHAMBER_COUNT];
    for (count, row) in member_counts.iter_mut().zip(present.iter()) {
        let present_count = row.iter().filter(|slot| slot.is_some()).count();
        *count = u8::try_from(present_count).unwrap_or(u8::MAX);
    }
    if !is_qualified(structure, member_counts) {
        return Err(Error::NotQualified);
    }

    let mut chamber_secrets: Zeroizing<[Option<Scalar>; CHAMBER_COUNT]> =
        Zeroizing::new([None; CHAMBER_COUNT]);
    let rows = structure
        .inner
        .iter()
        .zip(present.iter())
        .zip(chamber_secrets.iter_mut());
    for ((threshold, row), secret) in rows {
        let (points, count) = chamber_points(row)?;
        let needed = usize::from(threshold.k);
        if count >= needed {
            *secret = Some(interpolate_checked(points.as_ref(), count, needed)?);
        }
    }

    let mut rest_points = Zeroizing::new([(Scalar::ZERO, Scalar::ZERO); REST_CHAMBERS]);
    let mut rest_count = 0usize;
    let rest_present = Chamber::ALL
        .iter()
        .zip(chamber_secrets.iter())
        .filter_map(|(chamber, secret)| chamber.rest_point().zip(*secret));
    for (slot, (point, secret)) in rest_points.iter_mut().zip(rest_present) {
        *slot = (Scalar::from_u64(u64::from(point)), secret);
        rest_count = rest_count.saturating_add(1);
    }
    let rest = Zeroizing::new(interpolate_checked(
        rest_points.as_ref(),
        rest_count,
        REST_THRESHOLD,
    )?);

    let mut total = rest;
    let parties = Chamber::ALL
        .iter()
        .zip(chamber_secrets.iter())
        .filter(|(chamber, _)| chamber.is_party() && structure.includes(**chamber));
    for (_, secret) in parties {
        let party_secret = Zeroizing::new(secret.ok_or(Error::NotQualified)?);
        *total = total.add(&party_secret);
    }
    Ok(*total)
}
