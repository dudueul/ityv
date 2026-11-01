//! The election configuration the host builds from genesis (ADR-0017 §2).
//!
//! Everything the unit needs to know about the election is typed here and
//! validated once in [`ElectionConfig::new`]; the ballot flow then never
//! sees a raw identifier or an unchecked count.
//!
//! A chamber module serves exactly one chamber. Delegation to a neutral
//! module (PROTOCOL.md §7.1) is modelled as one *logical* module per
//! delegated chamber with `neutral = true`; the host may implement several
//! such logical modules over one physical device, each with its own
//! identifier, counter and port. Chambers X and Y must have a non-neutral
//! module; N never has one and always receives KEM transport.

use ityv_crypto::{AccessStructure, Chamber, HybridKemPublicKey, OptionCount};
use ityv_encoding::{
    BallotStyleId, BoxId, ChamberCode, ElectionId, MAX_SECRETS, ModuleId, StationId, TrusteeId,
};

use crate::error::{ConfigFault, Error};

/// Maximum number of modules (one per chamber with a module).
pub const MAX_MODULES: usize = 6;

// Five chambers can hold a module (N never does) and a style has at most
// eight chunks, so a member receives at most 5·8 + 2 = 42 secrets: every
// valid configuration fits the fifty-share `MemberShare` capacity.
const _: () = assert!(5 * ityv_crypto::MAX_CHUNKS + 2 <= MAX_SECRETS);
/// Maximum number of trustees over all chambers.
pub const MAX_TRUSTEES: usize = 64;
/// Maximum number of ballot styles a box may receive.
pub const MAX_STYLES: usize = 64;

/// Whether the box receives in-person ballots or absentee/overseas ballots
/// (which carry an envelope label, PROTOCOL.md §7.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Profile {
    /// Ballots drop into the box; no envelope label.
    InPerson,
    /// Ballots go to the return tray with an envelope label.
    Absentee,
}

impl Profile {
    /// `true` for the absentee profile, which derives an envelope label.
    #[must_use]
    pub const fn has_label(self) -> bool {
        matches!(self, Self::Absentee)
    }
}

/// A ballot style: its identifier and option set `m + 2`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BallotStyle<'a> {
    id: BallotStyleId<'a>,
    option_count: OptionCount,
}

impl<'a> BallotStyle<'a> {
    /// Builds a style.
    #[must_use]
    pub const fn new(id: BallotStyleId<'a>, option_count: OptionCount) -> Self {
        Self { id, option_count }
    }

    /// The identifier.
    #[must_use]
    pub const fn id(&self) -> BallotStyleId<'a> {
        self.id
    }

    /// The option set `m + 2`.
    #[must_use]
    pub const fn option_count(&self) -> OptionCount {
        self.option_count
    }

    /// The chunk count `k`.
    #[must_use]
    pub fn chunk_count(&self) -> u8 {
        self.option_count.chunk_count()
    }
}

/// One logical chamber module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ModuleConfig<'a> {
    module_id: ModuleId<'a>,
    chamber: Chamber,
    neutral: bool,
}

impl<'a> ModuleConfig<'a> {
    /// Builds a module entry. `neutral` marks a module supplied by the
    /// Independent Verification Committee for a delegated chamber.
    #[must_use]
    pub const fn new(module_id: ModuleId<'a>, chamber: Chamber, neutral: bool) -> Self {
        Self {
            module_id,
            chamber,
            neutral,
        }
    }

    /// The identifier.
    #[must_use]
    pub const fn module_id(&self) -> ModuleId<'a> {
        self.module_id
    }

    /// The chamber served.
    #[must_use]
    pub const fn chamber(&self) -> Chamber {
        self.chamber
    }

    /// Whether this is a neutral (delegated) module.
    #[must_use]
    pub const fn is_neutral(&self) -> bool {
        self.neutral
    }
}

/// One trustee member.
#[derive(Debug, Clone, Copy)]
pub struct TrusteeConfig<'a> {
    trustee_id: TrusteeId<'a>,
    chamber: Chamber,
    member_index: u8,
    pad_id: u32,
    kem_public_key: &'a HybridKemPublicKey,
}

impl<'a> TrusteeConfig<'a> {
    /// Builds a trustee entry. `member_index` is the member's position
    /// within its chamber (`0..n_c`), `pad_id` the identifier of the pad
    /// copy the member holds.
    #[must_use]
    pub const fn new(
        trustee_id: TrusteeId<'a>,
        chamber: Chamber,
        member_index: u8,
        pad_id: u32,
        kem_public_key: &'a HybridKemPublicKey,
    ) -> Self {
        Self {
            trustee_id,
            chamber,
            member_index,
            pad_id,
            kem_public_key,
        }
    }

    /// The identifier.
    #[must_use]
    pub const fn trustee_id(&self) -> TrusteeId<'a> {
        self.trustee_id
    }

    /// The chamber.
    #[must_use]
    pub const fn chamber(&self) -> Chamber {
        self.chamber
    }

    /// The member index within the chamber.
    #[must_use]
    pub const fn member_index(&self) -> u8 {
        self.member_index
    }

    /// The pad identifier.
    #[must_use]
    pub const fn pad_id(&self) -> u32 {
        self.pad_id
    }

    /// The member's KEM public key from genesis.
    #[must_use]
    pub const fn kem_public_key(&self) -> &'a HybridKemPublicKey {
        self.kem_public_key
    }
}

/// Unvalidated inputs for [`ElectionConfig::new`].
#[derive(Debug, Clone, Copy)]
pub struct ConfigParts<'a> {
    /// The election.
    pub election_id: ElectionId<'a>,
    /// The ballot box this unit serves.
    pub box_id: BoxId<'a>,
    /// The polling station (printed on slips).
    pub station_id: StationId<'a>,
    /// The ballot profile.
    pub profile: Profile,
    /// The ballot styles the box receives (at least one, distinct ids).
    pub styles: &'a [BallotStyle<'a>],
    /// The modules present, strictly ascending by identifier.
    pub modules: &'a [ModuleConfig<'a>],
    /// The trustees, strictly ascending by identifier.
    pub trustees: &'a [TrusteeConfig<'a>],
    /// The chamber access structure (per-chamber thresholds).
    pub access: AccessStructure,
    /// Whether the `VOTER_CODE` scope is active (slips are printed).
    pub voter_code_enabled: bool,
}

/// The validated configuration.
#[derive(Debug, Clone, Copy)]
pub struct ElectionConfig<'a> {
    parts: ConfigParts<'a>,
}

fn ascending<T>(items: &[T], key: impl Fn(&T) -> &[u8]) -> bool {
    items.windows(2).all(|pair| match pair {
        [a, b] => key(a) < key(b),
        _ => true,
    })
}

impl<'a> ElectionConfig<'a> {
    /// Validates `parts` (ADR-0017 §2).
    ///
    /// # Errors
    /// [`Error::Config`] with the first violated [`ConfigFault`].
    pub fn new(parts: ConfigParts<'a>) -> Result<Self, Error> {
        Self::check_modules(parts.modules)?;
        Self::check_trustees(parts.trustees, &parts.access)?;
        Self::check_styles(&parts)?;
        Ok(Self { parts })
    }

    fn check_modules(modules: &[ModuleConfig<'_>]) -> Result<(), ConfigFault> {
        if modules.len() > MAX_MODULES || !ascending(modules, |m| m.module_id.as_bytes()) {
            return Err(ConfigFault::ModulesUnsorted);
        }
        let mut per_chamber = [0u8; ityv_crypto::CHAMBER_COUNT];
        for module in modules {
            if let Some(slot) = per_chamber.get_mut(module.chamber.index()) {
                *slot = slot.saturating_add(1);
            }
            let mandatory_neutral = module.chamber.is_mandatory() && module.neutral;
            if matches!(module.chamber, Chamber::N) || mandatory_neutral {
                return Err(ConfigFault::ChamberModules);
            }
        }
        let x = per_chamber.get(Chamber::X.index()).copied().unwrap_or(0);
        let y = per_chamber.get(Chamber::Y.index()).copied().unwrap_or(0);
        if x != 1 || y != 1 || per_chamber.iter().any(|&n| n > 1) {
            return Err(ConfigFault::ChamberModules);
        }
        Ok(())
    }

    fn check_trustees(
        trustees: &[TrusteeConfig<'_>],
        access: &AccessStructure,
    ) -> Result<(), ConfigFault> {
        if trustees.len() > MAX_TRUSTEES || !ascending(trustees, |t| t.trustee_id.as_bytes()) {
            return Err(ConfigFault::TrusteesUnsorted);
        }
        for chamber in Chamber::ALL {
            let n = usize::from(access.threshold(chamber).n());
            let mut seen = [false; ityv_crypto::MAX_MEMBERS];
            let mut count = 0usize;
            for trustee in trustees.iter().filter(|t| t.chamber == chamber) {
                count = count.saturating_add(1);
                match seen.get_mut(usize::from(trustee.member_index)) {
                    Some(slot) if !*slot && usize::from(trustee.member_index) < n => *slot = true,
                    Some(_) | None => return Err(ConfigFault::MemberIndices),
                }
            }
            if count != n {
                return Err(ConfigFault::ThresholdCount);
            }
        }
        Ok(())
    }

    fn check_styles(parts: &ConfigParts<'_>) -> Result<(), ConfigFault> {
        let styles = parts.styles;
        if styles.is_empty() || styles.len() > MAX_STYLES {
            return Err(ConfigFault::Styles);
        }
        for (i, a) in styles.iter().enumerate() {
            if styles
                .iter()
                .skip(i.saturating_add(1))
                .any(|b| b.id.as_bytes() == a.id.as_bytes())
            {
                return Err(ConfigFault::Styles);
            }
        }
        Ok(())
    }

    /// The election.
    #[must_use]
    pub const fn election_id(&self) -> ElectionId<'a> {
        self.parts.election_id
    }

    /// The ballot box.
    #[must_use]
    pub const fn box_id(&self) -> BoxId<'a> {
        self.parts.box_id
    }

    /// The polling station.
    #[must_use]
    pub const fn station_id(&self) -> StationId<'a> {
        self.parts.station_id
    }

    /// The ballot profile.
    #[must_use]
    pub const fn profile(&self) -> Profile {
        self.parts.profile
    }

    /// The ballot styles.
    #[must_use]
    pub const fn styles(&self) -> &'a [BallotStyle<'a>] {
        self.parts.styles
    }

    /// The modules, ascending by identifier.
    #[must_use]
    pub const fn modules(&self) -> &'a [ModuleConfig<'a>] {
        self.parts.modules
    }

    /// The trustees, ascending by identifier.
    #[must_use]
    pub const fn trustees(&self) -> &'a [TrusteeConfig<'a>] {
        self.parts.trustees
    }

    /// The access structure.
    #[must_use]
    pub const fn access(&self) -> &AccessStructure {
        &self.parts.access
    }

    /// Whether slips are printed.
    #[must_use]
    pub const fn voter_code_enabled(&self) -> bool {
        self.parts.voter_code_enabled
    }

    /// The style with identifier `id`, with its index.
    #[must_use]
    pub fn style(&self, id: BallotStyleId<'_>) -> Option<(usize, &'a BallotStyle<'a>)> {
        self.parts
            .styles
            .iter()
            .enumerate()
            .find(|(_, s)| s.id.as_bytes() == id.as_bytes())
    }

    /// The module serving `chamber`, with its index, if any.
    #[must_use]
    pub fn module_for(&self, chamber: Chamber) -> Option<(usize, &'a ModuleConfig<'a>)> {
        self.parts
            .modules
            .iter()
            .enumerate()
            .find(|(_, m)| m.chamber == chamber)
    }

    /// Number of secrets shared with every member for `style`
    /// (`modules × k + 1`, plus one for the envelope label).
    #[must_use]
    pub fn secret_count(&self, style: &BallotStyle<'_>) -> usize {
        secret_count(
            self.parts.modules.len(),
            style.chunk_count(),
            self.parts.profile,
        )
    }

    /// Whether any configured module is neutral (sets `transport_flags`
    /// bit 1 on every record).
    #[must_use]
    pub fn uses_neutral_module(&self) -> bool {
        self.parts.modules.iter().any(|m| m.neutral)
    }
}

/// `modules × k + 1 (+ 1 for the envelope label)`.
#[must_use]
pub fn secret_count(module_count: usize, chunk_count: u8, profile: Profile) -> usize {
    module_count
        .saturating_mul(usize::from(chunk_count))
        .saturating_add(1)
        .saturating_add(usize::from(profile.has_label()))
}

/// The wire code of a chamber (ENCODING.md §8.10).
#[must_use]
pub const fn chamber_code(chamber: Chamber) -> ChamberCode {
    match chamber {
        Chamber::X => ChamberCode::X,
        Chamber::Y => ChamberCode::Y,
        Chamber::J => ChamberCode::J,
        Chamber::A => ChamberCode::A,
        Chamber::C => ChamberCode::C,
        Chamber::N => ChamberCode::N,
    }
}

/// The chamber of a wire code.
#[must_use]
pub const fn chamber_of(code: ChamberCode) -> Chamber {
    match code {
        ChamberCode::X => Chamber::X,
        ChamberCode::Y => Chamber::Y,
        ChamberCode::J => Chamber::J,
        ChamberCode::A => Chamber::A,
        ChamberCode::C => Chamber::C,
        ChamberCode::N => Chamber::N,
    }
}
