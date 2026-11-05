//! Reading a development bundle (format in `tools/ityv-sim/README.md`,
//! "번들 형식"). Every length is checked against what remains; anything
//! unexpected is an error, not a guess.

use ityv_encoding::Hash512;
use ityv_verify::{AmendableSets, AmendmentInput, FixedSets, GenesisInput};

/// The magic bytes.
pub const MAGIC: &[u8; 8] = b"ITYVSIMB";
/// The only version this reader takes (2: with the optional beacon
/// observation section).
pub const VERSION: u16 = 2;

/// Why a bundle could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundleError {
    /// Not a bundle (magic).
    Magic,
    /// Another version.
    Version,
    /// A length runs past the end, or bytes are left over.
    Truncated,
    /// A section tag out of order, repeated or unknown.
    Section,
    /// A required section is missing.
    Missing,
    /// The scenario name is not UTF-8.
    Name,
}

impl BundleError {
    /// A stable name for the report.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Magic => "Magic",
            Self::Version => "Version",
            Self::Truncated => "Truncated",
            Self::Section => "Section",
            Self::Missing => "Missing",
            Self::Name => "Name",
        }
    }
}

/// The publication deadlines' inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicationInput {
    /// The latest checkpoint's time bucket.
    pub checkpoint: u64,
    /// Buckets of the anchor receipts.
    pub receipts: Vec<u64>,
    /// The close of voting.
    pub close: u64,
    /// When the board was published.
    pub published: Option<u64>,
    /// The current bucket.
    pub now: u64,
}

/// The beacon publication the bundle carries for an audited ledger
/// (fixture data of the simulator): what the console hands the verifier as
/// its observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BeaconInput<'a> {
    /// The round.
    pub round: u64,
    /// The time bucket of its publication.
    pub published: u64,
    /// Its published output.
    pub output: &'a [u8],
}

/// The eight amendable sets, owned as slices into the bundle.
#[derive(Debug, Clone, Default)]
pub struct Sets<'a> {
    boxes: Vec<&'a [u8]>,
    stations: Vec<&'a [u8]>,
    policies: Vec<&'a [u8]>,
    units: Vec<&'a [u8]>,
    routes: Vec<&'a [u8]>,
    roster: Vec<&'a [u8]>,
    modules: Vec<&'a [u8]>,
    appointments: Vec<Hash512>,
}

impl Sets<'_> {
    fn view(&self) -> AmendableSets<'_> {
        AmendableSets {
            boxes: &self.boxes,
            stations: &self.stations,
            progress_policies: &self.policies,
            reporting_units: &self.units,
            routes: &self.routes,
            roster: &self.roster,
            modules: &self.modules,
            appointments: &self.appointments,
        }
    }
}

/// A decoded bundle.
#[derive(Debug, Clone)]
pub struct Bundle<'a> {
    /// The scenario name.
    pub name: &'a str,
    /// The genesis pin.
    pub pin: Hash512,
    signed: &'a [u8],
    sets: Sets<'a>,
    styles: Vec<&'a [u8]>,
    trustees: Vec<&'a [u8]>,
    witnesses: Vec<&'a [u8]>,
    amendments: Vec<(&'a [u8], Sets<'a>)>,
    /// The frame stream.
    pub frames: &'a [u8],
    /// The published events.
    pub events: Vec<&'a [u8]>,
    /// The publication inputs.
    pub publications: PublicationInput,
    /// The beacon observation, if the bundle has one.
    pub beacon: Option<BeaconInput<'a>>,
}

impl Bundle<'_> {
    /// The genesis input.
    #[must_use]
    pub fn genesis(&self) -> GenesisInput<'_> {
        GenesisInput {
            signed: self.signed,
            sets: self.sets.view(),
            fixed: FixedSets {
                ballot_styles: &self.styles,
                trustees: &self.trustees,
                witnesses: &self.witnesses,
            },
        }
    }

    /// The amendments.
    #[must_use]
    pub fn amendments(&self) -> Vec<AmendmentInput<'_>> {
        self.amendments
            .iter()
            .map(|(signed, sets)| AmendmentInput {
                signed,
                sets: sets.view(),
            })
            .collect()
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], BundleError> {
        if n > self.bytes.len() {
            return Err(BundleError::Truncated);
        }
        let (head, rest) = self.bytes.split_at(n);
        self.bytes = rest;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, BundleError> {
        self.take(1)?.first().copied().ok_or(BundleError::Truncated)
    }

    fn u16(&mut self) -> Result<u16, BundleError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes(
            b.try_into().map_err(|_| BundleError::Truncated)?,
        ))
    }

    fn u32(&mut self) -> Result<usize, BundleError> {
        let b = self.take(4)?;
        let v = u32::from_be_bytes(b.try_into().map_err(|_| BundleError::Truncated)?);
        usize::try_from(v).map_err(|_| BundleError::Truncated)
    }

    fn u64(&mut self) -> Result<u64, BundleError> {
        let b = self.take(8)?;
        Ok(u64::from_be_bytes(
            b.try_into().map_err(|_| BundleError::Truncated)?,
        ))
    }

    fn blob(&mut self) -> Result<&'a [u8], BundleError> {
        let n = self.u32()?;
        self.take(n)
    }

    fn list(&mut self) -> Result<Vec<&'a [u8]>, BundleError> {
        let n = self.u32()?;
        // Each entry takes at least its 4-byte length.
        if n > self.bytes.len() / 4 {
            return Err(BundleError::Truncated);
        }
        (0..n).map(|_| self.blob()).collect()
    }

    fn hashes(&mut self) -> Result<Vec<Hash512>, BundleError> {
        let n = self.u32()?;
        if n > self.bytes.len() / 64 {
            return Err(BundleError::Truncated);
        }
        (0..n)
            .map(|_| {
                let b = self.take(64)?;
                let mut h = [0u8; 64];
                h.copy_from_slice(b);
                Ok(Hash512(h))
            })
            .collect()
    }

    fn sets(&mut self) -> Result<Sets<'a>, BundleError> {
        Ok(Sets {
            boxes: self.list()?,
            stations: self.list()?,
            policies: self.list()?,
            units: self.list()?,
            routes: self.list()?,
            roster: self.list()?,
            modules: self.list()?,
            appointments: self.hashes()?,
        })
    }

    fn publications(&mut self) -> Result<PublicationInput, BundleError> {
        let checkpoint = self.u64()?;
        let n = self.u32()?;
        if n > self.bytes.len() / 8 {
            return Err(BundleError::Truncated);
        }
        let receipts = (0..n).map(|_| self.u64()).collect::<Result<Vec<_>, _>>()?;
        let close = self.u64()?;
        let has = self.u8()?;
        let published = self.u64()?;
        let now = self.u64()?;
        Ok(PublicationInput {
            checkpoint,
            receipts,
            close,
            published: (has == 1).then_some(published),
            now,
        })
    }

    fn beacon(&mut self) -> Result<BeaconInput<'a>, BundleError> {
        let round = self.u64()?;
        let published = self.u64()?;
        let output = self.blob()?;
        Ok(BeaconInput {
            round,
            published,
            output,
        })
    }

    fn end(&self) -> Result<(), BundleError> {
        if self.bytes.is_empty() {
            Ok(())
        } else {
            Err(BundleError::Truncated)
        }
    }
}

/// Decodes a bundle.
///
/// # Errors
/// The first problem found.
pub fn decode(bytes: &[u8]) -> Result<Bundle<'_>, BundleError> {
    let mut c = Cursor { bytes };
    if c.take(8)? != MAGIC {
        return Err(BundleError::Magic);
    }
    if c.u16()? != VERSION {
        return Err(BundleError::Version);
    }
    let count = c.u16()?;
    let mut last = 0u16;
    let mut name = None;
    let mut pin = None;
    let mut genesis = None;
    let mut amendments = Vec::new();
    let mut frames = None;
    let mut events = None;
    let mut publications = None;
    let mut beacon = None;
    for _ in 0..count {
        let tag = c.u16()?;
        if tag <= last {
            return Err(BundleError::Section);
        }
        last = tag;
        let mut s = Cursor { bytes: c.blob()? };
        match tag {
            0x0001 => {
                name = Some(core::str::from_utf8(s.bytes).map_err(|_| BundleError::Name)?);
                s.bytes = &[];
            }
            0x0002 => {
                let b = s.take(64)?;
                let mut h = [0u8; 64];
                h.copy_from_slice(b);
                pin = Some(Hash512(h));
            }
            0x0003 => {
                let signed = s.blob()?;
                let sets = s.sets()?;
                let styles = s.list()?;
                let trustees = s.list()?;
                let witnesses = s.list()?;
                genesis = Some((signed, sets, styles, trustees, witnesses));
            }
            0x0004 => {
                let n = s.u32()?;
                if n > s.bytes.len() / 4 {
                    return Err(BundleError::Truncated);
                }
                for _ in 0..n {
                    let signed = s.blob()?;
                    amendments.push((signed, s.sets()?));
                }
            }
            0x0005 => {
                frames = Some(s.bytes);
                s.bytes = &[];
            }
            0x0006 => events = Some(s.list()?),
            0x0007 => publications = Some(s.publications()?),
            0x0008 => beacon = Some(s.beacon()?),
            _ => return Err(BundleError::Section),
        }
        s.end()?;
    }
    c.end()?;
    let (signed, sets, styles, trustees, witnesses) = genesis.ok_or(BundleError::Missing)?;
    Ok(Bundle {
        name: name.ok_or(BundleError::Missing)?,
        pin: pin.ok_or(BundleError::Missing)?,
        signed,
        sets,
        styles,
        trustees,
        witnesses,
        amendments,
        frames: frames.ok_or(BundleError::Missing)?,
        events: events.ok_or(BundleError::Missing)?,
        publications: publications.ok_or(BundleError::Missing)?,
        beacon,
    })
}
