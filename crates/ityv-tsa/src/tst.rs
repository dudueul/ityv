//! `TSTInfo` (RFC 3161 §2.4.2), read strictly.
//!
//! ```text
//! TSTInfo ::= SEQUENCE {
//!    version        INTEGER { v1(1) },
//!    policy         TSAPolicyId,
//!    messageImprint MessageImprint,
//!    serialNumber   INTEGER,            -- up to 160 bits
//!    genTime        GeneralizedTime,
//!    accuracy       Accuracy            OPTIONAL,
//!    ordering       BOOLEAN             DEFAULT FALSE,
//!    nonce          INTEGER             OPTIONAL,
//!    tsa            [0] GeneralName     OPTIONAL,
//!    extensions     [1] IMPLICIT Extensions OPTIONAL }
//! ```

use crate::alg::{self, DigestAlgorithm};
use crate::cert;
use crate::der::{
    self, BOOLEAN, CONTEXT_0, CONTEXT_1, GENERALIZED_TIME, INTEGER, PRIMITIVE_0, PRIMITIVE_1,
    Reader, SEQUENCE, Tlv,
};
use crate::error::{DerError, TsaError};
use crate::time::{self, GenTime};

/// The longest serial number magnitude, in octets (160 bits, RFC 3161 §2.4.2).
pub const MAX_SERIAL_LEN: usize = 20;

/// The longest nonce magnitude, in octets (256 bits).
pub const MAX_NONCE_LEN: usize = 32;

/// The accuracy of `genTime` (RFC 3161 §2.4.2). A missing field is zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Accuracy {
    seconds: u64,
    millis: u16,
    micros: u16,
}

impl Accuracy {
    /// Whole seconds.
    #[must_use]
    pub const fn seconds(&self) -> u64 {
        self.seconds
    }

    /// Milliseconds, `0..=999`.
    #[must_use]
    pub const fn millis(&self) -> u16 {
        self.millis
    }

    /// Microseconds, `0..=999`.
    #[must_use]
    pub const fn micros(&self) -> u16 {
        self.micros
    }
}

/// The parts of a `TSTInfo`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TstInfo<'a> {
    /// The policy's `OBJECT IDENTIFIER` content octets.
    pub(crate) policy: &'a [u8],
    pub(crate) imprint_algorithm: DigestAlgorithm,
    pub(crate) imprint: &'a [u8],
    /// The serial number's magnitude octets.
    pub(crate) serial: &'a [u8],
    pub(crate) gen_time: GenTime,
    pub(crate) accuracy: Option<Accuracy>,
    pub(crate) ordering: bool,
    /// The nonce's magnitude octets.
    pub(crate) nonce: Option<&'a [u8]>,
    /// The `tsa` `GeneralName`, whole encoding.
    pub(crate) tsa: Option<Tlv<'a>>,
}

/// Reads a `TSTInfo` that is the whole of `content`.
pub(crate) fn parse(content: &[u8]) -> Result<TstInfo<'_>, TsaError> {
    let mut info = der::single(content, SEQUENCE)?;
    if der::small_unsigned(info.read(INTEGER)?.value)? != 1 {
        return Err(TsaError::TstInfoVersion);
    }
    let policy = info.oid()?;
    let mut imprint = info.sequence()?;
    let imprint_algorithm = alg::read_digest_algorithm(&mut imprint)?;
    let hashed_message = imprint.octets()?;
    imprint.finish()?;
    let serial = info.unsigned()?;
    if serial.len() > MAX_SERIAL_LEN {
        return Err(TsaError::SerialTooLarge);
    }
    let gen_time = time::generalized_time(info.read(GENERALIZED_TIME)?.value, true)?;
    let accuracy = if info.peek_tag() == Some(SEQUENCE) {
        Some(read_accuracy(info.sequence()?)?)
    } else {
        None
    };
    let ordering = match info.optional(BOOLEAN)? {
        Some(flag) if der::boolean(flag.value)? => true,
        Some(_) => return Err(TsaError::Der(DerError::DefaultEncoded)),
        None => false,
    };
    let nonce = match info.optional(INTEGER)? {
        Some(nonce) => {
            let magnitude = der::unsigned(nonce.value)?;
            if magnitude.len() > MAX_NONCE_LEN {
                return Err(TsaError::NonceTooLarge);
            }
            Some(magnitude)
        }
        None => None,
    };
    let tsa = match info.optional(CONTEXT_0)? {
        Some(explicit) => {
            let mut name = info.enter(&explicit)?;
            let general_name = name.checked_any()?;
            name.finish()?;
            Some(general_name)
        }
        None => None,
    };
    if let Some(extensions) = info.optional(CONTEXT_1)? {
        read_extensions(info.enter(&extensions)?)?;
    }
    info.finish()?;
    Ok(TstInfo {
        policy,
        imprint_algorithm,
        imprint: hashed_message,
        serial,
        gen_time,
        accuracy,
        ordering,
        nonce,
        tsa,
    })
}

/// `Accuracy ::= SEQUENCE { seconds INTEGER OPTIONAL,
/// millis [0] INTEGER (1..999) OPTIONAL, micros [1] INTEGER (1..999) OPTIONAL }`.
fn read_accuracy(mut accuracy: Reader<'_>) -> Result<Accuracy, TsaError> {
    let seconds = match accuracy.optional(INTEGER)? {
        Some(seconds) => der::small_unsigned(seconds.value)?,
        None => 0,
    };
    let millis = sub_second(accuracy.optional(PRIMITIVE_0)?)?;
    let micros = sub_second(accuracy.optional(PRIMITIVE_1)?)?;
    accuracy.finish()?;
    Ok(Accuracy {
        seconds,
        millis,
        micros,
    })
}

/// An optional `millis` or `micros` field: absent is zero, present is `1..=999`.
fn sub_second(field: Option<Tlv<'_>>) -> Result<u16, TsaError> {
    let Some(field) = field else {
        return Ok(0);
    };
    let value = der::small_unsigned(field.value)?;
    u16::try_from(value)
        .ok()
        .filter(|value| (1..=999).contains(value))
        .ok_or(TsaError::InvalidAccuracy)
}

/// `Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension`. No `TSTInfo`
/// extension is understood, so a critical one is refused (RFC 5280 §4.2
/// semantics); a non-critical one is ignored.
fn read_extensions(mut list: Reader<'_>) -> Result<(), TsaError> {
    if list.is_empty() {
        return Err(TsaError::EmptyExtensions);
    }
    while !list.is_empty() {
        if cert::read_extension(&mut list)?.critical {
            return Err(TsaError::CriticalExtension);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accuracy_fields() {
        let read = |bytes: &[u8]| read_accuracy(Reader::new(bytes));
        assert_eq!(
            read(&[0x02, 0x01, 0x01, 0x80, 0x02, 0x01, 0xF4, 0x81, 0x01, 0x64]),
            Ok(Accuracy {
                seconds: 1,
                millis: 500,
                micros: 100
            })
        );
        assert_eq!(
            read(&[]),
            Ok(Accuracy {
                seconds: 0,
                millis: 0,
                micros: 0
            })
        );
        assert_eq!(read(&[0x80, 0x02, 0x03, 0xE7]).map(|a| a.millis()), Ok(999));
        assert_eq!(read(&[0x81, 0x01, 0x01]).map(|a| a.micros()), Ok(1));
        assert_eq!(
            read(&[0x80, 0x02, 0x03, 0xE8]),
            Err(TsaError::InvalidAccuracy)
        );
        assert_eq!(read(&[0x81, 0x01, 0x00]), Err(TsaError::InvalidAccuracy));
        assert_eq!(
            read(&[0x81, 0x01, 0x01, 0x80, 0x01, 0x01]),
            Err(TsaError::Der(DerError::TrailingData))
        );
        assert_eq!(
            read(&[0x80, 0x09, 0x01, 0, 0, 0, 0, 0, 0, 0, 0]),
            Err(TsaError::Der(DerError::IntegerTooLarge))
        );
        assert_eq!(
            read(&[0x80, 0x05, 0x01, 0x00, 0x00, 0x00, 0x01]),
            Err(TsaError::InvalidAccuracy)
        );
        assert_eq!(read(&[0x02, 0x01, 0x07]).map(|a| a.seconds()), Ok(7));
    }

    #[test]
    fn extension_lists() {
        let critical = [
            0x30, 0x0A, 0x06, 0x03, 0x2A, 0x03, 0x04, 0x01, 0x01, 0xFF, 0x04, 0x00,
        ];
        let plain = [0x30, 0x07, 0x06, 0x03, 0x2A, 0x03, 0x04, 0x04, 0x00];
        assert_eq!(
            read_extensions(Reader::new(&critical)),
            Err(TsaError::CriticalExtension)
        );
        assert_eq!(read_extensions(Reader::new(&plain)), Ok(()));
        let mut both = plain.to_vec();
        both.extend_from_slice(&critical);
        assert_eq!(
            read_extensions(Reader::new(&both)),
            Err(TsaError::CriticalExtension)
        );
        assert_eq!(
            read_extensions(Reader::new(&[])),
            Err(TsaError::EmptyExtensions)
        );
    }
}
