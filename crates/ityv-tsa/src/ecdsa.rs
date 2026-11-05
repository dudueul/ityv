//! ECDSA signature verification on P-256 and P-384 (FIPS 186-5), with the
//! public key only, through the `p256` and `p384` crates.
//!
//! The signature is a strict DER `Ecdsa-Sig-Value` (RFC 5753 §7.2, RFC 5758
//! §3.2) read by this crate's reader; `r` and `s` must be in `[1, n-1]`.
//! The digest is passed whole; the backend truncates it to the order's
//! length (SHA-512 on P-384).

use crate::der::{self, SEQUENCE};
use crate::error::TsaError;
use p256::ecdsa::signature::hazmat::PrehashVerifier as _;

/// A supported curve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Curve {
    P256,
    P384,
}

impl Curve {
    /// The field and order size in octets.
    const fn field_len(self) -> usize {
        match self {
            Self::P256 => 32,
            Self::P384 => 48,
        }
    }
}

/// The longest `r ‖ s`, for P-384.
const MAX_SIGNATURE: usize = 96;

/// An EC public key: an uncompressed SEC1 point of the curve's length
/// (whether it is on the curve is checked when it is used).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EcPublicKey<'a> {
    curve: Curve,
    point: &'a [u8],
}

impl<'a> EcPublicKey<'a> {
    /// Checks the form of `point`: `04 ‖ X ‖ Y`. Compressed points are not
    /// accepted (certificates carry the uncompressed form, RFC 5480 §2.2).
    pub(crate) fn new(curve: Curve, point: &'a [u8]) -> Result<Self, TsaError> {
        let expected = curve
            .field_len()
            .checked_mul(2)
            .and_then(|len| len.checked_add(1));
        if point.first() == Some(&0x04) && Some(point.len()) == expected {
            Ok(Self { curve, point })
        } else {
            Err(TsaError::InvalidEcPoint)
        }
    }

    pub(crate) const fn curve(&self) -> Curve {
        self.curve
    }

    /// The point, SEC1 uncompressed.
    pub(crate) const fn point(&self) -> &'a [u8] {
        self.point
    }

    /// Whether the point is a point of the curve other than the identity,
    /// as [`EcPublicKey::verify`] needs it: decoded by the backend.
    pub(crate) fn on_curve(&self) -> bool {
        match self.curve {
            Curve::P256 => p256::ecdsa::VerifyingKey::from_sec1_bytes(self.point).is_ok(),
            Curve::P384 => p384::ecdsa::VerifyingKey::from_sec1_bytes(self.point).is_ok(),
        }
    }

    /// Verifies the DER `signature` over the message `digest`.
    pub(crate) fn verify(&self, digest: &[u8], signature: &[u8]) -> Result<(), TsaError> {
        let mut fixed = [0u8; MAX_SIGNATURE];
        let fixed = fixed_signature(signature, self.curve.field_len(), &mut fixed)?;
        match self.curve {
            Curve::P256 => {
                let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(self.point)
                    .map_err(|_| TsaError::InvalidEcPoint)?;
                let signature = p256::ecdsa::Signature::from_slice(fixed)
                    .map_err(|_| TsaError::EcdsaSignatureEncoding)?;
                key.verify_prehash(digest, &signature)
                    .map_err(|_| TsaError::SignatureInvalid)
            }
            Curve::P384 => {
                let key = p384::ecdsa::VerifyingKey::from_sec1_bytes(self.point)
                    .map_err(|_| TsaError::InvalidEcPoint)?;
                let signature = p384::ecdsa::Signature::from_slice(fixed)
                    .map_err(|_| TsaError::EcdsaSignatureEncoding)?;
                key.verify_prehash(digest, &signature)
                    .map_err(|_| TsaError::SignatureInvalid)
            }
        }
    }
}

/// Reads `Ecdsa-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }` and writes
/// `r ‖ s`, each left-padded to `field_len` octets, into `out`. Returns the
/// written prefix of `out`.
fn fixed_signature<'o>(
    signature: &[u8],
    field_len: usize,
    out: &'o mut [u8; MAX_SIGNATURE],
) -> Result<&'o [u8], TsaError> {
    let encoding = |_| TsaError::EcdsaSignatureEncoding;
    let mut value = der::single(signature, SEQUENCE).map_err(encoding)?;
    let r = value.unsigned().map_err(encoding)?;
    let s = value.unsigned().map_err(encoding)?;
    value.finish().map_err(encoding)?;
    let total = field_len
        .checked_mul(2)
        .ok_or(TsaError::EcdsaSignatureEncoding)?;
    let (fixed, _) = out
        .split_at_mut_checked(total)
        .ok_or(TsaError::EcdsaSignatureEncoding)?;
    let (r_out, s_out) = fixed
        .split_at_mut_checked(field_len)
        .ok_or(TsaError::EcdsaSignatureEncoding)?;
    for (integer, target) in [(r, r_out), (s, s_out)] {
        // A zero (empty magnitude) is left for the backend, which refuses it.
        let pad = field_len
            .checked_sub(integer.len())
            .ok_or(TsaError::EcdsaSignatureEncoding)?;
        let digits = target
            .get_mut(pad..)
            .ok_or(TsaError::EcdsaSignatureEncoding)?;
        for (digit, source) in digits.iter_mut().zip(integer) {
            *digit = *source;
        }
    }
    Ok(fixed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sig(r: &[u8], s: &[u8]) -> std::vec::Vec<u8> {
        let mut body = std::vec::Vec::new();
        for integer in [r, s] {
            body.push(0x02);
            body.push(u8::try_from(integer.len()).unwrap());
            body.extend_from_slice(integer);
        }
        let mut out = std::vec![0x30, u8::try_from(body.len()).unwrap()];
        out.extend_from_slice(&body);
        out
    }

    #[test]
    fn signature_values() {
        let mut out = [0u8; MAX_SIGNATURE];
        let fixed = fixed_signature(&sig(&[0x01], &[0x00, 0x80]), 32, &mut out).unwrap();
        assert_eq!(fixed.len(), 64);
        assert_eq!(fixed[31], 0x01);
        assert_eq!(fixed[63], 0x80);
        assert!(fixed[..31].iter().all(|b| *b == 0));
        assert!(fixed[32..63].iter().all(|b| *b == 0));

        let full = [0x7F; 48];
        let mut out = [0u8; MAX_SIGNATURE];
        let fixed = fixed_signature(&sig(&full, &full), 48, &mut out).unwrap();
        assert_eq!(fixed, &[0x7F; 96][..]);

        let mut out = [0u8; MAX_SIGNATURE];
        for bad in [
            sig(&[0x01; 33], &[0x01]),
            sig(&[0x01], &[0x80]),
            sig(&[0x00, 0x01], &[0x01]),
            {
                let mut long = sig(&[0x01], &[0x01]);
                long.push(0x00);
                long
            },
            std::vec![0x30, 0x08, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x05, 0x00],
            std::vec![0x30, 0x03, 0x02, 0x01, 0x01],
            std::vec![],
        ] {
            assert_eq!(
                fixed_signature(&bad, 32, &mut out),
                Err(TsaError::EcdsaSignatureEncoding),
                "{bad:02x?}"
            );
        }
    }

    #[test]
    fn scalars_out_of_range_are_refused() {
        // The P-256 test authority's key (tests/vectors/make.sh).
        let certificate = crate::cert::parse(include_bytes!("../tests/vectors/p256.crt")).unwrap();
        let crate::cert::PublicKey::Ec(key) = certificate.key else {
            panic!("an EC key");
        };
        let order: [u8; 32] = [
            0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2,
            0xFC, 0x63, 0x25, 0x51,
        ];
        let mut padded_order = std::vec![0x00];
        padded_order.extend_from_slice(&order);
        let digest = [0x42; 32];
        for (r, s) in [
            (&[0x00][..], &[0x01][..]),
            (&[0x01][..], &[0x00][..]),
            (&padded_order[..], &[0x01][..]),
            (&[0x01][..], &padded_order[..]),
        ] {
            assert_eq!(
                key.verify(&digest, &sig(r, s)),
                Err(TsaError::EcdsaSignatureEncoding),
                "{r:02x?} {s:02x?}"
            );
        }
        // In range and wrong.
        assert_eq!(
            key.verify(&digest, &sig(&[0x01], &[0x01])),
            Err(TsaError::SignatureInvalid)
        );
    }

    #[test]
    fn point_forms() {
        let mut point = std::vec![0x04];
        point.extend_from_slice(&[0x11; 64]);
        assert!(EcPublicKey::new(Curve::P256, &point).is_ok());
        assert_eq!(
            EcPublicKey::new(Curve::P384, &point),
            Err(TsaError::InvalidEcPoint)
        );
        point[0] = 0x02;
        assert_eq!(
            EcPublicKey::new(Curve::P256, &point),
            Err(TsaError::InvalidEcPoint)
        );
        let mut p384 = std::vec![0x04];
        p384.extend_from_slice(&[0x22; 96]);
        let key = EcPublicKey::new(Curve::P384, &p384).unwrap();
        assert_eq!(key.curve(), Curve::P384);
        // Not on the curve: refused when used.
        let r = [0x01; 48];
        assert_eq!(
            key.verify(&[0; 48], &sig(&r, &r)),
            Err(TsaError::InvalidEcPoint)
        );
        let mut compressed = std::vec![0x03];
        compressed.extend_from_slice(&[0x11; 32]);
        assert_eq!(
            EcPublicKey::new(Curve::P256, &compressed),
            Err(TsaError::InvalidEcPoint)
        );
        assert_eq!(
            EcPublicKey::new(Curve::P256, &[]),
            Err(TsaError::InvalidEcPoint)
        );
    }
}
