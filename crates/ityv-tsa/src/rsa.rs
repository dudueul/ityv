//! RSASSA-PKCS1-v1_5 signature verification (RFC 8017 §8.2.2), with the
//! public key only.
//!
//! The decrypted block is never parsed. The verifier builds the one
//! encoding EMSA-PKCS1-v1_5 allows for the digest (RFC 8017 §9.2: `00 01`,
//! `FF` padding, `00`, the DER `DigestInfo` with `NULL` parameters) and
//! compares all of it, so lenient-parsing forgeries (Bleichenbacher 2006)
//! have nothing to exploit.
//!
//! `s^e mod n` is computed in Montgomery form by `crypto-bigint` in a fixed
//! 4096-bit width; the modulus may be any odd value of 2048 to 4096 bits.
//! Nothing here is secret, so the variable-time parameter setup is fine.

use crate::alg::DigestAlgorithm;
use crate::error::TsaError;
use crypto_bigint::modular::{FixedMontyForm, FixedMontyParams};
use crypto_bigint::{Odd, U256, U4096};

/// The shortest accepted RSA modulus, in bits.
pub const MIN_RSA_BITS: usize = 2048;
/// The longest accepted RSA modulus, in bits.
pub const MAX_RSA_BITS: usize = 4096;

/// The width of every big-endian value here, in octets.
const WIDTH: usize = MAX_RSA_BITS / 8;

/// An RSA public key whose sizes this crate accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RsaPublicKey<'a> {
    modulus: &'a [u8],
    exponent: &'a [u8],
}

impl<'a> RsaPublicKey<'a> {
    /// Checks a key from the magnitudes of its modulus and public exponent
    /// (as [`der::unsigned`](crate::der::unsigned) returns them: no leading
    /// zero octet).
    ///
    /// The modulus is odd and of 2048 to 4096 bits. The exponent is odd and
    /// `2^16 < e < 2^256` (FIPS 186-5 §5.4): a magnitude of 3 to 32 octets,
    /// and an odd three-octet value is always above `0x010000`.
    pub(crate) fn new(modulus: &'a [u8], exponent: &'a [u8]) -> Result<Self, TsaError> {
        let size_ok = match (modulus.len(), modulus.first()) {
            (256, Some(&top)) => top >= 0x80,
            (257..=WIDTH, _) => true,
            _ => false,
        };
        if !size_ok {
            return Err(TsaError::RsaModulusSize);
        }
        if modulus.last().is_some_and(|last| last & 1 == 0) {
            return Err(TsaError::RsaModulusEven);
        }
        let exponent_ok =
            (3..=32).contains(&exponent.len()) && exponent.last().is_some_and(|last| last & 1 == 1);
        if !exponent_ok {
            return Err(TsaError::RsaExponent);
        }
        Ok(Self { modulus, exponent })
    }

    /// The modulus magnitude (no leading zero octet): what makes the key
    /// one signer's, whatever its public exponent.
    pub(crate) const fn modulus(&self) -> &'a [u8] {
        self.modulus
    }

    /// Verifies `signature` over `digest`, the `digest_algorithm` digest of the message.
    pub(crate) fn verify(
        &self,
        digest_algorithm: DigestAlgorithm,
        digest: &[u8],
        signature: &[u8],
    ) -> Result<(), TsaError> {
        let modulus_len = self.modulus.len();
        // RFC 8017 §8.2.2 step 1: the signature is exactly k octets.
        if signature.len() != modulus_len {
            return Err(TsaError::RsaSignatureLength);
        }
        // Both are at most WIDTH octets, so nothing is truncated.
        let modulus = U4096::from_be_slice_truncated(self.modulus, U4096::BITS);
        let representative = U4096::from_be_slice_truncated(signature, U4096::BITS);
        // RFC 8017 §5.2.2 step 1: the representative is less than n.
        if representative >= modulus {
            return Err(TsaError::RsaSignatureOutOfRange);
        }
        let modulus = Odd::new(modulus)
            .into_option()
            .ok_or(TsaError::RsaModulusEven)?;
        let exponent = U256::from_be_slice_truncated(self.exponent, U256::BITS);
        let params = FixedMontyParams::new_vartime(modulus);
        let message = FixedMontyForm::new(&representative, &params)
            .pow_bounded_exp(&exponent, exponent.bits_vartime())
            .retrieve();
        let expected = encoded_message(digest_algorithm, digest, modulus_len)
            .ok_or(TsaError::SignatureInvalid)?;
        if message.to_be_bytes().as_slice() == expected.as_slice() {
            Ok(())
        } else {
            Err(TsaError::SignatureInvalid)
        }
    }
}

/// EMSA-PKCS1-v1_5 (RFC 8017 §9.2) of `digest` for a `k`-octet modulus,
/// right-aligned in a [`WIDTH`]-octet buffer whose first `WIDTH - k` octets
/// are zero (as the big-endian `m < n` is).
///
/// `EM = 00 01 FF…FF 00 DigestInfo`; for `k >= 256` the padding is always
/// far more than the eight octets §9.2 step 5 demands.
fn encoded_message(algorithm: DigestAlgorithm, digest: &[u8], k: usize) -> Option<[u8; WIDTH]> {
    let prefix = algorithm.digest_info_prefix();
    let t_len = prefix.len().checked_add(digest.len())?;
    let start = WIDTH.checked_sub(k)?;
    let t_start = WIDTH.checked_sub(t_len)?;
    let separator = t_start.checked_sub(1)?;
    let padding_start = start.checked_add(2)?;
    let mut em = [0u8; WIDTH];
    *em.get_mut(start.checked_add(1)?)? = 0x01;
    em.get_mut(padding_start..separator)?.fill(0xFF);
    for (target, source) in em
        .get_mut(t_start..)?
        .iter_mut()
        .zip(prefix.iter().chain(digest))
    {
        *target = *source;
    }
    Some(em)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn modulus(len: usize, top: u8) -> std::vec::Vec<u8> {
        let mut n = std::vec![0xFF; len];
        n[0] = top;
        n
    }

    const E: &[u8] = &[0x01, 0x00, 0x01];

    #[test]
    fn key_sizes() {
        assert!(RsaPublicKey::new(&modulus(256, 0x80), E).is_ok());
        assert_eq!(
            RsaPublicKey::new(&modulus(256, 0x7F), E),
            Err(TsaError::RsaModulusSize)
        );
        assert!(RsaPublicKey::new(&modulus(257, 0x01), E).is_ok());
        assert!(RsaPublicKey::new(&modulus(384, 0xC0), E).is_ok());
        assert!(RsaPublicKey::new(&modulus(512, 0xFF), E).is_ok());
        assert_eq!(
            RsaPublicKey::new(&modulus(513, 0x01), E),
            Err(TsaError::RsaModulusSize)
        );
        assert_eq!(
            RsaPublicKey::new(&modulus(255, 0xFF), E),
            Err(TsaError::RsaModulusSize)
        );
        assert_eq!(RsaPublicKey::new(&[], E), Err(TsaError::RsaModulusSize));
        let mut even = modulus(256, 0xC0);
        even[255] = 0xFE;
        assert_eq!(RsaPublicKey::new(&even, E), Err(TsaError::RsaModulusEven));
    }

    #[test]
    fn exponents() {
        let n = modulus(256, 0xC0);
        assert!(RsaPublicKey::new(&n, &[0x01, 0x00, 0x01]).is_ok());
        assert!(RsaPublicKey::new(&n, &[0x01, 0x00, 0x03]).is_ok());
        assert!(RsaPublicKey::new(&n, &[0xFF; 32]).is_ok());
        for bad in [
            &[0x03][..],
            &[0xFF, 0xFF],
            &[0x01, 0x00, 0x00],
            &[0x01, 0x00, 0x02],
            &[0xFF; 33],
            &[],
        ] {
            assert_eq!(
                RsaPublicKey::new(&n, bad),
                Err(TsaError::RsaExponent),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn encoding_layout() {
        let digest = [0xAB; 32];
        let em = encoded_message(DigestAlgorithm::Sha256, &digest, 256).unwrap();
        let start = WIDTH - 256;
        assert!(em[..start].iter().all(|b| *b == 0));
        assert_eq!(em[start], 0x00);
        assert_eq!(em[start + 1], 0x01);
        let t_start = WIDTH - 19 - 32;
        assert!(em[start + 2..t_start - 1].iter().all(|b| *b == 0xFF));
        assert_eq!(em[t_start - 1], 0x00);
        assert_eq!(
            &em[t_start..t_start + 19],
            DigestAlgorithm::Sha256.digest_info_prefix()
        );
        assert_eq!(&em[t_start + 19..], &digest);
        let full = encoded_message(DigestAlgorithm::Sha512, &[0x11; 64], WIDTH).unwrap();
        assert_eq!(full[0], 0x00);
        assert_eq!(full[1], 0x01);
        assert_eq!(full[2], 0xFF);
        assert_eq!(full[WIDTH - 64 - 19 - 1], 0x00);
        assert_eq!(full[WIDTH - 64 - 19 - 2], 0xFF);
        assert_eq!(
            encoded_message(DigestAlgorithm::Sha512, &[0; 64], WIDTH + 1),
            None
        );
    }

    /// A 2048-bit modulus whose private key is unknown: an arbitrary odd
    /// value with the top bit set.
    fn toy_key() -> std::vec::Vec<u8> {
        let mut n: std::vec::Vec<u8> = (0..256u16)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect();
        n[0] = 0xC5;
        n[255] |= 1;
        n
    }

    #[test]
    fn signature_range() {
        let n = toy_key();
        let key = RsaPublicKey::new(&n, E).unwrap();
        let digest = [0u8; 32];
        let sha = DigestAlgorithm::Sha256;
        // s = n and s > n are refused before any arithmetic.
        assert_eq!(
            key.verify(sha, &digest, &n),
            Err(TsaError::RsaSignatureOutOfRange)
        );
        let mut above = n.clone();
        above[255] = 0xFF;
        above[254] = 0xFF;
        assert_eq!(
            key.verify(sha, &digest, &above),
            Err(TsaError::RsaSignatureOutOfRange)
        );
        assert_eq!(
            key.verify(sha, &digest, &[0xFF; 256]),
            Err(TsaError::RsaSignatureOutOfRange)
        );
        // s = n - 1 is in range (and wrong).
        let mut below = n.clone();
        below[255] &= 0xFE;
        assert_eq!(
            key.verify(sha, &digest, &below),
            Err(TsaError::SignatureInvalid)
        );
        // Short and long signatures, even with the right value.
        assert_eq!(
            key.verify(sha, &digest, &n[1..]),
            Err(TsaError::RsaSignatureLength)
        );
        assert_eq!(
            key.verify(sha, &digest, &[0x01; 255]),
            Err(TsaError::RsaSignatureLength)
        );
        let mut long = std::vec![0u8];
        long.extend_from_slice(&below);
        assert_eq!(
            key.verify(sha, &digest, &long),
            Err(TsaError::RsaSignatureLength)
        );
        // 0 and 1 are their own powers, never a valid encoding.
        let mut one = std::vec![0u8; 256];
        assert_eq!(
            key.verify(sha, &digest, &one),
            Err(TsaError::SignatureInvalid)
        );
        one[255] = 1;
        assert_eq!(
            key.verify(sha, &digest, &one),
            Err(TsaError::SignatureInvalid)
        );
    }
}
