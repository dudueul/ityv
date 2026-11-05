//! RFC 3161 timestamp token verification for ityv (ADR-0034 §6, ADR-0037).
//!
//! [`verify_token`] checks one DER `TimeStampToken` against one pinned
//! authority ([`PinnedTsa`], in the byte form a genesis holds) and one
//! expected [`Imprint`], and returns a [`VerifiedTimestamp`]: the time, the
//! policy, serial, nonce and accuracy, and which pinned certificate verified
//! it. The ledger verifier takes only that result.
//!
//! Properties that hold by construction:
//!
//! * `#![no_std]`, no heap allocation, no `unsafe`, no panics (the workspace
//!   lint set; Kani harnesses under `cfg(kani)` for the reader and the time
//!   parser; the proptests and the fuzz target for the whole token).
//! * One strict DER subset for the whole token: definite minimal lengths,
//!   one-octet tags, at most [`MAX_DEPTH`] levels and [`MAX_TOKEN_LEN`]
//!   octets, minimal `INTEGER`s, `BOOLEAN` `0x00`/`0xFF`, `NULL` empty, valid
//!   object identifiers, zero `BIT STRING` padding, primitive strings and
//!   times, and `SET OF` elements in DER order. The structures this crate
//!   interprets are also read whole (every `SEQUENCE` consumed, no `DEFAULT`
//!   value written out). The parts it does not interpret (names, chain
//!   certificates, unknown attributes and extension values) get the DER
//!   checks only, so a `DEFAULT` written out there is not noticed. Two
//!   unsigned sets, the embedded certificates and the unsigned attributes,
//!   may be in any order. Unknown critical extensions are refused, except a
//!   critical certificate policies extension, which is DER-checked and not
//!   interpreted.
//! * The signer's certificate is pinned by its SHA-256, not path-validated;
//!   its extended key usage must be critical and exactly timestamping.
//! * Signatures: RSASSA-PKCS1-v1_5 with SHA-256/384/512 over a 2048- to
//!   4096-bit modulus, verified by encoding and comparing the whole block;
//!   ECDSA P-256/SHA-256, P-384/SHA-384 and P-384/SHA-512. Only what the pin
//!   allows.
//! * The time is an interval: [`VerifiedTimestamp::earliest`] and
//!   [`VerifiedTimestamp::latest`] are `genTime` ∓ the accuracy, computed
//!   without overflow (the accuracy is at most [`MAX_ACCURACY_SECONDS`]).
//!
//! What this crate does **not** prove: that the asserted time is true (an
//! authority could sign any time; ADR-0034 requires two operators), that the
//! certificate is unrevoked, or anything about the data beyond its digest.
//! Nor does it make token bytes unique: the unsigned parts (certificates,
//! unsigned attributes, the signer identifier's form) and an ECDSA
//! signature's `s` (`n − s` verifies too) can change without changing the
//! result, so a ledger counts tokens per authority, never per token bytes.
//! It takes no expected nonce; the requester checks the nonce of the reply.
//!
//! ```
//! use ityv_tsa::{
//!     DerError, DigestAlgorithm, DigestSet, Imprint, PinnedTsa, SignatureAlgorithm,
//!     SignatureSet, TsaError, verify_token,
//! };
//!
//! // The genesis holds the authority's pin as bytes (made here from parts).
//! let digests = DigestSet::from_bits(DigestAlgorithm::Sha256.bit() | DigestAlgorithm::Sha512.bit())
//!     .ok_or("digest mask")?;
//! let signatures =
//!     SignatureSet::from_bits(SignatureAlgorithm::EcdsaP384Sha384.bit()).ok_or("signature mask")?;
//! let policy = [0x06, 0x03, 0x2A, 0x03, 0x04]; // 1.2.3.4
//! let certificate_sha256 = [0x11; 32];
//! let pin = PinnedTsa::new(certificate_sha256, digests, signatures, false, &policy, None)?;
//! let mut genesis_bytes = [0u8; 64];
//! let len = pin.encode(&mut genesis_bytes)?;
//! let pin = PinnedTsa::from_bytes(&genesis_bytes[..len])?;
//!
//! // ADR-0034 §3: the imprint is SHA-512 of the 64-octet checkpoint object hash.
//! let checkpoint_object_hash = [0x22; 64];
//! let expected = Imprint::of(DigestAlgorithm::Sha512, &checkpoint_object_hash);
//!
//! // Anything but a valid token of that authority over that imprint is
//! // refused with the rule it breaks.
//! let refused = verify_token(&[0x30, 0x00], &pin, &expected);
//! assert_eq!(refused, Err(TsaError::Der(DerError::MissingField)));
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```
//!
//! The public API is re-exported at the crate root; the module structure is
//! an implementation detail.
#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;

mod alg;
mod cert;
mod cms;
mod der;
mod ecdsa;
mod error;
mod oid;
mod pin;
mod rsa;
mod time;
mod tst;
mod verify;

// Kani harnesses live outside `src/` because they carry a file-level lint
// relaxation, which CONSTITUTION.md §1.1 forbids under `src/`.
#[cfg(kani)]
#[path = "../kani/proofs.rs"]
mod proofs;

/// The longest token accepted, in octets (16 KiB). A token with an
/// RSA-4096 signature and a three-certificate chain fits with room to spare.
pub const MAX_TOKEN_LEN: usize = 16 * 1024;

pub use alg::{DigestAlgorithm, DigestSet, Imprint, SignatureAlgorithm, SignatureSet};
pub use cms::MAX_CERTIFICATES;
pub use der::{MAX_DEPTH, MAX_OID_LEN};
pub use error::{DerError, TsaError};
pub use oid::ObjectId;
pub use pin::{MAX_POLICIES, PIN_FORMAT_VERSION, PinnedTsa, Policies, SignerKey};
pub use rsa::{MAX_RSA_BITS, MIN_RSA_BITS};
pub use time::GenTime;
pub use tst::{Accuracy, MAX_ACCURACY_SECONDS, MAX_NONCE_LEN, MAX_SERIAL_LEN};
pub use verify::{CertificateSource, VerifiedTimestamp, verify_token};
