//! Binding verification tokens to the signatures an event carries.
//!
//! This crate does not verify signatures. `ityv_crypto::verify_hybrid`
//! does, and returns a `Verified<HybridSigned>` token naming the key, the
//! purpose, the object bytes and the signature it checked. Here a token is
//! accepted for one signature on one event only if all four match: the
//! purpose of the event, its body bytes, the signature bytes the event
//! carries, and the key the genesis registers for that signer in that role
//! (ADR-0025 decision 2).
//!
//! Every signer on one event must also hold a key that shares no half
//! (ML-DSA-87 or Ed25519) with another signer's key: one person registered
//! twice, or two bodies sharing a key half, must not count as two
//! independent signatures (VC-006, VC-016, VC-098).

use ityv_crypto::sig::MLDSA87_SIG_LEN;
use ityv_crypto::{HybridSignature, HybridSigned, HybridVerifyingKey, Verified};
use ityv_encoding::{EventSig, HYBRID_SIG_LEN, MAX_EVENT_SIGS, WitnessedEvent};

use crate::error::Error;

/// A signed event and the verification tokens of its signatures, one per
/// signature in the event's (ascending signer) order.
#[derive(Debug, Clone, Copy)]
pub struct Signed<'s> {
    /// The event.
    pub event: &'s WitnessedEvent<'s>,
    /// The tokens, in signature order.
    pub tokens: &'s [Verified<HybridSigned<'s>>],
}

/// Whether two keys share neither half.
#[must_use]
pub fn halves_differ(a: &HybridVerifyingKey, b: &HybridVerifyingKey) -> bool {
    a.mldsa87() != b.mldsa87() && a.ed25519() != b.ed25519()
}

/// Whether `bytes` is the encoding of `signature`.
pub(crate) fn same_signature(bytes: &[u8; HYBRID_SIG_LEN], signature: &HybridSignature) -> bool {
    match bytes.split_first_chunk::<MLDSA87_SIG_LEN>() {
        Some((mldsa87, ed25519)) => {
            mldsa87 == signature.mldsa87() && ed25519 == signature.ed25519().as_slice()
        }
        None => false,
    }
}

/// Checks that `token` covers `object` under `purpose` with signature
/// `sig`, from `key`.
///
/// # Errors
/// [`Error::SignatureObject`] if the purpose, object or signature bytes
/// differ, [`Error::SignatureSigner`] if the key differs.
pub(crate) fn check_token(
    token: &Verified<HybridSigned<'_>>,
    object: &[u8],
    purpose: &[u8],
    sig: &[u8; HYBRID_SIG_LEN],
    key: &HybridVerifyingKey,
) -> Result<(), Error> {
    let signed = token.get();
    if signed.purpose().as_bytes() != purpose
        || signed.object() != object
        || !same_signature(sig, signed.signature())
    {
        return Err(Error::SignatureObject);
    }
    if signed.key() != key {
        return Err(Error::SignatureSigner);
    }
    Ok(())
}

/// Checks every signature of `signed.event` against its token and the key
/// `key_of` registers for it, and that no two signers share a key half.
///
/// # Errors
/// [`Error::Unverified`] if the number of tokens differs from the number
/// of signatures, the error of `key_of` for an unregistered signer,
/// [`Error::SignatureObject`] for a token over another purpose, object or
/// signature, [`Error::SignatureSigner`] for a token from another key or
/// if two signers' keys share a half.
pub fn check_event<'k, F>(signed: &Signed<'_>, key_of: F) -> Result<(), Error>
where
    F: Fn(&EventSig<'_>) -> Result<&'k HybridVerifyingKey, Error>,
{
    let event = signed.event;
    let pairs = event.sigs().map(|s| key_of(&s).map(|key| (s.sig, key)));
    check_pairs(
        event.body_bytes(),
        event.purpose(),
        signed.tokens,
        event.sig_count(),
        pairs,
    )
}

/// Checks `count` (signature bytes, registered key) pairs over `object`
/// under `purpose` against `tokens`, in order, and that no two keys share
/// a half.
///
/// # Errors
/// As [`check_event`].
pub(crate) fn check_pairs<'s, 'k, I>(
    object: &[u8],
    purpose: &[u8],
    tokens: &[Verified<HybridSigned<'_>>],
    count: usize,
    pairs: I,
) -> Result<(), Error>
where
    I: Iterator<Item = Result<(&'s [u8; HYBRID_SIG_LEN], &'k HybridVerifyingKey), Error>>,
{
    if tokens.len() != count {
        return Err(Error::Unverified);
    }
    let mut keys: [Option<&HybridVerifyingKey>; MAX_EVENT_SIGS] = [None; MAX_EVENT_SIGS];
    for (index, (pair, token)) in pairs.zip(tokens).enumerate() {
        let (sig, key) = pair?;
        check_token(token, object, purpose, sig, key)?;
        let shared = keys
            .iter()
            .flatten()
            .any(|other| !halves_differ(other, key));
        if shared {
            return Err(Error::SignatureSigner);
        }
        // Both envelopes carry at most eight signatures; more cannot be
        // compared for shared halves, so they are refused.
        let Some(slot) = keys.get_mut(index) else {
            return Err(Error::Unverified);
        };
        *slot = Some(key);
    }
    Ok(())
}
