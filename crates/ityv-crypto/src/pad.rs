//! One-time pad application (PROTOCOL.md §9.4).
//!
//! The pad itself lives in the chamber module and in the trustee's copy;
//! this crate only provides the XOR, with an exact-length check so that a
//! short pad can never silently leave part of a plaintext unencrypted.

use crate::error::Error;

/// XORs `pad` into `buffer` byte by byte.
///
/// # Errors
/// [`Error::LengthMismatch`] if `pad.len() != buffer.len()`; `buffer` is
/// untouched in that case.
pub fn xor_in_place(buffer: &mut [u8], pad: &[u8]) -> Result<(), Error> {
    if buffer.len() != pad.len() {
        return Err(Error::LengthMismatch);
    }
    for (byte, mask) in buffer.iter_mut().zip(pad.iter()) {
        *byte ^= *mask;
    }
    Ok(())
}
