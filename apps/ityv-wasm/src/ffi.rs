//! The C ABI the console calls. All `unsafe` of the crate is here, each
//! item allowed on its own.
//!
//! Protocol (single-threaded; JavaScript calls one function at a time):
//!
//! 1. `alloc(len)` returns a buffer of exactly `len` bytes (a boxed
//!    slice); the caller copies its input there.
//! 2. `verify_bundle(ptr, len)` (or `verify_bundle_with` with a 64-byte
//!    pin or none and the beacon flag, or `fingerprint(ptr, len)`) writes
//!    its UTF-8 JSON (or text)
//!    result into a buffer this module keeps and returns its pointer;
//!    `result_len()` gives its length. The result stays valid until the
//!    next call of any of these functions.
//! 3. `dealloc(ptr, len)` frees an input buffer from `alloc`.
//!
//! The report carries each record's inclusion itself; there is no state
//! kept between two verifications but the last result buffer.

use ::alloc::boxed::Box;
use ::alloc::vec::Vec;
use std::sync::{Mutex, PoisonError};

use ityv_encoding::Hash512;

use crate::report::{fingerprint_of, verify};

static RESULT: Mutex<Vec<u8>> = Mutex::new(Vec::new());

fn set_result(bytes: Vec<u8>) -> *const u8 {
    let mut guard = RESULT.lock().unwrap_or_else(PoisonError::into_inner);
    *guard = bytes;
    guard.as_ptr()
}

/// A buffer of exactly `len` bytes for the caller's input.
// Exported under its own name for the JavaScript caller.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn alloc(len: usize) -> *mut u8 {
    let buf: Box<[u8]> = ::alloc::vec![0u8; len].into_boxed_slice();
    Box::into_raw(buf).cast::<u8>()
}

/// Frees a buffer that [`alloc()`] returned for `len` bytes.
///
/// # Safety
/// `ptr` must come from `alloc(len)` with the same `len` and must not be
/// used afterwards.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dealloc(ptr: *mut u8, len: usize) {
    if ptr.is_null() {
        return;
    }
    let slice = core::ptr::slice_from_raw_parts_mut(ptr, len);
    // SAFETY: the caller guarantees `ptr` came from `alloc(len)`, which
    // leaked a `Box<[u8]>` of exactly `len` bytes; rebuilding that box
    // from the same pointer and length gives it back to the allocator
    // exactly once.
    drop(unsafe { Box::from_raw(slice) });
}

/// The length of the last result.
// Exported under its own name for the JavaScript caller.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn result_len() -> usize {
    RESULT.lock().unwrap_or_else(PoisonError::into_inner).len()
}

/// Reads `len` bytes at `ptr`.
///
/// # Safety
/// `ptr` must point to `len` initialised bytes that stay valid and
/// unchanged for the returned borrow.
#[allow(unsafe_code)]
unsafe fn input<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    if ptr.is_null() || len == 0 {
        return &[];
    }
    // SAFETY: the caller guarantees `ptr` points to `len` initialised bytes
    // (written into a buffer from `alloc`) that nothing changes while the
    // borrow lives.
    unsafe { core::slice::from_raw_parts(ptr, len) }
}

/// Verifies the bundle at `ptr` (`len` bytes) with its own pin and its
/// beacon observation, if it has one; returns the JSON report (see the
/// module protocol).
///
/// # Safety
/// `ptr` must point to `len` initialised bytes.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn verify_bundle(ptr: *const u8, len: usize) -> *const u8 {
    // SAFETY: forwarded from this function's contract.
    let bytes = unsafe { input(ptr, len) };
    set_result(verify(bytes, None, true).json.into_bytes())
}

/// As [`verify_bundle`], trusting the 64-byte pin at `pin` instead of the
/// bundle's (a null `pin` uses the bundle's), and handing the verifier the
/// bundle's beacon observation only if bit 0 of `flags` is set.
///
/// # Safety
/// `ptr` must point to `len` initialised bytes and `pin`, unless null, to
/// 64.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn verify_bundle_with(
    ptr: *const u8,
    len: usize,
    pin: *const u8,
    flags: u32,
) -> *const u8 {
    // SAFETY: forwarded from this function's contract.
    let bytes = unsafe { input(ptr, len) };
    // SAFETY: forwarded from this function's contract (64 bytes at `pin`).
    let pin_bytes = unsafe { input(pin, 64) };
    let pin = <[u8; 64]>::try_from(pin_bytes).ok().map(Hash512);
    set_result(verify(bytes, pin, flags & 1 == 1).json.into_bytes())
}

/// The 32-character fingerprint of the SHA3-512 hash of the `len` bytes
/// at `ptr`.
///
/// # Safety
/// `ptr` must point to `len` initialised bytes.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fingerprint(ptr: *const u8, len: usize) -> *const u8 {
    // SAFETY: forwarded from this function's contract.
    let bytes = unsafe { input(ptr, len) };
    set_result(fingerprint_of(bytes).into_bytes())
}
