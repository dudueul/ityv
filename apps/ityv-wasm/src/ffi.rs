//! The C ABI the console calls. All `unsafe` of the crate is here.
//!
//! Protocol (single-threaded; JavaScript calls one function at a time):
//!
//! 1. `alloc(len)` returns a buffer of `len` bytes; the caller copies its
//!    input there.
//! 2. `verify_bundle(ptr, len)` (or `verify_bundle_pinned` with a 64-byte
//!    pin, `inclusion(seq)`, `fingerprint(ptr, len)`) writes its UTF-8
//!    JSON (or text) result into a buffer this module keeps and returns
//!    its pointer; `result_len()` gives its length. The result stays valid
//!    until the next call of any of these functions.
//! 3. `dealloc(ptr, len)` frees an input buffer from `alloc`.

use std::sync::Mutex;

use ityv_encoding::Hash512;

use crate::report::{Proofs, fingerprint_of, verify};

static RESULT: Mutex<Vec<u8>> = Mutex::new(Vec::new());
static PROOFS: Mutex<Option<Proofs>> = Mutex::new(None);

fn set_result(bytes: Vec<u8>) -> *const u8 {
    let mut guard = RESULT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *guard = bytes;
    guard.as_ptr()
}

/// A buffer of `len` bytes for the caller's input.
#[unsafe(no_mangle)]
pub extern "C" fn alloc(len: usize) -> *mut u8 {
    let mut v: Vec<u8> = Vec::with_capacity(len);
    let ptr = v.as_mut_ptr();
    std::mem::forget(v);
    ptr
}

/// Frees a buffer that [`alloc`] returned for `len` bytes.
///
/// # Safety
/// `ptr` must come from `alloc(len)` with the same `len` and must not be
/// used afterwards.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dealloc(ptr: *mut u8, len: usize) {
    if ptr.is_null() {
        return;
    }
    // SAFETY: the caller guarantees `ptr` came from `alloc(len)`, which
    // made it from a `Vec<u8>` of capacity `len` and forgot it; rebuilding
    // that vector with length 0 and the same capacity gives it back to the
    // allocator exactly once.
    drop(unsafe { Vec::from_raw_parts(ptr, 0, len) });
}

/// The length of the last result.
#[unsafe(no_mangle)]
pub extern "C" fn result_len() -> usize {
    RESULT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .len()
}

/// Reads `len` bytes at `ptr`.
///
/// # Safety
/// `ptr` must point to `len` initialised bytes that stay valid and
/// unchanged for the returned borrow.
unsafe fn input<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    if ptr.is_null() || len == 0 {
        return &[];
    }
    // SAFETY: the caller guarantees `ptr` points to `len` initialised bytes
    // (written into a buffer from `alloc`) that nothing changes while the
    // borrow lives.
    unsafe { std::slice::from_raw_parts(ptr, len) }
}

/// Verifies the bundle at `ptr` (`len` bytes) with its own pin; returns
/// the JSON report (see the module protocol).
///
/// # Safety
/// `ptr` must point to `len` initialised bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn verify_bundle(ptr: *const u8, len: usize) -> *const u8 {
    // SAFETY: forwarded from this function's contract.
    let bytes = unsafe { input(ptr, len) };
    let v = verify(bytes, None);
    *PROOFS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(v.proofs);
    set_result(v.json.into_bytes())
}

/// As [`verify_bundle`], trusting the 64-byte pin at `pin` instead of the
/// bundle's.
///
/// # Safety
/// `ptr` must point to `len` initialised bytes and `pin` to 64.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn verify_bundle_pinned(
    ptr: *const u8,
    len: usize,
    pin: *const u8,
) -> *const u8 {
    // SAFETY: forwarded from this function's contract.
    let bytes = unsafe { input(ptr, len) };
    // SAFETY: forwarded from this function's contract (64 bytes at `pin`).
    let pin_bytes = unsafe { input(pin, 64) };
    let mut h = [0u8; 64];
    if pin_bytes.len() == 64 {
        h.copy_from_slice(pin_bytes);
    }
    let v = verify(bytes, Some(Hash512(h)));
    *PROOFS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(v.proofs);
    set_result(v.json.into_bytes())
}

/// The inclusion of frame `seq` of the last verified bundle in its first
/// covering checkpoint, as JSON.
#[unsafe(no_mangle)]
pub extern "C" fn inclusion(seq: u64) -> *const u8 {
    let json = PROOFS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_ref()
        .map_or_else(
            || "{\"error\":\"no bundle verified\"}".to_owned(),
            |p| p.inclusion_json(seq),
        );
    set_result(json.into_bytes())
}

/// The 32-character fingerprint of the SHA3-512 hash of the `len` bytes
/// at `ptr`.
///
/// # Safety
/// `ptr` must point to `len` initialised bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fingerprint(ptr: *const u8, len: usize) -> *const u8 {
    // SAFETY: forwarded from this function's contract.
    let bytes = unsafe { input(ptr, len) };
    set_result(fingerprint_of(bytes).into_bytes())
}
