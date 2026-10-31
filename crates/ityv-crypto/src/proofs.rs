//! Kani bounded model-checking harnesses (verification ladder V2).
//!
//! Compiled only under `cargo kani`. Each harness states one property of
//! the crate's pure arithmetic: digit packing and unpacking, the access
//! structure decision, share index arithmetic, pad XOR, purpose validation
//! and the signing-message length prefix. The group and lattice
//! arithmetic of the backends is outside Kani's reach and is covered by
//! V1 tests and the backends' own verification (README).
//!
//! Kani additionally checks every harness for panics, overflow and
//! out-of-bounds access on all explored inputs, which is the mechanical
//! form of the crate's "no panics" promise for these functions.
//!
//! Run with `cargo kani -p ityv-crypto` from the workspace root.

use crate::commit::{
    ChunkIndex, DIGIT_BITS, DIGITS_PER_CHUNK, MAX_CHUNKS, MAX_OPTIONS, OptionIndex, extract_bits,
    has_bits_above_packed_range, packed_exponent, set_bit,
};
use crate::hash::{Purpose, length_prefix};
use crate::orproof::{Proof, chunks_for};
use crate::pad::xor_in_place;
use crate::shares::{
    AccessStructure, CHAMBER_COUNT, Chamber, MAX_MEMBERS, MemberId, Threshold, is_qualified,
    member_point, reached,
};

/// `OptionIndex::new` accepts exactly `0..MAX_OPTIONS`.
#[kani::proof]
fn option_index_bounds() {
    let raw: u16 = kani::any();
    let accepted = OptionIndex::new(raw).map(OptionIndex::get);
    if usize::from(raw) < MAX_OPTIONS {
        assert_eq!(accepted, Some(raw));
    } else {
        assert_eq!(accepted, None);
    }
}

/// `ChunkIndex::new` accepts exactly `0..MAX_CHUNKS`.
#[kani::proof]
fn chunk_index_bounds() {
    let raw: u8 = kani::any();
    let accepted = ChunkIndex::new(raw).map(ChunkIndex::get);
    if usize::from(raw) < MAX_CHUNKS {
        assert_eq!(accepted, Some(raw));
    } else {
        assert_eq!(accepted, None);
    }
}

/// `packed_exponent(t, j)` is `Some(26·(t − 9j))` exactly when
/// `9j ≤ t ≤ 9j + 8` (PROTOCOL.md §7.4), and the exponent never exceeds
/// 26 · 8 = 208, so the packed value is below the group order.
#[kani::proof]
fn packed_exponent_matches_specification() {
    let t: u16 = kani::any();
    let j: u8 = kani::any();
    kani::assume(usize::from(t) < MAX_OPTIONS);
    kani::assume(usize::from(j) < MAX_CHUNKS);
    let Some(option) = OptionIndex::new(t) else {
        unreachable!("t is in range by assumption");
    };
    let Some(chunk) = ChunkIndex::new(j) else {
        unreachable!("j is in range by assumption");
    };
    let first = u32::from(j) * u32::from(DIGITS_PER_CHUNK);
    let in_chunk = u32::from(t) >= first && u32::from(t) < first + u32::from(DIGITS_PER_CHUNK);
    let result = packed_exponent(option, chunk);
    if in_chunk {
        assert_eq!(result, Some(DIGIT_BITS * (u32::from(t) - first)));
        assert!(result.is_some_and(|e| e <= 208));
    } else {
        assert_eq!(result, None);
    }
}

/// `set_bit` sets exactly the named bit and leaves every other bit alone.
#[kani::proof]
#[kani::unwind(33)]
fn set_bit_sets_exactly_one_bit() {
    let mut bytes: [u8; 32] = kani::any();
    let before = bytes;
    let bit: u32 = kani::any();
    kani::assume(bit < 256);
    set_bit(&mut bytes, bit);
    for index in 0..32usize {
        let expected = if index == (bit / 8) as usize {
            before[index] | (1u8 << (bit % 8))
        } else {
            before[index]
        };
        assert_eq!(bytes[index], expected);
    }
}

/// `set_bit` ignores bits beyond 255 and never panics.
#[kani::proof]
fn set_bit_ignores_out_of_range() {
    let mut bytes: [u8; 32] = kani::any();
    let before = bytes;
    let bit: u32 = kani::any();
    kani::assume(bit >= 256);
    set_bit(&mut bytes, bit);
    assert_eq!(bytes, before);
}

/// `extract_bits` returns `None` exactly for out-of-range requests and
/// otherwise the little-endian value of the requested bit window.
#[kani::proof]
#[kani::unwind(34)]
fn extract_bits_matches_reference() {
    let bytes: [u8; 32] = kani::any();
    let start: u32 = kani::any();
    let count: u32 = kani::any();
    kani::assume(count <= 32);
    let result = extract_bits(&bytes, start, count);
    let in_range = start.checked_add(count).is_some_and(|end| end <= 256);
    if !in_range {
        assert_eq!(result, None);
    } else {
        let mut expected: u32 = 0;
        for offset in 0..count {
            let bit = start + offset;
            let byte = bytes[(bit / 8) as usize];
            let value = u32::from((byte >> (bit % 8)) & 1);
            expected |= value << offset;
        }
        assert_eq!(result, Some(expected));
    }
}

/// `extract_bits` rejects windows wider than 32 bits.
#[kani::proof]
fn extract_bits_rejects_wide_windows() {
    let bytes: [u8; 32] = kani::any();
    let start: u32 = kani::any();
    let count: u32 = kani::any();
    kani::assume(count > 32);
    assert_eq!(extract_bits(&bytes, start, count), None);
}

/// `has_bits_above_packed_range` is true exactly when some bit at or
/// above 234 is set.
#[kani::proof]
#[kani::unwind(24)]
fn packed_range_check_matches_reference() {
    let bytes: [u8; 32] = kani::any();
    let mut any_high = false;
    for bit in 234u32..256 {
        let byte = bytes[(bit / 8) as usize];
        any_high |= (byte >> (bit % 8)) & 1 == 1;
    }
    assert_eq!(has_bits_above_packed_range(&bytes), any_high);
}

/// The chunk count of a statement is `⌈option_count / 9⌉` for every
/// admissible option count, and `None` outside `1..=MAX_OPTIONS`.
#[kani::proof]
fn chunks_for_is_ceiling_division() {
    let option_count: u16 = kani::any();
    let result = chunks_for(option_count);
    if option_count == 0 || usize::from(option_count) > MAX_OPTIONS {
        assert_eq!(result, None);
    } else {
        let expected = (option_count + DIGITS_PER_CHUNK - 1) / DIGITS_PER_CHUNK;
        assert_eq!(result, Some(expected as u8));
        assert!(result.is_some_and(|k| usize::from(k) <= MAX_CHUNKS && k >= 1));
    }
}

/// The proof encoding length is `3 + (m+2)·(64 + 32k)` and never overflows
/// for the fixed capacities.
#[kani::proof]
fn proof_encoded_len_formula() {
    let option_count: u16 = kani::any();
    let chunk_count: u8 = kani::any();
    kani::assume(usize::from(option_count) <= MAX_OPTIONS);
    kani::assume(usize::from(chunk_count) <= MAX_CHUNKS);
    let expected = 3 + usize::from(option_count) * (64 + 32 * usize::from(chunk_count));
    assert_eq!(Proof::encoded_len_for(option_count, chunk_count), expected);
}

/// `Threshold::new` accepts exactly `1 ≤ k ≤ n ≤ MAX_MEMBERS`.
#[kani::proof]
fn threshold_bounds() {
    let k: u8 = kani::any();
    let n: u8 = kani::any();
    let result = Threshold::new(k, n);
    let valid = k >= 1 && k <= n && usize::from(n) <= MAX_MEMBERS;
    assert_eq!(result.is_some(), valid);
    if let Some(threshold) = result {
        assert_eq!((threshold.k(), threshold.n()), (k, n));
    }
}

/// `MemberId::new` accepts exactly `index < MAX_MEMBERS`, and the Shamir
/// point is `index + 1`.
#[kani::proof]
fn member_id_bounds_and_point() {
    let index: u8 = kani::any();
    let result = MemberId::new(Chamber::J, index);
    assert_eq!(result.is_some(), usize::from(index) < MAX_MEMBERS);
    if let Some(member) = result {
        assert_eq!(member.index(), index);
        assert_eq!(member.chamber(), Chamber::J);
        assert_eq!(u32::from(member.point()), u32::from(index) + 1);
    }
}

/// `member_point(index)` is the scalar `index + 1` for every member slot,
/// as a little-endian integer.
#[kani::proof]
fn member_point_is_index_plus_one() {
    let index: usize = kani::any();
    kani::assume(index < MAX_MEMBERS);
    let Ok(point) = member_point(index) else {
        unreachable!("index is in range by assumption");
    };
    let bytes = point.to_bytes();
    assert_eq!(usize::from(bytes[0]), index + 1);
    assert!(bytes[1..].iter().all(|b| *b == 0));
}

/// Chamber indices are a bijection with positions in `Chamber::ALL`, and
/// the rest points are `J = 1, A = 2, C = 3, N = 4` with none for X and Y.
#[kani::proof]
fn chamber_indices_and_rest_points() {
    for (position, chamber) in Chamber::ALL.iter().enumerate() {
        assert_eq!(chamber.index(), position);
        assert_eq!(chamber.is_mandatory(), position < 2);
        match chamber.rest_point() {
            None => assert!(chamber.is_mandatory()),
            Some(point) => assert_eq!(usize::from(point), position - 1),
        }
    }
}

/// `is_qualified` is exactly the access structure Γ of ADR-0012: X and Y
/// reach their thresholds and at least three of J, A, C, N do.
#[kani::proof]
fn is_qualified_matches_access_structure() {
    let ks: [u8; CHAMBER_COUNT] = kani::any();
    let counts: [u8; CHAMBER_COUNT] = kani::any();
    let mut thresholds =
        [Threshold::new(1, 1).unwrap_or_else(|| unreachable!("1-of-1 is valid")); CHAMBER_COUNT];
    for (slot, k) in thresholds.iter_mut().zip(ks.iter()) {
        kani::assume(*k >= 1 && usize::from(*k) <= MAX_MEMBERS);
        let Some(threshold) = Threshold::new(*k, 8) else {
            unreachable!("k is in range by assumption");
        };
        *slot = threshold;
    }
    let structure = AccessStructure::new(thresholds);
    let flags = reached(&structure, counts);
    for i in 0..CHAMBER_COUNT {
        assert_eq!(flags[i], counts[i] >= ks[i]);
    }
    let rest = usize::from(flags[2])
        + usize::from(flags[3])
        + usize::from(flags[4])
        + usize::from(flags[5]);
    let expected = flags[0] && flags[1] && rest >= 3;
    assert_eq!(is_qualified(&structure, counts), expected);
}

/// `xor_in_place` fails exactly on a length mismatch, leaving the buffer
/// untouched, and otherwise XORs byte by byte.
#[kani::proof]
#[kani::unwind(6)]
fn xor_in_place_is_exact() {
    const N: usize = 4;
    let data: [u8; N] = kani::any();
    let pad: [u8; N] = kani::any();
    let buffer_len: usize = kani::any();
    let pad_len: usize = kani::any();
    kani::assume(buffer_len <= N && pad_len <= N);
    let mut buffer = data;
    let (buffer_slice, _) = buffer
        .split_at_mut_checked(buffer_len)
        .unwrap_or((&mut [], &mut []));
    let (pad_slice, _) = pad.split_at_checked(pad_len).unwrap_or((&[], &pad));
    let result = xor_in_place(buffer_slice, pad_slice);
    if buffer_len == pad_len {
        assert!(result.is_ok());
        for i in 0..buffer_len {
            assert_eq!(buffer[i], data[i] ^ pad[i]);
        }
    } else {
        assert!(result.is_err());
        assert_eq!(buffer, data);
    }
}

/// `Purpose::new` accepts exactly the strings of length `1..=32` over the
/// identifier alphabet (bounded to four bytes here).
#[kani::proof]
#[kani::unwind(6)]
fn purpose_alphabet_is_exact() {
    const N: usize = 4;
    let bytes: [u8; N] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= N);
    let (prefix, _) = bytes.split_at_checked(len).unwrap_or((&[], &bytes));
    let accepted = Purpose::new(prefix).is_some();
    let expected = len >= 1
        && prefix
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'));
    assert_eq!(accepted, expected);
    if let Some(purpose) = Purpose::new(prefix) {
        assert_eq!(purpose.as_bytes(), prefix);
    }
}

/// `Purpose::new` rejects every string longer than 32 bytes.
#[kani::proof]
fn purpose_rejects_long_strings() {
    let len: usize = kani::any();
    kani::assume(len > 32 && len <= 40);
    let bytes = [b'a'; 40];
    let (prefix, _) = bytes.split_at_checked(len).unwrap_or((&[], &bytes));
    assert!(Purpose::new(prefix).is_none());
}

/// The signing-message length prefix is the big-endian 64-bit length.
#[kani::proof]
fn length_prefix_is_big_endian() {
    let len: usize = kani::any();
    let prefix = length_prefix(len);
    assert_eq!(u64::from_be_bytes(prefix), len as u64);
}
