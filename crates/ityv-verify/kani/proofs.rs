//! Kani bounded model-checking harnesses (verification ladder V2).
//!
//! Compiled only under `cargo kani`, as `crate::proofs` via a `#[path]`
//! attribute in `src/lib.rs`. Each harness states one rule of the genesis
//! stage against an independently written statement:
//!
//! * the order rule of every entry set: a key after another is accepted
//!   only if strictly greater, and an equal key is a duplicate, not an
//!   order error;
//! * the chamber rule of a box's modules and of a check-in unit's modules
//!   (VC-067, VC-017), for every party count and every tally of up to
//!   three modules per chamber.
//!
//! Kani additionally checks every harness for panics, overflow and
//! out-of-bounds access on all explored inputs.
//!
//! Run with `cargo kani -p ityv-verify` from the workspace root.
// Harness file: outside the TCB and outside `src/` (CONSTITUTION.md §1.1).
// A harness states expected values with plain indexing on bounded symbolic
// inputs, and Kani itself reports any panic or overflow in them, so these
// restriction lints are relaxed for this file only.
#![allow(clippy::indexing_slicing, clippy::missing_panics_doc)]

use crate::cross::{CHAMBER_CODES, ChamberTally, box_modules_valid, unit_modules_valid};
use crate::error::Rule;
use crate::sets::successor;

/// Two keys of up to three bytes: lexicographic order as the encoding
/// compares identifiers (a prefix sorts first).
#[kani::proof]
#[kani::unwind(5)]
fn set_order_rule_is_exact() {
    let a: [u8; 3] = kani::any();
    let b: [u8; 3] = kani::any();
    let la: usize = kani::any();
    let lb: usize = kani::any();
    kani::assume(la <= 3 && lb <= 3);
    let (x, y) = (&a[..la], &b[..lb]);
    // Reference: the first differing byte decides; otherwise the shorter
    // key is smaller.
    let mut decided = None;
    let mut i = 0;
    while i < la && i < lb {
        if decided.is_none() && x[i] != y[i] {
            decided = Some(x[i] < y[i]);
        }
        i += 1;
    }
    let less = decided.unwrap_or(la < lb);
    let equal = decided.is_none() && la == lb;
    let expected = if less {
        None
    } else if equal {
        Some(Rule::Duplicate)
    } else {
        Some(Rule::NotSorted)
    };
    assert_eq!(successor(x, y), expected);
}

fn tally() -> ChamberTally {
    let t: ChamberTally = kani::any();
    for n in t {
        kani::assume(n <= 3);
    }
    t
}

/// A box: exactly one module of each of the `n` party chambers, none of
/// the other party chambers, at most one each of J, A, C. A module of N
/// does not decode, so its count is 0.
#[kani::proof]
fn box_chamber_rule_is_exact() {
    let t = tally();
    let parties: usize = kani::any();
    kani::assume((2..=4).contains(&parties));
    kani::assume(t[CHAMBER_CODES - 1] == 0);
    let parties_ok = (0..4).all(|i| if i < parties { t[i] == 1 } else { t[i] == 0 });
    let neutral_ok = t[4] <= 1 && t[5] <= 1 && t[6] <= 1;
    assert_eq!(box_modules_valid(t, parties), parties_ok && neutral_ok);
}

/// A check-in unit: exactly one module of each of the `n` party chambers
/// and nothing else.
#[kani::proof]
fn unit_chamber_rule_is_exact() {
    let t = tally();
    let parties: usize = kani::any();
    kani::assume((2..=4).contains(&parties));
    let expected = (0..CHAMBER_CODES).all(|i| t[i] == u8::from(i < parties));
    assert_eq!(unit_modules_valid(t, parties), expected);
}
