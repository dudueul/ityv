//! Publication deadlines.
// Integration-test crate: outside the TCB (CONSTITUTION.md §1.1).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use ityv_encoding::TimeBucket;
use ityv_ledger::{
    ANCHOR_WINDOW, BOARD_WINDOW, Breach, Error, REQUIRED_ANCHORS, Status, anchor_deadline,
    board_deadline, check_anchor, check_board,
};

const fn b(n: u64) -> TimeBucket {
    TimeBucket::new(n)
}

#[test]
fn deadlines_are_bucket_sums_and_never_overflow() {
    assert_eq!(ANCHOR_WINDOW, 4);
    assert_eq!(BOARD_WINDOW, 96);
    assert_eq!(REQUIRED_ANCHORS, 3);
    assert_eq!(anchor_deadline(b(100)).unwrap(), b(104));
    assert_eq!(board_deadline(b(100)).unwrap(), b(196));
    assert_eq!(anchor_deadline(b(u64::MAX - 4)).unwrap(), b(u64::MAX));
    assert_eq!(
        anchor_deadline(b(u64::MAX - 3)).unwrap_err(),
        Error::Overflow
    );
    assert_eq!(board_deadline(b(u64::MAX)).unwrap_err(), Error::Overflow);
    assert_eq!(
        check_anchor(b(u64::MAX), &[], 3, b(u64::MAX)).unwrap_err(),
        Error::Overflow
    );
    assert_eq!(
        check_board(b(u64::MAX), None, b(u64::MAX)).unwrap_err(),
        Error::Overflow
    );
}

#[test]
fn anchor_rule_counts_timely_receipts_only() {
    let cp = b(100);
    // Three receipts within the window: satisfied even before the deadline.
    assert_eq!(
        check_anchor(cp, &[b(100), b(101), b(104)], 3, b(102)).unwrap(),
        Status::Satisfied
    );
    // Two receipts and the deadline not yet passed: pending.
    assert_eq!(
        check_anchor(cp, &[b(100), b(101)], 3, b(104)).unwrap(),
        Status::Pending
    );
    // Deadline passed with two timely receipts and one late one: breach.
    assert_eq!(
        check_anchor(cp, &[b(100), b(101), b(105)], 3, b(105)).unwrap_err(),
        Error::Breach(Breach::AnchorsShort { have: 2, need: 3 })
    );
    // A receipt exactly at the deadline counts.
    assert_eq!(
        check_anchor(cp, &[b(104), b(104), b(104)], 3, b(200)).unwrap(),
        Status::Satisfied
    );
    // Zero required is always satisfied.
    assert_eq!(check_anchor(cp, &[], 0, b(200)).unwrap(), Status::Satisfied);
}

#[test]
fn board_rule_distinguishes_late_and_unpublished() {
    let close = b(1000);
    assert_eq!(
        check_board(close, Some(b(1096)), b(1096)).unwrap(),
        Status::Satisfied
    );
    assert_eq!(check_board(close, None, b(1096)).unwrap(), Status::Pending);
    assert_eq!(
        check_board(close, None, b(1097)).unwrap_err(),
        Error::Breach(Breach::BoardUnpublished)
    );
    assert_eq!(
        check_board(close, Some(b(1097)), b(1097)).unwrap_err(),
        Error::Breach(Breach::BoardLate {
            published: b(1097),
            deadline: b(1096)
        })
    );
    let texts = [
        std::format!("{}", Breach::AnchorsShort { have: 1, need: 3 }),
        std::format!("{}", Breach::BoardUnpublished),
        std::format!(
            "{}",
            Breach::BoardLate {
                published: b(2),
                deadline: b(1)
            }
        ),
    ];
    assert_eq!(
        texts
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        3
    );
}
