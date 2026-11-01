//! The [`Verified`] token: a value that exists only because a check passed.
//!
//! Every check in this crate that a caller must not skip returns
//! `Result<Verified<T>, Error>` instead of `bool`, and `T` borrows every
//! input the check examined. The constructor is private, so no other crate
//! can fabricate a token (ADR-0017 §12, the rule of ADR-0015 §2).

/// A value `T` together with the fact that a verification succeeded.
#[must_use = "a verification token proves nothing if it is dropped unused"]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Verified<T>(T);

impl<T> Verified<T> {
    /// Only verification functions in this crate create tokens.
    pub(crate) const fn new(value: T) -> Self {
        Self(value)
    }

    /// Borrows the verified value.
    #[must_use]
    pub const fn get(&self) -> &T {
        &self.0
    }

    /// Unwraps the verified value.
    #[must_use]
    pub fn into_inner(self) -> T {
        self.0
    }
}
