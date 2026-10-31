//! The [`Verified`] token: a value that exists only because a check passed.
//!
//! Verification functions return `Result<Verified<T>, Error>` instead of
//! `bool`. The constructor is private to this crate, so no other crate can
//! fabricate a `Verified` value, and a caller that forgets to call the check
//! has no token to pass on (ADR-0015 §2).

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
