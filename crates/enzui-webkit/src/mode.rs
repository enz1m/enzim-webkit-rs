//! Explicit backend-mode selection: a mock never silently replaces the native
//! backend.
//!

/// The engine backend a caller explicitly requests.
///
/// There is deliberately no `Default` and no `Auto`: an "auto" mode is exactly
/// a silent-substitution hazard, because "auto" resolves to
/// "whatever is available", which is the mock when the native engine is
/// missing. A caller must choose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BackendMode {
    /// The real WPE WebKit engine. Only buildable with the `wpe` feature; on a
    /// feature-off build, requesting it is [`ModeError::NativeUnavailable`].
    Native,
    /// A deterministic in-process test double. Always available, but only
    /// selected by naming it here - never inferred from a missing native
    /// engine.
    Mock,
}

impl BackendMode {
    /// Whether this mode is the mock test double.
    #[must_use]
    pub const fn is_mock(self) -> bool {
        matches!(self, BackendMode::Mock)
    }

    /// Whether this mode is the real native engine.
    #[must_use]
    pub const fn is_native(self) -> bool {
        matches!(self, BackendMode::Native)
    }
}

/// The concrete backend a successful [`resolve`] settled on.
///
/// Carries the mode it resolved to so a caller can *assert* what it got - the
/// whole point is that this is inspectable, not hidden. `resolve` guarantees
/// `resolved.mode() == requested`, so a caller that asked for `Native` and got
/// an `Ok` is guaranteed a native backend, never a mock wearing its name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedBackend {
    mode: BackendMode,
}

impl ResolvedBackend {
    /// The mode this backend actually is. Equal to the requested mode on every
    /// success - that equality *is* the no-silent-substitution guarantee.
    #[must_use]
    pub const fn mode(self) -> BackendMode {
        self.mode
    }

    /// Whether the resolved backend is the mock. A caller in a context that
    /// requires the real engine asserts `!resolved.is_mock()`.
    #[must_use]
    pub const fn is_mock(self) -> bool {
        self.mode.is_mock()
    }
}

/// Why a backend-mode request could not be satisfied.
///
/// A typed error rather than a fallback: the caller learns the native
/// engine is unavailable and decides what to do (surface it, refuse to start),
/// instead of unknowingly running against a mock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ModeError {
    /// [`BackendMode::Native`] was requested but this build did not compile the
    /// WPE backend (the `wpe` feature is off). The resolver refuses rather than
    /// substituting the mock.
    NativeUnavailable,
}

impl core::fmt::Display for ModeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ModeError::NativeUnavailable => f.write_str(
                "native WPE backend not compiled in (the `wpe` feature is off); \
                 refusing to substitute the mock",
            ),
        }
    }
}

impl std::error::Error for ModeError {}

/// Whether the native backend is compiled into this build.
///
/// This is the single `#[cfg]` seam. It is a `const fn` returning a plain
/// `bool` so the mode logic below is ordinary, testable code rather than a maze
/// of `#[cfg]` blocks - and so a test can read the value the resolver will see.
#[must_use]
pub const fn native_available() -> bool {
    cfg!(feature = "wpe")
}

/// Resolve an explicitly requested backend mode into a concrete backend, or
/// a typed error.
///
/// The contract, which the tests pin:
///
/// * [`BackendMode::Mock`] → always `Ok(Mock)`. The mock is always present.
/// * [`BackendMode::Native`] → `Ok(Native)` only if [`native_available`],
///   else `Err(`[`ModeError::NativeUnavailable`]`)`.
///
/// Crucially, the `Native`-missing arm returns an error, never
/// `Ok(Mock)` - that missing `Ok(Mock)` arm is the whole safety property. On
/// success, `resolved.mode() == requested`.
pub fn resolve(requested: BackendMode) -> Result<ResolvedBackend, ModeError> {
    match requested {
        BackendMode::Mock => Ok(ResolvedBackend {
            mode: BackendMode::Mock,
        }),
        BackendMode::Native => {
            if native_available() {
                Ok(ResolvedBackend {
                    mode: BackendMode::Native,
                })
            } else {
                Err(ModeError::NativeUnavailable)
            }
        }
    }
}

#[cfg(all(test, not(feature = "wpe")))]
mod tests {
    use super::*;

    #[test]
    fn requesting_native_without_the_feature_is_an_error_not_a_mock() {
        let outcome = resolve(BackendMode::Native);
        assert_eq!(
            outcome,
            Err(ModeError::NativeUnavailable),
            "requesting Native on a feature-off build must error, not fall back to Mock"
        );
    }
}
