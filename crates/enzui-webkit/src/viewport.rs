//! Logical viewport geometry shared by the widget and native engine boundary.
//!
//! WPEPlatform accepts signed C integers for a toplevel resize. Iced supplies
//! floating-point logical bounds. [`ViewportSize::from_logical`] is the one
//! checked conversion between them: it rounds to the nearest logical pixel and
//! rejects dimensions that are non-finite, non-positive after rounding, or too
//! large for WPE's `gint` ABI.

/// A positive WPE viewport size in integer logical pixels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ViewportSize {
    width: i32,
    height: i32,
}

impl ViewportSize {
    /// Convert floating-point layout dimensions into WPE logical pixels.
    ///
    /// Fractional dimensions are rounded to the nearest logical pixel. The
    /// conversion fails closed instead of relying on Rust's saturating float
    /// cast, which would otherwise turn infinity or an oversized allocation
    /// into a plausible WPE request.
    pub fn from_logical(width: f32, height: f32) -> Result<Self, ViewportSizeError> {
        fn dimension(value: f32, axis: &'static str) -> Result<i32, ViewportSizeError> {
            if !value.is_finite() {
                return Err(ViewportSizeError::NonFinite { axis });
            }
            let rounded = f64::from(value).round();
            if rounded < 1.0 {
                return Err(ViewportSizeError::NonPositive { axis });
            }
            if rounded > f64::from(i32::MAX) {
                return Err(ViewportSizeError::Overflow { axis });
            }
            Ok(rounded as i32)
        }

        Ok(Self {
            width: dimension(width, "width")?,
            height: dimension(height, "height")?,
        })
    }

    /// Width in integer logical pixels.
    #[must_use]
    pub const fn width(self) -> i32 {
        self.width
    }

    /// Height in integer logical pixels.
    #[must_use]
    pub const fn height(self) -> i32 {
        self.height
    }
}

/// Why floating-point widget bounds cannot be sent to WPEPlatform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewportSizeError {
    /// A layout dimension was NaN or infinite.
    NonFinite { axis: &'static str },
    /// A dimension rounded to zero or was negative.
    NonPositive { axis: &'static str },
    /// A dimension exceeded WPEPlatform's signed `gint` range.
    Overflow { axis: &'static str },
}

impl core::fmt::Display for ViewportSizeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NonFinite { axis } => write!(f, "viewport {axis} is not finite"),
            Self::NonPositive { axis } => {
                write!(
                    f,
                    "viewport {axis} does not round to a positive logical pixel"
                )
            }
            Self::Overflow { axis } => write!(f, "viewport {axis} exceeds WPE's gint range"),
        }
    }
}

impl std::error::Error for ViewportSizeError {}
