//! Paginated PDF export settings and completion identities.

/// Settings for a paginated PDF export, in PostScript points (72 per inch).
///
/// The default is portrait A4 with half-inch margins, unit scale, all pages,
/// and no printed backgrounds. CSS print styles, margins and page breaks apply;
/// physical sheet dimensions come from these settings rather than CSS `@page size`.
#[derive(Debug, Clone, PartialEq)]
pub struct PdfPrintSettings {
    /// Physical sheet width, between 72 and 14,400 points.
    pub paper_width: f64,
    /// Physical sheet height, between 72 and 14,400 points.
    pub paper_height: f64,
    /// Top, right, bottom and left fallback margins. CSS `@page` may override them.
    pub margins: [f64; 4],
    /// Content scale, between 0.1 and 4.0.
    pub scale: f64,
    /// Zero-based first page, below 256.
    pub first_page: u32,
    /// Maximum pages to include, or all remaining pages when absent.
    pub page_count: Option<u32>,
    /// Include background colors and images in printed content.
    pub print_backgrounds: bool,
}

impl Default for PdfPrintSettings {
    fn default() -> Self {
        Self {
            paper_width: 595.2756,
            paper_height: 841.8898,
            margins: [36.0; 4],
            scale: 1.0,
            first_page: 0,
            page_count: None,
            print_backgrounds: false,
        }
    }
}

impl PdfPrintSettings {
    /// Check the native export bounds before starting an operation.
    ///
    /// # Errors
    /// Returns [`PdfPrintError::InvalidSettings`] for non-finite values,
    /// unsupported dimensions, margins or scale, or an invalid page range.
    pub fn validate(&self) -> Result<(), PdfPrintError> {
        if !self.paper_width.is_finite()
            || !self.paper_height.is_finite()
            || !(72.0..=14_400.0).contains(&self.paper_width)
            || !(72.0..=14_400.0).contains(&self.paper_height)
            || !self.scale.is_finite()
            || !(0.1..=4.0).contains(&self.scale)
            || self
                .margins
                .iter()
                .any(|v| !v.is_finite() || !(0.0..=14_400.0).contains(v))
            || self.paper_width - self.margins[1] - self.margins[3] < 36.0
            || self.paper_height - self.margins[0] - self.margins[2] < 36.0
            || self.first_page >= 256
            || self.page_count.is_some_and(|v| v == 0 || v > 256)
        {
            return Err(PdfPrintError::InvalidSettings);
        }
        Ok(())
    }
}

/// Identifies one export until its completion event arrives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PdfPrintId(pub(crate) u64);

impl PdfPrintId {
    /// The process-unique numeric operation identity.
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Why PDF export was refused, cancelled or failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PdfPrintError {
    /// This native runtime does not expose the reviewed PDF export API.
    UnsupportedRuntime,
    /// Paper dimensions, margins, scale or page range are outside supported bounds.
    InvalidSettings,
    /// Another export is active or its completion still awaits host delivery.
    Busy,
    /// The session cannot currently navigate or print.
    SessionUnavailable,
    /// The host cancelled the operation, including session teardown or navigation.
    Cancelled,
    /// The PDF exceeded the 64 MiB output limit.
    OutputTooLarge,
    /// Native rendering or transport failed.
    Failed(String),
}

impl std::fmt::Display for PdfPrintError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedRuntime => f.write_str("native runtime does not support PDF export"),
            Self::InvalidSettings => f.write_str("invalid PDF print settings"),
            Self::Busy => f.write_str("a PDF export is already active"),
            Self::SessionUnavailable => f.write_str("session is not available for PDF export"),
            Self::Cancelled => f.write_str("PDF export was cancelled"),
            Self::OutputTooLarge => f.write_str("PDF export exceeds 64 MiB"),
            Self::Failed(message) => write!(f, "PDF export failed: {message}"),
        }
    }
}

impl std::error::Error for PdfPrintError {}

/// An owned PDF artifact with shared immutable storage and content-redacted diagnostics.
#[derive(Clone, PartialEq, Eq)]
pub struct PdfDocument(std::sync::Arc<Vec<u8>>);
impl PdfDocument {
    #[cfg(any(feature = "wpe", test))]
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        Self(std::sync::Arc::new(bytes))
    }
    /// The PDF file bytes, for a host viewer or print portal.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
    /// Consume the artifact, copying only when another clone still shares it.
    pub fn into_bytes(self) -> Vec<u8> {
        std::sync::Arc::try_unwrap(self.0).unwrap_or_else(|shared| (*shared).clone())
    }
}
impl AsRef<[u8]> for PdfDocument {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}
impl std::fmt::Debug for PdfDocument {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PdfDocument")
            .field("bytes", &self.0.len())
            .finish()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pdf_artifacts_share_storage_and_redact_debug_output() {
        let pdf = PdfDocument::new(b"private".to_vec());
        let copy = pdf.clone();
        assert_eq!(
            copy.as_bytes().as_ptr(),
            pdf.as_bytes().as_ptr(),
            "cloning a queued PDF copied its payload"
        );
        assert_eq!(format!("{pdf:?}"), "PdfDocument { bytes: 7 }");
        assert_eq!(copy.into_bytes(), b"private");
        assert_eq!(pdf.into_bytes(), b"private");
    }
}
