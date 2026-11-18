//! Page export formats, bounded host output and native capability limits.

use std::sync::Arc;
use std::time::Duration;

/// Maximum bytes retained in one host-owned page export.
pub const MAX_PAGE_EXPORT_BYTES: usize = 16 * 1024 * 1024;

/// Content exported from the active native view, without another network fetch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageExportFormat {
    /// Original loaded main-resource bytes, not serialized live DOM.
    MainResourceHtml,
    /// Native MHTML serialization, including loaded subresources.
    Mhtml,
    /// Full scroll-area PNG; requires the reviewed native allocation cap.
    FullDocumentPng,
}

/// Limits for host-owned output and asynchronous operation time.
///
/// Stock WPE may allocate a complete native resource/archive before exposing
/// its length. These limits bound host copies and stream reads, not internal
/// renderer or native serialization allocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageExportOptions {
    /// Host output limit, from one byte through 16 MiB.
    pub max_bytes: usize,
    /// Owner-thread deadline, greater than zero and at most 60 seconds.
    pub timeout: Duration,
}

impl Default for PageExportOptions {
    fn default() -> Self {
        Self {
            max_bytes: 8 * 1024 * 1024,
            timeout: Duration::from_secs(15),
        }
    }
}

impl PageExportOptions {
    #[cfg(any(feature = "wpe", test))]
    pub(crate) fn validate(&self) -> Result<(), PageExportError> {
        if self.max_bytes == 0 || self.max_bytes > MAX_PAGE_EXPORT_BYTES {
            return Err(PageExportError::InvalidInput(
                "page export host byte limit must be in 1..=16 MiB",
            ));
        }
        if self.timeout.is_zero() || self.timeout > Duration::from_secs(60) {
            return Err(PageExportError::InvalidInput(
                "page export timeout must be in (0, 60s]",
            ));
        }
        Ok(())
    }
}

/// Public-native capabilities; internal serialization allocations are not bounded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageExportCapabilities {
    /// Loaded HTML/XHTML main-resource bytes can be retrieved.
    pub main_resource_html: bool,
    /// An MHTML API exists; a native build without MHTML returns a typed refusal.
    pub mhtml_api: bool,
    /// Native preallocation-safe full-document PNG is available.
    pub full_document_png: bool,
    /// The implementation bounds native serialization allocation before it occurs.
    /// False for HTML/MHTML even when guarded full-document PNG is available.
    pub native_internal_allocation_bounded: bool,
    /// Full-document native bitmap pixel ceiling, when qualified support exists.
    pub max_snapshot_pixels: Option<u64>,
    /// Native bitmap width/height ceiling, including device scale.
    pub max_snapshot_dimension: Option<u32>,
}

impl PageExportCapabilities {
    /// Limits of the public WPE APIs used by this crate.
    pub const WPE: Self = Self {
        main_resource_html: true,
        mhtml_api: true,
        full_document_png: false,
        native_internal_allocation_bounded: false,
        max_snapshot_pixels: None,
        max_snapshot_dimension: None,
    };
}

/// Owned export artifact. Clones share storage and debug output excludes content.
#[derive(Clone)]
pub struct OwnedPageExport {
    format: PageExportFormat,
    mime_type: &'static str,
    bytes: Arc<[u8]>,
}

impl OwnedPageExport {
    #[cfg(any(feature = "wpe", test))]
    pub(crate) fn new(format: PageExportFormat, mime_type: &'static str, bytes: Vec<u8>) -> Self {
        Self {
            format,
            mime_type,
            bytes: bytes.into(),
        }
    }

    /// Native export format.
    pub fn format(&self) -> PageExportFormat {
        self.format
    }
    /// MIME type of these bytes, preserving HTML versus XHTML.
    pub fn mime_type(&self) -> &'static str {
        self.mime_type
    }
    /// Export bytes; the host chooses whether and where to save them.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl std::fmt::Debug for OwnedPageExport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnedPageExport")
            .field("format", &self.format)
            .field("mime_type", &self.mime_type)
            .field("bytes", &self.bytes.len())
            .finish()
    }
}

/// A refusal, cancellation or failure during native page export.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PageExportError {
    /// Called outside WPE's native owner thread.
    WrongThread,
    /// Outstanding native callbacks occupy the export budget.
    Busy,
    /// The host cancelled or dropped the export task.
    Cancelled,
    /// The deadline expired; native callback resources remain retained.
    TimedOut,
    /// Invalid byte/deadline options.
    InvalidInput(&'static str),
    /// No completed document/main resource is currently available.
    NotReady,
    /// The main resource is not HTML or XHTML.
    UnsupportedMime(String),
    /// A public native API cannot provide the required behavior safely.
    UnsupportedRuntime(&'static str),
    /// The native payload exceeds the requested host output limit.
    OutputTooLarge,
    /// The original document was replaced while export was pending.
    StaleDocument,
    /// Native operation failed; the diagnostic is bounded.
    Native(String),
}

impl std::fmt::Display for PageExportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongThread => f.write_str("page export requires the native owner thread"),
            Self::Busy => f.write_str("page export native budget is occupied"),
            Self::Cancelled => f.write_str("page export cancelled"),
            Self::TimedOut => f.write_str("page export deadline expired"),
            Self::InvalidInput(message) | Self::UnsupportedRuntime(message) => f.write_str(message),
            Self::NotReady => f.write_str("page export requires a completed main resource"),
            Self::UnsupportedMime(mime) => write!(f, "main resource is not HTML: {mime}"),
            Self::OutputTooLarge => f.write_str("page export exceeds host output limit"),
            Self::StaleDocument => f.write_str("page document changed during export"),
            Self::Native(message) => write!(f, "native page export failed: {message}"),
        }
    }
}
impl std::error::Error for PageExportError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_export_options_bound_host_output_and_redact_artifacts() {
        assert!(PageExportOptions::default().validate().is_ok());
        for bytes in [0, MAX_PAGE_EXPORT_BYTES + 1, usize::MAX] {
            assert!(matches!(
                PageExportOptions {
                    max_bytes: bytes,
                    ..Default::default()
                }
                .validate(),
                Err(PageExportError::InvalidInput(_))
            ));
        }
        for timeout in [Duration::ZERO, Duration::from_secs(61)] {
            assert!(matches!(
                PageExportOptions {
                    timeout,
                    ..Default::default()
                }
                .validate(),
                Err(PageExportError::InvalidInput(_))
            ));
        }
        let artifact = OwnedPageExport::new(
            PageExportFormat::MainResourceHtml,
            "text/html",
            b"private_page_content".to_vec(),
        );
        let clone = artifact.clone();
        assert!(std::ptr::eq(
            artifact.as_bytes().as_ptr(),
            clone.as_bytes().as_ptr()
        ));
        assert!(!format!("{artifact:?}").contains("private_page_content"));
        assert!(format!("{artifact:?}").ends_with("bytes: 20 }"));
        const { assert!(!PageExportCapabilities::WPE.full_document_png) };
        const { assert!(!PageExportCapabilities::WPE.native_internal_allocation_bounded) };
    }
}
