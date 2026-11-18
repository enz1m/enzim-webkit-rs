//! Native document-associated icons for browser-owned display and caching.

use std::sync::Arc;

/// A small PNG obtained from the native icon loader, never from page script.
#[derive(Clone, PartialEq, Eq)]
pub struct OwnedFavicon {
    /// Bound logical view and generation, if this session has been bound.
    pub view: Option<crate::web::ViewId>,
    /// Loaded document URI; the host chooses any persistent cache key.
    pub document_uri: String,
    /// Actual native icon candidate URL associated with these pixels.
    pub source_uri: String,
    /// Normalized 32 by 32 pixel PNG, bounded to 16 KiB.
    pub png: Arc<[u8]>,
}

impl std::fmt::Debug for OwnedFavicon {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnedFavicon")
            .field("png_bytes", &self.png.len())
            .finish_non_exhaustive()
    }
}

/// A native icon lookup could not provide a bounded current-document result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FaviconError {
    /// The runtime lacks bounded native icons with source provenance.
    UnsupportedRuntime,
    /// No completed native document or loaded icon is available yet.
    NotReady,
    /// The native icon lookup found no usable image.
    NotFound,
    /// Native image geometry, stride or bytes exceed the accepted limits.
    ImageTooLarge,
    /// A document load or logical session replacement invalidated the result.
    StaleDocument,
    /// Explicit cancellation or dropping the task won before completion.
    Cancelled,
    /// The owner-thread lookup exceeded its deadline.
    TimedOut,
    /// The bounded native lookup admission is occupied.
    Busy,
    /// The call was made outside WPE's owner thread.
    WrongThread,
    /// Native loading or PNG encoding failed.
    Native(String),
}
impl std::fmt::Display for FaviconError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "native favicon unavailable: {self:?}")
    }
}
impl std::error::Error for FaviconError {}
