//! Release ledger for thread-affine native owners, which must be destroyed in
//! order on their owning thread.
//!

use core::sync::atomic::{AtomicU64, Ordering};

static WEB_SESSIONS: AtomicU64 = AtomicU64::new(0);
static NETWORK_SESSIONS: AtomicU64 = AtomicU64::new(0);
static PROFILE_STORES: AtomicU64 = AtomicU64::new(0);
static DISPLAYS: AtomicU64 = AtomicU64::new(0);
static WEB_VIEWS_FINALIZED: AtomicU64 = AtomicU64::new(0);

/// A snapshot of how many native owners have been released process-wide.
///
/// Only differences between two snapshots are meaningful; the absolute values
/// count every page this process ever destroyed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeReleases {
    /// `WebSession`s dropped (each unref'd one `WebKitWebView`).
    pub web_sessions: u64,
    /// `NetworkSession`s dropped (each unref'd one `WebKitNetworkSession`).
    pub network_sessions: u64,
    /// `ProfileStore`s dropped.
    pub profile_stores: u64,
    /// `HeadlessDisplay`s dropped (each unref'd one `WPEDisplay`).
    pub displays: u64,
    /// `WebKitWebView`s GObject actually finalized. A session dropping its
    /// reference is `web_sessions`; this advances only when no reference is
    /// left anywhere, so a reference leaked to WebKit shows up here.
    pub web_views_finalized: u64,
}

impl NativeReleases {
    /// Per-field `self - earlier`, saturating: the released-since delta.
    #[must_use]
    pub fn since(self, earlier: Self) -> Self {
        Self {
            web_sessions: self.web_sessions.saturating_sub(earlier.web_sessions),
            network_sessions: self
                .network_sessions
                .saturating_sub(earlier.network_sessions),
            profile_stores: self.profile_stores.saturating_sub(earlier.profile_stores),
            displays: self.displays.saturating_sub(earlier.displays),
            web_views_finalized: self
                .web_views_finalized
                .saturating_sub(earlier.web_views_finalized),
        }
    }
}

/// Read the release ledger.
///
/// `Acquire` loads pair with the `Release` increments the owners' `Drop`
/// performs on the worker thread, so a reader that observes an advanced
/// counter also observes everything that `Drop` did before it.
#[must_use]
pub fn released() -> NativeReleases {
    NativeReleases {
        web_sessions: WEB_SESSIONS.load(Ordering::Acquire),
        network_sessions: NETWORK_SESSIONS.load(Ordering::Acquire),
        profile_stores: PROFILE_STORES.load(Ordering::Acquire),
        displays: DISPLAYS.load(Ordering::Acquire),
        web_views_finalized: WEB_VIEWS_FINALIZED.load(Ordering::Acquire),
    }
}

/// Record one released `WebSession`. Called only from its `Drop`.
#[cfg(feature = "wpe")]
pub(crate) fn record_web_session() {
    WEB_SESSIONS.fetch_add(1, Ordering::Release);
}

/// Record one released `NetworkSession`. Called only from its `Drop`.
#[cfg(feature = "wpe")]
pub(crate) fn record_network_session() {
    NETWORK_SESSIONS.fetch_add(1, Ordering::Release);
}

/// Record one released `ProfileStore`. Called only from its `Drop`.
#[cfg(feature = "wpe")]
pub(crate) fn record_profile_store() {
    PROFILE_STORES.fetch_add(1, Ordering::Release);
}

/// Record one released `HeadlessDisplay`. Called only from its `Drop`.
#[cfg(feature = "wpe")]
pub(crate) fn record_display() {
    DISPLAYS.fetch_add(1, Ordering::Release);
}

/// Record one finalized `WebKitWebView`. Called only from the GObject weak
/// notification every session's view carries.
#[cfg(feature = "wpe")]
pub(crate) fn record_web_view_finalized() {
    WEB_VIEWS_FINALIZED.fetch_add(1, Ordering::Release);
}
