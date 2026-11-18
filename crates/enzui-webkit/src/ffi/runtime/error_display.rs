//! `Display` and `Error` impls for the runtime's error types.

use super::*;

impl core::fmt::Display for DisplayError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DisplayError::WrongThread(error) => error.fmt(f),
            DisplayError::HeadlessPluginUnavailable => write!(
                f,
                "wpe_display_headless_new() returned NULL — the WPE headless \
                 platform plugin failed to load. This is NOT recovered by \
                 substituting a mock: the `wpe` feature was compiled against a \
                 runtime the current host cannot provide. Check that \
                 `libWPEWebKit-2.0.so` and its headless plugin are installed and \
                 loadable (LD_LIBRARY_PATH, WPE_PLATFORM_PLUGIN_PATH)."
            ),
            DisplayError::CredentialGuardUnavailable(why) => write!(
                f,
                "could not configure the mandatory pre-network credential guard: {why}"
            ),
        }
    }
}

impl std::error::Error for DisplayError {}

impl core::fmt::Display for NativeSnapshotError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NonPositiveDimensions { width, height } => write!(
                f,
                "native snapshot reported non-positive dimensions {width}x{height}"
            ),
            Self::Geometry(error) => write!(f, "native snapshot {error}"),
        }
    }
}

impl core::fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SnapshotError::InvalidUrl(why) => write!(
                f,
                "the requested URL was rejected: {why}. No WebView was \
                 constructed and no page was loaded."
            ),
            SnapshotError::NonDataUrl => write!(
                f,
                "snapshot_data_url accepts only host-supplied data: URLs; no WebView was constructed"
            ),
            SnapshotError::DestinationGuardUnavailable(why) => write!(
                f,
                "snapshot WebView destination guard unavailable: {why}; no unguarded view was used"
            ),
            SnapshotError::Timeout => write!(
                f,
                "the WebKit page-load + snapshot deadline expired before the \
                 snapshot callback fired — the load did not finish, or WebKit \
                 delivered no frame. This is NOT recovered by substituting a \
                 mock: the test asked for a real rendered page."
            ),
            SnapshotError::Failed(msg) => write!(
                f,
                "webkit_web_view_get_snapshot_finish returned NULL: {msg}. \
                 This is NOT recovered by substituting a mock."
            ),
            SnapshotError::WebViewConstructionFailed => write!(
                f,
                "g_object_new_with_properties(WEBKIT_TYPE_WEB_VIEW, display=…) \
                 returned NULL. The WPE display+WebKit build cannot construct a \
                 view. This is NOT recovered by substituting a mock."
            ),
            SnapshotError::SandboxDisabled(refusal) => write!(f, "{refusal}"),
            SnapshotError::SandboxNotAttested(reason) => write!(
                f,
                "the WebProcess could not be attested as sandboxed ({reason:?}); \
                 the snapshot was abandoned and the renderer terminated."
            ),
            SnapshotError::NativeSignalBindFailed(signal) => write!(
                f,
                "GObject refused to connect the `{signal}` signal (handler id 0): \
                 the signal is unknown or renamed on this WebKit, so the policy \
                 binding was refused and no view was exposed."
            ),
        }
    }
}

impl std::error::Error for SnapshotError {}

impl core::fmt::Display for PageTitleError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooLong {
                observed_bytes,
                max_bytes,
            } => write!(
                f,
                "page title exceeds {max_bytes} native bytes; observed at least {observed_bytes}"
            ),
        }
    }
}

impl std::error::Error for PageTitleError {}

impl core::fmt::Display for ImeCommandError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ImeCommandError::NotEnabled => write!(
                f,
                "the input-method seam is not installed on this view; nothing was typed"
            ),
            ImeCommandError::ViewNotBound => write!(
                f,
                "this session is bound to no view id; a view-scoped IME command \
                 cannot be attributed to it"
            ),
            ImeCommandError::ForeignSession { bound, asked } => write!(
                f,
                "IME command REFUSED: this session is bound to slot {}/gen {}, \
                 the command named slot {}/gen {}",
                bound.slot(),
                bound.generation().0,
                asked.slot(),
                asked.generation().0
            ),
            ImeCommandError::ViewNotLive { view } => write!(
                f,
                "IME command REFUSED: slot {} generation {} is no longer live \
                 (the page was recreated); nothing was typed",
                view.slot(),
                view.generation().0
            ),
            ImeCommandError::NoFocusedField => write!(
                f,
                "IME command REFUSED: no editable element holds focus in the page"
            ),
        }
    }
}

impl std::error::Error for ImeCommandError {}

impl core::fmt::Display for ViewportResizeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ViewNotBound => write!(f, "viewport resize refused: session is not bound"),
            Self::ForeignSession { bound, asked } => write!(
                f,
                "viewport resize refused: session is bound to slot {}/gen {}, request named slot {}/gen {}",
                bound.slot(),
                bound.generation().0,
                asked.slot(),
                asked.generation().0
            ),
            Self::ViewNotLive { view } => write!(
                f,
                "viewport resize refused: slot {} generation {} is no longer live",
                view.slot(),
                view.generation().0
            ),
            Self::NoToplevel => write!(f, "viewport resize refused: WPE view has no toplevel"),
            Self::Unsupported => write!(f, "viewport resize refused by the WPE platform backend"),
        }
    }
}

impl std::error::Error for ViewportResizeError {}

impl core::fmt::Display for SessionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SessionError::FontSettingsUnavailable => {
                f.write_str("native display rejected the font preference")
            }
            SessionError::BootstrapBusy => write!(f, "another renderer bootstrap is pending"),
            SessionError::BootstrapFailed(reason) => {
                write!(f, "renderer bootstrap failed: {reason}")
            }
            SessionError::ThemeSettingsUnavailable => {
                f.write_str("native display rejected the website color preference")
            }
            SessionError::OriginPermissionsUnsupported => {
                f.write_str("native runtime does not support origin-scoped browser permissions")
            }
            SessionError::InvalidUrl(why) => write!(
                f,
                "the requested URL was rejected: {why}. The load was not \
                 started."
            ),
            SessionError::InvalidScriptInput(why) => write!(f, "script input refused: {why}"),
            SessionError::DocumentReadiness(why) => {
                write!(f, "document readiness query failed: {why:?}")
            }
            SessionError::InvalidDocument { size, limit } => write!(
                f,
                "the host HTML document was rejected: {size} bytes against a \
                 {limit}-byte ceiling, or a NUL byte. The load was not started."
            ),
            SessionError::WebViewConstructionFailed => write!(
                f,
                "g_object_new_with_properties(WEBKIT_TYPE_WEB_VIEW, display=…) \
                 returned NULL. NOT recovered by substituting a mock."
            ),
            SessionError::NoWpeView => write!(
                f,
                "webkit_web_view_get_wpe_view returned NULL — the WebKit view \
                 has no WPEPlatform backing, so input cannot be forwarded. \
                 NOT recovered by substituting a mock."
            ),
            SessionError::GpuProcessUnsupported => write!(
                f,
                "WebGL or compositing in the GPU process was requested and the runtime lacks it"
            ),
            SessionError::SandboxDisabled(refusal) => write!(f, "{refusal}"),
            SessionError::SandboxNotAttested(reason) => write!(
                f,
                "the WebProcess could not be attested as sandboxed ({reason:?}); \
                 its termination was requested AND verified. The native security contract requires WebKit \
                 process sandboxing to stay enabled. NOT recovered by rendering anyway."
            ),
            SessionError::SandboxTerminationUnverified { reason, why } => write!(
                f,
                "the WebProcess was not attested ({reason:?}) and its termination \
                 could NOT be verified: {why}. The session is refused; do not assume \
                 the renderer is gone."
            ),
            SessionError::SandboxNotEstablished(reason) => write!(
                f,
                "navigation refused: this session has no attested isolated renderer \
                 ({reason:?}). Caller-supplied content is never loaded before the \
                 renderer is shown to be sandboxed."
            ),
            SessionError::Timeout(op) => write!(
                f,
                "WebSession::{op} deadline expired before completion. The GLib \
                 timeout source quit the loop; the operation did not finish. \
                 NOT recovered by substituting a mock."
            ),
            SessionError::LoadFailed { domain, code } => {
                write!(f, "main-resource load failed ({domain}, code {code})")
            }
            SessionError::TlsLoadFailed => write!(f, "main-resource TLS load failed"),
            SessionError::SnapshotFailed(msg) => write!(
                f,
                "webkit_web_view_get_snapshot_finish returned NULL: {msg}. NOT \
                 recovered by substituting a mock."
            ),
            SessionError::Profile(error) => write!(
                f,
                "WebSession profile provisioning failed: {error}. NOT recovered \
                 by using WebKit's default profile."
            ),
            SessionError::ProfileNotBound => write!(
                f,
                "WebKit did not bind the requested network session to the view. \
                 NOT recovered by using WebKit's default profile."
            ),
            SessionError::RecoveryRequiresProfile => write!(
                f,
                "cannot recover a WebSession that has no app-owned profile"
            ),
            SessionError::RecoveryWhileLive => write!(
                f,
                "cannot recover a WebSession before web-process-terminated"
            ),
            SessionError::RecoveryViewGone => write!(
                f,
                "cannot recover a WebSession from a stale or closed view generation"
            ),
            SessionError::PolicyViewGone => write!(
                f,
                "cannot bind native policy callbacks to a stale or closed view generation"
            ),
            SessionError::ForeignRebind => write!(
                f,
                "cannot rebind this session to a different slot's view id; a \
                 binding is per-slot identity and reassignment is refused"
            ),
            SessionError::RebindWhileLive => write!(
                f,
                "cannot rebind this session to a new generation while the \
                 previously-bound generation is still live; rebinding is owned \
                 recovery only"
            ),
            SessionError::ImeInstall(why) => write!(
                f,
                "could not install the input-method seam: {why}. NOT degraded to \
                 an IME-less view."
            ),
            SessionError::DestinationGuardUnavailable(why) => write!(
                f,
                "could not start the destination guard: {why}. NOT degraded to an unguarded view."
            ),
            SessionError::CredentialGuardUnavailable(why) => write!(
                f,
                "could not establish the pre-network URL-credential guard: {why}. \
                 NOT degraded to a WebView that can send embedded credentials."
            ),
            SessionError::DestinationRefused(cause) => write!(
                f,
                "destination REFUSED before any request: {} ({cause:?})",
                cause.reason()
            ),
            SessionError::NativeSignalBindFailed(signal) => write!(
                f,
                "GObject refused to connect the `{signal}` signal (handler id 0): \
                 the signal is unknown or renamed on this WebKit, so session \
                 construction was refused. NOT degraded to a view with a missing \
                 policy/lifecycle callback."
            ),
            SessionError::TlsCertificateError(why) => {
                write!(f, "TLS certificate exception could not be installed: {why}")
            }
        }
    }
}

impl std::error::Error for SessionError {}

impl core::fmt::Display for DeliverError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DeliverError::ForeignSession { bound, asked } => write!(
                f,
                "page-a11y delivery refused: this session is bound to slot {} \
                 generation {}, but the caller asked to deliver under slot {} \
                 generation {} — one session must not publish under another's id",
                bound.slot(),
                bound.generation().0,
                asked.slot(),
                asked.generation().0
            ),
            DeliverError::ViewNotBound => write!(
                f,
                "page-a11y delivery refused: this session has no bound view; \
                 call bind_view first"
            ),
            DeliverError::ViewNotLive { view } => write!(
                f,
                "page-a11y delivery refused: the bound view (slot {} generation \
                 {}) is no longer live; the walk was not attempted",
                view.slot(),
                view.generation().0
            ),
            DeliverError::Walk(e) => write!(f, "AT-SPI walk failed: {e}"),
        }
    }
}

impl std::error::Error for DeliverError {}

impl core::fmt::Display for PageActionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PageActionError::ForeignSession { bound, asked } => write!(
                f,
                "page action refused: this session is bound to slot {} generation \
                 {}, but the action named slot {} generation {} — one session \
                 must not act under another's id",
                bound.slot(),
                bound.generation().0,
                asked.slot(),
                asked.generation().0
            ),
            PageActionError::ViewNotBound => write!(
                f,
                "page action refused: this session has no bound view; call \
                 bind_view first"
            ),
            PageActionError::NotRouted(route) => write!(
                f,
                "the page action was not routed ({route:?}); nothing was performed"
            ),
            PageActionError::NotAnActivation(name) => write!(
                f,
                "the resolved action {name:?} is not an allow-listed activation, \
                 so it was refused at the point of execution"
            ),
            PageActionError::IndexOutOfRange(i) => {
                write!(f, "action index {i} does not fit an AT-SPI i32")
            }
            PageActionError::NotNativelyAuthorized(reason) => write!(
                f,
                "the page action was not authorized against native-owned state \
                 ({reason:?}), so it is refused rather than driving a real action \
                 on an unverified object"
            ),
            PageActionError::Bus(e) => write!(f, "AT-SPI: {e}"),
        }
    }
}
