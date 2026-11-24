//! Native WPE policy callbacks with correlated, generation-scoped replies.
//!
//! WebKit's default signal handlers are permissive for several decisions. This
//! bridge therefore returns `G_TRUE` from every callback it owns and performs a
//! terminal native action itself. The responder must echo the exact
//! [`ViewRequestId`] raised by the callback. No response, an id from another
//! request, or an id from a superseded [`ViewId`] all execute the native deny
//! action immediately; they never fall through to WebKit's default handler.

use super::wpe as ffi;
use crate::permission_map::MediaCaptureFlags;
use crate::web::policy::{
    CertContext, NavContext, PermissionKind, PolicyUrl, PopupContext, RequestKind,
};
use crate::web::{Decision, ViewId, WebPolicy};
use crate::{PolicySession, SessionResolve, ViewRequestId};
use core::ffi::{c_char, c_int, c_void};
use std::cell::Cell;
use std::collections::VecDeque;
use std::ffi::CString;
use std::ptr;

/// Constant-only WebProcess messages used by the pre-network credential guard.
/// Neither message has parameters; in particular URL userinfo never crosses
/// from the process that observed it.
const CREDENTIAL_GUARD_READY: &str = "enzui-credential-guard-ready-v1";
const CREDENTIALS_IN_URL_DENIED: &str = "enzui-credentials-in-url-v1";

/// Maximum number of bytes accepted from a native policy URI.
///
/// The terminating NUL is not part of this budget. Native strings are scanned
/// only through byte `MAX_POLICY_URI_BYTES + 1`, so an over-limit URI is
/// refused before it can become a full Rust allocation.
pub const MAX_POLICY_URI_BYTES: usize = 64 * 1024;

/// Maximum bytes in a certificate host authorization identity.
///
/// Unlike diagnostic strings, a host is never truncated: an over-limit host
/// is a different identity and is refused before policy or native routing.
pub const MAX_CERTIFICATE_HOST_BYTES: usize = 253;

/// A malformed native URI refused before policy evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeUriError {
    /// The native API returned a null URI pointer.
    Null,
    /// No terminating NUL occurred within the accepted byte limit.
    TooLong,
    /// The bounded native bytes were not valid UTF-8.
    InvalidUtf8,
    /// The URI did not contain a valid certificate host identity.
    InvalidHost,
    /// The complete certificate host exceeded [`MAX_CERTIFICATE_HOST_BYTES`].
    HostTooLong,
}

impl NativeUriError {
    fn diagnostic_url(self) -> &'static str {
        match self {
            Self::Null => "invalid:missing-uri",
            Self::TooLong => "invalid:uri-too-long",
            Self::InvalidUtf8 => "invalid:uri-not-utf8",
            Self::InvalidHost => "invalid:certificate-host",
            Self::HostTooLong => "invalid:certificate-host-too-long",
        }
    }
}

/// Why a certificate-authorization host identity was refused before any
/// native call.
///
/// WebKit compares the string handed to
/// `webkit_network_session_allow_tls_certificate_for_host` against the
/// request's `URL::host()` (ASCII-case-insensitively, IPv6 brackets already
/// stripped). Anything that cannot *be* a `URL::host()` - an empty string, a
/// `host:port` pair, a URL spelling, an unbracketed authority with a path or
/// userinfo, an over-limit or malformed DNS/IP name - would install an
/// exception that can never match, i.e. a silent no-op advertised as a
/// pre-trust. Each is named here instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateHostError {
    /// The host was empty. An empty exception scopes to nothing.
    Empty,
    /// The host carried a scheme, `//` prefix or other URL spelling.
    UrlForm,
    /// The host carried userinfo (`user@host`).
    UserInfo,
    /// The host carried a path, query or fragment.
    PathQueryOrFragment,
    /// The host carried a port. WebKit's comparison identity is host-only, so
    /// `localhost:8443` never equals `localhost`.
    Port,
    /// The host was a bracketed IPv6 spelling. WebKit documents the
    /// opposite: "If `host` is an IPv6 address, it should not be surrounded by
    /// brackets" - and it strips the brackets off the request URL's host
    /// before comparing, so a bracketed exception matches nothing. Pass the
    /// bare literal (`::1`).
    BracketedIpv6,
    /// The host exceeded [`MAX_CERTIFICATE_HOST_BYTES`]. A truncated host is a
    /// different identity, so it is refused rather than shortened.
    TooLong,
    /// The host was not a valid DNS name or canonical IP literal, including
    /// an alternate/malformed numeric spelling WebKit would treat as IPv4.
    InvalidShape,
}

impl CertificateHostError {
    /// Stable, request-data-free description for a typed error message.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Empty => "certificate host is empty",
            Self::UrlForm => "certificate host is a URL, not a host identity",
            Self::UserInfo => "certificate host carries userinfo",
            Self::PathQueryOrFragment => "certificate host carries a path, query or fragment",
            Self::Port => "certificate host carries a port",
            Self::BracketedIpv6 => {
                "certificate host is a bracketed IPv6 literal; WebKit compares the bare address"
            }
            Self::TooLong => "certificate host exceeds the DNS length limit",
            Self::InvalidShape => "certificate host is not a valid DNS name or IP literal",
        }
    }
}

/// One policy question observed at a real WebKit callback boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativePolicyRequest {
    /// Correlation id, including the originating view generation.
    pub id: ViewRequestId,
    /// The typed question translated from WebKit's callback arguments.
    pub kind: RequestKind,
}

/// Why a callback proceeded or failed closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativePolicyOutcome {
    /// The exact live request was answered and the typed policy was applied.
    Applied(Decision),
    /// The responder returned no answer; the native request was denied.
    NoResponseDenied,
    /// The responder answered with a different request id; the current native
    /// request was denied and the unrelated id was not consumed.
    MismatchedResponseDenied,
    /// The responder named a request from a superseded view generation.
    StaleResponseDenied,
    /// The host responder panicked. The panic was caught at the C ABI
    /// boundary, the native request was immediately denied, and the responder
    /// is poisoned: all subsequent requests are denied without calling it.
    /// No panic payload is retained (it may contain secrets).
    ResponderPanicked,
    /// The same binding dispatched another policy request while its responder
    /// was already running. The nested request was denied without invoking the
    /// responder again.
    ReentrantResponderDenied,
    /// The native URI was malformed or exceeded [`MAX_POLICY_URI_BYTES`].
    /// The host responder and URL authorization policy never receive the
    /// rejected bytes (including any truncated prefix).
    UriRefused(NativeUriError),
    /// WebKit fired `WebKitNetworkSession::download-started` for a download
    /// this view initiated after the paired response-policy decision selected
    /// [`ffi::webkit_policy_decision_download`]. Paired with
    /// [`RequestKind::Download`] carrying the URI WebKit reported.
    ///
    /// The safe layer immediately cancels the download so no bytes touch
    /// disk; the observation records the native follow-up alone. This
    /// is what proves the download allow branch actually reached WebKit,
    /// rather than only the decide-policy call site.
    DownloadStarted,
}

/// Auditable result of one WebKit callback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativePolicyObservation {
    /// Request raised by the callback.
    pub request: NativePolicyRequest,
    /// Terminal result actually applied at the native boundary.
    pub outcome: NativePolicyOutcome,
}

/// The terminal native action a real `load-failed-with-tls-errors` callback
/// performed for one failed certificate.
///
/// Exactly one of these is recorded per callback, so "the callback fired" and
/// "a terminal action was applied" are separately observable: a certificate
/// path that is registered but never fires, and one that fires but applies
/// nothing, are different defects with the same symptom (no continuation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateAction {
    /// Policy denied the certificate: no per-host exception was installed and
    /// the failing URI was not reloaded.
    Denied,
    /// Policy allowed it and the renderer passed the navigation gate, so a
    /// per-host exception was installed and the failing URI reloaded.
    ContinuedForHost,
    /// Policy allowed it but sandbox attestation failed or the binding/view
    /// changed while it ran, so the retry was refused: no exception, no reload.
    AttestationRefused,
    /// Policy allowed it but the failing URI carried no host to scope an
    /// exception to, so nothing was installed. A hostless exception would be a
    /// global one.
    HostUnknown,
    /// Policy allowed it, but this view has already spent its continuation
    /// budget for the host (or cannot track another host), so the retry was
    /// refused: no exception, no reload.
    ///
    /// The continuation is a retry of a security failure: it pins the exact
    /// certificate WebKit just rejected and immediately reloads the failing URI
    /// from inside the failure callback - no delay, and nothing in WebKit's
    /// signal ends the cycle. A repeat failure for the same host therefore
    /// means the exception did not settle the handshake (a rotated
    /// self-signed certificate, an interception injecting a fresh certificate
    /// per connection, or a policy that allows everything), so continuing again
    /// cannot succeed: it only re-issues the load. That is the unbounded,
    /// zero-delay retry this action refuses, and it is refused *before* any
    /// native call, so no further exception is installed either.
    RetryBudgetExhausted,
}

/// One real certificate callback and the terminal native action it took.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateEvent {
    /// Correlation id (including view generation) of the certificate request
    /// this action answered. Equal to the paired
    /// [`NativePolicyObservation`]'s request id, which is what proves the
    /// native action used the live correlated request rather than a stale one.
    pub request: ViewRequestId,
    /// The authorization identity parsed from the failing URI: exactly the
    /// string handed to WebKit's per-host exception (IPv6 brackets stripped, a
    /// trailing DNS-root dot preserved). Empty when the URI carried no valid
    /// host.
    pub host: String,
    /// The folded correlation key for the same authority (ASCII-lowercased,
    /// trailing root dot dropped, IP literals canonicalized). This is the
    /// retry-budget identity, never the authorization identity: two spellings
    /// of one authority share a budget, but each is authorized under the exact
    /// name WebKit compares.
    pub key: String,
    /// The policy outcome that selected this action.
    pub outcome: NativePolicyOutcome,
    /// The terminal native action performed. This is one enum rather than
    /// independently mutable booleans, so impossible partial combinations
    /// cannot appear in the ledger.
    pub action: CertificateAction,
}

/// One host-initiated certificate pre-trust and what it did.
///
/// The public installer takes no native action on invalid input, so without a
/// record "the exception was refused" and "the exception was installed and
/// never matched" look identical from outside. Both are appended here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreTrustEvent {
    /// The validated authorization identity actually handed to WebKit, or the
    /// empty string when nothing was installed. Rejected input is not
    /// retained: it is unvalidated and may be arbitrarily long.
    pub host: String,
    /// The folded correlation key for the installed identity, empty when
    /// nothing was installed. Same relationship as
    /// [`CertificateEvent::key`].
    pub key: String,
    /// What the installer did.
    pub outcome: PreTrustOutcome,
}

/// The terminal result of one host-initiated pre-trust.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreTrustOutcome {
    /// A scoped exception was installed for one certificate on one host.
    Installed,
    /// Denied: the host could never equal WebKit's request host. No native
    /// call was made, and the certificate PEM was never parsed.
    HostDenied(CertificateHostError),
    /// Denied: the host was a valid identity but the PEM did not parse, so no
    /// exception exists.
    CertificateDenied,
}

impl PreTrustOutcome {
    /// Whether this pre-trust installed an exception.
    #[must_use]
    pub const fn installed(self) -> bool {
        matches!(self, Self::Installed)
    }
}

/// A `load-failed` fallback WebKit reported, named by error domain and code.
///
/// Recorded for diagnostics only. `GError::message` is deliberately not
/// retained (it embeds the failing URI); the domain name is a glib-interned
/// compile-time identifier such as `g-tls-error-quark` or `g-io-error-quark`,
/// and the pair (domain, code) is what tells a TLS certificate failure apart
/// from "nothing was listening".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadFailure {
    /// Interned glib error-domain name, truncated to a fixed bound.
    pub domain: String,
    /// Domain-specific error code.
    pub code: i32,
    /// The failing URL, redacted before storage and length-bounded.
    pub url: PolicyUrl,
}

/// What WebKit actually received for one main-frame main-resource decision.
///
/// a missing certificate observation is ambiguous unless the
/// alternative is visible. If the origin answered at all - with what status
/// and what MIME type - then the handshake succeeded and the certificate was
/// never questioned; if nothing was received, the failure is upstream of the
/// response. Neither field can carry request data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MainResponse {
    /// The URL the decision was for, redacted before storage and length-bounded.
    pub url: PolicyUrl,
    /// HTTP status code WebKit reported (0 when unavailable).
    pub status: u32,
    /// MIME type WebKit resolved, truncated to a fixed bound.
    pub mime: String,
    /// Whether WebKit can render that MIME type (the branch selector between
    /// the resource arm and the download arm).
    pub mime_supported: bool,
}

struct CallbackLifetime {
    binding_live: Cell<bool>,
    active_callbacks: Cell<usize>,
}

impl CallbackLifetime {
    fn new() -> Self {
        Self {
            binding_live: Cell::new(true),
            active_callbacks: Cell::new(0),
        }
    }

    fn retire(&self) {
        self.binding_live.set(false);
    }

    fn can_free(&self) -> bool {
        !self.binding_live.get() && self.active_callbacks.get() == 0
    }
}

struct CallbackLease {
    state: *mut State,
}

impl CallbackLease {
    /// Keeps callback state allocated through nested main-context dispatch.
    ///
    /// # Safety
    ///
    /// `data` must be the live `State` pointer installed by
    /// `NativePolicyBinding`, or a live test state for one direct callback;
    /// callback entry and binding teardown must remain on the same GLib thread.
    unsafe fn enter(data: *mut c_void) -> Self {
        let state = data.cast::<State>();
        // SAFETY: the signal owns a live callback-data pointer at entry. The
        // active count defers binding teardown until every nested callback has
        // returned.
        let active = unsafe { (*state).callback_lifetime.active_callbacks.get() };
        let Some(next) = active.checked_add(1) else {
            std::process::abort();
        };
        // SAFETY: the same callback-data invariant permits this scalar update;
        // no `State` reference is created or retained.
        unsafe {
            (*state).callback_lifetime.active_callbacks.set(next);
        }
        Self { state }
    }

    fn with_state_no_reentry<R>(&self, use_state: impl FnOnce(&mut State) -> R) -> R {
        // SAFETY: this lease keeps the callback allocation alive. Callers use
        // this only for non-reentrant phases, and `R` cannot borrow the state,
        // so the exclusive reference ends before control returns.
        use_state(unsafe { &mut *self.state })
    }

    fn decide(&self, kind: RequestKind) -> (NativePolicyRequest, NativePolicyOutcome) {
        let (request, responder, immediate) = self.with_state_no_reentry(|state| {
            let id = state.session.open(state.view, kind.clone());
            let request = NativePolicyRequest { id, kind };
            let unavailable = if state.poisoned {
                Some(NativePolicyOutcome::ResponderPanicked)
            } else if state.responder.is_none() {
                Some(NativePolicyOutcome::ReentrantResponderDenied)
            } else {
                None
            };
            if let Some(outcome) = unavailable {
                let _ = state.session.resolve(id);
                state.observations.push(NativePolicyObservation {
                    request: request.clone(),
                    outcome,
                });
                (request, None, Some(outcome))
            } else {
                (request, state.responder.take(), None)
            }
        });
        if let Some(outcome) = immediate {
            return (request, outcome);
        }
        let mut responder = responder.expect("an available responder can be taken");

        // The responder is owned by this stack frame while host code runs, so
        // callback state can be reacquired only after that call has returned.
        let (reply, panic_payload) =
            match crate::panic_boundary::catch_silent(|| responder(&request)) {
                Ok(reply) => (Some(reply), None),
                Err(payload) => (None, Some(payload)),
            };
        let panicked = panic_payload.is_some();
        let mut responder = Some(responder);
        let outcome = self.with_state_no_reentry(|state| {
            if panicked {
                state.poisoned = true;
                let _ = state.session.resolve(request.id);
                NativePolicyOutcome::ResponderPanicked
            } else {
                debug_assert!(state.responder.is_none());
                state.responder = responder.take();
                if !state.callback_lifetime.binding_live.get() {
                    let _ = state.session.resolve(request.id);
                    NativePolicyOutcome::StaleResponseDenied
                } else {
                    match reply.expect("the non-panicking responder has a reply") {
                        None => {
                            let _ = state.session.resolve(request.id);
                            NativePolicyOutcome::NoResponseDenied
                        }
                        Some(reply) if reply != request.id => {
                            let _ = state.session.resolve(request.id);
                            if reply.view().slot() == request.id.view().slot()
                                && reply.view().generation() != request.id.view().generation()
                            {
                                NativePolicyOutcome::StaleResponseDenied
                            } else {
                                NativePolicyOutcome::MismatchedResponseDenied
                            }
                        }
                        Some(_) => match state.session.resolve(request.id) {
                            SessionResolve::Decided { decision, .. } => {
                                NativePolicyOutcome::Applied(decision)
                            }
                            SessionResolve::ViewGone { .. } => {
                                NativePolicyOutcome::StaleResponseDenied
                            }
                            SessionResolve::Unknown { .. } => {
                                NativePolicyOutcome::MismatchedResponseDenied
                            }
                        },
                    }
                }
            }
        });
        drop(responder);
        drop(panic_payload);
        self.with_state_no_reentry(|state| {
            state.observations.push(NativePolicyObservation {
                request: request.clone(),
                outcome,
            });
        });
        (request, outcome)
    }

    fn route_uri(
        &self,
        route: UriRoute,
        uri: Result<String, NativeUriError>,
    ) -> (NativePolicyRequest, NativePolicyOutcome) {
        match uri {
            Ok(uri) => self.decide(route.request(uri)),
            Err(error) => self.with_state_no_reentry(|state| {
                state.refuse_uri(route.request(error.diagnostic_url().to_owned()), error)
            }),
        }
    }

    fn route_certificate_identity(
        &self,
        identity: Result<(String, String), NativeUriError>,
    ) -> (
        String,
        String,
        Option<CString>,
        NativePolicyRequest,
        NativePolicyOutcome,
    ) {
        let identity = identity.and_then(|(host, key)| {
            let host_c = CString::new(host.as_str()).map_err(|_| NativeUriError::InvalidHost)?;
            Ok((host, key, host_c))
        });
        match identity {
            Ok((host, key, host_c)) => {
                let (request, outcome) = self.decide(RequestKind::Certificate(CertContext {
                    host: key.clone(),
                    validation_failed: true,
                }));
                (host, key, Some(host_c), request, outcome)
            }
            Err(error) => {
                let kind = RequestKind::Certificate(CertContext {
                    host: String::new(),
                    validation_failed: true,
                });
                let (request, outcome) =
                    self.with_state_no_reentry(|state| state.refuse_uri(kind, error));
                (String::new(), String::new(), None, request, outcome)
            }
        }
    }
}

impl Drop for CallbackLease {
    fn drop(&mut self) {
        // SAFETY: every lease increments this counter exactly once, and the
        // allocation remains live until the final lease observes retirement.
        let should_free = {
            let lifetime = unsafe { &(*self.state).callback_lifetime };
            let Some(remaining) = lifetime.active_callbacks.get().checked_sub(1) else {
                std::process::abort();
            };
            lifetime.active_callbacks.set(remaining);
            lifetime.can_free()
        };
        if should_free {
            // SAFETY: binding teardown relinquished the sole owner and this is
            // the last active callback lease.
            drop(unsafe { Box::from_raw(self.state) });
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum UriRoute {
    Navigation { user_initiated: bool },
    Popup { user_initiated: bool },
    Resource { main_frame: bool },
    Download,
}

impl UriRoute {
    fn request(self, url: String) -> RequestKind {
        let url = PolicyUrl::new(url);
        match self {
            Self::Navigation { user_initiated } => RequestKind::Navigation(NavContext {
                url,
                user_initiated,
            }),
            Self::Popup { user_initiated } => RequestKind::Popup(PopupContext {
                url,
                user_initiated,
            }),
            Self::Resource { main_frame } => RequestKind::Resource { url, main_frame },
            Self::Download => RequestKind::Download { url },
        }
    }
}

struct DownloadContinuation {
    target: String,
    requested: String,
    since: std::time::Instant,
    responded: bool,
}
struct State {
    local_origins: crate::local_origins::LocalOriginAllowlist,
    download_mime_types: Vec<String>,
    blob_downloads: VecDeque<(String, std::time::Instant)>,
    forced_download: Option<DownloadContinuation>,
    callback_lifetime: CallbackLifetime,
    view: ViewId,
    session: PolicySession,
    // Taken for the duration of a call: `None` means a dispatch is in flight,
    // not that the binding lacks a responder. A nested dispatch therefore finds
    // an empty slot and denies rather than aliasing the `FnMut`.
    responder: Option<Box<Responder>>,
    /// Whether the responder has panicked and is permanently poisoned.
    poisoned: bool,
    observations: BoundedObservations,
    web_view: *mut ffi::WebKitWebView,
    network_session: *mut ffi::WebKitNetworkSession,
    /// The session's outer-sandbox policy, carried so the certificate retry
    /// below enforces under the same policy the session was constructed with
    /// rather than a hard-coded stricter or looser one.
    outer_sandbox: crate::sandbox::OuterSandbox,
    /// The WebProcess identities that existed before the owning session's view,
    /// so the retry's attestation is scoped to this session's renderer.
    sandbox_baseline: Vec<crate::sandbox::ProcessIdentity>,
    /// Single-use permission to navigate to one exact inert URL.
    ///
    /// The renderer is spawned on `about:blank` before any policy exists to
    /// judge a real URL, and retrieving a host-supplied `data:` URL itself uses
    /// no network (its scripts/subresources remain guarded), so
    /// neither is a destination the policy can pass. Rather than exempt those
    /// schemes - which would hand every page a permanent bypass - the session
    /// mints one allowance for one exact URL immediately before it starts a
    /// host-initiated inert load, and the navigation callback consumes it for
    /// that URL and nothing else. A page-initiated navigation never finds a
    /// permit waiting.
    ///
    /// Held as a raw `String` rather than a `PolicyUrl` deliberately: it is
    /// compared, never rendered, and it never reaches an observation - so
    /// the diagnostic redaction surface does not grow.
    inert_permit: Option<String>,
    destination_policy: crate::web::DestinationPolicy,
    last_navigation: Option<String>,
    redirect_hops: u32,
    /// Set only by the WebProcess extension's constant bootstrap message. A
    /// session is not returned to a caller until this proves the cancellable
    /// `WebKitWebPage::send-request` hook is active in its renderer.
    credential_guard_ready: bool,
    /// Bounded diagnostics for the real TLS-certificate path.
    certificates: CertificateLedger,
    /// The session's page-event queue: registered redirect URIs are stopped
    /// here before any policy runs, and an allowed popup is reported to it.
    page: std::rc::Rc<super::page::PageHub>,
}

impl State {
    fn refuse_uri(
        &mut self,
        kind: RequestKind,
        error: NativeUriError,
    ) -> (NativePolicyRequest, NativePolicyOutcome) {
        let id = self.session.open(self.view, kind.clone());
        let request = NativePolicyRequest { id, kind };
        // Resolve only the fixed diagnostic sentinel, never a prefix of the
        // rejected URI. Its policy result is deliberately ignored; malformed
        // native input has the typed fail-closed outcome.
        let _ = self.session.resolve(id);
        let outcome = NativePolicyOutcome::UriRefused(error);
        self.observations.push(NativePolicyObservation {
            request: request.clone(),
            outcome,
        });
        (request, outcome)
    }

    fn force_deny(
        &mut self,
        kind: RequestKind,
        reason: crate::web::policy::DenyReason,
    ) -> NativePolicyOutcome {
        let id = self.session.open(self.view, kind.clone());
        let request = NativePolicyRequest { id, kind };
        let _ = self.session.resolve(id);
        let outcome = NativePolicyOutcome::Applied(Decision::Deny(reason));
        self.observations
            .push(NativePolicyObservation { request, outcome });
        outcome
    }
}

/// Owns the WebKit signal handlers and their stable callback state.
///
/// Six handlers hang off the `WebKitWebView` itself
/// (`decide-policy`, `permission-request`, `load-failed-with-tls-errors`,
/// `create`, `user-message-received`, and the diagnostic-only `load-failed`)
/// and one hangs off the view's `WebKitNetworkSession` (`download-started`).
/// Because those two objects are distinct GObject
/// instances, the [`Drop`] impl disconnects each handler from the correct
/// instance before the shared callback state is freed.
pub(crate) struct NativePolicyBinding {
    state: *mut State,
    view_handlers: [u64; VIEW_SIGNAL_COUNT],
    session_handlers: [u64; 1],
}

/// Signals connected on the `WebKitWebView` itself.
const VIEW_SIGNAL_COUNT: usize = 6;

/// Index of `load-failed-with-tls-errors` within [`VIEW_SIGNAL_COUNT`]'s
/// connection order. The binding records this id in the certificate ledger, so
/// a diagnosis can tell an unregistered callback from one that never fired.
const TLS_SIGNAL_SLOT: usize = 2;

impl NativePolicyBinding {
    pub(super) fn replace_transactionally<F>(
        installed: &mut Option<Self>,
        build: F,
    ) -> Result<(), super::signal::SignalBindError>
    where
        F: FnOnce() -> Result<Self, super::signal::SignalBindError>,
    {
        let replacement = build()?;
        let retired = installed.replace(replacement);
        drop(retired);
        Ok(())
    }

    /// Attach fail-closed policy handling to `web_view`.
    ///
    /// The responder is deliberately synchronous: the bounded engine worker
    /// may answer only what it already has. Returning `None` cannot leave a
    /// WebKit decision dangling; it denies in the same callback.
    pub(super) fn new<F>(
        web_view: *mut ffi::WebKitWebView,
        network_session: *mut ffi::WebKitNetworkSession,
        view: ViewId,
        policy: WebPolicy,
        outer_sandbox: crate::sandbox::OuterSandbox,
        sandbox_baseline: Vec<crate::sandbox::ProcessIdentity>,
        responder: F,
    ) -> Result<Self, super::signal::SignalBindError>
    where
        F: FnMut(&NativePolicyRequest) -> Option<ViewRequestId> + 'static,
    {
        let local_origins = policy.local_origins.clone();
        let destination_policy = policy.destination();
        let mut session = PolicySession::new(policy);
        session.open_view(view);
        let state = Box::into_raw(Box::new(State {
            local_origins,
            download_mime_types: Vec::new(),
            blob_downloads: VecDeque::new(),
            forced_download: None,
            callback_lifetime: CallbackLifetime::new(),
            view,
            session,
            responder: Some(Box::new(responder)),
            poisoned: false,
            observations: BoundedObservations::with_capacity(BoundedObservations::DEFAULT_CAPACITY),
            web_view,
            network_session,
            outer_sandbox,
            sandbox_baseline,
            inert_permit: None,
            destination_policy,
            last_navigation: None,
            redirect_hops: 0,
            credential_guard_ready: false,
            certificates: CertificateLedger::new(),
            page: std::rc::Rc::default(),
        }));
        // SAFETY: GSignal's C API erases callbacks to `void (*)(void)`; each
        // concrete function below exactly matches the documented signal ABI.
        let decide: extern "C" fn() = unsafe {
            core::mem::transmute(
                on_decide_policy
                    as extern "C" fn(
                        *mut ffi::WebKitWebView,
                        *mut ffi::WebKitPolicyDecision,
                        c_int,
                        *mut c_void,
                    ) -> ffi::GBoolean,
            )
        };
        let permission: extern "C" fn() = unsafe {
            core::mem::transmute(
                on_permission_request
                    as extern "C" fn(
                        *mut ffi::WebKitWebView,
                        *mut ffi::WebKitPermissionRequest,
                        *mut c_void,
                    ) -> ffi::GBoolean,
            )
        };
        let tls: extern "C" fn() = unsafe {
            core::mem::transmute(
                on_tls_failure
                    as extern "C" fn(
                        *mut ffi::WebKitWebView,
                        *const i8,
                        *mut ffi::GTlsCertificate,
                        c_int,
                        *mut c_void,
                    ) -> ffi::GBoolean,
            )
        };
        let create: extern "C" fn() = unsafe {
            core::mem::transmute(
                on_create
                    as extern "C" fn(
                        *mut ffi::WebKitWebView,
                        *mut ffi::WebKitNavigationAction,
                        *mut c_void,
                    ) -> *mut ffi::WebKitWebView,
            )
        };
        let user_message: extern "C" fn() = unsafe {
            core::mem::transmute(
                on_user_message
                    as extern "C" fn(
                        *mut ffi::WebKitWebView,
                        *mut ffi::WebKitUserMessage,
                        *mut c_void,
                    ) -> ffi::GBoolean,
            )
        };
        let load_failed: extern "C" fn() = unsafe {
            core::mem::transmute(
                on_load_failed
                    as extern "C" fn(
                        *mut ffi::WebKitWebView,
                        c_int,
                        *const i8,
                        *mut ffi::GError,
                        *mut c_void,
                    ) -> ffi::GBoolean,
            )
        };
        let download_started: extern "C" fn() = unsafe {
            core::mem::transmute(
                on_download_started
                    as extern "C" fn(
                        *mut ffi::WebKitNetworkSession,
                        *mut ffi::WebKitDownload,
                        *mut c_void,
                    ),
            )
        };
        // every connection is guarded against a zero handler id. A
        // `SignalBinder` accumulates the nonzero ids so that if any signal
        // (unknown or renamed on this WebKit) refuses to connect, every
        // earlier id is disconnected - from the correct GObject instance - and
        // the shared state box is freed, rather than exposing a binding that
        // is silently missing a callback.
        let mut binder = super::signal::SignalBinder::new();
        // `download-started` fires on the NetworkSession, not the
        // WebView. Connect it on the same session pointer the state carries so
        // the observation ring records the native consequence of
        // `webkit_policy_decision_download` - not merely the decide-policy
        // call site.
        type Connections = ([u64; VIEW_SIGNAL_COUNT], [u64; 1]);
        let connections: Result<Connections, super::signal::SignalBindError> = (|| {
            // SAFETY: each callback matches the ABI of the signal it is bound
            // to; `state` outlives every firing (it is freed only in `Drop`
            // or on the rollback path below).
            let view_handlers = unsafe {
                [
                    binder.connect(
                        web_view.cast::<c_void>(),
                        "decide-policy",
                        decide,
                        state.cast(),
                    )?,
                    binder.connect(
                        web_view.cast::<c_void>(),
                        "permission-request",
                        permission,
                        state.cast(),
                    )?,
                    binder.connect(
                        web_view.cast::<c_void>(),
                        "load-failed-with-tls-errors",
                        tls,
                        state.cast(),
                    )?,
                    binder.connect(web_view.cast::<c_void>(), "create", create, state.cast())?,
                    binder.connect(
                        web_view.cast::<c_void>(),
                        "user-message-received",
                        user_message,
                        state.cast(),
                    )?,
                    // Diagnostics only: WebKit emits `load-failed`
                    // when no handler claimed `load-failed-with-tls-errors`,
                    // and for every non-TLS failure. Recording the error
                    // DOMAIN and CODE (never the message, which embeds the
                    // URI) is what separates "the certificate callback is not
                    // wired" from "the fixture produced no TLS error". The
                    // handler returns FALSE, so WebKit's own default handling
                    // is unchanged.
                    binder.connect(
                        web_view.cast::<c_void>(),
                        "load-failed",
                        load_failed,
                        state.cast(),
                    )?,
                ]
            };
            // SAFETY: `download_started` matches the NetworkSession signal ABI.
            let session_handlers = unsafe {
                [binder.connect(
                    network_session.cast::<c_void>(),
                    "download-started",
                    download_started,
                    state.cast(),
                )?]
            };
            Ok((view_handlers, session_handlers))
        })();
        let (view_handlers, session_handlers) = match connections {
            Ok(handlers) => handlers,
            Err(err) => {
                // The binder already disconnected every earlier nonzero id.
                // Free the callback state allocated so a refused
                // construction leaks nothing.
                // SAFETY: `state` is the box minted above and no live
                // binding references it.
                drop(unsafe { Box::from_raw(state) });
                return Err(err);
            }
        };
        // record the REAL handler id GObject returned for the
        // certificate signal. A ledger flag set by hand would report "wired"
        // for a binding that never connected; this reports what GObject
        // actually did, so an unwired callback and a callback that never fires
        // are distinguishable in the same diagnostic.
        // SAFETY: `state` is the box minted above; no callback can have run
        // yet on this thread, so the unique borrow is sound.
        unsafe { (*state).certificates.tls_handler_id = view_handlers[TLS_SIGNAL_SLOT] };
        Ok(Self {
            state,
            view_handlers,
            session_handlers,
        })
    }

    pub(crate) fn set_download_mime_types(&self, types: &[&str]) {
        let types = types
            .iter()
            .take(32)
            .filter_map(|mime| normalized_mime(mime))
            .collect();
        // SAFETY: this owner-thread binding retains state; no native call or callback can reenter here.
        unsafe {
            (*self.state).download_mime_types = types;
        }
    }

    /// Shares the session's page-event queue with these callbacks, for
    /// redirect capture and popup reports. Until then the binding has a
    /// private queue no one reads, which captures nothing.
    pub(super) fn with_page(self, page: std::rc::Rc<super::page::PageHub>) -> Self {
        // SAFETY: state is owned by self and no callback is running.
        unsafe { (*self.state).page = page };
        self
    }

    /// Rebind callbacks to a replacement generation. Outstanding requests from
    /// the old generation are invalidated before the replacement becomes live.
    pub(super) fn replace_view(&mut self, view: ViewId) {
        // SAFETY: state is owned by self and callbacks are thread-affine.
        let state = unsafe { &mut *self.state };
        let old = state.view;
        let _ = state.session.close_view(old);
        state.view = view;
        state.blob_downloads.clear();
        state.forced_download = None;
        state.session.open_view(view);
    }

    /// Forget an unanswered range continuation for `uri`; false once its
    /// response arrived or another navigation superseded it.
    pub(super) fn retire_download_continuation(&self, uri: &str) -> bool {
        // SAFETY: this owner-thread binding retains state; no native callback runs inside the lease.
        let lease = unsafe { CallbackLease::enter(self.state.cast()) };
        lease.with_state_no_reentry(|state| {
            if state
                .forced_download
                .as_ref()
                .is_some_and(|p| p.requested == uri && !p.responded)
            {
                state.forced_download = None;
                true
            } else {
                false
            }
        })
    }
    /// Route the next main-frame response for `uri` to a download, for a
    /// host-started range continuation. One continuation is pending at a time.
    pub(super) fn force_download_response(&self, uri: &str) -> bool {
        // SAFETY: this owner-thread binding retains state; the closure performs no native callbacks.
        let lease = unsafe { CallbackLease::enter(self.state.cast()) };
        lease.with_state_no_reentry(|state| {
            if state
                .forced_download
                .as_ref()
                .is_some_and(|p| p.since.elapsed() < std::time::Duration::from_secs(30))
            {
                return false;
            }
            state.forced_download = Some(DownloadContinuation {
                target: uri.into(),
                requested: uri.into(),
                since: std::time::Instant::now(),
                responded: false,
            });
            true
        })
    }
    /// Screen a host-started download through the view's Download policy.
    pub(super) fn approve_host_download(&self, uri: &str) -> bool {
        // SAFETY: the owner-thread binding retains callback state for this synchronous policy lease.
        let lease = unsafe { CallbackLease::enter(self.state.cast()) };
        matches!(
            lease.route_uri(UriRoute::Download, Ok(uri.to_owned())).1,
            NativePolicyOutcome::Applied(Decision::Allow)
        )
    }

    /// Mint the single-use inert-load allowance for one exact URL.
    ///
    /// `pub(crate)`: only the session's own host-initiated load paths call it,
    /// immediately before starting an inert load, and the very next navigation
    /// to that exact URL consumes it. The URL is never stored in an
    /// observation, so this adds no logging surface.
    pub(crate) fn permit_inert_load(&self, url: &str) {
        // Keep the capability's domain structural even for future internal
        // callers: this method can never mint permission for a network/file
        // scheme.
        if !crate::ffi::runtime::is_inert_url(url) {
            return;
        }
        // SAFETY: state is owned by self and callbacks are thread-affine.
        unsafe { (*self.state).inert_permit = Some(url.to_owned()) };
    }

    /// Observations emitted by actual WebKit callbacks so tests and diagnostics
    /// can verify the native consequence, not merely a policy helper result.
    ///
    /// Returns an owned snapshot of the entry- and byte-bounded ring; call
    /// [`BoundedObservations::dropped`] to learn how many older entries were
    /// evicted.
    #[must_use]
    pub fn observations(&self) -> BoundedObservations {
        // SAFETY: callbacks and accessors are thread-affine, and cloning makes
        // no native call that could re-enter the callback. No reference into
        // the raw callback state escapes this expression.
        unsafe { (*self.state).observations.clone() }
    }

    /// Append one host-initiated pre-trust result to this view's certificate
    /// ledger.
    ///
    /// `pub(crate)`: only the session's own pre-trust installer calls it, after
    /// the shared host parser has decided. Nothing here makes a native call,
    /// and a rejected host contributes no caller bytes to the ledger.
    pub(crate) fn record_pre_trust(&self, event: PreTrustEvent) {
        // SAFETY: state is owned by self and callbacks are thread-affine.
        unsafe { (*self.state).certificates.record_pre_trust(event) };
    }

    /// An owned snapshot of bounded diagnostics for the native TLS-certificate
    /// path.
    #[must_use]
    pub fn certificate_ledger(&self) -> CertificateLedger {
        // SAFETY: callbacks and accessors are thread-affine, and cloning makes
        // no native call that could re-enter the callback. No reference into
        // the raw callback state escapes this expression.
        unsafe { (*self.state).certificates.clone() }
    }

    /// Tells this binding of a navigation that the binding before it on the
    /// same view allowed and left undecided: a popup's first one, judged
    /// before its host installed this policy. Its redirects are followed
    /// from that address, as any other navigation's are.
    pub(crate) fn note_allowed_navigation(&self, url: &str) {
        // SAFETY: state is owned by self and callbacks are thread-affine.
        unsafe {
            (*self.state).last_navigation = Some(url.to_owned());
            (*self.state).redirect_hops = 0;
        }
    }

    /// Whether this view's sandboxed WebProcess proved that the synchronous
    /// pre-network credential guard was loaded before bootstrap completed.
    #[must_use]
    pub(crate) fn credential_guard_ready(&self) -> bool {
        // SAFETY: immutable borrow; callbacks run only on this thread.
        unsafe { (*self.state).credential_guard_ready }
    }

    #[cfg(test)]
    fn handler_ids_for_test(&self) -> Vec<u64> {
        self.view_handlers
            .iter()
            .chain(self.session_handlers.iter())
            .copied()
            .collect()
    }
}

impl Drop for NativePolicyBinding {
    fn drop(&mut self) {
        // SAFETY: handlers belong to this live view and its network session.
        // Retirement prevents reentrant callbacks from applying native actions,
        // and callback leases defer freeing this allocation until return.
        unsafe {
            (*self.state).callback_lifetime.retire();
            let web_view = (*self.state).web_view;
            let network_session = (*self.state).network_session;
            for handler in self.view_handlers {
                super::signal::disconnect(web_view.cast::<c_void>(), handler);
            }
            for handler in self.session_handlers {
                super::signal::disconnect(network_session.cast::<c_void>(), handler);
            }
            if (*self.state).callback_lifetime.can_free() {
                drop(Box::from_raw(self.state));
            }
        }
    }
}

extern "C" fn on_decide_policy(
    _view: *mut ffi::WebKitWebView,
    decision: *mut ffi::WebKitPolicyDecision,
    decision_type: c_int,
    data: *mut c_void,
) -> ffi::GBoolean {
    // SAFETY: GSignal supplies the live callback-data pointer installed by the
    // binding, and callback entry is confined to its GLib thread.
    let lease = unsafe { CallbackLease::enter(data) };
    match decision_type {
        0 | 1 => {
            let nav = decision.cast::<ffi::WebKitNavigationPolicyDecision>();
            let action =
                unsafe { ffi::webkit_navigation_policy_decision_get_navigation_action(nav) };
            let request = if action.is_null() {
                ptr::null_mut()
            } else {
                unsafe { ffi::webkit_navigation_action_get_request(action) }
            };
            let gesture = !action.is_null()
                && unsafe { ffi::webkit_navigation_action_is_user_gesture(action) != 0 };
            let route = if decision_type == 1 {
                UriRoute::Popup {
                    user_initiated: gesture,
                }
            } else {
                UriRoute::Navigation {
                    user_initiated: gesture,
                }
            };
            // SAFETY: a non-null request is borrowed from this live policy
            // decision; WebKit keeps its URI readable for the callback.
            let uri = match unsafe { request_uri(request) } {
                Ok(uri) => uri,
                Err(error) => {
                    let (_, outcome) = lease.route_uri(route, Err(error));
                    apply_policy_decision(decision, outcome, false);
                    return ffi::G_TRUE;
                }
            };
            if decision_type == 0 && uri.starts_with("blob:") {
                // Asynchronous generators lose their transient gesture; Download policy authorizes the checked origin.
                let source = lease.with_state_no_reentry(|state| {
                    // SAFETY: the owner-thread callback retains the view and borrows its bounded URI only here.
                    let current =
                        unsafe { policy_uri(ffi::webkit_web_view_get_uri(state.web_view)) }.ok()?;
                    blob_download_origin(&uri, &current)
                });
                let allowed = source.is_some_and(|source| {
                    matches!(
                        lease.route_uri(UriRoute::Download, Ok(source)).1,
                        NativePolicyOutcome::Applied(Decision::Allow)
                    )
                });
                let reserved = allowed
                    && lease.with_state_no_reentry(|state| {
                        state.blob_downloads.retain(|(_, since)| {
                            since.elapsed() < std::time::Duration::from_secs(30)
                        });
                        if state.blob_downloads.len() >= super::page::MAX_ACTIVE_DOWNLOADS {
                            return false;
                        }

                        state
                            .blob_downloads
                            .push_back((uri.clone(), std::time::Instant::now()));
                        true
                    });
                if reserved {
                    // SAFETY: this live decision consumes the checked same-origin object URL as a download only.
                    unsafe { ffi::webkit_policy_decision_download(decision) };
                } else {
                    lease.with_state_no_reentry(|state| {
                        state.page.push(crate::page::PageEvent::DownloadDeclined {
                            url: PolicyUrl::new(uri),
                        })
                    });
                    // SAFETY: this callback owns the live navigation decision.
                    unsafe { ffi::webkit_policy_decision_ignore(decision) };
                }
                return ffi::G_TRUE;
            }
            // Subframe inert documents fetch nothing; main-frame loads still need a host permit.
            if decision_type == 0 && is_frame_inert_navigation(action, &uri) {
                // SAFETY: this callback owns the live navigation decision.
                unsafe { ffi::webkit_policy_decision_use(decision) };
                return ffi::G_TRUE;
            }
            // A registered redirect URI (an OAuth callback) is the host's,
            // not a page: stop it before policy, permits or the network see
            // it, and hand the URL to the host once.
            let redirect = !action.is_null()
                && unsafe { ffi::webkit_navigation_action_is_redirect(action) != 0 };
            let captured = lease.with_state_no_reentry(|state| {
                state
                    .page
                    .capture(&uri, gesture, redirect, decision_type == 1)
            });
            if captured {
                unsafe { ffi::webkit_policy_decision_ignore(decision) };
                return ffi::G_TRUE;
            }
            // Native middle-link activation is a host tab request, never a navigation of its source view.
            if decision_type == 0
                && gesture
                && !action.is_null()
                // SAFETY: this action is borrowed from the live owner-thread navigation decision.
                && unsafe { ffi::webkit_navigation_action_get_mouse_button(action) } == ffi::WPE_BUTTON_MIDDLE
            {
                let (_, outcome) = lease.route_uri(
                    UriRoute::Popup {
                        user_initiated: true,
                    },
                    Ok(uri.clone()),
                );
                if matches!(outcome, NativePolicyOutcome::Applied(Decision::Allow)) {
                    lease.with_state_no_reentry(|state| {
                        state.page.push(crate::page::PageEvent::PopupRequested {
                            url: PolicyUrl::new(uri),
                            user_initiated: true,
                            background: true,
                        })
                    });
                }
                // SAFETY: the live decision must be stopped after handing its disposition to the host.
                unsafe { ffi::webkit_policy_decision_ignore(decision) };
                return ffi::G_TRUE;
            }
            let inert_permitted = lease.with_state_no_reentry(|state| {
                decision_type == 0 && consume_inert_permit(&mut state.inert_permit, &uri)
            });
            // The permit is a host-minted capability for one exact inert URL,
            // so this branch answers without the responder and stays available
            // while another request holds it.
            let poisoned = lease.with_state_no_reentry(|state| state.poisoned);
            if inert_permitted && !poisoned {
                lease.with_state_no_reentry(|state| {
                    state.last_navigation = Some(uri);
                    state.redirect_hops = 0;
                });
                unsafe { ffi::webkit_policy_decision_use(decision) };
                return ffi::G_TRUE;
            }
            if decision_type == 0 && !redirect {
                lease.with_state_no_reentry(|state| {
                    if state
                        .forced_download
                        .as_ref()
                        .is_some_and(|p| p.target != uri)
                    {
                        state.forced_download = None;
                    }
                });
            }
            let kind = route.request(uri.clone());

            if decision_type == 0
                && !action.is_null()
                && unsafe { ffi::webkit_navigation_action_is_redirect(action) != 0 }
            {
                let (hop, redirect) = lease.with_state_no_reentry(|state| {
                    let hop = state.redirect_hops.saturating_add(1);
                    let redirect = state
                        .last_navigation
                        .as_deref()
                        .ok_or(crate::web::DestinationDenial::Url(
                            enzui_security::url_policy::UrlVerdict::Malformed,
                        ))
                        .and_then(|from| {
                            state
                                .local_origins
                                .policy_for_url(state.destination_policy, &uri)
                                .redirect_decision(from, &uri, hop)
                        });
                    (hop, redirect)
                });
                match redirect {
                    Ok(redirect) => {
                        if !redirect.carry_credentials {
                            strip_redirect_credentials(request);
                        }
                        let (_, outcome) = lease.decide(kind);
                        if matches!(outcome, NativePolicyOutcome::Applied(Decision::Allow)) {
                            lease.with_state_no_reentry(|state| {
                                if let Some(continuation) = &mut state.forced_download
                                    && state.last_navigation.as_ref() == Some(&continuation.target)
                                {
                                    continuation.target.clone_from(&uri);
                                }
                                state.last_navigation = Some(uri);
                                state.redirect_hops = hop;
                            });
                        }
                        apply_policy_decision(decision, outcome, false);
                    }
                    Err(cause) => {
                        let outcome = lease.with_state_no_reentry(|state| {
                            state.force_deny(kind, destination_deny_reason(cause))
                        });
                        apply_policy_decision(decision, outcome, false);
                    }
                }
            } else {
                let (_, outcome) = lease.decide(kind);
                let allowed = decision_type == 0
                    && matches!(outcome, NativePolicyOutcome::Applied(Decision::Allow));
                if allowed {
                    lease.with_state_no_reentry(|state| {
                        state.last_navigation = Some(uri.clone());
                        state.redirect_hops = 0;
                    });
                }
                // A popup whose host asked for it waits here, judged and
                // allowed, until the host has given it its scripts, filters
                // and policy: nothing of the page is fetched before then.
                if allowed
                    && lease
                        .with_state_no_reentry(|state| state.page.hold_navigation(decision, &uri))
                {
                    return ffi::G_TRUE;
                }
                apply_policy_decision(decision, outcome, false);
            }
        }
        2 => {
            let response = decision.cast::<ffi::WebKitResponsePolicyDecision>();
            let supported = unsafe {
                ffi::webkit_response_policy_decision_is_mime_type_supported(response) != 0
            };
            let main = unsafe {
                ffi::webkit_response_policy_decision_is_main_frame_main_resource(response) != 0
            };
            let request = unsafe { ffi::webkit_response_policy_decision_get_request(response) };
            // SAFETY: the response decision owns `request` and its URI for
            // the duration of this callback.
            let uri = match unsafe { request_uri(request) } {
                Ok(uri) => uri,
                Err(error) => {
                    if main {
                        lease.with_state_no_reentry(|state| {
                            state.certificates.record_main_response(MainResponse {
                                url: PolicyUrl::new(error.diagnostic_url()),
                                status: 0,
                                mime: String::new(),
                                mime_supported: supported,
                            });
                        });
                    }
                    let route = if supported || !main {
                        UriRoute::Resource { main_frame: main }
                    } else {
                        UriRoute::Download
                    };
                    let (_, outcome) = lease.route_uri(route, Err(error));
                    apply_policy_decision(decision, outcome, false);
                    return ffi::G_TRUE;
                }
            };
            // SAFETY: the response is borrowed from the live decision for
            // the duration of this callback; nothing is unreffed.
            let uri_response =
                unsafe { ffi::webkit_response_policy_decision_get_response(response) };
            let status = if uri_response.is_null() {
                0
            } else {
                // SAFETY: a non-null response is owned by the decision for this callback.
                unsafe { ffi::webkit_uri_response_get_status_code(uri_response) }
            };
            if main {
                // Diagnostics only: what the origin actually returned
                // for the document. A recorded response for an HTTPS URL is
                // proof the handshake completed, which is what tells a missing
                // certificate callback apart from a certificate that was never
                // questioned.
                let mime = if uri_response.is_null() {
                    String::new()
                } else {
                    // SAFETY: the MIME string is borrowed from the decision-owned response.
                    unsafe {
                        c_string(
                            ffi::webkit_uri_response_get_mime_type(uri_response).cast::<c_char>(),
                        )
                    }
                };
                lease.with_state_no_reentry(|state| {
                    state.certificates.record_main_response(MainResponse {
                        url: diagnostic_url(&uri),
                        status,
                        mime,
                        mime_supported: supported,
                    });
                });
            }
            let forced = main
                && lease.with_state_no_reentry(|state| {
                    if state.forced_download.as_ref().is_some_and(|p| {
                        !p.responded
                            && p.target == uri
                            && p.since.elapsed() < std::time::Duration::from_secs(30)
                    }) {
                        if let Some(p) = &mut state.forced_download {
                            p.responded = true;
                        }
                        true
                    } else {
                        false
                    }
                });
            // `Content-Disposition: attachment` asks for a download even of a
            // type WebKit could show; showing it inline would ignore the
            // server and bypass the download route's policy.
            let attachment = main && unsafe { is_attachment_response(response) };
            let host_handled = if main {
                // SAFETY: this decision owns the response and its MIME string for the callback.
                let response =
                    unsafe { ffi::webkit_response_policy_decision_get_response(response) };
                let mime = if response.is_null() {
                    None
                } else {
                    // SAFETY: the MIME string is borrowed from the live response.
                    normalized_mime(&unsafe {
                        c_string(ffi::webkit_uri_response_get_mime_type(response).cast::<c_char>())
                    })
                };
                lease.with_state_no_reentry(|state| {
                    mime.as_ref()
                        .is_some_and(|mime| state.download_mime_types.contains(mime))
                })
            } else {
                false
            };
            // A failed document the view cannot show is a navigation
            // failure, not a download: the user asked for a page. Renderable
            // error bodies still display, and explicit downloads keep their
            // own semantics.
            if main
                && (400..600).contains(&status)
                && !forced
                && (!supported || attachment || host_handled)
            {
                lease.with_state_no_reentry(|state| {
                    state.page.push(crate::page::PageEvent::LoadFailed {
                        url: PolicyUrl::new(&uri),
                        message: format!("HTTP response {status} could not be displayed."),
                        cancelled: false,
                    });
                });
                // SAFETY: the response decision is live and is resolved exactly once here.
                unsafe { ffi::webkit_policy_decision_ignore(decision) };
                return ffi::G_TRUE;
            }
            if forced || attachment || host_handled {
                let (_, outcome) = lease.route_uri(UriRoute::Download, Ok(uri));
                apply_policy_decision(decision, outcome, true);
            } else if supported && crate::ffi::runtime::is_inert_url(&uri) {
                // Host-supplied inert content (`about:blank`, `data:`) reached
                // no network, so there is no destination to judge; the
                // navigation stage already required a single-use permit for it.
                unsafe { ffi::webkit_policy_decision_use(decision) };
            } else if supported {
                // Navigation approval does not authorize later redirects or
                // subresources; every supported response is judged separately.
                let (_, outcome) =
                    lease.route_uri(UriRoute::Resource { main_frame: main }, Ok(uri));
                apply_policy_decision(decision, outcome, false);
            } else if !main {
                unsafe { ffi::webkit_policy_decision_ignore(decision) };
            } else {
                let (_, outcome) = lease.route_uri(UriRoute::Download, Ok(uri));
                apply_policy_decision(decision, outcome, true);
            }
        }
        _ => unsafe { ffi::webkit_policy_decision_ignore(decision) },
    }
    ffi::G_TRUE
}

extern "C" fn on_create(
    _view: *mut ffi::WebKitWebView,
    action: *mut ffi::WebKitNavigationAction,
    data: *mut c_void,
) -> *mut ffi::WebKitWebView {
    // SAFETY: GSignal supplies the live callback-data pointer installed by the
    // binding, and callback entry is confined to its GLib thread.
    let lease = unsafe { CallbackLease::enter(data) };
    // SAFETY: a non-null action and its request URI are borrowed from this
    // `create` signal for the duration of the callback.
    let uri = unsafe { navigation_uri(action) };
    let gesture =
        !action.is_null() && unsafe { ffi::webkit_navigation_action_is_user_gesture(action) != 0 };
    // A window asked for with the middle button (a `target` link, say) is
    // one the person wants behind the page in view.
    let background = gesture
        && !action.is_null()
        // SAFETY: the action is borrowed from this `create` signal for the callback.
        && unsafe { ffi::webkit_navigation_action_get_mouse_button(action) } == ffi::WPE_BUTTON_MIDDLE;
    if let Ok(uri) = &uri
        && lease.with_state_no_reentry(|state| state.page.capture(uri, gesture, false, true))
    {
        return ptr::null_mut();
    }
    let reported = uri.as_ref().ok().cloned();
    let opener = _view;
    let (_, outcome) = lease.route_uri(
        UriRoute::Popup {
            user_initiated: gesture,
        },
        uri,
    );
    // A refused popup gets NULL. An allowed one becomes a real related view
    // when the host enabled popups, and is otherwise reported so the host may
    // load its URL in this view or another.
    // A host that enabled popups gets a real view related to this one.
    if matches!(outcome, NativePolicyOutcome::Applied(Decision::Allow))
        && let Some(url) = reported
    {
        let page = lease.with_state_no_reentry(|state| std::rc::Rc::clone(&state.page));
        return super::page::PageHub::open_popup(
            &page,
            opener,
            PolicyUrl::new(url),
            gesture,
            background,
        );
    }
    ptr::null_mut()
}

extern "C" fn on_permission_request(
    _view: *mut ffi::WebKitWebView,
    request: *mut ffi::WebKitPermissionRequest,
    data: *mut c_void,
) -> ffi::GBoolean {
    // SAFETY: GSignal supplies the live callback-data pointer installed by the
    // binding, and callback entry is confined to its GLib thread.
    let lease = unsafe { CallbackLease::enter(data) };
    let source = NativePermissionRequest(request);
    let kind = permission_kind(&source);
    let page = lease.with_state_no_reentry(|state| std::rc::Rc::clone(&state.page));
    // Key-system requests lack native frame provenance and require an explicit view policy
    // grant; device requests retain the origin-bound path and never inherit that grant.
    if kind != PermissionKind::MediaKeySystem && page.handle_site_permission(request, kind) {
        return ffi::G_TRUE;
    }
    let action = decide_permission(&lease, &source);
    // SAFETY: `request` is the live permission request this callback was
    // invoked for; exactly one terminal action is performed on it.
    unsafe {
        match action {
            PermissionAction::Allow => ffi::webkit_permission_request_allow(request),
            PermissionAction::Deny => ffi::webkit_permission_request_deny(request),
        }
    }
    ffi::G_TRUE
}

struct PendingCertificateEvent {
    request: ViewRequestId,
    host: String,
    key: String,
    outcome: NativePolicyOutcome,
    next: CertificateNext,
}

impl PendingCertificateEvent {
    fn finish(self, action: CertificateAction) -> CertificateEvent {
        CertificateEvent {
            request: self.request,
            host: self.host,
            key: self.key,
            outcome: self.outcome,
            action,
        }
    }
}

enum CertificateNext {
    Terminal(CertificateAction),
    Attest(TlsContinuation),
}

struct TlsContinuation {
    view: ViewId,
    web_view: *mut ffi::WebKitWebView,
    network_session: *mut ffi::WebKitNetworkSession,
    outer_sandbox: crate::sandbox::OuterSandbox,
    sandbox_baseline: Vec<crate::sandbox::ProcessIdentity>,
    certificate: *mut ffi::GTlsCertificate,
    /// The authorization identity WebKit compares, never the folded key.
    host: CString,
    failing_uri: CString,
}

impl TlsContinuation {
    fn view_is_current(&self, state: &State) -> bool {
        state.callback_lifetime.binding_live.get()
            && state.view == self.view
            && state.web_view == self.web_view
            && state.network_session == self.network_session
    }
}

#[cfg(test)]
struct DroppedTlsState {
    certificates: CertificateLedger,
    observations: BoundedObservations,
}

#[cfg(test)]
struct TlsTestSeam {
    attestation: Option<Box<dyn FnOnce(*mut c_void) -> bool>>,
    native_continuations: std::rc::Rc<Cell<usize>>,
    dropped_state: std::rc::Rc<std::cell::RefCell<Option<DroppedTlsState>>>,
}

#[cfg(test)]
struct TlsTestEvidence {
    native_continuations: std::rc::Rc<Cell<usize>>,
    dropped_state: std::rc::Rc<std::cell::RefCell<Option<DroppedTlsState>>>,
}

#[cfg(test)]
thread_local! {
    static TLS_TEST_SEAM: std::cell::RefCell<Option<TlsTestSeam>> = const {
        std::cell::RefCell::new(None)
    };
}

#[cfg(test)]
struct TlsTestSeamGuard;

#[cfg(test)]
impl Drop for TlsTestSeamGuard {
    fn drop(&mut self) {
        TLS_TEST_SEAM.with(|seam| {
            *seam.borrow_mut() = None;
        });
    }
}

#[cfg(test)]
fn install_tls_test_seam(
    attestation: impl FnOnce(*mut c_void) -> bool + 'static,
) -> (TlsTestSeamGuard, TlsTestEvidence) {
    let native_continuations = std::rc::Rc::new(Cell::new(0));
    let dropped_state = std::rc::Rc::new(std::cell::RefCell::new(None));
    TLS_TEST_SEAM.with(|seam| {
        let replaced = seam.borrow_mut().replace(TlsTestSeam {
            attestation: Some(Box::new(attestation)),
            native_continuations: native_continuations.clone(),
            dropped_state: dropped_state.clone(),
        });
        assert!(replaced.is_none(), "TLS test seam already installed");
    });
    (
        TlsTestSeamGuard,
        TlsTestEvidence {
            native_continuations,
            dropped_state,
        },
    )
}

#[cfg(test)]
impl Drop for State {
    fn drop(&mut self) {
        TLS_TEST_SEAM.with(|seam| {
            if let Some(seam) = seam.borrow().as_ref() {
                *seam.dropped_state.borrow_mut() = Some(DroppedTlsState {
                    certificates: self.certificates.clone(),
                    observations: self.observations.clone(),
                });
            }
        });
    }
}

fn prepare_tls_failure(
    lease: &CallbackLease,
    parsed_uri: Result<String, NativeUriError>,
    certificate: *mut ffi::GTlsCertificate,
) -> PendingCertificateEvent {
    // Counted before the decision, so a callback that fired and applied
    // nothing stays distinguishable from one that never fired.
    lease.with_state_no_reentry(|state| {
        state.certificates.callbacks = state.certificates.callbacks.saturating_add(1);
    });
    let parsed_host = parsed_uri
        .as_deref()
        .map_err(|error| *error)
        .and_then(certificate_host);
    // WebKit authorizes the original host spelling; the folded key exists only
    // so rotated spellings of one authority cannot buy separate retry budgets.
    let identity = parsed_host.and_then(|host| {
        certificate_authorization_identity(host).map_err(|error| match error {
            CertificateHostError::TooLong => NativeUriError::HostTooLong,
            _ => NativeUriError::InvalidHost,
        })
    });
    // Converted to C before policy runs: a host that cannot cross the C
    // boundary is refused without reaching the responder.
    let (host, key, host_c, decided, outcome) = lease.route_certificate_identity(identity);
    debug_assert!(host.capacity() <= MAX_CERTIFICATE_HOST_BYTES);
    let next = lease.with_state_no_reentry(|state| match outcome {
        NativePolicyOutcome::Applied(Decision::Allow) if host.is_empty() => {
            CertificateNext::Terminal(CertificateAction::HostUnknown)
        }
        // An admitted firing spends the budget even when attestation then
        // refuses; paying for the attempt is the fail-closed direction.
        NativePolicyOutcome::Applied(Decision::Allow)
            if !state.certificates.admit_continuation(&key) =>
        {
            CertificateNext::Terminal(CertificateAction::RetryBudgetExhausted)
        }
        NativePolicyOutcome::Applied(Decision::Allow) => match (
            host_c,
            parsed_uri
                .as_deref()
                .ok()
                .and_then(|uri| CString::new(uri).ok()),
        ) {
            (Some(host), Some(failing_uri)) => CertificateNext::Attest(TlsContinuation {
                view: state.view,
                web_view: state.web_view,
                network_session: state.network_session,
                outer_sandbox: state.outer_sandbox,
                sandbox_baseline: state.sandbox_baseline.clone(),
                certificate,
                host,
                failing_uri,
            }),
            // An identity or failing URI that cannot cross the C boundary
            // installs no exception and issues no reload.
            _ => CertificateNext::Terminal(CertificateAction::Denied),
        },
        _ => CertificateNext::Terminal(CertificateAction::Denied),
    });
    PendingCertificateEvent {
        request: decided.id,
        host,
        key,
        outcome,
        next,
    }
}

fn attest_tls_continuation(data: *mut c_void, continuation: &TlsContinuation) -> bool {
    // Only the test seam reads the raw request pointer.
    #[cfg(not(test))]
    let _ = data;
    #[cfg(test)]
    if let Some(attestation) = TLS_TEST_SEAM.with(|seam| {
        seam.borrow_mut()
            .as_mut()
            .and_then(|seam| seam.attestation.take())
    }) {
        return attestation(data);
    }
    crate::ffi::runtime::enforce_navigation_on_view(
        continuation.web_view,
        &continuation.sandbox_baseline,
        continuation.outer_sandbox,
    )
    .is_ok()
}

fn apply_tls_continuation(continuation: &TlsContinuation) {
    #[cfg(test)]
    if TLS_TEST_SEAM.with(|seam| {
        let seam = seam.borrow();
        let Some(seam) = seam.as_ref() else {
            return false;
        };
        seam.native_continuations
            .set(seam.native_continuations.get().saturating_add(1));
        true
    }) {
        return;
    }
    // SAFETY: these are the owned callback inputs and native handles captured
    // before attestation; the caller revalidated the view after reentry and
    // holds a callback lease for the signal invocation.
    unsafe {
        ffi::webkit_network_session_allow_tls_certificate_for_host(
            continuation.network_session,
            continuation.certificate,
            continuation.host.as_ptr(),
        );
        if let Ok(host) = continuation.host.to_str() {
            exceptions::record(continuation.network_session, host);
        }
        ffi::webkit_web_view_load_uri(continuation.web_view, continuation.failing_uri.as_ptr());
    }
}

extern "C" fn on_tls_failure(
    _view: *mut ffi::WebKitWebView,
    failing_uri: *const i8,
    certificate: *mut ffi::GTlsCertificate,
    _errors: c_int,
    data: *mut c_void,
) -> ffi::GBoolean {
    // SAFETY: GSignal supplies the live callback-data pointer installed by the
    // binding. The lease contains only that pointer and keeps its allocation
    // alive across nested main-context dispatch without retaining a reference.
    let lease = unsafe { CallbackLease::enter(data) };
    // SAFETY: the signal contract keeps `failing_uri` readable and
    // NUL-terminated for this callback invocation.
    let parsed_uri = unsafe { policy_uri(failing_uri.cast::<c_char>()) };
    let pending = prepare_tls_failure(&lease, parsed_uri, certificate);
    let action = match &pending.next {
        CertificateNext::Terminal(action) => *action,
        CertificateNext::Attest(continuation) => {
            let attested = attest_tls_continuation(data, continuation);
            let view_is_current =
                lease.with_state_no_reentry(|state| continuation.view_is_current(state));
            if attested && view_is_current {
                apply_tls_continuation(continuation);
                CertificateAction::ContinuedForHost
            } else {
                CertificateAction::AttestationRefused
            }
        }
    };
    lease.with_state_no_reentry(|state| {
        state.certificates.record_event(pending.finish(action));
    });
    ffi::G_TRUE
}

/// `WebKitWebView::load-failed` - diagnostics only.
///
/// WebKit emits this for every load failure, and specifically *after*
/// `load-failed-with-tls-errors` when no handler claimed the TLS failure. The
/// error's domain and code therefore answer the question a missing
/// [`RequestKind::Certificate`] observation raises: a TLS-domain failure here
/// with zero certificate callbacks means the certificate handler is not wired,
/// while a transport-domain failure means the origin never produced a
/// certificate error at all.
///
/// `GError::message` is never read: it embeds the failing URI, and the URI is
/// recorded once through [`PolicyUrl`] with the same redaction every other
/// observation gets. The handler returns FALSE so WebKit's default handling
/// still runs.
extern "C" fn on_load_failed(
    _view: *mut ffi::WebKitWebView,
    _load_event: c_int,
    failing_uri: *const i8,
    error: *mut ffi::GError,
    data: *mut c_void,
) -> ffi::GBoolean {
    // SAFETY: GSignal supplies the live callback-data pointer installed by the
    // binding, and callback entry is confined to its GLib thread.
    let lease = unsafe { CallbackLease::enter(data) };
    let (domain, code) = if error.is_null() {
        (String::new(), 0)
    } else {
        // SAFETY: glib owns the GError for the duration of the emission; this
        // reads two scalar fields and an interned static domain name, and free
        // nothing.
        let (quark, code) = unsafe { ((*error).domain, (*error).code) };
        // SAFETY: glib returns either NULL or an interned NUL-terminated name.
        let name = unsafe { c_string(ffi::g_quark_to_string(quark).cast::<c_char>()) };
        (name, code)
    };
    let failure = LoadFailure {
        domain,
        code,
        // SAFETY: WebKit keeps the failing URI readable and NUL-terminated
        // for the duration of this diagnostic callback.
        url: match unsafe { policy_uri(failing_uri.cast::<c_char>()) } {
            Ok(uri) => diagnostic_url(&uri),
            Err(error) => PolicyUrl::new(error.diagnostic_url()),
        },
    };
    lease.with_state_no_reentry(|state| {
        state.certificates.record_load_failure(failure);
    });
    // FALSE: this binding does not handle the failure, it only records it.
    ffi::G_FALSE
}

/// Receive constant-only verdicts from the WebProcess extension. The extension
/// owns the authoritative action: returning TRUE from `WebKitWebPage::send-request`
/// cancels the request before it enters the NetworkProcess. This UI callback
/// terminates the surrounding navigation and records the shared typed reason.
extern "C" fn on_user_message(
    view: *mut ffi::WebKitWebView,
    message: *mut ffi::WebKitUserMessage,
    data: *mut c_void,
) -> ffi::GBoolean {
    if message.is_null() {
        return ffi::G_FALSE;
    }
    // SAFETY: the live WebKit message owns a NUL-terminated name for this
    // callback; NULL is accepted as an empty diagnostic string.
    let name = unsafe { c_string(ffi::webkit_user_message_get_name(message).cast::<c_char>()) };
    // SAFETY: GSignal supplies the live callback-data pointer installed by the
    // binding, and callback entry is confined to its GLib thread.
    let lease = unsafe { CallbackLease::enter(data) };
    match name.as_str() {
        CREDENTIAL_GUARD_READY => {
            lease.with_state_no_reentry(|state| state.credential_guard_ready = true);
            ffi::G_TRUE
        }
        CREDENTIALS_IN_URL_DENIED => {
            // Deliberately use a fixed non-secret URL. The extension never
            // sends the offending URI, and this process never retains or logs
            // its userinfo. The denial variant carries the complete fact.
            let kind = RequestKind::Navigation(NavContext {
                url: PolicyUrl::new("https://credentials-refused.invalid/"),
                user_initiated: false,
            });
            lease.with_state_no_reentry(|state| {
                state.force_deny(
                    kind,
                    crate::web::policy::DenyReason::SchemeRefused(
                        enzui_security::url_policy::UrlVerdict::CredentialsInUrl,
                    ),
                );
            });
            unsafe { ffi::webkit_web_view_stop_loading(view) };
            ffi::G_TRUE
        }
        _ => ffi::G_FALSE,
    }
}

/// `WebKitNetworkSession::download-started` - the native consequence of a
/// response-policy decision that selected `webkit_policy_decision_download`
///
/// Records a bounded observation carrying the URI WebKit reports. A host
/// that set a download directory then receives the download (see
/// `ffi::page`); otherwise it is cancelled so no bytes touch disk. A download for another
/// WebView on the same session is not this binding's business - filter it
/// out; the observation ring never sees another view's URI.
extern "C" fn on_download_started(
    _session: *mut ffi::WebKitNetworkSession,
    download: *mut ffi::WebKitDownload,
    data: *mut c_void,
) {
    // SAFETY: GSignal supplies the live callback-data pointer installed by the
    // binding, and callback entry is confined to its GLib thread.
    let lease = unsafe { CallbackLease::enter(data) };
    if download.is_null() {
        return;
    }
    // Ignore downloads started by another view sharing the network session.
    let origin_view = unsafe { ffi::webkit_download_get_web_view(download) };
    let is_own_view = lease.with_state_no_reentry(|state| origin_view == state.web_view);
    if !is_own_view {
        return;
    }
    let request = unsafe { ffi::webkit_download_get_request(download) };
    // SAFETY: the live download owns `request` and its URI for this callback.
    let mut adopted = false;
    match unsafe { request_uri(request) } {
        Ok(uri) => {
            let permitted = !uri.starts_with("blob:")
                || lease.with_state_no_reentry(|state| {
                    let Some(at) = state.blob_downloads.iter().position(|(value, since)| {
                        value == &uri && since.elapsed() < std::time::Duration::from_secs(30)
                    }) else {
                        return false;
                    };
                    state.blob_downloads.remove(at);
                    true
                });
            if !permitted {
                // SAFETY: the native callback retains this unadopted download.
                unsafe { ffi::webkit_download_cancel(download) };
                return;
            }
            // Mint a fresh view-scoped correlation id for the observation. It is
            // opened and immediately resolved so the session's outstanding count
            // stays consistent; this signal is a native follow-up.
            let kind = UriRoute::Download.request(uri.clone());
            lease.with_state_no_reentry(|state| {
                let id = state.session.open(state.view, kind.clone());
                let _ = state.session.resolve(id);
                state.observations.push(NativePolicyObservation {
                    request: NativePolicyRequest { id, kind },
                    outcome: NativePolicyOutcome::DownloadStarted,
                });
            });
            // A host with a download directory takes the download over; its
            // file goes there and nowhere else.
            let page = lease.with_state_no_reentry(|state| std::rc::Rc::clone(&state.page));
            let requested = lease.with_state_no_reentry(|state| {
                let matched = state.forced_download.as_ref().is_some_and(|p| {
                    p.responded
                        && p.target == uri
                        && p.since.elapsed() < std::time::Duration::from_secs(30)
                });
                if matched {
                    state.forced_download.take().map(|p| p.requested)
                } else {
                    None
                }
            });
            adopted = super::page::PageHub::adopt_download(
                &page,
                download,
                requested.as_deref().unwrap_or(&uri),
            );
            if !adopted {
                page.push(crate::page::PageEvent::DownloadDeclined {
                    url: PolicyUrl::new(uri),
                });
            }
        }
        Err(error) => {
            let _ = lease.route_uri(UriRoute::Download, Err(error));
        }
    }
    // Otherwise the observation is the whole outcome: cancel synchronously
    // so nothing is written anywhere.
    if !adopted {
        unsafe { ffi::webkit_download_cancel(download) };
    }
}

fn blob_download_origin(uri: &str, current: &str) -> Option<String> {
    use enzui_security::url_policy::Scheme;
    let inner = uri.strip_prefix("blob:")?;
    let policy = crate::web::DestinationPolicy::trusted_local();
    let blob = policy.screen_request(inner).ok()?;
    let page = policy.screen_request(current).ok()?;
    let port = |value: &enzui_security::url_policy::SafeUrl| {
        value.port().unwrap_or(if value.scheme() == Scheme::Https {
            443
        } else {
            80
        })
    };
    if blob.scheme() != page.scheme()
        || blob.host() != page.host()
        || port(&blob) != port(&page)
        || blob.path().is_empty()
        || blob.path() == "/"
    {
        return None;
    }
    Some(inner.to_owned())
}

fn is_frame_inert_navigation(action: *mut ffi::WebKitNavigationAction, url: &str) -> bool {
    let inert = url == "about:srcdoc"
        || url
            .strip_prefix("about:blank")
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('#'));
    if !inert || action.is_null() {
        return false;
    }
    let Some((target_frame, is_main_frame)) = frame_info_api() else {
        return false;
    };
    // SAFETY: the action is borrowed from the live navigation decision, and the
    // frame information from the action.
    unsafe {
        let target = target_frame(action);
        !target.is_null() && is_main_frame(target) == ffi::G_FALSE
    }
}

type TargetFrameInfo = unsafe extern "C" fn(*mut ffi::WebKitNavigationAction) -> *mut c_void;
type IsMainFrame = unsafe extern "C" fn(*mut c_void) -> ffi::GBoolean;

// Resolve the frame API from the runtime because link-time WebKit can be older.
fn frame_info_api() -> Option<(TargetFrameInfo, IsMainFrame)> {
    #[link(name = "dl")]
    unsafe extern "C" {
        fn dlsym(handle: *mut c_void, name: *const c_char) -> *mut c_void;
    }
    static API: std::sync::OnceLock<Option<(TargetFrameInfo, IsMainFrame)>> =
        std::sync::OnceLock::new();
    *API.get_or_init(|| {
        // SAFETY: fixed WebKit symbols are resolved from already loaded libraries.
        let (target, main) = unsafe {
            (
                dlsym(
                    core::ptr::null_mut(),
                    c"webkit_navigation_action_get_target_frame_info".as_ptr(),
                ),
                dlsym(
                    core::ptr::null_mut(),
                    c"webkit_frame_info_is_main_frame".as_ptr(),
                ),
            )
        };
        // SAFETY: both functions have these exact C signatures in WebKit's API.
        (!target.is_null() && !main.is_null()).then(|| unsafe {
            (
                std::mem::transmute::<*mut c_void, TargetFrameInfo>(target),
                std::mem::transmute::<*mut c_void, IsMainFrame>(main),
            )
        })
    })
}

fn consume_inert_permit(permit: &mut Option<String>, url: &str) -> bool {
    // Taking first makes mismatch and replay fail closed as well as success.
    permit.take().is_some_and(|expected| {
        crate::ffi::runtime::is_inert_url(url) && inert_urls_match(&expected, url)
    })
}

/// Whether the URL a permit was minted for (`expected`) names the same inert
/// resource as the URL WebKit reports to `decide-policy` (`observed`).
///
/// # Why a plain byte compare is wrong, and why a full decode is *also* wrong
///
/// WebKit runs its own URL parser between `webkit_web_view_load_uri(url)` and
/// the `decide-policy` callback, so the URI the callback observes is a
/// canonicalised form of the URL handed in. For a `data:` payload that
/// canonicalisation percent-encodes payload bytes outside WebKit's URL
/// code-point set (spaces, `<`, `>`, …). A byte-equal comparison therefore
/// rejects the very navigation the permit was minted for, wedging
/// `WebSession::load` on any inert page whose body contains those bytes.
///
/// The naïve repair - percent-decode *both* sides and compare - over-matches: it
/// dissolves the `data:` grammar's own delimiters. `data:text/html,x` and
/// `data:text/html%2Cx` decode to the same bytes even though the first is a
/// `text/html` document with body `x` and the second is a document whose media
/// type literally contains a comma; likewise a distinct media type could be
/// smuggled past the permit. The comma between the media type and the payload is
/// *structural*, so it must be matched literally, not as decoded content.
///
/// This function keeps the structural delimiter intact:
///
/// * `about:blank` (and any inert URL without a `data:` payload split) is matched
///   exactly - there is no payload to normalise.
/// * For `data:`, the prefix through the first *literal* comma (scheme, media
///   type, parameters, base64 flag, and the separator itself) must be
///   byte-identical on both sides. WebKit leaves that prefix untouched, so a
///   `%2C`, a different media type, or a missing comma cannot masquerade as the
///   separator minted the permit for.
/// * Only the opaque payload *after* the first literal comma is percent-
///   normalised, because that is the only region WebKit re-encodes. There the
///   comma is data, not a delimiter, so `a,b` and `a%2Cb` are legitimately the
///   same payload.
///
/// A malicious page still cannot forge a match: it can only be accepted by
/// requesting the exact structural prefix and payload the single-use permit was
/// minted for.
fn inert_urls_match(expected: &str, observed: &str) -> bool {
    match (
        expected.strip_prefix("data:"),
        observed.strip_prefix("data:"),
    ) {
        (Some(exp_rest), Some(obs_rest)) => {
            match (exp_rest.split_once(','), obs_rest.split_once(',')) {
                (Some((exp_head, exp_body)), Some((obs_head, obs_body))) => {
                    // Structural prefix (media type + params + separator) is
                    // matched literally; only the payload is normalised.
                    exp_head == obs_head
                        && percent_normalized(exp_body) == percent_normalized(obs_body)
                }
                // A `data:` URL missing the mandatory comma has no payload to
                // normalise; require exact equality rather than guessing.
                _ => expected == observed,
            }
        }
        // about:blank and any non-`data:` inert URL: exact match only.
        _ => expected == observed,
    }
}

/// Decode every well-formed `%XX` escape in `s` to its raw byte in a single
/// pass, leaving everything else (including malformed escapes and a bare `%`)
/// literal. A single pass is deliberate: `%2520` decodes to `%20`, not to a
/// space, so a double-encoded payload cannot collapse onto the raw byte it
/// merely *describes*.
fn percent_normalized(url: &str) -> Vec<u8> {
    let bytes = url.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'%'
            && i + 2 < bytes.len()
            && bytes[i + 1].is_ascii_hexdigit()
            && bytes[i + 2].is_ascii_hexdigit()
        {
            out.push((hex_nibble(bytes[i + 1]) << 4) | hex_nibble(bytes[i + 2]));
            i += 3;
        } else {
            out.push(b);
            i += 1;
        }
    }
    out
}

#[inline]
fn hex_nibble(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}

fn destination_deny_reason(cause: crate::web::DestinationDenial) -> crate::web::policy::DenyReason {
    match cause {
        crate::web::DestinationDenial::Url(verdict) => {
            crate::web::policy::DenyReason::SchemeRefused(verdict)
        }
        other => crate::web::policy::DenyReason::DestinationRefused(other),
    }
}

fn strip_redirect_credentials(request: *mut ffi::WebKitURIRequest) {
    if request.is_null() {
        return;
    }
    let headers = unsafe { ffi::webkit_uri_request_get_http_headers(request) };
    strip_credential_headers(headers);
}

fn strip_credential_headers(headers: *mut ffi::SoupMessageHeaders) {
    if headers.is_null() {
        return;
    }
    for name in ["Authorization", "Proxy-Authorization"] {
        let name = CString::new(name).expect("static header name");
        unsafe { ffi::soup_message_headers_remove(headers, name.as_ptr()) };
    }
}

/// Whether a response decision's response says `Content-Disposition:
/// attachment`.
///
/// # Safety
///
/// `response` is the live response policy decision of the callback.
unsafe fn is_attachment_response(response: *mut ffi::WebKitResponsePolicyDecision) -> bool {
    // SAFETY: borrowed from the live decision for this callback.
    unsafe {
        let uri_response = ffi::webkit_response_policy_decision_get_response(response);
        if uri_response.is_null() {
            return false;
        }
        let headers = super::page::sys::webkit_uri_response_get_http_headers(uri_response);
        if headers.is_null() {
            return false;
        }
        let name = c"Content-Disposition";
        let value = ffi::soup_message_headers_get_one(headers, name.as_ptr());
        content_disposition_is_attachment(&c_string(value))
    }
}

/// RFC 6266: the disposition type is the first token, case-insensitive.
fn content_disposition_is_attachment(value: &str) -> bool {
    value
        .split(';')
        .next()
        .is_some_and(|kind| kind.trim().eq_ignore_ascii_case("attachment"))
}

fn apply_policy_decision(
    decision: *mut ffi::WebKitPolicyDecision,
    outcome: NativePolicyOutcome,
    download: bool,
) {
    unsafe {
        if matches!(outcome, NativePolicyOutcome::Applied(Decision::Allow)) {
            if download {
                ffi::webkit_policy_decision_download(decision);
            } else {
                ffi::webkit_policy_decision_use(decision);
            }
        } else {
            ffi::webkit_policy_decision_ignore(decision);
        }
    }
}

/// Read the URI from a native navigation action.
///
/// # Safety
///
/// A non-null `action` must be a live WebKit navigation action whose request
/// and URI remain readable and NUL-terminated for the duration of this call.
unsafe fn navigation_uri(
    action: *mut ffi::WebKitNavigationAction,
) -> Result<String, NativeUriError> {
    if action.is_null() {
        return Err(NativeUriError::Null);
    }
    // SAFETY: upheld by this function's caller contract.
    let request = unsafe { ffi::webkit_navigation_action_get_request(action) };
    // SAFETY: the action owns the returned request for the same lifetime.
    unsafe { request_uri(request) }
}

/// Read the URI from a native URI request.
///
/// # Safety
///
/// A non-null `request` must be a live WebKit URI request whose URI remains
/// readable and NUL-terminated for the duration of this call.
unsafe fn request_uri(request: *mut ffi::WebKitURIRequest) -> Result<String, NativeUriError> {
    if request.is_null() {
        return Err(NativeUriError::Null);
    }
    // SAFETY: upheld by this function's caller contract.
    let uri = unsafe { ffi::webkit_uri_request_get_uri(request) };
    // SAFETY: WebKit ties the returned URI to the live request.
    unsafe { policy_uri(uri.cast::<c_char>()) }
}

unsafe extern "C" {
    fn strnlen(value: *const c_char, max_len: usize) -> usize;
}

/// Scan a bounded native C string with a caller-supplied byte ceiling,
/// refusing an over-limit or non-UTF-8 value before it becomes a full Rust
/// allocation.
///
/// This is the single native-URI scanner shared by policy routing
/// ([`policy_uri`]) and any other page-controlled URI seam - for example
/// [`WebSession::current_uri`](crate::ffi::runtime::WebSession::current_uri).
/// `strnlen` reads no more than `max_bytes + 1` bytes, so a page that controls
/// the string through navigation, redirects, or the history API cannot force an
/// unbounded native scan or an unbounded host allocation, and an over-limit URI
/// is refused rather than silently truncated.
///
/// # Safety
///
/// A non-null `value` must point to a readable NUL-terminated C string that
/// remains live for this call. Null is accepted and returned as
/// [`NativeUriError::Null`].
pub(crate) unsafe fn scan_bounded_native_uri(
    value: *const c_char,
    max_bytes: usize,
) -> Result<String, NativeUriError> {
    if value.is_null() {
        return Err(NativeUriError::Null);
    }
    // SAFETY: the caller's non-null readable NUL-terminated contract is
    // forwarded to the shared bounded scanner.
    let bytes =
        unsafe { scan_bounded_native_bytes(value, max_bytes) }.ok_or(NativeUriError::TooLong)?;
    let uri = core::str::from_utf8(bytes).map_err(|_| NativeUriError::InvalidUtf8)?;
    Ok(uri.to_owned())
}

/// Scan a NUL-terminated native C string to the first NUL, capped at
/// `max_bytes + 1` observed bytes.
///
/// Returns the borrowed bytes up to (but not including) the terminator when it
/// occurred within the accepted range, `None` when the pointer was null, and
/// `None` when no terminator occurred within the accepted range.
///
/// # Safety
///
/// `value` must be null or point to a readable NUL-terminated C string that
/// remains live for this call.
pub(crate) unsafe fn scan_bounded_native_bytes<'a>(
    value: *const c_char,
    max_bytes: usize,
) -> Option<&'a [u8]> {
    if value.is_null() {
        return None;
    }
    // SAFETY: the caller guarantees a readable NUL-terminated string; `strnlen`
    // reads no more than the supplied bound + 1 bytes before returning.
    let len = unsafe { strnlen(value, max_bytes + 1) };
    if len > max_bytes {
        return None;
    }
    // SAFETY: `strnlen` established `len` readable bytes borrowed from the
    // caller-owned string; the lifetime is that of the borrow the caller holds.
    Some(unsafe { core::slice::from_raw_parts(value.cast::<u8>(), len) })
}

/// Read and validate a native policy URI without an unbounded scan.
///
/// # Safety
///
/// A non-null `value` must point to a readable NUL-terminated C string that
/// remains live for this call. Null is accepted and returned as a typed error.
unsafe fn policy_uri(value: *const c_char) -> Result<String, NativeUriError> {
    // SAFETY: the caller contract is forwarded unchanged; the shared scanner
    // bounds the read to the policy-URI byte ceiling.
    unsafe { scan_bounded_native_uri(value, MAX_POLICY_URI_BYTES) }
}

/// Copy a bounded native diagnostic string.
///
/// # Safety
///
/// A non-null `value` must point to a readable NUL-terminated C string that
/// remains live for this call. Null is accepted as an empty diagnostic value.
unsafe fn c_string(value: *const c_char) -> String {
    const DETAIL_BYTES_MAX: usize = 4 * 1024;
    if value.is_null() {
        return String::new();
    }
    // Diagnostic/native-name strings never select URL authorization. They may
    // be lossily rendered, but their scan and allocation are still bounded.
    // SAFETY: upheld by this function's caller contract; `strnlen` reads at
    // most the stated bound.
    let len = unsafe { strnlen(value, DETAIL_BYTES_MAX + 1) }.min(DETAIL_BYTES_MAX);
    // SAFETY: the native contract keeps at least `len` bytes readable; when the
    // terminator lies beyond the diagnostic limit this code intentionally retains only
    // this bounded prefix.
    let bytes = unsafe { core::slice::from_raw_parts(value.cast::<u8>(), len) };
    String::from_utf8_lossy(bytes).into_owned()
}

pub(crate) mod exceptions;
mod host_identity;
mod records;
pub use self::host_identity::certificate_authorization_host;
pub(crate) use self::host_identity::certificate_authorization_identity;
#[allow(unused_imports)]
use self::host_identity::*;
pub use self::records::{BoundedObservations, CertificateLedger};
use self::records::{Responder, compact_string};

#[cfg(test)]
mod tests;

/// Everything the permission callback reads from a native permission request.
///
/// The seam exists so the unsafe half (asking WebKit what the request is and
/// which devices it names) is separated from the decision half, and so the
/// decision half can be driven deterministically without a live WebKit,
/// display or capture device.
trait PermissionSource {
    fn is_geolocation(&self) -> bool;
    fn is_notification(&self) -> bool;
    fn is_user_media(&self) -> bool;
    fn is_media_key_system(&self) -> bool;
    /// All three user-media device flags, read independently. No flag may
    /// short-circuit another: one native allow grants every device the request
    /// named, so the classifier must see the complete set.
    fn media_flags(&self) -> MediaCaptureFlags;
}

/// A live `WebKitPermissionRequest`. The only implementation that touches FFI.
struct NativePermissionRequest(*mut ffi::WebKitPermissionRequest);

impl PermissionSource for NativePermissionRequest {
    fn is_geolocation(&self) -> bool {
        is_a(self.0, ffi::webkit_geolocation_permission_request_get_type)
    }

    fn is_notification(&self) -> bool {
        is_a(self.0, ffi::webkit_notification_permission_request_get_type)
    }

    fn is_user_media(&self) -> bool {
        is_a(self.0, ffi::webkit_user_media_permission_request_get_type)
    }

    fn is_media_key_system(&self) -> bool {
        is_a(
            self.0,
            ffi::webkit_media_key_system_permission_request_get_type,
        )
    }

    fn media_flags(&self) -> MediaCaptureFlags {
        // SAFETY: the caller of the enclosing callback guarantees a live
        // user-media permission request (the `is_a` check above); each getter
        // only reads a boolean field of it. All three are read unconditionally;
        // one native allow grants every device the request names.
        unsafe {
            MediaCaptureFlags::new(
                ffi::webkit_user_media_permission_is_for_audio_device(self.0) != 0,
                ffi::webkit_user_media_permission_is_for_video_device(self.0) != 0,
                // No fallback: this symbol is linked unconditionally, so an
                // engine that lacks it fails to build rather than reporting a
                // screen-share request as "not display".
                ffi::webkit_user_media_permission_is_for_display_device(self.0) != 0,
            )
        }
    }
}

/// The single terminal action the permission callback may perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PermissionAction {
    /// `webkit_permission_request_allow`.
    Allow,
    /// `webkit_permission_request_deny`.
    Deny,
}

/// Classify a permission request. Concrete WebKit classes are matched first;
/// a user-media request delegates its three device flags to the pure
/// [`crate::permission_map`] mapping, which is where combined and display
/// capture are resolved.
fn permission_kind(source: &impl PermissionSource) -> PermissionKind {
    if source.is_geolocation() {
        PermissionKind::Geolocation
    } else if source.is_notification() {
        PermissionKind::Notifications
    } else if source.is_user_media() {
        crate::permission_map::user_media_kind(source.media_flags())
    } else if source.is_media_key_system() {
        PermissionKind::MediaKeySystem
    } else {
        // New WebKit permission classes fail closed until deliberately mapped.
        PermissionKind::Unknown(0)
    }
}

/// Classify, correlate and decide one permission request, returning the native
/// action to perform. Every read of the request happens here, before the
/// caller selects `webkit_permission_request_allow` or `..._deny`.
fn decide_permission(lease: &CallbackLease, source: &impl PermissionSource) -> PermissionAction {
    let kind = permission_kind(source);
    let (_, outcome) = lease.decide(RequestKind::Permission(kind));
    if matches!(outcome, NativePolicyOutcome::Applied(Decision::Allow)) {
        PermissionAction::Allow
    } else {
        PermissionAction::Deny
    }
}

fn normalized_mime(value: &str) -> Option<String> {
    if value.len() > 128 || !value.is_ascii() {
        return None;
    }
    let mime = value.split(';').next()?.trim();
    let (kind, subtype) = mime.split_once('/')?;
    let token = |part: &str| {
        !part.is_empty()
            && part
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'+-.^_`|~".contains(&b))
    };
    (token(kind) && token(subtype)).then(|| mime.to_ascii_lowercase())
}
