//! Correlated, default-deny policy for embedded web requests.
//!
//! Unknown schemes and permissions are denied. Each reply resolves exactly the outstanding [`RequestId`] it names; unknown or already-resolved ids decide nothing.

use std::fmt;

use crate::web::destination::{DestinationDenial, DestinationPolicy};
use enzui_security::url_policy::UrlVerdict;

pub use enzui_security::url_policy::Scheme;

/// An opaque correlation identifier for an outstanding request in a [`WebPolicy`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RequestId(u64);

/// A page permission kind; unrecognized engine kinds are represented by [`Self::Unknown`] and are always denied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PermissionKind {
    /// Geolocation.
    Geolocation,
    /// Camera / video capture.
    Camera,
    /// Microphone / audio capture.
    Microphone,
    /// A combined camera-and-microphone request, allowed only when both primitive permissions are granted.
    ///
    /// This variant cannot itself be granted through [`WebPolicy::grant`].
    CameraAndMicrophone,
    /// Desktop / window notifications.
    Notifications,
    /// Clipboard read.
    ClipboardRead,
    /// Sharing a screen or window (`getDisplayMedia`). Only an answer to the
    /// request itself allows it: [`WebPolicy::grant`] ignores it and origin
    /// mode never remembers it. The desktop's own picker then chooses what is
    /// shared, and may still refuse.
    ScreenCapture,
    /// Encrypted media (EME) access to a key system. ClearKey is the only key
    /// system a runtime can offer; licensed CDMs are not supported.
    MediaKeySystem,
    /// An unrecognized permission, always denied and carrying its engine tag for diagnostics.
    Unknown(u32),
}

/// A raw policy URL whose formatting omits fragments and redacts query text; `scheme://` authorities also have userinfo stripped.
#[derive(Clone, PartialEq, Eq)]
pub struct PolicyUrl(String);

impl PolicyUrl {
    /// Wrap a raw URL string for policy use.
    #[must_use]
    pub fn new(raw: impl Into<String>) -> Self {
        Self(raw.into())
    }

    /// Returns the unredacted URL for policy decisions; do not use it for logs or display.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns a diagnostic form with fragments omitted and query text replaced by `?<redacted>`; userinfo is stripped for `scheme://` authorities.
    #[must_use]
    pub fn redacted(&self) -> String {
        redact_url_string(&self.0)
    }
}

impl fmt::Debug for PolicyUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PolicyUrl({})", self.redacted())
    }
}

impl fmt::Display for PolicyUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.redacted())
    }
}

fn redact_url_string(url: &str) -> String {
    if let Some((scheme, rest)) = url.split_once("://") {
        let mut result = String::with_capacity(url.len());
        result.push_str(scheme);
        result.push_str("://");

        let path_start = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let authority = &rest[..path_start];
        let after_auth = &rest[path_start..];
        let hostport = match authority.rsplit_once('@') {
            Some((_userinfo, hp)) => hp,
            None => authority,
        };
        result.push_str(hostport);

        let no_frag = after_auth.split_once('#').map_or(after_auth, |(a, _)| a);
        if let Some((before_q, _)) = no_frag.split_once('?') {
            result.push_str(before_q);
            result.push_str("?<redacted>");
        } else {
            // Omit fragments because applications may place credentials in them.
            result.push_str(no_frag);
        }
        result
    } else {
        let no_frag = url.split_once('#').map_or(url, |(before, _)| before);
        if let Some((before, _)) = no_frag.split_once('?') {
            format!("{before}?<redacted>")
        } else {
            no_frag.to_owned()
        }
    }
}

/// The context of a navigation request: where it is going and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NavContext {
    /// The target URL, with redacted [`Debug`] output.
    pub url: PolicyUrl,
    /// Whether a user gesture, rather than script, initiated the navigation.
    pub user_initiated: bool,
}

/// The context of a TLS certificate error the engine is asking about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertContext {
    /// The host the certificate was presented for.
    pub host: String,
    /// Whether certificate-chain validation failed; `true` means the engine could not verify it.
    pub validation_failed: bool,
}

/// The context of a popup (new-window) request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PopupContext {
    /// The requested popup URL, with redacted [`Debug`] output.
    pub url: PolicyUrl,
    /// Whether a user gesture triggered the popup; absent gestures are denied.
    pub user_initiated: bool,
}

/// A decision request the engine raised, awaiting a correlated reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestKind {
    /// A scheme/navigation decision.
    Navigation(NavContext),
    /// A permission grant/deny.
    Permission(PermissionKind),
    /// A TLS certificate proceed/abort.
    Certificate(CertContext),
    /// A popup open/block.
    Popup(PopupContext),
    /// A request to begin a download; the URL's formatting is redacted.
    Download {
        /// The URL the download would fetch.
        url: PolicyUrl,
    },
    /// A document response, subframe, or subresource request screened by the same destination policy as navigation.
    Resource {
        /// The resource URL. Its [`Debug`] output is redacted.
        url: PolicyUrl,
        /// Whether this is the main frame's main resource (the document) as
        /// opposed to a subresource or a subframe.
        main_frame: bool,
    },
}

/// An allow-or-deny verdict for one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// The request may proceed.
    Allow,
    /// The request is refused, with the reason.
    Deny(DenyReason),
}

impl Decision {
    /// Whether this decision permits the request.
    #[must_use]
    pub const fn is_allowed(self) -> bool {
        matches!(self, Decision::Allow)
    }
}

/// The classified reason a request was denied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DenyReason {
    /// The URL's scheme is not on the allow-list (reuses [`enzui_security::url_policy`]).
    SchemeRefused(UrlVerdict),
    /// The URL was syntactically acceptable but its destination policy failed; the payload contains no URL.
    DestinationRefused(DestinationDenial),
    /// The requested permission is not granted by this policy (either not
    /// enabled, or an [`PermissionKind::Unknown`] the allow-list has no entry
    /// for).
    PermissionNotGranted,
    /// A TLS certificate error, and the policy does not permit overriding it.
    CertificateRejected,
    /// A popup, and the policy does not permit it (or it had no user gesture).
    PopupBlocked,
    /// A download, and the policy does not permit unsolicited downloads.
    DownloadRefused,
}

/// The result of resolving a request, distinguishing a decision from an unknown correlation id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveOutcome {
    /// The outstanding request was consumed and resolved to `decision`.
    Decided {
        /// The request that was resolved.
        id: RequestId,
        /// The decision reached for it.
        decision: Decision,
    },
    /// The id was never opened or was already resolved, so no request was decided.
    Unknown {
        /// The unrecognised id.
        id: RequestId,
    },
}

/// Policy configuration and outstanding correlated requests; all capability grants default off.
#[derive(Debug, Clone)]
pub struct WebPolicy {
    pub(crate) local_origins: crate::local_origins::LocalOriginAllowlist,
    /// Whether cleartext `http` navigations are allowed (else HTTPS only).
    pub allow_http: bool,
    /// The non-optional destination policy applied to navigation, popup, download, and resource URLs; strict by default.
    pub destination: DestinationPolicy,
    // Unknown permissions cannot be inserted, so absent kinds are denied.
    granted_permissions: PermissionSet,
    /// Whether a real TLS validation failure may be overridden (proceed anyway).
    /// Off by default - a cert error fails closed.
    pub allow_insecure_certificates: bool,
    /// Whether popups are allowed at all (still only with a user gesture).
    pub allow_popups: bool,
    /// Whether downloads may begin.
    pub allow_downloads: bool,

    next_id: u64,
    outstanding: std::collections::BTreeMap<RequestId, RequestKind>,
}

#[derive(Debug, Clone, Default)]
struct PermissionSet {
    geolocation: bool,
    camera: bool,
    microphone: bool,
    notifications: bool,
    clipboard_read: bool,
    media_key_system: bool,
}

impl PermissionSet {
    fn allows(&self, kind: PermissionKind) -> bool {
        match kind {
            PermissionKind::Geolocation => self.geolocation,
            PermissionKind::Camera => self.camera,
            PermissionKind::Microphone => self.microphone,
            PermissionKind::CameraAndMicrophone => self.camera && self.microphone,
            PermissionKind::Notifications => self.notifications,
            PermissionKind::ClipboardRead => self.clipboard_read,
            PermissionKind::MediaKeySystem => self.media_key_system,
            PermissionKind::ScreenCapture | PermissionKind::Unknown(_) => false,
        }
    }

    fn set(&mut self, kind: PermissionKind, on: bool) {
        match kind {
            PermissionKind::Geolocation => self.geolocation = on,
            PermissionKind::Camera => self.camera = on,
            PermissionKind::Microphone => self.microphone = on,
            PermissionKind::CameraAndMicrophone => {}
            PermissionKind::Notifications => self.notifications = on,
            PermissionKind::ClipboardRead => self.clipboard_read = on,
            PermissionKind::MediaKeySystem => self.media_key_system = on,
            PermissionKind::ScreenCapture | PermissionKind::Unknown(_) => {}
        }
    }
}

impl WebPolicy {
    /// A fresh policy in the strict default-deny posture: HTTPS only, no
    /// permissions granted, cert errors fatal, no popups, no downloads.
    #[must_use]
    pub fn strict() -> WebPolicy {
        WebPolicy {
            local_origins: Default::default(),
            allow_http: false,
            destination: DestinationPolicy::DEFAULT,
            granted_permissions: PermissionSet::default(),
            allow_insecure_certificates: false,
            allow_popups: false,
            allow_downloads: false,
            next_id: 1,
            outstanding: std::collections::BTreeMap::new(),
        }
    }

    /// Grants one primitive permission and returns `self`; unknown, combined and screen-capture kinds are ignored.
    #[must_use]
    pub fn grant(mut self, kind: PermissionKind) -> Self {
        self.granted_permissions.set(kind, true);
        self
    }

    /// Replaces the destination policy and returns `self` for builder chaining.
    #[must_use]
    pub fn with_destination(mut self, destination: DestinationPolicy) -> Self {
        // Installing a destination policy must not discard an existing cleartext opt-in.
        self.destination = destination;
        self
    }

    /// The destination rule in force, with this policy's cleartext flag folded
    /// in. This is the single value every URL decision is made against.
    #[must_use]
    pub fn destination(&self) -> DestinationPolicy {
        let mut destination = self.destination;
        destination.url.allow_http = self.allow_http || destination.url.allow_http;
        destination
    }

    /// Registers a request and returns the [`RequestId`] required to resolve it.
    pub fn open(&mut self, request: RequestKind) -> RequestId {
        let id = RequestId(self.next_id);
        self.next_id += 1;
        self.outstanding.insert(id, request);
        id
    }

    /// The number of requests awaiting a decision.
    #[must_use]
    pub fn outstanding_count(&self) -> usize {
        self.outstanding.len()
    }

    /// Whether `id` is an outstanding request.
    #[must_use]
    pub fn is_outstanding(&self, id: RequestId) -> bool {
        self.outstanding.contains_key(&id)
    }

    /// Returns the outstanding request associated with `id`, if any.
    #[must_use]
    pub fn request_kind(&self, id: RequestId) -> Option<&RequestKind> {
        self.outstanding.get(&id)
    }

    /// Consumes and decides the outstanding request named by `id`; unknown or already-resolved ids return [`ResolveOutcome::Unknown`].
    pub fn resolve(&mut self, id: RequestId) -> ResolveOutcome {
        let Some(request) = self.outstanding.remove(&id) else {
            return ResolveOutcome::Unknown { id };
        };
        let decision = self.decide(&request);
        ResolveOutcome::Decided { id, decision }
    }

    /// Decides a request without registering or consuming a correlation id.
    #[must_use]
    pub fn decide(&self, request: &RequestKind) -> Decision {
        match request {
            RequestKind::Navigation(nav) => self.decide_scheme(nav.url.as_str()),
            RequestKind::Resource { url, .. } => self.decide_scheme(url.as_str()),
            RequestKind::Popup(popup) => {
                if !self.allow_popups || !popup.user_initiated {
                    return Decision::Deny(DenyReason::PopupBlocked);
                }
                match self.decide_scheme(popup.url.as_str()) {
                    Decision::Allow => Decision::Allow,
                    deny => deny,
                }
            }
            RequestKind::Permission(kind) => {
                if self.granted_permissions.allows(*kind) {
                    Decision::Allow
                } else {
                    Decision::Deny(DenyReason::PermissionNotGranted)
                }
            }
            RequestKind::Certificate(cert) => {
                if cert.validation_failed && !self.allow_insecure_certificates {
                    Decision::Deny(DenyReason::CertificateRejected)
                } else {
                    Decision::Allow
                }
            }
            RequestKind::Download { url } => {
                if !self.allow_downloads {
                    return Decision::Deny(DenyReason::DownloadRefused);
                }
                match self.decide_scheme(url.as_str()) {
                    Decision::Allow => Decision::Allow,
                    deny => deny,
                }
            }
        }
    }

    /// Shares exact host-authorized local destination grants with this policy.
    #[must_use]
    pub fn with_local_origins(
        mut self,
        origins: crate::local_origins::LocalOriginAllowlist,
    ) -> Self {
        self.local_origins = origins;
        self
    }

    fn decide_scheme(&self, url: &str) -> Decision {
        match self
            .local_origins
            .policy_for_url(self.destination(), url)
            .screen_request(url)
        {
            Ok(_) => Decision::Allow,
            Err(DestinationDenial::Url(verdict)) => {
                Decision::Deny(DenyReason::SchemeRefused(verdict))
            }
            Err(other) => Decision::Deny(DenyReason::DestinationRefused(other)),
        }
    }
}
