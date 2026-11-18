//! Bounded native resource diagnostics, with explicit redaction and missing fields.

use crate::web::ViewId;
use std::time::Duration;

/// A field unavailable through native signals or deliberately excluded from diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceUnavailable {
    /// Native metadata is not yet available.
    NotReported,
    /// The value is outside this diagnostic surface's supported size or scheme.
    Redacted,
    /// Native resource signals do not expose this measurement.
    Unsupported,
}

/// An observed native value or the reason it is absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceField<T> {
    /// An owned bounded value.
    Available(T),
    /// A labelled missing value.
    Unavailable(ResourceUnavailable),
}

/// An allowlisted HTTP header; authentication, cookies and arbitrary headers are omitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceHeader {
    /// Lowercase fixed header name.
    pub name: &'static str,
    /// Bounded value, with control characters removed.
    pub value: String,
}

/// Metadata supplied by a native URI request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceRequest {
    /// HTTP(S) URL with userinfo removed and query/fragment redacted. Paths remain visible.
    pub url: ResourceField<String>,
    /// Native HTTP method, capped at 32 bytes.
    pub method: ResourceField<String>,
    /// Only accept, content-type and range; this is never a complete header dump.
    pub headers: ResourceField<Vec<ResourceHeader>>,
}

/// Metadata supplied by a native URI response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceResponse {
    /// Native HTTP status when reported.
    pub status: ResourceField<u32>,
    /// Native media type, capped at 256 bytes.
    pub mime_type: ResourceField<String>,
    /// Safe fixed header subset, excluding cookies, redirects and authentication.
    pub headers: ResourceField<Vec<ResourceHeader>>,
    /// Declared response content length, not measured wire traffic.
    pub content_length: ResourceField<u64>,
}

/// One native resource lifecycle transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceEventKind {
    /// WebView resource-load-started.
    Started(ResourceRequest),
    /// WebResource sent-request; status identifies the previous redirect response.
    Sent {
        request: ResourceRequest,
        redirect_status: Option<u32>,
    },
    /// WebResource notify::response.
    Response(ResourceResponse),
    /// WebResource failed. Diagnostic text is omitted because it can contain secrets.
    Failed { domain: u32, code: i32 },
    /// Native certificate rejection; certificate bytes and messages are omitted.
    TlsFailed { flags: u32 },
    /// WebResource finished, which also follows a failure.
    Finished { failed: bool },
}

/// Owned diagnostic correlated to a log, logical view and navigation epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceEvent {
    /// Unique subscription identity, including for unbound sessions.
    pub log_id: u64,
    /// Optional router generation captured when the log was opened.
    pub view: Option<ViewId>,
    /// Native page-load generation captured at resource start.
    pub navigation: u64,
    /// Subscription-local monotonic resource identity.
    pub resource_id: u64,
    /// Owner-observed time since resource-load-started; not network phase timing.
    pub elapsed: Duration,
    /// DNS, TLS and wire-transfer phase timings are not exposed by these signals.
    pub network_timing: ResourceField<Duration>,
    /// Native lifecycle event.
    pub kind: ResourceEventKind,
}
