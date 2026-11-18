//! Exact requesting-origin and top-origin identities for browser permissions.

use crate::page::PageRequestId;
use crate::web::policy::PermissionKind;

/// A non-opaque HTTP(S) origin, normalized to scheme, host and effective port.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PermissionOrigin(String);
impl PermissionOrigin {
    /// Parses an origin without credentials, path, query or fragment.
    /// Returns `None` for opaque, malformed or oversized identities.
    pub fn parse(value: &str) -> Option<Self> {
        crate::local_origins::canonical_origin(value).map(Self)
    }
    /// The normalized origin, including its effective port.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A permission authority scoped to both the requesting document and its top document.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SitePermission {
    /// The actual requesting frame's origin, supplied by native WebKit.
    pub requesting_origin: PermissionOrigin,
    /// The actual top document's origin at request time.
    pub top_origin: PermissionOrigin,
    /// Camera, microphone, their combination, location, or notifications for
    /// a top-level document; other kinds are denied.
    pub kind: PermissionKind,
}

/// A bounded native permission prompt awaiting an explicit host answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SitePermissionRequest {
    /// Session-scoped answer correlation, invalidated on navigation or policy replacement.
    pub id: PageRequestId,
    /// The exact authority the answer would permit.
    pub permission: SitePermission,
}
