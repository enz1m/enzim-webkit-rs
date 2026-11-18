//! Storage-profile identities for embedded web views.
//!
//! Shared profiles use a common identity, persistent profiles share identity by exact name, and ephemeral profiles are non-persistent and keyed by process-local tokens.

use std::sync::atomic::{AtomicU64, Ordering};

/// A storage-sharing identity; persistent names do not themselves contain filesystem paths.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ProfileKind {
    /// The process-wide default profile shared by all users of this variant.
    Shared,
    /// A persistent profile sharing storage only with profiles of the same case-sensitive name.
    Persistent {
        /// The stable profile name that maps to an on-disk data directory.
        name: String,
    },
    /// A non-persistent profile instance keyed by a process-local token.
    Ephemeral {
        /// The token minted by [`WebProfile::ephemeral`] for this instance.
        token: u64,
    },
}

impl ProfileKind {
    /// Returns whether this kind persists to disk; only [`Self::Ephemeral`] returns `false`.
    #[must_use]
    pub const fn is_persistent(&self) -> bool {
        matches!(self, ProfileKind::Shared | ProfileKind::Persistent { .. })
    }

    /// Whether this is an ephemeral (in-memory, non-persisting) profile.
    #[must_use]
    pub const fn is_ephemeral(&self) -> bool {
        matches!(self, ProfileKind::Ephemeral { .. })
    }
}

static EPHEMERAL_TOKEN: AtomicU64 = AtomicU64::new(1);

/// A comparable storage identity: shared default, exact persistent name, or ephemeral instance token.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ProfileId {
    /// The one shared default profile.
    Shared,
    /// A persistent profile, keyed by name.
    Persistent(String),
    /// An ephemeral profile, keyed by its process-local token.
    Ephemeral(u64),
}

/// A web storage profile with explicit sharing identity.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WebProfile {
    kind: ProfileKind,
    upstream: Option<crate::destination_guard::UpstreamProxy>,
}

impl WebProfile {
    /// The process-wide shared default profile.
    #[must_use]
    pub fn shared() -> WebProfile {
        WebProfile {
            kind: ProfileKind::Shared,
            upstream: None,
        }
    }

    /// Creates a persistent profile that shares storage only with the same exact name.
    #[must_use]
    pub fn persistent(name: impl Into<String>) -> WebProfile {
        WebProfile {
            kind: ProfileKind::Persistent { name: name.into() },
            upstream: None,
        }
    }

    /// Creates a non-persistent profile with a newly minted process-local token.
    #[must_use]
    pub fn ephemeral() -> WebProfile {
        let token = EPHEMERAL_TOKEN.fetch_add(1, Ordering::Relaxed);
        WebProfile {
            kind: ProfileKind::Ephemeral { token },
            upstream: None,
        }
    }

    /// Route this profile's guarded traffic through an upstream proxy.
    ///
    /// The destination guard still screens and pins every destination; the
    /// proxy only carries the tunnel. A live profile is shared only with
    /// views that request the same routing, and recovery keeps it.
    #[must_use]
    pub fn with_upstream_proxy(mut self, proxy: crate::destination_guard::UpstreamProxy) -> Self {
        self.upstream = Some(proxy);
        self
    }

    /// The upstream proxy this profile's traffic uses, if any.
    #[must_use]
    pub fn upstream_proxy(&self) -> Option<crate::destination_guard::UpstreamProxy> {
        self.upstream.clone()
    }

    /// This profile's kind.
    #[must_use]
    pub fn kind(&self) -> &ProfileKind {
        &self.kind
    }

    /// Whether this profile persists to disk. `false` for ephemeral only.
    #[must_use]
    pub fn persists(&self) -> bool {
        self.kind.is_persistent()
    }

    /// A cheap, comparable identity for this profile.
    #[must_use]
    pub fn id(&self) -> ProfileId {
        match &self.kind {
            ProfileKind::Shared => ProfileId::Shared,
            ProfileKind::Persistent { name } => ProfileId::Persistent(name.clone()),
            ProfileKind::Ephemeral { token } => ProfileId::Ephemeral(*token),
        }
    }

    /// Returns whether both values identify the same storage: shared-to-shared, equal persistent names, or the same ephemeral token.
    #[must_use]
    pub fn shares_storage(&self, other: &WebProfile) -> bool {
        match (&self.kind, &other.kind) {
            (ProfileKind::Shared, ProfileKind::Shared) => true,
            (ProfileKind::Persistent { name: a }, ProfileKind::Persistent { name: b }) => a == b,
            (ProfileKind::Ephemeral { token: a }, ProfileKind::Ephemeral { token: b }) => a == b,
            _ => false,
        }
    }
}
