//! Explicit, profile-scoped destination capabilities for local development sites.
//!
//! A grant permits connections to one destination origin, including private DNS
//! answers. It is not an initiator-origin permission: a CONNECT proxy does not
//! identify which document initiated a tunnel. Use a separate network session
//! when unrelated content must not share the capability.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use crate::web::DestinationPolicy;
use enzui_security::url_policy::{SafeUrl, Scheme, UrlPolicy};

/// Maximum number of explicit destination-origin grants per capability.
pub const MAX_LOCAL_ORIGINS: usize = 64;

/// Why an origin grant could not be installed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalOriginError {
    /// Expected an ASCII HTTP(S) origin without credentials, path, query or fragment.
    InvalidOrigin,
    /// The bounded table already contains [`MAX_LOCAL_ORIGINS`] other origins.
    Capacity,
}

impl std::fmt::Display for LocalOriginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidOrigin => {
                "expected an HTTP(S) origin without credentials, path, query or fragment"
            }
            Self::Capacity => "local destination origin table is full",
        })
    }
}

impl std::error::Error for LocalOriginError {}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Origin {
    https: bool,
    host: String,
    port: u16,
}

impl Origin {
    fn from_url(url: &str) -> Option<(Self, SafeUrl)> {
        if url.len() > 64 * 1024
            || !url.is_ascii()
            || url
                .bytes()
                .any(|byte| byte <= b' ' || byte == 127 || byte == b'\\')
        {
            return None;
        }
        let (_, remainder) = url.split_once("://")?;
        let authority = remainder.split(['/', '?', '#']).next()?;
        if !authority.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b':' | b'[' | b']')
        }) {
            return None;
        }
        let safe = DestinationPolicy::trusted_local()
            .screen_request(url)
            .ok()?;
        let host = match safe.host().parse::<IpAddr>() {
            Ok(address) => address.to_string(),
            Err(_) => {
                let name = safe.host().strip_suffix('.').unwrap_or(safe.host());
                if name.is_empty()
                    || safe.host().len() > 254
                    || name.split('.').any(|label| {
                        label.is_empty()
                            || label.len() > 63
                            || !label.as_bytes()[0].is_ascii_alphanumeric()
                            || !label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                            || !label
                                .bytes()
                                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                    })
                {
                    return None;
                }
                let last = name.rsplit('.').next()?;
                if last.bytes().all(|byte| byte.is_ascii_digit())
                    || last.strip_prefix("0x").is_some_and(|hex| {
                        !hex.is_empty() && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
                    })
                {
                    return None;
                }
                safe.host().to_owned()
            }
        };
        let port = safe.port().unwrap_or(if safe.scheme() == Scheme::Https {
            443
        } else {
            80
        });
        if port == 0 {
            return None;
        }
        Some((
            Self {
                https: safe.scheme() == Scheme::Https,
                host,
                port,
            },
            safe,
        ))
    }

    fn parse(origin: &str) -> Result<Self, LocalOriginError> {
        let (parsed, safe) = Self::from_url(origin).ok_or(LocalOriginError::InvalidOrigin)?;
        if origin.len() > 2048
            || !matches!(safe.path(), "" | "/")
            || safe.has_query()
            || origin.contains('#')
        {
            return Err(LocalOriginError::InvalidOrigin);
        }
        Ok(parsed)
    }
}

/// The canonical origin of a full HTTP(S) URL, path and query ignored.
#[cfg(feature = "wpe")]
pub(crate) fn url_origin(url: &str) -> Option<String> {
    let (origin, _) = Origin::from_url(url)?;
    Some(origin_text(origin))
}

pub(crate) fn canonical_origin(value: &str) -> Option<String> {
    Origin::parse(value).ok().map(origin_text)
}

fn origin_text(origin: Origin) -> String {
    let host = if origin.host.contains(':') {
        format!("[{}]", origin.host)
    } else {
        origin.host
    };
    format!(
        "{}://{}:{}",
        if origin.https { "https" } else { "http" },
        host,
        origin.port
    )
}

/// A shared, bounded set of exact HTTP(S) destination origins allowed to resolve locally.
///
/// The default is empty. Clones share grants. Hostnames are ASCII and case-folded;
/// default ports and canonical IP spellings identify the same origin. A trailing
/// DNS root dot remains distinct. Grants never match other schemes or ports.
#[derive(Debug, Clone, Default)]
pub struct LocalOriginAllowlist {
    origins: Arc<Mutex<HashSet<Origin>>>,
}

impl LocalOriginAllowlist {
    /// Grant one destination origin, returning whether it was newly inserted.
    ///
    /// The host must obtain this authorization explicitly from the person using
    /// the browser. A page request must not create its own destination grant.
    ///
    /// # Errors
    /// Returns [`LocalOriginError`] for malformed or excessive grants.
    pub fn allow_origin(&self, origin: &str) -> Result<bool, LocalOriginError> {
        let origin = Origin::parse(origin)?;
        let mut origins = self
            .origins
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if origins.contains(&origin) {
            return Ok(false);
        }
        if origins.len() >= MAX_LOCAL_ORIGINS {
            return Err(LocalOriginError::Capacity);
        }
        Ok(origins.insert(origin))
    }

    /// Revoke one origin for future connection setup, returning whether it existed.
    ///
    /// Established tunnels remain connected until closed or their guard is dropped.
    ///
    /// # Errors
    /// Returns [`LocalOriginError::InvalidOrigin`] for malformed input.
    pub fn revoke_origin(&self, origin: &str) -> Result<bool, LocalOriginError> {
        let origin = Origin::parse(origin)?;
        Ok(self
            .origins
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&origin))
    }

    /// Remove every grant for future connection setup.
    pub fn clear(&self) {
        self.origins
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
    }

    /// Select address rules for one complete destination URL.
    ///
    /// Nonmatching and malformed URLs retain `base`. A matching origin permits
    /// private addresses and its own HTTP scheme while preserving redirect limits.
    /// Callers must still screen the URL and every resolved address and port.
    #[must_use]
    pub fn policy_for_url(&self, base: DestinationPolicy, url: &str) -> DestinationPolicy {
        let origins = self
            .origins
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if origins.is_empty() {
            return base;
        }
        let Some((origin, _)) = Origin::from_url(url) else {
            return base;
        };
        if !origins.contains(&origin) {
            return base;
        }
        DestinationPolicy {
            url: UrlPolicy {
                allow_http: base.url.allow_http || !origin.https,
                allow_private_network: true,
                max_redirects: base.url.max_redirects,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_origins_match_exact_canonical_origin_and_revoke_shared_grants() {
        let list = LocalOriginAllowlist::default();
        let base = DestinationPolicy::DEFAULT;
        assert!(list.allow_origin("HTTP://DEV.LOCAL:08080/").unwrap());
        assert!(!list.allow_origin("http://dev.local:8080").unwrap());
        let clone = list.clone();
        assert!(
            clone
                .policy_for_url(base, "http://dev.local:8080/path?a=1#f")
                .screen_request("http://dev.local:8080/path")
                .is_ok()
        );
        for url in [
            "https://dev.local:8080/",
            "http://dev.local:8081/",
            "http://other.local:8080/",
            "http://dev.local.:8080/",
            "http://user@dev.local:8080/",
            "http://dev.local.evil:8080/",
        ] {
            assert_eq!(list.policy_for_url(base, url), base, "{url}");
        }
        assert!(list.allow_origin("https://127.0.0.1:443").unwrap());
        assert!(!list.allow_origin("https://127.0.0.1").unwrap());
        assert!(list.allow_origin("http://[0:0:0:0:0:0:0:1]:3000").unwrap());
        assert!(!list.allow_origin("http://[::1]:3000").unwrap());
        assert!(clone.revoke_origin("http://dev.local:8080").unwrap());
        assert_eq!(
            list.policy_for_url(base, "http://dev.local:8080/path"),
            base
        );
        clone.clear();
        assert_eq!(list.policy_for_url(base, "https://127.0.0.1"), base);
    }

    #[test]
    fn local_origins_reject_ambiguous_authorities_and_bound_retention() {
        let list = LocalOriginAllowlist::default();
        for origin in [
            "",
            "http://",
            "https://user:pass@localhost",
            "http://localhost/path",
            "http://localhost?",
            "http://localhost#",
            "file://localhost",
            "http://local host",
            "http://localhost\\evil",
            "http://127.1",
            "http://2130706433",
            "http://0x7f000001",
            "http://127.0.0.01",
            "http://-host",
            "http://host_1",
            "http://localhost:0",
            "http://localhost:+80",
            "http://%6cocalhost",
        ] {
            assert_eq!(
                list.allow_origin(origin),
                Err(LocalOriginError::InvalidOrigin),
                "{origin}"
            );
        }
        for index in 0..MAX_LOCAL_ORIGINS {
            assert!(
                list.allow_origin(&format!("http://dev{index}.local"))
                    .unwrap()
            );
        }
        assert!(!list.allow_origin("http://dev0.local:80").unwrap());
        assert_eq!(
            list.allow_origin("http://overflow.local"),
            Err(LocalOriginError::Capacity)
        );
    }
}
