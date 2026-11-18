//! Owned profile inventory metadata and explicit native cleanup scopes.
//!
//! Cookies have a domain and path, not a scheme/port origin. Native website-data
//! records group multiple origins under display names; reviewed runtimes also
//! expose their origin metadata and origin-scoped deletion. Cookie APIs lack
//! creation or modification timestamps; a visited-site filter belongs to the
//! host's history and must not be presented as a cookie creation-date filter.

#[cfg(any(feature = "wpe", test))]
use crate::page::WebsiteData;

/// Identity used by the native cookie store, without exposing cookie values.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CookieKey {
    /// Cookie name, compared exactly.
    pub name: String,
    /// Native domain, including its leading dot for domain cookies.
    pub domain: String,
    /// Cookie path, compared exactly.
    pub path: String,
}

/// Native SameSite policy. Unknown values remain visible without guessing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CookieSameSite {
    /// No SameSite restriction.
    None,
    /// Top-level safe navigations may carry this cookie.
    Lax,
    /// Only same-site requests may carry this cookie.
    Strict,
    /// The native runtime returned another policy.
    Unknown(i32),
}

/// Owned cookie inventory. Cookie values never leave the native store here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CookieMetadata {
    /// Exact native store identity.
    pub key: CookieKey,
    /// Whether transport must use TLS.
    pub secure: bool,
    /// Whether document scripts cannot read the cookie.
    pub http_only: bool,
    /// Native SameSite policy.
    pub same_site: CookieSameSite,
    /// Seconds since Unix epoch; `None` means a session cookie.
    pub expires_unix_seconds: Option<i64>,
}

/// A native website-data display group, which may contain several origins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebsiteDataRecord {
    /// Native display name; this is not an authoritative origin.
    pub group_name: String,
    /// Native WebKitWebsiteDataTypes bits present in this group.
    pub types: u32,
    /// Native estimated bytes for the fetched kinds; not total profile disk use.
    /// Zero may mean size is unavailable, including for cookies and memory cache.
    pub size_bytes: u64,
    /// Serialized native origins, or `None` when the runtime cannot expose them.
    /// Domain-scoped records such as cookies can have an empty origin list.
    pub origins: Option<Vec<String>>,
}

/// Scope requested for selective website-data removal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebsiteDataSelection {
    /// Remove a complete native display group, potentially several origins.
    NativeGroup(String),
    /// Remove origin-scoped kinds using a runtime with exact-origin support.
    /// Cookies, HSTS and tracking statistics remain domain-scoped and are refused.
    ExactOrigin(String),
}

/// What the public native inventory can honestly express.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SiteDataCapabilities {
    /// Cookie names, domains, paths, flags, SameSite and expiry are available.
    pub cookie_metadata: bool,
    /// Cookie creation/modification timestamps are available.
    pub cookie_creation_modification_times: bool,
    /// Native website-data records identify individual origins.
    pub exact_website_data_origins: bool,
    /// Kinds accepted by exact-origin removal; zero on an unsupported runtime.
    pub exact_website_data_removal_types: u32,
    /// An all-age cookie identity can be removed without clearing the domain.
    pub selective_cookie_deletion: bool,
}

impl SiteDataCapabilities {
    /// Capabilities of the WPE public cookie/website-data APIs used here.
    pub const WPE: Self = Self {
        cookie_metadata: true,
        cookie_creation_modification_times: false,
        exact_website_data_origins: false,
        exact_website_data_removal_types: 0,
        selective_cookie_deletion: true,
    };
}

/// Native kinds whose deletion authority is a scheme/host/port origin.
pub const ORIGIN_SCOPED_DATA_TYPES: u32 = (1 << 0)
    | (1 << 1)
    | (1 << 3)
    | (1 << 4)
    | (1 << 5)
    | (1 << 7)
    | (1 << 10)
    | (1 << 11)
    | (1 << 12);

#[cfg(any(feature = "wpe", test))]
pub(crate) fn validate_origin_selection(
    origin: &str,
    kinds: WebsiteData,
) -> Result<String, SiteDataError> {
    if kinds.bits() == 0 {
        return Err(SiteDataError::InvalidInput("empty website-data kinds"));
    }
    if kinds.bits() & !ORIGIN_SCOPED_DATA_TYPES != 0 {
        return Err(SiteDataError::UnsupportedScope(
            "selected data kinds are not origin-scoped",
        ));
    }
    crate::local_origins::canonical_origin(origin)
        .ok_or(SiteDataError::InvalidInput("expected an HTTP(S) origin"))
}

/// Typed refusal or failure of an inventory/cleanup operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SiteDataError {
    /// Called outside the native owner thread.
    WrongThread,
    /// The bounded native operation budget is occupied.
    Busy,
    /// Cancelled explicitly or by dropping the task.
    Cancelled,
    /// The operation exceeded its deadline; native cleanup remains retained.
    TimedOut,
    /// Invalid or excessive input.
    InvalidInput(&'static str),
    /// Native inventory exceeded the bounded metadata budget.
    InventoryTooLarge,
    /// Public native metadata cannot provide this precision.
    UnsupportedScope(&'static str),
    /// The selected identity no longer exists.
    NotFound,
    /// Native runtime failure.
    Native(String),
}

impl std::fmt::Display for SiteDataError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongThread => {
                f.write_str("site-data operation requires the native owner thread")
            }
            Self::Busy => f.write_str("site-data native operation budget is occupied"),
            Self::Cancelled => f.write_str("site-data operation cancelled"),
            Self::TimedOut => f.write_str("site-data operation timed out"),
            Self::InvalidInput(message) | Self::UnsupportedScope(message) => f.write_str(message),
            Self::InventoryTooLarge => {
                f.write_str("site-data inventory exceeds its metadata budget")
            }
            Self::NotFound => f.write_str("selected site-data identity no longer exists"),
            Self::Native(message) => write!(f, "site-data native failure: {message}"),
        }
    }
}

impl std::error::Error for SiteDataError {}

#[cfg(any(feature = "wpe", test))]
pub(crate) fn validate_group_selection(
    selection: &WebsiteDataSelection,
    kinds: WebsiteData,
) -> Result<&str, SiteDataError> {
    match selection {
        WebsiteDataSelection::ExactOrigin(_) => Err(SiteDataError::UnsupportedScope(
            "native website-data groups cannot safely express exact-origin cleanup",
        )),
        WebsiteDataSelection::NativeGroup(name) => {
            if name.is_empty() || name.len() > 8192 || name.contains('\0') || kinds.bits() == 0 {
                return Err(SiteDataError::InvalidInput(
                    "invalid website-data group or kinds",
                ));
            }
            Ok(name)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn site_data_exact_origin_rejects_domain_scopes_and_url_authority_changes() {
        assert_eq!(
            validate_origin_selection("https://example.test:8443", WebsiteData::LOCAL_STORAGE),
            Ok("https://example.test:8443".into())
        );
        for kinds in [
            WebsiteData::COOKIES,
            WebsiteData::HSTS_CACHE,
            WebsiteData::ALL,
        ] {
            assert!(matches!(
                validate_origin_selection("https://example.test", kinds),
                Err(SiteDataError::UnsupportedScope(_))
            ));
        }
        for origin in [
            "https://example.test/path",
            "https://user@example.test",
            "https://example.test?query",
            "data:text/plain,hello",
            "https://example.test#fragment",
        ] {
            assert!(matches!(
                validate_origin_selection(origin, WebsiteData::LOCAL_STORAGE),
                Err(SiteDataError::InvalidInput(_))
            ));
        }
    }

    #[test]
    fn site_data_native_scope_refuses_unobservable_precision() {
        let capabilities = SiteDataCapabilities::WPE;
        assert!(capabilities.cookie_metadata && capabilities.selective_cookie_deletion);
        assert!(!capabilities.cookie_creation_modification_times);
        assert!(!capabilities.exact_website_data_origins);
        assert!(matches!(
            validate_group_selection(
                &WebsiteDataSelection::ExactOrigin("https://example.test".into()),
                WebsiteData::ALL
            ),
            Err(SiteDataError::UnsupportedScope(_))
        ));
        assert_eq!(
            validate_group_selection(
                &WebsiteDataSelection::NativeGroup("example.test".into()),
                WebsiteData::COOKIES
            ),
            Ok("example.test")
        );
        for group in ["", "invalid\0group"] {
            assert!(matches!(
                validate_group_selection(
                    &WebsiteDataSelection::NativeGroup(group.into()),
                    WebsiteData::ALL
                ),
                Err(SiteDataError::InvalidInput(_))
            ));
        }
    }
}
