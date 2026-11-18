//! Native network profiles with isolated cookies, storage and cache.
//!
//! [`ProfileStore`] reuses sessions only within the same profile and destination
//! policy. Named profiles use private directories; ephemeral profiles stay in
//! memory. Persistent cookie storage is explicitly enabled with SQLite because
//! setting the native session's data directory alone does not persist cookies.

use super::wpe;
use crate::abandoned_operation::{self, AbandonedOperationFields, AbandonedOperationState};
use crate::deadline_source::{
    CompletionState, DeadlineRetirement, DeadlineSourceState, NativeSourceRemover, SourceRemover,
    retire_deadline,
};
use crate::web::{DestinationPolicy, ProfileId, ProfileKind, WebProfile};
use core::ffi::{CStr, c_char, c_uint, c_void};
use std::cell::Cell;
use std::collections::HashMap;
use std::ffi::CString;
use std::path::{Path, PathBuf};
use std::rc::{Rc, Weak};

/// How long any single async cookie op may take before it is treated as a
/// failure. This is a *safety net against a wedged network process*, not a
/// correctness threshold: the op resolves via its callback the instant WebKit
/// answers, and the deadline only bounds a hang. Cf. the snapshot path.
const COOKIE_DEADLINE_MS: u32 = 10_000;

/// Errors from the profile/storage layer - every one a loud, typed refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileError {
    /// Native WPE initialization belongs to another thread.
    WrongThread(super::NativeThreadError),
    /// The loaded libsoup predates the required proxy-credential hardening.
    UnsupportedNetworkRuntime([u32; 3]),
    /// `webkit_network_session_new*` returned NULL.
    SessionConstructionFailed,
    /// A path or cookie field contained an interior NUL.
    InteriorNul(&'static str),
    /// `soup_cookie_new` returned NULL.
    CookieConstructionFailed,
    /// An async cookie op did not complete before the internal deadline
    /// (`COOKIE_DEADLINE_MS`).
    Timeout(&'static str),
    /// `add_cookie` reported failure.
    AddFailed(String),
    /// `get_cookies` reported failure.
    GetFailed(String),
    /// The profile root or one of its private directories could not be made.
    ProvisioningFailed(String),
    /// The profile subtree failed a symlink-safe, user-private security
    /// invariant on disk. See [`crate::profile_fs::ProvisionError`].
    ProfileFs(String),
    /// A persistent profile name cannot be represented safely as one path
    /// component. Names are capped before hex encoding so they cannot exceed
    /// common filesystem component limits.
    InvalidProfileName,
    /// WPE's C API cannot receive a non-UTF-8 profile directory.
    NonUtf8Path,
    /// The mandatory destination guard could not be created or installed.
    DestinationGuard(String),
    /// A live view already uses this storage profile under a different network
    /// trust posture. Proxy settings are session-wide, so mixing is refused.
    DestinationPolicyConflict,
    /// A live view already uses this storage profile with a different upstream
    /// proxy. Routing is session-wide, so mixing is refused.
    UpstreamProxyConflict,
}

impl core::fmt::Display for ProfileError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::WrongThread(error) => error.fmt(f),
            Self::UnsupportedNetworkRuntime(version) => write!(
                f,
                "network sessions require libsoup >= 3.8.0 for proxy credential isolation; loaded {}.{}.{}",
                version[0], version[1], version[2]
            ),
            Self::SessionConstructionFailed => write!(f, "network session construction failed"),
            Self::InteriorNul(field) => write!(f, "interior NUL in {field}"),
            Self::CookieConstructionFailed => write!(f, "soup_cookie_new returned NULL"),
            Self::Timeout(op) => write!(f, "cookie op '{op}' timed out"),
            Self::AddFailed(m) => write!(f, "add_cookie failed: {m}"),
            Self::GetFailed(m) => write!(f, "get_cookies failed: {m}"),
            Self::ProvisioningFailed(m) => write!(f, "profile provisioning failed: {m}"),
            Self::ProfileFs(m) => write!(f, "profile filesystem refused: {m}"),
            Self::InvalidProfileName => write!(
                f,
                "persistent profile name exceeds 120 UTF-8 bytes and cannot be encoded safely"
            ),
            Self::NonUtf8Path => write!(f, "profile directory is not valid UTF-8"),
            Self::DestinationGuard(error) => {
                write!(f, "destination guard could not be installed: {error}")
            }
            Self::DestinationPolicyConflict => write!(
                f,
                "profile already has a live network session under a different destination policy"
            ),
            Self::UpstreamProxyConflict => write!(
                f,
                "profile already has a live network session with a different upstream proxy"
            ),
        }
    }
}

impl std::error::Error for ProfileError {}

/// Provisions real WebKit network sessions from app-owned [`WebProfile`]
/// identities.
///
/// The root layout is stable and traversal-safe:
///
/// - `shared/{data,cache}` for the process-wide shared profile;
/// - `persistent/<UTF-8 bytes as hex>/{data,cache}` for named profiles;
/// - no directory at all for ephemeral profiles.
///
/// Hex encoding is injective and uses only ASCII path-safe bytes, so names such
/// as `../work` cannot escape the root and distinct accepted names cannot
/// collide.
///
/// # Security invariant on disk
///
/// Every directory in this tree - from the store root inclusive down to
/// `<sub>/data` and `<sub>/cache` - is a real directory (never a symlink),
/// owned by the uid, and mode 0700. Provisioning refuses foreign-owned
/// paths, refuses non-directory collisions, refuses any symlink component,
/// tightens an over-permissive owned directory to 0700 rather than deleting
/// it, and creates fresh directories 0700 regardless of umask. See
/// [`crate::profile_fs`] and the gates in `tests/profile_fs.rs`.
///
/// The shared engine must own one `ProfileStore`. Within it, a live
/// session is cached weakly by [`ProfileId`]. Two live views may share it only
/// when their destination policies match; a conflicting strict/trusted-local
/// request is refused. This is required because proxy settings are
/// session-wide. A trusted-local view therefore cannot overwrite or inherit a
/// strict view's proxy. Dropping one sharing view cannot kill the guard while
/// another remains. Once the final view closes, the profile may be reopened
/// under a different explicit posture. Reopening a
/// persistent profile reconstructs a
/// session on the same directories; reopening an ephemeral profile starts
/// empty, as required.
#[derive(Debug)]
pub struct ProfileStore {
    root: PathBuf,
    // Proxy settings live on WebKitNetworkSession, not WebKitWebView. A live
    // profile has exactly one immutable destination posture; a conflicting
    // request is refused rather than overwriting or inheriting routing.
    live: HashMap<ProfileId, Weak<NetworkSession>>,
}

impl Drop for ProfileStore {
    /// The store holds only `Weak` handles, so this releases no GObject by
    /// itself - it records that the provisioner between `WebSession` and
    /// `HeadlessDisplay` in a page's drop order was itself destroyed.
    fn drop(&mut self) {
        crate::native_release::record_profile_store();
    }
}

impl ProfileStore {
    /// Create a profile provisioner rooted at `root`.
    ///
    /// Directories are created lazily when a persistent/shared profile is
    /// first used. This constructor performs no WPE call.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            live: HashMap::new(),
        }
    }

    /// Resolve `profile` to the real WebKit storage session a view must use.
    /// Same-identity strict profiles return the same `Rc`; distinct or freshly
    /// minted ephemeral identities never share. WebViews use
    /// `session_for_policy`, which refuses a different trust posture while the
    /// profile's current session is live.
    ///
    /// # Errors
    /// Returns [`ProfileError::WrongThread`] before filesystem changes when
    /// another thread owns WPE, or a profile/session provisioning error.
    pub fn session_for(
        &mut self,
        profile: &WebProfile,
    ) -> Result<Rc<NetworkSession>, ProfileError> {
        self.session_for_policy(profile, DestinationPolicy::DEFAULT)
    }

    /// Resolve a profile under an explicit destination policy. Network sessions
    /// are shared only when both profile identity and destination policy match:
    /// proxy configuration is session-wide in WebKit and must never be
    /// overwritten by another view.
    pub(crate) fn session_for_policy(
        &mut self,
        profile: &WebProfile,
        policy: DestinationPolicy,
    ) -> Result<Rc<NetworkSession>, ProfileError> {
        NetworkSession::validate_runtime()?;
        let id = profile.id();
        if let Some(existing) = self.live.get(&id).and_then(Weak::upgrade) {
            if existing.destination_policy() != policy {
                return Err(ProfileError::DestinationPolicyConflict);
            }
            if existing.upstream_proxy() != profile.upstream_proxy() {
                return Err(ProfileError::UpstreamProxyConflict);
            }
            return Ok(existing);
        }

        self.prune_closed_profiles();

        let session = match profile.kind() {
            ProfileKind::Ephemeral { .. } => {
                NetworkSession::new_ephemeral_routed(policy, profile.upstream_proxy())?
            }
            ProfileKind::Shared => {
                self.persistent_under(Path::new("shared"), policy, profile.upstream_proxy())?
            }
            ProfileKind::Persistent { name } => {
                let component = encoded_profile_name(name)?;
                self.persistent_under(
                    &Path::new("persistent").join(component),
                    policy,
                    profile.upstream_proxy(),
                )?
            }
        };
        let session = Rc::new(session);
        self.live.insert(id, Rc::downgrade(&session));
        Ok(session)
    }

    /// Remove cached identities whose session handles have all been dropped.
    /// Returns the number removed. Live sessions and their policy bindings remain
    /// shared; persistent website data on disk is unchanged. New-session lookup
    /// also prunes these identities automatically.
    pub fn prune_closed_profiles(&mut self) -> usize {
        let previous = self.live.len();
        self.live.retain(|_, session| session.strong_count() != 0);
        previous - self.live.len()
    }

    fn persistent_under(
        &self,
        relative: &Path,
        policy: DestinationPolicy,
        upstream: Option<crate::destination_guard::UpstreamProxy>,
    ) -> Result<NetworkSession, ProfileError> {
        // `create_dir_all` follows symlinks, inherits umask, and never
        // checks ownership. Persistent WebView storage cannot ride on those
        // defaults - a permissive or pre-planted directory would expose or
        // redirect the cookie sqlite. Provision through the symlink-safe,
        // 0700, uid-verified `profile_fs` module; every failure surfaces as a
        // typed `ProfileError::ProfileFs` with the exact refused path/reason.
        let provision = crate::profile_fs::begin_persistent_profile_tree(&self.root, relative)
            .map_err(|e| ProfileError::ProfileFs(e.to_string()))?;
        let result = NetworkSession::new_persistent_path_with_policy(
            &provision.paths().data,
            &provision.paths().cache,
            policy,
            upstream,
        );
        match result {
            Ok(session) => {
                let _ = provision.commit();
                Ok(session)
            }
            Err(backend_error) => match provision.rollback() {
                Ok(()) => Err(backend_error),
                Err(rollback_error) => Err(ProfileError::ProfileFs(format!(
                    "{backend_error}; rollback also failed: {rollback_error}"
                ))),
            },
        }
    }
}

/// Encode an app-owned profile name as one injective path component. At two
/// hex digits per byte, the 120-byte cap keeps the component <=240 bytes.
fn encoded_profile_name(name: &str) -> Result<String, ProfileError> {
    if name.len() > 120 {
        return Err(ProfileError::InvalidProfileName);
    }
    if name.is_empty() {
        return Ok("empty".to_owned());
    }
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(name.len() * 2);
    for byte in name.bytes() {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    Ok(encoded)
}

/// A live WebKit network/storage session - the real boundary a profile isolates.
///
/// `!Send + !Sync`: the whole WPE runtime is single-threaded (a raw pointer
/// field enforces it), matching the rest of this crate.
#[derive(Debug)]
pub struct NetworkSession {
    session: *mut wpe::WebKitNetworkSession,
    destination_policy: DestinationPolicy,
    destination_guard: Option<crate::destination_guard::DestinationGuard>,
    upstream: Option<crate::destination_guard::UpstreamProxy>,
    _not_send_sync: core::marker::PhantomData<*const c_void>,
}

impl Drop for NetworkSession {
    fn drop(&mut self) {
        if !self.session.is_null() {
            // SAFETY: `session` is a WebKitNetworkSession* this code owns (rc>=1).
            unsafe { wpe::g_object_unref(self.session.cast::<c_void>()) };
        }
        // a destroyed page must give back its storage session, not just
        // its view; the close gate reads this counter.
        crate::native_release::record_network_session();
    }
}

impl NetworkSession {
    fn validate_runtime() -> Result<(), ProfileError> {
        super::threading::claim().map_err(ProfileError::WrongThread)?;
        let version = super::native_runtime_versions().network;
        if version < [3, 8, 0] {
            return Err(ProfileError::UnsupportedNetworkRuntime(version));
        }
        Ok(())
    }

    /// A persistent session storing cookies under `data_dir`. Enables SQLite
    /// cookie persistence explicitly - the data directory alone does not, so a
    /// session that trusted it would silently forget cookies on restart.
    ///
    /// # Errors
    ///
    /// [`ProfileError::WrongThread`], [`ProfileError::SessionConstructionFailed`],
    /// [`ProfileError::UnsupportedNetworkRuntime`], [`ProfileError::InteriorNul`],
    /// or [`ProfileError::DestinationGuard`].
    pub fn new_persistent(data_dir: &str, cache_dir: &str) -> Result<Self, ProfileError> {
        Self::new_persistent_path_with_policy(
            Path::new(data_dir),
            Path::new(cache_dir),
            DestinationPolicy::DEFAULT,
            None,
        )
    }

    fn new_persistent_path_with_policy(
        data_dir: &Path,
        cache_dir: &Path,
        policy: DestinationPolicy,
        upstream: Option<crate::destination_guard::UpstreamProxy>,
    ) -> Result<Self, ProfileError> {
        Self::validate_runtime()?;
        let data_dir = data_dir.to_str().ok_or(ProfileError::NonUtf8Path)?;
        let cache_dir = cache_dir.to_str().ok_or(ProfileError::NonUtf8Path)?;
        let c_data = CString::new(data_dir).map_err(|_| ProfileError::InteriorNul("data_dir"))?;
        let c_cache =
            CString::new(cache_dir).map_err(|_| ProfileError::InteriorNul("cache_dir"))?;
        // SAFETY: two live C strings; returns rc=1 or NULL.
        let session = unsafe { wpe::webkit_network_session_new(c_data.as_ptr(), c_cache.as_ptr()) };
        if session.is_null() {
            return Err(ProfileError::SessionConstructionFailed);
        }
        let cookie_path = format!("{data_dir}/cookies.sqlite");
        let c_path =
            CString::new(cookie_path).map_err(|_| ProfileError::InteriorNul("cookie_path"))?;
        // SAFETY: `session` is live; the cookie manager is borrowed from it.
        unsafe {
            let cm = wpe::webkit_network_session_get_cookie_manager(session);
            wpe::webkit_cookie_manager_set_persistent_storage(
                cm,
                c_path.as_ptr(),
                wpe::WEBKIT_COOKIE_PERSISTENT_STORAGE_SQLITE,
            );
        }
        Self::finish_construction(session, policy, upstream)
    }

    /// An ephemeral session - all storage in memory, nothing on disk.
    ///
    /// # Errors
    ///
    /// [`ProfileError::WrongThread`], [`ProfileError::SessionConstructionFailed`],
    /// [`ProfileError::UnsupportedNetworkRuntime`], or [`ProfileError::DestinationGuard`].
    pub fn new_ephemeral() -> Result<Self, ProfileError> {
        Self::new_ephemeral_with_policy(DestinationPolicy::DEFAULT)
    }

    pub(crate) fn new_ephemeral_with_policy(
        policy: DestinationPolicy,
    ) -> Result<Self, ProfileError> {
        Self::new_ephemeral_routed(policy, None)
    }

    fn new_ephemeral_routed(
        policy: DestinationPolicy,
        upstream: Option<crate::destination_guard::UpstreamProxy>,
    ) -> Result<Self, ProfileError> {
        Self::validate_runtime()?;
        // SAFETY: the current thread owns WPE; returns rc=1 or NULL.
        let session = unsafe { wpe::webkit_network_session_new_ephemeral() };
        if session.is_null() {
            return Err(ProfileError::SessionConstructionFailed);
        }
        Self::finish_construction(session, policy, upstream)
    }

    /// Build an ephemeral session with deterministic DNS/connect seams for
    /// full native integration tests.
    ///
    /// # Errors
    ///
    /// Returns the same construction/guard failures as [`Self::new_ephemeral`].
    #[doc(hidden)]
    pub fn new_ephemeral_with_destination_seams(
        policy: DestinationPolicy,
        resolver: std::sync::Arc<dyn crate::destination_guard::Resolver>,
        connector: std::sync::Arc<dyn crate::destination_guard::Connector>,
    ) -> Result<Self, ProfileError> {
        Self::validate_runtime()?;
        // SAFETY: the current thread owns WPE; returns rc=1 or NULL.
        let session = unsafe { wpe::webkit_network_session_new_ephemeral() };
        if session.is_null() {
            return Err(ProfileError::SessionConstructionFailed);
        }
        // Even trusted-local sessions retain the guard. Address restrictions
        // are disabled by that named policy, but the guard is also the only
        // boundary that sees a cleartext redirect's wire `Location` before
        // WPE 2.52 removes URL userinfo.
        let guard = match crate::destination_guard::DestinationGuard::start_with(
            policy, resolver, connector,
        ) {
            Ok(guard) => Some(guard),
            Err(error) => {
                // SAFETY: construction owns this rc=1 session, which has not been published.
                unsafe { wpe::g_object_unref(session.cast::<c_void>()) };
                return Err(ProfileError::DestinationGuard(error.to_string()));
            }
        };
        Self::finish_with_guard(session, policy, guard)
    }

    fn finish_construction(
        session: *mut wpe::WebKitNetworkSession,
        policy: DestinationPolicy,
        upstream: Option<crate::destination_guard::UpstreamProxy>,
    ) -> Result<Self, ProfileError> {
        // `trusted_local` relaxes address classification; it does not relax
        // the invariant that URL credentials are refused. Keep its network
        // session behind the guard so cleartext redirects are screened on the
        // wire, before WebKit canonicalises them.
        let guard = match crate::destination_guard::DestinationGuard::start_routed(policy, upstream)
        {
            Ok(guard) => Some(guard),
            Err(error) => {
                unsafe { wpe::g_object_unref(session.cast::<c_void>()) };
                return Err(ProfileError::DestinationGuard(error.to_string()));
            }
        };
        Self::finish_with_guard(session, policy, guard).map(|mut session| {
            session.upstream = upstream;
            session
        })
    }

    fn finish_with_guard(
        session: *mut wpe::WebKitNetworkSession,
        policy: DestinationPolicy,
        guard: Option<crate::destination_guard::DestinationGuard>,
    ) -> Result<Self, ProfileError> {
        if let Some(guard) = guard {
            // Keep the proxy URI credential-free. WPE/libsoup rewrites a
            // cleartext request target to a proxy URI containing userinfo;
            // the WebView's authenticate callback supplies the capability.
            let uri = CString::new(guard.proxy_uri())
                .expect("generated loopback proxy configuration contains no NUL");
            // NULL ignore-hosts means no destination bypasses the guard. WebKit
            // copies the boxed settings during the setter, so free the value.
            let settings =
                unsafe { wpe::webkit_network_proxy_settings_new(uri.as_ptr(), core::ptr::null()) };
            if settings.is_null() {
                unsafe { wpe::g_object_unref(session.cast::<c_void>()) };
                return Err(ProfileError::DestinationGuard(
                    "webkit_network_proxy_settings_new returned NULL".into(),
                ));
            }
            unsafe {
                wpe::webkit_network_session_set_proxy_settings(
                    session,
                    wpe::WEBKIT_NETWORK_PROXY_MODE_CUSTOM,
                    settings,
                );
                wpe::webkit_network_proxy_settings_free(settings);
            }
            return Ok(Self {
                session,
                destination_policy: policy,
                destination_guard: Some(guard),
                upstream: None,
                _not_send_sync: core::marker::PhantomData,
            });
        }
        Ok(Self {
            session,
            destination_policy: policy,
            destination_guard: None,
            upstream: None,
            _not_send_sync: core::marker::PhantomData,
        })
    }

    /// The upstream proxy this session's guard tunnels through, if any.
    #[must_use]
    pub fn upstream_proxy(&self) -> Option<crate::destination_guard::UpstreamProxy> {
        self.upstream
    }

    /// The immutable policy paired with this network session.
    #[must_use]
    pub(crate) fn destination_policy(&self) -> DestinationPolicy {
        self.destination_policy
    }

    /// The guard address for this network session. Strict and trusted-local
    /// policies both retain the guard; only their address posture differs.
    #[must_use]
    /// Shared destination grants for this network session, absent only without a guard.
    pub fn local_origins(&self) -> Option<crate::local_origins::LocalOriginAllowlist> {
        self.destination_guard
            .as_ref()
            .map(|guard| guard.local_origins())
    }

    pub(crate) fn destination_guard_addr(&self) -> Option<std::net::SocketAddr> {
        self.destination_guard.as_ref().map(|guard| guard.addr())
    }

    /// Borrow the exact endpoint and capability for a view's proxy challenge.
    pub(crate) fn destination_guard_proxy_auth(
        &self,
    ) -> Option<(std::net::SocketAddr, &'static str, &str)> {
        self.destination_guard.as_ref().map(|guard| {
            let (username, password) = guard.proxy_credentials();
            (guard.addr(), username, password)
        })
    }

    #[must_use]
    pub(crate) fn destination_guard_events(&self) -> Vec<crate::destination_guard::GuardEvent> {
        self.destination_guard
            .as_ref()
            .map(crate::destination_guard::DestinationGuard::events)
            .unwrap_or_default()
    }

    #[must_use]
    pub(crate) fn destination_guard_dropped(&self) -> u64 {
        self.destination_guard
            .as_ref()
            .map(crate::destination_guard::DestinationGuard::dropped_events)
            .unwrap_or(0)
    }

    /// Borrow the underlying session for constructing a WebKit view. The
    /// resulting view takes its own GObject reference; safe wrappers also keep
    /// the `Rc<NetworkSession>` alive for an explicit ownership chain.
    pub(crate) fn as_ptr(&self) -> *mut wpe::WebKitNetworkSession {
        self.session
    }

    /// Whether WebKit considers this session ephemeral. Read back through the
    /// FFI rather than remembered from construction, so it observes WebKit's
    /// own answer.
    #[must_use]
    pub fn is_ephemeral(&self) -> bool {
        // SAFETY: `session` is live.
        unsafe { wpe::webkit_network_session_is_ephemeral(self.session) != wpe::G_FALSE }
    }

    /// Add a cookie for `domain`/`path` with `name=value`, blocking on a
    /// bounded main loop until WebKit confirms.
    ///
    /// # Errors
    ///
    /// [`ProfileError::CookieConstructionFailed`], [`ProfileError::Timeout`],
    /// [`ProfileError::AddFailed`], or [`ProfileError::InteriorNul`].
    pub fn add_cookie(
        &self,
        domain: &str,
        path: &str,
        name: &str,
        value: &str,
    ) -> Result<(), ProfileError> {
        self.add_cookie_with_caps(domain, path, name, value, COOKIE_DEADLINE_MS, DRAIN_CAP_MS)
    }

    /// [`add_cookie`](Self::add_cookie) with the deadline and the bounded
    /// drain cap injected, so a gate can force the cap-expiry
    /// ownership-transfer branch deterministically instead of waiting for a
    /// wedged network process.
    ///
    /// A `drain_cap_ms` of 0 returns from the drain loop *before* it iterates
    /// the context, so the still-pending callback cannot resolve during the
    /// call and the transfer branch runs every time. The production entry point
    /// keeps `COOKIE_DEADLINE_MS` / [`DRAIN_CAP_MS`]; this seam changes no
    /// default.
    ///
    /// # Errors
    ///
    /// As [`add_cookie`](Self::add_cookie).
    pub fn add_cookie_with_caps(
        &self,
        domain: &str,
        path: &str,
        name: &str,
        value: &str,
        deadline_ms: u32,
        drain_cap_ms: u64,
    ) -> Result<(), ProfileError> {
        let c_name = CString::new(name).map_err(|_| ProfileError::InteriorNul("name"))?;
        let c_value = CString::new(value).map_err(|_| ProfileError::InteriorNul("value"))?;
        let c_domain = CString::new(domain).map_err(|_| ProfileError::InteriorNul("domain"))?;
        let c_path = CString::new(path).map_err(|_| ProfileError::InteriorNul("path"))?;

        // SAFETY: four live C strings; max_age > 0 => a persistent cookie.
        let cookie = unsafe {
            wpe::soup_cookie_new(
                c_name.as_ptr(),
                c_value.as_ptr(),
                c_domain.as_ptr(),
                c_path.as_ptr(),
                3600,
            )
        };
        if cookie.is_null() {
            return Err(ProfileError::CookieConstructionFailed);
        }
        // Free the cookie however this code exits (add_cookie copies it).
        struct CookieGuard(*mut wpe::SoupCookie);
        impl Drop for CookieGuard {
            fn drop(&mut self) {
                // SAFETY: `self.0` is a SoupCookie* owned here.
                unsafe { wpe::soup_cookie_free(self.0) };
            }
        }
        let _cookie_guard = CookieGuard(cookie);

        // SAFETY: `session` is live; cookie manager borrowed from it.
        let cm = unsafe { wpe::webkit_network_session_get_cookie_manager(self.session) };

        let outcome = run_bounded(
            deadline_ms,
            drain_cap_ms,
            "add_cookie",
            self.session,
            |state_ptr, cancellable| {
                // SAFETY: launching the async add; `on_add_ready` receives `state_ptr`.
                unsafe {
                    wpe::webkit_cookie_manager_add_cookie(
                        cm,
                        cookie,
                        cancellable,
                        on_add_ready,
                        state_ptr,
                    );
                }
            },
        )?;
        match outcome {
            OpOutcome::AddOk => Ok(()),
            OpOutcome::Failed(m) => Err(ProfileError::AddFailed(m)),
            OpOutcome::Cookies(_) => Err(ProfileError::AddFailed(
                "add returned a cookie list (impossible)".into(),
            )),
        }
    }

    /// Read back every cookie visible to `uri` as `(name, value)` pairs.
    ///
    /// # Errors
    ///
    /// [`ProfileError::Timeout`], [`ProfileError::GetFailed`], or
    /// [`ProfileError::InteriorNul`].
    pub fn cookies_for(&self, uri: &str) -> Result<Vec<(String, String)>, ProfileError> {
        self.cookies_for_with_caps(uri, COOKIE_DEADLINE_MS, DRAIN_CAP_MS)
    }

    /// [`cookies_for`](Self::cookies_for) with the deadline and bounded drain
    /// cap injected - the read-side twin of
    /// [`add_cookie_with_caps`](Self::add_cookie_with_caps).
    ///
    /// # Errors
    ///
    /// As [`cookies_for`](Self::cookies_for).
    pub fn cookies_for_with_caps(
        &self,
        uri: &str,
        deadline_ms: u32,
        drain_cap_ms: u64,
    ) -> Result<Vec<(String, String)>, ProfileError> {
        let c_uri = CString::new(uri).map_err(|_| ProfileError::InteriorNul("uri"))?;
        // SAFETY: `session` is live; cookie manager borrowed from it.
        let cm = unsafe { wpe::webkit_network_session_get_cookie_manager(self.session) };
        let outcome = run_bounded(
            deadline_ms,
            drain_cap_ms,
            "get_cookies",
            self.session,
            |state_ptr, cancellable| {
                // SAFETY: launching the async query; `on_get_ready` receives `state_ptr`.
                unsafe {
                    wpe::webkit_cookie_manager_get_cookies(
                        cm,
                        c_uri.as_ptr(),
                        cancellable,
                        on_get_ready,
                        state_ptr,
                    );
                }
            },
        )?;
        match outcome {
            OpOutcome::Cookies(v) => Ok(v),
            OpOutcome::Failed(m) => Err(ProfileError::GetFailed(m)),
            OpOutcome::AddOk => Err(ProfileError::GetFailed(
                "get returned add-ok (impossible)".into(),
            )),
        }
    }

    /// Convenience: how many cookies `uri` sees.
    ///
    /// # Errors
    ///
    /// As [`NetworkSession::cookies_for`].
    pub fn cookie_count(&self, uri: &str) -> Result<usize, ProfileError> {
        self.cookies_for(uri).map(|v| v.len())
    }
}

// ---------------------------------------------------------------------------
// Bounded async driver, mirroring the snapshot path's structure: build a
// GMainLoop, install a g_timeout_add deadline, kick off the async op, run the
// loop; the op's callback (or the deadline) quits it. The callback fills the
// state; this code reads it after the loop returns.
// ---------------------------------------------------------------------------

/// What a cookie op produced.
enum OpOutcome {
    AddOk,
    Cookies(Vec<(String, String)>),
    Failed(String),
}

/// State shared with the async callbacks. `!repr(C)` is fine - only pointers to
/// it cross the FFI boundary, opaquely.
///
/// # The box is not the only thing a late callback touches
///
/// [`on_add_ready`] / [`on_get_ready`] reach `main_loop` *through* this box and
/// finish against the cookie manager borrowed from `session`. So on the
/// cap-expiry path the main thread must not free any of them: it transfers
/// ownership of the box, the loop, the cancellable and an extra strong ref on
/// the network session to the callback, which frees them exactly once when it
/// finally runs (the same asynchronous ownership transfer the a11y `DoAction` and snapshot paths
/// already do).
struct OpState {
    main_loop: *mut wpe::GMainLoop,
    /// The `GCancellable*` the outstanding op holds. Freed by whichever side
    /// owns cleanup: the main thread normally, the callback when abandoned.
    cancellable: *mut c_void,
    /// An extra strong ref on the `WebKitNetworkSession` the op's cookie
    /// manager belongs to, taken only on the cap-expiry transfer path so a
    /// dropped [`NetworkSession`] cannot finalize the manager the pending
    /// callback finishes against. NULL on every normal path.
    session: *mut wpe::WebKitNetworkSession,
    /// Deterministic lifetime witness for `session`: set to the session pointer
    /// on the transfer path and registered with `g_object_add_weak_pointer`, so
    /// GLib NULLs it if the object is finalized before the callback runs. The
    /// callback checks it, turning a missing ownership transfer into an
    /// observable [`profile_lifetime_violation_count`] instead of a
    /// probabilistic use-after-free.
    session_witness: Cell<*mut c_void>,
    /// The same witness for `cancellable`.
    cancellable_witness: Cell<*mut c_void>,
    /// Set true by the op’s `GAsyncReadyCallback` (add or get), so the
    /// deadline path knows whether the callback has already resolved.
    callback_fired: Cell<bool>,
    /// Set true by the deadline callback, which destroys its own source. The
    /// retirement decision reads this rather than
    /// [`callback_fired`](Self::callback_fired): GLib can dispatch the deadline
    /// and the op callback in one batch.
    deadline_fired: Cell<bool>,
    /// Set true by the main thread when its bounded drain expired. It transfers
    /// ownership of the box and every callback-reachable resource to the op
    /// callback, which frees them when it runs. `false` on every normal path,
    /// where the main thread owns cleanup.
    abandoned: Cell<bool>,
    /// Filled by the op callback.
    outcome: std::cell::RefCell<Option<OpOutcome>>,
}

impl AbandonedOperationState for OpState {
    type Session = wpe::WebKitNetworkSession;
    type Witness = c_void;

    fn abandoned_operation_fields(
        &mut self,
    ) -> AbandonedOperationFields<'_, Self::Session, Self::Witness> {
        AbandonedOperationFields {
            session: &mut self.session,
            session_witness: &self.session_witness,
            cancellable_witness: &self.cancellable_witness,
            abandoned: &self.abandoned,
        }
    }

    fn is_abandoned(&self) -> bool {
        self.abandoned.get()
    }
}

/// How long the cancel/drain loop waits for a cancelled op’s callback to
/// resolve before handing it ownership of everything it can still reach.
///
/// This is callback-owned cleanup, not a permanent leak: the callback frees the
/// state box, the main loop, the cancellable, the outcome and the extra session
/// ref exactly once and bumps [`profile_abandoned_cleanup_count`].
pub const DRAIN_CAP_MS: u64 = 2_000;

thread_local! {
    /// How many times an abandoned profile op callback completed its own
    /// cleanup on this thread. A gate reads it before and after pumping
    /// to prove the callback ran and *released*, rather than that the process
    /// merely survived - mirroring
    /// [`crate::ffi::a11y::abandoned_cleanup_count`].
    static PROFILE_ABANDONED_CLEANUPS: Cell<u64> = const { Cell::new(0) };
    /// How many times an abandoned profile op callback found a resource it was
    /// handed already finalized (its weak witness NULL). Must stay 0: any
    /// increment means the main thread freed a callback-reachable pointee, i.e.
    /// the ownership transfer is broken.
    static PROFILE_LIFETIME_VIOLATIONS: Cell<u64> = const { Cell::new(0) };
}

/// How many times a cancelled profile-op callback completed its own
/// abandoned-path cleanup on this thread.
#[must_use]
pub fn profile_abandoned_cleanup_count() -> u64 {
    PROFILE_ABANDONED_CLEANUPS.with(Cell::get)
}

/// How many times an abandoned profile-op callback observed a resource it owns
/// as already finalized. A non-zero value is a proven lifetime bug: the
/// main thread released something the pending callback still reaches.
#[must_use]
pub fn profile_lifetime_violation_count() -> u64 {
    PROFILE_LIFETIME_VIOLATIONS.with(Cell::get)
}

/// Free everything an abandoned [`OpState`] owns - the outcome, the main loop,
/// the cancellable and the extra session ref - then the box, and record the
/// cleanup. Called only by [`on_abandoned_cleanup`], the deferred source
/// [`on_add_ready`] / [`on_get_ready`] install on the abandoned path.
///
/// Each GObject is checked against its weak witness first: a NULLed witness
/// means the pointee was finalized before this callback ran, so unref'ing it
/// would be the very use-after-free the transfer prevents. That case is
/// recorded, loudly, rather than performed.
///
/// # Safety
///
/// `ptr` must be the live, abandoned `OpState` box, and this must run on the
/// owning (single) thread with no other reference to it outstanding.
unsafe fn free_abandoned_op(ptr: *mut OpState) {
    // SAFETY: `ptr` came from `Box::into_raw`; every resource it names was kept
    // alive (the main thread disarmed its guards) precisely for this moment.
    // `Box::from_raw` does not move the allocation, so the witness addresses
    // registered with GLib stay valid until the box drops below.
    let boxed = unsafe { Box::from_raw(ptr) };
    let mut violations = 0_u64;

    for (object, witness) in [
        (boxed.cancellable, &boxed.cancellable_witness),
        (boxed.session.cast::<c_void>(), &boxed.session_witness),
    ] {
        if object.is_null() {
            continue;
        }
        if witness.get().is_null() {
            // GLib nullified the witness: this object was finalized while the
            // callback was still outstanding. Do not unref a freed pointee.
            violations += 1;
            continue;
        }
        // SAFETY: the witness still names a live object registered here, so
        // removing the weak pointer and dropping the ref are both valid.
        unsafe {
            wpe::g_object_remove_weak_pointer(object, witness.as_ptr());
            wpe::g_object_unref(object);
        }
    }

    if !boxed.main_loop.is_null() {
        // SAFETY: the main loop the main thread deliberately did not unref.
        unsafe { wpe::g_main_loop_unref(boxed.main_loop) };
    }

    if violations > 0 {
        // Loud: a silently-recorded lifetime bug reads like a clean run.
        eprintln!(
            "enzui web-engine: PROFILE LIFETIME VIOLATION — {violations} resource(s) an \
             abandoned cookie-op callback owns were already finalized; the \
             cap-expiry ownership transfer is broken"
        );
        PROFILE_LIFETIME_VIOLATIONS.with(|c| c.set(c.get() + violations));
    }
    PROFILE_ABANDONED_CLEANUPS.with(|c| c.set(c.get() + 1));
    // `boxed` drops here, freeing the outcome (owned Strings) and the box.
}

/// The deferred abandoned-cleanup source. Returns `G_FALSE` so it runs once.
///
/// # Why the free is deferred by one dispatch
///
/// Empirically (this gate, before the deferral existed): releasing the extra
/// session ref *inside* the completion callback finalized the
/// `WebKitNetworkSession` while GLib was still tearing down the completing
/// `GTask`, whose source object is the session's `WebKitCookieManager`. The
/// task's own `g_object_unref` then ran WebKit's cookie-manager dispose against
/// the just-destroyed session and SIGSEGV'd inside `libWPEWebKit` - *after* the
/// callback had returned, so no ordering inside the callback could avoid it.
///
/// A 0-ms source dispatches strictly after the current source's dispatch
/// completes, i.e. after WebKit has finished with the in-flight task, so the
/// cleanup is safe there. It is still callback-owned: the callback hands the
/// free to a source it created, nothing else can reach the box, and
/// [`free_abandoned_op`] runs exactly once.
extern "C" fn on_abandoned_cleanup(user_data: *mut c_void) -> wpe::GBoolean {
    if !user_data.is_null() {
        // SAFETY: the abandoned box, handed to this source by the op callback;
        // single-threaded, no other reader, and the source fires once.
        unsafe { free_abandoned_op(user_data.cast::<OpState>()) };
    }
    wpe::G_FALSE
}

/// If the main thread abandoned this op, hand the free to a deferred source and
/// return true - after which nothing may read the state again.
///
/// # Safety
///
/// `user_data` must be the live `OpState` box this callback was registered with.
unsafe fn finish_if_abandoned(user_data: *mut c_void) -> bool {
    // SAFETY: caller guarantees a live box; read the transfer flag before any
    // free so no reference into the box outlives it.
    if !unsafe { (&*user_data.cast::<OpState>()).is_abandoned() } {
        return false;
    }
    // The box (and everything it owns) is now the deferred source's, which frees
    // it on the next dispatch - see `on_abandoned_cleanup` for why not here.
    // SAFETY: `on_abandoned_cleanup` matches GSourceFunc and receives the box.
    unsafe { wpe::g_timeout_add(0, on_abandoned_cleanup, user_data) };
    true
}

/// Build the loop, install the deadline, run `launch`, drive the loop, and
/// return the outcome - or a [`ProfileError::Timeout`] if the deadline won.
///
/// The `launch` closure receives `(state_ptr, cancellable)` so each async
/// WebKit call passes a live `GCancellable*`. On timeout the cancellable is
/// cancelled and the default context is drained until the callback fires -
/// exactly the pattern `runtime.rs` uses for snapshots - so the callback
/// can never run against a freed `OpState` box.
///
/// If the bounded drain expires with the callback still outstanding, ownership
/// of every callback-reachable resource (the box, the loop, the cancellable,
/// the outcome and an extra ref on `session`) is transferred to that callback,
/// which frees them exactly once. `session` may be NULL only if the
/// caller has no native object the callback reaches.
fn run_bounded(
    deadline_ms: u32,
    drain_cap_ms: u64,
    which: &'static str,
    session: *mut wpe::WebKitNetworkSession,
    launch: impl FnOnce(/*state*/ *mut c_void, /*cancellable*/ *mut c_void),
) -> Result<OpOutcome, ProfileError> {
    // SAFETY: a fresh, running-flag-false GMainLoop.
    let main_loop = unsafe { wpe::g_main_loop_new(core::ptr::null_mut(), wpe::G_FALSE) };
    /// Unrefs the loop unless the cap-expiry path disarmed it by handing
    /// ownership to the pending callback.
    struct LoopGuard(*mut wpe::GMainLoop);
    impl Drop for LoopGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: `self.0` is a GMainLoop* created here.
                unsafe { wpe::g_main_loop_unref(self.0) };
            }
        }
    }
    let mut loop_guard = LoopGuard(main_loop);

    // A cancellable for the async op. On a timeout this code cancels it and drain
    // until the callback has fired, so the callback can never run against
    // the freed `state` box.
    // SAFETY: returns a GCancellable* rc=1.
    let cancellable = unsafe { wpe::g_cancellable_new() };
    assert!(!cancellable.is_null(), "g_cancellable_new returned NULL");
    /// Unrefs the cancellable unless the cap-expiry path disarmed it.
    struct CancelGuard(*mut c_void);
    impl Drop for CancelGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: the cancellable, rc=1.
                unsafe { wpe::g_object_unref(self.0) };
            }
        }
    }
    let mut cancel_guard = CancelGuard(cancellable);

    let state = Box::new(OpState {
        main_loop,
        cancellable,
        session: core::ptr::null_mut(),
        session_witness: Cell::new(core::ptr::null_mut()),
        cancellable_witness: Cell::new(core::ptr::null_mut()),
        callback_fired: Cell::new(false),
        deadline_fired: Cell::new(false),
        abandoned: Cell::new(false),
        outcome: std::cell::RefCell::new(None),
    });
    let state_ptr = Box::into_raw(state);
    struct StateGuard(*mut OpState);
    impl Drop for StateGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: `self.0` came from Box::into_raw; all callback
                // sources have either fired or been removed before this code reaches
                // this point.
                drop(unsafe { Box::from_raw(self.0) });
            }
        }
    }
    let mut _state_guard = StateGuard(state_ptr);

    // Install the deadline BEFORE launching, so even an op that fails to start
    // its callback cannot hang. Returning G_FALSE removes it.
    // SAFETY: `on_deadline` matches the g_timeout_add callback signature.
    let deadline_id =
        unsafe { wpe::g_timeout_add(deadline_ms, on_op_deadline, state_ptr.cast::<c_void>()) };

    launch(state_ptr.cast::<c_void>(), cancellable);

    // SAFETY: the loop runs until a callback quits it (op or deadline).
    unsafe { wpe::g_main_loop_run(main_loop) };

    // Only a source that never dispatched is still registered and must be removed, and it must
    // be retired before StateGuard frees the box.
    // SAFETY: single-threaded; both flags are written only by callbacks
    // dispatched on this thread, which finished before the loop returned.
    let retirement =
        unsafe { retire_op_deadline(&*state_ptr, deadline_id, &mut NativeSourceRemover) };
    if !retirement.completion_resolved() {
        // The deadline won. The async op’s callback is still pending and
        // would fire later against this freed box. Cancel it and drain the
        // default context until the callback runs (it fires exactly once,
        // promptly, with G_IO_ERROR_CANCELLED). Bounded so it cannot hang.
        // SAFETY: the live cancellable.
        unsafe { wpe::g_cancellable_cancel(cancellable) };
        let drain_start = std::time::Instant::now();
        let drain_cap = std::time::Duration::from_millis(drain_cap_ms);
        // `callback_fired` is flipped by `on_add_ready` / `on_get_ready`,
        // which runs *inside* `g_main_context_iteration` below - a
        // mutation clippy cannot see, hence the explicit `loop` + `break`
        // (a `while` on the flag trips `while_immutable_condition`).
        loop {
            // SAFETY: single-threaded read of a flag written only by the
            // callback dispatched on this thread.
            if unsafe { (*state_ptr).callback_fired.get() } {
                break;
            }
            if drain_start.elapsed() >= drain_cap {
                // A pending callback retains the state, loop, cancellable, outcome, and a
                // strong session reference; weak witnesses expose premature finalization.
                // SAFETY: callbacks run only during main-context dispatch, so `state_ptr` is
                // exclusively accessible here; each pointer passed to GLib is a live GObject.
                unsafe {
                    if !session.is_null() {
                        wpe::g_object_ref(session.cast::<c_void>());
                    }
                    let witnesses = abandoned_operation::transfer_abandoned_ownership(
                        state_ptr,
                        session,
                        session.cast::<c_void>(),
                        cancellable,
                    );
                    if !session.is_null() {
                        wpe::g_object_add_weak_pointer(session.cast::<c_void>(), witnesses.session);
                    }
                    wpe::g_object_add_weak_pointer(cancellable, witnesses.cancellable);
                }
                // Disarm every guard: the callback owns these now.
                _state_guard.0 = core::ptr::null_mut();
                loop_guard.0 = core::ptr::null_mut();
                cancel_guard.0 = core::ptr::null_mut();
                return Err(ProfileError::Timeout(which));
            }
            // SAFETY: NULL context = default; may_block=FALSE returns at
            // once, so this loop is bounded by the wall-clock cap. This
            // is what dispatches the (now-cancelled) async callback that
            // flips `callback_fired`.
            unsafe {
                let _ = wpe::g_main_context_iteration(core::ptr::null_mut(), wpe::G_FALSE);
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        return Err(ProfileError::Timeout(which));
    }

    // SAFETY: take the outcome out of the state.
    let outcome = unsafe { (*state_ptr).outcome.borrow_mut().take() };
    match outcome {
        Some(o) => Ok(o),
        None => Err(ProfileError::Timeout(which)),
    }
}

// Split from each callback's GLib quit so a dispatch-order test can drive both
// with no main context.
fn mark_op_completion(state: &OpState) {
    state.callback_fired.set(true);
}

fn mark_op_deadline(state: &OpState) -> wpe::GBoolean {
    state.deadline_fired.set(true);
    wpe::G_FALSE // G_SOURCE_REMOVE: the source destroys itself.
}

fn retire_op_deadline<R>(
    state: &OpState,
    deadline_id: c_uint,
    remover: &mut R,
) -> DeadlineRetirement
where
    R: SourceRemover + ?Sized,
{
    retire_deadline(
        CompletionState::from_resolved(state.callback_fired.get()),
        DeadlineSourceState::from_fired(state.deadline_fired.get()),
        deadline_id,
        remover,
    )
}

extern "C" fn on_op_deadline(user_data: *mut c_void) -> wpe::GBoolean {
    // SAFETY: `user_data` is the live `OpState`.
    let state = unsafe { &*(user_data as *const OpState) };
    let disposition = mark_op_deadline(state);
    // SAFETY: `main_loop` is valid for any callback's lifetime.
    unsafe { wpe::g_main_loop_quit(state.main_loop) };
    disposition
}

/// `add_cookie` completion.
extern "C" fn on_add_ready(
    source: *mut c_void,
    result: *mut wpe::GAsyncResult,
    user_data: *mut c_void,
) {
    // SAFETY: `user_data` is the live `OpState`.
    let state = unsafe { &*(user_data as *const OpState) };
    let cm = source as *mut wpe::WebKitCookieManager;
    let mut error: *mut wpe::GError = core::ptr::null_mut();
    // SAFETY: `cm` and `result` are valid for the callback body.
    let ok = unsafe { wpe::webkit_cookie_manager_add_cookie_finish(cm, result, &mut error) };
    let outcome = if ok != wpe::G_FALSE {
        OpOutcome::AddOk
    } else {
        // SAFETY: `webkit_cookie_manager_add_cookie_finish` failed, so
        // `error` is a live, owned `GError` that has not been freed.
        OpOutcome::Failed(unsafe { take_error(error) })
    };
    *state.outcome.borrow_mut() = Some(outcome);
    mark_op_completion(state);
    // SAFETY: valid loop pointer - the caller unrefs it after this returns, or this
    // function frees it just below on the abandoned path. Quit is idempotent.
    unsafe { wpe::g_main_loop_quit(state.main_loop) };
    // If the main thread's drain cap expired, it handed over ownership of
    // the box, the loop, the cancellable and the session ref. Free them; after
    // this nothing may read `state`.
    // SAFETY: `user_data` is the box, abandoned or not.
    let _freed = unsafe { finish_if_abandoned(user_data) };
}

/// `get_cookies` completion - walk the `GList<SoupCookie*>`, freeing as this code goes.
extern "C" fn on_get_ready(
    source: *mut c_void,
    result: *mut wpe::GAsyncResult,
    user_data: *mut c_void,
) {
    // SAFETY: `user_data` is the live `OpState`.
    let state = unsafe { &*(user_data as *const OpState) };
    let cm = source as *mut wpe::WebKitCookieManager;
    let mut error: *mut wpe::GError = core::ptr::null_mut();
    // SAFETY: `cm` and `result` are valid for the callback body.
    let list = unsafe { wpe::webkit_cookie_manager_get_cookies_finish(cm, result, &mut error) };

    let outcome = if list.is_null() && !error.is_null() {
        // SAFETY: `webkit_cookie_manager_get_cookies_finish` failed
        // (NULL list + non-NULL error), so `error` is a live, owned
        // `GError` that has not been freed.
        OpOutcome::Failed(unsafe { take_error(error) })
    } else {
        let mut pairs = Vec::new();
        let mut node = list;
        // Walk the GList; transfer=full, so free each cookie then the list.
        while !node.is_null() {
            // SAFETY: `node` is a live GList node; `data` is a SoupCookie*.
            let cookie = unsafe { (*node).data } as *mut wpe::SoupCookie;
            if !cookie.is_null() {
                // SAFETY: `cookie` is live; the getters return borrowed C strings.
                let name = unsafe { c_str_to_owned(wpe::soup_cookie_get_name(cookie)) };
                let value = unsafe { c_str_to_owned(wpe::soup_cookie_get_value(cookie)) };
                pairs.push((name, value));
                // SAFETY: this code owns each cookie in the list (transfer=full).
                unsafe { wpe::soup_cookie_free(cookie) };
            }
            // SAFETY: advancing to the next node before freeing the list.
            node = unsafe { (*node).next };
        }
        if !list.is_null() {
            // SAFETY: free the list nodes; elements already freed.
            unsafe { wpe::g_list_free(list) };
        }
        OpOutcome::Cookies(pairs)
    };
    *state.outcome.borrow_mut() = Some(outcome);
    mark_op_completion(state);
    // SAFETY: valid loop pointer; see `on_add_ready`.
    unsafe { wpe::g_main_loop_quit(state.main_loop) };
    // Callback-owned cleanup when the main thread abandoned this operation.
    // SAFETY: `user_data` is the box, abandoned or not.
    let _freed = unsafe { finish_if_abandoned(user_data) };
}

/// Read the message from a `GError` and free it, or return a placeholder
/// if `error` is null.
///
/// # Safety
///
/// - If `error` is non-null it must point to a live, validly-initialized
///   `GError` whose `message` field is a valid NUL-terminated C string
///   (as guaranteed by `g_error_new` and related GLib constructors).
/// - The caller must own the `GError`: this function frees it with
///   `g_error_free` exactly once, so the pointer must not be used
///   afterwards and must not have been freed already.
/// - Must be called from the thread that owns the GLib objects reachable
///   through the error (the main/engine thread for every current caller).
unsafe fn take_error(error: *mut wpe::GError) -> String {
    if error.is_null() {
        return "(no error set)".to_string();
    }
    // SAFETY: `error` is a live, owned `GError` per caller contract.
    let msg_ptr = unsafe { (*error).message };
    let msg = if msg_ptr.is_null() {
        "(null message)".to_string()
    } else {
        // SAFETY: glib guarantees a NUL-terminated message; the read is
        // bounded by the shared native-diagnostic ceiling.
        unsafe {
            crate::native_diagnostic::read_bounded_diagnostic(
                msg_ptr,
                crate::native_diagnostic::MAX_NATIVE_DIAGNOSTIC_BYTES,
            )
        }
    };
    // SAFETY: the caller guarantees sole ownership; freed exactly once.
    unsafe { wpe::g_error_free(error) };
    msg
}

/// Copy a borrowed C string (or NULL) into an owned `String`.
///
/// # Safety
///
/// `p` must be NULL or a valid NUL-terminated C string.
unsafe fn c_str_to_owned(p: *const c_char) -> String {
    if p.is_null() {
        String::new()
    } else {
        // SAFETY: caller guarantees a valid C string.
        unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
    }
}
