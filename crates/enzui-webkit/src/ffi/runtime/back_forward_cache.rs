//! The back/forward cache: pages WebKit keeps alive after navigating away.
//!
//! A cached page restores instantly on Back. After a cross-site navigation it
//! keeps its own suspended web process, with that process's whole heap, until
//! it expires. Sessions start with WebKit's two-page capacity and a ten-minute
//! lifetime, Chromium's, instead of WebKit's thirty minutes.
use super::*;
use std::sync::OnceLock;
use std::time::Duration;

type SetPolicy = unsafe extern "C" fn(*mut c_void, c_uint, c_uint);
type Clear = unsafe extern "C" fn(*mut c_void);
struct Api {
    set_policy: SetPolicy,
    clear: Clear,
}
#[link(name = "dl")]
unsafe extern "C" {
    fn dlsym(handle: *mut c_void, name: *const c_char) -> *mut c_void;
}
fn api() -> Option<&'static Api> {
    static API: OnceLock<Option<Api>> = OnceLock::new();
    API.get_or_init(|| {
        // SAFETY: fixed fork symbols are resolved from already loaded native libraries.
        let (set_policy, clear) = unsafe {
            (
                dlsym(
                    ptr::null_mut(),
                    c"webkit_web_context_enzui_set_back_forward_cache_v1".as_ptr(),
                ),
                dlsym(
                    ptr::null_mut(),
                    c"webkit_web_context_enzui_clear_back_forward_cache_v1".as_ptr(),
                ),
            )
        };
        if set_policy.is_null() || clear.is_null() {
            return None;
        }
        // SAFETY: these functions use the reviewed fork's exact C ABI.
        Some(unsafe {
            Api {
                set_policy: std::mem::transmute::<*mut c_void, SetPolicy>(set_policy),
                clear: std::mem::transmute::<*mut c_void, Clear>(clear),
            }
        })
    })
    .as_ref()
}

/// How many pages WebKit keeps for instant Back and Forward, and how long.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackForwardCachePolicy {
    /// Pages kept at once across all sessions; 0 disables the cache.
    pub capacity: u32,
    /// How long a page cached after this policy is set stays cached.
    pub lifetime: Duration,
}

impl BackForwardCachePolicy {
    /// No cache: Back reloads the previous page.
    pub const DISABLED: Self = Self {
        capacity: 0,
        lifetime: Duration::ZERO,
    };
}

impl Default for BackForwardCachePolicy {
    fn default() -> Self {
        Self {
            capacity: 2,
            lifetime: Duration::from_secs(600),
        }
    }
}

thread_local! {
    static HOST_POLICY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// The runtime predates the back/forward cache policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackForwardCacheUnsupported;

impl std::fmt::Display for BackForwardCacheUnsupported {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the runtime cannot bound the back/forward cache")
    }
}

impl std::error::Error for BackForwardCacheUnsupported {}

fn apply(policy: BackForwardCachePolicy) -> Result<(), BackForwardCacheUnsupported> {
    let api = api().ok_or(BackForwardCacheUnsupported)?;
    let lifetime = c_uint::try_from(policy.lifetime.as_millis()).unwrap_or(c_uint::MAX);
    // SAFETY: the default context is a live process-global object on the
    // native owner thread; the call evicts down to the new capacity.
    unsafe {
        (api.set_policy)(
            ffi::webkit_web_context_get_default().cast(),
            policy.capacity,
            lifetime,
        )
    };
    Ok(())
}

/// Set the back/forward cache policy for every session on the default context.
///
/// Call on the native owner thread. It replaces the default
/// ([`BackForwardCachePolicy::default`]) and evicts the oldest pages beyond
/// the new capacity. Pages already cached keep their lifetime.
///
/// # Errors
/// [`BackForwardCacheUnsupported`] on a runtime without the policy.
pub fn set_back_forward_cache(
    policy: BackForwardCachePolicy,
) -> Result<(), BackForwardCacheUnsupported> {
    apply(policy)?;
    HOST_POLICY.with(|set| set.set(true));
    Ok(())
}

/// Drop every cached page now, keeping the policy; their suspended processes exit.
///
/// # Errors
/// [`BackForwardCacheUnsupported`] on a runtime without the policy.
pub fn clear_back_forward_cache() -> Result<(), BackForwardCacheUnsupported> {
    let api = api().ok_or(BackForwardCacheUnsupported)?;
    // SAFETY: the default context is live on the native owner thread.
    unsafe { (api.clear)(ffi::webkit_web_context_get_default().cast()) };
    Ok(())
}

/// Apply the default policy before the first session, unless the host chose one.
pub(super) fn ensure_default_policy() {
    if HOST_POLICY.with(|set| set.replace(true)) {
        return;
    }
    // An older runtime keeps WebKit's own thirty-minute lifetime.
    let _ = apply(BackForwardCachePolicy::default());
}
