//! The web process cache: processes WebKit keeps after their last page closes.
//!
//! A cached process keeps its whole heap so that a later page on the same site
//! can reuse it. Sessions start with the cache disabled; a host that prefers
//! faster reopening of recently closed sites sets a bounded policy.
use super::*;
use std::sync::OnceLock;

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
                    c"webkit_web_context_enzui_set_web_process_cache_v1".as_ptr(),
                ),
                dlsym(
                    ptr::null_mut(),
                    c"webkit_web_context_enzui_clear_web_process_cache_v1".as_ptr(),
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

/// How many closed pages' web processes WebKit keeps for reuse, and how long.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WebProcessCachePolicy {
    /// Processes kept at once; 0 disables the cache.
    pub capacity: u32,
    /// How long each kept process lives before it exits.
    pub lifetime: std::time::Duration,
}

impl WebProcessCachePolicy {
    /// No cache: a page's process exits once its last page closes.
    pub const DISABLED: Self = Self {
        capacity: 0,
        lifetime: std::time::Duration::ZERO,
    };
}

impl Default for WebProcessCachePolicy {
    fn default() -> Self {
        Self::DISABLED
    }
}

thread_local! {
    static HOST_POLICY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// The runtime predates the process cache policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessCacheUnsupported;

impl std::fmt::Display for ProcessCacheUnsupported {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the runtime cannot bound the web process cache")
    }
}

impl std::error::Error for ProcessCacheUnsupported {}

fn apply(policy: WebProcessCachePolicy) -> Result<(), ProcessCacheUnsupported> {
    let api = api().ok_or(ProcessCacheUnsupported)?;
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

/// Set the web process cache policy for every session on the default context.
///
/// Call on the native owner thread. It replaces the default
/// ([`WebProcessCachePolicy::DISABLED`]) and evicts cached processes beyond
/// the new capacity.
///
/// # Errors
/// [`ProcessCacheUnsupported`] on a runtime without the policy.
pub fn set_web_process_cache(policy: WebProcessCachePolicy) -> Result<(), ProcessCacheUnsupported> {
    apply(policy)?;
    HOST_POLICY.with(|set| set.set(true));
    Ok(())
}

/// End every cached web process now, keeping the policy.
///
/// # Errors
/// [`ProcessCacheUnsupported`] on a runtime without the policy.
pub fn clear_web_process_cache() -> Result<(), ProcessCacheUnsupported> {
    let api = api().ok_or(ProcessCacheUnsupported)?;
    // SAFETY: the default context is live on the native owner thread.
    unsafe { (api.clear)(ffi::webkit_web_context_get_default().cast()) };
    Ok(())
}

/// Apply the default policy before the first session, unless the host chose one.
pub(super) fn ensure_default_policy() {
    if HOST_POLICY.with(|set| set.replace(true)) {
        return;
    }
    // An older runtime keeps WebKit's own cache; nothing else to do.
    let _ = apply(WebProcessCachePolicy::DISABLED);
}
