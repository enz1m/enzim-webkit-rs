//! Native rule compilation, private persistent caching and scoped installation.
//!
//! Compile or load successfully before installing. An installation owns a manager
//! reference, not a borrow of the session, so ordinary navigation remains possible.
//! Keep it alive across reloads; dropping it removes its filter. Changes affect
//! subsequent requests and do not cancel already admitted network traffic.

use std::cell::RefCell;
use std::collections::HashSet;
use std::ffi::{CStr, CString, c_char, c_void};
use std::marker::PhantomData;
use std::path::{Component, Path, PathBuf};
use std::ptr;
use std::rc::{Rc, Weak};
use std::time::Duration;

use super::WebSession;
use crate::content_filter::{ContentFilterId, FILTER_ID_PREFIX, MAX_CONTENT_FILTER_JSON_BYTES};
use crate::ffi::native_task::{
    NativeTask, NativeTaskCompletion, NativeTaskError, NativeTaskLimiter, take_gerror,
};
use crate::ffi::wpe;

#[repr(C)]
struct FilterStore {
    _private: [u8; 0],
}
#[repr(C)]
struct Filter {
    _private: [u8; 0],
}
#[repr(C)]
struct Manager {
    _private: [u8; 0],
}

type Callback = extern "C" fn(*mut c_void, *mut wpe::GAsyncResult, *mut c_void);
unsafe extern "C" {
    fn webkit_user_content_filter_store_new(path: *const c_char) -> *mut FilterStore;
    fn webkit_user_content_filter_store_save(
        store: *mut FilterStore,
        id: *const c_char,
        source: *mut wpe::GBytes,
        cancellable: *mut c_void,
        callback: Callback,
        data: *mut c_void,
    );
    fn webkit_user_content_filter_store_save_finish(
        store: *mut FilterStore,
        result: *mut wpe::GAsyncResult,
        error: *mut *mut wpe::GError,
    ) -> *mut Filter;
    fn webkit_user_content_filter_store_load(
        store: *mut FilterStore,
        id: *const c_char,
        cancellable: *mut c_void,
        callback: Callback,
        data: *mut c_void,
    );
    fn webkit_user_content_filter_store_load_finish(
        store: *mut FilterStore,
        result: *mut wpe::GAsyncResult,
        error: *mut *mut wpe::GError,
    ) -> *mut Filter;
    fn webkit_user_content_filter_get_identifier(filter: *mut Filter) -> *const c_char;
    fn webkit_user_content_filter_unref(filter: *mut Filter);
    fn webkit_web_view_get_user_content_manager(view: *mut wpe::WebKitWebView) -> *mut Manager;
    fn webkit_user_content_manager_add_filter(manager: *mut Manager, filter: *mut Filter);
    fn webkit_user_content_manager_remove_filter_by_id(manager: *mut Manager, id: *const c_char);
    fn g_compute_checksum_for_data(kind: i32, data: *const u8, length: usize) -> *mut c_char;
}

/// A compiled native filter, ready for installation or use by another native view.
///
/// The boxed native reference is confined to its construction thread. Compilation
/// alone does not enable blocking in any session.
pub struct CompiledContentFilter {
    raw: *mut Filter,
    identifier: ContentFilterId,
    _owner: PhantomData<Rc<()>>,
}
impl CompiledContentFilter {
    /// Identity of the exact source compiled or loaded successfully.
    pub fn identifier(&self) -> &ContentFilterId {
        &self.identifier
    }
}
impl std::fmt::Debug for CompiledContentFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompiledContentFilter")
            .field("identifier", &self.identifier)
            .finish_non_exhaustive()
    }
}
impl Drop for CompiledContentFilter {
    fn drop(&mut self) {
        // SAFETY: this thread-affine owner holds one live boxed filter reference.
        unsafe { webkit_user_content_filter_unref(self.raw) };
    }
}

/// A user-private, rule-only compiled-filter cache.
///
/// The dedicated absolute root and its rule cache are provisioned through the
/// profile filesystem guard with mode 0700, rejecting symlinks and foreign owners.
/// Native compilation can outlive cancellation; at most two operations per store
/// and eight across the owner thread retain native admission until actual callback.
pub struct ContentFilterStore {
    raw: *mut FilterStore,
    cache: PathBuf,
    limiter: NativeTaskLimiter,
    _owner: PhantomData<Rc<()>>,
}

impl ContentFilterStore {
    /// Open or provision a dedicated private rule-cache root.
    ///
    /// # Errors
    /// Refuses non-absolute, symlinked, non-private or invalid paths, a wrong native
    /// thread, or failure to construct the native store. Existing owned directory
    /// permissions may be tightened by the profile filesystem guard. Parent
    /// directories must already exist and must not be symlinks.
    pub fn new(root: impl AsRef<Path>) -> Result<Self, NativeTaskError> {
        crate::ffi::threading::claim().map_err(|_| NativeTaskError::WrongThread)?;
        let root = root.as_ref();
        if !root.is_absolute() || root.components().any(|c| matches!(c, Component::ParentDir)) {
            return Err(NativeTaskError::InvalidInput(
                "filter cache requires an absolute path without parent components",
            ));
        }
        for parent in root.ancestors().skip(1) {
            let metadata = std::fs::symlink_metadata(parent)
                .map_err(|e| NativeTaskError::Native(e.to_string()))?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(NativeTaskError::InvalidInput(
                    "filter cache parent must be a real directory",
                ));
            }
        }
        let provision = crate::profile_fs::begin_persistent_profile_tree(
            root,
            Path::new("content-filter-rules-v1"),
        )
        .map_err(|e| NativeTaskError::Native(e.to_string()))?;
        let cache = provision.paths().cache.clone();
        let path = CString::new(
            cache
                .to_str()
                .ok_or(NativeTaskError::InvalidInput("cache path must be UTF-8"))?,
        )
        .map_err(|_| NativeTaskError::InvalidInput("cache path contains NUL"))?;
        // SAFETY: the validated private path is NUL-terminated and copied by construction.
        let raw = unsafe { webkit_user_content_filter_store_new(path.as_ptr()) };
        if raw.is_null() {
            return Err(NativeTaskError::Native(
                "native filter store unavailable".into(),
            ));
        }
        let _ = provision.commit();
        Ok(Self {
            raw,
            cache,
            limiter: NativeTaskLimiter::new(2),
            _owner: PhantomData,
        })
    }

    /// The private directory containing compiled rules and their source, never page history.
    pub fn cache_path(&self) -> &Path {
        &self.cache
    }

    /// Count native operations still holding admission, including cancelled host tasks.
    pub fn inflight(&self) -> usize {
        self.limiter.inflight()
    }

    /// Derive the stable cache identity without compiling or installing the source.
    ///
    /// # Errors
    /// Refuses source beyond 16 MiB, literal NUL bytes or a checksum allocation failure.
    pub fn identifier_for(json: &str) -> Result<ContentFilterId, NativeTaskError> {
        if json.len() > MAX_CONTENT_FILTER_JSON_BYTES || json.as_bytes().contains(&0) {
            return Err(NativeTaskError::InvalidInput(
                "filter JSON exceeds 16 MiB or contains NUL",
            ));
        }
        // SAFETY: G_CHECKSUM_SHA256 is 2; the immutable bytes remain valid through hashing.
        let digest = unsafe { g_compute_checksum_for_data(2, json.as_ptr(), json.len()) };
        if digest.is_null() {
            return Err(NativeTaskError::Native(
                "filter checksum unavailable".into(),
            ));
        }
        // SAFETY: GLib transfers one owned, NUL-terminated checksum string.
        let value = unsafe { CStr::from_ptr(digest).to_string_lossy().into_owned() };
        // SAFETY: GLib allocated the checksum and this call owns it.
        unsafe { wpe::g_free(digest.cast()) };
        ContentFilterId::parse(&format!("{FILTER_ID_PREFIX}{value}"))
            .map_err(|_| NativeTaskError::Native("invalid native checksum".into()))
    }

    /// Compile bounded UTF-8 JSON into a content-addressed cache entry.
    ///
    /// The task succeeds only after native validation/compilation. A cancelled or
    /// expired compilation may still finish writing its rule-only cache entry; it
    /// never changes an installed filter. Keep dispatching the owner context.
    ///
    /// # Errors
    /// Returns source-validation or native-admission errors before submission.
    pub fn compile(
        &self,
        json: &str,
        timeout: Duration,
    ) -> Result<NativeTask<CompiledContentFilter>, NativeTaskError> {
        let id = Self::identifier_for(json)?;
        let native_id = CString::new(id.as_str()).expect("validated filter identity");
        let (task, token) = NativeTask::start(&self.limiter, timeout)?;
        // SAFETY: GLib copies the bounded JSON bytes and transfers one reference.
        let bytes = unsafe { wpe::g_bytes_new(json.as_ptr().cast(), json.len()) };
        if bytes.is_null() {
            return Err(NativeTaskError::Native(
                "filter source allocation failed".into(),
            ));
        }
        let cancellable = token.cancellable();
        let request = Box::new(CompileRequest {
            token,
            id,
            load: false,
        });
        // SAFETY: the store is live; native code retains its task/source and owns heap callback data.
        unsafe {
            webkit_user_content_filter_store_save(
                self.raw,
                native_id.as_ptr(),
                bytes,
                cancellable,
                compiled,
                Box::into_raw(request).cast(),
            );
            wpe::g_bytes_unref(bytes);
        }
        Ok(task)
    }

    /// Load one previously compiled, validated cache identity.
    ///
    /// # Errors
    /// Returns admission errors before submission; missing/incompatible entries
    /// become an observable task error and never affect an installed filter.
    pub fn load(
        &self,
        id: &ContentFilterId,
        timeout: Duration,
    ) -> Result<NativeTask<CompiledContentFilter>, NativeTaskError> {
        let native_id = CString::new(id.as_str()).expect("validated filter identity");
        let (task, token) = NativeTask::start(&self.limiter, timeout)?;
        let cancellable = token.cancellable();
        let request = Box::new(CompileRequest {
            token,
            id: id.clone(),
            load: true,
        });
        // SAFETY: the live native store retains itself for the asynchronous load and callback.
        unsafe {
            webkit_user_content_filter_store_load(
                self.raw,
                native_id.as_ptr(),
                cancellable,
                compiled,
                Box::into_raw(request).cast(),
            )
        };
        Ok(task)
    }
}
impl Drop for ContentFilterStore {
    fn drop(&mut self) {
        // SAFETY: this owner holds one native store GObject reference; GTasks retain their own.
        unsafe { wpe::g_object_unref(self.raw.cast()) };
    }
}
struct CompileRequest {
    token: NativeTaskCompletion<CompiledContentFilter>,
    id: ContentFilterId,
    load: bool,
}
extern "C" fn compiled(store: *mut c_void, result: *mut wpe::GAsyncResult, data: *mut c_void) {
    // SAFETY: one native completion consumes exactly the request box submitted above.
    let request = unsafe { Box::from_raw(data.cast::<CompileRequest>()) };
    let mut error = ptr::null_mut();
    // SAFETY: the callback source/result belongs to this store's save or load operation.
    let raw = unsafe {
        if request.load {
            webkit_user_content_filter_store_load_finish(store.cast(), result, &mut error)
        } else {
            webkit_user_content_filter_store_save_finish(store.cast(), result, &mut error)
        }
    };
    let outcome = if !error.is_null() {
        if !raw.is_null() {
            // SAFETY: an unexpected success still returns a reference to release.
            unsafe { webkit_user_content_filter_unref(raw) };
        }
        // SAFETY: finish transferred this one error allocation.
        Err(unsafe { take_gerror(error) })
    } else if raw.is_null() {
        Err(NativeTaskError::Native(
            "native compilation returned no filter".into(),
        ))
    } else {
        // SAFETY: native identity is a borrowed, NUL-terminated string while the filter is live.
        let pointer = unsafe { webkit_user_content_filter_get_identifier(raw) };
        let expected = request.id.as_str().as_bytes();
        let matches = !pointer.is_null()
            && expected.iter().enumerate().all(|(i, &byte)| {
                // SAFETY: native filter names terminate at their allocation's NUL; stop on mismatch.
                unsafe { pointer.add(i).read() as u8 == byte }
            });
        // SAFETY: the matched prefix has no NUL, so the next byte is still in the native string.
        let matches = matches && unsafe { pointer.add(expected.len()).read() == 0 };
        if matches {
            Ok(CompiledContentFilter {
                raw,
                identifier: request.id,
                _owner: PhantomData,
            })
        } else {
            // SAFETY: finish transferred one owned filter reference, which is not published.
            unsafe { webkit_user_content_filter_unref(raw) };
            Err(NativeTaskError::Native(
                "native filter identity mismatch".into(),
            ))
        }
    };
    request.token.complete(outcome);
}

thread_local! { static INSTALLED: RefCell<HashSet<usize>> = RefCell::new(HashSet::new()); }

/// Exclusive ownership of a native manager's controlled filter bundle.
///
/// This lease owns a manager reference and can outlive its view. Drop removes only
/// this bundle's current filters; stale leases cannot remove a newer replacement.
/// Related views sharing the manager share the same installation. The native
/// registration is queued before later loads; no past requests are revoked.
/// Reconstructing a session retires this lease; install a new lease on its
/// replacement before loading a site. Cleanup still owns the old manager.
pub struct ContentFilterInstallation {
    manager: *mut Manager,
    view: Weak<crate::ffi::page::PageHub>,
    ids: Vec<ContentFilterId>,
    _owner: PhantomData<Rc<()>>,
}
impl ContentFilterInstallation {
    /// The identity of a single-filter bundle, absent for multiple filters or a retired view.
    pub fn identifier(&self) -> Option<&ContentFilterId> {
        let ids = self.identifiers();
        if ids.len() == 1 { ids.first() } else { None }
    }

    /// Registered identities, absent after removal or logical view retirement.
    pub fn identifiers(&self) -> &[ContentFilterId] {
        if self.view.upgrade().is_some() {
            &self.ids
        } else {
            &[]
        }
    }

    /// Replace the bundle with one compiled filter.
    ///
    /// # Errors
    /// Refuses a retired logical view; old-manager cleanup remains available.
    pub fn replace(&mut self, filter: &CompiledContentFilter) -> Result<(), NativeTaskError> {
        self.replace_all(&[filter])
    }

    /// Replace up to eight independently compiled filters without dropping unchanged registrations.
    /// New identities are registered before obsolete identities are removed; this does not revoke past requests.
    ///
    /// # Errors
    /// Refuses a retired view, an empty bundle, duplicate identities or more than eight filters before mutation.
    pub fn replace_all(
        &mut self,
        filters: &[&CompiledContentFilter],
    ) -> Result<(), NativeTaskError> {
        if self.view.upgrade().is_none() {
            return Err(NativeTaskError::InvalidInput(
                "filter installation belongs to a retired view",
            ));
        }
        if filters.is_empty() || filters.len() > 8 {
            return Err(NativeTaskError::InvalidInput(
                "a filter bundle requires one to eight filters",
            ));
        }
        let mut next = Vec::with_capacity(filters.len());
        for filter in filters {
            if next.contains(filter.identifier()) {
                return Err(NativeTaskError::InvalidInput(
                    "duplicate content filter identity",
                ));
            }
            next.push(filter.identifier().clone());
        }
        for filter in filters {
            if !self.ids.contains(filter.identifier()) {
                // SAFETY: both native objects remain live on their shared native owner thread.
                unsafe { webkit_user_content_manager_add_filter(self.manager, filter.raw) };
            }
        }
        for old in self.ids.iter().filter(|id| !next.contains(id)) {
            let id = CString::new(old.as_str()).expect("validated filter identity");
            // SAFETY: the retained manager owns this registration and borrows the ID only during dispatch.
            unsafe { webkit_user_content_manager_remove_filter_by_id(self.manager, id.as_ptr()) };
        }
        self.ids = next;
        Ok(())
    }

    /// Remove this bundle from future requests; already admitted traffic continues.
    pub fn remove(&mut self) {
        for old in self.ids.drain(..) {
            let id = CString::new(old.as_str()).expect("validated filter identity");
            // SAFETY: the lease retains this manager through removal on its native owner thread.
            unsafe { webkit_user_content_manager_remove_filter_by_id(self.manager, id.as_ptr()) };
        }
    }
}
impl Drop for ContentFilterInstallation {
    fn drop(&mut self) {
        self.remove();
        INSTALLED.with(|installed| {
            installed.borrow_mut().remove(&(self.manager as usize));
        });
        // SAFETY: this lease owns the one manager reference acquired at installation.
        unsafe { wpe::g_object_unref(self.manager.cast()) };
    }
}
impl WebSession {
    /// Install a compiled content filter before loading untrusted page resources.
    ///
    /// The lease does not borrow the session. Keep it across navigation and reload,
    /// and drop or remove it to stop filtering future requests. Only one owned slot
    /// is permitted per native manager, so overlapping leases cannot undo each other.
    /// This leaves destination screening, cookies and profiles unchanged.
    ///
    /// # Errors
    /// Refuses a missing manager or an already-owned manager slot.
    pub fn install_content_filter(
        &self,
        filter: &CompiledContentFilter,
    ) -> Result<ContentFilterInstallation, NativeTaskError> {
        self.install_content_filters(&[filter])
    }

    /// Install one to eight compiled filters under the manager's single exclusive lease.
    /// Drop removes the entire bundle; rule exceptions remain local to each compiled filter.
    ///
    /// # Errors
    /// Refuses an absent manager, an already-owned manager slot or an invalid bundle.
    pub fn install_content_filters(
        &self,
        filters: &[&CompiledContentFilter],
    ) -> Result<ContentFilterInstallation, NativeTaskError> {
        if filters.is_empty() || filters.len() > 8 {
            return Err(NativeTaskError::InvalidInput(
                "a filter bundle requires one to eight filters",
            ));
        }
        for (i, filter) in filters.iter().enumerate() {
            if filters[..i]
                .iter()
                .any(|old| old.identifier() == filter.identifier())
            {
                return Err(NativeTaskError::InvalidInput(
                    "duplicate content filter identity",
                ));
            }
        }
        // SAFETY: this owner-thread session retains the native view through synchronous lookup.
        let manager = unsafe { webkit_web_view_get_user_content_manager(self.web_view) };
        if manager.is_null() {
            return Err(NativeTaskError::Native(
                "native content manager unavailable".into(),
            ));
        }
        if !INSTALLED.with(|installed| installed.borrow_mut().insert(manager as usize)) {
            return Err(NativeTaskError::Busy);
        }
        // SAFETY: this new manager reference belongs to the lease until its owner-thread Drop.
        unsafe { wpe::g_object_ref(manager.cast()) };
        let mut slot = ContentFilterInstallation {
            manager,
            view: Rc::downgrade(&self.page_hub),
            ids: Vec::new(),
            _owner: PhantomData,
        };
        slot.replace_all(filters)?;
        Ok(slot)
    }
}
