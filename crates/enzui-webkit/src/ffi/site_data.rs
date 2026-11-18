//! Owner-thread native inventory and selective profile cleanup.

use std::ffi::{CStr, c_char, c_void};
use std::ptr;
use std::time::Duration;

use super::native_task::{NativeTask, NativeTaskCompletion, NativeTaskError, NativeTaskLimiter};
use super::page::sys::webkit_network_session_get_website_data_manager;
use super::profile::NetworkSession;
use super::wpe;
use crate::page::WebsiteData;
use crate::site_data::{
    CookieKey, CookieMetadata, CookieSameSite, SiteDataCapabilities, SiteDataError,
    WebsiteDataRecord, WebsiteDataSelection, validate_group_selection,
};

mod origins;

pub(crate) fn capabilities() -> SiteDataCapabilities {
    origins::capabilities()
}

const DEADLINE: Duration = Duration::from_secs(15);
const MAX_RECORDS: usize = 16_384;
const MAX_STRING: usize = 8192;
const MAX_METADATA: usize = 16 * 1024 * 1024;

thread_local! {
    static LIMITER: NativeTaskLimiter = NativeTaskLimiter::new(4);
}

enum Reply {
    Cookies(Vec<CookieMetadata>),
    Records(Vec<WebsiteDataRecord>),
    Removed,
}

/// A bounded native operation, polled and cancelled on WPE's owner thread.
///
/// Drive the native main context using the normal runtime event integration.
/// `take_result` and `is_finished` observe the deadline; neither blocks. Dropping
/// the handle requests cancellation. Callback state and native references remain
/// alive until the real native callback returns, even after timeout or drop.
/// Cancellation or timeout cannot roll back a deletion already committed by the
/// native backend. The fetch-to-delete transition checks the task is still active.
pub struct SiteDataTask<T> {
    native: NativeTask<Result<Reply, SiteDataError>>,
    extract: fn(Reply) -> Result<T, SiteDataError>,
}

impl<T> SiteDataTask<T> {
    /// Take the result once, if completion, cancellation or timeout has occurred.
    pub fn take_result(&self) -> Option<Result<T, SiteDataError>> {
        self.native.take_result().map(|result| {
            result
                .map_err(map_task_error)
                .and_then(|value| value)
                .and_then(self.extract)
        })
    }

    /// Whether a terminal result is available or has already been taken.
    pub fn is_finished(&self) -> bool {
        self.native.is_finished()
    }

    /// Request cancellation without freeing callback-reachable native state.
    /// An already committed native deletion cannot be undone.
    pub fn cancel(&self) {
        self.native.cancel();
    }
}

fn map_task_error(error: NativeTaskError) -> SiteDataError {
    match error {
        NativeTaskError::Cancelled => SiteDataError::Cancelled,
        NativeTaskError::TimedOut => SiteDataError::TimedOut,
        NativeTaskError::Busy => SiteDataError::Busy,
        NativeTaskError::WrongThread => SiteDataError::WrongThread,
        NativeTaskError::InvalidInput(message) => SiteDataError::InvalidInput(message),
        NativeTaskError::Native(message) => SiteDataError::Native(message),
    }
}

fn task<T>(
    extract: fn(Reply) -> Result<T, SiteDataError>,
) -> Result<(SiteDataTask<T>, Completion), SiteDataError> {
    let (native, completion) = LIMITER
        .with(|limiter| NativeTask::start(limiter, DEADLINE))
        .map_err(map_task_error)?;
    Ok((SiteDataTask { native, extract }, completion))
}

type Completion = NativeTaskCompletion<Result<Reply, SiteDataError>>;

struct Owner(*mut wpe::WebKitNetworkSession);
impl Owner {
    fn retain(session: *mut wpe::WebKitNetworkSession) -> Self {
        // SAFETY: callers borrow a live native session on its owner thread.
        unsafe { wpe::g_object_ref(session.cast()) };
        Self(session)
    }
}
impl Drop for Owner {
    fn drop(&mut self) {
        // SAFETY: this operation owns the reference until actual native completion.
        unsafe { wpe::g_object_unref(self.0.cast()) };
    }
}

enum Action {
    Cookies,
    DeleteCookie(CookieKey),
    Records(u32),
    RemoveGroup { name: String, types: u32 },
}

struct Request {
    completion: Completion,
    _owner: Owner,
    action: Action,
    retained_cookie: *mut wpe::SoupCookie,
    retained_records: *mut wpe::GList,
}

struct Completed {
    completion: Completion,
    _owner: Owner,
    result: Result<Reply, SiteDataError>,
}

extern "C" fn complete_after_native_task(data: *mut c_void) -> wpe::GBoolean {
    // SAFETY: the one-shot source owns the boxed completion after native task teardown.
    let completed = unsafe { Box::from_raw(data.cast::<Completed>()) };
    let Completed {
        completion,
        _owner,
        result,
    } = *completed;
    completion.complete(Ok(result));
    drop(_owner);
    wpe::G_FALSE
}

impl Request {
    fn finish(self, result: Result<Reply, SiteDataError>) {
        let Self {
            completion,
            _owner,
            retained_cookie,
            retained_records,
            ..
        } = self;
        // SAFETY: these are transfer-full results retained across the second async call.
        unsafe {
            if !retained_cookie.is_null() {
                wpe::soup_cookie_free(retained_cookie);
            }
            release_records(retained_records);
        }
        let completed = Box::new(Completed {
            completion,
            _owner,
            result,
        });
        // Releasing the last session during GTask's callback can invalidate its later teardown.
        // SAFETY: this one-shot source owns the completion box until its next dispatch.
        unsafe {
            wpe::g_timeout_add(
                0,
                complete_after_native_task,
                Box::into_raw(completed).cast(),
            )
        };
    }
}

impl NetworkSession {
    /// Native inventory precision and the kinds supported by exact-origin cleanup.
    pub fn site_data_capabilities(&self) -> SiteDataCapabilities {
        origins::capabilities()
    }

    /// Enumerate owned cookie metadata for this profile, excluding cookie values.
    pub fn cookie_inventory(&self) -> Result<SiteDataTask<Vec<CookieMetadata>>, SiteDataError> {
        start_cookies(self.as_ptr(), Action::Cookies)
    }

    /// Remove one exact name/domain/path identity from this profile, of any age.
    ///
    /// The live native cookie is fetched before deletion. Other names, paths and
    /// domains remain untouched. Native creation-date filtering is unavailable.
    pub fn delete_cookie(&self, key: &CookieKey) -> Result<SiteDataTask<()>, SiteDataError> {
        start_delete_cookie(self.as_ptr(), key)
    }

    /// Fetch native display groups and estimated sizes for the requested kinds.
    /// Group names may represent multiple origins and are not origin authority.
    pub fn website_data_inventory(
        &self,
        kinds: WebsiteData,
    ) -> Result<SiteDataTask<Vec<WebsiteDataRecord>>, SiteDataError> {
        start_records(self.as_ptr(), kinds)
    }

    /// Remove selected kinds from a native group or supported exact origin, across all ages.
    /// Domain-scoped kinds cannot be removed by exact origin.
    pub fn remove_website_data(
        &self,
        selection: &WebsiteDataSelection,
        kinds: WebsiteData,
    ) -> Result<SiteDataTask<()>, SiteDataError> {
        start_remove_group(self.as_ptr(), selection, kinds)
    }
}

fn start_cookies(
    session: *mut wpe::WebKitNetworkSession,
    action: Action,
) -> Result<SiteDataTask<Vec<CookieMetadata>>, SiteDataError> {
    let (task, completion) = task(|reply| match reply {
        Reply::Cookies(value) => Ok(value),
        _ => Err(SiteDataError::Native(
            "unexpected cookie inventory result".into(),
        )),
    })?;
    launch_cookie_fetch(session, action, completion);
    Ok(task)
}

pub(super) fn inventory_cookies(
    session: *mut wpe::WebKitNetworkSession,
) -> Result<SiteDataTask<Vec<CookieMetadata>>, SiteDataError> {
    start_cookies(session, Action::Cookies)
}

pub(super) fn start_delete_cookie(
    session: *mut wpe::WebKitNetworkSession,
    key: &CookieKey,
) -> Result<SiteDataTask<()>, SiteDataError> {
    if key.name.len() > MAX_STRING
        || key.domain.is_empty()
        || key.domain.len() > MAX_STRING
        || key.path.is_empty()
        || key.path.len() > MAX_STRING
        || [&key.name, &key.domain, &key.path]
            .iter()
            .any(|value| value.contains('\0'))
    {
        return Err(SiteDataError::InvalidInput("invalid cookie identity"));
    }
    let (task, completion) = task(removed)?;
    launch_cookie_fetch(session, Action::DeleteCookie(key.clone()), completion);
    Ok(task)
}

fn removed(reply: Reply) -> Result<(), SiteDataError> {
    match reply {
        Reply::Removed => Ok(()),
        _ => Err(SiteDataError::Native("unexpected cleanup result".into())),
    }
}

fn launch_cookie_fetch(
    session: *mut wpe::WebKitNetworkSession,
    action: Action,
    completion: Completion,
) {
    let request = Box::new(Request {
        completion,
        _owner: Owner::retain(session),
        action,
        retained_cookie: ptr::null_mut(),
        retained_records: ptr::null_mut(),
    });
    // SAFETY: session remains retained until callback; callback consumes this box once.
    unsafe {
        let manager = wpe::webkit_network_session_get_cookie_manager(session);
        webkit_cookie_manager_get_all_cookies(
            manager,
            request.completion.cancellable(),
            cookies_ready,
            Box::into_raw(request).cast(),
        );
    }
}

extern "C" fn cookies_ready(
    source: *mut c_void,
    result: *mut wpe::GAsyncResult,
    data: *mut c_void,
) {
    // SAFETY: this callback owns exactly the box supplied to get_all_cookies.
    let mut request = unsafe { Box::from_raw(data.cast::<Request>()) };
    let mut error = ptr::null_mut();
    // SAFETY: source/result are the matching native cookie-manager operation.
    let list =
        unsafe { webkit_cookie_manager_get_all_cookies_finish(source.cast(), result, &mut error) };
    if let Some(error) = native_error(error) {
        // SAFETY: finish results are transfer-full even when an error accompanies them.
        unsafe { release_cookies(list) };
        request.finish(Err(error));
        return;
    }
    let mut cookies = Vec::new();
    let mut selected = ptr::null_mut();
    let mut selection_count = 0;
    let mut bytes = 0;
    let mut outcome = Ok(());
    let mut node = list;
    while !node.is_null() {
        // SAFETY: each node and cookie belong to the live transfer-full list.
        let cookie = unsafe { (*node).data.cast::<wpe::SoupCookie>() };
        if !cookie.is_null() && outcome.is_ok() {
            let metadata = cookie_metadata(cookie);
            match metadata {
                Ok(value) => {
                    bytes += value.key.name.len() + value.key.domain.len() + value.key.path.len();
                    if cookies.len() >= MAX_RECORDS || bytes > MAX_METADATA {
                        outcome = Err(SiteDataError::InventoryTooLarge);
                    } else {
                        if matches!(&request.action, Action::DeleteCookie(key) if key == &value.key)
                        {
                            selected = cookie;
                            selection_count += 1;
                        }
                        cookies.push(value);
                    }
                }
                Err(error) => outcome = Err(error),
            }
        }
        // SAFETY: node is a live list node until release below.
        node = unsafe { (*node).next };
    }
    if outcome.is_ok() && matches!(request.action, Action::DeleteCookie(_)) {
        outcome = match selection_count {
            0 => Err(SiteDataError::NotFound),
            1 => Ok(()),
            _ => Err(SiteDataError::UnsupportedScope(
                "native cookies have ambiguous identity",
            )),
        };
        if outcome.is_ok() {
            // SAFETY: selected is a cookie in the owned list; copy retains its native identity.
            request.retained_cookie = unsafe { soup_cookie_copy(selected) };
        }
    }
    // SAFETY: the copy, if needed, survives independently; release every original cookie.
    unsafe { release_cookies(list) };
    if let Err(error) = outcome {
        request.finish(Err(error));
    } else if matches!(request.action, Action::Cookies) {
        cookies.sort_by(|a, b| a.key.cmp(&b.key));
        request.finish(Ok(Reply::Cookies(cookies)));
    } else if request.retained_cookie.is_null() {
        request.finish(Err(SiteDataError::Native(
            "native cookie copy failed".into(),
        )));
    } else if !request.completion.is_active() {
        request.finish(Err(SiteDataError::Cancelled));
    } else {
        // SAFETY: request retains the selected cookie, session and cancellable through delete.
        unsafe {
            webkit_cookie_manager_delete_cookie(
                source.cast(),
                request.retained_cookie,
                request.completion.cancellable(),
                cookie_deleted,
                Box::into_raw(request).cast(),
            )
        };
    }
}

extern "C" fn cookie_deleted(
    source: *mut c_void,
    result: *mut wpe::GAsyncResult,
    data: *mut c_void,
) {
    // SAFETY: this callback receives its uniquely owned request box.
    let request = unsafe { Box::from_raw(data.cast::<Request>()) };
    let mut error = ptr::null_mut();
    // SAFETY: finish matches delete_cookie and its native manager/result.
    let ok =
        unsafe { webkit_cookie_manager_delete_cookie_finish(source.cast(), result, &mut error) };
    let result = native_error(error).map_or_else(
        || {
            if ok != 0 {
                Ok(Reply::Removed)
            } else {
                Err(SiteDataError::Native(
                    "native cookie deletion failed".into(),
                ))
            }
        },
        Err,
    );
    request.finish(result);
}

pub(super) fn start_records(
    session: *mut wpe::WebKitNetworkSession,
    kinds: WebsiteData,
) -> Result<SiteDataTask<Vec<WebsiteDataRecord>>, SiteDataError> {
    let (task, completion) = task(|reply| match reply {
        Reply::Records(value) => Ok(value),
        _ => Err(SiteDataError::Native(
            "unexpected website-data inventory result".into(),
        )),
    })?;
    launch_records(
        session,
        Action::Records(kinds.bits()),
        kinds.bits(),
        completion,
    );
    Ok(task)
}

pub(super) fn start_remove_group(
    session: *mut wpe::WebKitNetworkSession,
    selection: &WebsiteDataSelection,
    kinds: WebsiteData,
) -> Result<SiteDataTask<()>, SiteDataError> {
    if let WebsiteDataSelection::ExactOrigin(origin) = selection {
        return origins::remove(session, origin, kinds);
    }
    let name = validate_group_selection(selection, kinds)?.to_owned();
    let (task, completion) = task(removed)?;
    launch_records(
        session,
        Action::RemoveGroup {
            name,
            types: kinds.bits(),
        },
        kinds.bits(),
        completion,
    );
    Ok(task)
}

fn launch_records(
    session: *mut wpe::WebKitNetworkSession,
    action: Action,
    types: u32,
    completion: Completion,
) {
    let request = Box::new(Request {
        completion,
        _owner: Owner::retain(session),
        action,
        retained_cookie: ptr::null_mut(),
        retained_records: ptr::null_mut(),
    });
    // SAFETY: the request retains the native session until matching fetch completion.
    unsafe {
        webkit_website_data_manager_fetch(
            webkit_network_session_get_website_data_manager(session).cast(),
            types,
            request.completion.cancellable(),
            records_ready,
            Box::into_raw(request).cast(),
        )
    };
}

extern "C" fn records_ready(
    source: *mut c_void,
    result: *mut wpe::GAsyncResult,
    data: *mut c_void,
) {
    // SAFETY: this callback receives the unique heap state passed to fetch.
    let mut request = unsafe { Box::from_raw(data.cast::<Request>()) };
    let mut error = ptr::null_mut();
    // SAFETY: source/result belong to the fetch operation.
    let list = unsafe { webkit_website_data_manager_fetch_finish(source, result, &mut error) };
    if let Some(error) = native_error(error) {
        // SAFETY: native transferred this record list to this code.
        unsafe { release_records(list) };
        request.finish(Err(error));
        return;
    }
    let types = match &request.action {
        Action::Records(types) | Action::RemoveGroup { types, .. } => *types,
        _ => 0,
    };
    let mut records = Vec::new();
    let mut bytes = 0;
    let mut outcome = Ok(());
    let mut node = list;
    while !node.is_null() {
        // SAFETY: list nodes and their records remain owned until release below.
        let record = unsafe { (*node).data };
        if !record.is_null() && outcome.is_ok() {
            // SAFETY: native record accessors borrow the live owned record.
            match unsafe { read_string(webkit_website_data_get_name(record)) } {
                Ok(name) => {
                    bytes += name.len();
                    if records.len() >= MAX_RECORDS || bytes > MAX_METADATA {
                        outcome = Err(SiteDataError::InventoryTooLarge);
                    } else {
                        // SAFETY: accessors borrow the live native record.
                        let (present, size) = unsafe {
                            (
                                webkit_website_data_get_types(record),
                                webkit_website_data_get_size(record, types),
                            )
                        };
                        if matches!(&request.action, Action::RemoveGroup { name: wanted, .. } if wanted == &name)
                        {
                            // SAFETY: the retained list owns one extra native record reference.
                            unsafe {
                                request.retained_records = g_list_prepend(
                                    request.retained_records,
                                    webkit_website_data_ref(record),
                                )
                            };
                        }
                        let origins = match origins::read_origins(record) {
                            Ok(origins) => origins,
                            Err(error) => {
                                outcome = Err(error);
                                break;
                            }
                        };
                        bytes += origins
                            .as_ref()
                            .map_or(0, |values| values.iter().map(String::len).sum::<usize>());
                        if bytes > MAX_METADATA {
                            outcome = Err(SiteDataError::InventoryTooLarge);
                            break;
                        }
                        records.push(WebsiteDataRecord {
                            group_name: name,
                            types: present,
                            size_bytes: size,
                            origins,
                        });
                    }
                }
                Err(error) => outcome = Err(error),
            }
        }
        // SAFETY: node remains live until the list release.
        node = unsafe { (*node).next };
    }
    // SAFETY: selected records retain independent references.
    unsafe { release_records(list) };
    if let Err(error) = outcome {
        request.finish(Err(error));
    } else if matches!(request.action, Action::Records(_)) {
        records.sort_by(|a, b| a.group_name.cmp(&b.group_name).then(a.types.cmp(&b.types)));
        request.finish(Ok(Reply::Records(records)));
    } else if request.retained_records.is_null() {
        request.finish(Err(SiteDataError::NotFound));
    } else if !request.completion.is_active() {
        request.finish(Err(SiteDataError::Cancelled));
    } else {
        // SAFETY: records, cancellable and owner remain retained through remove completion.
        unsafe {
            webkit_website_data_manager_remove(
                source,
                types,
                request.retained_records,
                request.completion.cancellable(),
                records_removed,
                Box::into_raw(request).cast(),
            )
        };
    }
}

extern "C" fn records_removed(
    source: *mut c_void,
    result: *mut wpe::GAsyncResult,
    data: *mut c_void,
) {
    // SAFETY: the remove operation owns this unique callback box.
    let request = unsafe { Box::from_raw(data.cast::<Request>()) };
    let mut error = ptr::null_mut();
    // SAFETY: finish matches the website-data remove operation.
    let ok = unsafe { webkit_website_data_manager_remove_finish(source, result, &mut error) };
    let outcome = native_error(error).map_or_else(
        || {
            if ok != 0 {
                Ok(Reply::Removed)
            } else {
                Err(SiteDataError::Native(
                    "native website-data removal failed".into(),
                ))
            }
        },
        Err,
    );
    request.finish(outcome);
}

fn native_error(error: *mut wpe::GError) -> Option<SiteDataError> {
    if error.is_null() {
        return None;
    }
    // SAFETY: finish transferred this GError; the shared helper consumes it once.
    Some(map_task_error(unsafe {
        super::native_task::take_gerror(error)
    }))
}

fn cookie_metadata(cookie: *mut wpe::SoupCookie) -> Result<CookieMetadata, SiteDataError> {
    // SAFETY: all native getters borrow the live cookie for this synchronous copy.
    unsafe {
        let expiry = soup_cookie_get_expires(cookie);
        let same_site = match soup_cookie_get_same_site_policy(cookie) {
            0 => CookieSameSite::None,
            1 => CookieSameSite::Lax,
            2 => CookieSameSite::Strict,
            value => CookieSameSite::Unknown(value),
        };
        Ok(CookieMetadata {
            key: CookieKey {
                name: read_string(wpe::soup_cookie_get_name(cookie))?,
                domain: read_string(soup_cookie_get_domain(cookie))?,
                path: read_string(soup_cookie_get_path(cookie))?,
            },
            secure: soup_cookie_get_secure(cookie) != 0,
            http_only: soup_cookie_get_http_only(cookie) != 0,
            same_site,
            expires_unix_seconds: (!expiry.is_null()).then(|| g_date_time_to_unix(expiry)),
        })
    }
}

unsafe fn read_string(value: *const c_char) -> Result<String, SiteDataError> {
    if value.is_null() {
        return Err(SiteDataError::Native(
            "native metadata contains a null string".into(),
        ));
    }
    // SAFETY: native accessors guarantee NUL-terminated borrowed strings.
    let bytes = unsafe { CStr::from_ptr(value) }.to_bytes();
    if bytes.len() > MAX_STRING {
        return Err(SiteDataError::InventoryTooLarge);
    }
    String::from_utf8(bytes.to_vec())
        .map_err(|_| SiteDataError::Native("native metadata is not valid UTF-8".into()))
}

unsafe fn release_cookies(list: *mut wpe::GList) {
    let mut node = list;
    while !node.is_null() {
        // SAFETY: this is a transfer-full cookie list owned by this operation.
        unsafe {
            if !(*node).data.is_null() {
                wpe::soup_cookie_free((*node).data.cast());
            }
            node = (*node).next;
        }
    }
    // SAFETY: every list element has been released above.
    unsafe { wpe::g_list_free(list) };
}

unsafe fn release_records(list: *mut wpe::GList) {
    let mut node = list;
    while !node.is_null() {
        // SAFETY: this operation owns all record references and list nodes.
        unsafe {
            if !(*node).data.is_null() {
                webkit_website_data_unref((*node).data);
            }
            node = (*node).next;
        }
    }
    // SAFETY: the elements were released separately above.
    unsafe { wpe::g_list_free(list) };
}

type Callback = extern "C" fn(*mut c_void, *mut wpe::GAsyncResult, *mut c_void);

unsafe extern "C" {
    fn webkit_cookie_manager_get_all_cookies(
        manager: *mut wpe::WebKitCookieManager,
        cancellable: *mut c_void,
        callback: Callback,
        data: *mut c_void,
    );
    fn webkit_cookie_manager_get_all_cookies_finish(
        manager: *mut wpe::WebKitCookieManager,
        result: *mut wpe::GAsyncResult,
        error: *mut *mut wpe::GError,
    ) -> *mut wpe::GList;
    fn webkit_cookie_manager_delete_cookie(
        manager: *mut wpe::WebKitCookieManager,
        cookie: *mut wpe::SoupCookie,
        cancellable: *mut c_void,
        callback: Callback,
        data: *mut c_void,
    );
    fn webkit_cookie_manager_delete_cookie_finish(
        manager: *mut wpe::WebKitCookieManager,
        result: *mut wpe::GAsyncResult,
        error: *mut *mut wpe::GError,
    ) -> i32;
    fn soup_cookie_copy(cookie: *mut wpe::SoupCookie) -> *mut wpe::SoupCookie;
    fn soup_cookie_get_domain(cookie: *mut wpe::SoupCookie) -> *const c_char;
    fn soup_cookie_get_path(cookie: *mut wpe::SoupCookie) -> *const c_char;
    fn soup_cookie_get_secure(cookie: *mut wpe::SoupCookie) -> i32;
    fn soup_cookie_get_http_only(cookie: *mut wpe::SoupCookie) -> i32;
    fn soup_cookie_get_same_site_policy(cookie: *mut wpe::SoupCookie) -> i32;
    fn soup_cookie_get_expires(cookie: *mut wpe::SoupCookie) -> *mut c_void;
    fn g_date_time_to_unix(date: *mut c_void) -> i64;
    fn webkit_website_data_manager_fetch(
        manager: *mut c_void,
        types: u32,
        cancellable: *mut c_void,
        callback: Callback,
        data: *mut c_void,
    );
    fn webkit_website_data_manager_fetch_finish(
        manager: *mut c_void,
        result: *mut wpe::GAsyncResult,
        error: *mut *mut wpe::GError,
    ) -> *mut wpe::GList;
    fn webkit_website_data_manager_remove(
        manager: *mut c_void,
        types: u32,
        records: *mut wpe::GList,
        cancellable: *mut c_void,
        callback: Callback,
        data: *mut c_void,
    );
    fn webkit_website_data_manager_remove_finish(
        manager: *mut c_void,
        result: *mut wpe::GAsyncResult,
        error: *mut *mut wpe::GError,
    ) -> i32;
    fn webkit_website_data_get_name(record: *mut c_void) -> *const c_char;
    fn webkit_website_data_get_types(record: *mut c_void) -> u32;
    fn webkit_website_data_get_size(record: *mut c_void, types: u32) -> u64;
    fn webkit_website_data_ref(record: *mut c_void) -> *mut c_void;
    fn webkit_website_data_unref(record: *mut c_void);
    fn g_list_prepend(list: *mut wpe::GList, data: *mut c_void) -> *mut wpe::GList;
}
