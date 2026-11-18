use super::*;
use std::ffi::CString;
use std::sync::OnceLock;

type CopyOrigins = unsafe extern "C" fn(*mut c_void) -> *mut *mut c_char;
type RemoveOrigin = unsafe extern "C" fn(
    *mut c_void,
    u32,
    *const c_char,
    *mut c_void,
    extern "C" fn(*mut c_void, *mut wpe::GAsyncResult, *mut c_void),
    *mut c_void,
);

struct Api {
    copy: CopyOrigins,
    remove: RemoveOrigin,
}

#[link(name = "dl")]
unsafe extern "C" {
    fn dlsym(handle: *mut c_void, name: *const c_char) -> *mut c_void;
    fn g_strfreev(strings: *mut *mut c_char);
}

fn api() -> Option<&'static Api> {
    static API: OnceLock<Option<Api>> = OnceLock::new();
    API.get_or_init(|| {
        // SAFETY: both names refer to the reviewed runtime's versioned C ABI.
        let (copy, remove) = unsafe {
            (
                dlsym(
                    ptr::null_mut(),
                    c"webkit_website_data_enzui_copy_origins".as_ptr(),
                ),
                dlsym(
                    ptr::null_mut(),
                    c"webkit_website_data_manager_enzui_remove_origin".as_ptr(),
                ),
            )
        };
        if copy.is_null() || remove.is_null() {
            return None;
        }
        // SAFETY: these signatures match the two reviewed exported declarations.
        Some(unsafe {
            Api {
                copy: std::mem::transmute::<*mut c_void, CopyOrigins>(copy),
                remove: std::mem::transmute::<*mut c_void, RemoveOrigin>(remove),
            }
        })
    })
    .as_ref()
}

pub(super) fn capabilities() -> SiteDataCapabilities {
    let mut capabilities = SiteDataCapabilities::WPE;
    if api().is_some() {
        capabilities.exact_website_data_origins = true;
        capabilities.exact_website_data_removal_types = crate::site_data::ORIGIN_SCOPED_DATA_TYPES;
    }
    capabilities
}

pub(super) fn read_origins(record: *mut c_void) -> Result<Option<Vec<String>>, SiteDataError> {
    let Some(api) = api() else { return Ok(None) };
    // SAFETY: the caller holds the native record through this synchronous transfer.
    let strings = unsafe { (api.copy)(record) };
    if strings.is_null() {
        return Err(SiteDataError::InventoryTooLarge);
    }
    let mut result = Vec::new();
    let mut bytes = 0;
    let outcome = (|| {
        for index in 0..=MAX_RECORDS {
            // SAFETY: native returns a NUL-terminated vector with at most MAX_RECORDS entries.
            let value = unsafe { *strings.add(index) };
            if value.is_null() {
                result.sort();
                result.dedup();
                return Ok(Some(result));
            }
            // SAFETY: each non-null entry is owned by this transferred string vector.
            let value = unsafe { read_string(value) }?;
            bytes += value.len();
            if index == MAX_RECORDS || bytes > MAX_METADATA {
                return Err(SiteDataError::InventoryTooLarge);
            }
            result.push(value);
        }
        Err(SiteDataError::InventoryTooLarge)
    })();
    // SAFETY: release exactly the transferred string vector and its entries.
    unsafe { g_strfreev(strings) };
    outcome
}

pub(super) fn remove(
    session: *mut wpe::WebKitNetworkSession,
    origin: &str,
    kinds: WebsiteData,
) -> Result<SiteDataTask<()>, SiteDataError> {
    let origin = crate::site_data::validate_origin_selection(origin, kinds)?;
    let api = api().ok_or(SiteDataError::UnsupportedScope(
        "native runtime lacks exact-origin cleanup",
    ))?;
    let origin = CString::new(origin).map_err(|_| SiteDataError::InvalidInput("invalid origin"))?;
    let (task, completion) = task(removed)?;
    let request = Box::new(Request {
        completion,
        _owner: Owner::retain(session),
        action: Action::Records(kinds.bits()),
        retained_cookie: ptr::null_mut(),
        retained_records: ptr::null_mut(),
    });
    // SAFETY: native copies the origin synchronously; the request retains its owner and cancellable.
    unsafe {
        (api.remove)(
            webkit_network_session_get_website_data_manager(session).cast(),
            kinds.bits(),
            origin.as_ptr(),
            request.completion.cancellable(),
            records_removed,
            Box::into_raw(request).cast(),
        );
    }
    Ok(task)
}
