use super::*;
use crate::ffi::page::sys;

static BOOTSTRAP_MARK: u8 = 1;
const BOOTSTRAP_KEY: &std::ffi::CStr = c"enzui-private-attestation-history-v1";

impl WebSession {
    /// Whether the current document is the constructor's private attestation page.
    ///
    /// This stays true through pending or rejected navigation until a caller document commits.
    /// Caller-opened blank and HTML documents are not private bootstrap pages.
    /// Embedders can omit its URI/title and drain startup events before starting caller navigation.
    /// This current-document flag does not identify older events in a queue after a commit.
    pub fn is_private_bootstrap_document(&self) -> bool {
        self.page_hub.is_private_bootstrap_document()
    }

    pub(super) fn mark_bootstrap_history(&self) {
        self.page_hub.mark_private_bootstrap_document();
        // SAFETY: list and current item are borrowed from this live view on its owner thread.
        unsafe {
            let list = sys::webkit_web_view_get_back_forward_list(self.web_view);
            if !list.is_null() {
                let item = sys::webkit_back_forward_list_get_current_item(list);
                if !item.is_null() {
                    sys::g_object_set_data(
                        item,
                        BOOTSTRAP_KEY.as_ptr(),
                        (&BOOTSTRAP_MARK as *const u8).cast_mut().cast(),
                    );
                }
            }
        }
    }

    /// A restored history begins with the attestation page of the session it
    /// came from, which stays out of history navigation like this session's own.
    pub(super) fn mark_restored_bootstrap_history(&self) {
        // SAFETY: list and items are borrowed from this live view on its owner thread.
        unsafe {
            let list = sys::webkit_web_view_get_back_forward_list(self.web_view);
            if list.is_null() {
                return;
            }
            let length = c_int::try_from(sys::webkit_back_forward_list_get_length(list))
                .unwrap_or(c_int::MAX);
            let oldest = (0..length)
                .map(|back| sys::webkit_back_forward_list_get_nth_item(list, -back))
                .take_while(|item| !item.is_null())
                .last();
            let Some(oldest) = oldest else {
                return;
            };
            let uri = current_uri_from_native(sys::webkit_back_forward_list_item_get_uri(oldest));
            if uri.ok().flatten().as_deref() == Some(INERT_BOOTSTRAP_URL) {
                sys::g_object_set_data(
                    oldest,
                    BOOTSTRAP_KEY.as_ptr(),
                    (&BOOTSTRAP_MARK as *const u8).cast_mut().cast(),
                );
            }
        }
    }

    pub(super) fn navigate_document_history(&self, direction: i32) -> Result<(), SessionError> {
        let item = self.document_history_item(direction);
        if item.is_null() {
            return Ok(());
        }
        // SAFETY: this borrowed history item owns the URI until native dispatch resumes.
        if let Ok(uri) = unsafe {
            crate::ffi::policy::scan_bounded_native_uri(
                sys::webkit_back_forward_list_item_get_uri(item),
                64 * 1024,
            )
        } {
            self.screen_host_load(&uri)?;
        }
        self.page_hub.begin_host_navigation();
        // SAFETY: the borrowed item belongs to this view and dispatch has not resumed.
        unsafe { sys::webkit_web_view_go_to_back_forward_list_item(self.web_view, item) };
        Ok(())
    }

    pub(super) fn document_history_item(&self, direction: i32) -> *mut c_void {
        // SAFETY: borrowed list items remain live until control returns to native dispatch.
        unsafe {
            let list = sys::webkit_web_view_get_back_forward_list(self.web_view);
            if list.is_null() {
                return ptr::null_mut();
            }
            let mut offset = direction;
            loop {
                let item = sys::webkit_back_forward_list_get_nth_item(list, offset);
                if item.is_null() || ffi::g_object_get_data(item, BOOTSTRAP_KEY.as_ptr()).is_null()
                {
                    return item;
                }
                let Some(next) = offset.checked_add(direction) else {
                    return ptr::null_mut();
                };
                offset = next;
            }
        }
    }
}
