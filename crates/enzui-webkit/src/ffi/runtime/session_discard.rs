//! Discarding a page the user is not looking at, as Chromium discards tabs: the
//! session and its web process go, and a new session brings the page back
//! from WebKit's snapshot of its history, scroll positions and form contents.
use super::*;
use crate::ffi::page::sys;
use crate::ffi::wpe::{GBytes, g_bytes_get_data, g_bytes_new, g_bytes_unref};

/// What a new session needs to bring a discarded page back, and what a tab
/// strip shows until then.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscardedPage {
    state: Vec<u8>,
    uri: Option<String>,
    title: Option<String>,
}

impl DiscardedPage {
    /// The address of the page that was showing.
    #[must_use]
    pub fn uri(&self) -> Option<&str> {
        self.uri.as_deref()
    }

    /// The title of the page that was showing.
    #[must_use]
    pub fn title(&self) -> Option<&str> {
        self.title.as_deref()
    }
}

impl WebSession {
    /// Discards the page: the session closes, and its web process exits unless
    /// another page shares it or the host keeps a process cache.
    ///
    /// The returned page holds WebKit's session state: the history, with each
    /// entry's scroll position and form contents. A page records the current
    /// entry's when it is hidden, so discard it after
    /// [`Self::set_view_visibility`] hid it, as a browser discards a background
    /// tab; a page discarded while visible comes back without its latest
    /// scroll position and form edits. [`Self::restore_discarded`] brings it
    /// back in a new session; `crate::tab_memory` chooses which pages to
    /// discard.
    #[must_use]
    pub fn discard(self) -> DiscardedPage {
        let page = DiscardedPage {
            state: self.session_state(),
            uri: self.page_hub.last_committed(),
            title: self.page_title().ok().flatten(),
        };
        drop(self);
        page
    }

    /// Loads a page discarded by [`Self::discard`] into this new session, with
    /// its history, and its scroll position and form contents once it has
    /// loaded. The load is asynchronous and passes the destination policy like
    /// any other; without a usable snapshot the page's address is loaded.
    ///
    /// # Errors
    /// The errors of [`Self::begin_load_uri`].
    pub fn restore_discarded(&self, page: &DiscardedPage) -> Result<(), SessionError> {
        self.require_navigable()?;
        if let Some((item, uri)) = self.restore_session_state(&page.state) {
            self.screen_host_load(&uri)?;
            self.page_hub.begin_host_navigation();
            // SAFETY: the item belongs to this live view's list.
            unsafe { sys::webkit_web_view_go_to_back_forward_list_item(self.web_view, item) };
            return Ok(());
        }
        match &page.uri {
            Some(uri) => self.begin_load_uri(uri),
            None => Ok(()),
        }
    }

    fn session_state(&self) -> Vec<u8> {
        // SAFETY: a live view; the state and bytes are released here, and the
        // data is copied before the bytes are.
        unsafe {
            let state = sys::webkit_web_view_get_session_state(self.web_view);
            if state.is_null() {
                return Vec::new();
            }
            let bytes = sys::webkit_web_view_session_state_serialize(state).cast::<GBytes>();
            sys::webkit_web_view_session_state_unref(state);
            if bytes.is_null() {
                return Vec::new();
            }
            let mut size = 0;
            let data = g_bytes_get_data(bytes, &mut size);
            let copy = if data.is_null() {
                Vec::new()
            } else {
                std::slice::from_raw_parts(data.cast::<u8>(), size).to_vec()
            };
            g_bytes_unref(bytes);
            copy
        }
    }

    /// Installs the snapshot's history; the current entry to load and its
    /// address, unless it is missing or the attestation page.
    fn restore_session_state(&self, state: &[u8]) -> Option<(*mut c_void, String)> {
        if state.is_empty() {
            return None;
        }
        // SAFETY: a live view on its owner thread; WebKit copies what it keeps
        // from the state, which is released here with the bytes.
        unsafe {
            let bytes = g_bytes_new(state.as_ptr().cast(), state.len());
            let session_state = sys::webkit_web_view_session_state_new(bytes.cast());
            g_bytes_unref(bytes);
            if session_state.is_null() {
                return None;
            }
            sys::webkit_web_view_restore_session_state(self.web_view, session_state);
            sys::webkit_web_view_session_state_unref(session_state);
        }
        self.mark_restored_bootstrap_history();
        // SAFETY: the list and item are borrowed from the live view.
        unsafe {
            let list = sys::webkit_web_view_get_back_forward_list(self.web_view);
            let item = if list.is_null() {
                ptr::null_mut()
            } else {
                sys::webkit_back_forward_list_get_current_item(list)
            };
            if item.is_null() {
                return None;
            }
            let uri = current_uri_from_native(sys::webkit_back_forward_list_item_get_uri(item))
                .ok()
                .flatten()?;
            (uri != INERT_BOOTSTRAP_URL).then_some((item, uri))
        }
    }
}
