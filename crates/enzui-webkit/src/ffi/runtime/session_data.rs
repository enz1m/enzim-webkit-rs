//! Profile-routed inventory and selective cleanup for a live page session.

use super::{WebSession, ffi};
use crate::ffi::site_data::{self, SiteDataTask};
use crate::page::WebsiteData;
use crate::site_data::{
    CookieKey, CookieMetadata, SiteDataCapabilities, SiteDataError, WebsiteDataRecord,
    WebsiteDataSelection,
};

impl WebSession {
    /// Precision provided by the public native cookie/website-data APIs.
    pub fn site_data_capabilities(&self) -> SiteDataCapabilities {
        site_data::capabilities()
    }

    /// Enumerate this view's profile cookies without disclosing their values.
    /// Drive the native event loop and poll the returned owner-thread task.
    pub fn cookie_inventory(&self) -> Result<SiteDataTask<Vec<CookieMetadata>>, SiteDataError> {
        // SAFETY: a live session owns its native view and borrowed network session.
        let session = unsafe { ffi::webkit_web_view_get_network_session(self.web_view) };
        site_data::inventory_cookies(session)
    }

    /// Delete the selected exact cookie identity in this view's profile.
    /// No creation-date filter is available; unrelated names/paths/domains remain.
    pub fn delete_cookie(&self, key: &CookieKey) -> Result<SiteDataTask<()>, SiteDataError> {
        // SAFETY: the async operation retains the session borrowed from this live view.
        let session = unsafe { ffi::webkit_web_view_get_network_session(self.web_view) };
        site_data::start_delete_cookie(session, key)
    }

    /// Enumerate native groups with origin metadata when the runtime exposes it.
    pub fn website_data_inventory(
        &self,
        kinds: WebsiteData,
    ) -> Result<SiteDataTask<Vec<WebsiteDataRecord>>, SiteDataError> {
        // SAFETY: the operation retains the native session before returning.
        let session = unsafe { ffi::webkit_web_view_get_network_session(self.web_view) };
        site_data::start_records(session, kinds)
    }

    /// Remove all-age data kinds from a native group or supported exact origin.
    /// Consult the capability mask before requesting origin-scoped kinds.
    pub fn remove_website_data(
        &self,
        selection: &WebsiteDataSelection,
        kinds: WebsiteData,
    ) -> Result<SiteDataTask<()>, SiteDataError> {
        // SAFETY: this session owns the view; the operation retains its native profile session.
        let session = unsafe { ffi::webkit_web_view_get_network_session(self.web_view) };
        site_data::start_remove_group(session, selection, kinds)
    }
}
