use super::*;
pub use crate::site_data::CookieKey;
use crate::site_data::{CookieMetadata, CookieSameSite};

/// Non-secret cookie metadata retained by the browser callback adapter.
#[derive(Clone, Debug)]
pub struct CookieInfo {
    /// Exact cookie identity.
    pub key: CookieKey,
    /// Secure transport restriction.
    pub secure: bool,
    /// Script access restriction.
    pub http_only: bool,
    /// Expiry in Unix seconds, absent for session cookies.
    pub expires: Option<i64>,
    /// Native SameSite policy value.
    pub same_site: i32,
}
impl From<CookieMetadata> for CookieInfo {
    fn from(value: CookieMetadata) -> Self {
        Self {
            key: value.key,
            secure: value.secure,
            http_only: value.http_only,
            expires: value.expires_unix_seconds,
            same_site: match value.same_site {
                CookieSameSite::None => 0,
                CookieSameSite::Lax => 1,
                CookieSameSite::Strict => 2,
                CookieSameSite::Unknown(value) => value,
            },
        }
    }
}
struct Poll(Box<dyn FnMut() -> bool>);
extern "C" fn poll(data: *mut c_void) -> ffi::GBoolean {
    // SAFETY: the source owns this allocation until its callback returns false.
    let keep = unsafe { (&mut *data.cast::<Poll>()).0() };
    if keep {
        ffi::G_TRUE
    } else {
        // SAFETY: no subsequent callback is scheduled after false is returned.
        drop(unsafe { Box::from_raw(data.cast::<Poll>()) });
        ffi::G_FALSE
    }
}
fn schedule(callback: impl FnMut() -> bool + 'static) {
    let state = Box::into_raw(Box::new(Poll(Box::new(callback))));
    // SAFETY: GLib's owner context receives this allocation until poll releases it.
    unsafe {
        ffi::g_timeout_add(5, poll, state.cast());
    }
}
impl WebSession {
    /// Enumerate cookies through the upstream bounded native inventory task.
    pub fn cookies(&self, done: impl FnOnce(Result<Vec<CookieInfo>, String>) + 'static) {
        let task = match self.cookie_inventory() {
            Ok(task) => task,
            Err(error) => {
                done(Err(error.to_string()));
                return;
            }
        };
        let mut done = Some(done);
        schedule(move || {
            if let Some(result) = task.take_result() {
                if let Some(done) = done.take() {
                    done(
                        result
                            .map(|rows| rows.into_iter().map(Into::into).collect())
                            .map_err(|e| e.to_string()),
                    );
                }
                false
            } else {
                true
            }
        });
    }
    /// Delete exact cookie identities serially through the upstream bounded native task API.
    /// A partial failure reports the number already removed; committed deletions cannot be rolled back.
    pub fn delete_cookies(
        &self,
        keys: Vec<CookieKey>,
        done: impl FnOnce(Result<usize, String>) + 'static,
    ) {
        use crate::ffi::site_data::SiteDataTask;
        let Some(network) = self.network_session.as_ref().cloned() else {
            done(Err("No profile network session.".into()));
            return;
        };
        let mut keys = keys.into_iter();
        let mut pending: Option<SiteDataTask<()>> = None;
        let mut count = 0;
        let mut done = Some(done);
        let start = std::time::Instant::now();
        schedule(move || {
            let error = if start.elapsed() > std::time::Duration::from_secs(15) {
                if let Some(task) = pending.take() {
                    task.cancel();
                }
                Some("Cookie cleanup timed out.".into())
            } else if let Some(task) = &pending {
                if let Some(result) = task.take_result() {
                    pending = None;
                    match result {
                        Ok(()) => {
                            count += 1;
                            None
                        }
                        Err(error) => Some(error.to_string()),
                    }
                } else {
                    return true;
                }
            } else {
                None
            };
            if let Some(error) = error {
                if let Some(done) = done.take() {
                    done(Err(format!(
                        "{count} cookies removed before cleanup stopped: {error}"
                    )));
                }
                return false;
            }
            if let Some(key) = keys.next() {
                match network.delete_cookie(&key) {
                    Ok(task) => pending = Some(task),
                    Err(error) => {
                        if let Some(done) = done.take() {
                            done(Err(format!(
                                "{count} cookies removed before cleanup stopped: {error}"
                            )));
                        }
                        return false;
                    }
                }
                true
            } else {
                if let Some(done) = done.take() {
                    done(Ok(count));
                }
                false
            }
        });
    }
}
