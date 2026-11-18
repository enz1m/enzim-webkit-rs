use super::*;

// GLib retains callback state until source destruction, including cancellation.
struct LoadWake {
    id: u32,
    fired: std::rc::Rc<std::cell::Cell<bool>>,
}
impl LoadWake {
    fn after(milliseconds: u32) -> Self {
        extern "C" fn fire(data: *mut c_void) -> ffi::GBoolean {
            // SAFETY: the source retains this heap Rc until its destroy callback.
            unsafe { &*data.cast::<std::rc::Rc<std::cell::Cell<bool>>>() }.set(true);
            ffi::G_FALSE
        }
        extern "C" fn destroy(data: *mut c_void) {
            // SAFETY: GLib destroys this one allocation after firing or source removal.
            drop(unsafe { Box::from_raw(data.cast::<std::rc::Rc<std::cell::Cell<bool>>>()) });
        }
        let fired = std::rc::Rc::new(std::cell::Cell::new(false));
        let data = Box::into_raw(Box::new(fired.clone()));
        // SAFETY: callbacks match GSourceFunc/GDestroyNotify and own stable heap userdata.
        let id = unsafe {
            ffi::g_timeout_add_full(0, milliseconds, Some(fire), data.cast(), Some(destroy))
        };
        Self { id, fired }
    }
    fn fired(&self) -> bool {
        self.fired.get()
    }
}
impl Drop for LoadWake {
    fn drop(&mut self) {
        if !self.fired() {
            // SAFETY: this live one-shot source has not fired; removal destroys its heap callback data.
            unsafe { ffi::g_source_remove(self.id) };
        }
    }
}

#[cfg(feature = "sandbox-test-entrypoints")]
mod readiness_probe;

/// Slot used by the constructor-installed native policy until the host binds
/// its own generation-scoped view id.
pub(super) const DEFAULT_POLICY_SLOT: u64 = u64::MAX;

pub(crate) fn configure_credential_guard_extension() -> Result<(), String> {
    crate::ffi::deployment::configure()
}

pub(super) fn session_error_from_profile(error: crate::ffi::profile::ProfileError) -> SessionError {
    match error {
        crate::ffi::profile::ProfileError::DestinationGuard(why) => {
            SessionError::DestinationGuardUnavailable(why)
        }
        other => SessionError::Profile(other),
    }
}

// Host loads and inert bootstrap share signal and deadline ownership.
/// What a blocking load points WebKit at.
pub(crate) enum LoadSource<'a> {
    /// A screened URL.
    Uri(&'a CString),
    /// A host-supplied HTML document and the screened base it resolves against.
    Html {
        content: &'a CString,
        base_uri: &'a CString,
    },
}

pub(crate) fn run_load_on_view(
    web_view: *mut ffi::WebKitWebView,
    url_c: &CString,
    deadline_ms: u32,
) -> Result<(), SessionError> {
    run_load_source_on_view(web_view, LoadSource::Uri(url_c), deadline_ms)
}

pub(crate) fn run_load_source_on_view(
    web_view: *mut ffi::WebKitWebView,
    source: LoadSource<'_>,
    deadline_ms: u32,
) -> Result<(), SessionError> {
    record_native_load(true);
    {
        // SAFETY: NULL context = default; rc=1.
        let main_loop = unsafe { ffi::g_main_loop_new(ptr::null_mut(), ffi::G_FALSE) };
        // INVARIANT, not an environmental failure: glib aborts on
        // allocation failure rather than returning NULL, so NULL is unreachable.
        assert!(!main_loop.is_null(), "g_main_loop_new returned NULL");
        struct LoopGuard(*mut ffi::GMainLoop);
        impl Drop for LoopGuard {
            fn drop(&mut self) {
                // SAFETY: the loop.
                unsafe { ffi::g_main_loop_unref(self.0) };
            }
        }
        let _loop_guard = LoopGuard(main_loop);

        let state = Box::into_raw(Box::new(LoadState {
            main_loop,
            finished: false,
            started: false,
            failure: None,
            deadline_fired: false,
        }));
        struct StateGuard(*mut LoadState);
        impl Drop for StateGuard {
            fn drop(&mut self) {
                // SAFETY: recover the box after the loop has quit.
                let _ = unsafe { Box::from_raw(self.0) };
            }
        }
        let _state_guard = StateGuard(state);

        // Deadline installed BEFORE the load starts. Keep the source id so it
        // can be removed if the load finishes first (otherwise the leaked
        // timeout fires later against the freed box).
        // SAFETY: `on_load_deadline` is a GSourceFunc; state outlives the loop.
        let deadline_id =
            unsafe { ffi::g_timeout_add(deadline_ms, on_load_deadline, state.cast::<c_void>()) };

        // SAFETY: the callback matches the `load-changed` signature; GObject
        // casts to GCallback. `state` outlives the loop.
        let cb: extern "C" fn() = unsafe {
            core::mem::transmute::<
                extern "C" fn(*mut ffi::WebKitWebView, c_int, *mut c_void),
                extern "C" fn(),
            >(on_session_load_changed)
        };
        // SAFETY: `web_view` is a valid GObject; `state` outlives the loop.
        let handler = match unsafe {
            crate::ffi::signal::connect_checked(
                web_view.cast::<c_void>(),
                "load-changed",
                cb,
                state.cast::<c_void>(),
            )
        } {
            Ok(id) => id,
            Err(_) => {
                // SAFETY: `deadline_id` is a live source created here and have
                // not removed; remove it before the StateGuard frees the box.
                unsafe { ffi::g_source_remove(deadline_id) };
                return Err(SessionError::NativeSignalBindFailed("load-changed"));
            }
        };

        // SAFETY: the callback has the load-failed signal ABI; state outlives both handlers.
        let failed_cb: extern "C" fn() = unsafe {
            core::mem::transmute::<
                extern "C" fn(
                    *mut ffi::WebKitWebView,
                    c_int,
                    *const c_char,
                    *mut ffi::GError,
                    *mut c_void,
                ) -> ffi::GBoolean,
                extern "C" fn(),
            >(on_blocking_load_failed)
        };
        // SAFETY: the view and state remain live until the handlers are disconnected.
        let failed_handler = match unsafe {
            crate::ffi::signal::connect_checked(
                web_view.cast(),
                "load-failed",
                failed_cb,
                state.cast(),
            )
        } {
            Ok(id) => id,
            Err(_) => {
                // SAFETY: both ids name live resources installed by this operation.
                unsafe {
                    g_signal_handler_disconnect(web_view.cast(), handler);
                    ffi::g_source_remove(deadline_id);
                }
                return Err(SessionError::NativeSignalBindFailed("load-failed"));
            }
        };

        // The caller validated and screened every string.
        match source {
            // SAFETY: valid view + url.
            LoadSource::Uri(url_c) => unsafe {
                ffi::webkit_web_view_load_uri(web_view, url_c.as_ptr());
            },
            // SAFETY: valid view, NUL-terminated content and base.
            LoadSource::Html { content, base_uri } => unsafe {
                ffi::webkit_web_view_load_html(web_view, content.as_ptr(), base_uri.as_ptr());
            },
        }
        // SAFETY: valid loop; quit is guaranteed by the deadline.
        unsafe { ffi::g_main_loop_run(main_loop) };

        // Both callbacks must be disconnected before the state is freed.
        // SAFETY: `handler` is the id returned above; disconnect is safe even
        // if the handler already ran.
        unsafe {
            g_signal_handler_disconnect(web_view.cast::<c_void>(), handler);
            g_signal_handler_disconnect(web_view.cast::<c_void>(), failed_handler);
        };

        // Remove the deadline source if it did not fire (load finished first),
        // so it cannot fire later against the freed box.
        // SAFETY: single-threaded; `deadline_fired` written only by the
        // (now-quit) callback on this thread.
        if !unsafe { (*state).deadline_fired } {
            // SAFETY: live source id created here and have not removed.
            unsafe { ffi::g_source_remove(deadline_id) };
        }

        // SAFETY: loop has quit; single-threaded read.
        let finished = unsafe { (*state).finished };
        if finished {
            record_native_load(false);
        }
        if !finished {
            Err(SessionError::Timeout("load"))
        } else {
            // SAFETY: callbacks are disconnected; the owned error can be moved out.
            match unsafe { (*state).failure.take() } {
                Some((domain, code)) => Err(SessionError::LoadFailed { domain, code }),
                None => Ok(()),
            }
        }
    }
}

extern "C" fn on_blocking_load_failed(
    _view: *mut ffi::WebKitWebView,
    _event: c_int,
    _uri: *const c_char,
    error: *mut ffi::GError,
    data: *mut c_void,
) -> ffi::GBoolean {
    // SAFETY: the load owns this state until both handlers are disconnected.
    let state = unsafe { &mut *data.cast::<LoadState>() };
    if state.started {
        let (domain, code) = if error.is_null() {
            (String::new(), 0)
        } else {
            // SAFETY: WebKit lends GError and its interned domain during this callback.
            let name = unsafe { ffi::g_quark_to_string((*error).domain) };
            let domain = if name.is_null() {
                String::new()
            } else {
                // SAFETY: a non-null quark name is a NUL-terminated interned string.
                unsafe { CStr::from_ptr(name) }
                    .to_string_lossy()
                    .chars()
                    .take(64)
                    .collect()
            };
            (domain, unsafe { (*error).code })
        };
        // Error messages and failing URIs can contain credentials; retain only domain/code.
        state.failure = Some((domain, code));
    }
    ffi::G_FALSE
}

impl WebSession {
    pub(super) fn wait_for_document_load(
        &self,
        started: std::time::Instant,
        deadline_ms: u32,
        failures_before: u64,
    ) -> Result<(), SessionError> {
        let budget = std::time::Duration::from_millis(u64::from(deadline_ms));
        let remaining = budget.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return Err(SessionError::Timeout("document load"));
        }
        self.require_navigable()?;
        let world = crate::page::ScriptWorld::Isolated("enzui-document-load".to_owned());
        let query = |confirm| {
            let body = if confirm {
                "return globalThis.__enzDocumentLoad === document && document.readyState === 'complete';"
            } else {
                "globalThis.__enzDocumentLoad = document; \
                 return new Promise(resolve => { \
                 if (document.readyState === 'complete') { resolve(true); return; } \
                 document.addEventListener('readystatechange', function ready() { \
                 if (document.readyState !== 'complete') return; \
                 document.removeEventListener('readystatechange', ready); resolve(true); \
                 }); });"
            };
            self.page_binding()
                .call_private_async(body, &world)
                .map_err(SessionError::InvalidScriptInput)
        };
        let mut pending = None;
        let mut use_native_probe =
            !std::env::var_os("ENZUI_WEBKIT_NATIVE_READINESS").is_some_and(|value| value == "0");
        let mut native_probe = None;
        let mut native_recheck: Option<LoadWake> = None;
        let tls_before = self
            .native_certificate_ledger()
            .map(|ledger| ledger.callbacks());
        let deadline =
            LoadWake::after(remaining.as_millis().max(1).min(u128::from(u32::MAX)) as u32);
        loop {
            if deadline.fired() || started.elapsed() >= budget {
                break Err(SessionError::Timeout("document load"));
            }
            if let Err(error) = self.require_navigable() {
                break Err(error);
            }
            if self
                .native_certificate_ledger()
                .map(|ledger| ledger.callbacks())
                != tls_before
            {
                break Err(SessionError::TlsLoadFailed);
            }
            if native_recheck.as_ref().is_some_and(LoadWake::fired) {
                native_recheck = None;
            }
            let (generation, failures, failure) = self.page_hub.load_state();
            if failures != failures_before
                && let Some((domain, code)) = failure
            {
                break Err(SessionError::LoadFailed { domain, code });
            }
            if pending
                .as_ref()
                .is_some_and(|(queried, _, _)| *queried != generation)
            {
                pending = None;
            }
            if native_probe
                .as_ref()
                .is_some_and(|(queried, _)| *queried != generation)
                || self.is_loading()
            {
                native_probe = None;
            }
            if use_native_probe
                && native_probe.is_none()
                && native_recheck.is_none()
                && !self.is_loading()
            {
                native_probe = Some((generation, self.page_binding().native_document_readiness()));
                if std::env::var_os("ENZUI_WEBKIT_NATIVE_READINESS_TRACE").is_some() {
                    eprintln!(
                        "native load probe queued: {:.3} ms",
                        started.elapsed().as_secs_f64() * 1000.0
                    );
                }
            }
            let native_result = native_probe
                .as_ref()
                .and_then(|(_, reply)| reply.borrow_mut().take());
            if let Some(state) = native_result {
                native_probe = None;
                if std::env::var_os("ENZUI_WEBKIT_NATIVE_READINESS_TRACE").is_some() {
                    eprintln!(
                        "native document readiness: {state:?} at {:.3} ms",
                        started.elapsed().as_secs_f64() * 1000.0
                    );
                }
                match state {
                    crate::ffi::page::NativeDocumentReadiness::Ready if !self.is_loading() => {
                        break Ok(());
                    }
                    crate::ffi::page::NativeDocumentReadiness::Unavailable => {
                        use_native_probe = false
                    }
                    crate::ffi::page::NativeDocumentReadiness::Failed => {
                        break Err(SessionError::DocumentReadiness(
                            crate::page::ScriptError::Failed(
                                "native document readiness reply failed".into(),
                            ),
                        ));
                    }
                    _ => {
                        // Busy is authoritative; a readyState-only fallback can precede deferred load dispatch.
                        native_recheck = Some(LoadWake::after(8));
                    }
                }
            }
            if !use_native_probe && pending.is_none() && !self.is_loading() {
                pending = match query(false) {
                    Ok(reply) => Some((generation, reply, false)),
                    Err(error) => break Err(error),
                };
            }
            let result = pending.as_ref().and_then(|(_, reply, confirm)| {
                reply.borrow_mut().take().map(|result| (result, *confirm))
            });
            if let Some((result, confirmed)) = result {
                if self.is_loading() {
                    pending = None;
                    continue;
                }
                match result {
                    Ok(value) if value == "true" && !confirmed => {
                        pending = match query(true) {
                            Ok(reply) => Some((generation, reply, true)),
                            Err(error) => break Err(error),
                        };
                        continue;
                    }
                    Ok(value) if value == "false" && confirmed => {
                        pending = None;
                        continue;
                    }
                    // The old document can disappear before its replacement's load-started signal.
                    Err(crate::page::ScriptError::Failed(message))
                        if message
                            == "Completion handler for function call is no longer reachable" =>
                    {
                        pending = None;
                        continue;
                    }
                    Ok(value) if value == "true" => break Ok(()),
                    Ok(_) => {
                        break Err(SessionError::DocumentReadiness(
                            crate::page::ScriptError::Failed(
                                "document readiness did not resolve true".into(),
                            ),
                        ));
                    }
                    Err(error) => break Err(SessionError::DocumentReadiness(error)),
                }
            }
            // SAFETY: the default owner context dispatches the reply or deadline.
            unsafe { ffi::g_main_context_iteration(ptr::null_mut(), ffi::G_TRUE) };
        }
    }
}
