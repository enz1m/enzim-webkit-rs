//! Loopback-only diagnostic runner, absent from ordinary WPE builds.
use super::*;
use std::cell::Cell;
use std::rc::Rc;
use std::time::{Duration, Instant};

struct HeldState {
    decision: Cell<*mut ffi::WebKitPolicyDecision>,
    released: Cell<bool>,
}
struct HeldPolicy<'a> {
    view: *mut ffi::WebKitWebView,
    handler: u64,
    state: Rc<HeldState>,
    _session: PhantomData<&'a WebSession>,
}
impl<'a> HeldPolicy<'a> {
    fn new(session: &'a WebSession) -> Result<Self, String> {
        extern "C" fn policy(
            _view: *mut ffi::WebKitWebView,
            decision: *mut ffi::WebKitPolicyDecision,
            kind: c_int,
            data: *mut c_void,
        ) -> ffi::GBoolean {
            // Navigation action is enum 0; other policy decisions use WebKit's normal handler.
            if kind != 0 {
                return ffi::G_FALSE;
            }
            // SAFETY: this signal borrows the navigation decision and matching action/request.
            let uri = unsafe {
                let action =
                    ffi::webkit_navigation_policy_decision_get_navigation_action(decision.cast());
                let request = ffi::webkit_navigation_action_get_request(action);
                ffi::webkit_uri_request_get_uri(request)
            };
            if uri.is_null() {
                return ffi::G_FALSE;
            }
            // SAFETY: request URI is a borrowed native NUL-terminated string.
            if !unsafe { CStr::from_ptr(uri) }
                .to_bytes()
                .ends_with(b"/replacement")
            {
                return ffi::G_FALSE;
            }
            // SAFETY: the guard retains this stable Rc allocation until signal disconnect.
            let state = unsafe { &*data.cast::<HeldState>() };
            if !state.decision.get().is_null() {
                return ffi::G_FALSE;
            }
            // SAFETY: a separate owned native reference keeps this decision pending after return.
            unsafe { ffi::g_object_ref(decision.cast()) };
            state.released.set(false);
            state.decision.set(decision);
            ffi::G_TRUE
        }
        let state = Rc::new(HeldState {
            decision: Cell::new(ptr::null_mut()),
            released: Cell::new(false),
        });
        // SAFETY: typed function exactly matches WebView::decide-policy.
        let callback = unsafe {
            std::mem::transmute::<
                extern "C" fn(
                    *mut ffi::WebKitWebView,
                    *mut ffi::WebKitPolicyDecision,
                    c_int,
                    *mut c_void,
                ) -> ffi::GBoolean,
                extern "C" fn(),
            >(policy)
        };
        // SAFETY: the borrowed session retains view, and this Rc allocation outlives the handler.
        let handler = unsafe {
            ffi::g_signal_connect_data(
                session.web_view.cast(),
                c"decide-policy".as_ptr(),
                callback,
                Rc::as_ptr(&state).cast_mut().cast(),
                ptr::null_mut(),
                0,
            )
        };
        if handler == 0 {
            return Err("held policy signal unavailable".into());
        }
        Ok(Self {
            view: session.web_view,
            handler,
            state,
            _session: PhantomData,
        })
    }
}
impl Drop for HeldPolicy<'_> {
    fn drop(&mut self) {
        // SAFETY: the borrowed session keeps the view live until handler disconnect.
        unsafe { ffi::g_signal_handler_disconnect(self.view.cast(), self.handler) };
        let decision = self.state.decision.replace(ptr::null_mut());
        if !decision.is_null() {
            // SAFETY: an unreleased held decision owns one reference and must receive a terminal action.
            unsafe {
                ffi::webkit_policy_decision_ignore(decision);
                ffi::g_object_unref(decision.cast());
            }
        }
    }
}
struct Release {
    source: u32,
    fired: Rc<Cell<bool>>,
}
impl Release {
    fn after(state: Rc<HeldState>, milliseconds: u32) -> Self {
        extern "C" fn fire(data: *mut c_void) -> ffi::GBoolean {
            // SAFETY: this source owns the boxed state until its destroy callback.
            let (state, fired) = unsafe { &*data.cast::<(Rc<HeldState>, Rc<Cell<bool>>)>() };
            fired.set(true);
            let decision = state.decision.replace(ptr::null_mut());
            state.released.set(true);
            if !decision.is_null() {
                // SAFETY: the held owned decision receives its terminal use and matching unref.
                unsafe {
                    ffi::webkit_policy_decision_use(decision);
                    ffi::g_object_unref(decision.cast());
                }
            }
            ffi::G_FALSE
        }
        extern "C" fn destroy(data: *mut c_void) {
            // SAFETY: GLib transfers this one heap allocation back exactly once.
            drop(unsafe { Box::from_raw(data.cast::<(Rc<HeldState>, Rc<Cell<bool>>)>()) });
        }
        let fired = Rc::new(Cell::new(false));
        let data = Box::into_raw(Box::new((state, fired.clone())));
        // SAFETY: callbacks match source ABI and own stable heap state through source destruction.
        let source = unsafe {
            ffi::g_timeout_add_full(0, milliseconds, Some(fire), data.cast(), Some(destroy))
        };
        Self { source, fired }
    }
}
impl Drop for Release {
    fn drop(&mut self) {
        if !self.fired.get() {
            // SAFETY: this pending source has not fired; removal frees its owned callback data.
            unsafe { ffi::g_source_remove(self.source) };
        }
    }
}
fn script(web: &WebSession, source: &str) -> Result<String, String> {
    let reply = web
        .page_binding()
        .call_private_async(
            source,
            &crate::page::ScriptWorld::Isolated("enzui-readiness-proof".into()),
        )
        .map_err(|e| format!("script input: {e:?}"))?;
    let end = Instant::now() + Duration::from_secs(4);
    loop {
        if let Some(result) = reply.borrow_mut().take() {
            return result.map_err(|e| format!("script: {e:?}"));
        }
        if Instant::now() >= end {
            return Err("readiness proof script timeout".into());
        }
        web.pump(2);
    }
}
#[repr(C)]
struct ProcessTimespec {
    seconds: std::ffi::c_long,
    nanoseconds: std::ffi::c_long,
}
unsafe extern "C" {
    fn clock_gettime(clock: i32, result: *mut ProcessTimespec) -> i32;
}
fn cpu_seconds() -> Option<f64> {
    let mut time = ProcessTimespec {
        seconds: 0,
        nanoseconds: 0,
    };
    // SAFETY: Linux CLOCK_PROCESS_CPUTIME_ID=2 initializes a writable native timespec.
    let status = unsafe { clock_gettime(2, &mut time) };
    (status == 0).then_some(time.seconds as f64 + time.nanoseconds as f64 / 1_000_000_000.0)
}

impl WebSession {
    /// Exercise the actual load wait against a disposable loopback server.
    ///
    /// # Errors
    /// Refuses non-loopback endpoints or a failed native qualification invariant.
    #[doc(hidden)]
    pub fn qualify_native_document_readiness(
        address: std::net::SocketAddr,
    ) -> Result<String, String> {
        if !address.ip().is_loopback() || address.port() == 0 {
            return Err("readiness diagnostic requires an owned loopback endpoint".into());
        }
        let display = HeadlessDisplay::new().map_err(|e| format!("display: {e:?}"))?;
        let mut web = Self::new_trusted_local(&display).map_err(|e| format!("view: {e:?}"))?;
        let base = format!("http://{address}");
        web.load(&format!("{base}/initial"), 4000)
            .map_err(|e| format!("initial: {e:?}"))?;
        let legacy = std::env::var_os("ENZUI_WEBKIT_NATIVE_READINESS").is_some_and(|v| v == "0");
        if legacy {
            web.load(&format!("{base}/fallback"), 4000)
                .map_err(|e| format!("fallback network: {e:?}"))?;
            if script(
                &web,
                "return document.title==='Fallback ready' && document.readyState==='complete' && document.documentElement.dataset.fallback==='done';",
            )? != "true"
            {
                return Err("legacy network fallback completed before the slow script".into());
            }
            web.load_html(
                "<!doctype html><title>Inline ready</title><p>Owned inline document</p>",
                &base,
                4000,
            )
            .map_err(|e| format!("fallback HTML: {e:?}"))?;
            if script(
                &web,
                "return document.title==='Inline ready' && document.readyState==='complete';",
            )? != "true"
            {
                return Err("legacy inline fallback failed".into());
            }
            return Ok(
                "{\"mode\":\"explicit-fallback\",\"network\":true,\"inline_html\":true}".into(),
            );
        }
        // This feature-only proof replaces navigation handling solely on its owned loopback view.
        // Product builds retain the constructor's destination/sandbox policy unchanged.
        drop(web.native_policy.take());
        let held = HeldPolicy::new(&web)?;
        script(
            &web,
            "setTimeout(()=>location.replace('/replacement'),0);return true;",
        )?;
        let end = Instant::now() + Duration::from_secs(4);
        while held.state.decision.get().is_null() {
            if Instant::now() >= end {
                return Err("replacement policy was not held".into());
            }
            web.pump(2);
        }
        if web.is_loading() {
            return Err("policy barrier must precede native loading".into());
        }
        if script(
            &web,
            "return document.readyState==='complete' && performance.getEntriesByType('navigation')[0].loadEventEnd>0;",
        )? != "true"
        {
            return Err("old document positive control was not complete".into());
        }
        let reply = web.page_binding().native_document_readiness();
        let end = Instant::now() + Duration::from_secs(4);
        let busy = loop {
            if let Some(state) = reply.borrow_mut().take() {
                break state;
            }
            if Instant::now() >= end {
                return Err("native Busy control timeout".into());
            }
            web.pump(2);
        };
        if busy != crate::ffi::page::NativeDocumentReadiness::Busy {
            return Err(format!(
                "native complete-document barrier was not Busy: {busy:?}"
            ));
        }
        let released = Release::after(held.state.clone(), 200);
        let cpu = cpu_seconds();
        let started = Instant::now();
        let (_, failures, _) = web.page_hub.load_state();
        eprintln!("BARRIER_WAIT_BEGIN");
        let result = web.wait_for_document_load(started, 4000, failures);
        eprintln!("BARRIER_WAIT_END");
        result.map_err(|e| format!("held replacement wait: {e:?}"))?;
        let elapsed = started.elapsed().as_secs_f64() * 1000.0;
        let host_cpu = cpu_seconds()
            .zip(cpu)
            .map(|(after, before)| (after - before) * 1000.0)
            .map_or_else(|| "null".to_owned(), |value| format!("{value:.3}"));
        if !held.state.released.get() || elapsed < 180.0 {
            return Err(format!(
                "native Busy fell through before policy release: {elapsed:.3}ms"
            ));
        }
        if script(
            &web,
            "return document.title==='Replacement ready' && document.readyState==='complete' && performance.getEntriesByType('navigation')[0].loadEventEnd>0;",
        )? != "true"
        {
            return Err("wait accepted the old document or an unfinished replacement".into());
        }
        drop(released);
        script(
            &web,
            "setTimeout(()=>location.replace('/replacement'),0);return true;",
        )?;
        let end = Instant::now() + Duration::from_secs(4);
        while held.state.decision.get().is_null() {
            if Instant::now() >= end {
                return Err("timeout barrier was not held".into());
            }
            web.pump(2);
        }
        let (_, failures, _) = web.page_hub.load_state();
        if !matches!(
            web.wait_for_document_load(Instant::now(), 5, failures),
            Err(SessionError::Timeout("document load"))
        ) {
            return Err("native Busy did not respect the load deadline".into());
        }
        drop(held);
        // Delayed GLib callbacks must remain safe after the load owner is dropped.
        web.pump(20);

        Ok(format!(
            "{{\"mode\":\"native\",\"held_ms\":200,\"wait_ms\":{elapsed:.3},\"host_process_cpu_ms\":{host_cpu},\"replacement_loaded\":true,\"deadline_refused\":true}}"
        ))
    }
}
