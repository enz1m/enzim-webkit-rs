//! Private implementation of the persistent WebSession lifecycle.
//!
//! Types stay in the parent module so every caller-facing path remains
//! `ffi::runtime::*`; this child contains only cohesive implementation blocks.

use super::*;

mod deferred;
pub use deferred::PendingWebSession;

impl ProxyAuthenticationBinding {
    pub(super) fn install(
        web_view: *mut ffi::WebKitWebView,
        network_session: &crate::ffi::profile::NetworkSession,
    ) -> Result<Option<Self>, &'static str> {
        let Some((address, username, password)) = network_session.destination_guard_proxy_auth()
        else {
            return Ok(None);
        };
        let state = Box::into_raw(Box::new(ProxyAuthenticationState {
            host: CString::new(address.ip().to_string()).expect("IP address contains no NUL"),
            port: u32::from(address.port()),
            username: CString::new(username).expect("proxy username contains no NUL"),
            password: CString::new(password).expect("proxy password contains no NUL"),
        }));
        // SAFETY: the concrete callback matches WebKitWebView's `authenticate`
        // signal ABI; GObject stores it through the erased GCallback type.
        let callback: extern "C" fn() = unsafe {
            core::mem::transmute::<
                extern "C" fn(
                    *mut ffi::WebKitWebView,
                    *mut ffi::WebKitAuthenticationRequest,
                    *mut c_void,
                ) -> ffi::GBoolean,
                extern "C" fn(),
            >(on_proxy_authenticate)
        };
        // SAFETY: `web_view` is live and owns the signal; `state` remains
        // allocated until the binding disconnects the returned handler.
        match unsafe {
            crate::ffi::signal::connect_checked(
                web_view.cast::<c_void>(),
                "authenticate",
                callback,
                state.cast::<c_void>(),
            )
        } {
            Ok(handler) => Ok(Some(Self {
                web_view,
                handler,
                state,
            })),
            Err(error) => {
                // SAFETY: connection failed, so no callback retained `state`.
                drop(unsafe { Box::from_raw(state) });
                Err(error.signal)
            }
        }
    }
}

impl Drop for ProxyAuthenticationBinding {
    fn drop(&mut self) {
        // SAFETY: the view remains live until WebSession/standalone teardown;
        // disconnecting first makes this binding the sole owner of `state`.
        unsafe {
            g_signal_handler_disconnect(self.web_view.cast::<c_void>(), self.handler);
            drop(Box::from_raw(self.state));
        }
    }
}

fn proxy_authentication_matches(
    state: &ProxyAuthenticationState,
    is_proxy: bool,
    is_retry: bool,
    host: &CStr,
    port: u32,
) -> bool {
    is_proxy && !is_retry && port == state.port && host == state.host.as_c_str()
}

extern "C" fn on_proxy_authenticate(
    _web_view: *mut ffi::WebKitWebView,
    request: *mut ffi::WebKitAuthenticationRequest,
    user_data: *mut c_void,
) -> ffi::GBoolean {
    if request.is_null() || user_data.is_null() {
        return ffi::G_FALSE;
    }
    // SAFETY: both pointers were checked non-NULL; `user_data` is the boxed
    // state retained by the connected binding, and `request` is callback-live.
    let state = unsafe { &*(user_data as *const ProxyAuthenticationState) };
    // SAFETY: all accessors borrow only from the callback-live request.
    let (is_proxy, is_retry, host, port) = unsafe {
        (
            ffi::webkit_authentication_request_is_for_proxy(request) != ffi::G_FALSE,
            ffi::webkit_authentication_request_is_retry(request) != ffi::G_FALSE,
            ffi::webkit_authentication_request_get_host(request),
            ffi::webkit_authentication_request_get_port(request),
        )
    };
    if host.is_null() {
        return ffi::G_FALSE;
    }
    // SAFETY: WebKit returned a non-NULL borrowed NUL-terminated host string
    // whose lifetime covers this callback.
    let host = unsafe { CStr::from_ptr(host) };
    if !proxy_authentication_matches(state, is_proxy, is_retry, host, port) {
        return ffi::G_FALSE;
    }
    // SAFETY: both CString pointers are NUL-terminated and callback-live; zero
    // requests non-persistent credentials, so no secret reaches disk.
    let credential =
        unsafe { ffi::webkit_credential_new(state.username.as_ptr(), state.password.as_ptr(), 0) };
    if credential.is_null() {
        return ffi::G_FALSE;
    }
    // SAFETY: `credential` is a live boxed value. WebKit consumes its value,
    // not its allocation, so the caller frees the box after authenticating.
    unsafe {
        ffi::webkit_authentication_request_authenticate(request, credential);
        ffi::webkit_credential_free(credential);
    }
    ffi::G_TRUE
}

impl Drop for HeadlessDisplay {
    fn drop(&mut self) {
        // SAFETY: `self.ptr` was produced by `wpe_display_headless_new` and
        // has been held with ref-count >= 1 throughout `self`'s lifetime.
        // `g_object_unref` accepts any GObject-derived pointer; `WPEDisplay`
        // inherits GObject.
        unsafe { ffi::g_object_unref(self.ptr.cast::<c_void>()) }
        // the display is the last owner in a page's drop order, so this
        // counter is what a UI-side close gate can observe once the worker is
        // gone and there is nothing left to ask.
        crate::native_release::record_display();
    }
}

impl WebSession {
    /// Construct a session on `display` using a private ephemeral WebKit
    /// network session. The private session owns its strict proxy guard, so
    /// another view cannot overwrite its routing and dropping another view
    /// cannot strand it on a dead proxy. App-owned views should use
    /// [`WebSession::new_profiled`] so storage identity is explicit.
    pub fn new(display: &HeadlessDisplay) -> Result<WebSession, SessionError> {
        Self::new_with_sandbox_policy(display, crate::ffi::deployment::sandbox_policy())
    }

    /// [`WebSession::new`] for host-supplied local content: the named
    /// destination-policy opt-out. It also receives a private ephemeral
    /// network session; it never inherits a strict default session's proxy.
    ///
    /// Every other constructor installs
    /// [`DestinationPolicy::DEFAULT`](crate::web::DestinationPolicy::DEFAULT)
    /// and a running guard, so loopback and private addresses are refused
    /// before any connection. A framework fixture, or an app embedding a
    /// service it started itself on loopback, must say so here - in code, at
    /// one greppable call site - rather than by flipping a field.
    ///
    /// Never point a session created this way at untrusted remote content.
    ///
    /// # Errors
    ///
    /// As [`WebSession::new`].
    pub fn new_trusted_local(display: &HeadlessDisplay) -> Result<WebSession, SessionError> {
        crate::sandbox::preflight_in(
            &crate::sandbox::RealEnv,
            crate::ffi::deployment::sandbox_policy(),
        )
        .map_err(SessionError::SandboxDisabled)?;
        Self::construct(
            display,
            None,
            None,
            crate::ffi::deployment::sandbox_policy(),
            crate::web::DestinationPolicy::trusted_local(),
        )
    }

    /// [`WebSession::new_profiled`] under the named local destination opt-out.
    /// A live profile already used under the strict posture is refused here,
    /// because WebKit proxy settings are network-session-wide; after its final
    /// strict view closes, the same persistent identity may be reopened here.
    ///
    /// # Errors
    ///
    /// As [`WebSession::new_profiled`].
    pub fn new_profiled_trusted_local(
        display: &HeadlessDisplay,
        profiles: &mut crate::ffi::profile::ProfileStore,
        profile: &crate::web::WebProfile,
    ) -> Result<WebSession, SessionError> {
        crate::sandbox::preflight_in(
            &crate::sandbox::RealEnv,
            crate::ffi::deployment::sandbox_policy(),
        )
        .map_err(SessionError::SandboxDisabled)?;
        let destination_policy = crate::web::DestinationPolicy::trusted_local();
        let network_session = profiles
            .session_for_policy(profile, destination_policy)
            .map_err(session_error_from_profile)?;
        Self::construct(
            display,
            Some(profile.clone()),
            Some(network_session),
            crate::ffi::deployment::sandbox_policy(),
            destination_policy,
        )
    }

    /// Deterministic destination-boundary constructor for native integration
    /// gates. Production callers use `new`/`new_profiled`; this keeps the real
    /// WebKit network path while substituting only DNS/connect observations.
    ///
    /// # Errors
    ///
    /// As [`WebSession::new`], plus a typed destination-guard setup failure.
    #[doc(hidden)]
    pub fn new_with_destination_seams(
        display: &HeadlessDisplay,
        policy: crate::web::DestinationPolicy,
        resolver: std::sync::Arc<dyn crate::destination_guard::Resolver>,
        connector: std::sync::Arc<dyn crate::destination_guard::Connector>,
    ) -> Result<WebSession, SessionError> {
        crate::sandbox::preflight_in(
            &crate::sandbox::RealEnv,
            crate::ffi::deployment::sandbox_policy(),
        )
        .map_err(SessionError::SandboxDisabled)?;
        let network = crate::ffi::profile::NetworkSession::new_ephemeral_with_destination_seams(
            policy, resolver, connector,
        )
        .map_err(session_error_from_profile)?;
        Self::construct(
            display,
            None,
            Some(Rc::new(network)),
            crate::ffi::deployment::sandbox_policy(),
            policy,
        )
    }

    /// [`WebSession::new`] under an explicit outer-sandbox policy.
    ///
    /// A host that runs inside Flatpak/Snap/a container - where WebKit does not
    /// use its bubblewrap launcher at all - states so in code with
    /// [`crate::sandbox::OuterSandbox::AcceptedByHost`], and the decision then
    /// reaches preflight *and* postflight. Without this the acceptance existed
    /// but no production call could use it, so a legitimately outer-confined
    /// renderer was terminated anyway.
    ///
    /// Acceptance admits only the container itself: sandbox-weakening
    /// environment variables are still refused, and post-spawn it only excuses
    /// the two verdicts a missing inner sandbox actually explains.
    ///
    /// # Errors
    ///
    /// As [`WebSession::new`].
    pub fn new_with_sandbox_policy(
        display: &HeadlessDisplay,
        outer: crate::sandbox::OuterSandbox,
    ) -> Result<WebSession, SessionError> {
        // refuse before ANY native work, including the profile
        // resolution `new_profiled` would do. `construct` checks again - it is
        // the choke point a future constructor cannot bypass - but the check
        // has to be here too so no allocation precedes the refusal.
        crate::sandbox::preflight_in(&crate::sandbox::RealEnv, outer)
            .map_err(SessionError::SandboxDisabled)?;
        Self::construct(
            display,
            None,
            None,
            outer,
            crate::web::DestinationPolicy::DEFAULT,
        )
    }

    /// Construct a real WebKit view for `profile`.
    ///
    /// The profile identity is resolved by `profiles`, then passed through the
    /// WebView's construct-only `network-session` property. The property is
    /// read back and compared before success, so a misspelled/unsupported
    /// property cannot silently place the page on WebKit's default session.
    pub fn new_profiled(
        display: &HeadlessDisplay,
        profiles: &mut crate::ffi::profile::ProfileStore,
        profile: &crate::web::WebProfile,
    ) -> Result<WebSession, SessionError> {
        Self::new_profiled_with_sandbox_policy(
            display,
            profiles,
            profile,
            crate::ffi::deployment::sandbox_policy(),
        )
    }

    /// [`WebSession::new_profiled`] under an explicit outer-sandbox policy.
    ///
    /// See [`WebSession::new_with_sandbox_policy`].
    ///
    /// # Errors
    ///
    /// As [`WebSession::new_profiled`].
    pub fn new_profiled_with_sandbox_policy(
        display: &HeadlessDisplay,
        profiles: &mut crate::ffi::profile::ProfileStore,
        profile: &crate::web::WebProfile,
        outer: crate::sandbox::OuterSandbox,
    ) -> Result<WebSession, SessionError> {
        // Before `session_for`, which provisions directories and constructs a
        // WebKitNetworkSession: a refused session must not touch storage.
        crate::sandbox::preflight_in(&crate::sandbox::RealEnv, outer)
            .map_err(SessionError::SandboxDisabled)?;
        let destination_policy = crate::web::DestinationPolicy::DEFAULT;
        let network_session = profiles
            .session_for_policy(profile, destination_policy)
            .map_err(session_error_from_profile)?;
        Self::construct(
            display,
            Some(profile.clone()),
            Some(network_session),
            outer,
            destination_policy,
        )
    }

    fn construct(
        display: &HeadlessDisplay,
        profile: Option<crate::web::WebProfile>,
        network_session: Option<Rc<crate::ffi::profile::NetworkSession>>,
        outer: crate::sandbox::OuterSandbox,
        destination_policy: crate::web::DestinationPolicy,
    ) -> Result<WebSession, SessionError> {
        let mut session = Self::construct_view(
            display.as_ptr(),
            None,
            profile,
            network_session,
            outer,
            destination_policy,
        )?;
        // native policy callbacks are installed by the CONSTRUCTOR, not
        // by an optional `install_native_policy` the caller may forget. The
        // policy is `WebPolicy::strict()` carrying this session's destination
        // rule, and the default responder echoes the request id so the typed
        // policy - not WebKit's permissive default handler - decides.
        session.install_default_native_policy()?;
        // the renderer is spawned on INERT content and attested here,
        // before this constructor returns and therefore before any caller URI,
        // script or network fetch can run in it. A session that reaches a
        // caller is a session whose renderer was shown to be isolated.
        session.bootstrap_and_attest()?;
        session.connect_page()?;
        Ok(session)
    }

    /// Connects the page signals; done after any bootstrap so the host never
    /// sees the inert bootstrap load.
    fn connect_page(&mut self) -> Result<(), SessionError> {
        self.page = Some(
            crate::ffi::page::PageBinding::new(self.web_view, Rc::clone(&self.page_hub))
                .map_err(|err| SessionError::NativeSignalBindFailed(err.signal))?,
        );
        Ok(())
    }

    /// The view a page opened with `window.open`, built in WebKit's `create`
    /// callback: related to `opener` (same renderer and network session),
    /// with the opener's profile, destination rule, sandbox posture and
    /// current policy, and no inert bootstrap, because WebKit loads the
    /// popup's own URL as soon as the callback returns. It is attested when
    /// the host takes it ([`WebSession::take_popup`]).
    pub(crate) fn open_popup(
        template: &crate::ffi::page::PopupTemplate,
        opener: *mut ffi::WebKitWebView,
        opener_hub: &Rc<crate::ffi::page::PageHub>,
    ) -> Result<WebSession, SessionError> {
        // SAFETY: the opener is live for the `create` callback; its display
        // is borrowed and referenced again by the new view's property.
        let display = unsafe { crate::ffi::page::sys::webkit_web_view_get_display(opener) };
        if display.is_null() {
            return Err(SessionError::NoWpeView);
        }
        let mut session = Self::construct_view(
            display,
            Some(opener),
            template.profile.clone(),
            Some(Rc::clone(&template.network_session)),
            template.outer,
            template.destination_policy,
        )?;
        session.sandbox_baseline = template.sandbox_baseline.clone();
        let policy = template
            .policy
            .clone()
            .with_destination(session.destination_policy)
            .with_local_origins(session.local_origins().unwrap_or_default());
        // SAFETY: borrowed from this live view, shares its lifetime.
        let network_session = unsafe { ffi::webkit_web_view_get_network_session(session.web_view) };
        session.native_policy = Some(
            crate::ffi::policy::NativePolicyBinding::new(
                session.web_view,
                network_session,
                crate::web::ViewId::new(DEFAULT_POLICY_SLOT),
                policy,
                session.sandbox_policy,
                session.sandbox_baseline.clone(),
                // Until the host installs its own responder the popup takes
                // what the opener's policy allows without asking, but for a
                // certificate that failed validation: whether to go on to
                // such a site is the host's to answer, and nobody is here to.
                |request| {
                    (!matches!(request.kind, crate::web::RequestKind::Certificate(_)))
                        .then_some(request.id)
                },
            )
            .map_err(|err| SessionError::NativeSignalBindFailed(err.signal))?
            .with_page(Rc::clone(&session.page_hub)),
        );
        // The popup is the opener's sign-in window as often as not: it
        // captures the opener's redirects (reported to the opener), answers
        // the same prompts, downloads to the same directory, and starts with
        // the same settings.
        if let Some(settings) = session.page_hub.inherit(opener_hub) {
            // SAFETY: the popup's view is live.
            unsafe { crate::ffi::page::apply_settings(session.web_view, &settings) };
        }
        session.connect_page()?;
        Ok(session)
    }

    /// Whether the page asked to close (`window.close()`).
    pub(crate) fn page_closed(&self) -> bool {
        self.page_hub.has_close_request()
    }

    /// Whether the renderer this session attested has gone (a crash, an
    /// OOM kill, a host termination) and not yet been replaced.
    pub(crate) fn renderer_lost(&self) -> bool {
        self.attested_renderer
            .get()
            .is_some_and(|identity| self.renderer_is_gone(identity))
    }

    fn renderer_is_gone(&self, identity: crate::sandbox::ProcessIdentity) -> bool {
        if let Some(gone) = self
            .renderer_liveness
            .borrow()
            .as_ref()
            .filter(|witness| witness.identity() == identity)
            .and_then(crate::sandbox::process_liveness::ProcessLiveness::is_gone)
        {
            record_native_liveness(true);
            return gone;
        }
        record_native_liveness(false);
        crate::sandbox::process_is_gone(identity)
    }

    /// Finishes a popup for its host: the WebProcess credential hook must
    /// have answered for this page, and the renderer(s) the opener and popup
    /// run in must attest as isolated, before the host receives it.
    pub(crate) fn finish_popup(self) -> Result<WebSession, SessionError> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(2_000);
        while !self
            .native_policy
            .as_ref()
            .is_some_and(crate::ffi::policy::NativePolicyBinding::credential_guard_ready)
        {
            if std::time::Instant::now() >= deadline {
                return Err(SessionError::CredentialGuardUnavailable(
                    "the popup's WebProcess did not acknowledge the send-request hook".into(),
                ));
            }
            self.pump(25);
        }
        self.attest_and_enforce(SANDBOX_ATTESTATION_BUDGET_MS)?;
        Ok(self)
    }

    fn construct_view(
        display_ptr: *mut ffi::WPEDisplay,
        related: Option<*mut ffi::WebKitWebView>,
        profile: Option<crate::web::WebProfile>,
        network_session: Option<Rc<crate::ffi::profile::NetworkSession>>,
        outer: crate::sandbox::OuterSandbox,
        destination_policy: crate::web::DestinationPolicy,
    ) -> Result<WebSession, SessionError> {
        crate::sandbox::preflight_in(&crate::sandbox::RealEnv, outer)
            .map_err(SessionError::SandboxDisabled)?;
        deferred::wait_for_pending_bootstrap()?;
        Self::construct_view_unblocked(
            display_ptr,
            related,
            profile,
            network_session,
            outer,
            destination_policy,
        )
    }

    fn construct_view_unblocked(
        display_ptr: *mut ffi::WPEDisplay,
        related: Option<*mut ffi::WebKitWebView>,
        profile: Option<crate::web::WebProfile>,
        network_session: Option<Rc<crate::ffi::profile::NetworkSession>>,
        outer: crate::sandbox::OuterSandbox,
        destination_policy: crate::web::DestinationPolicy,
    ) -> Result<WebSession, SessionError> {
        // the sandbox check is here, in the single private constructor
        // both public entry points funnel through, so a future third
        // constructor cannot forget it. It runs *first*: no display use, no
        // GObject allocation and no WebProcess spawn happens in an environment
        // that has disabled WebProcess confinement.
        crate::sandbox::preflight_in(&crate::sandbox::RealEnv, outer)
            .map_err(SessionError::SandboxDisabled)?;
        super::process_cache::ensure_default_policy();
        super::back_forward_cache::ensure_default_policy();
        // HeadlessDisplay configured the mandatory WebProcess request hook
        // before WPE was initialized; bootstrap below verifies its handshake.
        // Proxy settings live on WebKitNetworkSession. Give every unprofiled
        // view a private ephemeral session; profiled sessions are cached only
        // under the same profile AND destination policy.
        let network_session = match network_session {
            Some(session) if session.destination_policy() == destination_policy => session,
            Some(_) => {
                return Err(SessionError::DestinationGuardUnavailable(
                    "profile network session policy does not match the view".into(),
                ));
            }
            None => Rc::new(
                crate::ffi::profile::NetworkSession::new_ephemeral_with_policy(destination_policy)
                    .map_err(session_error_from_profile)?,
            ),
        };
        // The renderers that exist BEFORE this view does. Everything attested
        // later is scoped against this set.
        let sandbox_baseline = crate::sandbox::current_web_processes();
        let display_ptr = display_ptr.cast::<c_void>();
        // SAFETY: pure GObject accessors, always valid once the lib is loaded.
        let (view_gtype, display_gtype) =
            unsafe { (ffi::webkit_web_view_get_type(), ffi::wpe_display_get_type()) };

        let display_name = CString::new("display").expect("static string, no NUL");
        let network_name = CString::new("network-session").expect("static string, no NUL");
        let related_name = CString::new("related-view").expect("static string, no NUL");
        let mut names = Vec::with_capacity(3);
        let mut values = Vec::with_capacity(3);
        match related {
            // A popup shares its opener's renderer, display and network
            // session; WebKit refuses either property beside a related view.
            Some(related) => {
                names.push(related_name.as_ptr());
                values.push(ffi::GValue::default());
                // SAFETY: a WebKitWebView-typed value holding the live opener.
                unsafe {
                    ffi::g_value_init(&mut values[0], view_gtype);
                    ffi::g_value_set_object(&mut values[0], related.cast::<c_void>());
                }
            }
            None => {
                names.push(display_name.as_ptr());
                values.push(ffi::GValue::default());
                // SAFETY: zero-inited GValue is glib's "uninitialised"; init
                // then set.
                unsafe {
                    ffi::g_value_init(&mut values[0], display_gtype);
                    ffi::g_value_set_object(&mut values[0], display_ptr);
                }
            }
        }
        // A related view inherits the opener's network session (WebKit
        // refuses one beside it); the check below still proves it is the
        // expected session.
        if related.is_none() {
            names.push(network_name.as_ptr());
            values.push(ffi::GValue::default());
            // SAFETY: initialise the second value with the exact declared
            // NetworkSession GType, then give it the live session object.
            unsafe {
                ffi::g_value_init(&mut values[1], ffi::webkit_network_session_get_type());
                ffi::g_value_set_object(&mut values[1], network_session.as_ptr().cast::<c_void>());
            }
        }
        // SAFETY: property/value arrays have equal lengths and stay live for
        // the call; returns a WebKitWebView* rc=1.
        let web_view = unsafe {
            ffi::g_object_new_with_properties(
                view_gtype,
                names.len() as c_uint,
                names.as_ptr(),
                values.as_ptr(),
            )
        } as *mut ffi::WebKitWebView;
        // SAFETY: done with all values; unset drops the refs they added.
        for value in &mut values {
            unsafe { ffi::g_value_unset(value) };
        }

        if web_view.is_null() {
            return Err(SessionError::WebViewConstructionFailed);
        }
        // SAFETY: the view was just created.
        unsafe { crate::ffi::page::watch_finalization(web_view) };
        if !super::gpu_process::apply(web_view) {
            // SAFETY: the view is still owned here.
            unsafe { ffi::g_object_unref(web_view.cast::<c_void>()) };
            return Err(SessionError::GpuProcessUnsupported);
        }

        // SAFETY: live view; returned pointer is borrowed.
        let actual = unsafe { ffi::webkit_web_view_get_network_session(web_view) };
        if actual != network_session.as_ptr() {
            // SAFETY: the failed-to-bind view is still owned here.
            unsafe { ffi::g_object_unref(web_view.cast::<c_void>()) };
            return Err(SessionError::ProfileNotBound);
        }

        // SAFETY: `web_view` is a live WebKitWebView*. Borrowed WPEView* back.
        let wpe_view = unsafe { ffi::webkit_web_view_get_wpe_view(web_view) };
        if wpe_view.is_null() {
            // Clean up the view this code just built before failing.
            // SAFETY: `web_view` is owned here, rc=1.
            unsafe { ffi::g_object_unref(web_view.cast::<c_void>()) };
            return Err(SessionError::NoWpeView);
        }

        // Install the cursor recorder on this view's class so a page's cursor
        // request (a `set_cursor_from_name` vfunc call) is captured for the
        // host. Idempotent - a second session reuses the installed pointer.
        // SAFETY: `wpe_view` is a live WPEView*.
        unsafe { crate::ffi::cursor::install_cursor_recorder(wpe_view) };
        // SAFETY: the live view owns the completion observer and its counter.
        unsafe { crate::ffi::presentation::enzui_wpe_observe_frames(wpe_view) };

        // Install the a11y plug-id recorder BEFORE anything loads. `bind` is
        // called once, when the WebProcess publishes its accessible tree;
        // installing after a load would miss it entirely.
        // SAFETY: `wpe_view` is live; the accessible is borrowed from it.
        let accessible = unsafe { ffi::wpe_view_get_accessible(wpe_view) };
        if !accessible.is_null() {
            // SAFETY: `accessible` is a live WPEViewAccessible*.
            unsafe { crate::ffi::a11y::install_bind_recorder(accessible) };
        }

        let proxy_authentication =
            match ProxyAuthenticationBinding::install(web_view, network_session.as_ref()) {
                Ok(binding) => binding,
                Err(signal) => {
                    unsafe { ffi::g_object_unref(web_view.cast::<c_void>()) };
                    return Err(SessionError::NativeSignalBindFailed(signal));
                }
            };

        let termination_state = Box::into_raw(Box::new(TerminationState {
            reason: std::cell::Cell::new(None),
            count: std::cell::Cell::new(0),
        }));
        // SAFETY: callback signature matches `(WebKitWebView*, reason, data)`;
        // the box remains live until Drop disconnects the returned handler.
        let callback: extern "C" fn() = unsafe {
            core::mem::transmute::<
                extern "C" fn(*mut ffi::WebKitWebView, c_int, *mut c_void),
                extern "C" fn(),
            >(on_web_process_terminated)
        };
        // a zero handler id means WebKit did not connect the signal
        // (unknown/renamed), so `web-process-terminated` would never fire and
        // Drop's `g_signal_handler_disconnect(_, 0)` would be a silent no-op.
        // Refuse construction, freeing the state box and the view this code builts.
        // SAFETY: `web_view` owns the signal; the callback matches its ABI;
        // `termination_state` outlives every firing (freed only in Drop or on
        // this rollback path).
        let termination_handler = match unsafe {
            crate::ffi::signal::connect_checked(
                web_view.cast::<c_void>(),
                "web-process-terminated",
                callback,
                termination_state.cast::<c_void>(),
            )
        } {
            Ok(id) => id,
            Err(err) => {
                // SAFETY: recover and drop the box this code just minteds; nothing
                // else references it yet.
                drop(unsafe { Box::from_raw(termination_state) });
                drop(proxy_authentication);
                // SAFETY: `web_view` is owned here, rc=1, not yet handed to a
                // WebSession.
                unsafe { ffi::g_object_unref(web_view.cast::<c_void>()) };
                return Err(SessionError::NativeSignalBindFailed(err.signal));
            }
        };

        let session = WebSession {
            web_view,
            profile,
            network_session: Some(network_session),
            wpe_view,
            gpu_presentation: None,
            accessible,
            termination_state,
            termination_handler,
            proxy_authentication,
            native_policy: None,
            destination_policy,
            ime: None,
            bound_view: None,
            page_copy_serial: std::cell::Cell::new(0),
            favicon_identity: Rc::new(std::cell::Cell::new(None)),
            favicon_lifetime: Rc::new(()),
            native_authority: crate::page_delivery::NativeActionAuthority::new(),
            sandbox_baseline,
            attested_renderer: std::cell::Cell::new(None),
            attested_after_terminations: std::cell::Cell::new(0),
            renderer_liveness: std::cell::RefCell::new(None),
            sandbox_policy: outer,
            snapshot_selection: true,
            last_viewport_request: None,
            inspector: std::cell::RefCell::new(None),
            page_hub: std::rc::Rc::default(),
            pdf_exports: Default::default(),
            page: None,
            _not_send_sync: PhantomData,
        };
        let registry = session.pdf_exports.clone();
        session
            .page_hub
            .set_export_canceller(std::rc::Rc::new(move || registry.cancel_all()));
        Ok(session)
    }

    /// Spawn this view's renderer on inert content and attest it.
    ///
    /// Fail-closed in both directions: a bootstrap that does not finish is
    /// treated as "a renderer may exist and cannot be vouched for", so the
    /// renderer is terminated (and the termination verified) before the error
    /// is returned.
    fn bootstrap_and_attest(&self) -> Result<(), SessionError> {
        let bootstrap = CString::new(INERT_BOOTSTRAP_URL).expect("static, no NUL");
        // the inert bootstrap is the one load the destination policy
        // does not judge, because it fetches nothing. The allowance is a
        // single-use, private capability for exactly `INERT_BOOTSTRAP_URL`,
        // handed out here and consumed by the navigation callback - not a
        // scheme exemption a page could reuse.
        self.permit_inert_load(INERT_BOOTSTRAP_URL);
        let finished = run_load_on_view(self.web_view, &bootstrap, BOOTSTRAP_DEADLINE_MS);
        if let Err(error) = finished {
            let subject = super::attest_native_view(
                self.web_view,
                &self.sandbox_baseline,
                self.sandbox_policy,
            )
            .subject();
            let _ = self.terminate_and_verify(subject);
            return Err(match error {
                SessionError::Timeout(_) => SessionError::Timeout("bootstrap"),
                other => other,
            });
        }
        // Caller content must wait for the native credential hook, even when
        // its ready message arrives after the inert document finished loading.
        if !super::ready_wait::wait_until_ready(
            std::time::Duration::from_millis(100),
            || {
                self.native_policy
                    .as_ref()
                    .is_some_and(crate::ffi::policy::NativePolicyBinding::credential_guard_ready)
            },
            || self.pump(5),
        ) {
            let subject = super::attest_native_view(
                self.web_view,
                &self.sandbox_baseline,
                self.sandbox_policy,
            )
            .subject();
            let _ = self.terminate_and_verify(subject);
            return Err(SessionError::CredentialGuardUnavailable(
                "WebProcess did not acknowledge the WebKitWebPage::send-request hook".into(),
            ));
        }
        self.attest_and_enforce(SANDBOX_ATTESTATION_BUDGET_MS)?;
        self.mark_bootstrap_history();
        Ok(())
    }

    fn attest_and_enforce(
        &self,
        budget_ms: u64,
    ) -> Result<crate::sandbox::SandboxAttestation, SessionError> {
        let verdict = super::await_scoped_attestation(
            self.web_view,
            self.sandbox_policy,
            &self.sandbox_baseline,
            budget_ms,
        );
        self.enforce_attestation(verdict)
    }

    fn enforce_attestation(
        &self,
        verdict: crate::sandbox::SandboxAttestation,
    ) -> Result<crate::sandbox::SandboxAttestation, SessionError> {
        let decision = crate::sandbox::enforcement_decision_with_outer(
            &verdict,
            self.sandbox_policy,
            crate::sandbox::detect_container_now(),
        );
        match decision {
            Ok(()) => {
                self.attested_renderer.set(verdict.subject());
                // SAFETY: the state box lives with `self` on this thread.
                self.attested_after_terminations
                    .set(unsafe { (*self.termination_state).count.get() });
                *self.renderer_liveness.borrow_mut() = verdict
                    .subject()
                    .filter(|_| {
                        !std::env::var_os("ENZUI_WEBKIT_STAT_LIVENESS")
                            .is_some_and(|value| value == "0")
                    })
                    .and_then(crate::sandbox::process_liveness::ProcessLiveness::new);
                Ok(verdict)
            }
            Err(reason) => {
                self.attested_renderer.set(None);
                self.renderer_liveness.borrow_mut().take();
                match self.terminate_and_verify(verdict.subject()) {
                    Ok(()) => Err(SessionError::SandboxNotAttested(reason)),
                    Err(why) => Err(SessionError::SandboxTerminationUnverified { reason, why }),
                }
            }
        }
    }

    /// Terminate this view's renderer and verify it stopped, within
    /// `budget_ms`.
    ///
    /// The public form of the enforcement side effect. `Ok` means two things
    /// were observed - the attested renderer identity is gone from `/proc`, and
    /// WebKit delivered `web-process-terminated` for this view - not merely
    /// that the void API was called.
    ///
    /// # Errors
    ///
    /// What could not be shown; the caller must not assume the renderer is
    /// gone.
    /// The verification half of
    /// [`terminate_web_process_verified_within`](Self::terminate_web_process_verified_within)
    /// alone, for a live renderer that nothing terminated: it must fail. That
    /// is the gate's proof that the verification reads the two facts rather
    /// than assuming them.
    #[cfg(feature = "sandbox-test-entrypoints")]
    pub fn await_renderer_termination_without_terminating_for_negative_control(
        &self,
        budget_ms: u64,
    ) -> Result<(), String> {
        super::await_termination(
            Some(self.termination_state),
            self.attested_renderer.get(),
            budget_ms,
        )
    }

    pub fn terminate_web_process_verified_within(&self, budget_ms: u64) -> Result<(), String> {
        terminate_and_verify_view(
            self.web_view,
            Some(self.termination_state),
            self.attested_renderer.get(),
            budget_ms,
        )
    }

    /// [`terminate_web_process_verified_within`](Self::terminate_web_process_verified_within)
    /// with the standard budget.
    ///
    /// # Errors
    ///
    /// As above.
    pub fn terminate_web_process_verified(&self) -> Result<(), String> {
        self.terminate_web_process_verified_within(SANDBOX_TERMINATION_BUDGET_MS)
    }

    /// Terminate this view's renderer and verify both the kernel fact and
    /// WebKit's own `web-process-terminated` signal for this view.
    fn terminate_and_verify(
        &self,
        subject: Option<crate::sandbox::ProcessIdentity>,
    ) -> Result<(), String> {
        terminate_and_verify_view(
            self.web_view,
            Some(self.termination_state),
            subject,
            SANDBOX_TERMINATION_BUDGET_MS,
        )
    }

    /// The single gate every navigation passes through.
    ///
    /// `load`, `begin_load_uri` and the policy layer's certificate retry all
    /// call this before caller-chosen content is fetched: the attested renderer
    /// must still be the same live process. If it died (a crash, or an earlier
    /// enforced termination) a fresh renderer is spawned on inert content and
    /// attested before the navigation is allowed - never after.
    ///
    /// # Errors
    ///
    /// [`SessionError::SandboxNotEstablished`] when no isolated renderer can be
    /// established, or the enforcement error from attestation.
    pub fn require_navigable(&self) -> Result<(), SessionError> {
        if let Some(identity) = self.attested_renderer.get()
            && !self.renderer_is_gone(identity)
        {
            return Ok(());
        }
        // Cross-site swaps retire the attested renderer without reporting a loss;
        // attest the current page before replacing its document.
        // SAFETY: the state box lives with `self` on this thread.
        let lost_since_attestation = unsafe { (*self.termination_state).count.get() }
            != self.attested_after_terminations.get();
        if self.attested_renderer.get().is_some()
            && !lost_since_attestation
            && self
                .attest_and_enforce(SANDBOX_ATTESTATION_BUDGET_MS)
                .is_ok()
        {
            return Ok(());
        }
        self.bootstrap_and_attest().map_err(|e| match e {
            SessionError::SandboxNotAttested(reason) => SessionError::SandboxNotEstablished(reason),
            other => other,
        })
    }

    /// The app-owned profile identity bound at construction, or `None` for a
    /// low-level session created with [`WebSession::new`].
    #[must_use]
    pub fn profile(&self) -> Option<&crate::web::WebProfile> {
        self.profile.as_ref()
    }

    /// Bind this session to its own [`ViewId`](crate::web::ViewId)
    ///
    /// The host does this once, with the router-minted id for this session's
    /// slot. From then on, page-accessibility delivery and routed actions are
    /// accepted only under this exact id: a call naming another session's
    /// id - even a live one - is refused before any work happens, so one
    /// session cannot publish its tree, or perform an action, under another's
    /// identity.
    ///
    /// # Binding is one-time, and rebinding is owned recovery only
    ///
    /// The router must consider `view` live; a stale or unknown id is refused.
    /// Beyond the first bind, the only legal rebind is owned recovery: the
    /// same slot advanced to a new generation *after the previously-bound
    /// generation has died*. Every other rebind is refused:
    ///
    /// * rebinding the exact same id is an idempotent no-op;
    /// * rebinding to a different slot is [`SessionError::ForeignRebind`] -
    ///   the arbitrary reassignment that would let session A adopt session B's
    ///   identity even though both are live;
    /// * rebinding to a new generation while the old one is still live is
    ///   [`SessionError::RebindWhileLive`] - a reassignment dressed up as a
    ///   recovery, refused because nothing died.
    ///
    /// This makes the ordinary crash path
    /// ([`recover_after_termination`](Self::recover_after_termination), which
    /// sets the binding directly) and a same-slot generation advance the only
    /// ways a binding ever changes.
    pub fn bind_view(
        &mut self,
        router: &crate::web::ViewRouter,
        view: crate::web::ViewId,
    ) -> Result<(), SessionError> {
        if !router.accepts(view) {
            return Err(SessionError::PolicyViewGone);
        }
        match self.bound_view {
            None => {
                self.bound_view = Some(view);
                self.favicon_identity.set(Some(view));
                if let Some(binding) = &self.gpu_presentation {
                    binding.set_view(view);
                }
                Ok(())
            }
            Some(current) if current == view => Ok(()),
            Some(current) => {
                if current.slot() != view.slot() {
                    return Err(SessionError::ForeignRebind);
                }
                // Same slot, different generation: legal only if the old
                // generation is gone. If the router still accepts it, this is a
                // reassignment, not a recovery.
                if router.accepts(current) {
                    return Err(SessionError::RebindWhileLive);
                }
                self.bound_view = Some(view);
                self.favicon_identity.set(Some(view));
                if let Some(binding) = &self.gpu_presentation {
                    binding.set_view(view);
                }
                Ok(())
            }
        }
    }

    /// This session's bound [`ViewId`](crate::web::ViewId), if any.
    #[must_use]
    pub fn bound_view(&self) -> Option<crate::web::ViewId> {
        self.bound_view
    }

    /// Forward a live widget viewport size to this view's WPE toplevel.
    ///
    /// `size` is already a positive, `gint`-representable integer logical size
    /// because it can only be built by
    /// [`ViewportSize::from_logical`](crate::viewport::ViewportSize::from_logical).
    /// The request must name this session's exact live [`ViewId`](crate::web::ViewId); a stale
    /// resize queued before crash recovery cannot affect its replacement.
    /// Repeated reports of the same integer size are suppressed before the FFI
    /// call, while the same size under a new generation is forwarded again.
    ///
    /// # Errors
    ///
    /// Returns [`ViewportResizeError::ViewNotBound`],
    /// [`ViewportResizeError::ForeignSession`] or
    /// [`ViewportResizeError::ViewNotLive`] before touching WPE when ownership
    /// is invalid. A missing toplevel or backend refusal is also reported
    /// rather than pretending the page adopted the requested viewport.
    pub fn resize_viewport(
        &mut self,
        router: &crate::web::ViewRouter,
        view: crate::web::ViewId,
        size: crate::viewport::ViewportSize,
    ) -> Result<ViewportResize, ViewportResizeError> {
        let bound = self.bound_view.ok_or(ViewportResizeError::ViewNotBound)?;
        if bound != view {
            return Err(ViewportResizeError::ForeignSession { bound, asked: view });
        }
        if !router.accepts(view) {
            return Err(ViewportResizeError::ViewNotLive { view });
        }
        if self.last_viewport_request == Some((view, size)) {
            return Ok(ViewportResize::Unchanged);
        }

        // SAFETY: `self.wpe_view` is live for the session. The returned
        // toplevel is borrowed from it and used only for this synchronous call.
        let toplevel = unsafe { ffi::wpe_view_get_toplevel(self.wpe_view) };
        if toplevel.is_null() {
            return Err(ViewportResizeError::NoToplevel);
        }
        // WPE 2.52 `wpe_toplevel_resize` returns FALSE for two distinct cases:
        // "resize is not supported" and "the requested dimensions already
        // equal the current size". Read the current size first so an initial
        // request that happens to match WPE's default (headless: 1024x768)
        // reports `Unchanged` rather than being falsely mapped to
        // `Unsupported`. Only a genuine differing-size refusal is
        // `Unsupported` after this check.
        let mut current_w: c_int = 0;
        let mut current_h: c_int = 0;
        // SAFETY: `toplevel` is a live borrowed WPEToplevel*; the two int
        // out-parameters are stack locals owned here.
        unsafe { ffi::wpe_toplevel_get_size(toplevel, &mut current_w, &mut current_h) };
        // Record the attempted generation+size before returning, so a caller
        // whose viewport already matches WPE does not re-read `get_size` on
        // every redraw; a genuinely new size that appears later still bypasses
        // this cache and reaches `resize`.
        self.last_viewport_request = Some((view, size));
        if current_w == size.width() && current_h == size.height() {
            return Ok(ViewportResize::Unchanged);
        }
        // SAFETY: `toplevel` is a live borrowed WPEToplevel; `ViewportSize`
        // guarantees positive dimensions representable by the C `gint` ABI.
        let accepted =
            unsafe { ffi::wpe_toplevel_resize(toplevel, size.width(), size.height()) != 0 };
        if accepted {
            Ok(ViewportResize::Requested)
        } else {
            Err(ViewportResizeError::Unsupported)
        }
    }

    /// Whether this view still owns an explicit network session. Exposed as a
    /// narrow observable for lifecycle tests; the raw pointer is never public.
    #[must_use]
    pub fn has_explicit_network_session(&self) -> bool {
        self.network_session.is_some()
    }

    /// Attest that the WebProcesses this process spawned were reached through
    /// WebKit's bubblewrap launcher and have their own namespaces.
    ///
    /// [`WebSession::new`] refuses to start when the environment has *asked*
    /// for a weaker sandbox; this reports what the kernel actually did. The two
    /// are different claims - an environment variable is an intention, a mount
    /// namespace is a fact - and only the second survives a WebKit build
    /// without `bwrap`, a container where bubblewrap silently fails, or a
    /// future engine that stops sandboxing for some other reason.
    ///
    /// Before the first page load there is no WebProcess yet, so the honest
    /// answer is [`crate::sandbox::UnattestedReason::WebProcessNotFound`]
    /// rather than a premature pass. See
    /// [`SandboxAttestation::BubblewrapIsolated`](crate::sandbox::SandboxAttestation::BubblewrapIsolated)
    /// for what the positive verdict does not claim.
    ///
    /// Attestation is per process, not per session: WebKit shares one
    /// WebProcess pool across the views in an application, so the verdict
    /// covers every renderer this process owns and takes the worst one.
    ///
    /// Reads `/proc`: blocking I/O, not for a per-frame path.
    #[must_use]
    pub fn attest_sandbox(&self) -> crate::sandbox::SandboxAttestation {
        super::attest_native_view(self.web_view, &self.sandbox_baseline, self.sandbox_policy)
    }

    /// The renderer identity this session last attested, if any.
    #[must_use]
    pub fn attested_renderer(&self) -> Option<crate::sandbox::ProcessIdentity> {
        self.attested_renderer.get()
    }

    /// The outer-sandbox policy this session was constructed under.
    #[must_use]
    pub fn sandbox_policy(&self) -> crate::sandbox::OuterSandbox {
        self.sandbox_policy
    }

    /// Require an isolated renderer, and terminate it if that cannot be
    /// shown.
    ///
    /// This is the post-spawn half of the policy. The preflight can only refuse
    /// what the environment announces; a renderer that ends up unsandboxed for
    /// any other reason - WebKit built without `ENABLE(BUBBLEWRAP_SANDBOX)`, a
    /// container where its bwrap probe failed, a user-namespace policy that
    /// blocked the unshare - is caught only here. On failure the WebProcess is
    /// terminated before the error is returned, so an unattested renderer does
    /// not keep running with a live page in it.
    ///
    /// A renderer may take a moment to appear after a load completes, so the
    /// "not found yet" case is polled within `budget_ms`; every other
    /// non-attestation is immediate.
    ///
    /// # Errors
    ///
    /// [`SessionError::SandboxNotAttested`] with the reason.
    pub fn require_isolated_web_process(
        &self,
        budget_ms: u64,
    ) -> Result<crate::sandbox::SandboxAttestation, SessionError> {
        self.attest_and_enforce(budget_ms)
    }

    /// The last termination reason delivered by WebKit for this view.
    #[must_use]
    pub fn web_process_termination(&self) -> Option<WebProcessTermination> {
        // SAFETY: the state box lives with `self` and callbacks run on this
        // same main-context thread.
        unsafe { (*self.termination_state).reason.get() }
    }

    /// Ask WebKit to terminate this view's WebProcess. Production crash and
    /// OOM termination reach the same observed signal; this explicit path is
    /// also useful for controlled restarts and deterministic recovery tests.
    pub fn terminate_web_process(&self) {
        // SAFETY: `web_view` is live for `self`'s lifetime.
        unsafe { ffi::webkit_web_view_terminate_web_process(self.web_view) };
    }

    /// Reconstruct a terminated profiled view on the same storage identity,
    /// preserving direct GPU presentation when enabled.
    ///
    /// Construction happens before replacement, so a failure leaves the dead
    /// session and router generation available for diagnostics. On success the
    /// router is advanced at the same boundary as the native replacement; late
    /// events carrying `dead_view` are therefore stale before this returns.
    pub fn recover_after_termination(
        &mut self,
        display: &HeadlessDisplay,
        profiles: &mut crate::ffi::profile::ProfileStore,
        router: &mut crate::web::ViewRouter,
        dead_view: crate::web::ViewId,
    ) -> Result<crate::web::ViewId, SessionError> {
        if self.web_process_termination().is_none() {
            return Err(SessionError::RecoveryWhileLive);
        }
        if !router.accepts(dead_view) {
            return Err(SessionError::RecoveryViewGone);
        }
        let profile = self
            .profile
            .clone()
            .ok_or(SessionError::RecoveryRequiresProfile)?;
        // A session that owned an id keeps owning its slot across recovery, now
        // at the recreated generation: late deliveries/actions
        // naming the dead generation are refused, and the new session accepts
        // its own new id.
        let was_bound = self.bound_view.is_some();
        // The replacement inherits this session's sandbox policy AND its
        // destination policy: recovery must not quietly become a
        // stricter-or-looser session than the one it replaces. A
        // recovered session that silently reverted to the default destination
        // rule would strand a legitimately trusted-local caller after a
        // renderer crash - a fail-closed break, but a break - while the
        // reverse mistake would be a silent downgrade. Neither is acceptable,
        // so the policy is carried explicitly.
        crate::sandbox::preflight_in(&crate::sandbox::RealEnv, self.sandbox_policy)
            .map_err(SessionError::SandboxDisabled)?;
        let network_session = profiles
            .session_for_policy(&profile, self.destination_policy)
            .map_err(session_error_from_profile)?;
        let mut replacement = Self::construct(
            display,
            Some(profile.clone()),
            Some(network_session),
            self.sandbox_policy,
            self.destination_policy,
        )?;
        if self.gpu_presentation.is_some() {
            replacement.enable_gpu_presentation();
        }
        replacement
            .page_hub
            .inherit_site_permissions(&self.page_hub);
        let replacement_id = router.recreate(dead_view.slot());
        *self = replacement;
        if was_bound {
            self.bind_view(router, replacement_id)?;
        }
        Ok(replacement_id)
    }

    /// Install correlated, generation-scoped handlers for WebKit navigation,
    /// popup, response/download, permission, and TLS-certificate callbacks.
    ///
    /// The responder must echo the exact request id it was given. `None`, a
    /// stale generation, or a different request id is denied synchronously at
    /// the native callback boundary; WebKit's default handler never runs.
    /// Replacement is transactional: registration failure leaves the current
    /// policy and responder installed.
    pub fn install_native_policy<F>(
        &mut self,
        router: &crate::web::ViewRouter,
        view: crate::web::ViewId,
        policy: crate::web::WebPolicy,
        responder: F,
    ) -> Result<(), SessionError>
    where
        F: FnMut(&crate::ffi::policy::NativePolicyRequest) -> Option<crate::ViewRequestId>
            + 'static,
    {
        if !router.accepts(view) {
            return Err(SessionError::PolicyViewGone);
        }
        // the session's destination rule is authoritative. A host names
        // it once, at construction, and the guard enforces the same value at
        // the socket; a per-install destination rule could disagree with the
        // guard, and the disagreement would be silent.
        self.page_hub.cancel_site_permissions();
        let policy = policy
            .with_destination(self.destination_policy)
            .with_local_origins(self.local_origins().unwrap_or_default());
        self.page_hub.set_popup_policy(policy.clone());
        // SAFETY boundary stays inside NativePolicyBinding. The network-session
        // pointer is borrowed from this live WebView and shares its lifetime.
        let web_view = self.web_view;
        let network_session = unsafe { ffi::webkit_web_view_get_network_session(web_view) };
        let sandbox_policy = self.sandbox_policy;
        let sandbox_baseline = self.sandbox_baseline.clone();
        let page = std::rc::Rc::clone(&self.page_hub);
        crate::ffi::policy::NativePolicyBinding::replace_transactionally(
            &mut self.native_policy,
            move || {
                crate::ffi::policy::NativePolicyBinding::new(
                    web_view,
                    network_session,
                    view,
                    policy,
                    sandbox_policy,
                    sandbox_baseline,
                    responder,
                )
                .map(|binding| binding.with_page(page))
            },
        )
        .map_err(|err| SessionError::NativeSignalBindFailed(err.signal))
    }

    /// Advance the policy callback's live generation after host-authorised
    /// recreation. Responses naming the previous generation then fail closed.
    pub fn replace_native_policy_view(
        &mut self,
        router: &crate::web::ViewRouter,
        view: crate::web::ViewId,
    ) -> Result<(), SessionError> {
        if !router.accepts(view) {
            return Err(SessionError::PolicyViewGone);
        }
        self.page_hub.cancel_site_permissions();
        if let Some(binding) = &mut self.native_policy {
            binding.replace_view(view);
        }
        Ok(())
    }

    /// The destination policy this session was constructed under.
    #[must_use]
    pub fn destination_policy(&self) -> crate::web::DestinationPolicy {
        self.destination_policy
    }

    /// The loopback address of this session's destination guard, if one is
    /// enforcing.
    ///
    /// `Some` for every session, including the named
    /// [`WebSession::new_trusted_local`] address-policy opt-out. Trusted-local
    /// still needs the guard to reject credential-bearing cleartext redirects
    /// before WPE normalises their userinfo.
    #[must_use]
    pub fn destination_guard_addr(&self) -> Option<std::net::SocketAddr> {
        self.network_session
            .as_ref()
            .and_then(|session| session.destination_guard_addr())
    }

    /// The decisions this session's destination guard has made so far.
    #[must_use]
    pub fn destination_guard_events(&self) -> Vec<crate::destination_guard::GuardEvent> {
        self.network_session
            .as_ref()
            .map(|session| session.destination_guard_events())
            .unwrap_or_default()
    }

    /// Pre-trust a PEM-encoded TLS certificate for `host` on this session's
    /// network session, so the first navigation to `host` over HTTPS
    /// succeeds without waiting for a `load-failed-with-tls-errors` round
    /// trip.
    ///
    /// This exception is deliberately scoped: it applies only to
    /// the concrete certificate and only on this session, and a navigation
    /// to any other self-signed host still fails with the strict default.
    ///
    /// `host` must be the identity WebKit itself compares - a bare host, no
    /// scheme, userinfo, path, query, fragment or port. IPv6 must be bare:
    /// bracketed IPv6 is refused by this public pre-trust API; only the internal
    /// URL-callback adapter strips brackets from a parsed URL authority. It is
    /// validated by the same
    /// [`crate::ffi::policy::certificate_authorization_host`] parser the native
    /// TLS callback reaches, before any native call: an
    /// exception installed under
    /// a string WebKit can never ask for is a silent no-op advertised as
    /// pre-trust, so it is refused instead. Every outcome - installation or
    /// refusal - is appended to this session's certificate ledger
    /// ([`WebSession::native_certificate_ledger`]).
    ///
    /// # Errors
    ///
    /// [`SessionError::TlsCertificateError`] if `host` is not a possible
    /// WebKit request host, or if GLib cannot parse the PEM.
    pub fn allow_tls_certificate_for_host(
        &self,
        pem: &[u8],
        host: &str,
    ) -> Result<(), SessionError> {
        let network_session = self
            .network_session
            .as_ref()
            .ok_or_else(|| SessionError::TlsCertificateError("no network session".into()))?;
        // Host identity FIRST: an unusable identity performs no native work at
        // all, not even a PEM parse.
        let (identity, key) = match crate::ffi::policy::certificate_authorization_identity(host) {
            Ok(pair) => pair,
            Err(invalid) => {
                if let Some(binding) = self.native_policy.as_ref() {
                    binding.record_pre_trust(crate::ffi::policy::PreTrustEvent {
                        host: String::new(),
                        key: String::new(),
                        outcome: crate::ffi::policy::PreTrustOutcome::HostDenied(invalid),
                    });
                }
                return Err(SessionError::TlsCertificateError(invalid.as_str().into()));
            }
        };
        let mut error: *mut ffi::GError = core::ptr::null_mut();
        // SAFETY: `pem` is valid for `pem.len()` bytes; `error` receives a
        // heap-allocated GError on failure that this code frees below.
        let cert = unsafe {
            ffi::g_tls_certificate_new_from_pem(
                pem.as_ptr().cast::<std::ffi::c_char>(),
                pem.len() as isize,
                &mut error,
            )
        };
        if cert.is_null() {
            let message = if !error.is_null() {
                let msg = unsafe { std::ffi::CStr::from_ptr((*error).message) }
                    .to_string_lossy()
                    .into_owned();
                unsafe { ffi::g_error_free(error) };
                msg
            } else {
                "unknown PEM parse error".into()
            };
            if let Some(binding) = self.native_policy.as_ref() {
                binding.record_pre_trust(crate::ffi::policy::PreTrustEvent {
                    host: String::new(),
                    key: String::new(),
                    outcome: crate::ffi::policy::PreTrustOutcome::CertificateDenied,
                });
            }
            return Err(SessionError::TlsCertificateError(message));
        }
        // The validated identity, byte-for-byte: the parser accepted no NUL,
        // no port and no URL spelling, and folded nothing (a trailing DNS-root
        // dot is part of what WebKit compares).
        let c_host = std::ffi::CString::new(identity.as_str()).map_err(|_| {
            // SAFETY: cert is a GObject with rc=1.
            unsafe { ffi::g_object_unref(cert.cast::<std::ffi::c_void>()) };
            SessionError::TlsCertificateError("host contains NUL".into())
        })?;
        // SAFETY: `network_session.as_ptr()` is a live WebKitNetworkSession*;
        // `cert` is a live GTlsCertificate* owned here; `c_host` is NUL-terminated.
        unsafe {
            ffi::webkit_network_session_allow_tls_certificate_for_host(
                network_session.as_ptr(),
                cert,
                c_host.as_ptr(),
            );
            ffi::g_object_unref(cert.cast::<std::ffi::c_void>());
            crate::ffi::policy::exceptions::record(network_session.as_ptr(), &identity);
        }
        if let Some(binding) = self.native_policy.as_ref() {
            binding.record_pre_trust(crate::ffi::policy::PreTrustEvent {
                host: identity,
                key,
                outcome: crate::ffi::policy::PreTrustOutcome::Installed,
            });
        }
        Ok(())
    }

    /// Install the constructor's default native policy binding.
    ///
    /// `WebPolicy::strict()` carrying this session's destination rule, with a
    /// responder that echoes the request id: the typed policy decides, and
    /// WebKit's permissive default handler never runs, whether or not the host
    /// later calls [`WebSession::install_native_policy`].
    fn install_default_native_policy(&mut self) -> Result<(), SessionError> {
        let policy = crate::web::WebPolicy::strict()
            .with_destination(self.destination_policy)
            .with_local_origins(self.local_origins().unwrap_or_default());
        // SAFETY: borrowed from this live view, shares its lifetime.
        let network_session = unsafe { ffi::webkit_web_view_get_network_session(self.web_view) };
        self.native_policy = Some(
            crate::ffi::policy::NativePolicyBinding::new(
                self.web_view,
                network_session,
                crate::web::ViewId::new(DEFAULT_POLICY_SLOT),
                policy,
                self.sandbox_policy,
                self.sandbox_baseline.clone(),
                |request| Some(request.id),
            )
            .map_err(|err| SessionError::NativeSignalBindFailed(err.signal))?
            .with_page(std::rc::Rc::clone(&self.page_hub)),
        );
        Ok(())
    }

    /// Hand the native policy binding a single-use allowance for one exact
    /// inert URL. Private: no caller outside this module can mint one.
    fn permit_inert_load(&self, url: &str) {
        if let Some(binding) = self.native_policy.as_ref() {
            binding.permit_inert_load(url);
        }
    }

    /// The decisions this session's destination guard has made so far, and how
    /// many entries the bounded log dropped. The guard's log is bounded for the
    /// same reason as the observation ring.
    #[must_use]
    pub fn destination_guard_dropped(&self) -> u64 {
        self.network_session
            .as_ref()
            .map(|session| session.destination_guard_dropped())
            .unwrap_or(0)
    }

    /// The destination screen every host-initiated load passes.
    ///
    /// Inert host-supplied content (`about:blank`, `data:`) is not a network
    /// destination: it is permitted, but only through a single-use permit tied
    /// to that exact URL, so a page cannot navigate itself to one. Everything
    /// else is judged by this session's [`DestinationPolicy`], refusing before
    /// WebKit has been asked to do anything.
    ///
    /// # Errors
    ///
    /// [`SessionError::DestinationRefused`] naming the rule that refused.
    pub(super) fn screen_host_load(&self, url: &str) -> Result<(), SessionError> {
        if crate::ffi::runtime::is_inert_url(url) {
            self.pdf_exports.cancel_all();
            self.page_hub.cancel_site_permissions();
            self.permit_inert_load(url);
            return Ok(());
        }
        self.local_origins()
            .unwrap_or_default()
            .policy_for_url(self.destination_policy, url)
            .screen_request(url)
            .map(|_| {
                self.pdf_exports.cancel_all();
                self.page_hub.cancel_site_permissions();
            })
            .map_err(SessionError::DestinationRefused)
    }

    /// Native callback observations accumulated by the installed policy.
    ///
    /// Returns an owned snapshot of the bounded observation ring; call
    /// [`crate::ffi::policy::BoundedObservations::dropped`] to learn how many
    /// older entries were evicted.
    #[must_use]
    pub fn native_policy_observations(&self) -> Option<crate::ffi::policy::BoundedObservations> {
        self.native_policy
            .as_ref()
            .map(|binding| binding.observations())
    }
    /// An owned snapshot of bounded diagnostics for this session's native
    /// TLS-certificate path.
    ///
    /// The observation ring says what policy decided. This says whether
    /// WebKit's `load-failed-with-tls-errors` callback was registered at all,
    /// how many times it fired, which terminal native action each firing
    /// applied, and which non-TLS load failures WebKit reported instead - the
    /// evidence needed to tell an unwired certificate callback from an origin
    /// that produced no certificate error.
    #[must_use]
    pub fn native_certificate_ledger(&self) -> Option<crate::ffi::policy::CertificateLedger> {
        self.native_policy
            .as_ref()
            .map(|binding| binding.certificate_ledger())
    }

    /// Start an asynchronous URI load without entering a nested main loop.
    /// This is the worker-facing form used when policy callbacks must run and
    /// be answered while a navigation is pending; drive it with [`Self::pump`].
    pub fn begin_load_uri(&self, uri: &str) -> Result<(), SessionError> {
        // was `SessionError::SnapshotFailed`, which named the wrong
        // failure - nothing had been snapshotted. A rejected URL now has its
        // own variant, shared with `load` and `snapshot_data_url`, so all three
        // report the same condition the same way.
        let uri_c = url_to_cstring(uri).map_err(SessionError::InvalidUrl)?;
        // the same destination screen `load` performs.
        self.screen_host_load(uri)?;
        let uri = uri_c;
        // the same gate `load` passes. This entry point starts a real
        // navigation to caller-chosen content, so it may not skip enforcement
        // merely because it does not run a nested loop.
        self.require_navigable()?;
        self.page_hub.begin_host_navigation();
        // SAFETY: a live view and a NUL-terminated URI.
        unsafe { ffi::webkit_web_view_load_uri(self.web_view, uri.as_ptr()) };
        Ok(())
    }

    /// Start loading a host-supplied HTML document without entering a nested
    /// main loop: the asynchronous form of [`Self::load_html`] for hosts that
    /// already drive [`Self::pump`] and page events.
    ///
    /// The document and `base_uri` pass the same checks as `load_html`, and
    /// the same enforcement as [`Self::begin_load_uri`] applies before WebKit
    /// is pointed at it. Completion and failure arrive as page events; the
    /// document bytes never pass the URL policy scanner.
    ///
    /// # Errors
    ///
    /// [`SessionError::InvalidDocument`] past
    /// [`MAX_HTML_DOCUMENT_BYTES`] or for a
    /// NUL byte, otherwise as [`Self::begin_load_uri`].
    pub fn begin_load_html(&self, html: &str, base_uri: &str) -> Result<(), SessionError> {
        let invalid = SessionError::InvalidDocument {
            size: html.len(),
            limit: MAX_HTML_DOCUMENT_BYTES,
        };
        if html.len() > MAX_HTML_DOCUMENT_BYTES {
            return Err(invalid);
        }
        let content = CString::new(html).map_err(|_| invalid)?;
        let base_c = url_to_cstring(base_uri).map_err(SessionError::InvalidUrl)?;
        self.screen_host_load(base_uri)?;
        self.require_navigable()?;
        self.page_hub.begin_host_navigation();
        // SAFETY: a live view; WebKit copies both NUL-terminated strings.
        unsafe {
            ffi::webkit_web_view_load_html(self.web_view, content.as_ptr(), base_c.as_ptr());
        }
        Ok(())
    }

    /// The URI WebKit currently reports for this view.
    ///
    /// A page controls this URI through navigation, redirects and the history
    /// API, so the native bytes are read through the shared bounded scanner
    /// (`scan_bounded_native_uri`) rather than an
    /// unbounded NUL scan. A URI longer than
    /// [`MAX_POLICY_URI_BYTES`](crate::ffi::policy::MAX_POLICY_URI_BYTES) is
    /// refused with a typed outcome before it becomes a Rust allocation and is
    /// never silently truncated. A null URI (no load has started) stays
    /// `Ok(None)`.
    ///
    /// # Errors
    ///
    /// [`NativeUriError::TooLong`](crate::ffi::policy::NativeUriError::TooLong)
    /// when the URI exceeds the byte ceiling and
    /// [`NativeUriError::InvalidUtf8`](crate::ffi::policy::NativeUriError::InvalidUtf8)
    /// when the bounded bytes are not valid UTF-8.
    pub fn current_uri(&self) -> Result<Option<String>, crate::ffi::policy::NativeUriError> {
        // SAFETY: a live view; WebKit ties the returned URI to the view and the
        // shared scanner copies (or refuses) it before this returns.
        let uri = unsafe { ffi::webkit_web_view_get_uri(self.web_view) };
        // SAFETY: `uri` is null or a readable NUL-terminated string borrowed
        // from the live view for the duration of this call.
        unsafe { current_uri_from_native(uri) }
    }

    /// Whether this view's network session continues past a failed
    /// certificate for `host`, a URL host (bracketed IPv6 accepted). Such an
    /// exception covers every view sharing the network session until the
    /// session is dropped.
    #[must_use]
    pub fn has_certificate_exception(&self, host: &str) -> bool {
        // SAFETY: a live view on the owning thread; the borrowed session is
        // live for as long as the view.
        unsafe {
            let session = ffi::webkit_web_view_get_network_session(self.web_view);
            crate::ffi::policy::exceptions::contains(session, host)
        }
    }

    /// Read a cheap per-session revision without copying native property strings.
    ///
    /// A changed revision requires resampling the complete metadata snapshot.
    /// It does not replace the live IME or focus reports.
    pub fn page_metadata_revision(&self) -> PageMetadataRevision {
        PageMetadataRevision {
            page: self.page_hub.metadata_revision(),
            cursor: crate::ffi::cursor::cursor_revision_for(self.wpe_view),
            failures: self.page_hub.load_failure_revision(),
        }
    }

    /// The borrowed `WPEView*`. Exposed so a test can assert it is non-NULL -
    /// the load-bearing proof that input has somewhere real to go.
    #[must_use]
    pub fn wpe_view_is_present(&self) -> bool {
        !self.wpe_view.is_null()
    }

    /// The cursor name the page has most recently requested for this view, or
    /// `None` if none has been requested yet. This is the host-side seam a
    /// widget uses to render the page's cursor (e.g. `"pointer"` over a link,
    /// `"text"` over an input, `"default"` elsewhere). Populated by the WPE
    /// `set_cursor_from_name` vfunc when the pointer moves over styled content.
    #[must_use]
    pub fn requested_cursor(&self) -> Option<String> {
        crate::ffi::cursor::last_cursor_for(self.wpe_view)
    }

    /// Copies WebKit's borrowed `document.title` without an unbounded scan.
    ///
    /// The native title is a NUL-terminated C string that WebKit owns; the
    /// pointer is scanned to the first NUL through at most
    /// [`MAX_PAGE_TITLE_BYTES`] plus one bytes before any Rust allocation, and
    /// a title over that ceiling is refused rather than truncated. Invalid
    /// native bytes decode lossily; the worst-case owned length is described on
    /// [`MAX_PAGE_TITLE_BYTES`].
    ///
    /// # Errors
    ///
    /// Returns [`PageTitleError::TooLong`] when the bounded scan reached
    /// [`MAX_PAGE_TITLE_BYTES`] plus one non-NUL bytes.
    ///
    /// [`MAX_PAGE_TITLE_BYTES`]: crate::ffi::runtime::MAX_PAGE_TITLE_BYTES
    /// [`PageTitleError::TooLong`]: crate::ffi::runtime::PageTitleError::TooLong
    // `Result` already carries `#[must_use]`; `double_must_use` forbids doubling it.
    pub fn page_title(&self) -> Result<Option<String>, PageTitleError> {
        // SAFETY: live view; WebKit retains the returned pointer.
        let raw = unsafe { ffi::webkit_web_view_get_title(self.web_view) };
        // SAFETY: WebKit returns null or a readable NUL-terminated string
        // borrowed from the live view for this call.
        unsafe { page_title_from_native(raw) }
    }

    /// Whether the platform exposed an accessibility object for this view.
    /// False means no a11y implementation at all, which is a finding rather
    /// than something to paper over.
    #[must_use]
    pub fn has_accessible(&self) -> bool {
        !self.accessible.is_null()
    }

    /// The AT-SPI plug id the WebProcess published for this view's accessible
    /// tree, or `None` if `bind` has not been called yet.
    ///
    /// The tree itself is not in this process - this identifier
    /// (`<dbus-name>:<object-path>`) addresses the real root in the sandboxed
    /// WebProcess over the AT-SPI bus. See [`crate::ffi::a11y`].
    #[must_use]
    pub fn accessibility_plug_id(&self) -> Option<String> {
        if self.accessible.is_null() {
            return None;
        }
        crate::ffi::a11y::plug_id_for(self.accessible)
    }

    /// Read the page's accessible tree across the process seam.
    ///
    /// Connects to the AT-SPI bus, resolves this view's published plug id, and
    /// walks the remote tree (bounded by `max_depth` / `max_nodes`).
    ///
    /// # Errors
    ///
    /// [`crate::ffi::a11y::A11yError::NoAccessible`] if the platform exposes
    /// none, [`crate::ffi::a11y::A11yError::NotBound`] if the WebProcess never
    /// published a tree, or a bus/call error. Each is a loud typed refusal -
    /// none of them degrade to an empty tree, which would be indistinguishable
    /// from a page with no content.
    pub fn accessibility_tree(
        &self,
        max_depth: usize,
        max_nodes: usize,
    ) -> Result<crate::ffi::a11y::A11yNode, crate::ffi::a11y::A11yError> {
        use crate::ffi::a11y;
        if self.accessible.is_null() {
            return Err(a11y::A11yError::NoAccessible);
        }
        let plug = a11y::plug_id_result_for(self.accessible).ok_or(a11y::A11yError::NotBound)??;
        let (bus_name, path) = a11y::split_plug_id(&plug)?;
        let bus = a11y::A11yBus::connect()?;
        bus.walk(&bus_name, &path, max_depth, max_nodes)
    }

    /// Walk this session's page and hand the translated tree to `delivery`,
    /// tagged with the [`ViewId`](crate::web::ViewId) that produced
    /// it.
    ///
    /// # Why the native path goes through the delivery owner
    ///
    /// [`accessibility_tree`](Self::accessibility_tree) returns an untagged
    /// tree, which is exactly the shape that lets a walk finished *after* a
    /// WebProcess crash be published under the recreated view. Going through
    /// [`PageA11yDelivery`](crate::page_delivery::PageA11yDelivery) makes the
    /// generation check unavoidable for the real engine, not only for a demo
    /// host: the returned [`PageDelivery`](crate::page_delivery::PageDelivery)
    /// says whether the snapshot was accepted or refused as stale.
    ///
    /// # This session may only deliver under its OWN bound id
    ///
    /// If [`bind_view`](Self::bind_view) has run, `view` must equal the bound
    /// id, checked before the tree is walked. A call naming another
    /// session's id - even one that is live in the router - is refused with
    /// [`DeliverError::ForeignSession`], so session A cannot walk its own page
    /// and publish it under session B's identity. An unbound session refuses
    /// with [`DeliverError::ViewNotBound`]: delivering a view-scoped tree from
    /// a session that never claimed a view is exactly the untagged-publish
    /// mistake this path exists to prevent.
    ///
    /// # Errors
    ///
    /// [`DeliverError::ForeignSession`]/[`DeliverError::ViewNotBound`] for a
    /// binding violation, or [`DeliverError::Walk`] when the walk itself fails
    /// (no accessible, never bound, bus unreachable).
    pub fn deliver_page_accessibility(
        &mut self,
        router: &crate::web::ViewRouter,
        view: crate::web::ViewId,
        delivery: &mut crate::page_delivery::PageA11yDelivery,
        max_depth: usize,
        max_nodes: usize,
    ) -> Result<crate::page_delivery::PageDelivery, DeliverError> {
        match self.bound_view {
            None => return Err(DeliverError::ViewNotBound),
            Some(bound) if bound != view => {
                return Err(DeliverError::ForeignSession { bound, asked: view });
            }
            Some(_) => {}
        }
        // reject a stale bound id BEFORE the native walk. A
        // session still bound to a generation the router has since superseded
        // must not read AT-SPI at all - the delivery layer would reject the
        // offer afterwards, but only after a pointless (and, on a dead
        // WebProcess, potentially wedging) cross-process walk. The walk is the
        // native effect, so the liveness check precedes it.
        if !router.accepts(view) {
            return Err(DeliverError::ViewNotLive { view });
        }
        let tree = self
            .accessibility_tree(max_depth, max_nodes)
            .map_err(DeliverError::Walk)?;
        let page = crate::page_a11y::PageA11y::from_source(&tree);
        // seed the native action authority from THIS walk, so a
        // later `perform_page_action` reads the object and index from
        // native-owned state rather than from whatever tree a caller offered.
        // Installed only for the live view whose offer this code is about to accept.
        let outcome = delivery.offer(router, view, page.clone());
        if matches!(outcome, crate::page_delivery::PageDelivery::Accepted { .. }) {
            self.native_authority
                .install(view, page.native_action_targets().into_iter().collect());
        }
        Ok(outcome)
    }

    /// Perform a routed accessibility action on a published page node.
    ///
    /// This is the runtime seam an `AccessibilityAction::Activate` on a
    /// published page node ends at.
    ///
    /// # It re-resolves rather than trusting a held target
    ///
    /// The caller passes the node's [`PageNodeKey`](crate::page_a11y::PageNodeKey),
    /// the same identity the widget published, and the address, index and
    /// action name are read here, from the currently published tree, under
    /// the router's current generation. A target resolved earlier by the
    /// caller would be checked far from its use, and the gap between them is
    /// exactly a page mutation or a WebProcess crash.
    ///
    /// The allow-list is re-checked immediately before the call as well, so a
    /// future edit that widened what may be *resolved* cannot silently widen
    /// what may be *performed*.
    ///
    /// Returns what the page reported: `false` means the object refused the
    /// action, which is a real answer and not an error.
    ///
    /// # Errors
    ///
    /// [`PageActionError`] for a refusal to route, a non-activation action, an
    /// out-of-range index, or an AT-SPI failure.
    #[allow(
        clippy::result_large_err,
        reason = "the public error preserves the complete routing refusal for direct pattern matching"
    )]
    pub fn perform_page_action(
        &self,
        router: &crate::web::ViewRouter,
        live: crate::web::ViewId,
        delivery: &crate::page_delivery::PageA11yDelivery,
        key: &crate::page_a11y::PageNodeKey,
    ) -> Result<bool, PageActionError> {
        use crate::page_delivery::PageActionRoute;
        // a routed action is performed only under THIS session's
        // own bound id. A `live` naming another session - even a live one - is
        // refused before the delivery layer or AT-SPI is touched, so one
        // session cannot drive `DoAction` through another's identity.
        match self.bound_view {
            None => return Err(PageActionError::ViewNotBound),
            Some(bound) if bound != live => {
                return Err(PageActionError::ForeignSession { bound, asked: live });
            }
            Some(_) => {}
        }
        // The delivery layer gives the typed liveness/existence refusals (no
        // page, stale page, unknown node, not operable), so a caller can still
        // distinguish a hostile request from a page that simply changed.
        let route = delivery.route_action(router, live, key);
        let PageActionRoute::Routed { .. } = route else {
            return Err(PageActionError::NotRouted(route));
        };
        // the object and index that reach `DoAction` come from
        // this session's OWN native walk, held in `native_authority` - not from
        // the caller-supplied delivery tree. A tree an external
        // `AccessibleSource` built (even one that cloned a real native address
        // and reordered its actions) can be `Routed` at the display layer
        // above, but it cannot install into the authority, so it can never
        // choose what `DoAction` receives. Provenance is no longer a
        // `Clone`-able bit the executor trusts; authorization is a lookup
        // against native-owned, generation-stamped state.
        let authorized = self
            .native_authority
            .authorize(router, live, key)
            .map_err(PageActionError::NotNativelyAuthorized)?;
        let index = i32::try_from(authorized.index())
            .map_err(|_| PageActionError::IndexOutOfRange(authorized.index()))?;
        let bus = crate::ffi::a11y::A11yBus::connect().map_err(PageActionError::Bus)?;
        bus.do_action(authorized.bus_name(), authorized.path(), index)
            .map_err(PageActionError::Bus)
    }
}

/// The native production dispatch port: a `WebSession` IS the port a
/// resolved AccessKit activation is dispatched through, so the same trait method
/// the probe's production update path calls drives a real native
/// `Action.DoAction` here. This is what makes the end-to-end chain one
/// composition rather than an id recipe shared between two tests.
impl crate::page_action::PageActionDispatch for WebSession {
    fn dispatch_page_action(
        &mut self,
        router: &crate::web::ViewRouter,
        live: crate::web::ViewId,
        delivery: &crate::page_delivery::PageA11yDelivery,
        key: &crate::page_a11y::PageNodeKey,
    ) -> crate::page_action::PageActionDispatchOutcome {
        use crate::page_action::PageActionDispatchOutcome as Out;
        match self.perform_page_action(router, live, delivery, key) {
            Ok(true) => Out::Dispatched {
                view: live,
                key: key.clone(),
            },
            Ok(false) => Out::Refused {
                reason: "the page control refused the native action".to_owned(),
            },
            Err(e) => Out::Refused {
                reason: e.to_string(),
            },
        }
    }
}

impl Drop for WebSession {
    fn drop(&mut self) {
        self.pdf_exports.cancel_all();
        // Close the frontend while the inspected view is live, then release it.
        let _ = self.set_inspector_open(false);
        self.inspector.replace(None);
        self.gpu_presentation = None;
        // Policy callbacks carry a pointer to their state and the WebView;
        // disconnect/free them while the view is unquestionably still live.
        // Page prompts still waiting are declined while the view is live.
        self.page = None;
        self.native_policy = None;
        self.proxy_authentication = None;
        // Same discipline for the input-method context: its Drop detaches it
        // from the view (`set_input_method_context(view, NULL)`) and only then
        // unrefs, so it must run while `web_view` is still alive.
        self.ime = None;
        // Disconnect before freeing callback state; otherwise a late
        // termination signal could dereference a dead box.
        unsafe {
            g_signal_handler_disconnect(self.web_view.cast::<c_void>(), self.termination_handler);
            drop(Box::from_raw(self.termination_state));
        }
        // Forget this view's recorded cursor first, so a reused view pointer
        // cannot read a dead session's cursor.
        crate::ffi::cursor::forget_view(self.wpe_view);
        // Same for the a11y plug id - a reused accessible pointer must not
        // read a dead session's tree address.
        if !self.accessible.is_null() {
            crate::ffi::a11y::forget_accessible(self.accessible);
        }
        // SAFETY: `web_view` is owned here (rc>=1). `wpe_view` is borrowed - not
        // unref'd. Dropping the view releases its WPEView with it.
        unsafe { ffi::g_object_unref(self.web_view.cast::<c_void>()) };
        // record the released WebView for the close gate. Only a real
        // `WebSession` can reach this line, so the counter cannot be advanced
        // by a witness object standing in for a page.
        crate::native_release::record_web_session();
    }
}

/// State for a `WebSession::load` main loop. `load-changed` sets `finished`
/// and quits; the deadline quits without setting it.
#[repr(C)]
struct LoadState {
    main_loop: *mut ffi::GMainLoop,
    finished: bool,
    started: bool,
    failure: Option<(String, i32)>,
    /// Set true by `on_load_deadline` when the deadline fires (auto-removing
    /// its source). If still false after the loop quits, the load finished
    /// first and the deadline source must be explicitly removed.
    deadline_fired: bool,
}

/// `load-changed` callback for a session load. Signature
/// `(WebKitWebView*, WebKitLoadEvent, gpointer)`.
extern "C" fn on_session_load_changed(
    _web_view: *mut ffi::WebKitWebView,
    load_event: c_int,
    user_data: *mut c_void,
) {
    // SAFETY: `user_data` is the boxed `LoadState`; single-threaded on the
    // main-context thread, so no aliasing.
    let state = unsafe { &mut *(user_data as *mut LoadState) };
    if load_event == ffi::WEBKIT_LOAD_STARTED {
        // Starting a replacement load can first cancel the preceding navigation.
        state.started = true;
        state.failure = None;
    }
    if !state.started || load_event != ffi::WEBKIT_LOAD_FINISHED {
        return;
    }
    state.finished = true;
    // SAFETY: `main_loop` is valid for the operation's lifetime.
    unsafe { ffi::g_main_loop_quit(state.main_loop) };
}

/// The deadline callback for a `LoadState` loop. Quits without setting
/// `finished`, so the caller sees a `Timeout`.
extern "C" fn on_load_deadline(user_data: *mut c_void) -> ffi::GBoolean {
    // SAFETY: `user_data` is the `LoadState`.
    let state = unsafe { &mut *(user_data as *mut LoadState) };
    state.deadline_fired = true;
    // SAFETY: valid loop.
    unsafe { ffi::g_main_loop_quit(state.main_loop) };
    ffi::G_FALSE
}

/// The largest host HTML document [`WebSession::load_html`] accepts.
pub const MAX_HTML_DOCUMENT_BYTES: usize = 16 * 1024 * 1024;

impl WebSession {
    /// Load a host-supplied HTML document, such as an email body, until
    /// completion or the deadline, without routing its bytes through the URL
    /// policy scanner (and its size limit).
    ///
    /// The document resolves relative references against `base_uri`, which is
    /// screened like a [`load`](Self::load) URL; use `about:blank` for content
    /// that should resolve nothing. Every other guard is the same as `load`:
    /// the attested renderer, the pre-network destination guard and policy,
    /// navigation interception, settings such as disabled JavaScript, and the
    /// post-load re-attestation.
    ///
    /// # Errors
    ///
    /// [`SessionError::InvalidDocument`] past [`MAX_HTML_DOCUMENT_BYTES`] or
    /// for a NUL byte, otherwise as [`load`](Self::load).
    pub fn load_html(
        &mut self,
        html: &str,
        base_uri: &str,
        deadline_ms: u32,
    ) -> Result<(), SessionError> {
        let invalid = SessionError::InvalidDocument {
            size: html.len(),
            limit: MAX_HTML_DOCUMENT_BYTES,
        };
        if html.len() > MAX_HTML_DOCUMENT_BYTES {
            return Err(invalid);
        }
        let content = CString::new(html).map_err(|_| invalid)?;
        let base_c = url_to_cstring(base_uri).map_err(SessionError::InvalidUrl)?;
        self.screen_host_load(base_uri)?;
        self.require_navigable()?;
        self.page_hub.begin_host_navigation();
        let load_started = std::time::Instant::now();
        let (_, failures_before, _) = self.page_hub.load_state();
        let tls_before = self
            .native_certificate_ledger()
            .map(|ledger| ledger.callbacks());
        self::load::run_load_source_on_view(
            self.web_view,
            self::load::LoadSource::Html {
                content: &content,
                base_uri: &base_c,
            },
            deadline_ms,
        )?;
        self.attest_and_enforce(SANDBOX_ATTESTATION_BUDGET_MS)?;
        if self
            .native_certificate_ledger()
            .map(|ledger| ledger.callbacks())
            != tls_before
        {
            return Err(SessionError::TlsLoadFailed);
        }
        if std::env::var_os("ENZUI_WEBKIT_NATIVE_READINESS_TRACE").is_some() {
            eprintln!(
                "native load attested: {:.3} ms",
                load_started.elapsed().as_secs_f64() * 1000.0
            );
        }
        self.wait_for_document_load(load_started, deadline_ms, failures_before)
    }

    /// Load `url` until the document load event completes or the deadline.
    /// Network, TLS and policy-cancellation failures return errors even when WebKit
    /// emits `FINISHED`. HTTP error responses remain successful transport loads.
    ///
    /// # Enforcement order
    ///
    /// The renderer was already spawned on inert content and attested by the
    /// constructor, and [`require_navigable`](Self::require_navigable) re-checks
    /// that the same process is still alive before WebKit is pointed at
    /// `url`. Nothing the caller supplies executes in an unattested renderer.
    /// After the load, the verdict is re-read: a renderer that was replaced
    /// mid-load (a crash and respawn) is caught rather than inherited.
    pub fn load(&mut self, url: &str, deadline_ms: u32) -> Result<(), SessionError> {
        let url_c = url_to_cstring(url).map_err(SessionError::InvalidUrl)?;
        // Refuse a bad host destination before WebKit can resolve or connect.
        self.screen_host_load(url)?;
        self.require_navigable()?;
        self.page_hub.begin_host_navigation();
        let load_started = std::time::Instant::now();
        let (_, failures_before, _) = self.page_hub.load_state();
        let tls_before = self
            .native_certificate_ledger()
            .map(|ledger| ledger.callbacks());
        run_load_on_view(self.web_view, &url_c, deadline_ms)?;
        if std::env::var_os("ENZUI_WEBKIT_NATIVE_READINESS_TRACE").is_some() {
            eprintln!(
                "native load signal: {:.3} ms",
                load_started.elapsed().as_secs_f64() * 1000.0
            );
        }
        // Post-load re-attestation. The pre-load gate proves the renderer was
        // isolated when the navigation started; this proves the renderer that
        // ran the page is the same isolated one.
        self.attest_and_enforce(SANDBOX_ATTESTATION_BUDGET_MS)?;
        if self
            .native_certificate_ledger()
            .map(|ledger| ledger.callbacks())
            != tls_before
        {
            // The policy handler claims TLS failures, suppressing the generic load-failed signal.
            return Err(SessionError::TlsLoadFailed);
        }
        if std::env::var_os("ENZUI_WEBKIT_NATIVE_READINESS_TRACE").is_some() {
            eprintln!(
                "native load attested: {:.3} ms",
                load_started.elapsed().as_secs_f64() * 1000.0
            );
        }
        self.wait_for_document_load(load_started, deadline_ms, failures_before)
    }
}

mod load;
#[allow(unused_imports)]
use self::load::*;
pub(super) use self::load::{configure_credential_guard_extension, run_load_on_view};
/// State for a `WebSession::snapshot` main loop. Mirrors the standalone snapshot
/// `CallbackState` but scoped to a session snapshot (the load already
/// happened).
#[repr(C)]
struct SessionSnapState {
    main_loop: *mut ffi::GMainLoop,
    web_view: *mut ffi::WebKitWebView,
    result_image: *mut ffi::WebKitImage,
    error_message: *mut c_char,
    /// Set true by `on_snap_deadline` when the deadline source fires (and thus
    /// auto-removes itself). If it is still false after the loop quits, the
    /// snapshot completed first and the deadline source must be explicitly
    /// removed so it cannot fire later against this freed box.
    deadline_fired: bool,
    /// Set true by `on_session_snapshot_ready` when the async snapshot callback
    /// fires (success, error, OR cancellation - all resolve the operation). If
    /// still false after a timeout, the async op is still pending and its
    /// callback would fire later against this freed box; the caller cancels and
    /// drains until this flips before freeing.
    callback_fired: bool,
    /// TRUE when the main thread's bounded drain expired and it transferred
    /// ownership of the box and every GLib object the callback can reach
    /// (`web_view` - an extra ref taken because the session may drop first -
    /// `main_loop`, `cancellable`, `result_image`, `error_message`) to
    /// [`on_session_snapshot_ready`], which frees them when it finally fires.
    /// `false` on every normal path.
    abandoned: bool,
    /// The cancellable the outstanding call holds, recorded so the abandoned
    /// callback can unref it. NULL until the snapshot is kicked off.
    cancellable: *mut c_void,
}

/// Free everything an abandoned [`SessionSnapState`] owns, then the box, and
/// record it. Called only by [`on_session_snapshot_ready`] on
/// the abandoned path. Mirrors [`free_abandoned_snapshot`].
///
/// # Safety
///
/// `ptr` must be the live, abandoned `SessionSnapState` box, run on the owning
/// (single) thread with no other reference outstanding.
unsafe fn free_abandoned_session_snap(ptr: *mut SessionSnapState) {
    // SAFETY: `ptr` came from `Box::into_raw`; every GLib object was kept alive
    // for this moment (the main thread forgot its guards and took an extra
    // web_view ref).
    let boxed = unsafe { Box::from_raw(ptr) };
    unsafe {
        if !boxed.result_image.is_null() {
            ffi::g_object_unref(boxed.result_image.cast::<c_void>());
        }
        if !boxed.error_message.is_null() {
            let _ = CString::from_raw(boxed.error_message);
        }
        ffi::g_object_unref(boxed.web_view.cast::<c_void>());
        ffi::g_main_loop_unref(boxed.main_loop);
        if !boxed.cancellable.is_null() {
            ffi::g_object_unref(boxed.cancellable);
        }
    }
    SNAPSHOT_ABANDONED_CLEANUPS.with(|c| c.set(c.get() + 1));
}

/// The snapshot-ready callback for a session snapshot.
extern "C" fn on_session_snapshot_ready(
    _source: *mut c_void,
    result: *mut ffi::GAsyncResult,
    user_data: *mut c_void,
) {
    // SAFETY: `user_data` is the boxed `SessionSnapState`.
    let state = unsafe { &mut *(user_data as *mut SessionSnapState) };
    // Record that the async operation has resolved (success, error, or
    // cancellation) - this is the flag the timeout path drains on.
    state.callback_fired = true;
    let mut error: *mut ffi::GError = ptr::null_mut();
    // SAFETY: `web_view` live; `result` valid for the callback body.
    let image =
        unsafe { ffi::webkit_web_view_get_snapshot_finish(state.web_view, result, &mut error) };
    if image.is_null() {
        if !error.is_null() {
            // SAFETY: on NULL, `error.message` is a valid C string this code now owns.
            let msg = unsafe { CStr::from_ptr((*error).message) };
            let owned = CString::new(msg.to_bytes()).unwrap_or_default();
            state.error_message = owned.into_raw();
            // SAFETY: transfer=full error; free it.
            unsafe { ffi::g_error_free(error) };
        }
    } else {
        state.result_image = image;
    }
    // SAFETY: idempotent quit.
    unsafe { ffi::g_main_loop_quit(state.main_loop) };

    // if the main thread gave up, it transferred ownership.
    // Free everything it deliberately did not, and record it. After this the
    // box is gone.
    if state.abandoned {
        // SAFETY: this code owns the abandoned box; single-threaded, no other reader.
        unsafe { free_abandoned_session_snap(user_data as *mut SessionSnapState) };
    }
}

/// The deadline callback for a `SessionSnapState` loop.
extern "C" fn on_snap_deadline(user_data: *mut c_void) -> ffi::GBoolean {
    // SAFETY: `user_data` is the `SessionSnapState`.
    let state = unsafe { &mut *(user_data as *mut SessionSnapState) };
    // Mark that the deadline fired so `snapshot` does not try to remove an
    // already-auto-removed source (returning G_FALSE removes it).
    state.deadline_fired = true;
    // SAFETY: valid loop.
    unsafe { ffi::g_main_loop_quit(state.main_loop) };
    ffi::G_FALSE
}

/// How long an interactive host keeps re-snapshotting after input. WebKit
/// repaints a selection or caret asynchronously after pointer and key input,
/// and exposes no frame-change signal, so a host re-snapshots for this long
/// after the last input to catch the repaint.
pub const INPUT_REPAINT_WINDOW: std::time::Duration = std::time::Duration::from_millis(200);

/// How long [`WebSession::snapshot`] drains a cancelled snapshot callback
/// before handing it ownership of the state box and every GLib object it can
/// reach.
const SNAPSHOT_DRAIN_CAP_MS: u64 = 2_000;

impl WebSession {
    /// Whether [`snapshot`](Self::snapshot) paints the page's text selection.
    /// On by default, so dragging over an interactive page shows the
    /// highlight; turn it off for document or export captures. Re-snapshot
    /// for [`INPUT_REPAINT_WINDOW`] after input to catch the repaint.
    pub fn set_snapshot_selection_highlight(&mut self, include: bool) {
        self.snapshot_selection = include;
    }

    /// Take a snapshot of the current page. Bounded by `deadline_ms`, with the
    /// same three-mechanism termination as `load`.
    pub fn snapshot(
        &mut self,
        generation: Generation,
        seq: FrameSeq,
        deadline_ms: u32,
    ) -> Result<Rgba8Frame, SessionError> {
        self.snapshot_with_drain_cap(generation, seq, deadline_ms, SNAPSHOT_DRAIN_CAP_MS)
    }

    /// Take a snapshot with a limit on callback draining after cancellation.
    ///
    /// A zero drain cap transfers cleanup immediately to the eventual callback.
    /// The callback retains its native references until completion; the caller
    /// still receives the original deadline or cancellation error.
    ///
    /// # Errors
    /// As [`snapshot`](Self::snapshot).
    pub fn snapshot_with_drain_cap(
        &mut self,
        generation: Generation,
        seq: FrameSeq,
        deadline_ms: u32,
        drain_cap_ms: u64,
    ) -> Result<Rgba8Frame, SessionError> {
        record_native_snapshot(true);
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

        let state = Box::into_raw(Box::new(SessionSnapState {
            main_loop,
            web_view: self.web_view,
            result_image: ptr::null_mut(),
            error_message: ptr::null_mut(),
            deadline_fired: false,
            callback_fired: false,
            abandoned: false,
            cancellable: ptr::null_mut(),
        }));
        struct StateGuard(*mut SessionSnapState);
        impl Drop for StateGuard {
            fn drop(&mut self) {
                if !self.0.is_null() {
                    // SAFETY: recover the box; free any owned resources it
                    // still points at (NULL frees are no-ops).
                    let boxed = unsafe { Box::from_raw(self.0) };
                    if !boxed.result_image.is_null() {
                        // SAFETY: transfer=full image this code holds.
                        unsafe { ffi::g_object_unref(boxed.result_image.cast::<c_void>()) };
                    }
                    if !boxed.error_message.is_null() {
                        // SAFETY: retake the CString leaked.
                        let _ = unsafe { CString::from_raw(boxed.error_message) };
                    }
                }
            }
        }
        let _state_guard = StateGuard(state);

        // Deadline installed BEFORE the snapshot request. Keep its source id:
        // if the snapshot completes first the deadline never fires, and this code must
        // remove it so it cannot fire later against this box after it is freed
        // (a use-after-free that, under rapid repeated snapshots, corrupted a
        // live GMainLoop and hung the run - the bug the poll loop exposed).
        // SAFETY: GSourceFunc; state outlives the loop.
        let deadline_id =
            unsafe { ffi::g_timeout_add(deadline_ms, on_snap_deadline, state.cast::<c_void>()) };

        // Cancellation must drain or transfer the callback before its state can be freed.
        // SAFETY: returns a GCancellable* rc=1.
        let cancellable = unsafe { ffi::g_cancellable_new() };
        // INVARIANT: as `g_main_loop_new` - glib aborts on allocation failure,
        // so NULL is unreachable and stays an assertion.
        assert!(!cancellable.is_null(), "g_cancellable_new returned NULL");
        struct CancelGuard(*mut c_void);
        impl Drop for CancelGuard {
            fn drop(&mut self) {
                // SAFETY: the cancellable, rc=1.
                unsafe { ffi::g_object_unref(self.0) };
            }
        }
        let _cancel_guard = CancelGuard(cancellable);
        // Record the cancellable on the box so the abandoned callback can unref
        // it (the give-up path forgets `_cancel_guard`).
        // SAFETY: single-threaded; box is live and not yet aliased by a fired
        // callback.
        unsafe { (*state).cancellable = cancellable };

        // SAFETY: valid view; the callback receives the state; `cancellable`
        // lives until after this code has drained its callback below.
        unsafe {
            ffi::webkit_web_view_get_snapshot(
                self.web_view,
                ffi::WEBKIT_SNAPSHOT_REGION_VISIBLE,
                if self.snapshot_selection {
                    ffi::WEBKIT_SNAPSHOT_OPTIONS_INCLUDE_SELECTION_HIGHLIGHTING
                } else {
                    ffi::WEBKIT_SNAPSHOT_OPTIONS_NONE
                },
                cancellable,
                on_session_snapshot_ready,
                state.cast::<c_void>(),
            );
        }
        // SAFETY: valid loop; quit guaranteed by the deadline.
        unsafe { ffi::g_main_loop_run(main_loop) };

        // The loop has quit. If the deadline did not fire (snapshot completed
        // first), its timeout source is still registered pointing at `state`;
        // remove it now, before `StateGuard` frees the box.
        // SAFETY: single-threaded; `deadline_fired` written only by the
        // (now-quit) callback on this same thread.
        if !unsafe { (*state).deadline_fired } {
            // SAFETY: `deadline_id` is a live source id created here and have not
            // removed.
            unsafe { ffi::g_source_remove(deadline_id) };
        }

        // If the deadline fired but the async snapshot has not resolved, its
        // callback is still pending and would fire later against this freed
        // box. Cancel it and drain the context until the callback runs (it
        // fires exactly once, promptly, with G_IO_ERROR_CANCELLED). Bounded so
        // it cannot hang: a wall-clock cap plus a spin ceiling.
        // SAFETY: single-threaded reads of flags written only by (now-quit)
        // callbacks on this thread.
        if !unsafe { (*state).callback_fired } {
            // SAFETY: the live cancellable.
            unsafe { ffi::g_cancellable_cancel(cancellable) };
            let drain_start = std::time::Instant::now();
            let drain_cap = std::time::Duration::from_millis(drain_cap_ms);
            // `callback_fired` is flipped by `on_session_snapshot_ready`, which
            // runs *inside* `g_main_context_iteration` below - a mutation
            // clippy cannot see, hence the explicit `loop` + `break` (a `while`
            // on the flag trips `while_immutable_condition`).
            loop {
                // SAFETY: single-threaded read of a flag written only by the
                // callback dispatched on this thread.
                if unsafe { (*state).callback_fired } {
                    break;
                }
                if drain_start.elapsed() >= drain_cap {
                    // cannot prove the cancelled callback ran.
                    // TRANSFER ownership to it rather than freeing anything it
                    // can still reach (which would UAF) or leaking permanently.
                    // `web_view` is owned by this session, which the caller may
                    // drop while the call is outstanding, so take an extra
                    // strong ref; the callback releases it (and the loop,
                    // cancellable, image, error and box) when it fires, bumping
                    // `SNAPSHOT_ABANDONED_CLEANUPS`. Forget the guards so they
                    // free nothing.
                    // SAFETY: the live web_view; single-threaded; the callback
                    // has not run, so the transfer flag races nothing.
                    unsafe { ffi::g_object_ref((*state).web_view.cast::<c_void>()) };
                    unsafe { (*state).abandoned = true };
                    core::mem::forget(_state_guard);
                    core::mem::forget(_loop_guard);
                    core::mem::forget(_cancel_guard);
                    return Err(SessionError::Timeout("snapshot"));
                }
                // SAFETY: NULL context = default; may_block=FALSE returns at
                // once, so this loop is bounded by the wall-clock cap. This is
                // what dispatches the (now-cancelled) snapshot callback that
                // flips `callback_fired`.
                unsafe {
                    let _ = ffi::g_main_context_iteration(ptr::null_mut(), ffi::G_FALSE);
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
        }

        // SAFETY: loop quit; single-threaded read.
        let state_ref = unsafe { &*state };
        if state_ref.result_image.is_null() {
            // A deadline that fired means this code timed out (and, above, cancelled
            // and drained the async op). Report Timeout even though the drained
            // callback set a G_IO_ERROR_CANCELLED message - the cancellation is
            // an artefact of its own timeout, not a distinct failure.
            if state_ref.deadline_fired {
                return Err(SessionError::Timeout("snapshot"));
            }
            if !state_ref.error_message.is_null() {
                let msg = unsafe { CStr::from_ptr(state_ref.error_message) }
                    .to_string_lossy()
                    .into_owned();
                return Err(SessionError::SnapshotFailed(msg));
            }
            return Err(SessionError::Timeout("snapshot"));
        }

        let image = state_ref.result_image;
        // SAFETY: `image` is a WebKitImage* rc=1.
        let width = unsafe { ffi::webkit_image_get_width(image) };
        let height = unsafe { ffi::webkit_image_get_height(image) };
        let stride = unsafe { ffi::webkit_image_get_stride(image) };

        // Native-output failures (a malformed snapshot from WebKit) degrade to a
        // typed `SessionError::SnapshotFailed` instead of aborting the process.
        // Every early return below leaves `state.result_image` set, so
        // `StateGuard` frees the image (plus loop/cancellable) - no leak.

        // SAFETY: as_bytes is transfer=none (borrowed); valid while `image` is.
        let bytes_ptr = unsafe { ffi::webkit_image_as_bytes(image) };
        if bytes_ptr.is_null() {
            return Err(SessionError::SnapshotFailed(
                "webkit_image_as_bytes returned NULL for a non-NULL snapshot image".to_string(),
            ));
        }
        let mut size: usize = 0;
        // SAFETY: valid GBytes; size written by glib.
        let data_ptr = unsafe { ffi::g_bytes_get_data(bytes_ptr, &mut size) };
        if data_ptr.is_null() {
            return Err(SessionError::SnapshotFailed(
                "g_bytes_get_data returned NULL for a non-NULL snapshot buffer".to_string(),
            ));
        }
        // SAFETY: `data_ptr` points at `size` bytes owned by the GBytes and is
        // live while `image` is held. The shared converter preflights geometry,
        // stride, multiplication and length before its one destination copy.
        let bgra_slice = unsafe { core::slice::from_raw_parts(data_ptr.cast::<u8>(), size) };
        let rgba = copy_native_bgra_to_rgba(width, height, stride, bgra_slice)
            .map_err(|error| SessionError::SnapshotFailed(error.to_string()))?;
        record_native_frame_copy(rgba.len());

        // Release the image now; clear the slot so StateGuard does not double
        // free.
        // SAFETY: transfer=full image owned here.
        unsafe { ffi::g_object_unref(image.cast::<c_void>()) };
        // SAFETY: single-threaded, no callback pending.
        unsafe { (*state).result_image = ptr::null_mut() };

        let frame = Rgba8Frame::new(generation, seq, width as u32, height as u32, rgba)
            .map_err(|e| SessionError::SnapshotFailed(format!("Rgba8Frame rejected: {e:?}")))?;
        record_native_snapshot(false);
        Ok(frame)
    }
}
