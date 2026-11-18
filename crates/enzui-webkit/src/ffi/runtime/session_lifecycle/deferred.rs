use super::*;
use std::cell::{Cell, RefCell};
use std::time::{Duration, Instant};

thread_local! {
    static ACTIVE: Cell<bool> = const { Cell::new(false) };
    static POISONED: Cell<bool> = const { Cell::new(false) };
}

struct Admission;
impl Admission {
    fn reserve() -> Result<Self, SessionError> {
        if POISONED.with(Cell::get) {
            return Err(SessionError::BootstrapFailed(
                "earlier renderer termination was unverified",
            ));
        }
        if ACTIVE.with(|active| active.replace(true)) {
            Err(SessionError::BootstrapBusy)
        } else {
            Ok(Self)
        }
    }
}
impl Drop for Admission {
    fn drop(&mut self) {
        ACTIVE.with(|active| active.set(false));
        crate::ffi::wake_native_event_loop();
    }
}

pub(super) fn wait_for_pending_bootstrap() -> Result<(), SessionError> {
    let deadline = Instant::now()
        + Duration::from_millis(BOOTSTRAP_DEADLINE_MS.into())
        + Duration::from_millis(SANDBOX_ATTESTATION_BUDGET_MS)
        + Duration::from_millis(SANDBOX_TERMINATION_BUDGET_MS);
    while ACTIVE.with(Cell::get) {
        if Instant::now() >= deadline {
            return Err(SessionError::Timeout("pending renderer bootstrap"));
        }
        // SAFETY: construction stays on the native owner; iteration never blocks.
        unsafe { ffi::g_main_context_iteration(ptr::null_mut(), ffi::G_FALSE) };
        std::thread::sleep(Duration::from_millis(1));
    }
    if POISONED.with(Cell::get) {
        return Err(SessionError::BootstrapFailed(
            "earlier renderer termination was unverified",
        ));
    }
    Ok(())
}

type ResultSlot = Rc<RefCell<Option<Result<WebSession, SessionError>>>>;

/// An inert renderer bootstrap driven by the native event loop.
///
/// No session is published until the inert load, credential hook and sandbox
/// attestation succeed. Dropping before completion cancels setup on its native
/// owner thread. If renderer termination cannot be verified, subsequent
/// constructors on that owner refuse to create a session.
pub struct PendingWebSession {
    result: ResultSlot,
    source: Rc<Cell<u32>>,
}
impl core::fmt::Debug for PendingWebSession {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PendingWebSession")
            .field("finished", &self.is_finished())
            .finish_non_exhaustive()
    }
}
impl PendingWebSession {
    /// Whether construction completed or was refused.
    pub fn is_finished(&self) -> bool {
        self.source.get() == 0
    }

    /// Take a ready session or setup failure once, without pumping or waiting.
    /// Native events must continue to be dispatched while this returns `None`.
    pub fn take_result(&self) -> Option<Result<WebSession, SessionError>> {
        self.result.borrow_mut().take()
    }
}
impl Drop for PendingWebSession {
    fn drop(&mut self) {
        let id = self.source.get();
        if id != 0 {
            // SAFETY: the source id is cleared on destruction; removal owns Driver's drop.
            unsafe { ffi::g_source_remove(id) };
        }
    }
}

#[derive(Default)]
struct LoadFlags {
    finished: Cell<Option<Instant>>,
    failed: Cell<bool>,
}

struct Driver {
    session: Option<WebSession>,
    result: ResultSlot,
    source: Rc<Cell<u32>>,
    flags: Box<LoadFlags>,
    signals: Vec<u64>,
    deadline: Instant,
    attestation_deadline: Option<Instant>,
    load_started: bool,
    _admission: Admission,
}

impl Driver {
    fn disconnect(&mut self) {
        if let Some(session) = &self.session {
            for id in self.signals.drain(..) {
                // SAFETY: every id belongs to this retained view and borrows Driver's flags.
                unsafe { ffi::g_signal_handler_disconnect(session.web_view.cast(), id) };
            }
        }
    }

    fn stop_session(&mut self) -> Result<(), String> {
        if !self.load_started {
            self.disconnect();
            self.session.take();
            return Ok(());
        }
        // A cancelled native launch must settle on inert content before its process can be killed.
        while self.flags.finished.get().is_none()
            && !self.flags.failed.get()
            && Instant::now() < self.deadline
        {
            // SAFETY: Driver remains on its native owner and its source cannot dispatch recursively.
            unsafe { ffi::g_main_context_iteration(ptr::null_mut(), ffi::G_FALSE) };
            std::thread::sleep(Duration::from_millis(1));
        }
        self.disconnect();
        if let Some(session) = self.session.take() {
            let subject = super::super::attest_native_view(
                session.web_view,
                &session.sandbox_baseline,
                session.sandbox_policy,
            )
            .subject();
            session.terminate_and_verify(subject)
        } else {
            Ok(())
        }
    }

    fn fail(&mut self, error: SessionError) {
        let cleanup = self.stop_session();
        let result = match cleanup {
            Ok(()) => error,
            Err(_) => {
                POISONED.with(|state| state.set(true));
                SessionError::BootstrapFailed("renderer termination could not be verified")
            }
        };
        *self.result.borrow_mut() = Some(Err(result));
    }

    fn step(&mut self) -> bool {
        if self.flags.failed.get() {
            self.fail(SessionError::BootstrapFailed("inert load failed"));
            return false;
        }
        let now = Instant::now();
        let Some(finished) = self.flags.finished.get() else {
            if now >= self.deadline {
                self.fail(SessionError::Timeout("bootstrap"));
                return false;
            }
            return true;
        };
        let session = self.session.as_ref().expect("pending session");
        if !session
            .native_policy
            .as_ref()
            .is_some_and(crate::ffi::policy::NativePolicyBinding::credential_guard_ready)
        {
            if now >= finished + Duration::from_millis(100) {
                self.fail(SessionError::CredentialGuardUnavailable(
                    "WebProcess did not acknowledge its request hook".into(),
                ));
                return false;
            }
            return true;
        }
        let deadline = *self
            .attestation_deadline
            .get_or_insert_with(|| now + Duration::from_millis(SANDBOX_ATTESTATION_BUDGET_MS));
        let verdict = super::super::attest_native_view(
            session.web_view,
            &session.sandbox_baseline,
            session.sandbox_policy,
        );
        if super::super::is_transient_attestation(&verdict) && now < deadline {
            return true;
        }
        if let Err(error) = session.enforce_attestation(verdict) {
            if matches!(error, SessionError::SandboxTerminationUnverified { .. }) {
                POISONED.with(|state| state.set(true));
            }
            self.disconnect();
            self.session.take();
            *self.result.borrow_mut() = Some(Err(error));
            return false;
        }
        session.mark_bootstrap_history();
        self.disconnect();
        let mut session = self.session.take().expect("attested session");
        match session.connect_page() {
            Ok(()) => *self.result.borrow_mut() = Some(Ok(session)),
            Err(error) => {
                self.session = Some(session);
                self.fail(error);
            }
        }
        false
    }
}
impl Drop for Driver {
    fn drop(&mut self) {
        self.source.set(0);
        if self.session.is_some() {
            self.fail(SessionError::BootstrapFailed("setup cancelled"));
        }
    }
}

extern "C" fn load_changed(_: *mut ffi::WebKitWebView, stage: c_int, data: *mut c_void) {
    // SAFETY: Driver owns the flags and disconnects both view signals before dropping them.
    let flags = unsafe { &*data.cast::<LoadFlags>() };
    if stage == 3 {
        flags.finished.set(Some(Instant::now()));
    }
}
extern "C" fn load_failed(
    _: *mut ffi::WebKitWebView,
    _: c_int,
    _: *const c_char,
    _: *mut ffi::GError,
    data: *mut c_void,
) -> ffi::GBoolean {
    // SAFETY: Driver owns the flags for this signal's entire connection lifetime.
    unsafe { &*data.cast::<LoadFlags>() }.failed.set(true);
    ffi::G_FALSE
}
extern "C" fn poll(data: *mut c_void) -> ffi::GBoolean {
    // SAFETY: GLib retains the boxed Driver; timeout sources do not recursively dispatch themselves.
    let driver = unsafe { &mut *data.cast::<Driver>() };
    let keep = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| driver.step()));
    match keep {
        Ok(true) => ffi::G_TRUE,
        Ok(false) => ffi::G_FALSE,
        Err(_) => {
            driver.fail(SessionError::BootstrapFailed("native setup panicked"));
            ffi::G_FALSE
        }
    }
}
extern "C" fn destroy(data: *mut c_void) {
    // SAFETY: GLib destroys this allocation once after source removal or callback completion.
    drop(unsafe { Box::from_raw(data.cast::<Driver>()) });
}

impl WebSession {
    /// Start profiled renderer setup without entering a nested main loop.
    ///
    /// The native owner must dispatch events and poll the returned handle.
    /// Construction admission is bounded to one pending bootstrap; no caller
    /// destination can be loaded until `take_result` publishes an attested session.
    ///
    /// # Errors
    /// Returns `BootstrapBusy` while another setup owns admission, or the same
    /// sandbox, profile, native-policy and signal failures as `new_profiled`.
    pub fn begin_profiled(
        display: &HeadlessDisplay,
        profiles: &mut crate::ffi::profile::ProfileStore,
        profile: &crate::web::WebProfile,
    ) -> Result<PendingWebSession, SessionError> {
        let outer = crate::ffi::deployment::sandbox_policy();
        crate::sandbox::preflight_in(&crate::sandbox::RealEnv, outer)
            .map_err(SessionError::SandboxDisabled)?;
        let admission = Admission::reserve()?;
        let policy = crate::web::DestinationPolicy::DEFAULT;
        let network = profiles
            .session_for_policy(profile, policy)
            .map_err(session_error_from_profile)?;
        let mut session = Self::construct_view_unblocked(
            display.as_ptr(),
            None,
            Some(profile.clone()),
            Some(network),
            outer,
            policy,
        )?;
        session.install_default_native_policy()?;
        let result = Rc::new(RefCell::new(None));
        let source = Rc::new(Cell::new(0));
        let mut driver = Box::new(Driver {
            session: Some(session),
            result: result.clone(),
            source: source.clone(),
            flags: Box::default(),
            signals: Vec::new(),
            deadline: Instant::now() + Duration::from_millis(BOOTSTRAP_DEADLINE_MS.into()),
            attestation_deadline: None,
            load_started: false,
            _admission: admission,
        });
        let view = driver.session.as_ref().expect("new session").web_view;
        let flags = (&mut *driver.flags as *mut LoadFlags).cast::<c_void>();
        // SAFETY: these concrete callbacks match their GObject signal ABIs; Driver retains flags.
        let changed = unsafe {
            core::mem::transmute::<
                extern "C" fn(*mut ffi::WebKitWebView, c_int, *mut c_void),
                extern "C" fn(),
            >(load_changed)
        };
        // SAFETY: the retained view owns the signal and Driver keeps its userdata allocated.
        let id = unsafe {
            crate::ffi::signal::connect_checked(view.cast(), "load-changed", changed, flags)
        }
        .map_err(|error| SessionError::NativeSignalBindFailed(error.signal))?;
        driver.signals.push(id);
        // SAFETY: the callback matches load-failed's ABI; Driver retains its stable flags.
        let failed = unsafe {
            core::mem::transmute::<
                extern "C" fn(
                    *mut ffi::WebKitWebView,
                    c_int,
                    *const c_char,
                    *mut ffi::GError,
                    *mut c_void,
                ) -> ffi::GBoolean,
                extern "C" fn(),
            >(load_failed)
        };
        // SAFETY: both callback userdata and the view remain live until Driver disconnects.
        let id = unsafe {
            crate::ffi::signal::connect_checked(view.cast(), "load-failed", failed, flags)
        }
        .map_err(|error| SessionError::NativeSignalBindFailed(error.signal))?;
        driver.signals.push(id);
        let bootstrap = CString::new(INERT_BOOTSTRAP_URL).expect("static bootstrap");
        driver
            .session
            .as_ref()
            .expect("new session")
            .permit_inert_load(INERT_BOOTSTRAP_URL);
        // SAFETY: the retained view and NUL-terminated inert URL are live for the native call.
        unsafe { ffi::webkit_web_view_load_uri(view, bootstrap.as_ptr()) };
        driver.load_started = true;
        let data = Box::into_raw(driver);
        // SAFETY: GLib owns Driver through destroy; its bounded 5ms source only runs during setup.
        let id = unsafe { ffi::g_timeout_add_full(0, 5, Some(poll), data.cast(), Some(destroy)) };
        if id == 0 {
            // SAFETY: no source retained the allocation when attachment returned zero.
            drop(unsafe { Box::from_raw(data) });
            return Err(SessionError::BootstrapFailed(
                "could not attach native setup source",
            ));
        }
        source.set(id);
        Ok(PendingWebSession { result, source })
    }
}
