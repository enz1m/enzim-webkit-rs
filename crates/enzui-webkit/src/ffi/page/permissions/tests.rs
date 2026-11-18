//! These fixture-owned origins test pending-request lifetime, not native origin authority.

use super::*;
use std::ffi::{CStr, CString};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

type ObserverCallback = extern "C" fn(*mut c_void, ffi::GBoolean, ffi::GBoolean);
type OwnerDestroy = extern "C" fn(*mut c_void);

struct Fixture {
    new: unsafe extern "C" fn(ObserverCallback, *mut c_void, OwnerDestroy) -> *mut c_void,
    set_timeout: unsafe extern "C" fn(*mut c_void, c_uint),
    count: unsafe extern "C" fn(*mut c_void, ffi::GBoolean) -> c_uint,
    source_exists: unsafe extern "C" fn(c_uint) -> ffi::GBoolean,
    _library: usize,
}

impl Fixture {
    fn shared() -> &'static Self {
        static FIXTURE: OnceLock<Fixture> = OnceLock::new();
        FIXTURE.get_or_init(|| {
            let root = Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap()
                .parent()
                .unwrap();
            let directory = root
                .join("work/permission-pending-reentrancy")
                .join(format!("fixture-{}", std::process::id()));
            std::fs::create_dir_all(&directory).expect("owned fixture directory");
            let library = directory.join("permission_request.so");
            let flags = Command::new("pkg-config")
                .args(["--cflags", "--libs", "wpe-webkit-2.0"])
                .output()
                .expect("WPE fixture compiler flags");
            assert!(
                flags.status.success(),
                "{}",
                String::from_utf8_lossy(&flags.stderr)
            );
            let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/permission_request.c");
            let compiled = Command::new("cc")
                .args(["-shared", "-fPIC", "-Wall", "-Wextra", "-Werror"])
                .arg(source)
                .arg("-o")
                .arg(&library)
                .args(
                    String::from_utf8(flags.stdout)
                        .expect("compiler flags UTF-8")
                        .split_whitespace(),
                )
                .output()
                .expect("compile GObject permission fixture");
            assert!(
                compiled.status.success(),
                "{}",
                String::from_utf8_lossy(&compiled.stderr)
            );
            let path = CString::new(library.as_os_str().as_bytes()).expect("fixture path");
            // SAFETY: the owned fixture has just been compiled against the linked native ABI.
            let handle = unsafe { libc::dlopen(path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
            assert!(!handle.is_null(), "load compiled permission fixture");
            // GType retains the fixture's virtual methods for the process lifetime.
            // SAFETY: each fixed symbol has the exact C prototype in permission_request.c.
            unsafe {
                Self {
                    new: symbol(handle, c"enzui_permission_fixture_new"),
                    set_timeout: symbol(handle, c"enzui_permission_fixture_set_timeout"),
                    count: symbol(handle, c"enzui_permission_fixture_count"),
                    source_exists: symbol(handle, c"enzui_permission_fixture_source_exists"),
                    _library: handle as usize,
                }
            }
        })
    }

    fn request(&'static self, observer: &Rc<Observer>) -> OwnedRequest {
        let owner = Rc::into_raw(Rc::clone(observer)).cast_mut().cast();
        // SAFETY: the fixture owns this Rc count and releases it through destroy_owner.
        let request = unsafe { (self.new)(observe, owner, destroy_owner) };
        assert!(!request.is_null(), "fixture GObject allocation");
        OwnedRequest { request }
    }

    fn set_timeout(&self, request: &OwnedRequest, timeout: c_uint) {
        // SAFETY: request owns a fixture GObject, and this setter does not reenter.
        unsafe { (self.set_timeout)(request.request, timeout) };
    }

    fn denials(&self, request: &OwnedRequest) -> c_uint {
        // SAFETY: request owns a fixture GObject for this scalar read.
        unsafe { (self.count)(request.request, ffi::G_FALSE) }
    }

    fn timer_present(&self, timeout: c_uint) -> bool {
        // SAFETY: the fixture queries GLib by source ID without borrowing the source.
        unsafe { (self.source_exists)(timeout) != 0 }
    }
}

unsafe fn symbol<T: Copy>(handle: *mut c_void, name: &CStr) -> T {
    // SAFETY: handle is the retained fixture, and name is a fixed NUL-terminated symbol.
    let address = unsafe { libc::dlsym(handle, name.as_ptr()) };
    assert!(!address.is_null(), "fixture symbol {name:?}");
    assert_eq!(std::mem::size_of::<T>(), std::mem::size_of_val(&address));
    // SAFETY: callers instantiate only the exact fixture function pointer types above.
    unsafe { std::mem::transmute_copy(&address) }
}

struct OwnedRequest {
    request: *mut c_void,
}

impl OwnedRequest {
    fn native(&self) -> *mut ffi::WebKitPermissionRequest {
        self.request.cast()
    }
}

impl Drop for OwnedRequest {
    fn drop(&mut self) {
        // SAFETY: this owner releases its one GObject reference; pending slots retain their own.
        unsafe { ffi::g_object_unref(self.request) };
    }
}

#[derive(Default)]
struct Observer {
    hub: Weak<PageHub>,
    nested: Option<OwnedRequest>,
    terminal_calls: Cell<u32>,
    nested_attempts: Cell<u32>,
    nested_handled: Cell<Option<bool>>,
    timer_during_terminal: Cell<Option<bool>>,
    callback_panicked: Cell<bool>,
}

extern "C" fn observe(owner: *mut c_void, _allowed: ffi::GBoolean, timer_present: ffi::GBoolean) {
    // SAFETY: the fixture retains this immutable Rc payload through its terminal callback.
    let observer = unsafe { &*owner.cast::<Observer>() };
    observer
        .terminal_calls
        .set(observer.terminal_calls.get() + 1);
    observer.timer_during_terminal.set(Some(timer_present != 0));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if let (Some(hub), Some(nested)) = (observer.hub.upgrade(), observer.nested.as_ref()) {
            observer
                .nested_attempts
                .set(observer.nested_attempts.get() + 1);
            observer.nested_handled.set(Some(
                hub.handle_site_permission(nested.native(), PermissionKind::Geolocation),
            ));
        }
    }));
    observer.callback_panicked.set(result.is_err());
}

extern "C" fn destroy_owner(owner: *mut c_void) {
    // SAFETY: the fixture finalizer releases exactly the Rc count passed to its constructor.
    drop(unsafe { Rc::from_raw(owner.cast::<Observer>()) });
}

#[test]
fn permission_pending_native_cancel_denies_reentrant_admission() {
    let fixture = Fixture::shared();
    let hub = Rc::new(PageHub::default());
    hub.enable_site_permissions(true);
    let nested_observer = Rc::new(Observer::default());
    let nested = fixture.request(&nested_observer);
    let observer = Rc::new(Observer {
        hub: Rc::downgrade(&hub),
        nested: Some(nested),
        ..Observer::default()
    });
    let request = fixture.request(&observer);
    let handled = hub.handle_site_permission(request.native(), PermissionKind::Geolocation);
    let pending_before = hub.state.borrow().site_permissions.pending.len();
    let cancelled = hub.cancel_site_permissions();
    let pending_after = hub.state.borrow().site_permissions.pending.len();
    let denials = fixture.denials(&request);
    let nested_denials = fixture.denials(observer.nested.as_ref().unwrap());
    hub.cancel_site_permissions();
    drop(request);
    drop(hub);

    assert!(handled);
    assert_eq!(pending_before, 1);
    assert_eq!(cancelled, 1);
    assert_eq!(
        denials, 1,
        "real WebKit deny must reach the C virtual method"
    );
    assert_eq!(observer.terminal_calls.get(), 1);
    assert_eq!(observer.nested_attempts.get(), 1);
    assert_eq!(observer.nested_handled.get(), Some(true));
    assert!(!observer.callback_panicked.get());
    assert_eq!(pending_after, 0, "nested request survived cancellation");
    assert_eq!(
        nested_denials, 1,
        "nested request was not immediately denied"
    );
    assert_eq!(nested_observer.terminal_calls.get(), 1);
}

#[test]
fn permission_pending_native_terminal_call_observes_removed_timeout() {
    let fixture = Fixture::shared();
    let hub = Rc::new(PageHub::default());
    hub.enable_site_permissions(true);
    let observer = Rc::new(Observer::default());
    let request = fixture.request(&observer);
    let handled = hub.handle_site_permission(request.native(), PermissionKind::Geolocation);
    let slot = hub
        .state
        .borrow()
        .site_permissions
        .pending
        .first()
        .map(|(id, slot)| (*id, slot.timeout));
    let (answer, timer_live, native_denials) = if let Some((id, timeout)) = slot {
        fixture.set_timeout(&request, timeout);
        let timer_live = fixture.timer_present(timeout);
        let answer = hub.answer_site_permission(id, false);
        (answer, timer_live, fixture.denials(&request))
    } else {
        (Err(AnswerError::Unknown), false, 0)
    };
    hub.cancel_site_permissions();
    drop(request);
    drop(hub);

    assert!(handled);
    assert!(
        timer_live,
        "positive control: pending timeout was never registered"
    );
    assert!(answer.is_ok(), "pending permission answer: {answer:?}");
    assert_eq!(native_denials, 1);
    assert_eq!(observer.terminal_calls.get(), 1);
    assert_eq!(
        observer.timer_during_terminal.get(),
        Some(false),
        "timeout remained registered during native terminal call"
    );
    assert!(!observer.callback_panicked.get());
}

#[test]
fn permission_pending_native_answer_cannot_cross_session() {
    let fixture = Fixture::shared();
    let a = Rc::new(PageHub::default());
    let b = Rc::new(PageHub::default());
    a.enable_site_permissions(true);
    b.enable_site_permissions(true);
    let first_observer = Rc::new(Observer::default());
    let second_observer = Rc::new(Observer::default());
    let first = fixture.request(&first_observer);
    let second = fixture.request(&second_observer);
    assert!(a.handle_site_permission(first.native(), PermissionKind::Geolocation));
    assert!(b.handle_site_permission(second.native(), PermissionKind::Geolocation));
    let first_id = a.state.borrow().site_permissions.pending[0].0;
    let second_id = b.state.borrow().site_permissions.pending[0].0;
    let foreign_answer = b.answer_site_permission(first_id, true);
    let calls_before_cleanup = second_observer.terminal_calls.get();
    let own_answer = b.answer_site_permission(second_id, false);
    a.cancel_site_permissions();
    b.cancel_site_permissions();
    assert_ne!(
        first_id, second_id,
        "permission IDs collided across sessions"
    );
    assert!(matches!(foreign_answer, Err(AnswerError::Unknown)));
    assert_eq!(
        calls_before_cleanup, 0,
        "foreign answer reached another native request"
    );
    assert!(own_answer.is_ok());
    assert_eq!(fixture.denials(&second), 1);
}
