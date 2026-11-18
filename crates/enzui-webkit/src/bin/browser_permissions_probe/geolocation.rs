#![allow(
    unsafe_code,
    reason = "The synthetic provider fixture uses the native geolocation C ABI."
)]
use std::ffi::{CString, c_char, c_void};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::process::Command;
#[link(name = "dl")]
unsafe extern "C" {
    fn dlopen(path: *const c_char, flags: i32) -> *mut c_void;
    fn dlsym(handle: *mut c_void, name: *const c_char) -> *mut c_void;
}
pub(super) struct Provider {
    push: unsafe extern "C" fn(f64) -> i32,
    counts: unsafe extern "C" fn(*mut u32, *mut u32),
    uninstall: unsafe extern "C" fn(),
    _library: usize,
}
impl Provider {
    pub(super) fn install(directory: &Path) -> Self {
        let library = directory.join("geolocation-provider.so");
        let flags = Command::new("pkg-config")
            .args(["--cflags", "--libs", "wpe-webkit-2.0"])
            .output()
            .unwrap();
        assert!(flags.status.success());
        let compiled = Command::new("cc")
            .args(["-shared", "-fPIC", "-Wall", "-Wextra", "-Werror"])
            .arg(
                Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/geolocation_provider.c"),
            )
            .arg("-o")
            .arg(&library)
            .args(String::from_utf8(flags.stdout).unwrap().split_whitespace())
            .output()
            .unwrap();
        assert!(
            compiled.status.success(),
            "{}",
            String::from_utf8_lossy(&compiled.stderr)
        );
        let path = CString::new(library.as_os_str().as_bytes()).unwrap();
        // SAFETY: this owned library was compiled against the loaded native ABI; RTLD_NOW resolves all references.
        let handle = unsafe { dlopen(path.as_ptr(), 2) };
        assert!(!handle.is_null());
        // SAFETY: every fixed fixture symbol has this exact C signature; keep its code mapped for native callbacks.
        unsafe {
            let install: unsafe extern "C" fn() -> i32 =
                std::mem::transmute(symbol(handle, c"enzui_geolocation_provider_install"));
            assert!(
                install() != 0,
                "could not install synthetic geolocation provider"
            );
            Self {
                push: std::mem::transmute::<*mut c_void, unsafe extern "C" fn(f64) -> i32>(symbol(
                    handle,
                    c"enzui_geolocation_provider_push",
                )),
                counts: std::mem::transmute::<*mut c_void, unsafe extern "C" fn(*mut u32, *mut u32)>(
                    symbol(handle, c"enzui_geolocation_provider_get_counts"),
                ),
                uninstall: std::mem::transmute::<*mut c_void, unsafe extern "C" fn()>(symbol(
                    handle,
                    c"enzui_geolocation_provider_uninstall",
                )),
                _library: handle as usize,
            }
        }
    }
    pub(super) fn push(&self, latitude: f64) {
        // SAFETY: the fixture retains the native manager; only finite synthetic coordinates are supplied.
        assert!(unsafe { (self.push)(latitude) } != 0);
    }
    pub(super) fn counts(&self) -> (u32, u32) {
        let (mut starts, mut stops) = (0, 0);
        // SAFETY: both distinct outputs are initialized stack storage and the fixture only writes two guint values.
        unsafe { (self.counts)(&mut starts, &mut stops) };
        (starts, stops)
    }
}
impl Drop for Provider {
    fn drop(&mut self) {
        // SAFETY: disconnect fixture callbacks before releasing its native manager; the library remains mapped until process exit.
        unsafe { (self.uninstall)() };
    }
}
unsafe fn symbol(handle: *mut c_void, name: &std::ffi::CStr) -> *mut c_void {
    // SAFETY: handle is the retained fixture library and name is static NUL-terminated text.
    let symbol = unsafe { dlsym(handle, name.as_ptr()) };
    assert!(!symbol.is_null(), "fixture symbol {name:?}");
    symbol
}
