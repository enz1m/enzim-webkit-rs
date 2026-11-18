//! Process-wide application identity and WebProcess credential guard location.

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

const MODULE: &str = "libenzui_credential_guard.so";

#[derive(Default)]
struct Configuration {
    directory: Option<PathBuf>,
    application_id: Option<String>,
    flatpak: bool,
    initialized: Option<Result<(), String>>,
}

unsafe extern "C" {
    fn g_application_id_is_valid(application_id: *const c_char) -> c_int;
    fn g_application_get_default() -> *mut c_void;
    fn g_application_get_application_id(application: *mut c_void) -> *const c_char;
    fn g_set_prgname(name: *const c_char);
}

/// Register the host's application ID before creating a WPE display.
///
/// WebKit uses this identity for desktop portals and Flatpak renderer sandboxes.
/// Inside Flatpak it must match the application's manifest ID. Call during
/// application startup, before native displays are initialized. An existing `GApplication`
/// must have the same ID. Repeating the same ID before initialization is allowed;
/// changing it or registering after initialization is refused.
///
/// # Errors
/// Returns an error for an invalid ID, a conflicting identity,
/// a poisoned configuration lock, or prior native initialization.
pub fn set_application_id(application_id: &str) -> Result<(), String> {
    let value =
        CString::new(application_id).map_err(|_| "application ID contains NUL".to_owned())?;
    // SAFETY: GLib borrows this live NUL-terminated string for stateless validation.
    if unsafe { g_application_id_is_valid(value.as_ptr()) } == 0 {
        return Err("application ID must be a valid GLib application identifier".into());
    }
    let mut state = configuration()
        .lock()
        .map_err(|_| "application identity configuration lock poisoned".to_owned())?;
    if state.initialized.is_some() {
        return Err("application ID is frozen after WPE initialization".into());
    }
    if state
        .application_id
        .as_deref()
        .is_some_and(|current| current != application_id)
    {
        return Err("application ID was already registered with a different identity".into());
    }
    // SAFETY: the host registers on the native owner thread while its application is live.
    let application = unsafe { g_application_get_default() };
    if !application.is_null() {
        // SAFETY: the default GApplication is borrowed during startup on its owner thread.
        let existing = unsafe { g_application_get_application_id(application) };
        // SAFETY: a non-NULL application ID is a borrowed NUL-terminated string.
        if !existing.is_null() && unsafe { CStr::from_ptr(existing) }.to_bytes() != value.as_bytes()
        {
            return Err("application ID conflicts with the host GApplication".into());
        }
    }
    // SAFETY: GLib copies this live string; registration is serialized before WPE initialization.
    unsafe { g_set_prgname(value.as_ptr()) };
    state.application_id = Some(application_id.to_owned());
    Ok(())
}

/// Configure a Flatpak application before starting native displays or workers.
///
/// The ID must match the immutable `/.flatpak-info` application metadata. The
/// guard directory is validated as in [`set_credential_guard_directory`]. After
/// registration, ordinary and deferred session constructors use Flatpak's portal
/// launcher and require a verified, separately isolated renderer. Hosts outside
/// Flatpak keep the default bubblewrap policy.
///
/// # Errors
/// Returns an error for missing Flatpak metadata, mismatched application identity,
/// an invalid guard directory, or registration after native initialization.
pub fn configure_flatpak_application(
    application_id: &str,
    guard_directory: impl AsRef<Path>,
) -> Result<(), String> {
    if crate::sandbox::flatpak_application_id()? != application_id {
        return Err("application ID does not match the Flatpak application".into());
    }
    let directory = validate_directory(guard_directory.as_ref())?;
    set_application_id(application_id)?;
    set_credential_guard_directory(directory)?;
    let mut state = configuration()
        .lock()
        .map_err(|_| "Flatpak deployment configuration lock poisoned".to_owned())?;
    if state.initialized.is_some() {
        return Err("Flatpak deployment is frozen after WPE initialization".into());
    }
    state.flatpak = true;
    Ok(())
}

pub(crate) fn sandbox_policy() -> crate::sandbox::OuterSandbox {
    if configuration().lock().is_ok_and(|state| state.flatpak) {
        crate::sandbox::OuterSandbox::AcceptedByHost
    } else {
        crate::sandbox::OuterSandbox::Rejected
    }
}

fn configuration() -> &'static Mutex<Configuration> {
    static CONFIGURATION: OnceLock<Mutex<Configuration>> = OnceLock::new();
    CONFIGURATION.get_or_init(|| Mutex::new(Configuration::default()))
}

/// Locate this build's guard module for packaging, not installed runtime lookup.
/// Copy `libenzui_credential_guard.so` from here into the application's trusted
/// extension directory and select that directory before creating a WPE display.
#[must_use]
pub fn credential_guard_build_directory() -> &'static Path {
    Path::new(env!("ENZUI_WPE_EXTENSION_DIR"))
}

/// Select a trusted installed guard directory before the first WPE display.
///
/// The path must be absolute and contain a readable regular
/// `libenzui_credential_guard.so`. Symlinks in the directory path are resolved.
/// The directory and its modules must remain available and trusted for the
/// process lifetime: WebKit loads native code from this directory. The choice
/// is process-wide; it cannot change after native initialization is attempted.
/// Without a selection, development builds use their build directory.
/// A session still requires the guard's native ready handshake.
///
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use enzui_webkit::ffi::deployment::set_credential_guard_directory;
/// use enzui_webkit::ffi::runtime::HeadlessDisplay;
/// set_credential_guard_directory("/opt/my-app/lib/wpe-extensions")?;
/// let _display = HeadlessDisplay::new()?;
/// # Ok(())
/// # }
/// ```
///
/// # Errors
/// Returns an error for an invalid path, missing/unreadable module, poisoned
/// configuration lock, or a selection after native initialization was attempted.
pub fn set_credential_guard_directory(directory: impl AsRef<Path>) -> Result<(), String> {
    let directory = validate_directory(directory.as_ref())?;
    let mut state = configuration()
        .lock()
        .map_err(|_| "credential guard configuration lock poisoned".to_owned())?;
    if state.initialized.is_some() {
        return Err("credential guard directory is frozen after WPE initialization".into());
    }
    state.directory = Some(directory);
    Ok(())
}

fn validate_directory(directory: &Path) -> Result<PathBuf, String> {
    if !directory.is_absolute() {
        return Err("credential guard directory must be absolute".into());
    }
    let directory = directory
        .canonicalize()
        .map_err(|e| format!("credential guard directory unavailable: {e}"))?;
    if !directory.is_dir() {
        return Err("credential guard path is not a directory".into());
    }
    let module = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(enzui_security::platform::libc_o_nonblock())
        .open(directory.join(MODULE))
        .map_err(|e| format!("credential guard module unavailable: {e}"))?;
    if !module
        .metadata()
        .map_err(|e| format!("credential guard module metadata unavailable: {e}"))?
        .is_file()
    {
        return Err("credential guard module is not a regular file".into());
    }
    Ok(directory)
}

pub(crate) fn configure() -> Result<(), String> {
    super::threading::claim().map_err(|error| error.to_string())?;
    let mut state = configuration()
        .lock()
        .map_err(|_| "credential guard configuration lock poisoned".to_owned())?;
    if let Some(result) = &state.initialized {
        return result.clone();
    }
    let result = configure_native(
        state
            .directory
            .as_deref()
            .unwrap_or_else(|| credential_guard_build_directory()),
    );
    state.initialized = Some(result.clone());
    result
}

fn configure_native(directory: &Path) -> Result<(), String> {
    let directory = validate_directory(directory)?;
    let directory = CString::new(directory.as_os_str().as_bytes())
        .map_err(|_| "credential guard directory contains NUL".to_owned())?;
    // WebKit freezes sandbox paths before launching its first subprocess.
    // SAFETY: the default context has process lifetime and this call borrows no pointers.
    let context = unsafe { super::wpe::webkit_web_context_get_default() };
    if context.is_null() {
        return Err("webkit_web_context_get_default returned NULL".into());
    }
    // SAFETY: the default context and the canonical directory string remain live for both calls.
    unsafe {
        super::wpe::webkit_web_context_add_path_to_sandbox(
            context,
            directory.as_ptr(),
            super::wpe::G_TRUE,
        );
        super::wpe::webkit_web_context_set_web_process_extensions_directory(
            context,
            directory.as_ptr(),
        );
    }
    Ok(())
}
