//! Process budgets, host allocator release and current renderer diagnostics.
use super::*;
use std::sync::OnceLock;

type SetBudgets = unsafe extern "C" fn(u64, u64);
#[link(name = "dl")]
unsafe extern "C" {
    fn dlsym(handle: *mut c_void, name: *const c_char) -> *mut c_void;
}

fn budget_api() -> Option<SetBudgets> {
    static API: OnceLock<Option<SetBudgets>> = OnceLock::new();
    *API.get_or_init(|| {
        // SAFETY: the constant symbol is resolved only from already loaded libraries.
        let symbol = unsafe {
            dlsym(
                ptr::null_mut(),
                c"webkit_enzui_set_process_memory_budgets_v1".as_ptr(),
            )
        };
        // SAFETY: the versioned fork symbol has this exact two-u64 C ABI.
        (!symbol.is_null())
            .then(|| unsafe { std::mem::transmute::<*mut c_void, SetBudgets>(symbol) })
    })
}

/// The runtime does not support explicit child-process budgets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessMemoryBudgetsUnsupported;

impl std::fmt::Display for ProcessMemoryBudgetsUnsupported {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the runtime cannot configure child-process memory budgets")
    }
}

impl std::error::Error for ProcessMemoryBudgetsUnsupported {}

/// Set soft heap/cache budgets in bytes for future web and shared GPU/network processes.
///
/// Call before creating sessions. Existing child processes keep their budgets.
/// Zero inherits the system/cgroup budget; nonzero values are clamped to it.
/// These guide cache sizing and collection heuristics, rather than limit allocations.
///
/// # Errors
/// Returns [`ProcessMemoryBudgetsUnsupported`] if the native runtime lacks the API.
pub fn set_process_memory_budgets(
    web_bytes: u64,
    shared_bytes: u64,
) -> Result<(), ProcessMemoryBudgetsUnsupported> {
    let set = budget_api().ok_or(ProcessMemoryBudgetsUnsupported)?;
    // SAFETY: the versioned API accepts byte counts and stores them atomically.
    unsafe { set(web_bytes, shared_bytes) };
    Ok(())
}

type CurrentRenderer = unsafe extern "C" fn(*mut ffi::WebKitWebView) -> u64;

fn renderer_api() -> Option<CurrentRenderer> {
    static API: OnceLock<Option<CurrentRenderer>> = OnceLock::new();
    *API.get_or_init(|| {
        // SAFETY: the constant symbol is resolved from already loaded native libraries.
        let symbol = unsafe {
            dlsym(
                ptr::null_mut(),
                c"webkit_web_view_enzui_current_renderer_pid_v1".as_ptr(),
            )
        };
        // SAFETY: the versioned getter accepts a live view and returns a host PID as u64.
        (!symbol.is_null())
            .then(|| unsafe { std::mem::transmute::<*mut c_void, CurrentRenderer>(symbol) })
    })
}

/// The runtime cannot report the current view's renderer process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RendererProcessIdUnsupported;

impl std::fmt::Display for RendererProcessIdUnsupported {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the runtime cannot report the current renderer process")
    }
}

impl std::error::Error for RendererProcessIdUnsupported {}

impl WebSession {
    /// Report the current main-frame renderer's host OS PID, including after process swaps.
    ///
    /// Returns `None` before launch or after termination. This is diagnostic metadata;
    /// PIDs can be reused and this getter does not attest sandbox or document authority.
    ///
    /// # Errors
    /// Returns [`RendererProcessIdUnsupported`] if the native query is absent or incompatible.
    pub fn renderer_process_id(&self) -> Result<Option<u32>, RendererProcessIdUnsupported> {
        // SAFETY: the session owns this live view on the native owner thread.
        unsafe { renderer_pid_for_view(self.web_view) }
    }
}

/// Return unused host allocator pages to the operating system.
///
/// May be called from any thread. This may briefly lock allocator arenas; call
/// away from latency-sensitive
/// paths after large temporary allocations. Only glibc has an implementation.
/// False also means that no pages could be returned.
pub fn release_host_allocator_memory() -> bool {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    {
        unsafe extern "C" {
            fn malloc_trim(padding: usize) -> std::ffi::c_int;
        }
        // SAFETY: glibc's MT-safe allocator operation takes padding, not pointers.
        unsafe { malloc_trim(0) != 0 }
    }
    #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
    false
}

/// Ask the kernel to drop the resident pages behind `bytes`.
///
/// For data that was read once and may not be needed again, such as a large
/// blob embedded in the executable after it has been copied out. The contents
/// stay valid: file-backed pages are read back from the file on the next
/// access, and anonymous pages are only moved to swap where there is any.
/// Only whole pages inside the slice are affected. False means that nothing
/// was released. Linux only.
pub fn release_resident_pages(bytes: &[u8]) -> bool {
    #[cfg(target_os = "linux")]
    {
        const MADV_PAGEOUT: std::ffi::c_int = 21;
        const SC_PAGESIZE: std::ffi::c_int = 30;
        unsafe extern "C" {
            fn madvise(
                address: *mut std::ffi::c_void,
                length: usize,
                advice: std::ffi::c_int,
            ) -> std::ffi::c_int;
            fn sysconf(name: std::ffi::c_int) -> std::ffi::c_long;
        }
        // SAFETY: sysconf takes a name and returns a number.
        let Ok(page) = usize::try_from(unsafe { sysconf(SC_PAGESIZE) }) else {
            return false;
        };
        if page == 0 {
            return false;
        }
        let start = bytes.as_ptr().addr();
        let first = start.next_multiple_of(page);
        let last = (start + bytes.len()) / page * page;
        if first >= last {
            return false;
        }
        // SAFETY: the range lies inside the live borrow. MADV_PAGEOUT only asks for
        // reclaim: it never changes what a later read of the range observes, for
        // file-backed and anonymous memory alike.
        unsafe {
            madvise(
                bytes.as_ptr().with_addr(first).cast_mut().cast(),
                last - first,
                MADV_PAGEOUT,
            ) == 0
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = bytes;
        false
    }
}

#[cfg(all(test, target_os = "linux"))]
mod resident_page_tests {
    use std::io::Write;

    fn resident_bytes(path: &std::path::Path) -> u64 {
        let name = path.to_str().expect("utf-8 path");
        let text = std::fs::read_to_string("/proc/self/smaps").expect("process mappings");
        let mut inside = false;
        let mut total = 0;
        for line in text.lines() {
            // A mapping header starts with its address range; attribute lines start with a name.
            let header = line
                .split_whitespace()
                .next()
                .is_some_and(|field| field.contains('-') && !field.ends_with(':'));
            if header {
                inside = line.ends_with(name);
            } else if inside && let Some(value) = line.strip_prefix("Rss:") {
                total += value
                    .split_whitespace()
                    .next()
                    .and_then(|value| value.parse::<u64>().ok())
                    .expect("resident size")
                    * 1024;
            }
        }
        total
    }

    #[test]
    fn read_only_file_pages_leave_the_process_and_read_back_unchanged() {
        const LENGTH: usize = 8 * 1024 * 1024;
        let path =
            std::env::temp_dir().join(format!("enzui-resident-pages-{}", std::process::id()));
        let mut file = std::fs::File::create(&path).expect("fixture file");
        file.write_all(&vec![0xa7_u8; LENGTH])
            .expect("fixture bytes");
        file.sync_all().expect("clean pages");
        let file = std::fs::File::open(&path).expect("reopen fixture");
        // SAFETY: a private read-only mapping of a file this test owns; unmapped below.
        let address = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                LENGTH,
                libc::PROT_READ,
                libc::MAP_PRIVATE,
                std::os::fd::AsRawFd::as_raw_fd(&file),
                0,
            )
        };
        assert_ne!(address, libc::MAP_FAILED, "map fixture");
        // SAFETY: the mapping is live and LENGTH bytes long until munmap below.
        let bytes = unsafe { std::slice::from_raw_parts(address.cast::<u8>(), LENGTH) };
        let touched: u64 = bytes
            .iter()
            .step_by(4096)
            .map(|byte| u64::from(*byte))
            .sum();
        assert_eq!(touched, 0xa7 * (LENGTH as u64 / 4096));
        let before = resident_bytes(&path);
        assert!(
            before >= LENGTH as u64 / 2,
            "fixture pages were not resident: {before}"
        );
        assert!(
            super::release_resident_pages(bytes),
            "the kernel refused the advice"
        );
        let after = resident_bytes(&path);
        assert!(
            after <= before / 8,
            "pages stayed resident after release: {before} -> {after}"
        );
        assert!(
            bytes.iter().step_by(4096).all(|byte| *byte == 0xa7),
            "released pages read back differently"
        );
        assert!(
            !super::release_resident_pages(&bytes[1..100]),
            "no whole page in a small slice"
        );
        // SAFETY: the mapping created above, not used afterwards.
        unsafe { libc::munmap(address, LENGTH) };
        std::fs::remove_file(&path).expect("remove fixture");
    }
}

pub(super) unsafe fn renderer_pid_for_view(
    view: *mut ffi::WebKitWebView,
) -> Result<Option<u32>, RendererProcessIdUnsupported> {
    let get = renderer_api().ok_or(RendererProcessIdUnsupported)?;
    // SAFETY: the caller retains the view on its native owner thread.
    let pid = unsafe { get(view) };
    if pid == 0 {
        return Ok(None);
    }
    u32::try_from(pid)
        .map(Some)
        .map_err(|_| RendererProcessIdUnsupported)
}
