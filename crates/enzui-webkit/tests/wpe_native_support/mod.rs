//! Native gates run in a bounded child to isolate WebKit's thread finalizers.
//! The parent reports the normal Rust test result after checking completion.

use std::io::Write;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const CHILD_FIXTURE: &str = "ENZUI_WPE_NATIVE_GATE_FIXTURE";

const CHILD_ROLE: &str = "ENZUI_WPE_NATIVE_GATE_CHILD";

#[allow(
    dead_code,
    reason = "Each integration target has its own copy and can use only the fixture-aware entry point."
)]
pub fn run(name: &str, checks: impl FnOnce()) {
    run_with_fixture(name, |_| checks());
}

pub fn run_with_fixture(name: &str, checks: impl FnOnce(&std::path::Path)) {
    let marker = format!("native gate completed: {name}");
    if std::env::var(CHILD_ROLE).ok().as_deref() == Some(name) {
        let fixture = std::env::var_os(CHILD_FIXTURE).expect("native child fixture");
        let _ = std::io::stdout().flush();
        let _ = std::io::stderr().flush();
        // WPE 2.55 and newer run only on the process main thread, and libtest
        // runs this on a worker. A forked process's only thread is its main
        // thread, so the checks run there; nothing native exists before fork.
        #[allow(unsafe_code, reason = "native gates need the process main thread")]
        // SAFETY: this disposable child runs one test; no native state or other
        // test exists yet, and the forked side only runs the checks and exits.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork for the native main thread failed");
        if pid == 0 {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                checks(std::path::Path::new(&fixture));
            }));
            if result.is_ok() {
                println!("{marker}");
            }
            let _ = std::io::stdout().flush();
            let _ = std::io::stderr().flush();
            #[allow(
                unsafe_code,
                reason = "the native child must bypass WebKit thread-exit finalizers"
            )]
            // SAFETY: gate-owned Rust values have dropped; only this disposable child exits.
            unsafe {
                libc::_exit(i32::from(result.is_err()))
            }
        }
        let mut status = 0;
        #[allow(unsafe_code, reason = "reap the forked native process")]
        // SAFETY: `pid` is this process's own unreaped child.
        let reaped = unsafe { libc::waitpid(pid, &mut status, 0) };
        let passed = reaped == pid && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0;
        #[allow(unsafe_code, reason = "the test process exits with the native result")]
        // SAFETY: only this disposable child process exits.
        unsafe {
            libc::_exit(i32::from(!passed))
        }
    }

    let log = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("wpe-native-{}-{name}.log", std::process::id()));
    let output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&log)
        .expect("native child log");
    let fixture = log.with_extension("fixture");
    std::fs::create_dir(&fixture).expect("create native child fixture");
    let mut child = Command::new(std::env::current_exe().expect("test executable"))
        .args(["--exact", name, "--ignored", "--nocapture"])
        .env(CHILD_ROLE, name)
        .env(CHILD_FIXTURE, &fixture)
        .process_group(0)
        .stdout(Stdio::from(output.try_clone().expect("stdout log")))
        .stderr(Stdio::from(output))
        .spawn()
        .expect("native child");
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut timed_out = false;
    let status = loop {
        if let Some(status) = child.try_wait().expect("native child status") {
            break status;
        }
        if Instant::now() >= deadline {
            timed_out = true;
            let group = i32::try_from(child.id()).expect("process group id");
            assert!(group > 1);
            #[allow(
                unsafe_code,
                reason = "timed-out native gates require process-group cleanup"
            )]
            // SAFETY: the unreaped child leads the process group created above.
            unsafe {
                libc::kill(-group, libc::SIGKILL)
            };
            break child.wait().expect("reap timed-out native child");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let output = std::fs::read_to_string(&log).expect("read native child log");
    print!("{output}");
    assert!(
        !timed_out,
        "native child exceeded its deadline; log: {}",
        log.display()
    );
    assert!(
        status.success(),
        "native child failed; log: {}",
        log.display()
    );
    assert!(
        output.lines().any(|line| line == marker),
        "native child did not complete the gates"
    );
    std::fs::remove_dir_all(fixture).expect("remove native child fixture after exit");
    std::fs::remove_file(log).expect("remove successful child log");
}
