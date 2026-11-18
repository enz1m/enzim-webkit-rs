//! Real isolated and non-isolated processes for the sandbox
//! attestation.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use enzui_webkit::sandbox::{
    DISABLE_VARIABLE, NamespaceKind, ProcessTable, RealEnv, SandboxAttestation, SandboxEnv,
    SandboxRefusal, UnattestedReason, WEB_PROCESS_COMM, attest_tree, preflight,
    trusted_launcher_identities, verify_launcher_executable,
};

/// The controls observe *this process's* descendants, so two of them running at
/// once would see each other's children and disagree about the verdict. They
/// are serialised rather than split into separate binaries so the shared setup
/// stays in one place.
fn control_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Kill the child on the way out of the test, including on panic.
struct Reaped(Child);

impl Drop for Reaped {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A copy of `sleep`, named `WPEWebProcess` so `/proc/<pid>/comm` matches
/// discovery.
///
/// One copy per control, in its own directory: the file name has to be
/// exactly [`WEB_PROCESS_COMM`] for discovery to see it, and a previous
/// control's child (or its own grandchild, under `unshare --fork`) can still
/// hold the image open, which makes overwriting it `ETXTBSY`.
fn web_process_lookalike(label: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("sandbox-controls")
        .join(label);
    fs::create_dir_all(&dir).expect("scratch dir");
    let dest = dir.join(WEB_PROCESS_COMM);
    let source = ["/usr/bin/sleep", "/bin/sleep"]
        .into_iter()
        .map(PathBuf::from)
        .find(|p| p.exists())
        .expect("a `sleep` binary is required for the process controls");
    fs::copy(&source, &dest).expect("copy sleep");
    let mut perms = fs::metadata(&dest).expect("stat copy").permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&dest, perms).expect("chmod copy");
    dest
}

/// Wait until at least one `WPEWebProcess` descendant of this process exists,
/// then return the table that saw it.
///
/// A bounded poll, not a sleep: `bwrap` has to unshare and exec before the
/// process is visible, and the wait is over the *observation* rather than a
/// guessed duration.
fn wait_for_web_process(label: &str) -> ProcessTable {
    let me = std::process::id();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let table = ProcessTable::read();
        assert!(
            table.len() > 5,
            "{label}: /proc yielded only {} processes; the reader is broken and \
             every verdict below would be vacuous",
            table.len()
        );
        if !table.web_processes(me).is_empty() {
            return table;
        }
        assert!(
            Instant::now() < deadline,
            "{label}: no {WEB_PROCESS_COMM} descendant of pid {me} appeared within 10s"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// A `WPEWebProcess` that is just a child process is not isolated, and the
/// attestation must say so through the real reader.
///
/// This is the state a build gets when the sandbox is switched off: the
/// renderer still runs, still has the right name, and shares the user's whole
/// filesystem view.
#[test]
fn a_plain_child_named_like_a_web_process_is_reported_unattested() {
    let _serial = control_lock();
    let binary = web_process_lookalike("plain");
    let _child = Reaped(
        Command::new(&binary)
            .arg("30")
            .spawn()
            .expect("spawn the lookalike"),
    );

    let table = wait_for_web_process("unconfined control");
    let me = std::process::id();
    let verdict = attest_tree(&table, me);

    match verdict {
        SandboxAttestation::Unattested(UnattestedReason::SharesHostNamespaces {
            shared, ..
        }) => {
            assert_eq!(
                shared,
                vec![
                    NamespaceKind::Mount,
                    NamespaceKind::Pid,
                    NamespaceKind::User
                ],
                "a plain child shares every namespace with its parent"
            );
        }
        other => panic!("expected an unattested verdict, got {other:?}"),
    }
}

/// The ancestry control. `unshare -Urpf` gives the child its own mount, PID
/// and user namespaces - exactly the three this module compares - without going
/// anywhere near WebKit's launcher. It must not attest.
///
/// Without this control, "all three namespaces differ" would be the whole
/// verdict, and any process that called `unshare` would be indistinguishable
/// from one WebKit sandboxed.
#[test]
fn a_child_that_unshares_without_bwrap_is_not_attested() {
    let _serial = control_lock();
    let unshare = PathBuf::from("/usr/bin/unshare");
    if !unshare.exists() {
        panic!(
            "/usr/bin/unshare is missing: the ancestry control cannot run, and \
             without it the positive control below proves only that namespaces \
             differ"
        );
    }
    let binary = web_process_lookalike("unshare");
    let _child = Reaped(
        Command::new(&unshare)
            .args([
                "--user",
                "--pid",
                "--mount",
                "--fork",
                "--kill-child",
                "--map-root-user",
            ])
            .arg(&binary)
            .arg("30")
            .spawn()
            .expect("spawn unshare"),
    );

    let table = wait_for_web_process("unshare control");
    let me = std::process::id();
    let verdict = attest_tree(&table, me);

    match verdict {
        SandboxAttestation::Unattested(UnattestedReason::NoBubblewrapAncestor {
            chain, ..
        }) => {
            assert!(
                chain.iter().any(|c| c.contains("unshare")),
                "the refusal must name the real chain, got {chain:?}"
            );
            assert!(
                !chain.iter().any(|c| c == "bwrap"),
                "control: this chain must contain no bwrap, got {chain:?}"
            );
        }
        other => panic!(
            "a child isolated by `unshare` alone must NOT attest as \
             bubblewrap-isolated, got {other:?}"
        ),
    }
}

/// The same binary, the same argument, the same parent - wrapped in `bwrap`.
///
/// The only variable against the two negatives above is the launcher, and the
/// verdict flips. Without this control the negatives would be satisfied by an
/// attestation that always answers "unattested".
#[test]
fn the_same_binary_under_bwrap_is_reported_isolated() {
    let _serial = control_lock();
    if !PathBuf::from("/usr/bin/bwrap").exists() {
        // WebKit's own sandbox needs bwrap too, so a host without it cannot run
        // a sandboxed WebProcess at all. Loud, because a silent skip here would
        // retire the positive control.
        panic!(
            "/usr/bin/bwrap is missing: this host cannot sandbox a WebProcess, \
             so the sandbox requirement cannot be met here"
        );
    }
    let binary = web_process_lookalike("bwrap");
    let _child = Reaped(
        Command::new("/usr/bin/bwrap")
            .args([
                "--ro-bind",
                "/",
                "/",
                "--dev",
                "/dev",
                "--proc",
                "/proc",
                "--unshare-user",
                "--unshare-pid",
                "--die-with-parent",
                "--",
            ])
            .arg(&binary)
            .arg("30")
            .spawn()
            .expect("spawn bwrap"),
    );

    let table = wait_for_web_process("bwrap control");
    let me = std::process::id();
    let verdict = attest_tree(&table, me);

    let (renderer, bwrap_ancestor) = match &verdict {
        SandboxAttestation::BubblewrapIsolated {
            renderer,
            bwrap_ancestor,
            ..
        } => (*renderer, *bwrap_ancestor),
        other => panic!("a bwrap-launched child must attest, got {other:?}"),
    };

    // The renderer is not a direct child: bwrap sits between, and the verdict
    // names which bwrap.
    assert_eq!(
        table.comm(bwrap_ancestor.pid),
        Some("bwrap"),
        "the named ancestor must actually be a bwrap"
    );
    assert!(
        table
            .ancestry_to(renderer.pid, me)
            .expect("the renderer is in our tree")
            .contains(&bwrap_ancestor.pid),
        "the named bwrap must be on the renderer's own ancestry chain"
    );

    // The claim is exactly as strong as the evidence: this child can read the
    // entire filesystem read-only, so the summary must not say "confined" and
    // must say what was not inspected.
    let summary = verdict.summary();
    assert!(
        summary.contains("not inspected"),
        "the isolated summary must disclaim what it did not check: {summary}"
    );
    assert!(
        !summary.to_lowercase().contains("confined"),
        "a --ro-bind / / child is NOT confined; the summary must not say so: {summary}"
    );
}

/// The forgery control. `comm` is the basename of the exec'd file, so any
/// binary copied to a file called `bwrap` reports `comm == "bwrap"`.
///
/// This control is a copy of `unshare` named `bwrap`: it produces a renderer
/// with its own mount, PID and user namespaces and an ancestor whose `comm`
/// is exactly what the ancestry rule looks for. Everything the previous version
/// of this module checked is satisfied, and it must still not attest - the
/// launcher's `/proc/<pid>/exe` is not a trusted bwrap binary.
///
/// Without this control, "reached through WebKit's bubblewrap launcher" was a
/// claim backed by an attacker-choosable string.
#[test]
fn a_fake_executable_named_bwrap_does_not_launder_a_renderer() {
    let _serial = control_lock();
    let unshare = PathBuf::from("/usr/bin/unshare");
    assert!(
        unshare.exists(),
        "/usr/bin/unshare is missing: the forgery control cannot be built"
    );
    assert!(
        !trusted_launcher_identities().is_empty(),
        "no trusted bwrap on this host: the control could not distinguish a \
         forgery from a genuine launcher"
    );

    // A copy of `unshare` whose FILE NAME is `bwrap`, so `comm` matches.
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("sandbox-controls")
        .join("fake-bwrap");
    fs::create_dir_all(&dir).expect("scratch dir");
    let fake = dir.join("bwrap");
    fs::copy(&unshare, &fake).expect("copy unshare as bwrap");
    let mut perms = fs::metadata(&fake).expect("stat").permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&fake, perms).expect("chmod");
    // Calibration: the forgery really is a different file from the real bwrap.
    assert!(
        verify_launcher_executable(std::process::id()).is_err(),
        "control: this test process is not bwrap, so verification must refuse it"
    );

    let renderer = web_process_lookalike("fake-bwrap-child");
    let _child = Reaped(
        Command::new(&fake)
            .args([
                "--user",
                "--pid",
                "--mount",
                "--fork",
                "--kill-child",
                "--map-root-user",
            ])
            .arg(&renderer)
            .arg("30")
            .spawn()
            .expect("spawn the fake bwrap"),
    );

    let table = wait_for_web_process("fake-bwrap control");
    let me = std::process::id();
    let verdict = attest_tree(&table, me);

    // Calibration: the forgery satisfies BOTH weaker rules - an ancestor whose
    // `comm` is `bwrap`, and three unshared namespaces. If either of these
    // fails, the control is not exercising the check it claims to.
    let renderer_pid = table
        .web_processes(me)
        .first()
        .map(|i| i.pid)
        .expect("the lookalike renderer is in our tree");
    let chain = table.comm_chain_to(renderer_pid, me);
    assert!(
        chain.iter().any(|c| c == "bwrap"),
        "control: the forged ancestor must report comm == bwrap, got {chain:?}"
    );

    match verdict {
        SandboxAttestation::Unattested(UnattestedReason::UntrustedBubblewrapAncestor {
            launcher_pid,
            why,
            ..
        }) => {
            assert_eq!(
                table.comm(launcher_pid),
                Some("bwrap"),
                "the refusal must name the process that CALLED itself bwrap"
            );
            assert!(
                why.contains("not any trusted bwrap"),
                "the refusal must say why the executable was rejected: {why}"
            );
        }
        other => panic!(
            "a copy of `unshare` named `bwrap` must NOT launder a renderer into an \
             attestation, got {other:?}"
        ),
    }
}

/// Selects the child role of the real-environment control below.
const ENV_ROLE_VARIABLE: &str = "ENZUI_SANDBOX_ENV_CHILD";

/// The real-environment reader must not lose a non-UTF-8 value.
///
/// `std::env::var(..).ok()` turns a non-UTF-8 value into `None`, which reads as
/// "the variable is not set" - a fail-open, because WebKit reads the raw bytes
/// and disables its sandbox for any value but `"0"`. The unit tests inject an
/// `OsString` into a fake environment and so cannot see this; only a real
/// process with a real environment can, which is why this control re-execs
/// itself with an invalid-UTF-8 value and asserts the child refused.
#[test]
fn a_non_utf8_disable_value_is_refused_in_a_real_environment() {
    use std::os::unix::ffi::OsStringExt;

    let raw = std::ffi::OsString::from_vec(vec![0x31, 0xff, 0xfe]);
    assert!(
        raw.clone().into_string().is_err(),
        "fixture control: the value must not be valid UTF-8"
    );

    let exe = std::env::current_exe().expect("current_exe");
    let out = Command::new(exe)
        .env(ENV_ROLE_VARIABLE, "1")
        .env(DISABLE_VARIABLE, &raw)
        .args(["--exact", "--nocapture", "the_real_environment_child_role"])
        .output()
        .expect("spawn the env child");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("env-child: refused a non-UTF-8 disable value OK"),
        "the child did not refuse. stdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// The child half of the control above. A no-op unless selected, so the
/// ordinary run of this file neither needs it nor is affected by it.
#[test]
fn the_real_environment_child_role() {
    if std::env::var_os(ENV_ROLE_VARIABLE).is_none() {
        return;
    }
    // The reader must see the variable at all...
    let raw = RealEnv.var(DISABLE_VARIABLE);
    assert!(
        raw.is_some(),
        "env-child: the real reader lost a non-UTF-8 value entirely"
    );
    assert!(
        raw.expect("checked").into_string().is_err(),
        "env-child: the fixture value arrived as valid UTF-8; the control is vacuous"
    );
    // ...and the production preflight must refuse because of it.
    match preflight() {
        Err(SandboxRefusal::DisableVariablePresent { lossy, .. }) => {
            assert!(lossy, "env-child: the refusal must record the lossy decode");
            println!("env-child: refused a non-UTF-8 disable value OK");
        }
        other => panic!("env-child: expected a refusal, got {other:?}"),
    }
}

/// The zero control: with no child at all the answer is "no WebProcess", not
/// "isolated". Holds the same lock so a live control cannot leak into it.
#[test]
fn with_no_child_the_verdict_is_web_process_not_found() {
    let _serial = control_lock();
    let table = ProcessTable::read();
    let verdict = attest_tree(&table, std::process::id());
    assert_eq!(
        verdict,
        SandboxAttestation::Unattested(UnattestedReason::WebProcessNotFound),
        "a test process with no renderer must report none"
    );
}
