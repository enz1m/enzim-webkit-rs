//! `wpe_sandbox` - the real WebKit WebProcess is reached through
//! bubblewrap, and every native entry point refuses to start when the
//! environment would weaken the sandbox.
//!
//! ```text
//! cargo test --features sandbox-test-entrypoints -p enzui-webkit \
//!     --test wpe_sandbox -- --ignored --nocapture --test-threads=1
//! ```

#![cfg(all(feature = "wpe", feature = "sandbox-test-entrypoints"))]

mod wpe_native_support;

use std::process::Command;
use std::time::{Duration, Instant};

use enzui_webkit::ffi::runtime::{
    HeadlessDisplay, SessionError, SnapshotError, WebSession, snapshot_data_url,
    snapshot_data_url_without_sandbox_preflight_for_negative_control,
};
use enzui_webkit::frame::Generation;
use enzui_webkit::frame_plan::FrameSeq;
use enzui_webkit::sandbox::{
    self, DEBUG_PERMISSIONS_VARIABLE, DISABLE_VARIABLE, INSPECTOR_VARIABLE, NamespaceKind,
    ProcessTable, SandboxAttestation, UnattestedReason, WEB_PROCESS_COMM,
    verify_launcher_executable,
};

/// A trivial deterministic page. The pixels are irrelevant here - the point is
/// that a WebProcess exists at all - but a real load is what spawns it.
const PAGE: &str = "data:text/html,<!DOCTYPE html><html><body style='background:rgb(0,128,255)'>\
sandbox gate</body></html>";

/// Selects the re-exec'd child role.
const ROLE_VARIABLE: &str = "ENZUI_SANDBOX_CHILD_ROLE";

/// Wait until this process has a `WPEWebProcess` descendant, then attest.
///
/// Bounded, and loud on expiry: "no WebProcess found" must never be reported as
/// a pass by either side of this gate.
fn attest_when_web_process_exists(
    label: &str,
    budget: Duration,
) -> Result<SandboxAttestation, String> {
    let me = std::process::id();
    let deadline = Instant::now() + budget;
    loop {
        let table = ProcessTable::read();
        if table.len() < 5 {
            return Err(format!(
                "{label}: /proc yielded {} processes; the reader is broken",
                table.len()
            ));
        }
        if !table.web_processes(me).is_empty() {
            return Ok(sandbox::attest_tree(&table, me));
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "{label}: no {WEB_PROCESS_COMM} descendant of pid {me} within {budget:?} — \
                 WebKit never spawned a renderer, so nothing was attested"
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// gate1: the real WebProcess of a real session is bubblewrap-isolated, and
/// `load` enforces that rather than merely reporting it.
fn gate1_real_web_process_is_isolated() -> Result<(), String> {
    let display = HeadlessDisplay::new().expect("headless WPE display");
    let mut session = WebSession::new(&display).map_err(|e| format!("gate1 new: {e}"))?;

    // the constructor spawns the renderer on INERT content and attests it
    // before returning, so by here a renderer exists AND has been attested. The
    // two observables that make that specific rather than vague:
    //
    //  * the session recorded the renderer identity it attested, and
    //  * the only page that has run in it so far is `about:blank` - no caller
    //    URI, script or network fetch preceded the verdict.
    let established = session.attested_renderer().ok_or_else(|| {
        "gate1: the constructor returned without attesting a renderer".to_string()
    })?;
    let bootstrapped = session
        .current_uri()
        .map_err(|e| format!("gate1 current_uri refused the bootstrap URI: {e:?}"))?
        .unwrap_or_default();
    if !bootstrapped.starts_with("about:blank") {
        return Err(format!(
            "gate1: the pre-attestation page was {bootstrapped:?}, not inert about:blank — \
             caller content could run before the sandbox verdict"
        ));
    }
    if !session.attest_sandbox().is_isolated() {
        return Err(format!(
            "gate1: the bootstrap renderer {} is not attested, yet construction succeeded",
            established.pid
        ));
    }
    println!(
        "gate1: renderer {} attested on inert {bootstrapped} BEFORE any caller URL OK",
        established.pid
    );

    // This is the enforcement point: `load` returns Err and terminates the
    // renderer if it cannot be attested.
    session
        .load(PAGE, 10_000)
        .map_err(|e| format!("gate1 load (enforced): {e}"))?;
    for _ in 0..4 {
        session.pump(200);
    }

    let verdict = attest_when_web_process_exists("gate1", Duration::from_secs(10))?;
    let (renderer, bwrap_ancestor, host, web) = match &verdict {
        SandboxAttestation::BubblewrapIsolated {
            renderer,
            bwrap_ancestor,
            host,
            web,
        } => (*renderer, *bwrap_ancestor, host.clone(), web.clone()),
        other => {
            return Err(format!(
                "gate1: the real WebProcess is NOT attested: {other:?}. The contract requires \
                 WebKit process sandboxing to stay enabled."
            ));
        }
    };
    println!("gate1: {}", verdict.summary());
    println!("gate1: host {host:?}");
    println!("gate1: web  {web:?}");

    // The isolation must be structural, not a coincidence of one namespace.
    if host.mnt == web.mnt || host.pid == web.pid || host.user == web.user {
        return Err(format!("gate1: a namespace is shared: {host:?} vs {web:?}"));
    }

    // Evidence of the mechanism: the named `bwrap` must be on the renderer's
    // OWN ancestry chain, not merely somewhere in the process tree. A walk that
    // only looked one level down, or only asked "does any bwrap exist", would
    // pass without this.
    let table = ProcessTable::read();
    let me = std::process::id();
    let chain = table
        .ancestry_to(renderer.pid, me)
        .ok_or_else(|| format!("gate1: attested pid {} left our tree", renderer.pid))?;
    if !chain.contains(&bwrap_ancestor.pid) {
        return Err(format!(
            "gate1: the named bwrap {} is not on the renderer's chain {chain:?}",
            bwrap_ancestor.pid
        ));
    }
    if table.comm(bwrap_ancestor.pid) != Some("bwrap") {
        return Err(format!(
            "gate1: pid {} is not a bwrap ({:?})",
            bwrap_ancestor.pid,
            table.comm(bwrap_ancestor.pid)
        ));
    }
    // ...and `comm` is not the evidence. The launcher's `/proc/<pid>/exe` must
    // be a trusted bwrap binary by device+inode; the feature-off control
    // `a_fake_executable_named_bwrap_does_not_launder_a_renderer` proves the
    // same check refuses a forgery.
    verify_launcher_executable(bwrap_ancestor.pid).map_err(|why| {
        format!(
            "gate1: the named bwrap {} is not a trusted binary: {why}",
            bwrap_ancestor.pid
        )
    })?;
    println!(
        "gate1: renderer {} reached through bwrap {} OK",
        renderer.pid, bwrap_ancestor.pid
    );
    Ok(())
}

/// gate4: enforcement's side effect is verified, not merely requested.
///
/// `webkit_web_view_terminate_web_process` returns `void`; a caller that says
/// "it has been terminated" on the strength of having called it is asserting
/// something it never observed. This drives the real termination path and
/// requires evidence in both directions:
///
/// * waiting on a live renderer nobody terminated must FAIL, so success there
///   would mean the verification is assumed rather than read (this is the
///   half a sabotage of the `gone` requirement reddens);
/// * a real budget must succeed, and the two facts - the renderer identity is
///   gone from `/proc`, and WebKit delivered `web-process-terminated` for THIS
///   view - are then asserted independently of the helper's own return value.
fn gate4_termination_is_verified_not_assumed() -> Result<(), String> {
    let display = HeadlessDisplay::new().expect("headless WPE display");
    let session = WebSession::new(&display).map_err(|e| format!("gate4 new: {e}"))?;
    let renderer = session
        .attested_renderer()
        .ok_or_else(|| "gate4: no attested renderer to terminate".to_string())?;
    if sandbox::process_is_gone(renderer) {
        return Err("gate4: the renderer was already gone; the control is vacuous".to_string());
    }

    // Negative control: wait for a live renderer nobody terminated. The
    // verification must fail, which shows it reads both facts. (A zero budget
    // was the old control; it no longer is one: the kill is synchronous and
    // an exited renderer its sandbox parent has not reaped yet is already
    // gone, so a single pass genuinely observes it.)
    match session.await_renderer_termination_without_terminating_for_negative_control(300) {
        Err(why) => println!("gate4: a live renderer cannot be verified terminated OK ({why})"),
        Ok(()) => {
            return Err(
                "gate4: a live, untouched renderer was reported terminated — the \
                 verification is assumed, not observed"
                    .to_string(),
            );
        }
    }

    session
        .terminate_web_process_verified_within(5_000)
        .map_err(|why| format!("gate4: termination could not be verified: {why}"))?;

    if !sandbox::process_is_gone(renderer) {
        return Err(format!(
            "gate4: renderer {} is still present after a VERIFIED termination",
            renderer.pid
        ));
    }
    if session.web_process_termination().is_none() {
        return Err(
            "gate4: no web-process-terminated signal was delivered for this view, so the \
             termination cannot be attributed to it"
                .to_string(),
        );
    }
    println!(
        "gate4: renderer {} gone AND web-process-terminated delivered for this view OK",
        renderer.pid
    );
    Ok(())
}

/// Re-exec this binary in the child role with `extra` set in the environment.
fn run_child_with(extra: &[(&str, &str)], role: &str, markers: &[&str]) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let mut command = Command::new(exe);
    command.env(ROLE_VARIABLE, role);
    for (name, value) in extra {
        command.env(name, value);
    }
    let out = command
        .arg("--ignored")
        .arg("--nocapture")
        .arg("--test-threads=1")
        .arg("wpe_sandbox_child_role")
        .output()
        .map_err(|e| format!("child spawn: {e}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    for marker in markers {
        if !stdout.contains(marker) {
            return Err(format!(
                "missing marker {marker:?}\n--- child stdout ---\n{stdout}\
                 \n--- child stderr ---\n{stderr}"
            ));
        }
    }
    Ok(())
}

/// gate2: with the sandbox disabled, every production entry point refuses and
/// real WebKit attests as not isolated. Runs in a re-exec of this binary.
fn gate2_disabled_sandbox_refuses_and_attests_unisolated() -> Result<(), String> {
    run_child_with(
        &[(DISABLE_VARIABLE, "1")],
        "disabled",
        &[
            "child: WebSession::new refused with SandboxDisabled OK",
            "child: snapshot_data_url refused with SandboxDisabled OK",
            "child: real WebKit WebProcess attested NOT ISOLATED OK",
        ],
    )?;
    println!("gate2: child refusals + not-isolated attestation OK");
    Ok(())
}

/// gate3: the sandbox-weakening variables are refused too, and each on its own.
fn gate3_weakening_variables_refuse() -> Result<(), String> {
    for (name, value) in [
        (DEBUG_PERMISSIONS_VARIABLE, "1"),
        (INSPECTOR_VARIABLE, "127.0.0.1:2222"),
    ] {
        run_child_with(
            &[(name, value)],
            "weakened",
            &["child: WebSession::new refused a weakening variable OK"],
        )
        .map_err(|e| format!("gate3 [{name}]: {e}"))?;
        println!("gate3: {name} refused OK");
    }
    Ok(())
}

/// The child half of gates 2 and 3. Only meaningful with [`ROLE_VARIABLE`] set;
/// when a human runs the whole file it exits immediately as a no-op.
#[test]
#[ignore = "internal child role for gates 2-3; set ENZUI_SANDBOX_CHILD_ROLE"]
fn wpe_sandbox_child_role() {
    let Ok(role) = std::env::var(ROLE_VARIABLE) else {
        println!("child role: not selected, nothing to do");
        return;
    };
    wpe_native_support::run("wpe_sandbox_child_role", || {
        let result = match role.as_str() {
            "disabled" => run_disabled_child(),
            "weakened" => run_weakened_child(),
            other => Err(format!("unknown child role {other:?}")),
        };
        if let Err(e) = result {
            panic!("child: FAILED {e}");
        }
        println!("child: OK");
    });
}

fn run_disabled_child() -> Result<(), String> {
    let display = HeadlessDisplay::new().expect("headless WPE display");

    // Half one: the production constructor refuses.
    match WebSession::new(&display) {
        Err(SessionError::SandboxDisabled(refusal)) => {
            let text = refusal.to_string();
            if !text.contains(DISABLE_VARIABLE) {
                return Err(format!("refusal did not name the variable: {text}"));
            }
            println!("child: WebSession::new refused with SandboxDisabled OK");
        }
        Err(other) => return Err(format!("expected SandboxDisabled, got {other}")),
        Ok(_) => {
            return Err("WebSession::new SUCCEEDED with the sandbox disabled — the \
                 production path does not fail closed"
                .to_string());
        }
    }

    // Half two: the OTHER public entry point that spawns a renderer refuses as
    // well. This was the hole an independent review found: `snapshot_data_url`
    // rendered untrusted content with no preflight at all.
    match snapshot_data_url(&display, PAGE, 10_000, Generation::FIRST, FrameSeq(0)) {
        Err(SnapshotError::SandboxDisabled(_)) => {
            println!("child: snapshot_data_url refused with SandboxDisabled OK");
        }
        Err(other) => {
            return Err(format!(
                "expected SnapshotError::SandboxDisabled, got {other}"
            ));
        }
        Ok(_) => {
            return Err(
                "snapshot_data_url rendered a page with the sandbox disabled — \
                 the entry point does not preflight"
                    .to_string(),
            );
        }
    }

    // Half three: the negative control on real WebKit, through the one path
    // whose name says it skips the preflight. A renderer really does start
    // here; the attestation must refuse to call it isolated.
    let frame = snapshot_data_url_without_sandbox_preflight_for_negative_control(
        &display,
        PAGE,
        10_000,
        Generation::FIRST,
        FrameSeq(1),
    )
    .map_err(|e| format!("child snapshot: {e}"))?;
    if frame.width() == 0 {
        return Err("child snapshot produced a zero-width frame".to_string());
    }
    let verdict = attest_when_web_process_exists("child", Duration::from_secs(5))?;
    match &verdict {
        SandboxAttestation::Unattested(UnattestedReason::SharesHostNamespaces {
            shared, ..
        }) => {
            let want = vec![
                NamespaceKind::Mount,
                NamespaceKind::Pid,
                NamespaceKind::User,
            ];
            if *shared != want {
                return Err(format!("expected every namespace shared, got {shared:?}"));
            }
            println!(
                "child: real WebKit WebProcess attested NOT ISOLATED OK ({})",
                verdict.summary()
            );
        }
        other => {
            return Err(format!(
                "with {DISABLE_VARIABLE} set the renderer must not attest, got {other:?}"
            ));
        }
    }
    Ok(())
}

fn run_weakened_child() -> Result<(), String> {
    let display = HeadlessDisplay::new().expect("headless WPE display");
    match WebSession::new(&display) {
        Err(SessionError::SandboxDisabled(refusal)) => {
            println!("child: WebSession::new refused a weakening variable OK ({refusal})");
            Ok(())
        }
        Err(other) => Err(format!("expected SandboxDisabled, got {other}")),
        Ok(_) => Err(
            "WebSession::new SUCCEEDED with a sandbox-weakening variable set — \
             a namespace check alone cannot see this, so nothing else would have"
                .to_string(),
        ),
    }
}

#[test]
#[ignore = "requires the confined WPE source runtime"]
fn wpe_web_process_sandbox_is_enforced() {
    wpe_native_support::run("wpe_web_process_sandbox_is_enforced", || {
        // The parent must not inherit a weakened sandbox from the caller's shell,
        // or gate1 would be measuring the wrong thing and the children would be
        // indistinguishable from it.
        for name in [
            DISABLE_VARIABLE,
            DEBUG_PERMISSIONS_VARIABLE,
            INSPECTOR_VARIABLE,
        ] {
            if std::env::var_os(name).is_some() {
                panic!("gate: FAILED {name} is set in this shell; unset it");
            }
        }
        let outcome = gate1_real_web_process_is_isolated()
            // The children fork and render their own pages; run them after gate1
            // has read the process tree so the two never overlap.
            .and_then(|()| gate4_termination_is_verified_not_assumed())
            .and_then(|()| gate2_disabled_sandbox_refuses_and_attests_unisolated())
            .and_then(|()| gate3_weakening_variables_refuse());
        if let Err(e) = outcome {
            panic!("sandbox gate FAILED: {e}");
        }
        println!("wpe_web_process_sandbox_is_enforced: ALL GATES OK");
    });
}
