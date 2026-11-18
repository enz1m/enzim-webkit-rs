//! Installed WPE consumer with its original Cargo target hidden by a mount namespace.
//!
//! ```text
//! cargo test --offline --locked -p enzui-webkit --features wpe --test wpe_guard_installation wpe_guard_installed_consumer -- --ignored --nocapture
//! ```
//! The parent installs and invokes the internal child role; it needs WPE 2.52,
//! bubblewrap, OpenSSL and Python. The child must only run with the parent's fixture.

#![cfg(feature = "wpe")]

mod wpe_native_support;
mod wpe_tls_origin;

use enzui_webkit::ffi::deployment::{
    credential_guard_build_directory, set_credential_guard_directory,
};
use enzui_webkit::ffi::runtime::{HeadlessDisplay, WebSession};
use enzui_webkit::frame::Generation;
use enzui_webkit::frame_plan::FrameSeq;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const MODULE: &str = "libenzui_credential_guard.so";

/// The child role and fixture variables `wpe_native_support` reads. The mount
/// namespace hides the build tree that holds its logs, so this parent starts
/// the installed consumer directly in its native child role.
const NATIVE_CHILD_ROLE: &str = "ENZUI_WPE_NATIVE_GATE_CHILD";
const NATIVE_CHILD_FIXTURE: &str = "ENZUI_WPE_NATIVE_GATE_FIXTURE";

#[test]
#[ignore = "requires the confined WPE source runtime and bubblewrap installation isolation"]
fn wpe_guard_installed_consumer() {
    let origin = wpe_tls_origin::TlsRedirectOrigin::start().expect("real HTTPS fixture");
    let prefix = std::env::temp_dir().join(format!("enzui-installed-wpe-{}", std::process::id()));
    assert!(!prefix.exists(), "fresh installation prefix");
    std::fs::create_dir_all(prefix.join("bin")).unwrap();
    std::fs::create_dir_all(prefix.join("lib/guard")).unwrap();
    std::fs::create_dir_all(prefix.join("empty")).unwrap();
    let executable = std::env::current_exe().unwrap();
    let target = executable
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    std::fs::copy(&executable, prefix.join("bin/consumer")).unwrap();
    std::fs::copy(
        credential_guard_build_directory().join(MODULE),
        prefix.join("lib/guard").join(MODULE),
    )
    .unwrap();
    assert!(
        std::fs::read(&executable).unwrap() == std::fs::read(prefix.join("bin/consumer")).unwrap(),
        "installed consumer must match this test build"
    );
    assert!(
        std::fs::read(credential_guard_build_directory().join(MODULE)).unwrap()
            == std::fs::read(prefix.join("lib/guard").join(MODULE)).unwrap(),
        "installed guard must match this build"
    );
    std::fs::write(prefix.join("certificate.pem"), origin.cert_pem()).unwrap();
    for phase in ["default", "disappeared", "invalid-abi", "render"] {
        run_child(&prefix, target, &origin, phase);
    }
    assert_eq!(origin.count("/installed-page"), 1);
    assert_eq!(origin.count("/safe-start"), 1);
    assert_eq!(origin.count("/safe-target"), 1);
    assert_eq!(origin.count("/credential-start"), 1);
    assert_eq!(
        origin.count("/credential-target"),
        0,
        "credential-bearing redirect must not reach target"
    );
    println!(
        "Installed consumer rendered real HTTPS with hidden build tree; safe source/target=1, credential source=1/target=0; evidence {}",
        prefix.display()
    );
    if let Some(destination) = std::env::var_os("ENZUI_GUARD_TEST_EVIDENCE") {
        std::fs::create_dir_all(&destination).unwrap();
        for file in [
            "render.stdout.log",
            "render.stderr.log",
            "default.stdout.log",
            "disappeared.stdout.log",
            "invalid-abi.stdout.log",
            "frame.rgba",
            "frame-0.rgba",
            "frame-1.rgba",
            "frame-2.rgba",
            "frame-size.txt",
        ] {
            std::fs::copy(prefix.join(file), Path::new(&destination).join(file)).unwrap();
        }
    }
    std::fs::remove_dir_all(&prefix).unwrap();
}

fn run_child(
    prefix: &Path,
    target: &Path,
    origin: &wpe_tls_origin::TlsRedirectOrigin,
    phase: &str,
) {
    let stdout = std::fs::File::create(prefix.join(format!("{phase}.stdout.log"))).unwrap();
    let stderr = std::fs::File::create(prefix.join(format!("{phase}.stderr.log"))).unwrap();
    let mut child = Command::new("bwrap")
        .args([
            "--die-with-parent",
            "--bind",
            "/",
            "/",
            "--dev-bind",
            "/dev",
            "/dev",
            "--ro-bind",
        ])
        .arg(prefix.join("empty"))
        .arg(target)
        .arg("--")
        .arg(prefix.join("bin/consumer"))
        .args([
            "--ignored",
            "--exact",
            "wpe_guard_installed_child",
            "--nocapture",
        ])
        .env("ENZUI_GUARD_TEST_PREFIX", prefix)
        .env("ENZUI_GUARD_TEST_ORIGIN", origin.url(""))
        .env("ENZUI_GUARD_TEST_PHASE", phase)
        .env(NATIVE_CHILD_ROLE, "wpe_guard_installed_child")
        .env(NATIVE_CHILD_FIXTURE, prefix)
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .expect("mount namespace child");
    let seconds = if phase == "default" || phase == "disappeared" {
        5
    } else {
        60
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(seconds);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "installed consumer exceeded deadline; evidence at {}",
                prefix.display()
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    };
    let stdout = std::fs::read_to_string(prefix.join(format!("{phase}.stdout.log"))).unwrap();
    let stderr = std::fs::read_to_string(prefix.join(format!("{phase}.stderr.log"))).unwrap();
    assert!(
        status.success(),
        "installed consumer {phase} failed: {status}\n{stdout}\n{stderr}\nevidence {}",
        prefix.display()
    );
    assert!(
        stdout.contains("INSTALLED_WPE_OK"),
        "child did not execute native gate"
    );
    println!("{phase}: {stdout}");
}

#[test]
#[ignore = "internal child role for installed WPE consumer"]
fn wpe_guard_installed_child() {
    wpe_native_support::run("wpe_guard_installed_child", || {
        // Only meaningful when spawned by its parent, which requires the OK marker.
        let Some(prefix) = std::env::var_os("ENZUI_GUARD_TEST_PREFIX").map(PathBuf::from) else {
            return;
        };
        if let Err(error) = run_installed(&prefix) {
            panic!("INSTALLED_WPE_FAILED: {error}");
        }
        println!("INSTALLED_WPE_OK");
    });
}

fn run_installed(prefix: &Path) -> Result<(), String> {
    let executable = std::env::current_exe().map_err(|e| e.to_string())?;
    if executable != prefix.join("bin/consumer") {
        return Err("child did not execute the installed consumer".into());
    }
    println!("Installed executable: {}", executable.display());
    if credential_guard_build_directory().join(MODULE).exists() {
        return Err("original build module remained reachable".into());
    }
    let depth = std::env::current_dir()
        .map_err(|e| e.to_string())?
        .components()
        .filter(|c| matches!(c, std::path::Component::Normal(_)))
        .count();
    let relative_valid = PathBuf::from("../".repeat(depth))
        .join(prefix.strip_prefix("/").map_err(|e| e.to_string())?)
        .join("lib/guard");
    let nonregular = prefix.join("nonregular");
    std::fs::create_dir_all(nonregular.join(MODULE)).map_err(|e| e.to_string())?;
    let fifo = prefix.join("fifo");
    std::fs::create_dir_all(&fifo).map_err(|e| e.to_string())?;
    if !fifo.join(MODULE).exists() {
        let status = Command::new("mkfifo")
            .arg(fifo.join(MODULE))
            .status()
            .map_err(|e| e.to_string())?;
        if !status.success() {
            return Err("FIFO fixture creation failed".into());
        }
    }
    for invalid in [
        fifo,
        relative_valid,
        nonregular,
        prefix.join("absent"),
        prefix.join("empty"),
        prefix.join("certificate.pem"),
    ] {
        if set_credential_guard_directory(&invalid).is_ok() {
            return Err(format!("invalid directory accepted: {}", invalid.display()));
        }
    }
    let phase = std::env::var("ENZUI_GUARD_TEST_PHASE").map_err(|e| e.to_string())?;
    if phase == "default" {
        if !matches!(
            HeadlessDisplay::new(),
            Err(enzui_webkit::ffi::runtime::DisplayError::CredentialGuardUnavailable(_))
        ) {
            return Err("missing default guard did not fail visibly".into());
        }
        return Ok(());
    }
    if phase == "invalid-abi" || phase == "disappeared" {
        let broken = prefix.join(&phase);
        std::fs::create_dir(&broken).map_err(|e| e.to_string())?;
        std::fs::write(broken.join(MODULE), b"not a native module").map_err(|e| e.to_string())?;
        set_credential_guard_directory(&broken)?;
        if phase == "disappeared" {
            std::fs::remove_file(broken.join(MODULE)).map_err(|e| e.to_string())?;
            if !matches!(
                HeadlessDisplay::new(),
                Err(enzui_webkit::ffi::runtime::DisplayError::CredentialGuardUnavailable(_))
            ) {
                return Err("disappeared selected guard did not fail visibly".into());
            }
        } else {
            let display = HeadlessDisplay::new().map_err(|e| format!("display: {e:?}"))?;
            if !matches!(
                WebSession::new_trusted_local(&display),
                Err(enzui_webkit::ffi::runtime::SessionError::CredentialGuardUnavailable(_))
            ) {
                return Err("invalid native module did not fail its required handshake".into());
            }
        }
        return Ok(());
    }
    if phase != "render" {
        return Err("unknown installation phase".into());
    }
    let directory = prefix.join("lib/guard");
    set_credential_guard_directory(&directory)?;
    let display = HeadlessDisplay::new().map_err(|e| format!("display: {e:?}"))?;
    if set_credential_guard_directory(&directory).is_ok() {
        return Err("late guard replacement accepted".into());
    }
    let mut session =
        WebSession::new_trusted_local(&display).map_err(|e| format!("session: {e}"))?;
    if !session.attest_sandbox().is_isolated() {
        return Err("installed renderer sandbox not isolated".into());
    }
    session
        .allow_tls_certificate_for_host(
            &std::fs::read(prefix.join("certificate.pem")).map_err(|e| e.to_string())?,
            "localhost",
        )
        .map_err(|e| e.to_string())?;
    let mut router = enzui_webkit::web::ViewRouter::new();
    let view = router.create(3305);
    let mut policy = enzui_webkit::web::WebPolicy::strict();
    policy.allow_insecure_certificates = true;
    session
        .bind_view(&router, view)
        .map_err(|e| e.to_string())?;
    session
        .install_native_policy(&router, view, policy, |request| Some(request.id))
        .map_err(|e| e.to_string())?;
    let origin = std::env::var("ENZUI_GUARD_TEST_ORIGIN").map_err(|e| e.to_string())?;
    session
        .load(&format!("{origin}/installed-page"), 10000)
        .map_err(|e| e.to_string())?;
    session.pump(500);
    let mut ink = 0;
    for seq in 0..6 {
        let frame = session
            .snapshot(Generation::FIRST, FrameSeq(seq), 10000)
            .map_err(|e| e.to_string())?;
        ink = frame
            .pixels()
            .as_chunks::<4>()
            .0
            .iter()
            .filter(|p| p[3] == 255 && p[0] > 220 && p[1] > 220 && p[2] > 220)
            .count();
        let green = frame
            .pixels()
            .as_chunks::<4>()
            .0
            .iter()
            .filter(|p| **p == [18, 170, 68, 255])
            .count();
        if ink > 50 && green > (frame.width() as usize * frame.height() as usize) * 95 / 100 {
            for repeat in 0..3 {
                let repeated = session
                    .snapshot(Generation::FIRST, FrameSeq(seq + 10 + repeat), 10000)
                    .map_err(|e| e.to_string())?;
                if repeated.pixels() != frame.pixels() {
                    return Err("same-input native HTTPS snapshots changed".into());
                }
                std::fs::write(
                    prefix.join(format!("frame-{repeat}.rgba")),
                    repeated.pixels(),
                )
                .map_err(|e| e.to_string())?;
            }
            std::fs::write(prefix.join("frame.rgba"), frame.pixels()).map_err(|e| e.to_string())?;
            std::fs::write(
                prefix.join("frame-size.txt"),
                format!("{} {}", frame.width(), frame.height()),
            )
            .map_err(|e| e.to_string())?;
            break;
        }
        ink = 0;
        session.pump(300);
    }
    if ink <= 50 {
        return Err("real HTTPS page did not produce the green page and white text".into());
    }
    session
        .load(&format!("{origin}/safe-start"), 10000)
        .map_err(|e| e.to_string())?;
    session
        .begin_load_uri(&format!("{origin}/credential-start"))
        .map_err(|e| e.to_string())?;
    session.pump(2000);
    let observations = session
        .native_policy_observations()
        .ok_or("native policy observations absent")?;
    let denied = observations.iter().any(|observation| {
        matches!(
            observation.outcome,
            enzui_webkit::ffi::policy::NativePolicyOutcome::Applied(
                enzui_webkit::web::Decision::Deny(
                    enzui_webkit::web::policy::DenyReason::SchemeRefused(
                        enzui_security::url_policy::UrlVerdict::CredentialsInUrl
                    )
                )
            )
        )
    });
    if !denied {
        return Err("typed credential-bearing HTTPS redirect refusal absent".into());
    }
    let diagnostics = format!("{:?}", observations.to_vec());
    if diagnostics.contains("TOP-SECRET") || diagnostics.contains("redirect-user") {
        return Err("credential diagnostics retained userinfo".into());
    }
    println!(
        "HTTPS snapshot ink={ink}; sandbox isolated; typed credential refusal; build tree unavailable"
    );
    Ok(())
}
