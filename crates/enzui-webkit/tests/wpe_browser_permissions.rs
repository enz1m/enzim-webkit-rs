//! Origin-scoped permissions and exact LAN grants on the reviewed native runtime.
//!
//! Reviewed runtime:
//! ```text
//! cargo test --offline --locked --workspace --features enzui-webkit/wpe --test wpe_browser_permissions browser_permissions_origins_ -- --ignored --nocapture
//! cargo test --offline --locked --workspace --features enzui-webkit/wpe --test wpe_browser_permissions browser_permissions_notification_ -- --ignored --nocapture
//! ```
//! Unpatched runtime control:
//! ```text
//! cargo test --offline --locked --workspace --features enzui-webkit/wpe --test wpe_browser_permissions browser_permissions_unpatched_ -- --ignored --nocapture
//! ```
mod wpe_native_support;
#[test]
#[ignore = "requires the reviewed WPE origin metadata runtime and openssl"]
fn browser_permissions_origins_and_navigation_lifecycle() {
    wpe_native_support::run_with_fixture(
        "browser_permissions_origins_and_navigation_lifecycle",
        |fixture| {
            let result = std::process::Command::new(env!(
                "CARGO_BIN_EXE_enzui-webkit-browser-permissions-probe"
            ))
            .arg(fixture)
            .output()
            .unwrap();
            let stdout = String::from_utf8_lossy(&result.stdout);
            println!("{stdout}{}", String::from_utf8_lossy(&result.stderr));
            assert!(
                result.status.success(),
                "native browser permission probe failed"
            );
            for marker in [
                "Exact HTTP LAN navigation and revocation passed",
                "Exact LAN origins and native cross-origin permission attribution passed",
                "Navigation retires held permission requests passed",
                "Origin-scoped query grants and revocation passed",
                "Native geolocation watch revocation, blocked navigation and regrant passed",
                "Permission mode reset prompts again and mode-off restores legacy grant passed",
                "Mock capture combined grants and ended-track revocation passed",
                "Screen capture is asked for every request and never remembered passed",
            ] {
                assert!(
                    stdout.contains(marker),
                    "missing probe completion: {marker}"
                );
            }
        },
    );
}

#[test]
#[ignore = "requires a WPE runtime without the reviewed origin metadata"]
fn browser_permissions_unpatched_origin_metadata_fails_closed() {
    wpe_native_support::run_with_fixture(
        "browser_permissions_unpatched_origin_metadata_fails_closed",
        |fixture| {
            let result = std::process::Command::new(env!(
                "CARGO_BIN_EXE_enzui-webkit-browser-permissions-probe"
            ))
            .args([
                fixture.as_os_str(),
                std::ffi::OsStr::new("--legacy-control"),
            ])
            .output()
            .unwrap();
            let stdout = String::from_utf8_lossy(&result.stdout);
            println!("{stdout}{}", String::from_utf8_lossy(&result.stderr));
            assert!(result.status.success());
            assert!(stdout.contains(
                "Unpatched runtime explicitly refuses origin mode without changing existing policy"
            ));
        },
    );
}

#[test]
#[ignore = "requires the reviewed WPE origin metadata runtime and openssl"]
fn browser_permissions_notification_cache_cannot_bypass_origin_mode() {
    wpe_native_support::run_with_fixture(
        "browser_permissions_notification_cache_cannot_bypass_origin_mode",
        |fixture| {
            let output = std::process::Command::new(env!(
                "CARGO_BIN_EXE_enzui-webkit-browser-permissions-probe"
            ))
            .arg(fixture)
            .arg("--notifications")
            .output()
            .unwrap();
            let stdout = String::from_utf8_lossy(&output.stdout);
            println!("{stdout}{}", String::from_utf8_lossy(&output.stderr));
            assert!(
                output.status.success(),
                "native notification cache probe failed"
            );
            assert!(stdout.contains("Notification legacy delivery, cached-grant suppression and legacy restoration passed"));
        },
    );
}
