//! Actual native profile inventory and selective cleanup, on a process main thread.
//!
//! ```text
//! cargo test --offline --locked --workspace --features enzui-webkit/wpe --test wpe_site_data site_data_native_ -- --ignored --nocapture
//! ```

mod wpe_native_support;
use std::os::unix::process::CommandExt;

struct ProbeGroup(std::process::Child);
impl Drop for ProbeGroup {
    fn drop(&mut self) {
        let group = i32::try_from(self.0.id()).expect("probe process group");
        assert!(group > 1);
        #[allow(
            unsafe_code,
            reason = "clean only the isolated probe's process group, including descendants after a native crash"
        )]
        // SAFETY: this child was spawned as leader of its own dedicated process group.
        unsafe {
            libc::kill(-group, libc::SIGKILL);
        }
        let _ = self.0.wait();
    }
}

#[test]
#[ignore = "requires WPE native runtime, Python and OpenSSL"]
fn site_data_native_profile_inventory_and_selective_cleanup() {
    wpe_native_support::run_with_fixture(
        "site_data_native_profile_inventory_and_selective_cleanup",
        |fixture| {
            let stdout_path = fixture.join("probe.stdout");
            let stderr_path = fixture.join("probe.stderr");
            let mut probe = ProbeGroup(
                std::process::Command::new(env!(
                    "CARGO_BIN_EXE_enzui-webkit-browser-site-data-probe"
                ))
                .arg(fixture)
                .process_group(0)
                .stdout(std::fs::File::create(&stdout_path).expect("probe stdout"))
                .stderr(std::fs::File::create(&stderr_path).expect("probe stderr"))
                .spawn()
                .expect("main-thread site-data probe"),
            );
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(45);
            let status = loop {
                if let Some(status) = probe.0.try_wait().expect("probe status") {
                    break Some(status);
                }
                if std::time::Instant::now() >= deadline {
                    break None;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            };
            drop(probe);
            let stdout = std::fs::read_to_string(stdout_path).expect("probe stdout");
            let stderr = std::fs::read_to_string(stderr_path).expect("probe stderr");
            println!("{stdout}{stderr}");
            assert!(
                status.is_some_and(|status| status.success()),
                "native site-data probe failed: {status:?}"
            );
            for marker in [
                "Owned cookie flags, expiry and two-profile positive controls passed",
                "Exact cookie deletion preserves other profile, domain, path and name passed",
                "Native grouped cleanup and exact-origin typed refusal passed",
                "Cancellation and ephemeral reopen-empty passed",
                "Pending cookie inventory retains session through native GTask teardown passed",
            ] {
                assert!(
                    stdout.contains(marker),
                    "missing native completion: {marker}"
                );
            }
        },
    );
}
