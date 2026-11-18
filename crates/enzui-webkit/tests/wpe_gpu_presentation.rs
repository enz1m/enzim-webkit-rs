//! Compositor DMA-BUF leases are exercised by a consumer on its process main thread.
//!
//! ```text
//! cargo test --offline --locked --workspace --features enzui-webkit/wpe --test wpe_gpu_presentation gpu_presentation_ -- --ignored --nocapture
//! ```

mod wpe_native_support;

#[test]
#[ignore = "requires native WPE runtime and EGL/GLES"]
fn gpu_presentation_exports_real_frames_without_snapshot_readback() {
    wpe_native_support::run(
        "gpu_presentation_exports_real_frames_without_snapshot_readback",
        || {
            let mut command =
                std::process::Command::new(env!("CARGO_BIN_EXE_enzui-webkit-gpu-probe"));
            if enzui_webkit::ffi::native_requires_process_main_thread() {
                command.arg("--expect-main-thread");
            }
            let output = command
                .env("G_DEBUG", "fatal-criticals")
                .output()
                .expect("main-thread GPU probe");
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            println!("{stdout}{stderr}");
            assert!(
                output.status.success(),
                "GPU probe failed: {}",
                output.status
            );
            assert!(stdout.lines().any(|line| line == "GPU presentation probe completed: DMA-BUF export, EGL import, stable leases, discard, generation, zero snapshot copies"));
        },
    );
}

#[test]
#[ignore = "requires native WPE runtime and compositor DMA-BUFs"]
fn gpu_presentation_shared_completion_transport() {
    wpe_native_support::run("gpu_presentation_shared_completion_transport", || {
        for (args, marker) in [
            (
                ["--completion-lifecycle"],
                "Completion lifecycle completed:",
            ),
            (["--owner-completion"], "Owner completion completed:"),
        ] {
            let output = std::process::Command::new(env!("CARGO_BIN_EXE_enzui-webkit-gpu-probe"))
                .args(args)
                .env("G_DEBUG", "fatal-criticals")
                .output()
                .expect("main-thread completion probe");
            let stdout = String::from_utf8_lossy(&output.stdout);
            println!("{stdout}{}", String::from_utf8_lossy(&output.stderr));
            assert!(
                output.status.success(),
                "completion transport probe failed: {}",
                output.status
            );
            assert!(
                stdout.contains(marker),
                "completion probe did not execute its selected path"
            );
        }
    });
}

#[test]
#[ignore = "requires native WPE runtime and compositor DMA-BUFs"]
fn gpu_presentation_shared_allocation_metadata() {
    wpe_native_support::run("gpu_presentation_shared_allocation_metadata", || {
        let args = ["--shared-buffer-lifecycle"];
        let marker = "Shared buffer lifecycle completed:";
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_enzui-webkit-gpu-probe"))
            .args(args)
            .env("G_DEBUG", "fatal-criticals")
            .output()
            .expect("shared buffer probe");
        let stdout = String::from_utf8_lossy(&output.stdout);
        println!("{stdout}{}", String::from_utf8_lossy(&output.stderr));
        assert!(
            output.status.success(),
            "shared buffer probe failed: {}",
            output.status
        );
        assert!(
            stdout.contains(marker),
            "shared buffer probe did not execute its selected path"
        );
    });
}
