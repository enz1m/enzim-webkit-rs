//! Main-thread metadata publication through the production worker and bounded queue.
//!
//! Run through the reviewed source runtime with its native dependencies:
//! `cargo test --offline --locked --release --workspace --features webview-probe/diagnostics --test native_metadata native_metadata_ -- --ignored --nocapture`.

#[test]
#[ignore = "requires native WPE and its reviewed source runtime"]
fn native_metadata_reuses_complete_snapshots_and_publishes_without_gpu_frames() {
    let output = std::process::Command::new("timeout")
        .args([
            "-k",
            "2",
            "30",
            env!("CARGO_BIN_EXE_webview-probe"),
            "--metadata-check",
        ])
        .output()
        .expect("bounded main-thread metadata child");
    let stdout = String::from_utf8_lossy(&output.stdout);
    println!("{stdout}{}", String::from_utf8_lossy(&output.stderr));
    assert!(
        output.status.success(),
        "metadata child failed: {}",
        output.status
    );
    assert!(
        stdout.contains("Metadata gate completed:"),
        "metadata child did not complete its real worker checks"
    );
}
