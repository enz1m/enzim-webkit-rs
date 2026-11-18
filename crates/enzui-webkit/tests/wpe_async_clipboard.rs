//! Main-thread page copy responsiveness and identity boundaries.
//!
//! ```text
//! cargo test --offline --locked --workspace --features enzui-webkit/wpe --test wpe_async_clipboard clipboard_async_ -- --ignored --nocapture
//! ```

mod wpe_native_support;

#[test]
#[ignore = "requires WPE native runtime"]
fn clipboard_async_owner_completion_preserves_page_copy_and_lifecycle() {
    wpe_native_support::run(
        "clipboard_async_owner_completion_preserves_page_copy_and_lifecycle",
        || {
            let output = std::process::Command::new(env!(
                "CARGO_BIN_EXE_enzui-webkit-browser-clipboard-probe"
            ))
            .output()
            .expect("main-thread clipboard probe");
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            println!("{stdout}{stderr}");
            assert!(output.status.success(), "clipboard native probe failed");
            for marker in [
                "Body/input selection and gesture/focus start guards passed",
                "Exact native session identity guard passed",
                "Page-initiated navigation epoch guard passed",
                "Busy-page real copy handler is asynchronous passed",
                "Accepted copy survives ordinary window defocus passed",
                "Cancellation, supersession, navigation and generation guards passed",
                "Page copy cancellation is not replaced by a selection fallback passed",
            ] {
                assert!(
                    stdout.contains(marker),
                    "missing clipboard qualification: {marker}"
                );
            }
        },
    );
}
