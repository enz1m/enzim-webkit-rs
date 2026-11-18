# enzim-webkit-rs contributor notes

Read README.md and the relevant engine or embedding guide. Keep enzui-webkit
independent of UI toolkits; only enzui-security may come from the enzUI SDK.
Widget integration and its tests belong in enzui-webview.

Use the pinned public SDK and foundation sources. Reuse CARGO_TARGET_DIR when
configured and keep machine-specific build policies outside the repository.
Run formatting, strict Clippy and focused tests for affected behavior. Retain
checks of security boundaries, ownership and observable runtime behavior.

Keep runtime/engine.json aligned with the maintained WebKit fork and its
qualified runtime builds. Engine patches, source bundles and native dependency
recipes belong in the engine/build repositories, not in this Rust workspace.
Keep sandbox and credential-guard enforcement enabled in product builds.

Keep local captures, review logs, profiles and credentials under ignored AGENTS/.
