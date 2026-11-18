# Contributing

Keep the engine independent of UI toolkits. enzUI widget integration belongs in
`enzui-webview`; use the published SDK and matching foundation pins.

Run formatting, strict Clippy and the focused tests for the affected behavior.
Retain tests for security boundaries, ownership, cancellation and observable API
behavior. Native tests require their documented runtime and graphical environment.
Loopback transport fixtures need an ordinary test network; host XDP packet
filters can interfere with bulk-transfer checks. Use a private network namespace
for those checks when needed. Use disposable profiles and test data, and keep local logs and captures under
ignored `AGENTS/`. Do not use personal browsing profiles for verification.

Keep runtime/engine.json aligned with an exact commit in the WebKit fork. Native
source changes and dependency recipes belong in the engine and packaging projects.
A runtime update needs matching source identity and verification. Keep the renderer
sandbox, credential guard and destination policy enabled. Document unsafe FFI
contracts at the boundary and report unsupported capabilities explicitly.
