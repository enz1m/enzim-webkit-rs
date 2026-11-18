# enzim-webkit-rs

Rust integration for [enzim-webkit](https://github.com/enz1m/enzim-webkit),
our WPE WebKit fork, with an enzUI/iced widget for native Linux applications.
The Rust crates keep their `enzui-webkit` and `enzui-webview` names.

| Crate | Purpose |
| --- | --- |
| `enzui-webkit` | Toolkit-free engine, sessions, profiles, input, navigation and security policy |
| `enzui-webview` | enzUI/iced widget, GPU frame import and accessibility integration |
| `webview-probe` | Interactive embedding example and diagnostic application |

The engine depends on enzUI's security primitives, without pulling in iced or
GTK. The adapter uses [enzUI Alpha 0.2](https://github.com/enz1m/enzui/releases/tag/v0.2.0-alpha.1)
and its pinned public foundation forks. No sibling framework checkout is needed.
This is a developer alpha. Native engine binaries are distributed separately
from the Rust source. The probe uses Wayland by default; add `--features webview-probe/x11`
for X11 support.

## Build

Use Rust **1.99.1** (minimum **1.95**), a C/C++ toolchain, pkg-config and the
Wayland/XKB, fontconfig and graphics development libraries required by enzUI.
The toolchain file selects the development compiler automatically.

```sh
git clone https://github.com/enz1m/enzim-webkit-rs.git
cd enzim-webkit-rs
cargo fetch --locked
cargo check --locked --workspace --all-targets
cargo build --locked --bin webview-probe
```

Without the `wpe` feature, the engine provides its mock backend and explicitly
refuses native sessions. Real rendering requires WPE WebKit **2.52 or newer**,
WPE Platform **2.50 or newer**, its headless plugin and **libsoup 3.8 or newer**
at runtime. The reviewed source runtimes use a patched WebKit development
snapshot. Optional APIs report unsupported runtimes explicitly.

```sh
cargo build --locked --bin webview-probe --features webview-probe/wpe
```

See the [engine guide](crates/enzui-webkit/README.md) for native headers, runtime
requirements and the mandatory credential guard. Cargo uses its ordinary target
directory; set `CARGO_TARGET_DIR` to reuse a compatible shared cache. Build and
interactive launch helpers impose no machine-specific memory or disk reserve.

## Use in an application

Select the engine alone for a host-owned integration, or the enzUI widget for
an iced application. Use the initial source release in your Cargo manifest:

```toml
[dependencies]
enzui-webkit = { git = "https://github.com/enz1m/enzim-webkit-rs.git", tag = "v0.1.0", features = ["wpe"] }
enzui-webview = { git = "https://github.com/enz1m/enzim-webkit-rs.git", tag = "v0.1.0", features = ["wpe"] }
```

Use the matching enzUI and iced sources, including the root Cargo patch table
for the published foundation forks. Cargo does not inherit patches from a
dependency's manifest; this workspace's Cargo.toml provides the matching pins.
The [embedding guide](docs/browser-embedding.md) covers permissions, downloads,
profiles, page events and host responsibilities. The probe demonstrates widget
integration. The host owns application chrome and user-facing policy decisions.

## Native runtime and launch

This repository contains the Rust integration and its small native FFI/credential
bridge. The engine source lives in the separate `enzim-webkit` fork, on its
`enzim` branch. [`runtime/engine.json`](runtime/engine.json) pins that engine's
repository, exact source commit, ABI and qualified compatible build identities.
It contains no engine patches or Git bundles.

Selected [engine releases](https://github.com/enz1m/enzim-webkit/releases) provide
native runtime and matching development SDK archives, dependency sources and
build inputs. Application developers compile Rust against the SDK and run with
the matching runtime; Cargo does not rebuild WebKit or perform PGO training.
Flatpak applications use the separately distributed Platform and SDK.

For a prepared native runtime and a locally built probe:

```sh
python3 tools/source_runtime.py --directory /path/to/runtime verify
./tools/browser --runtime /path/to/runtime https://example.org/
```

The launcher discovers the Cargo target directory, or accepts
`--binary /path/to/webview-probe`. It expects a release binary by default; pass
the debug binary explicitly when using a development build. File verification,
CPU compatibility, credential-guard setup and renderer sandbox enforcement remain
required. See [native runtime setup](docs/native-runtime.md) and
[Flatpak integration](docs/flatpak.md).

## Development

```sh
cargo fmt --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --lib mode::tests
```

The all-features check requires the native development libraries. Native page
and GPU integration tests name their required runtime and environment and are
ignored until explicitly selected. See [contributing](CONTRIBUTING.md).

## Guides

- [Engine API and native setup](crates/enzui-webkit/README.md)
- [Browser embedding](docs/browser-embedding.md)
- [GPU compositing](docs/gpu-process-compositing.md)
- [Media playback](docs/gstreamer-playback.md)
- [Resource diagnostics](docs/resource-diagnostics.md)
- [Alpha limitations](docs/alpha-status.md)

## License

Rust integration and its crate-local FFI bridge are licensed under [MIT](LICENSE).
WebKit and other native dependencies are separate distributions with their own
upstream licenses, source and notices. The native packaging project preserves
those materials in its runtime releases.
