# Native engine setup

The Rust workspace builds the Rust API, optional enzUI widget and small native
FFI/credential-guard bridge. It does not contain or build the WebKit engine.

| Component | Source project |
|---|---|
| WebKit engine and downstream changes | `enzim-webkit`, branch `enzim` |
| Rust API and enzUI adapter | `enzim-webkit-rs` (`enzui-webkit` and `enzui-webview` crates) |
| Native runtime, SDK and build inputs | [Engine releases](https://github.com/enz1m/enzim-webkit/releases) |
| Flatpak runtime packaging | `enzim-webkit-flatpak` |

[`runtime/engine.json`](../runtime/engine.json) selects an engine by immutable
fork commit and ABI. The maintained selection is the baseline x86-64 PGO build.
Its compatible-build list retains previously qualified builds of the same engine
implementation; the newer source selection adds an optional CPU target and build
documentation. This list does not admit older engine variants with different
runtime behavior.

## Application builds

Download the matching native runtime and development SDK from the
[engine releases](https://github.com/enz1m/enzim-webkit/releases). The SDK includes
headers, relocatable pkg-config metadata and the matching libraries. Its
`enzim-webkit-env` wrapper supplies build paths without installing system files:

```sh
/path/to/sdk/bin/enzim-webkit-env cargo build --release --locked \
  --bin webview-probe --features webview-probe/wpe
/path/to/runtime/bin/enzim-webkit-run ./target/release/webview-probe
```

These commands build the example from this workspace. Applications use their own
Cargo targets and feature selection. Cargo compiles Rust and the app-local guard;
it does not download or compile WebKit. Keep the runtime and SDK versions matched
and check the native release's qualified system-library requirements. The first
native archives are qualified on Arch Linux, with baseline x86-64 CPU targeting.
Flatpak applications use the matching Flatpak development SDK instead.

Native frame, profile and embedding APIs check runtime support and return
explicit errors when the installed engine lacks a required capability.

The guard must be installed in a trusted app directory. Select it with
`set_credential_guard_directory` before native initialization. Flatpak applications
use `configure_flatpak_application`; see [Flatpak integration](flatpak.md).

## Native Linux launch

Obtain a qualified runtime from the publisher. A prepared native runtime contains
`source-runtime.json`, verified libraries, process helpers, resources and license
notices. Inspect it before launching:

```sh
python3 tools/source_runtime.py --directory /path/to/runtime verify
./tools/browser --runtime /path/to/runtime --binary /path/to/webview-probe https://example.org/
```

The helper verifies the selected engine identity, file hashes/aliases, CPU and
relocation compatibility. It mounts the engine's compiled helper/resource paths
in a private namespace; WebKit still creates and enforces its renderer sandbox.
Runtime file verification does not replace the Rust API's credential-guard
handshake or renderer attestation. Launch only publisher-authenticated packages:
a file manifest detects modifications but does not authenticate an untrusted
publisher. The Flatpak path uses signed runtime delivery.

## Engine maintainers

Clone the WebKit fork at the exact pinned commit and build it with the release
configuration and build inputs accompanying its native release. Those inputs
include libsoup and GStreamer source pins, patches and upstream license notices.
WebKit changes are committed directly in its fork; no WebKit patch application or
incremental Git bundle import is needed.

The browser runtime is configured with `-DENABLE_WEB_RTC=ON`, which on WPE
builds WebKit's bundled LibWebRTC. Its libvpx and libaom assembly needs nasm;
the yasm in the fork's `Source/ThirdParty/libwebrtc/Source/third_party/yasm`
serves as well when passed as `CMAKE_ASM_NASM_COMPILER`. A runtime whose
manifest records `ENABLE_WEB_RTC=ON` must carry the LibWebRTC licence set
(`WEB_RTC_LICENSES` in `tools/source_runtime.py`).

Build and train PGO once in the engine release pipeline, then publish prebuilt
runtime and development packages. Application developers and end users do not
need training profiles. Supply corresponding source and notices with native
releases according to the included components' licenses.
