# Shared Flatpak engine integration

A publisher can provide an optimized native WebKit engine once as
`dev.enzim.WebKit.Platform//26.08-1`, with development headers and tools in
`dev.enzim.WebKit.Sdk//26.08-1`. Applications compile their own Rust code and the
small credential guard against the matching SDK. They do not rebuild WebKit or
train PGO. The companion `enzim-webkit-flatpak` packaging project prepares and
tests these runtime images and supplies an application manifest template.

The initial packages target Linux x86-64-v3 and Freedesktop 26.08. The launcher
checks the CPU and engine ABI before starting an engine-linked executable. The
Platform's native helper paths are preserved under `/usr/local`.

## Startup

Call the deployment registration API during application startup, before creating
native displays or worker threads:

```rust,no_run
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use enzui_webkit::ffi::deployment::configure_flatpak_application;
use enzui_webkit::ffi::runtime::{HeadlessDisplay, WebSession};
configure_flatpak_application("dev.example.MyApp", "/app/lib/wpe-extensions")?;
let display = HeadlessDisplay::new()?;
let session = WebSession::new(&display)?;
# Ok(())
# }
```

The app ID must match `[Application] name` in `/.flatpak-info`. Registration
sets GLib's program identity, checks any existing `GApplication` ID, validates the
guard and enables the Flatpak policy used by default constructors, including
profiled and deferred construction. Register before any WPE initialization;
configuration is frozen afterward. A changed identity is refused. The public
sandbox preflight uses the same deployment policy after registration.

Outside Flatpak use normal constructors and the default bubblewrap policy.
`set_application_id` is available separately for non-Flatpak hosts that need a
stable portal identity; it does not change the sandbox policy.

## Build and install

Select the Platform/SDK above in the app's Flatpak manifest. Enable the `wpe`
feature and build against `/usr/local/lib/pkgconfig`. The matching SDK supplies
headers and native libraries. Add the Freedesktop Rust SDK extension, using the
base's `26.08` extension branch.

Capture Cargo's JSON build messages. Copy the selected executable and the guard
from the `ENZUI_WPE_EXTENSION_DIR` emitted by that build script into the app's
trusted `/app` prefix. The companion packaging installer performs this selection
without searching stale build directories. The installed guard is required even
though WebKit itself is shared. Invoke the executable through:

```sh
/usr/local/bin/enzim-webkit-run --abi=1 -- /app/libexec/my-app
```

A wrapper in `/app/bin/my-app` normally supplies that command. The launcher checks
CPU support, ABI, Flatpak presence and a working nested-sandbox portal. Network
permission is needed for web access. Display and device permissions depend on
the host UI; the headless probe needs neither X11 nor a Wayland socket.

## Security and validation

A Flatpak session requires a verified portal-launched renderer with the same
application and runtime deployment identities, a trusted helper executable,
separate mount/PID/network namespaces, seccomp and no-new-privileges. A container
marker alone is insufficient. Missing renderer PID support or inaccessible
process metadata causes refusal. The native credential-guard handshake also
remains mandatory. See [sandbox requirements](alpha-status.md).

The `flatpak_probe` example renders a pixel marker, evaluates JavaScript and
reports the actual shared library inode and renderer isolation. It can also test
HTTPS (`--https`) and WebM decoding (`--media-fixture /path/to/generated.html`).
The companion packaging integration test runs two independent app IDs, installs a
signed engine update without rebuilding either app and exercises rejection cases.

Compatible runtime fixes can be delivered centrally on the same branch. ABI or
base changes require a new branch and application rebuilds. Running processes
must restart to use an updated deployment. The publisher maintains WebKit,
private native dependencies and the inherited Freedesktop base together.
