# enzui-webkit

The **typed WebView engine/protocol layer**: plain Rust over WPE WebKit, with
no UI toolkit. Web support is split into this engine crate and an iced adapter
(`enzui-webview`, in this repository); this is the engine side, usable by
any toolkit.

## What it is

The app↔engine protocol and view-scoped lifecycle build on the crate's own web
vocabulary, `web` (`ViewId`/`Generation`, `WebPolicy`, `WebProfile`), and its
own frame types, `frame` and `frame_plan`. Its only enzUI dependency is
`enzui-security` (URL policy, redirect capture, decode limits and the secure
file primitives), which is toolkit-free too. With
the optional `wpe` feature, the crate also owns the real toolkit-free WPE
WebKit session: leased GPU frames, CPU RGBA snapshots, input, clipboard/cursor/a11y seams, explicit
profile storage, and WebProcess termination recovery.

`ProfileStore` maps shared and named profiles to stable private directories and
ephemeral profiles to in-memory sessions. `WebSession::new_profiled` binds that
session through WebKit's construct-only `network-session` property and verifies
the binding. `WebSession::recover_after_termination` reconstructs a dead view on
the same profile and advances its `ViewRouter` generation at the same boundary.

Browser hosts can use [scoped permissions, local destinations, site-data controls,
content filters, page/PDF exports and diagnostics](../../docs/browser-embedding.md)
without depending on a GUI toolkit.
These optional native extensions report unsupported runtimes explicitly.

## Native build requirements

The `wpe` feature requires WPE WebKit 2.52 or newer, including development
headers and WPE Platform 2.50 or newer with its headless plugin.
Snapshots use the `WebKitImage`
API introduced in [WPE 2.52](https://wpewebkit.org/release/wpewebkit-2.52.0.html).
Older SDKs are refused by `pkg-config` before native compilation. Builds without
`wpe` do not probe or link the native libraries.

Network sessions require a loaded libsoup 3.8.0 or newer, independently of the
SDK version. Older runtimes are refused with
`ProfileError::UnsupportedNetworkRuntime` before native session allocation or
profile provisioning. The host's 3.6.6 library leaks proxy authentication into
the TLS origin in the authenticated CONNECT fixture. The pinned 3.8.0 runtime
includes upstream proxy-credential hardening and passes the isolation check.

## HTTPS URL-credential boundary

WPE WebKit 2.52.5 removes `user:password@` from an HTTP-family URL before
the UI-process `decide-policy` callback can reliably enforce it. HTTPS also
hides the redirect response inside CONNECT, so the destination proxy cannot
inspect `Location`. The installed ABI does expose
`WebKitWebPage::send-request` (`WebKitWebPage.h`) in a WebProcess extension.
Its 2.52 ABI is `gboolean (WebKitWebPage*, WebKitURIRequest*,
WebKitURIResponse*)`: it runs immediately before network send, runs again for
redirects, and returning `G_TRUE` cancels that resource. We install that hook
before WPE initialization.
On 2.52.5 the new request URI passed to that hook is already normalised, but
its `redirected_response` still carries the original `Location` header. The
extension inspects that value and cancels synchronously before the normalized
follow-up request is sent. It sends only a constant denial name back to the UI,
which records the typed `CredentialsInUrl` refusal and stops the surrounding
navigation; URI userinfo is neither retained nor logged. The hook does not
intercept `WebKitWebView::authenticate`, so ordinary no-userinfo authentication
challenges continue through WebKit's normal handler.

Construction requires a constant ready handshake from that extension during
the inert bootstrap. If the module is missing or the ABI cannot load it,
`WebSession` fails closed with `CredentialGuardUnavailable`; it never continues
with only post-normalization callbacks. Ordinary authentication challenges and
credential-free HTTPS redirects are untouched.

## Install the mandatory guard

The `wpe` build compiles `libenzui_credential_guard.so` alongside the engine.
Development runs use that build directory. Installed consumers must package the
module and call `ffi::deployment::set_credential_guard_directory` before creating
any WPE display. This is a process-wide choice, frozen even if the first native
initialization fails. A missing guard never selects an unguarded fallback.

For an application installed as `PREFIX/bin/my-app`, the following startup
pattern also gives the packager the exact module directory for that binary:

```rust
use enzui_webkit::ffi::deployment::{
    credential_guard_build_directory, set_credential_guard_directory,
};
use enzui_webkit::ffi::runtime::HeadlessDisplay;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args().any(|arg| arg == "--print-wpe-guard-directory") {
        println!("{}", credential_guard_build_directory().display());
        return Ok(());
    }
    let executable = std::env::current_exe()?;
    let prefix = executable.parent().and_then(std::path::Path::parent)
        .ok_or("application installation prefix unavailable")?;
    set_credential_guard_directory(prefix.join("lib/my-app/wpe-extensions"))?;
    let _display = HeadlessDisplay::new()?;
    Ok(())
}
```

Build the application with its normal `wpe` feature, then install its own guard:

```sh
prefix=/absolute/install/prefix
app_guard_dir="$(./target/release/my-app --print-wpe-guard-directory)"
install -Dm755 ./target/release/my-app "$prefix/bin/my-app"
install -Dm755 "$app_guard_dir/libenzui_credential_guard.so" \
  "$prefix/lib/my-app/wpe-extensions/libenzui_credential_guard.so"
```

Use an absolute directory. It must contain a readable regular module; directory
symlinks are resolved, and the module is checked again before WPE initialization.
Keep the directory trusted and available for the process lifetime: WebKit loads
native code from every extension there. Package the module from the same engine
source as the application, and install compatible WPE WebKit and headless
platform libraries. The engine registers the selected path read-only with the
WebKit sandbox. Every session still requires the pre-network guard's ready
handshake; an ABI mismatch produces `CredentialGuardUnavailable` before caller
content loads. The sandbox and raw HTTPS redirect-credential refusal remain
mandatory.

The native installation regression gate copies a consumer binary and guard into
a fresh prefix, hides the original Cargo target in a mount namespace, renders a
real HTTPS page, attests the renderer sandbox, and checks that a credential-bearing
redirect reaches its source but never its target. Its run command is in
[`tests/wpe_guard_installation.rs`](tests/wpe_guard_installation.rs).

## Feature-off contract

A build without `wpe` emits no WPE FFI and links no WPE library. Asking for the
native backend returns `ModeError::NativeUnavailable`; it never silently falls
back to the mock.

## Native runtime thread

WPE uses one process-wide initialization thread. Create and use native displays,
profiles and sessions on that same thread, and keep its execution lane alive for
the process lifetime. Separate displays do not create independent runtimes.
The probe's native producer uses a process-long lane for this purpose.

Safe native constructors and `WebSession::feature_defaults()` claim the calling
thread before native initialization. Other threads receive `WrongThread` or
`NativeThreadError`; profile stores refuse before provisioning directories.
Ownership remains fixed after initialization failures and after every object is
dropped. The thread must stay alive until process exit. `feature_defaults()`
returns a `Result` so diagnostics obey the same thread contract.

The Rust owners are `!Send + !Sync`. Closing a session releases that view; it
does not shut down WebKit's process-global runtime. Native integration gates
that exercise thread finalization use a bounded child process and report their
result from the parent test harness.

## What to reach for first

- Protocol message types and view-scoped policy lifecycle: `protocol` and
  `session`.
- Native profile/view construction and recovery: `ffi::profile::ProfileStore`
  and `ffi::runtime::WebSession` (with `--features enzui-webkit/wpe`).

## Frame delivery and ownership

The snapshot path performs one full-frame CPU copy; handing that CPU frame to
the widget's image renderer performs one more. The probe prefers leased GPU
frames and falls back to snapshots when its renderer cannot import them.

`WebSession::enable_gpu_presentation` switches that session to leased DMA-BUF
frames. `take_gpu_frame` duplicates plane descriptors without reading pixels;
`DmaBufFrame::buffer_id` gives each allocation a stable process-unique identity
for bounded GPU import caches. `DmaBufFrame::presented` acknowledges host
presentation, and dropping the frame
releases the native buffer for reuse. Keep the frame until GPU reads finish.
At most three buffers are held before presentation acknowledgment applies
backpressure. Dropping an unpresented frame discards it and resumes rendering.
The frame carries its exact view generation and remains valid after its session
closes. Renderer recovery preserves GPU delivery on the new generation. These
native owners stay on the WPE initialization thread.

The toolkit-free `enzui-webkit-gpu-probe` imports the exported descriptors into
real EGL textures, verifies pixel colors and retained-buffer stability, and
checks that GPU delivery requests no snapshots. Diagnostic pixel reads are
performed by the probe.

The `enzui-webview` adapter uses the framework's shared external-image widget
on the renderer's Vulkan device. It advertises renderer-supported format and
modifier pairs through `WebSession::set_gpu_buffer_formats`, so unsupported
auxiliary-plane layouts can be replaced with compatible tiled allocations.
The adapter uses `WebSession::take_shared_gpu_frame` to share validated plane
descriptors across exports of each native allocation. Its metadata association
retires with the native buffer; retained metadata can keep descriptors open after
native retirement without retaining the native object. Each frame has a separate
completion hold. `take_gpu_frame` and `DmaBufFrame::into_thread_safe` retain the
owned-descriptor API for other consumers. Native references stay on the owning
thread: a consumer on that thread is acknowledged and released where it calls, and one on another thread through a shared eventfd-backed GLib source. Each native owner retains one wake descriptor between frames. The renderer retains the token through final GPU use. Continue native
dispatch after page close until `pending_gpu_frame_completions()` reaches zero.
Frame exports expose `content_info()` with a content serial and bounded physical-pixel
damage history independent of allocation reuse. `damage_since(previous)` returns
full damage for missing, skipped, foreign or resized history. A host still needs
preserved destination contents and its own exposure/transform handling before
using that region for partial drawing. The adapter's current GPU target remains
fully cleared and composited.

Explicit synchronization-file import is not implemented; the shared importer
uses implicit DMA-BUF synchronization. Software rendering uses CPU fallback.

The shared-frame adapter requests native acknowledgement on first command
encoding, separately from final GPU use and monitor presentation. Consumers
rejecting or superseding an adapter frame call `GpuFrame::discard()` to resume
production even if a renderer still retains that frame; the lease stays live
through every remaining GPU read. The owned-descriptor adapter keeps immediate
acknowledgement.

The adapter's `gpu_widget` example verifies actual Vulkan pixels, import-cache
replay, changing frames and final lease release. The probe's `gpu_host` example
drives the application's update and view on the process main thread. Both
require the `wpe` feature and the pinned runtime; their screenshots perform
diagnostic GPU readback, separate from the page's presentation path.

## Browser embedding scope

The engine is intended for in-app views and future browser hosts. Window chrome,
tabs, menus and dialogs belong to the host toolkit. The native engine surface
is not yet a complete browser embedding API:

| Area | Available | Remaining engine surface |
|---|---|---|
| Navigation | Back, forward, reload, stop, URI/title/progress events | History enumeration and session-state export/restore |
| Security | Mandatory sandbox/guard, scoped camera/microphone/location prompts, TLS failure handling and certificate details | TLS protocol/cipher details and profile-wide notification revocation |
| Website data | Profiles, cookie metadata/selective deletion, native website-data groups and all-age clearing | Partition-exact website-data cleanup and cookie creation times |
| Page integration | Scripts and user styles, message handlers, prompts, popups, find, downloads, accessibility and compiled content filters | Host UI and extension policy |
| Developer tools and export | Bounded native resource events, PDF, HTML/MHTML and qualified full-document PNG, opt-in remote inspector | Embedded inspector frontend/protocol client; native HTML/MHTML allocation bounds |
| Presentation | CPU snapshots, toolkit-free input, leased DMA-BUF export, format negotiation and the enzUI Vulkan adapter | Explicit synchronization-file import and compressed auxiliary-plane layouts |

`WebSession::add_user_script` returns a validation result. User-script source
and isolated-world names containing NUL bytes are refused; empty isolated-world
names are refused too. Evaluation retains its explicit source length, so NUL
bytes inside a valid JavaScript string literal are preserved. Message-handler
registration refuses malformed names instead of registering a rewritten alias.
`WebSession::unregister_message_handler` removes the exact name and world,
disconnects delivery and releases capacity for another registration. Messages
already queued remain available to the host.

Option menus are limited to 4096 entries and 256 KiB of combined label and
tooltip text. Larger menus are declined as a whole, so host indices keep their
native meaning and one event cannot retain thousands of individually large
strings.

`WebSession::clear_website_data` uses `None` for an unbounded clear. Explicit
zero and sub-microsecond windows preserve data and report successful completion.
Positive windows containing cookies are refused before deletion because native
cookie creation times are unavailable. See the [browser API contracts](../../docs/browser-embedding.md)
for scope, cancellation, export limits and runtime capability checks.

Authentication answers containing NUL bytes are refused without consuming the
challenge. The host can correct the credentials and answer the same request;
user names are never rewritten into another account name.

The engine uses the published enzUI alpha's toolkit-free `enzui-security`
dependency. No sibling checkout is required. Native consumers must package the
mandatory credential guard described above.

## Host input devices

`ffi::runtime::HeadlessDisplay::new()` declares a mouse and keyboard, without
a touchscreen. Hosts with other input use `new_with_input_devices` or
`set_input_devices` with `DisplayInputDevices`. This declares capabilities;
the host still forwards input events. WebKit derives process-wide capabilities
from WPE's primary display.

The reviewed source runtime updates live pointer and hover media-query styles
after a declaration change. Touch-event DOM attributes reflect the declaration
when a document creates its window. Other native runtimes retain their own
style-invalidation and touch-attribute behavior.

## Browser host events, certificates and MIME viewers

`WebSession::has_page_events()` reports queued events without draining them,
including script replies, find results, dialogs and downloads that do not change
metadata or GPU frames. Include it in the host's publication readiness predicate.

`connection_tls_info()` returns owned certificate subject/issuer names and
WebKit's TLS error mask for the current main-resource connection;
`connection_tls_details()` supplies a text presentation. Inert and cleartext
pages return `None`. A zero mask can reflect a host-installed certificate
exception, so it must not be presented as proof of public certificate trust.

`set_download_mime_types(&["application/pdf"])` selects a host-provided viewer
through the existing download lifecycle even when WPE reports inline support.
The empty default preserves native rendering. Matching ignores parameters and
ASCII case, applies only to main-document responses, and does not enable
downloads or choose their destination. Install a download policy and validated
download directory separately. Reapply the MIME list after replacing native
policy. Deliver finished files to the host viewer or save portal.

## Loopback transport under generic XDP

The destination guard queries the loopback interface once at startup. Generic
XDP on loopback can need one contiguous atomic allocation for a whole packet,
and a large coalesced packet that fails it is dropped and retransmitted after a
timeout. On Linux with such an attachment, the relay therefore sends data
toward the engine in records of at most 4 KiB, each marked `MSG_EOR`: Linux
merges nothing across that mark, in the send queue or on retransmission, so no
loopback packet exceeds one record. The send queue keeps its normal size, so a
record does not wait for the engine to read the previous one. External sockets
are not changed, and an unavailable query preserves ordinary sends.

`ENZUI_WEBKIT_LOOPBACK_SEND_BUDGET=0` disables the adaptation for diagnostics.
The guard does not change interface settings, detach packet filters or alter
destination validation.

Renderer health checks retain one identity-validated `/proc/PID/stat` descriptor
per attested session on Linux. Every check reads fresh kernel status and verifies
process start time and exit state. Full sandbox attestation remains separate.
`ENZUI_WEBKIT_STAT_LIVENESS=0` selects fresh path lookups for diagnostics; sessions
without a usable descriptor use that path automatically.


Native browser hosts can opt into profile-wide icon discovery with
`WebSession::set_favicons_enabled` and poll `favicon()` for a bounded 32-pixel PNG
with native candidate/document/view provenance. The reviewed runtime also exposes
website-record origin metadata and exact-origin storage deletion through
`remove_website_data`. Query `site_data_capabilities()` for supported kinds;
domain-scoped cookies, HSTS and tracking statistics cannot be deleted by port.
See [browser embedding](../../docs/browser-embedding.md) for deadlines, native
bounds, cancellation and stock-runtime refusals.
