# Browser embedding

`enzui-webkit` is toolkit-free. The host owns browser chrome, persistence,
permission prompts, download destinations and desktop portal interactions.
These APIs operate on the session's existing native view and network profile.

## Permissions

Check `WebSession::supports_origin_permissions()` before enabling
`set_origin_permission_mode(true)`. Older runtimes return
`SessionError::OriginPermissionsUnsupported` before changing the existing policy.
The reviewed runtime supplies requesting and top-document origins from native
frame state. Missing or opaque origins are denied. For camera, microphone and location, legacy global
`WebPolicy` grants do not authorize these requests. Notifications are asked
for by a top-level document only: a frame of another origin is denied without
a prompt. Profile and background (service worker) notifications remain
outside this API's scope.

`PageEvent::PermissionRequested` contains a process-unique request ID, permission
kind and both canonical origins. Answer through `answer_permission(id, allowed)`;
this answers one request without storing a choice. Four requests can be held at
once, for at most 30 seconds. Navigation, policy replacement, process loss and
session teardown retire held prompts. Remove host prompts on
`PermissionCancelled`; late answers return `AnswerError::Unknown`.

`set_site_permission` stores a session-only choice for an exact origin pair.
Camera and microphone grants are separate; combined requests require both.
Remembering a media grant clears cached native denials while preserving active
capture. Denying media stops that capability throughout the view and clears its
native grant history. The host persists choices and reapplies them to new sessions.
Popups and renderer recovery inherit current choices, without pending prompts.

Location changes are asynchronous. `revoke_geolocation()` returns an operation
ID; its matching `GeolocationPermissionChanged` confirms that current watches
have stopped. `reset_geolocation_permission()` returns an operation ID for
clearing cached denials without granting access or stopping allowed watches.
When applying choices with `set_site_permission`, use these explicit operations
as ordered completion fences when the host needs to associate completion with a
specific UI action. Continue dispatching until the matching event arrives.
A missing or failed native revocation acknowledgement terminates the involved
renderers. This barrier assumes the normal cooperative WebKit process model.

## Local destinations

`WebSession::local_origins()` exposes the network profile's shared
`LocalOriginAllowlist`. It starts empty. An explicit host authorization can allow
one ASCII HTTP(S) destination origin, including its exact scheme and effective
port, to resolve to private addresses. Navigation, subresources, downloads and
the pre-network guard use the same table. Other destinations retain normal rules.

This is a destination capability, not an initiator-origin permission: CONNECT
cannot identify the document requesting a tunnel. Isolate unrelated content in
separate network profiles. Revocation prevents future connection setup;
established tunnels and cached responses remain available until closed or cleared.

## Web process cache

WebKit can keep a closed page's web process, with its whole heap, so a later
page on the same site starts faster. Sessions start with this cache disabled:
a page's process exits once its last page closes. A host that prefers faster
reopening sets a bounded policy with `set_web_process_cache`, for example
`WebProcessCachePolicy { capacity: 2, lifetime: Duration::from_secs(30) }`.
WebKit keeps at most one cached process per site. `clear_web_process_cache`
ends every cached process now, for example on memory pressure. Both run on the
native owner thread. Older runtimes return `ProcessCacheUnsupported` and keep
WebKit's cache of up to 32 processes for five minutes. Reopening a site that
was just closed takes about 0.3 s longer without the cache.

## Native process budgets

`ffi::runtime::set_process_memory_budgets(web_bytes, shared_bytes)` optionally
sets Linux heap/cache sizing budgets for future web and shared GPU/network
processes. Call before creating sessions. Zero inherits the system/cgroup-v2
limit; larger requests are clamped to it. Existing children keep their budgets.
The runtime returns `ProcessMemoryBudgetsUnsupported` when the optional API is
absent.

These are sizing hints, rather than allocation limits. Native process termination
uses actual system/cgroup capacity. Lower budgets trade collection/cache reuse
against memory and need workload-specific CPU and latency qualification. Automatic tab discarding
is a separate policy.

`WebSession::renderer_process_id()` reports the current main-frame renderer's
host OS PID, including after a process swap, or `None` when no process runs.
It is optional diagnostic metadata, not sandbox attestation or document authority;
PIDs may be reused. `attested_renderer()` remains the last attested identity.

## Background tab memory

Automatic WebKit memory-pressure handling depends on the native runtime.
`release_memory()` asks processes showing a page to release memory now: compiled JavaScript, decoded
images and other resources, style and font caches, then a garbage collection
that returns freed heap to the system. The page stays loaded with its state
and rebuilds what it needs when used again, so the next interaction can be
slower. A host can call it after hiding a tab with `set_view_visibility(false)`.
Other pages sharing a process are released with it. Older runtimes return
`MemoryReleaseUnsupported`.

`release_idle_memory()` is the light counterpart for a page that was just hidden: one full
collection that also returns free allocator pages, keeping compiled code, decoded images and
caches, so returning to the page costs nothing extra. Measured pages gave back 5 to 10 MiB.

On a hidden page the release also drops the page's tiles and returns their
GPU memory to the driver. Showing the page again repaints the visible part;
scrolling repaints the remaining tiles as needed.
Set `WEBKIT_DISABLE_GPU_MEMORY_RECLAIM=1` to keep
the GPU memory in the driver's caches.

The release also frees the hidden page's compositor buffers, up to four
per page, except one holding a frame the host still keeps. A frame the host
has not taken is dropped. A browser that drops its last frame of a hidden
tab frees that buffer as well; showing the tab requests a new frame and
repaints the tiles.

A silent or paused video in a hidden page frees its hardware decoder and
resumes where it stopped when the page is shown. A streaming (MSE) video does
this by rebuilding its pipeline from the media the page already appended. A
paused video with sound that the page plays while hidden gets its decoder
back and plays. A muted video outside the viewport frees its decoder too,
including one that has only loaded its first frame. All videos of a web process share one VA-API display
instead of starting a driver instance each; set
`WEBKIT_GST_DISABLE_SHARED_VA_DISPLAY=1` to give each its own.

## Tab discarding

`discard()` closes a page's session, and with it the web process unless
another page shares it, and returns a `DiscardedPage`: WebKit's session state
(the history, with each entry's scroll position and form contents), the
address and the title. `restore_discarded(&page)` loads it into a new session
when the user returns to the tab. A page records its current scroll position
and form contents when hidden, so discard tabs after
`set_view_visibility(false)`; a page discarded while visible comes back
without its latest scroll and form edits.

`tab_memory` decides when, without the native runtime:

- `MemorySnapshot::read()` reads the memory the browser may use (the system's,
  or its cgroup limit when lower), what is available, and the kernel's memory
  stall share, and `pressure()` turns them into `Normal`, `Moderate` or
  `Critical` (below 15% and 7% available, or 10% stalled, by default).
- `TabMemoryPolicy::tick(now, pressure, &tabs)`, called about once a second,
  returns the actions due: `Release` for hidden tabs 30 s and 5 min after
  they were hidden and every 30 min after that, and `Discard` for the least
  recently shown background tab, at once under critical pressure and after
  10 min hidden under moderate pressure, one per tick. `discard_after` adds
  Chromium's Memory Saver: discarding every tab hidden that long.

Visible tabs, tabs playing audio and tabs the browser marks `protected`, such
as pinned tabs or ones with unsent form input, are never discarded.

Hidden pages also throttle their timers more the longer they stay hidden and
suspend CSS animations, as in WebKitGTK and Safari.

## Back/forward cache

WebKit keeps recently left pages alive so Back restores them instantly. After
a cross-site navigation each kept page holds a suspended web process with its
whole heap. Sessions keep WebKit's two pages for ten minutes, Chromium's
lifetime, instead of WebKit's thirty. `set_back_forward_cache` changes the
policy, for example `BackForwardCachePolicy::DISABLED`, and
`clear_back_forward_cache` drops every kept page now, for example on memory
pressure. Both run on the native owner thread; a new lifetime applies to pages
cached afterwards. Older runtimes return `BackForwardCacheUnsupported` and keep
WebKit's thirty minutes. WebKit may also keep one spare process ready for the
next navigation.

## Web Inspector

The local Web Inspector is a second view the host presents. Enable
`WebSettings::developer_extras`, then call `set_inspector_open(true)` or
`inspect_element_at(point)`. The latter opens the inspector on the element at
a view point, as a context menu's Inspect Element does. The frontend appears
asynchronously: pump until `bind_inspector(router, id)` succeeds, using a
`ViewId` distinct from the page's. The frontend then uses the session's usual
calls with that id: `take_gpu_frame` or `take_shared_gpu_frame` for frames,
`forward_input` for input, and `resize_inspector` for its size. Opening does
not change the page's view, focus or input routing.

`PageEvent::InspectorClosed` reports a frontend that closed, from its own UI
or through `set_inspector_open(false)`. Its id then receives no frames or
input. Closing releases the frontend and stops the page's instrumentation.
Check `supports_inspector()` first; older runtimes return
`InspectorError::Unsupported`.

The frontend runs in its own sandboxed web process with WebKit's dedicated
inspector storage (`wpewebkit-2.0/WebInspector` under the user cache and data
directories), separate from page profiles. There is no remote inspector:
sessions refuse to start with `WEBKIT_INSPECTOR_SERVER` or
`WEBKIT_INSPECTOR_HTTP_SERVER` set. The frontend is a detached window with no
docked mode. Its copy and paste use WPE's display clipboard, not the SDK's
page clipboard route.

## Encrypted media

`WebSettings::encrypted_media` (off by default) exposes
`navigator.requestMediaKeySystemAccess`, but only on a runtime built with
encrypted media; the selected runtime is not. Each key-system request is
`PermissionKind::MediaKeySystem` and is denied until granted through
`WebPolicy::grant`. A refused request rejects with `NotSupportedError`.
A separately qualified ClearKey build can expose `org.w3.clearkey`, decrypting
`cenc` and `cbcs` in the sandboxed web process. That build is not selected by
`runtime/engine.json`. Widevine and PlayReady need a licensed CDM and are not supported.
Prompting for key-system access in origin-permission mode is untested.

## Pointer boundary

`InputEvent::PointerLeft` tells the page the pointer has left its view. WPE
receives it as a pointer leave at (-1, -1), so `:hover` clears and `mouseout`
and `mouseleave` fire. A host that routes its own pointer input sends one leave
when the pointer leaves the page's visible area for native chrome or leaves the
window, and when the view is hidden or replaced. During a drag, send no leave
while the button is held: the implicit grab keeps moves and the paired release
going to the page, and the leave follows a release outside the view. The next
`PointerMoved` re-enters at its own position and modifiers. The `enzui-webview`
widget does this itself; window unfocus alone keeps hover.

## Script previews

`evaluate_script_preview(source, world)` submits the original source once and
delivers `PageEvent::ScriptResult`. Successful JSON contains `kind` and `preview`
strings: `json` contains serialized JSON, `undefined` preserves an undefined
statement result, and `display` describes a non-JSON value. Output is bounded by
`MAX_PAGE_TEXT_BYTES`. Ordinary `evaluate_script` keeps its existing JSON behavior.

`ScriptError::Unavailable` means WebKit could not serialize the returned value;
it is distinct from a thrown `Failed` error. Evaluation may already have effects
or have started pending Promise work. Preview does not await Promise fulfillment,
retry source or impose a JavaScript execution deadline. A never-settling Promise
therefore produces unavailable preview rather than a Promise-completion wait.
The native cancellation path remains `ScriptError::Cancelled`.

`evaluate_async_function_preview(body, world)` runs `body` once as an async
function and answers with the same preview after its Promise settles. The body
may `await` and must `return` its result; without a `return` the preview is
`undefined`. A rejection arrives as `ScriptError::Failed` with its message.
Declarations stay local to the body, so a console keeps ordinary evaluation for
input that should define persistent bindings. Navigation or dropping the session
cancels a body that has not settled; there is no execution deadline.

## Secret scripts

For a credential provider, `evaluate_secret_script(&SecretText, world)` runs
private source in a named isolated world and returns a `SecretScriptJob`
whose `take()` yields the JSON result once as `SecretText`. It never appears
as `PageEvent::ScriptResult`, a page exception becomes a fixed message, and
navigation or dropping the session cancels it. `register_secret_message_handler(name,
world)` delivers that world's posts as `PageEvent::SecretScriptMessage`, with
the JSON as `SecretText`, redacted in `Debug`. The page world cannot register
one, and a name stays either secret or ordinary. Native JSON and error
buffers are wiped before they are freed. Messages are still untrusted input
from any frame of the isolated world: check the document, origin and TLS
state yourself before saving or filling.

A sign-in form often lives in a cross-origin frame, so the top document has
no form to fill. `register_frame_secret_message_handler(name, world)` works
like the secret handler, and each post arrives as
`PageEvent::FrameSecretMessage` with WebKit's record of where it came from: a
`FrameDocument`, the posting document's origin, the top document's origin,
and whether it was the top frame. Only HTTPS documents inside HTTPS top
documents are delivered; posts from other documents are dropped. Inject the
bridge with a `UserScript` for `ScriptFrames::AllFrames` in the same world.
`evaluate_secret_script_in_frame(&frame, &SecretText, world)` runs private
source in that document only. The web process checks the document identity
just before running it, so if the frame has moved on to another document,
the job yields an error. Decide per origin pair: an embedded sign-in origin
the user approved is not its embedding site's origin.

## Notifications

`PageEvent::Notification` carries `NotificationRequest::id` and the origin of
the document that showed it, from WebKit's own record. Show it in the
desktop's notification service, then report the user's actions with
`notification_clicked(id)` (the page's `click` handler runs) and
`close_notification(id)` (its `close` handler runs).
`PageEvent::NotificationClosed { id }` reports every close, including one the
page made itself. A session keeps up to `MAX_SHOWN_NOTIFICATIONS`; a newer one
closes the oldest. In origin-permission mode a notification is delivered
only while the view's table allows its origin: answering a notifications
prompt stores that choice, and a stored denial (`set_site_permission` with
the same requesting and top origin) closes and refuses the origin's
notifications. `set_notifications_enabled(false)` is the global switch:
requests are denied without a prompt and shown notifications close, while
stored choices survive turning it back on. `reset_notification_permissions()`
forgets the notification choices only. Dropping the session closes its
notifications.

WebKit's own per-process permission cache is not seeded from the host table:
after a session is recreated, `Notification.permission` reads `default` until
the page asks again, even for an origin the host allows. Seeding it needs a
native change.

WebKit asks for notification permission only from a user gesture (a click
that calls `Notification.requestPermission()`), and never in an ephemeral
session: a private window's pages are denied without a prompt. The fork
symbols behind origins, frame-scoped secrets and focus handoff ship in the
selected source runtime (`5506988bf3` and later); on an older runtime
`NotificationRequest::origin` is `None`, the frame-scoped handler does not
register, and `set_focus_handoff(true)` returns `false`.

## Focus handoff

With `set_focus_handoff(true)`, Tab past the page's last focusable element or
Shift+Tab past its first reports `PageEvent::FocusLeftPage { backward, load }`.
Move keyboard focus to the browser's own controls; `load` matches
`load_generation()` while the same document is showing. Without the handoff,
focus stays inside the page.

## PDF export

Check `supports_pdf_export()`. `export_pdf(&PdfPrintSettings)` returns a
`PdfPrintId`; `PageEvent::PdfExportFinished` supplies owned `PdfDocument` bytes or
a typed error. `cancel_pdf_export(id)` cancels an active operation. Navigation
and session teardown also cancel exports. Only one export, including an
undrained completion, is permitted per view.

Settings specify physical sheet dimensions and margins in PostScript points,
scale, a zero-based page range and whether backgrounds print. CSS print styles,
margins and page breaks apply. Physical sheet size comes from the settings,
rather than CSS `@page size`. Output is limited to 256 document pages and 64 MiB.
Remote-frame documents are explicitly unsupported. The host chooses an output
destination or hands the bytes to its print portal; the engine writes no file.
`PdfDocument` clones share immutable storage and its debug output omits content.

## Navigation and connection state

`can_go_back`, `can_go_forward`, `go_back` and `go_forward` exclude actual private
attestation history entries. Caller-opened blank pages retain normal history
behavior. History navigation passes through the destination and navigation policy.

`is_private_bootstrap_document()` identifies the constructor's attestation document
until the first caller document commits. A pending or refused navigation keeps that
identity; caller-loaded `about:blank` and HTML clear it on commit. This uses the
logical commit boundary because WPE can retain the marked history item during
`load_html`. Hosts suppress initial URI/title publication and drain startup events
while the flag is true, before starting caller navigation. The flag describes the
current document; it cannot assign provenance to older events in an already mixed
queue. The identity change invalidates `page_metadata_revision()` even when URI and
title do not change.

`connection_tls_info()` returns owned certificate subject, issuer and native error
flags when present. Host certificate exceptions can suppress error flags, so zero
flags alone do not establish public trust. `has_page_events()` lets an event loop
notice nonvisual replies independently of frame or metadata changes.

`set_download_mime_types` opts supported main-document MIME types into the normal
host-mediated download lifecycle. The default list is empty. Existing policy
and destination-directory approval still apply.

A main-document HTTP 400-599 response the view cannot show (an unsupported
MIME type, an attachment or a host-handled type) is a navigation failure, not
a download: the host receives `PageEvent::LoadFailed` with the status and no
download starts. Renderable error pages still display, and explicitly forced
downloads keep their semantics. WebKit leaves that provisional load open until
the next navigation interrupts it, so start the next navigation with
`begin_load_uri`; a synchronous `load` would report the interruption.

A gesture-authorized middle-button link activation becomes a
`PopupRequested { user_initiated: true }` screened by the Popup policy, and the
source view does not navigate. This includes same-document links. If the policy
refuses, nothing opens. The host opens the tab in the source tab's profile.

`set_preferred_dark(bool)` sets `prefers-color-scheme` through the display's
native settings. Loaded pages receive `matchMedia` change events; no script or
style override is involved. WebKit reads the preference from the primary WPE
display, so it applies to every view in the process. Set it before the first
navigation and again when the toolkit theme changes.

`set_system_font_name("Adwaita Sans 11")` forwards the desktop font
description that CSS `system-ui` resolves to; the size does not change author
CSS sizes, and every view on the display shares it. `set_font_families(standard,
serif, sans_serif, monospace)` sets this view's fallback families. Malformed
names return `SessionError::FontSettingsUnavailable`. Set both before the first
navigation: a loaded page keeps the `system-ui` family it already resolved,
because WebKit's settings observer does not invalidate system-font matches.

## Downloads

Every adopted transfer reports `DownloadRequested` first, before its response or
file name is known, so early failures still have an identity. `DownloadResponse`
carries bounded status, length, `Accept-Ranges`, `ETag`, `Last-Modified`,
`Content-Range` and `Content-Encoding`. A finished transfer whose identity-coded
body is shorter than its announced length ends as `DownloadInterrupted` or
`DownloadFailed`, never `DownloadFinished`, even when a cleartext origin closes
cleanly.

A same-origin Blob URL (`URL.createObjectURL` plus an anchor with `download`)
is adopted when the Download policy allows the page's origin. The Blob's
embedded scheme, host and effective port must equal the current document's.
Asynchronous generators often click after the transient gesture has expired,
so a gesture is not required; the policy remains authoritative. Each Blob gets
a single-use permit that expires after 30 seconds. Blob navigation in general
stays refused, and a Blob download cannot resume.

`pause_download(id)` stops a range-capable transfer and returns false when its
response lacks a validator, byte ranges or a written prefix. The result is
`DownloadPaused { partial }`; a network failure on the same kind of response
yields `DownloadInterrupted { partial, .. }`. `PartialDownload::file()` is the
stopped writer's unlinked inode, opened read-only; `received` is its exact
length. The destination file is removed. The partial lives only in this process.

`start_range_download(uri, offset, validator)` loads `Range: bytes=offset-` with
`If-Range: validator` in the view's own profile, so cookies, authentication,
TLS, destination screening and filters apply. Its response becomes a download
and the current document stays. The reviewed runtime keeps `If-Range` on this
main-resource request; WebKit otherwise drops conditional headers there. A 206
response carries the suffix: append it to the prefix only after checking that
its `Content-Range` starts at `offset` and its validator matches. A 200 response
is the whole current entity. `cancel_range_download(uri)` withdraws a
continuation that has not yet received its response. `start_download(uri)`
restarts a transfer from the beginning.

## Extension content scripts

`add_content_script(&ContentScript)` installs a browser-extension content
script for documents loaded afterwards. It runs only where the page URL matches
one of `matches` and none of `excludes` (WebKit user-content patterns such as
`https://*.example.com/*`; the port is not part of a pattern), in the named
isolated world: it shares the DOM but not JavaScript globals with the page.
`add_content_style(&ContentStyle)` adds a user-level style sheet with the same
matching. Each call returns a `ContentInjectionId`; `remove_content_injection`
removes just that script or style, so one extension can be disabled without
touching others. At least one match pattern is required, each list holds at
most 64 patterns of at most 2048 bytes, and invalid input installs nothing.
`remove_user_scripts` also clears content scripts. Background pages, service
workers, extension messaging, storage and browser UI are not provided.

## Upstream proxy

`WebProfile::with_upstream_proxy(UpstreamProxy::http_connect(addr))` routes a
profile's traffic through an unauthenticated HTTP CONNECT proxy at a numeric
address. The destination guard still screens, resolves and pins every
destination; it then opens the stream by sending `CONNECT <pinned ip:port>`
to the proxy, so the proxy performs no DNS and cannot choose another address.
HTTP and HTTPS origins both use the tunnel. The guard's own
`Proxy-Authorization` never leaves the process. A proxy refusal, a malformed
reply or a silent proxy ends the request; there is no direct fallback, and
UDP (HTTP/3) is refused. The proxy address is a configured hop and is not
screened by the destination policy. A live profile is shared only by views
that request the same routing; a different proxy on the same live profile
returns `ProfileError::UpstreamProxyConflict`. Renderer recovery keeps the
profile's routing. Proxy authentication and SOCKS are not supported.

## Time-scoped cleanup

`clear_website_data(data, since)` acts on the session's network profile.
`None` includes all ages; zero and sub-microsecond windows preserve data.
A positive window containing cookies returns a `DataCleared` error before
removing anything: native cookie creation timestamps are unavailable and WebKit
skips cookies in timed clears. All-age cookie clearing remains supported.

## Cookie and website-data inventory

`NetworkSession` and `WebSession` provide `cookie_inventory`, `delete_cookie`,
`website_data_inventory` and `remove_website_data`. Each returns an owner-thread
`SiteDataTask`; drive the native context and poll `take_result()`. Tasks have a
15-second deadline. Drop or `cancel()` requests cancellation; deletion already
committed by native code cannot be rolled back. Admission remains occupied until
actual native completion, including after a dropped host handle.

Cookie metadata includes name, domain, path, Secure, HttpOnly, SameSite and expiry,
never values. Delete by the complete `CookieKey` identity; deletion is all-age.
Cookie creation and modification times are unavailable. The host can filter
cookies by sites visited during a period, provided it labels that history scope
separately from cookie creation time.

Website records are native display groups, which can contain several origins.
`WebsiteDataSelection::NativeGroup` removes selected kinds from that group;
Records include optional serialized native origins on the reviewed source runtime.
`ExactOrigin` removes supported scheme/host/port-scoped kinds, across all ages;
consult `exact_website_data_removal_types`. Cookies, HSTS, tracking statistics and
unsupported runtime selections return `UnsupportedScope` before deleting anything.
Native groups remain broader than origin boundaries. A storage deletion does not
claim a date filter or silently broaden to a cookie domain.
Inventories allow at most 16,384 records and 16 MiB of metadata, with 8 KiB fields.
Native enumeration may allocate its result before the host can inspect its size.

## Native content filters

`ffi::content_filters::ContentFilterStore::new(private_absolute_root)` provisions
a private rule cache. `compile(json, timeout)` validates and compiles native
WebKit content-blocker rules; `load(&ContentFilterId, timeout)` reopens a compiled
entry. Both return `NativeTask<CompiledContentFilter>`. Dispatch the owner context
and poll `take_result()`. The timeout must be positive and at most five minutes.
The source limit is 16 MiB. Identities are SHA-256 hashes of exact UTF-8 JSON,
including whitespace. Cache entries contain rules, without browsing history.

`session.install_content_filter(&compiled)` returns an installation lease.
`install_content_filters(&[&ads, &trackers])` installs up to eight independent
lists under the same single lease, and `replace_all` swaps them atomically:
it validates the whole bundle first, registers new identities before removing
obsolete ones, and keeps unchanged ones registered. Rules such as
`ignore-previous-rules` stay local to their own list, so a site exception in
the ad list keeps tracker filtering. Each list keeps the 16 MiB source limit.
Keep the lease alive across loads; `replace(&other)`, `remove()` and lease drop
change future request filtering. They do not cancel requests already admitted or
remove already loaded content; the browser must reload when appropriate.
Install before navigation to filter the first page requests. A lease does not
borrow the session, so it can remain alive while the host loads a URL.

An installation belongs to one logical session. After drop or renderer recovery,
its `identifier()` returns `None` and replacement is refused. Reinstall on the
replacement session before navigation. Compilation alone never installs rules;
cancelled compilation may still write its rule-only cache entry. Admission is
limited to two native operations per store and eight per owner thread, and is
released only after actual native completion.

## Page export

`WebSession::export_page(format, &PageExportOptions)` exports from the active
native view without fetching a second copy. `MainResourceHtml` returns the
original loaded HTML/XHTML bytes. `Mhtml` serializes the live DOM and resources
already loaded by WebKit. Export does not change the profile, policy or installed
content filters. Unsupported main-resource MIME types return a typed refusal.

`PageExportTask` supports `take_result`, `is_finished` and cancellation on the
owner thread. The default deadline is 15 seconds, with a 60-second maximum.
Host output defaults to 8 MiB and cannot exceed 16 MiB. Two exports may retain
native admission at once; dropped or timed-out tasks retain callback ownership
until native completion. Navigation or logical session retirement prevents an
old export from being reported as a current-document result.

`FullDocumentPng` requires the reviewed runtime's native preallocation capability;
stock runtimes return `UnsupportedRuntime`. Device-scaled snapshots are limited
to 16,384 pixels in either dimension and 16,777,216 pixels total (64 MiB RGBA),
before native bitmap allocation. The host rechecks geometry and stride, then encodes one row at a time
into the bounded PNG output. A native bitmap failure is reported as a native
error; the public snapshot API cannot distinguish its causes precisely.

`page_export_capabilities()` exposes runtime support and limits. HTML/MHTML
serialization can allocate internally before host code can inspect its result;
`native_internal_allocation_bounded` explicitly remains false. The output ceiling
bounds host-retained bytes and does not imply a native serializer memory ceiling.
`OwnedPageExport` clones share immutable bytes and omit content from debug output.

## Resource diagnostics

`WebSession::open_resource_log()` returns an opt-in owner-thread subscription to
native WebView/WebResource signals. Bind the view first, retain the log and drain
`take_events()`. Events carry subscription, view generation, navigation epoch and
resource identity. There are at most 128 tracked resources and 512 queued events;
`dropped()` reports omissions. A retired logical view makes the log inactive.

URLs omit userinfo, query values and fragments; captured OAuth redirects are
suppressed completely. Paths remain visible. Header fields use a fixed safe
allowlist; cookies, authentication and proxy credentials are excluded. Bodies and
native error messages are omitted. Missing fields and unsupported network phase
timing are explicitly labelled. HTTP error responses remain distinct from native
transport failures, and requests refused before native resource creation have no
resource event. See [resource diagnostics and inspector transport](resource-diagnostics.md)
for exact fields, limits and the separate opt-in remote inspector.


## Native favicons

Opt in before navigation with `WebSession::set_favicons_enabled(true)`. This
changes discovery for the whole network profile. `favicon()` starts a nonblocking
lookup for the current completed document; drive the owner event loop and poll
`FaviconTask::take_result`. A missing or still-loading icon returns `NotFound`
and can be retried. Stock runtimes without the reviewed bounds/provenance return
`UnsupportedRuntime`.

WebKit files icons under the page URL current when they loaded. After a
same-document `history.replaceState` or `pushState`, the lookup also asks for
up to four earlier same-origin URLs of the same live document, newest first;
`OwnedFavicon::document_uri` stays the current URL.

`OwnedFavicon` carries document URI, exact bound view/generation when present,
native candidate URL and a 32 by 32 PNG of at most 16 KiB. Its debug output omits
URLs and pixels. Native bitmap icons can load cross-origin without CORS or page
JavaScript; icon CSP still applies. Native requests omit credentials and retain
the profile's TLS and destination policy. No arbitrary host fetch is exposed.
The native acceptance limits are 32 candidates, 256 KiB encoded input and
512 pixels per dimension before decoding. Internal network buffering is not
claimed bounded by that encoded acceptance limit.

Lookups have a 15-second deadline and at most two retained native operations per
owner thread. Cancellation/drop retain callback ownership through actual native
completion. Accepted host navigation invalidates pending results synchronously;
native document changes, view replacement and session retirement also reject old
results. Profile/private cache persistence remains the browser host's policy.

## Asynchronous page copy

Interactive owners call `WebSession::begin_page_copy` with a live focused view
and host copy gesture, then dispatch the native context and poll
`PendingPageCopy::poll`. Neither call pumps a nested event loop. A reviewed native
runtime captures plain text from the exact trusted Editor Copy command, including
custom page copy handlers. Results do not read the shared display clipboard.
A runtime without command capture returns `UnsupportedRuntime` when a clipboard
backend exists. Backends without a clipboard retain an isolated asynchronous
selection-only fallback; poll it before draining ordinary page events.

Native copy has a two-second deadline, at most two callback-retained operations
per owner, and the four-MiB clipboard text limit. Cancelled/dropped tasks retain
native view and Rust network ownership/admission through callback teardown.
Cookie/profile policy and document scripting permissions are unchanged.

Ordinary native window defocus does not revoke an accepted request. Exact
session/view/document checks still apply; host navigation invalidates a request
synchronously before native load notifications. A copy cannot start while that
host navigation is pending. Later copy/paste supersedes prior completion. Hosts
call `cancel()` when hiding a view or discarding the action. Native work already
dispatched cannot be recalled. Synchronous clipboard and selection helpers remain
available for callers that can block. `copy_page_selection_to_host` pumps the
same exact native capture and returns its owned text with observed native write
counters. It also requires the reviewed capture runtime; it never waits for an
unattributed global change or reads global clipboard text.

The repository probe uses this route by default and includes the pending deadline
in its native owner watcher. It publishes validated owned text to its WPEClipboard
and records the actual before/after write counters, rather than reading global
clipboard text or inventing a write. Hiding, navigation, recreation and paste
cancel its pending action. Hosts with another desktop clipboard can publish the
owned `PageSelection` through their own toolkit.

Probe software captures are suppressed on every update that starts with a pending
copy, including completion and timeout updates. A later independent software-frame
request still uses the existing bounded synchronous snapshot path; this copy
integration does not establish nonblocking behavior for unrelated renderer work.

## Media volume

The reviewed GStreamer runtime retains exact DOM volume assignments, including
values set before metadata. Assigning the same value again does not produce an
extra `volumechange` event. PulseAudio and the software-volume element recognize
their own rounded acknowledgements in the selected backend's native
representation. Genuine PulseAudio mixer changes, including an adjacent native
step, still reach the DOM at double precision. Other sink types retain generic
readback handling and have not all been qualified.

### Speech voice modules

The Flite backend loads `libflite_cmu_us_{kal,slt,rms,awb}.so.1` beside the loaded
Flite core when a voice is selected. Ship these four modules even though they
are absent from libWPEWebKit's direct dynamic dependencies. The source-runtime
helper includes every shared library in its dependency directory in the
verified runtime manifest. Enumerating voices does not load their data.

### Scoped native user styles

`WebSession::add_user_style` installs user-level CSS in existing and future
documents, including opaque frames. Use CSS `@scope` with a document-specific
root marker when rules differ between frames. Unlike an author DOM stylesheet,
user-level `!important` rules override inline author declarations and preserve
filtering under strict CSP. Remove the returned identity when its policy or
document changes with `remove_content_injection`.
