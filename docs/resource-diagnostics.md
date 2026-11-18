# Resource diagnostics and Web Inspector

`WebSession::open_resource_log()` opens an owner-thread native signal subscription.
Bind the logical view first, then open the log before loading the target page.
Retain the returned `ResourceLog`, dispatch the owning GLib context and drain
`take_events()`. Dropping the log disconnects its handlers. Opening the log does
not enable developer extras or start a network listener.

Every event contains the subscription ID, optional router view generation captured
at opening, page navigation epoch captured at resource start, resource ID and
owner-observed elapsed duration. The events are native `resource-load-started`,
`sent-request`, `notify::response`, `failed` and `finished` observations. A failed
resource also emits `Finished { failed: true }`. HTTP errors such as 404 can finish
successfully at the transport layer; inspect response status separately. A redirect
includes the preceding response status on its `Sent` event.

There are at most 128 tracked resources and 512 retained events per subscription.
`dropped()` counts omitted resources and evicted events. Fields and header values
are capped. Completed resources release their signal handlers on the next drain
or resource start. A log can outlive its logical session, but `is_active()` then
returns false; reopen after recovery. It does not automatically transfer to the
replacement view. An already-started resource cannot be reconstructed after a log
is opened. Resources rejected before WebKit creates a WebResource have no native
resource event; use the separate destination-policy events for those decisions.

URLs retain paths but remove userinfo, query values and fragments; captured OAuth
redirects are wholly suppressed. Do not put sensitive data in paths or persist
logs without consent. Request headers include only accept, content-type and range.
Response headers include only content-type, content-length, content-encoding,
cache-control and accept-ranges. Cookies, authentication, proxy credentials,
redirect Location and arbitrary headers are never read by the logger. These are
safe subsets, never complete header dumps. Error messages and response bodies are
not exposed. Numeric native error domain/code remain available.

`ResourceField::Unavailable` distinguishes missing, redacted and unsupported
metadata. DNS, connection, TLS and wire-transfer phase timing are unsupported by
these signals. Elapsed duration includes UI-process event delivery delay; response
content length is declared length, not measured network bytes. The obsolete
`received-data` signal is not used because modern WebKit no longer emits it.

## WPE inspector availability

WPE's upstream `Source/WebKit/glib/remote-inspector.md.in` states that WPE supports
Web Inspector remotely, rather than an embedded toolkit inspector widget. The
Web Inspector frontend itself is web content. The HTTP inspector server can serve
that frontend to a separate browser; this crate does not supply an embedded
frontend or a public inspector protocol client.

For an explicitly opened tools session, a host can opt into
`WebSettings { developer_extras: true, ..Default::default() }`. Its default is
false. Upstream runtime transport selection is process-wide, configured before
WebKit initialization with `WEBKIT_INSPECTOR_SERVER=127.0.0.1:PORT` or
`WEBKIT_INSPECTOR_HTTP_SERVER=127.0.0.1:PORT`. The latter serves a browser-accessible
frontend. Availability depends on the runtime having remote-inspector support
compiled in. This repository has not qualified those listeners as an embedding
API or added authentication to them. A host must deliberately configure local
transport; ordinary logging does not open an inspector endpoint. Disable developer
extras when the tools session closes. Do not expose an inspector listener to
untrusted networks: it grants privileged inspection and script execution.

Native resource diagnostics complement existing script evaluation and script
exceptions; they are not a substitute inspector made from performance entries.
