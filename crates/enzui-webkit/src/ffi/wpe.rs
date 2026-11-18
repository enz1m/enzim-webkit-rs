//! Hand-written FFI declarations for the WPE WebKit 2.0 C API, limited to the
//! functions this crate calls.
//!

use core::ffi::{c_char, c_int, c_uint, c_void};

/// `GType` - the runtime type tag glib/GObject use everywhere.
///
/// On Linux x86_64 this is `gulong` (8 bytes). This code types-alias to `usize` so a
/// `webkit_web_view_get_type()` return value is stored losslessly regardless
/// of the host's `long` width.
///
/// Source: `/usr/include/glib-2.0/gobject/gtype.h`
pub type GType = usize;

/// `gboolean` - glib's C boolean (an `int`, TRUE=1 / FALSE=0). Stored as a
/// widened int because C `bool` is not standardized.
///
/// Source: `/usr/include/glib-2.0/glib/gtypes.h`
pub type GBoolean = c_int;

/// `void (*GLogFunc) (const gchar *log_domain, GLogLevelFlags log_level, const
/// gchar *message, gpointer user_data);`
pub type GLogFunc =
    extern "C" fn(domain: *const c_char, level: c_int, message: *const c_char, user: *mut c_void);

/// `G_LOG_LEVEL_ERROR` - always fatal in GLib.
pub const G_LOG_LEVEL_ERROR: c_int = 1 << 2;

/// `G_LOG_LEVEL_CRITICAL` - a failed GLib precondition, e.g. a ref count of 0
/// on an object a callback still uses.
pub const G_LOG_LEVEL_CRITICAL: c_int = 1 << 3;

// ---------------------------------------------------------------------------
// Opaque handle types
// ---------------------------------------------------------------------------

/// `WPEDisplay*` - abstract display base class.
///
/// Source: `/usr/include/wpe-webkit-2.0/wpe-platform/wpe/WPEDisplay.h`
#[repr(C)]
pub struct WPEDisplay {
    _priv: [u8; 0],
}

/// `WPESettings*` - a display's typed settings store, owned by the display.
///
/// Source: `/usr/include/wpe-webkit-2.0/wpe-platform/wpe/WPESettings.h`
#[repr(C)]
pub struct WPESettings {
    _priv: [u8; 0],
}

/// `WPE_SETTINGS_SOURCE_APPLICATION`: a value set by the embedding application.
pub const WPE_SETTINGS_SOURCE_APPLICATION: c_int = 1;

/// `WPEBuffer*` - abstract RGBA buffer base class.
///
/// Source: `/usr/include/wpe-webkit-2.0/wpe-platform/wpe/WPEBuffer.h`
#[repr(C)]
pub struct WPEBuffer {
    _priv: [u8; 0],
}

/// `WPEBufferSHM*` - CPU-visible RGBA buffer, `ARGB8888`.
///
/// Source: `/usr/include/wpe-webkit-2.0/wpe-platform/wpe/WPEBufferSHM.h`
#[repr(C)]
pub struct WPEBufferSHM {
    _priv: [u8; 0],
}

/// `GBytes*` - immutable glib byte buffer.
///
/// Source: `/usr/include/glib-2.0/glib/gbytes.h`
#[repr(C)]
pub struct GBytes {
    _priv: [u8; 0],
}

/// `GMainLoop*` - an event-loop instance; opaque.
///
/// Source: `/usr/include/glib-2.0/glib/gmain.h`
#[repr(C)]
pub struct GMainLoop {
    _priv: [u8; 0],
}

/// `GAsyncResult*` - the result of an asynchronous glib operation.
///
/// Source: `/usr/include/glib-2.0/gio/gasyncresult.h`
#[repr(C)]
pub struct GAsyncResult {
    _priv: [u8; 0],
}

/// `WebKitWebView*` - the central WebKit widget.
///
/// Source: `/usr/include/wpe-webkit-2.0/wpe/WebKitWebView.h`
#[repr(C)]
pub struct WebKitWebView {
    _priv: [u8; 0],
}

/// `WebKitAuthenticationRequest*` - a borrowed WebKit authentication challenge.
#[repr(C)]
pub struct WebKitAuthenticationRequest {
    _priv: [u8; 0],
}

/// `WebKitCredential*` - a boxed username/password credential.
#[repr(C)]
pub struct WebKitCredential {
    _priv: [u8; 0],
}

/// `WebKitWebContext*` - process-pool configuration shared by WPE views.
///
/// Source: `/usr/include/wpe-webkit-2.0/wpe/WebKitWebContext.h`
#[repr(C)]
pub struct WebKitWebContext {
    _priv: [u8; 0],
}

/// `WebKitUserMessage*` - a name plus optional payload used for communication
/// between a WebProcess extension and its owning view. The credential guard
/// sends names only; URL userinfo never crosses this boundary.
///
/// Source: `/usr/include/wpe-webkit-2.0/wpe/WebKitUserMessage.h`
#[repr(C)]
pub struct WebKitUserMessage {
    _priv: [u8; 0],
}

/// `WebKitImage*` - the pixel buffer a snapshot resolves to.
///
/// Source: `/usr/include/wpe-webkit-2.0/wpe/WebKitImage.h`
#[repr(C)]
pub struct WebKitImage {
    _priv: [u8; 0],
}

/// Opaque WebKit policy decision hierarchy used by `decide-policy`.
#[repr(C)]
pub struct WebKitPolicyDecision {
    _priv: [u8; 0],
}
/// Navigation/new-window policy decision subclass.
#[repr(C)]
pub struct WebKitNavigationPolicyDecision {
    _priv: [u8; 0],
}
/// The response WebKit received for a request; read only for bounded
/// diagnostics: status code and MIME type.
#[repr(C)]
pub struct WebKitURIResponse {
    _opaque: [u8; 0],
}

/// Response/download policy decision.
#[repr(C)]
pub struct WebKitResponsePolicyDecision {
    _priv: [u8; 0],
}
/// Navigation metadata attached to a navigation policy decision.
#[repr(C)]
pub struct WebKitNavigationAction {
    _priv: [u8; 0],
}
/// URI request attached to navigation and response policy decisions.
#[repr(C)]
pub struct WebKitURIRequest {
    _priv: [u8; 0],
}
/// Permission request interface delivered by `permission-request`.
#[repr(C)]
pub struct WebKitPermissionRequest {
    _priv: [u8; 0],
}
/// TLS certificate delivered by `load-failed-with-tls-errors`.
#[repr(C)]
pub struct GTlsCertificate {
    _priv: [u8; 0],
}
/// `WebKitDownload*` - a live download initiated by a policy decision that
/// selected [`webkit_policy_decision_download`]. Delivered to the
/// `WebKitNetworkSession::download-started` signal so hosts can observe the
/// native consequence of that decision.
///
/// Source: `/usr/include/wpe-webkit-2.0/wpe/WebKitDownload.h`
#[repr(C)]
pub struct WebKitDownload {
    _priv: [u8; 0],
}
/// Base GType instance used only for checked concrete-permission type tests.
#[repr(C)]
pub struct GTypeInstance {
    _priv: [u8; 0],
}

/// `WebKitNetworkSession*` - a browsing session's network/storage boundary
/// Owns the cookie store, cache and website data. A
/// persistent session is created with a data directory
/// (`webkit_network_session_new`); an ephemeral one holds everything in
/// memory (`webkit_network_session_new_ephemeral`). Two persistent sessions
/// on different directories are isolated; an ephemeral one persists nothing.
///
/// Source: `/usr/include/wpe-webkit-2.0/wpe/WebKitNetworkSession.h`
#[repr(C)]
pub struct WebKitNetworkSession {
    _priv: [u8; 0],
}

/// `WebKitNetworkProxySettings*` - a boxed custom proxy configuration
/// Applied to a network session so that every request it makes
/// passes through the process-owned destination guard.
///
/// Source: `/usr/include/wpe-webkit-2.0/wpe/WebKitNetworkProxySettings.h`
#[repr(C)]
pub struct WebKitNetworkProxySettings {
    _private: [u8; 0],
}

/// `WEBKIT_NETWORK_PROXY_MODE_CUSTOM` - the third value of
/// `WebKitNetworkProxyMode` (default, no-proxy, custom).
pub const WEBKIT_NETWORK_PROXY_MODE_CUSTOM: c_int = 2;

/// `WebKitCookieManager*` - the cookie store of a `WebKitNetworkSession`
/// Borrowed from the session (owned by it, never unref'd).
///
/// Source: `/usr/include/wpe-webkit-2.0/wpe/WebKitCookieManager.h`
#[repr(C)]
pub struct WebKitCookieManager {
    _priv: [u8; 0],
}

/// `SoupCookie*` - libsoup's cookie value type. Constructed
/// with `soup_cookie_new`, freed with `soup_cookie_free`. `webkit_cookie_manager_add_cookie`
/// copies it (does not take ownership), so the caller always frees its own.
///
/// libsoup-3.0 is already in the link flags (`pkg-config --libs
/// wpe-webkit-2.0` emits `-lsoup-3.0`), so this adds no dependency.
///
/// Source: `/usr/include/libsoup-3.0/libsoup/soup-cookie.h`
#[repr(C)]
pub struct SoupCookie {
    _priv: [u8; 0],
}

/// Borrowed HTTP request headers owned by WebKit/libsoup.
#[repr(C)]
pub struct SoupMessageHeaders {
    _priv: [u8; 0],
}

/// `GList*` - glib's doubly-linked list. The cookie query
/// returns one. This code mirrors the head layout to walk it: `{ gpointer data;
/// GList *next; GList *prev; }`.
///
/// Source: `/usr/include/glib-2.0/glib/glist.h`
#[repr(C)]
pub struct GList {
    /// The element payload (a `SoupCookie*` for a cookie list).
    pub data: *mut c_void,
    /// The next node, or NULL at the tail.
    pub next: *mut GList,
    /// The previous node, or NULL at the head.
    pub prev: *mut GList,
}

/// `WPEView*` - the platform view a `WebKitWebView` presents into. Input events
/// are dispatched to the WPEView, not the WebKitWebView:
/// `wpe_view_event(view, event)` is the seam through which a
/// synthesized pointer/wheel/key reaches the WebProcess.
///
/// Obtained from a live `WebKitWebView` via `webkit_web_view_get_wpe_view`
/// (a borrowed pointer - do not unref).
///
/// Source: `/usr/include/wpe-webkit-2.0/wpe-platform/wpe/WPEView.h`
#[repr(C)]
pub struct WPEView {
    _priv: [u8; 0],
}

/// `WPEToplevel*` - the top-level surface a [`WPEView`] is attached to; opaque.
///
/// The view's device scale (`WPEView:scale`) is read-only and *follows* the
/// scale of the toplevel/screen it is shown on (see `WPEView.h`, the `scale`
/// property doc). A real Wayland/DRM backend calls `wpe_toplevel_scale_changed`
/// when the compositor reports a non-1 output scale; the headless platform
/// exposes no screen (`wpe_display_get_n_screens` == 0), so a gate that needs a
/// non-1 `wpe_view_get_scale()` drives it through this same toplevel entry
/// point - the genuine `WPEView:scale`, not page zoom.
///
/// Obtained borrowed from a live view via `wpe_view_get_toplevel` - do not
/// unref.
///
/// Source: `/usr/include/wpe-webkit-2.0/wpe-platform/wpe/WPEToplevel.h`
#[repr(C)]
pub struct WPEToplevel {
    _priv: [u8; 0],
}

/// The C type of a `WPEViewClass::set_cursor_from_name` vfunc:
/// `void (*)(WPEView *view, const char *name)`.
///
/// A page requesting `cursor: pointer` makes WebKit call this on the view. The
/// headless view's default implementation is NULL (it has nowhere to draw a
/// cursor), so intercepting it is how the host learns the page's requested
/// cursor. See [`WPEViewClass`].
pub type SetCursorFromNameFn = extern "C" fn(view: *mut WPEView, name: *const c_char);

/// `WPEViewClass` - the class (vtable) of a `WPEView` subclass.
///
/// This code mirrors the exact C layout so this code can patch one vfunc:
/// `set_cursor_from_name`. The page's cursor request arrives only through this
/// vfunc (there is no `wpe_view_get_cursor` and no cursor signal), so the host
/// seam is to overwrite this pointer on the concrete view class with its own
/// recorder. The offsets are pinned by a C `offsetof` probe against
/// `WPEView.h`:
///
/// ```text
/// parent_class          @ 0    (GObjectClass, 136 bytes on x86_64)
/// buffers_changed       @ 136
/// render_buffer         @ 144
/// lock_pointer          @ 152
/// unlock_pointer        @ 160
/// set_cursor_from_name @ 168 <- the one this code patches
/// set_cursor_from_bytes @ 176
/// ```
///
/// `GObjectClass` is carried as an opaque 136-byte aligned prefix; this code never
/// read its fields, only the vfunc pointers after it.
///
/// Source: `/usr/include/wpe-webkit-2.0/wpe-platform/wpe/WPEView.h`
///         (`struct _WPEViewClass`)
#[repr(C)]
pub struct WPEViewClass {
    /// `GObjectClass parent_class;` - 136 bytes on x86_64, treated as opaque.
    /// `u64` alignment matches the pointer/GType members inside it.
    pub parent_class: [u64; 17],
    /// `buffers_changed` @ 136.
    pub buffers_changed: *mut c_void,
    /// `render_buffer` @ 144.
    pub render_buffer: *mut c_void,
    /// `lock_pointer` @ 152.
    pub lock_pointer: *mut c_void,
    /// `unlock_pointer` @ 160.
    pub unlock_pointer: *mut c_void,
    /// `set_cursor_from_name` @ 168 - the vfunc this code overwrites.
    pub set_cursor_from_name: Option<SetCursorFromNameFn>,
    /// `set_cursor_from_bytes` @ 176. (Left untouched.)
    pub set_cursor_from_bytes: *mut c_void,
    // Remaining fields (set_opaque_rectangles, can_be_mapped, get_accessible,
    // padding[32]) are past the field this code patches and never accessed, so they are
    // omitted; `#[repr(C)]` only needs correct offsets up to the field.
}

/// `WPEEvent*` - a synthesized (or real) input event, ref-counted. Constructed
/// by `wpe_event_*_new`, dispatched with `wpe_view_event`, and released with
/// `wpe_event_unref`. `wpe_view_event`
/// takes its own reference, so the constructor's reference is always dropped
/// here.
///
/// Source: `/usr/include/wpe-webkit-2.0/wpe-platform/wpe/WPEEvent.h`
#[repr(C)]
pub struct WPEEvent {
    _priv: [u8; 0],
}

/// `WPEViewAccessible*` - the view's accessibility object.
///
/// This is a GObject interface; on this host the headless view's concrete
/// implementation is `WPEViewAccessibleAtk`, whose hierarchy is
/// `WPEViewAccessibleAtk < AtkSocket < AtkObject < GObject` (measured, see
/// `ffi/a11y.rs`). Being an `AtkSocket` is the whole architecture: the UI
/// process holds an empty socket, and the page's real accessible tree lives in
/// the sandboxed WebProcess, published over the AT-SPI D-Bus and attached by
/// `bind(plug_id)`.
///
/// Borrowed from `wpe_view_get_accessible` - owned by the view, never unref'd.
///
/// Source: `/usr/include/wpe-webkit-2.0/wpe-platform/wpe/WPEViewAccessible.h`
#[repr(C)]
pub struct WPEViewAccessible {
    _priv: [u8; 0],
}

/// The C type of `WPEViewAccessibleInterface::bind`:
/// `void (*)(WPEViewAccessible *accessible, const char *plug_id)`.
///
/// WebKit calls this from the UI process when the WebProcess has published its
/// accessible tree, handing over the AT-SPI plug identifier
/// (`<dbus-name>:<object-path>`) that addresses the remote document root.
pub type AccessibleBindFn =
    extern "C" fn(accessible: *mut WPEViewAccessible, plug_id: *const c_char);

/// `WPEViewAccessibleInterface` - the interface vtable of `WPEViewAccessible`.
///
/// This code mirrors the exact C layout so this code can patch `bind` and capture the
/// plug id, which is the only place that identifier is ever exposed (there is
/// no `wpe_view_accessible_get_plug_id` getter). This is the same technique
/// used for `set_cursor_from_name`, applied here to an interface vtable
/// rather than a class vtable.
///
/// Offsets pinned by a C `offsetof` probe against `WPEViewAccessible.h`:
///
/// ```text
/// parent_interface @ 0   (GTypeInterface, 16 bytes on x86_64)
/// bind @ 16 <- the one this code patches
/// sizeof           = 24
/// ```
///
/// Source: `/usr/include/wpe-webkit-2.0/wpe-platform/wpe/WPEViewAccessible.h`
///         (`struct _WPEViewAccessibleInterface`)
#[repr(C)]
pub struct WPEViewAccessibleInterface {
    /// `GTypeInterface parent_interface;` - 16 bytes (two GTypes), opaque.
    pub parent_interface: [usize; 2],
    /// `bind` @ 16 - the vfunc this code overwrites.
    pub bind: Option<AccessibleBindFn>,
}

/// `WPEClipboard*` - the display's clipboard. Obtained from
/// `wpe_display_get_clipboard` (borrowed, owned by the display) and carries
/// text/bytes between the page and the host. Opaque.
///
/// Source: `/usr/include/wpe-webkit-2.0/wpe-platform/wpe/WPEClipboard.h`
#[repr(C)]
pub struct WPEClipboard {
    _priv: [u8; 0],
}

/// `WPEClipboardContent*` - a ref-counted bundle of formats (text/bytes) set on
/// a clipboard. Built with `wpe_clipboard_content_new`, populated with
/// `wpe_clipboard_content_set_text`, handed to `wpe_clipboard_set_content`, and
/// released with `wpe_clipboard_content_unref`. Opaque.
///
/// Source: `/usr/include/wpe-webkit-2.0/wpe-platform/wpe/WPEClipboard.h`
#[repr(C)]
pub struct WPEClipboardContent {
    _priv: [u8; 0],
}

/// `WebKitInputMethodContext*` - the object WebKit drives when a page text
/// field is focused.
///
/// # Why the WebKit-level type and not `WPEInputMethodContext`
///
/// WPEPlatform also declares a `WPEInputMethodContext`, but it is abstract
/// and is only instantiated by a platform backend through
/// `WPEDisplayClass::create_input_method_context`; the headless display leaves
/// that vfunc unimplemented, so there is no WPE-level context to observe. The
/// WebKit-level `WebKitInputMethodContext` is derivable, is settable on the
/// view (`webkit_web_view_set_input_method_context`), and is driven by
/// WebKit's *shared* glib `InputMethodFilter` - the same code path the GTK port
/// uses - so a focused DOM input calls its vfuncs on the WPE port too. That is
/// the seam a toolkit is meant to implement, and it needs no GTK.
///
/// Opaque: this code subclasses it and key the per-instance state by pointer rather than
/// extending the instance struct, so no instance-size arithmetic is required.
///
/// Source: `/usr/include/wpe-webkit-2.0/wpe/WebKitInputMethodContext.h`
#[repr(C)]
pub struct WebKitInputMethodContext {
    _priv: [u8; 0],
}

/// `void (*)(WebKitInputMethodContext *)` - the no-argument notification
/// vfuncs (`notify_focus_in`, `notify_focus_out`, `reset`).
pub type ImeNotifyFn = extern "C" fn(context: *mut WebKitInputMethodContext);

/// `void (*)(WebKitInputMethodContext *, int x, int y, int width, int height)`:
/// `notify_cursor_area`, the only place the page's caret rectangle is
/// reported. Coordinates are logical view pixels relative to the view.
/// WebKit sources them from the logical root-view `caretRectAtStart`; WPE's
/// `platformTransformCursorRectToViewCoordinates` is the identity. Page zoom
/// is baked into layout, but the output/device scale is not applied.
pub type ImeNotifyCursorAreaFn =
    extern "C" fn(context: *mut WebKitInputMethodContext, x: c_int, y: c_int, w: c_int, h: c_int);

/// `void (*)(WebKitInputMethodContext *, const gchar *text, guint length,
/// guint cursor_index, guint selection_index)` - `notify_surrounding`, the text
/// around the caret plus the caret/selection byte offsets into it.
pub type ImeNotifySurroundingFn = extern "C" fn(
    context: *mut WebKitInputMethodContext,
    text: *const c_char,
    length: c_uint,
    cursor_index: c_uint,
    selection_index: c_uint,
);

/// `void (*)(WebKitInputMethodContext *, gboolean enabled)` -
/// `set_enable_preedit`. WebKit calls this to say whether the field can display
/// a composition on the spot.
pub type ImeSetEnablePreeditFn =
    extern "C" fn(context: *mut WebKitInputMethodContext, enabled: GBoolean);

/// `void (*)(WebKitInputMethodContext *, gchar text, GList underlines,
/// guint *cursor_offset)` - `get_preedit`. WebKit calls this to READ the
/// composition being shown, after this code emits `preedit-changed`. `*text` must be
/// a `g_malloc`ed string WebKit takes ownership of.
pub type ImeGetPreeditFn = extern "C" fn(
    context: *mut WebKitInputMethodContext,
    text: *mut *mut c_char,
    underlines: *mut *mut GList,
    cursor_offset: *mut c_uint,
);

/// `WebKitInputMethodContextClass` - mirrored so this code can install its own vfuncs
/// into a subclass's copy of the vtable.
///
/// This is not the vtable-patch technique `cursor.rs` uses on a shared class:
/// here this code registers its own GType, so the class this code writes into is its own and no
/// other consumer of `WebKitInputMethodContext` is affected.
///
/// Offsets pinned by a C `offsetof` probe against the installed header
/// (WPE WebKit 2.52.5, x86_64); `sizeof` is 368 and `GObjectClass` is 136:
///
/// ```text
/// parent_class       @ 0    (GObjectClass, 136 bytes)
/// preedit_started    @ 136
/// preedit_changed    @ 144
/// preedit_finished   @ 152
/// committed          @ 160
/// delete_surrounding @ 168
/// set_enable_preedit @ 176
/// get_preedit        @ 184
/// filter_key_event   @ 192
/// notify_focus_in    @ 200
/// notify_focus_out   @ 208
/// notify_cursor_area @ 216
/// notify_surrounding @ 224
/// reset              @ 232
/// ```
///
/// The class is allocated by GObject at the size the *parent* reports
/// (`g_type_query`), so this mirror is only ever used to write the slots above;
/// the reserved tail is never touched.
///
/// Source: `/usr/include/wpe-webkit-2.0/wpe/WebKitInputMethodContext.h`
///         (`struct _WebKitInputMethodContextClass`)
#[repr(C)]
pub struct WebKitInputMethodContextClass {
    /// `GObjectClass parent_class;` - 136 bytes on x86_64, opaque.
    pub parent_class: [u64; 17],
    /// `preedit_started` @ 136 (signal class handler; left alone).
    pub preedit_started: *mut c_void,
    /// `preedit_changed` @ 144 (signal class handler; left alone).
    pub preedit_changed: *mut c_void,
    /// `preedit_finished` @ 152 (signal class handler; left alone).
    pub preedit_finished: *mut c_void,
    /// `committed` @ 160 (signal class handler; left alone).
    pub committed: *mut c_void,
    /// `delete_surrounding` @ 168 (signal class handler; left alone).
    pub delete_surrounding: *mut c_void,
    /// `set_enable_preedit` @ 176 - overridden.
    pub set_enable_preedit: Option<ImeSetEnablePreeditFn>,
    /// `get_preedit` @ 184 - overridden.
    pub get_preedit: Option<ImeGetPreeditFn>,
    /// `filter_key_event` @ 192. Left NULL: the toolkit filters keys, and
    /// claiming to filter them here would swallow the page's own key handling.
    pub filter_key_event: *mut c_void,
    /// `notify_focus_in` @ 200 - overridden.
    pub notify_focus_in: Option<ImeNotifyFn>,
    /// `notify_focus_out` @ 208 - overridden.
    pub notify_focus_out: Option<ImeNotifyFn>,
    /// `notify_cursor_area` @ 216 - overridden.
    pub notify_cursor_area: Option<ImeNotifyCursorAreaFn>,
    /// `notify_surrounding` @ 224 - overridden.
    pub notify_surrounding: Option<ImeNotifySurroundingFn>,
    /// `reset` @ 232 - overridden.
    pub reset: Option<ImeNotifyFn>,
    // The 16 reserved slots past `reset` are never written; `#[repr(C)]` only
    // needs correct offsets up to the last field this code touches.
}

/// `GTypeQuery` - filled by `g_type_query` with a type's *actual* class and
/// instance sizes.
///
/// Using this instead of a hardcoded `sizeof` is what makes registering a
/// subclass ABI-safe: `WebKitInputMethodContext` carries private instance data
/// whose size is not in the header, and a too-small instance size would have
/// GObject scribble past the allocation.
///
/// Source: `/usr/include/glib-2.0/gobject/gtype.h`
#[repr(C)]
#[derive(Clone, Copy)]
pub struct GTypeQuery {
    /// The type itself.
    pub type_: GType,
    /// `const gchar *type_name`.
    pub type_name: *const c_char,
    /// `guint class_size`.
    pub class_size: c_uint,
    /// `guint instance_size`.
    pub instance_size: c_uint,
}

impl Default for GTypeQuery {
    /// A zeroed query, as `g_type_query` expects to be handed. A zero
    /// `class_size` after the call is glib's "not a classed type" answer, which
    /// the caller must check rather than trust.
    fn default() -> Self {
        GTypeQuery {
            type_: 0,
            type_name: core::ptr::null(),
            class_size: 0,
            instance_size: 0,
        }
    }
}

/// `GValue` - the property carrier for `g_object_new_with_properties`.
///
/// Documented layout is `GType g_type` + a 16-byte union (two 8-byte slots
/// on x86_64). This code keeps the exact ABI as an aligned 3×8-byte record with a
/// `Default` (zero-init) impl - glib initialises the value slot via
/// `g_value_init`, this code never touches its private bytes itself.
///
/// Source: `/usr/include/glib-2.0/gobject/gvalue.h`
#[repr(C)]
#[derive(Clone, Copy)]
pub struct GValue {
    /// The runtime type tag; zero means "uninitialised".
    pub g_type: GType,
    /// The 16-byte union payload. Never accessed directly - glib owns it.
    pub data: [u64; 2],
}

impl Default for GValue {
    /// A zeroed GValue is glib's documented "uninitialised" state; it must be
    /// followed by `g_value_init` before use.
    fn default() -> Self {
        GValue {
            g_type: 0,
            data: [0, 0],
        }
    }
}

/// `GError*` - glib's error type.
///
/// Source: `/usr/include/glib-2.0/glib/gerror.h`
#[repr(C)]
pub struct GError {
    /// `GQuark domain` - an interned error-domain id.
    pub domain: u32,
    /// `gint code` - the domain-specific error code.
    pub code: c_int,
    /// `gchar *message` - a UTF-8 message the caller must free with
    /// `g_error_free`. Read but never freed here (glib owns the memory once
    /// `g_error_free` returns).
    pub message: *mut c_char,
}

/// `WPEPixelFormat` - the only enum this file cares about; the header currently
/// declares exactly one value (`ARGB8888`), reserved for future expansion.
///
/// Source: `/usr/include/wpe-webkit-2.0/wpe-platform/wpe/WPEBufferSHM.h`
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WPEPixelFormat {
    /// The only supported format on this WPE build. Cairo `ARGB32` byte order:
    /// on little-endian, memory is `B,G,R,A` per pixel.
    Argb8888 = 0,
}

// ---------------------------------------------------------------------------
// glib functions - the minimum this code needs to round-trip a `Vec<u8>` through
// `GBytes` and read a `GError` message.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// glib main loop and GObject construction.
// ---------------------------------------------------------------------------

unsafe extern "C" {
    /// `GMainLoop *g_main_loop_new (GMainContext *context, gboolean is_running);`
    ///
    /// Passing NULL for `context` uses the default main context. Ref-count 1;
    /// release with `g_main_loop_unref`.
    ///
    /// Source: `/usr/include/glib-2.0/glib/gmain.h`
    pub fn g_main_loop_new(context: *mut c_void, is_running: GBoolean) -> *mut GMainLoop;

    /// `void g_main_loop_run (GMainLoop *loop);`
    ///
    /// Runs until `g_main_loop_quit` is called; the calling thread blocks.
    ///
    /// Source: `/usr/include/glib-2.0/glib/gmain.h`
    pub fn g_main_loop_run(loop_: *mut GMainLoop);

    /// `void g_main_loop_quit (GMainLoop *loop);`
    ///
    /// Idempotent: quitting an already-stopped loop is a no-op, which is
    /// exactly what this code needs to safely quit from *both* the snapshot callback
    /// and the deadline-timeout callback without ordering constraints.
    ///
    /// Source: `/usr/include/glib-2.0/glib/gmain.h`
    pub fn g_main_loop_quit(loop_: *mut GMainLoop);

    /// `void g_main_loop_unref (GMainLoop *loop);`
    ///
    /// Source: `/usr/include/glib-2.0/glib/gmain.h`
    pub fn g_main_loop_unref(loop_: *mut GMainLoop);

    /// `GLogFunc g_log_set_default_handler (GLogFunc log_func, gpointer user_data);`
    ///
    /// Installs the handler GLib calls for every message with no domain-specific
    /// handler, returning the previous one. A gate installs a counting handler
    /// so a `GLib-CRITICAL` - e.g. `g_main_loop_quit: assertion 'ref_count > 0'`
    /// from a callback that outlived its loop - becomes an assertable
    /// observation instead of a line of ignorable stderr. A loop-guard
    /// sabotage passed the gate while printing exactly that critical.
    ///
    /// Source: `/usr/include/glib-2.0/glib/gmessages.h`
    pub fn g_log_set_default_handler(log_func: GLogFunc, user_data: *mut c_void) -> GLogFunc;

    /// `guint g_timeout_add (guint interval, GSourceFunc function, gpointer data);`
    ///
    /// Schedules `function(data)` to fire on the default main context after
    /// `interval` milliseconds. Returning `FALSE` from the callback removes
    /// the source. Return value is a source id (for `g_source_remove`).
    ///
    /// Source: `/usr/include/glib-2.0/glib/gmain.h`
    pub fn g_timeout_add(
        interval: c_uint,
        function: extern "C" fn(*mut c_void) -> GBoolean,
        data: *mut c_void,
    ) -> c_uint;

    /// `gboolean g_source_remove (guint tag);`
    ///
    /// Removes the source with the given id from its context. This code calls this on a
    /// deadline source that did not fire (the operation completed first), so
    /// the leaked timeout cannot fire *later* against a freed state box - a
    /// use-after-free that, under rapid repeated snapshots, corrupted a live
    /// `GMainLoop` and hung the run.
    ///
    /// Source: `/usr/include/glib-2.0/glib/gmain.h`
    pub fn g_source_remove(tag: c_uint) -> GBoolean;

    /// `gboolean g_main_context_iteration (GMainContext *context, gboolean may_block);`
    ///
    /// Runs a single iteration of the given context (NULL = default). With
    /// `may_block = FALSE` it dispatches whatever is ready and returns at
    /// once, so a bounded drain loop cannot hang.
    ///
    /// Used by `runtime.rs` (pump) and `profile.rs` (cancel/drain on timeout)
    /// - declared here so the extern is shared rather than duplicated.
    ///
    /// Source: `/usr/include/glib-2.0/glib/gmain.h`
    pub fn g_main_context_iteration(context: *mut c_void, may_block: GBoolean) -> GBoolean;

    /// `GObject *g_object_new_with_properties (GType, guint, const char *names[], const GValue values[]);`
    ///
    /// The non-variadic form of `g_object_new`. This code uses it because Rust extern
    /// variadics are unstable and this code needs exactly one property (`display`).
    ///
    /// Available since glib 2.54. WPE 2.52 requires glib >= 2.70, so this is
    /// present.
    ///
    /// Source: `/usr/include/glib-2.0/gobject/gobject.h`
    pub fn g_object_new_with_properties(
        object_type: GType,
        n_properties: c_uint,
        names: *const *const c_char,
        values: *const GValue,
    ) -> *mut c_void;

    /// `GValue *g_value_init (GValue *value, GType g_type);`
    ///
    /// Initialises a zero-inited `GValue` slot to hold a value of `g_type`.
    ///
    /// Source: `/usr/include/glib-2.0/gobject/gvalue.h`
    pub fn g_value_init(value: *mut GValue, g_type: GType) -> *mut GValue;

    /// `void g_value_set_object (GValue *value, gpointer v_object);`
    ///
    /// Sets `value` (which must have been `g_value_init`'d with a
    /// GObject-derived type) to `v_object`, adding a reference.
    ///
    /// Source: `/usr/include/glib-2.0/gobject/gobject.h`
    pub fn g_value_set_object(value: *mut GValue, v_object: *mut c_void);

    /// `void g_value_unset (GValue *value);`
    ///
    /// Releases the value's reference to its content and clears the slot.
    ///
    /// Source: `/usr/include/glib-2.0/gobject/gvalue.h`
    pub fn g_value_unset(value: *mut GValue);

    /// `gulong g_signal_connect_data (gpointer, const gchar*, GCallback, gpointer, GClosureNotify, GConnectFlags);`
    ///
    /// The non-macro form of `g_signal_connect`. Returns a handler id; pass
    /// NULL for `destroy_data` and 0 for `flags` for a plain connect.
    ///
    /// Source: `/usr/include/glib-2.0/gobject/gsignal.h`
    pub fn g_signal_connect_data(
        instance: *mut c_void,
        detailed_signal: *const c_char,
        c_handler: extern "C" fn(),
        data: *mut c_void,
        destroy_data: *mut c_void,
        connect_flags: c_uint,
    ) -> u64;

    /// Runtime-checked `G_TYPE_CHECK_INSTANCE_TYPE`, without relying on a C macro.
    /// Source: `/usr/include/glib-2.0/gobject/gtype.h`
    pub fn g_type_check_instance_is_a(instance: *mut GTypeInstance, iface_type: GType) -> GBoolean;

    /// Disconnect a signal handler before freeing its callback state.
    /// Source: `/usr/include/glib-2.0/gobject/gsignal.h`
    pub fn g_signal_handler_disconnect(instance: *mut c_void, handler_id: u64);
}

// ---------------------------------------------------------------------------
// WPE Platform display and the SHM buffer type.
// ---------------------------------------------------------------------------

unsafe extern "C" {
    /// `GType wpe_display_get_type (void);`
    ///
    /// Source: `/usr/include/wpe-webkit-2.0/wpe-platform/wpe/WPEDisplay.h`
    pub fn wpe_display_get_type() -> GType;

    /// `WPESettings *wpe_display_get_settings (WPEDisplay *display);`
    ///
    /// Borrowed; owned by the display. Source: `WPEDisplay.h`
    pub fn wpe_display_get_settings(display: *mut WPEDisplay) -> *mut WPESettings;

    /// `gboolean wpe_settings_set_boolean (WPESettings *, const char *key,
    /// gboolean value, WPESettingsSource source, GError error);`
    ///
    /// Source: `WPESettings.h`
    pub fn wpe_settings_set_boolean(
        settings: *mut WPESettings,
        key: *const c_char,
        value: GBoolean,
        source: c_int,
        error: *mut *mut GError,
    ) -> GBoolean;

    /// Sets a copied UTF-8 display preference; the display owns `settings`.
    /// Source: `WPESettings.h`.
    pub fn wpe_settings_set_string(
        settings: *mut WPESettings,
        key: *const c_char,
        value: *const c_char,
        source: c_int,
        error: *mut *mut GError,
    ) -> GBoolean;
    /// `GBytes *g_bytes_new (gconstpointer data, gsize size);`
    ///
    /// Copies `size` bytes from `data` into a fresh `GBytes`. Ownership: the
    /// returned `GBytes` has ref-count 1; unref with `g_bytes_unref`.
    ///
    /// Source: `/usr/include/glib-2.0/glib/gbytes.h`
    pub fn g_bytes_new(data: *const c_void, size: usize) -> *mut GBytes;

    /// `void g_bytes_unref (GBytes *bytes);`
    ///
    /// Drop one reference; frees the buffer when the last ref is dropped.
    ///
    /// Source: `/usr/include/glib-2.0/glib/gbytes.h`
    pub fn g_bytes_unref(bytes: *mut GBytes);

    /// `gconstpointer g_bytes_get_data (GBytes *bytes, gsize *size);`
    ///
    /// Returns a *borrowed* pointer to the underlying bytes; `size` is filled
    /// with the length. Valid only as long as `bytes` is alive.
    ///
    /// Source: `/usr/include/glib-2.0/glib/gbytes.h`
    pub fn g_bytes_get_data(bytes: *mut GBytes, size: *mut usize) -> *const c_void;

    /// `gsize g_bytes_get_size (GBytes *bytes);`
    ///
    /// Source: `/usr/include/glib-2.0/glib/gbytes.h`
    pub fn g_bytes_get_size(bytes: *mut GBytes) -> usize;

    /// `void g_error_free (GError *error);`
    ///
    /// Source: `/usr/include/glib-2.0/glib/gerror.h`
    pub fn g_error_free(error: *mut GError);

    /// `GQuark g_quark_from_string (const gchar *string);`
    ///
    /// Returns an interned quark id, copying `string` into the quark table.
    /// Unlike `g_quark_from_static_string`, the caller's buffer need not
    /// outlive the call.
    ///
    /// Source: `/usr/include/glib-2.0/glib/gquark.h`
    pub fn g_quark_from_string(string: *const c_char) -> u32;

    /// `GError *g_error_new_literal (GQuark domain, gint code, const gchar *message);`
    ///
    /// Creates a new `GError` with domain, code, and a literal message.
    /// The message is copied by glib, so the caller may free the original.
    ///
    /// Source: `/usr/include/glib-2.0/glib/gerror.h`
    pub fn g_error_new_literal(domain: u32, code: c_int, message: *const c_char) -> *mut GError;

    /// `const gchar *g_quark_to_string (GQuark quark);`
    ///
    /// Returns the *static* interned name of an error domain (for example
    /// `g-tls-error-quark`), or NULL for an unknown quark. Used only to name
    /// the domain of a `GError` in bounded diagnostics: the domain
    /// name distinguishes "the certificate failed validation" from "the
    /// connection never happened", and unlike `GError::message` it is a
    /// compile-time identifier that can carry no request data.
    ///
    /// Source: `/usr/include/glib-2.0/glib/gquark.h`
    pub fn g_quark_to_string(quark: u32) -> *const c_char;

    /// `void g_object_unref (gpointer object);`
    ///
    /// Every GObject-derived type (`WPEDisplay`, `WPEBuffer`, ...) is released
    /// with this. This code types-erase to `*mut c_void` at the call site.
    ///
    /// Source: `/usr/include/glib-2.0/gobject/gobject.h`
    pub fn g_object_unref(object: *mut c_void);

    /// `gpointer g_object_ref (gpointer object);`
    ///
    /// Adds a strong reference. Used on the `DoAction` give-up path to keep the
    /// `GDBusConnection` the outstanding callback dereferences alive after the
    /// drain cap expires, even if the owning
    /// `A11yBus` is dropped - the same retention the state box, main loop and
    /// cancellable already get. Returns the same pointer.
    ///
    /// Source: `/usr/include/glib-2.0/gobject/gobject.h`
    pub fn g_object_ref(object: *mut c_void) -> *mut c_void;

    /// `void g_object_add_weak_pointer (GObject *object, gpointer *weak_pointer_location);`
    ///
    /// Registers `weak_pointer_location` so GLib NULLs it when `object` is
    /// finalized. The caller stores `object` there first; GLib only nullifies.
    ///
    /// Used as a *deterministic lifetime witness* on the profile cap-expiry
    /// transfer path: the abandoned callback checks the witness before
    /// touching the object it was handed, so a missing ownership transfer shows
    /// up as an observable counter instead of a probabilistic
    /// use-after-free.
    ///
    /// Source: `/usr/include/glib-2.0/gobject/gobject.h`
    pub fn g_object_add_weak_pointer(object: *mut c_void, weak_pointer_location: *mut *mut c_void);

    /// `void g_object_remove_weak_pointer (GObject *object, gpointer *weak_pointer_location);`
    ///
    /// Unregisters a witness added by [`g_object_add_weak_pointer`]. Must be
    /// called while `object` is still alive and before the memory holding
    /// `weak_pointer_location` is freed, or GLib would later write into a freed
    /// location.
    ///
    /// Source: `/usr/include/glib-2.0/gobject/gobject.h`
    pub fn g_object_remove_weak_pointer(
        object: *mut c_void,
        weak_pointer_location: *mut *mut c_void,
    );

    /// `GCancellable *g_cancellable_new (void);`
    ///
    /// A cancellable token for an async GIO operation. This code passes one to
    /// `webkit_web_view_get_snapshot` so a snapshot that outlives its deadline
    /// can be cancelled - otherwise its `GAsyncReadyCallback` fires later
    /// against the freed callback-state box (a confirmed use-after-free that
    /// SIGSEGVs). Ref-count 1; release with `g_object_unref`.
    ///
    /// Source: `/usr/include/glib-2.0/gio/gcancellable.h`
    pub fn g_cancellable_new() -> *mut c_void;

    /// `void g_cancellable_cancel (GCancellable *cancellable);`
    ///
    /// Requests cancellation. The pending operation's callback still fires
    /// exactly once (with `G_IO_ERROR_CANCELLED`), so after cancelling the caller
    /// must drain the context until it has fired before freeing its state.
    ///
    /// Source: `/usr/include/glib-2.0/gio/gcancellable.h`
    pub fn g_cancellable_cancel(cancellable: *mut c_void);
}

// ---------------------------------------------------------------------------
// WPE Platform - the display and the SHM buffer type.
// ---------------------------------------------------------------------------

unsafe extern "C" {
    /// `WPEDisplay *wpe_display_headless_new (void);`
    ///
    /// Constructs a headless `WPEDisplay` (no compositor needed). Ref-count 1;
    /// release with `g_object_unref`. Returns `NULL` if the headless platform
    /// plugin failed to load - the FFI wrapper turns that into a hard error.
    ///
    /// Source: `/usr/include/wpe-webkit-2.0/wpe-platform/wpe/headless/WPEDisplayHeadless.h`
    pub fn wpe_display_headless_new() -> *mut WPEDisplay;

    /// Declare the devices forwarded by the embedding platform.
    /// Uses the `WPEAvailableInputDevices` flags from `WPEDisplay.h`.
    pub fn wpe_display_set_available_input_devices(display: *mut WPEDisplay, devices: u32);

    /// `WPEClipboard *wpe_display_get_clipboard (WPEDisplay *display);`
    ///
    /// The display's clipboard. Borrowed - owned by the display, do not
    /// unref. Returns NULL only if the display has none.
    ///
    /// Source: `/usr/include/wpe-webkit-2.0/wpe-platform/wpe/WPEDisplay.h`
    pub fn wpe_display_get_clipboard(display: *mut WPEDisplay) -> *mut WPEClipboard;

    /// `gint64 wpe_clipboard_get_change_count (WPEClipboard *clipboard);`
    ///
    /// A monotonically-increasing counter bumped on every content change - the
    /// signal a widget watches to know the clipboard was written.
    ///
    /// Source: `/usr/include/wpe-webkit-2.0/wpe-platform/wpe/WPEClipboard.h`
    pub fn wpe_clipboard_get_change_count(clipboard: *mut WPEClipboard) -> i64;

    /// `void wpe_clipboard_set_content (WPEClipboard *clipboard, WPEClipboardContent *content);`
    ///
    /// Publishes `content` (may be NULL to clear). The clipboard takes its own
    /// reference; the caller still owns theirs.
    ///
    /// Source: `/usr/include/wpe-webkit-2.0/wpe-platform/wpe/WPEClipboard.h`
    pub fn wpe_clipboard_set_content(
        clipboard: *mut WPEClipboard,
        content: *mut WPEClipboardContent,
    );

    /// `char *wpe_clipboard_read_text (WPEClipboard *clipboard, const char *format, gsize *size);`
    ///
    /// Reads the text for `format` (e.g. `text/plain;charset=utf-8`). Returns a
    /// newly-allocated C string the caller frees with `g_free`, or NULL.
    ///
    /// Source: `/usr/include/wpe-webkit-2.0/wpe-platform/wpe/WPEClipboard.h`
    pub fn wpe_clipboard_read_text(
        clipboard: *mut WPEClipboard,
        format: *const c_char,
        size: *mut usize,
    ) -> *mut c_char;

    /// `WPEClipboardContent *wpe_clipboard_content_new (void);`
    ///
    /// A fresh, empty content bundle, ref-count 1; release with
    /// `wpe_clipboard_content_unref`.
    ///
    /// Source: `/usr/include/wpe-webkit-2.0/wpe-platform/wpe/WPEClipboard.h`
    pub fn wpe_clipboard_content_new() -> *mut WPEClipboardContent;

    /// `void wpe_clipboard_content_set_text (WPEClipboardContent *content, const char *text);`
    ///
    /// Sets the text/plain payload (copied).
    ///
    /// Source: `/usr/include/wpe-webkit-2.0/wpe-platform/wpe/WPEClipboard.h`
    pub fn wpe_clipboard_content_set_text(content: *mut WPEClipboardContent, text: *const c_char);

    /// `void wpe_clipboard_content_unref (WPEClipboardContent *content);`
    ///
    /// Source: `/usr/include/wpe-webkit-2.0/wpe-platform/wpe/WPEClipboard.h`
    pub fn wpe_clipboard_content_unref(content: *mut WPEClipboardContent);

    /// `void g_free (gpointer mem);`
    ///
    /// Frees memory glib allocated (e.g. the string from
    /// `wpe_clipboard_read_text`).
    ///
    /// Source: `/usr/include/glib-2.0/glib/gmem.h`
    pub fn g_free(mem: *mut c_void);

    // -----------------------------------------------------------------------
    // GDBus - reading the page's accessible tree.
    //
    // The tree is not in this process: WPE's a11y object is an `AtkSocket`,
    // and the real nodes live in the sandboxed WebProcess, published over the
    // AT-SPI D-Bus. Reading a role or a name therefore means a D-Bus call.
    //
    // These come from `libgio-2.0`, which is ALREADY in the link flags -
    // `pkg-config --libs wpe-webkit-2.0` emits `-lgio-2.0` - so binding them
    // adds no dependency, no build.rs change, and no new `Cargo.lock` entry.
    // -----------------------------------------------------------------------

    /// `GDBusConnection *g_bus_get_sync (GBusType bus_type, GCancellable *c, GError error);`
    ///
    /// `bus_type` 2 = `G_BUS_TYPE_SESSION`. Used only to ask the session-bus
    /// broker for the a11y bus address; the accessible tree itself is on the
    /// separate a11y bus. Returned connection is owned (unref with
    /// `g_object_unref`).
    ///
    /// Source: `/usr/include/glib-2.0/gio/gdbusconnection.h`
    pub fn g_bus_get_sync(
        bus_type: c_int,
        cancellable: *mut c_void,
        error: *mut *mut GError,
    ) -> *mut c_void;

    /// `GDBusConnection *g_dbus_connection_new_for_address_sync (const gchar *address, GDBusConnectionFlags flags, GDBusAuthObserver *o, GCancellable *c, GError error);`
    ///
    /// Connects to the AT-SPI bus by address. `flags` must include
    /// `AUTHENTICATION_CLIENT` (1) | `MESSAGE_BUS_CONNECTION` (2) = 3, or the
    /// connection is not a bus client and named calls fail.
    ///
    /// Source: `/usr/include/glib-2.0/gio/gdbusconnection.h`
    pub fn g_dbus_connection_new_for_address_sync(
        address: *const c_char,
        flags: c_int,
        observer: *mut c_void,
        cancellable: *mut c_void,
        error: *mut *mut GError,
    ) -> *mut c_void;

    /// `GVariant *g_dbus_connection_call_sync (GDBusConnection *c, const gchar *bus_name, const gchar *object_path, const gchar *interface_name, const gchar *method_name, GVariant *parameters, const GVariantType *reply_type, GDBusCallFlags flags, gint timeout_msec, GCancellable *c, GError error);`
    ///
    /// One blocking AT-SPI method call. Returns a floating-consumed
    /// `parameters` (this code passes NULL or a `g_variant_new` result) and an owned
    /// reply `GVariant` (unref with `g_variant_unref`).
    ///
    /// Every call site passes a finite `timeout_msec`, so a wedged WebProcess
    /// surfaces as an error rather than a hang.
    ///
    /// Source: `/usr/include/glib-2.0/gio/gdbusconnection.h`
    #[allow(clippy::too_many_arguments)]
    pub fn g_dbus_connection_call_sync(
        connection: *mut c_void,
        bus_name: *const c_char,
        object_path: *const c_char,
        interface_name: *const c_char,
        method_name: *const c_char,
        parameters: *mut c_void,
        reply_type: *const c_void,
        flags: c_int,
        timeout_msec: c_int,
        cancellable: *mut c_void,
        error: *mut *mut GError,
    ) -> *mut c_void;

    /// `void g_dbus_connection_call (GDBusConnection *c, const gchar *bus_name, const gchar *object_path, const gchar *interface_name, const gchar *method_name, GVariant *parameters, const GVariantType *reply_type, GDBusCallFlags flags, gint timeout_msec, GCancellable *c, GAsyncReadyCallback callback, gpointer user_data);`
    ///
    /// The asynchronous form. Required for AT-SPI `Action.DoAction` on a
    /// WebKit page: `..._call_sync` blocks this (the UI) process, and WebKit's
    /// WebProcess needs UI-process IPC serviced to complete a DOM activation,
    /// so the synchronous form deadlocks until its own timeout expires. The
    /// async form lets this code run a `GMainLoop` while the call is outstanding.
    ///
    /// `parameters` is consumed (a floating reference is sunk).
    ///
    /// Source: `/usr/include/glib-2.0/gio/gdbusconnection.h`
    #[allow(clippy::too_many_arguments)]
    pub fn g_dbus_connection_call(
        connection: *mut c_void,
        bus_name: *const c_char,
        object_path: *const c_char,
        interface_name: *const c_char,
        method_name: *const c_char,
        parameters: *mut c_void,
        reply_type: *const c_void,
        flags: c_int,
        timeout_msec: c_int,
        cancellable: *mut c_void,
        callback: extern "C" fn(*mut c_void, *mut GAsyncResult, *mut c_void),
        user_data: *mut c_void,
    );

    /// `GVariant *g_dbus_connection_call_finish (GDBusConnection *c, GAsyncResult *res, GError error);`
    ///
    /// Completes a [`g_dbus_connection_call`]. Returns an owned reply
    /// variant, or NULL with `error` set.
    ///
    /// Source: `/usr/include/glib-2.0/gio/gdbusconnection.h`
    pub fn g_dbus_connection_call_finish(
        connection: *mut c_void,
        res: *mut GAsyncResult,
        error: *mut *mut GError,
    ) -> *mut c_void;

    /// `GVariant *g_variant_new (const gchar *format_string, ...);`
    ///
    /// Declared with the exact fixed arity this code uses - `("(ss)", a, b)` - rather
    /// than as a variadic, so the compiler type-checks the only call shape.
    /// Returns a floating reference, consumed by `g_dbus_connection_call_sync`.
    ///
    /// Source: `/usr/include/glib-2.0/glib/gvariant.h`
    pub fn g_variant_new(
        format_string: *const c_char,
        a: *const c_char,
        b: *const c_char,
    ) -> *mut c_void;

    /// `const gchar *g_variant_get_string (GVariant *value, gsize *length);`
    ///
    /// Borrowed pointer into the variant - valid until the variant is unref'd.
    ///
    /// Source: `/usr/include/glib-2.0/glib/gvariant.h`
    pub fn g_variant_get_string(value: *mut c_void, length: *mut usize) -> *const c_char;

    /// `GVariant *g_variant_get_child_value (GVariant *value, gsize index_);`
    ///
    /// The `index_`-th child of a container variant. Owned - unref it.
    /// Used instead of the variadic `g_variant_get` so no format string is
    /// parsed at run time and every extraction is explicit.
    ///
    /// Source: `/usr/include/glib-2.0/glib/gvariant.h`
    pub fn g_variant_get_child_value(value: *mut c_void, index: usize) -> *mut c_void;

    /// `gsize g_variant_n_children (GVariant *value);`
    ///
    /// Source: `/usr/include/glib-2.0/glib/gvariant.h`
    pub fn g_variant_n_children(value: *mut c_void) -> usize;

    /// `guint32 g_variant_get_uint32 (GVariant *value);`
    ///
    /// Source: `/usr/include/glib-2.0/glib/gvariant.h`
    pub fn g_variant_get_uint32(value: *mut c_void) -> u32;

    /// `gint32 g_variant_get_int32 (GVariant *value);`
    ///
    /// Reads an `i` variant - AT-SPI's `Action.NActions` property type.
    ///
    /// Source: `/usr/include/glib-2.0/glib/gvariant.h`
    pub fn g_variant_get_int32(value: *mut c_void) -> i32;

    /// `gboolean g_variant_get_boolean (GVariant *value);`
    ///
    /// Reads a `b` variant - `Action.DoAction`'s success reply. `gboolean` is
    /// `gint`, i.e. `c_int`, not a Rust `bool`: any non-zero value is true,
    /// so it must not be transmuted.
    ///
    /// Source: `/usr/include/glib-2.0/glib/gvariant.h`
    pub fn g_variant_get_boolean(value: *mut c_void) -> c_int;

    /// `GVariant *g_variant_new_int32 (gint32 value);`
    ///
    /// Returns a floating reference, consumed when it is put into a tuple
    /// (or passed to `g_dbus_connection_call_sync`).
    ///
    /// Source: `/usr/include/glib-2.0/glib/gvariant.h`
    pub fn g_variant_new_int32(value: i32) -> *mut c_void;

    /// `GVariant *g_variant_new_string (const gchar *string);`
    ///
    /// Returns a floating string variant. Used by native boundary fixtures to
    /// drive the same length-reporting API as AT-SPI replies.
    ///
    /// Source: `/usr/include/glib-2.0/glib/gvariant.h`
    pub fn g_variant_new_string(value: *const c_char) -> *mut c_void;

    /// `GVariant *g_variant_new_object_path (const gchar *object_path);`
    ///
    /// Returns a floating object-path variant.
    ///
    /// Source: `/usr/include/glib-2.0/glib/gvariant.h`
    pub fn g_variant_new_object_path(value: *const c_char) -> *mut c_void;

    /// `GVariant *g_variant_new_array (const GVariantType *child_type, GVariant
    /// *const *children, gsize n_children);`
    ///
    /// With non-empty `children`, a NULL `child_type` infers the element type.
    /// Consumes the children's floating references and returns a floating array.
    ///
    /// Source: `/usr/include/glib-2.0/glib/gvariant.h`
    pub fn g_variant_new_array(
        child_type: *const c_void,
        children: *const *mut c_void,
        n_children: usize,
    ) -> *mut c_void;

    /// `GVariant *g_variant_new_tuple (GVariant * const *children, gsize n_children);`
    ///
    /// Builds the `(i)` parameter tuple AT-SPI's `Action.GetName` /
    /// `Action.DoAction` take. Used instead of a second variadic
    /// `g_variant_new` declaration so the argument count is checked by the
    /// compiler rather than by a format string at run time. Consumes the
    /// floating references of `children` and returns a floating reference.
    ///
    /// Source: `/usr/include/glib-2.0/glib/gvariant.h`
    pub fn g_variant_new_tuple(children: *const *mut c_void, n_children: usize) -> *mut c_void;

    /// `GVariant *g_variant_get_variant (GVariant *value);`
    ///
    /// Unboxes a `v` (variant-typed) child, as returned by
    /// `org.freedesktop.DBus.Properties.Get`. Owned - unref it.
    ///
    /// Source: `/usr/include/glib-2.0/glib/gvariant.h`
    pub fn g_variant_get_variant(value: *mut c_void) -> *mut c_void;

    /// `void g_variant_unref (GVariant *value);`
    ///
    /// Source: `/usr/include/glib-2.0/glib/gvariant.h`
    pub fn g_variant_unref(value: *mut c_void);

    /// `WPEBufferSHM *wpe_buffer_shm_new (WPEDisplay *display, int width, int height, WPEPixelFormat format, GBytes *data, guint stride);`
    ///
    /// Wraps `data` (a `GBytes` owned here) as a `WPEBufferSHM`. The buffer
    /// borrows the `GBytes` reference; unref the `GBytes` when done. The
    /// returned buffer is a `WPEBuffer` subclass, ref-count 1.
    ///
    /// Source: `/usr/include/wpe-webkit-2.0/wpe-platform/wpe/WPEBufferSHM.h`
    pub fn wpe_buffer_shm_new(
        display: *mut WPEDisplay,
        width: c_int,
        height: c_int,
        format: WPEPixelFormat,
        data: *mut GBytes,
        stride: c_uint,
    ) -> *mut WPEBufferSHM;

    /// `WPEPixelFormat wpe_buffer_shm_get_format (WPEBufferSHM *buffer);`
    ///
    /// Source: `/usr/include/wpe-webkit-2.0/wpe-platform/wpe/WPEBufferSHM.h`
    pub fn wpe_buffer_shm_get_format(buffer: *mut WPEBufferSHM) -> WPEPixelFormat;

    /// `GBytes *wpe_buffer_shm_get_data (WPEBufferSHM *buffer);`
    ///
    /// Returns a borrowed pointer to the buffer's inner `GBytes` - per the
    /// gobject-introspection annotation in `WPEPlatform-2.0.gir`:
    /// `transfer-ownership="none"`. DO not unref the returned pointer; it
    /// is owned by the `WPEBufferSHM` and freed with it. Unref'ing here
    /// produces the `g_atomic_ref_count_dec` critical.
    ///
    /// Source: `/usr/include/wpe-webkit-2.0/wpe-platform/wpe/WPEBufferSHM.h`
    /// GIR:    `/usr/share/gir-1.0/WPEPlatform-2.0.gir` (`wpe_buffer_shm_get_data`)
    pub fn wpe_buffer_shm_get_data(buffer: *mut WPEBufferSHM) -> *mut GBytes;

    /// `guint wpe_buffer_shm_get_stride (WPEBufferSHM *buffer);`
    ///
    /// Source: `/usr/include/wpe-webkit-2.0/wpe-platform/wpe/WPEBufferSHM.h`
    pub fn wpe_buffer_shm_get_stride(buffer: *mut WPEBufferSHM) -> c_uint;

    /// `int wpe_buffer_get_width (WPEBuffer *buffer);`
    ///
    /// Source: `/usr/include/wpe-webkit-2.0/wpe-platform/wpe/WPEBuffer.h`
    pub fn wpe_buffer_get_width(buffer: *mut WPEBuffer) -> c_int;

    /// `int wpe_buffer_get_height (WPEBuffer *buffer);`
    ///
    /// Source: `/usr/include/wpe-webkit-2.0/wpe-platform/wpe/WPEBuffer.h`
    pub fn wpe_buffer_get_height(buffer: *mut WPEBuffer) -> c_int;
}

// ---------------------------------------------------------------------------
// WebKit - the WebView, HTML loading, and the async snapshot.
// ---------------------------------------------------------------------------

unsafe extern "C" {
    /// `GType webkit_web_view_get_type (void);`
    ///
    /// Source: `/usr/include/wpe-webkit-2.0/wpe/WebKitWebView.h`
    pub fn webkit_web_view_get_type() -> GType;

    /// `GType webkit_network_session_get_type (void);`
    ///
    /// Used to initialise the construct-only `network-session` GValue when a
    /// profiled WebView is created.
    ///
    /// Source: `/usr/include/wpe-webkit-2.0/wpe/WebKitNetworkSession.h`
    pub fn webkit_network_session_get_type() -> GType;

    /// `WebKitNetworkSession *webkit_web_view_get_network_session (WebKitWebView *web_view);`
    ///
    /// Returns the view's borrowed network session. Reading it back lets the
    /// safe constructor reject a GObject/property mismatch instead of silently
    /// running the page on WebKit's default profile.
    ///
    /// Source: `/usr/include/wpe-webkit-2.0/wpe/WebKitWebView.h`
    pub fn webkit_web_view_get_network_session(
        web_view: *mut WebKitWebView,
    ) -> *mut WebKitNetworkSession;

    /// Borrow the authentication challenge's host.
    pub fn webkit_authentication_request_get_host(
        request: *mut WebKitAuthenticationRequest,
    ) -> *const c_char;
    /// Return the authentication challenge's port.
    pub fn webkit_authentication_request_get_port(
        request: *mut WebKitAuthenticationRequest,
    ) -> c_uint;
    /// Return true only for a proxy, rather than origin-server, challenge.
    pub fn webkit_authentication_request_is_for_proxy(
        request: *mut WebKitAuthenticationRequest,
    ) -> GBoolean;
    /// Return true when earlier credentials were already refused.
    pub fn webkit_authentication_request_is_retry(
        request: *mut WebKitAuthenticationRequest,
    ) -> GBoolean;
    /// Answer a challenge with a boxed credential value.
    pub fn webkit_authentication_request_authenticate(
        request: *mut WebKitAuthenticationRequest,
        credential: *mut WebKitCredential,
    );
    /// Create a username/password credential with the requested persistence.
    pub fn webkit_credential_new(
        username: *const c_char,
        password: *const c_char,
        persistence: c_int,
    ) -> *mut WebKitCredential;
    /// Free a caller-owned boxed credential.
    pub fn webkit_credential_free(credential: *mut WebKitCredential);

    /// `WebKitNetworkProxySettings *webkit_network_proxy_settings_new (const gchar *default_proxy_uri, const gchar* const *ignore_hosts);`
    ///
    /// Ref-count-free boxed value (transfer=full) - free with
    /// [`webkit_network_proxy_settings_free`]. `ignore_hosts` is a NULL
    /// terminated array; passing NULL means nothing bypasses the proxy,
    /// because a bypass list would be a hole in the
    /// destination guard.
    ///
    /// Source: `/usr/include/wpe-webkit-2.0/wpe/WebKitNetworkProxySettings.h`
    pub fn webkit_network_proxy_settings_new(
        default_proxy_uri: *const c_char,
        ignore_hosts: *const *const c_char,
    ) -> *mut WebKitNetworkProxySettings;

    /// `void webkit_network_proxy_settings_free (WebKitNetworkProxySettings *proxy_settings);`
    ///
    /// Source: `/usr/include/wpe-webkit-2.0/wpe/WebKitNetworkProxySettings.h`
    pub fn webkit_network_proxy_settings_free(settings: *mut WebKitNetworkProxySettings);

    /// `void webkit_network_session_set_proxy_settings (WebKitNetworkSession *session, WebKitNetworkProxyMode mode, WebKitNetworkProxySettings *settings);`
    ///
    /// With [`WEBKIT_NETWORK_PROXY_MODE_CUSTOM`] and a settings object, every
    /// network request of the session - documents, subresources, `fetch`,
    /// redirect hops - is routed through the given proxy. The settings are
    /// copied by WebKit, so the caller frees its own.
    ///
    /// Source: `/usr/include/wpe-webkit-2.0/wpe/WebKitNetworkSession.h`
    pub fn webkit_network_session_set_proxy_settings(
        session: *mut WebKitNetworkSession,
        proxy_mode: c_int,
        settings: *mut WebKitNetworkProxySettings,
    );

    /// Return the process-wide default context (borrowed). Configuring it
    /// before view construction ensures the request guard is inherited by the
    /// first WebProcess rather than racing its first load.
    /// Source: `/usr/include/wpe-webkit-2.0/wpe/WebKitWebContext.h`.
    pub fn webkit_web_context_get_default() -> *mut WebKitWebContext;

    /// Add a read-only path to the WebProcess sandbox and select the directory
    /// from which process extensions are loaded. Both calls must happen before
    /// the context starts loading anything.
    /// Source: `/usr/include/wpe-webkit-2.0/wpe/WebKitWebContext.h`.
    pub fn webkit_web_context_add_path_to_sandbox(
        context: *mut WebKitWebContext,
        path: *const c_char,
        read_only: GBoolean,
    );
    pub fn webkit_web_context_set_web_process_extensions_directory(
        context: *mut WebKitWebContext,
        directory: *const c_char,
    );

    /// Stop the current load. The WebProcess request hook already cancels the
    /// offending request synchronously; this terminates the surrounding
    /// navigation when its constant refusal message reaches the UI process.
    /// Source: `/usr/include/wpe-webkit-2.0/wpe/WebKitWebView.h`.
    pub fn webkit_web_view_stop_loading(web_view: *mut WebKitWebView);

    /// Borrow the constant name of a WebProcess-to-view message.
    /// Source: `/usr/include/wpe-webkit-2.0/wpe/WebKitUserMessage.h`.
    pub fn webkit_user_message_get_name(message: *mut WebKitUserMessage) -> *const c_char;

    /// Create a floating message; sending it consumes that floating reference.
    pub fn webkit_user_message_new(
        name: *const c_char,
        parameters: *mut c_void,
    ) -> *mut WebKitUserMessage;

    /// Send a private message to the view's process extension.
    pub fn webkit_web_view_send_message_to_page(
        web_view: *mut WebKitWebView,
        message: *mut WebKitUserMessage,
        cancellable: *mut c_void,
        callback: Option<extern "C" fn(*mut c_void, *mut GAsyncResult, *mut c_void)>,
        data: *mut c_void,
    );

    /// Finish a message call, returning an owned reply or an owned error.
    pub fn webkit_web_view_send_message_to_page_finish(
        web_view: *mut WebKitWebView,
        result: *mut GAsyncResult,
        error: *mut *mut GError,
    ) -> *mut WebKitUserMessage;

    /// `void webkit_web_view_load_html (WebKitWebView *web_view, const gchar *content, const gchar *base_uri);`
    ///
    /// `content` is a NUL-terminated UTF-8 HTML string, `base_uri` may be NULL.
    /// Loading is asynchronous; the `load-changed` signal fires with
    /// `WEBKIT_LOAD_FINISHED` when the page has finished loading.
    ///
    /// Source: `/usr/include/wpe-webkit-2.0/wpe/WebKitWebView.h`
    pub fn webkit_web_view_load_html(
        web_view: *mut WebKitWebView,
        content: *const c_char,
        base_uri: *const c_char,
    );

    /// `void webkit_web_view_load_uri (WebKitWebView *web_view, const gchar *uri);`
    ///
    /// Accepts any URI scheme WebKit knows, including `data:` (which needs no
    /// network and is what the smoke test uses).
    ///
    /// Source: `/usr/include/wpe-webkit-2.0/wpe/WebKitWebView.h`
    pub fn webkit_web_view_load_uri(web_view: *mut WebKitWebView, uri: *const c_char);

    /// Borrowed current URI, or NULL before any load.
    /// Source: `/usr/include/wpe-webkit-2.0/wpe/WebKitWebView.h`.
    pub fn webkit_web_view_get_uri(web_view: *mut WebKitWebView) -> *const c_char;

    /// Policy-decision accessors and terminal actions. Sources:
    /// `WebKitPolicyDecision.h`, `WebKitNavigationPolicyDecision.h`,
    /// `WebKitNavigationAction.h`, `WebKitResponsePolicyDecision.h`, and
    /// `WebKitURIRequest.h`.
    pub fn webkit_navigation_policy_decision_get_navigation_action(
        decision: *mut WebKitNavigationPolicyDecision,
    ) -> *mut WebKitNavigationAction;
    pub fn webkit_navigation_action_get_request(
        action: *mut WebKitNavigationAction,
    ) -> *mut WebKitURIRequest;
    pub fn webkit_navigation_action_get_mouse_button(action: *mut WebKitNavigationAction)
    -> c_uint;
    pub fn webkit_navigation_action_is_user_gesture(
        action: *mut WebKitNavigationAction,
    ) -> GBoolean;

    /// Whether this navigation action was produced by an HTTP redirect.
    pub fn webkit_navigation_action_is_redirect(action: *mut WebKitNavigationAction) -> GBoolean;

    /// Borrowed mutable HTTP headers for a URI request.
    pub fn webkit_uri_request_get_http_headers(
        request: *mut WebKitURIRequest,
    ) -> *mut SoupMessageHeaders;

    /// Remove every value for `name` from a libsoup header set.
    pub fn soup_message_headers_remove(headers: *mut SoupMessageHeaders, name: *const c_char);

    /// Small header helpers used by the credential-stripping consequence gate.
    pub fn soup_message_headers_new(headers_type: c_int) -> *mut SoupMessageHeaders;
    pub fn soup_message_headers_unref(headers: *mut SoupMessageHeaders);
    pub fn soup_message_headers_append(
        headers: *mut SoupMessageHeaders,
        name: *const c_char,
        value: *const c_char,
    );
    pub fn soup_message_headers_get_one(
        headers: *mut SoupMessageHeaders,
        name: *const c_char,
    ) -> *const c_char;
    pub fn webkit_response_policy_decision_get_request(
        decision: *mut WebKitResponsePolicyDecision,
    ) -> *mut WebKitURIRequest;
    pub fn webkit_response_policy_decision_is_mime_type_supported(
        decision: *mut WebKitResponsePolicyDecision,
    ) -> GBoolean;
    pub fn webkit_response_policy_decision_is_main_frame_main_resource(
        decision: *mut WebKitResponsePolicyDecision,
    ) -> GBoolean;

    /// `WebKitURIResponse *webkit_response_policy_decision_get_response (WebKitResponsePolicyDecision*);`
    ///
    /// Borrowed pointer - do not unref. Read only for bounded diagnostics
    /// The status code and MIME type WebKit actually received for a
    /// main-resource decision are what distinguish "the origin answered with
    /// something unrenderable" from "the origin never answered".
    ///
    /// Source: `/usr/include/wpe-webkit-2.0/wpe/WebKitResponsePolicyDecision.h`
    pub fn webkit_response_policy_decision_get_response(
        decision: *mut WebKitResponsePolicyDecision,
    ) -> *mut WebKitURIResponse;

    /// `guint webkit_uri_response_get_status_code (WebKitURIResponse *response);`
    ///
    /// Source: `/usr/include/wpe-webkit-2.0/wpe/WebKitURIResponse.h`
    pub fn webkit_uri_response_get_status_code(response: *mut WebKitURIResponse) -> u32;

    /// Borrow the response's canonical URI while the response is retained.
    pub fn webkit_uri_response_get_uri(response: *mut WebKitURIResponse) -> *const c_char;
    /// Borrow the native response headers for synchronous, bounded metadata inspection.
    pub fn webkit_uri_response_get_http_headers(
        response: *mut WebKitURIResponse,
    ) -> *mut SoupMessageHeaders;

    /// `const gchar *webkit_uri_response_get_mime_type (WebKitURIResponse *response);`
    ///
    /// Borrowed string owned by the response; may be NULL.
    ///
    /// Source: `/usr/include/wpe-webkit-2.0/wpe/WebKitURIResponse.h`
    pub fn webkit_uri_response_get_mime_type(response: *mut WebKitURIResponse) -> *const c_char;
    /// Create one owned native URI request.
    pub fn webkit_uri_request_new(uri: *const c_char) -> *mut WebKitURIRequest;
    /// Replace a request header before native dispatch.
    pub fn soup_message_headers_replace(
        headers: *mut SoupMessageHeaders,
        name: *const c_char,
        value: *const c_char,
    );
    /// Load a copied request on the live view.
    pub fn webkit_web_view_load_request(view: *mut WebKitWebView, request: *mut WebKitURIRequest);
    pub fn webkit_uri_request_get_uri(request: *mut WebKitURIRequest) -> *const c_char;
    pub fn webkit_policy_decision_use(decision: *mut WebKitPolicyDecision);
    pub fn webkit_policy_decision_ignore(decision: *mut WebKitPolicyDecision);
    pub fn webkit_policy_decision_download(decision: *mut WebKitPolicyDecision);

    /// `WebKitURIRequest *webkit_download_get_request (WebKitDownload *download);`
    ///
    /// Borrowed pointer - do not unref. Carries the URI the download was
    /// started for; this code reads only its URI, never its body.
    ///
    /// Source: `/usr/include/wpe-webkit-2.0/wpe/WebKitDownload.h`
    pub fn webkit_download_get_request(download: *mut WebKitDownload) -> *mut WebKitURIRequest;

    /// Start a download with a transferred caller-owned GObject reference.
    pub fn webkit_web_view_download_uri(
        view: *mut WebKitWebView,
        uri: *const c_char,
    ) -> *mut WebKitDownload;

    /// `WebKitWebView *webkit_download_get_web_view (WebKitDownload *download);`
    ///
    /// Borrowed pointer - do not unref. Identifies the view that initiated
    /// the download so a network-session-scoped signal handler can filter to
    /// downloads it actually owns.
    ///
    /// Source: `/usr/include/wpe-webkit-2.0/wpe/WebKitDownload.h`
    pub fn webkit_download_get_web_view(download: *mut WebKitDownload) -> *mut WebKitWebView;

    /// `void webkit_download_cancel (WebKitDownload *download);`
    ///
    /// Asks WebKit to cancel a live download. Emitting `download-started` is
    /// enough to prove `webkit_policy_decision_download` ran; the safe layer
    /// then cancels so bytes never touch disk.
    ///
    /// Source: `/usr/include/wpe-webkit-2.0/wpe/WebKitDownload.h`
    pub fn webkit_download_cancel(download: *mut WebKitDownload);

    /// Permission terminal actions and concrete request types. Unknown concrete
    /// types deliberately map to `PermissionKind::Unknown` in the safe layer.
    /// Sources: `WebKitPermissionRequest.h` and concrete permission headers.
    pub fn webkit_permission_request_allow(request: *mut WebKitPermissionRequest);
    pub fn webkit_permission_request_deny(request: *mut WebKitPermissionRequest);
    pub fn webkit_geolocation_permission_request_get_type() -> GType;
    pub fn webkit_media_key_system_permission_request_get_type() -> GType;
    pub fn webkit_notification_permission_request_get_type() -> GType;
    pub fn webkit_user_media_permission_request_get_type() -> GType;
    pub fn webkit_user_media_permission_is_for_audio_device(
        request: *mut WebKitPermissionRequest,
    ) -> GBoolean;
    pub fn webkit_user_media_permission_is_for_video_device(
        request: *mut WebKitPermissionRequest,
    ) -> GBoolean;
    /// `gboolean webkit_user_media_permission_is_for_display_device (WebKitUserMediaPermissionRequest *request);`
    ///
    /// The third, independent device flag of a user-media request: screen
    /// or window capture. It is declared unconditionally and read on every
    /// user-media request, because one `webkit_permission_request_allow` grants
    /// every device the request named - a display flag left unread would be
    /// granted by a camera decision. There is no display capability in the
    /// policy, so the safe layer maps any display request to an un-grantable
    /// `PermissionKind::Unknown`.
    ///
    /// Availability is not treated as optional: a WPE build without this symbol
    /// fails to link rather than defaulting the flag to `false`, which is
    /// the fail-closed direction.
    ///
    /// Source: `/usr/include/wpe-webkit-2.0/wpe/WebKitUserMediaPermissionRequest.h`
    pub fn webkit_user_media_permission_is_for_display_device(
        request: *mut WebKitPermissionRequest,
    ) -> GBoolean;

    /// Permit one concrete certificate for one host. The safe layer invokes
    /// this only after a correlated live-generation policy Allow.
    /// Source: `WebKitNetworkSession.h`.
    pub fn webkit_network_session_allow_tls_certificate_for_host(
        session: *mut WebKitNetworkSession,
        certificate: *mut GTlsCertificate,
        host: *const c_char,
    );

    /// `GTlsCertificate *g_tls_certificate_new_from_pem (const gchar *data, gssize length, GError error);`
    ///
    /// Construct a `GTlsCertificate` from PEM-encoded data. Returned object
    /// has ref-count 1; release with [`g_object_unref`]. Used by
    /// [`WebSession::allow_tls_certificate_for_host`](crate::ffi::runtime::WebSession::allow_tls_certificate_for_host) to pre-trust a
    /// self-signed certificate before navigation.
    ///
    /// Source: `/usr/include/glib-2.0/gio/gtlscertificate.h`
    pub fn g_tls_certificate_new_from_pem(
        data: *const c_char,
        length: isize,
        error: *mut *mut GError,
    ) -> *mut GTlsCertificate;

    /// `void webkit_web_view_terminate_web_process (WebKitWebView *web_view);`
    ///
    /// Requests termination of the associated WebProcess. WebKit then emits
    /// `web-process-terminated` with `TERMINATED_BY_API`; production crashes
    /// reach the same signal with a different reason.
    ///
    /// Source: `/usr/include/wpe-webkit-2.0/wpe/WebKitWebView.h`
    pub fn webkit_web_view_terminate_web_process(web_view: *mut WebKitWebView);

    /// `void webkit_web_view_get_snapshot (WebKitWebView*, WebKitSnapshotRegion, WebKitSnapshotOptions, GCancellable*, GAsyncReadyCallback, gpointer);`
    ///
    /// Kicks off an asynchronous snapshot; the callback receives a
    /// `GAsyncResult*` that this code passes to `webkit_web_view_get_snapshot_finish`.
    ///
    /// Source: `/usr/include/wpe-webkit-2.0/wpe/WebKitWebView.h`
    pub fn webkit_web_view_get_snapshot(
        web_view: *mut WebKitWebView,
        region: c_int,   // WebKitSnapshotRegion enum
        options: c_uint, // WebKitSnapshotOptions bitset
        cancellable: *mut c_void,
        callback: extern "C" fn(*mut c_void, *mut GAsyncResult, *mut c_void),
        user_data: *mut c_void,
    );

    /// `WebKitImage *webkit_web_view_get_snapshot_finish (WebKitWebView*, GAsyncResult*, GError);`
    ///
    /// Returns a `WebKitImage*` with ref-count 1 (`transfer-ownership="full"`),
    /// or NULL on error - in which case `*error` is populated.
    ///
    /// Source: `/usr/include/wpe-webkit-2.0/wpe/WebKitWebView.h`
    /// GIR:    `/usr/share/gir-1.0/WPEWebKit-2.0.gir` (`webkit_web_view_get_snapshot_finish`)
    pub fn webkit_web_view_get_snapshot_finish(
        web_view: *mut WebKitWebView,
        result: *mut GAsyncResult,
        error: *mut *mut GError,
    ) -> *mut WebKitImage;

    /// `int webkit_image_get_width (WebKitImage *image);`
    ///
    /// Source: `/usr/include/wpe-webkit-2.0/wpe/WebKitImage.h`
    pub fn webkit_image_get_width(image: *mut WebKitImage) -> c_int;

    /// `int webkit_image_get_height (WebKitImage *image);`
    ///
    /// Source: `/usr/include/wpe-webkit-2.0/wpe/WebKitImage.h`
    pub fn webkit_image_get_height(image: *mut WebKitImage) -> c_int;

    /// `guint webkit_image_get_stride (WebKitImage *image);`
    ///
    /// Source: `/usr/include/wpe-webkit-2.0/wpe/WebKitImage.h`
    pub fn webkit_image_get_stride(image: *mut WebKitImage) -> c_uint;

    /// `GBytes *webkit_image_as_bytes (WebKitImage *image);`
    ///
    /// Borrowed pointer - per the GIR annotation
    /// `transfer-ownership="none"`, this code does not unref. The pixel format is
    /// documented as "32-bit per pixel with 8-bit premultiplied alpha, in the
    /// preferred byte order for the architecture" - on little-endian x86_64
    /// that is cairo `ARGB32` (memory bytes B,G,R,A per pixel), same order as
    /// `WPEBufferSHM`, so this code reuses `argb8888_bytes_to_rgba8`.
    ///
    /// Source: `/usr/include/wpe-webkit-2.0/wpe/WebKitImage.h`
    /// GIR:    `/usr/share/gir-1.0/WPEWebKit-2.0.gir` (`webkit_image_as_bytes`)
    pub fn webkit_image_as_bytes(image: *mut WebKitImage) -> *mut GBytes;
}

// ---------------------------------------------------------------------------
// Input events - pointer / wheel / keyboard forwarding.
//
// The dispatch seam is `wpe_view_event(WPEView*, WPEEvent*)`. A synthesized
// event is built with the matching `wpe_event_*_new` constructor, dispatched,
// and unref'd. WebKit receives it in the WebProcess and runs the page's DOM
// handlers - which is why a colour-changing script is observable in a
// snapshot after this code dispatches.
// ---------------------------------------------------------------------------

unsafe extern "C" {
    /// `WPEView *webkit_web_view_get_wpe_view (WebKitWebView *web_view);`
    ///
    /// Returns the platform view the WebKit view presents into. Borrowed
    /// pointer (transfer=none per GIR) - do not unref; it lives as long as the
    /// `WebKitWebView`. Returns NULL if the view has no WPE backing, which is
    /// a build mismatch this code surfaces loudly rather than papering over.
    ///
    /// Source: `/usr/include/wpe-webkit-2.0/wpe/WebKitWebView.h`
    /// GIR:    `/usr/share/gir-1.0/WPEWebKit-2.0.gir` (`webkit_web_view_get_wpe_view`)
    pub fn webkit_web_view_get_wpe_view(web_view: *mut WebKitWebView) -> *mut WPEView;

    /// `void wpe_view_event (WPEView *view, WPEEvent *event);`
    ///
    /// Delivers `event` to `view`. Takes its own reference on `event`; the
    /// caller retains ownership of the reference the constructor returned and
    /// must `wpe_event_unref` it.
    ///
    /// Source: `/usr/include/wpe-webkit-2.0/wpe-platform/wpe/WPEView.h`
    pub fn wpe_view_event(view: *mut WPEView, event: *mut WPEEvent);

    /// `WPEViewAccessible *wpe_view_get_accessible (WPEView *view);`
    ///
    /// The view's accessibility object. Borrowed pointer
    /// (transfer=none per GIR) - owned by the view, do not unref. May be NULL
    /// if the platform has no a11y implementation; on this host the headless
    /// view returns a live `WPEViewAccessibleAtk` (an `AtkSocket`), verified
    /// empirically - see `ffi/a11y.rs`.
    ///
    /// Source: `/usr/include/wpe-webkit-2.0/wpe-platform/wpe/WPEView.h:157`
    /// GIR:    `/usr/share/gir-1.0/WPEPlatform-2.0.gir` (`wpe_view_get_accessible`)
    pub fn wpe_view_get_accessible(view: *mut WPEView) -> *mut WPEViewAccessible;

    /// `GType wpe_view_accessible_get_type (void);`
    ///
    /// The `WPEViewAccessible` interface GType, needed to look up its
    /// vtable on a concrete implementation via `g_type_interface_peek`.
    ///
    /// Source: `/usr/include/wpe-webkit-2.0/wpe-platform/wpe/WPEViewAccessible.h`
    pub fn wpe_view_accessible_get_type() -> GType;

    /// `gpointer g_type_class_peek (GType type);`
    ///
    /// The already-initialised class structure for `type`, or NULL if it has
    /// not been referenced yet. "Peek" does not take a reference and does
    /// not instantiate the class, so there is nothing to release.
    ///
    /// Source: `/usr/include/glib-2.0/gobject/gtype.h`
    pub fn g_type_class_peek(g_type: GType) -> *mut c_void;

    /// `gpointer g_type_interface_peek (gpointer instance_class, GType iface_type);`
    ///
    /// The `iface_type` vtable belonging to `instance_class`, or NULL if the
    /// class does not implement that interface. Borrowed - no reference taken.
    ///
    /// Source: `/usr/include/glib-2.0/gobject/gtype.h`
    pub fn g_type_interface_peek(
        instance_class: *mut c_void,
        iface_type: GType,
    ) -> *mut WPEViewAccessibleInterface;

    /// `void wpe_event_unref (WPEEvent *event);`
    ///
    /// Drops one reference to a `WPEEvent`.
    ///
    /// Source: `/usr/include/wpe-webkit-2.0/wpe-platform/wpe/WPEEvent.h`
    pub fn wpe_event_unref(event: *mut WPEEvent);

    /// `WPEEvent *wpe_event_pointer_button_new (WPEEventType type, WPEView *view,
    ///     WPEInputSource source, guint32 time, WPEModifiers modifiers,
    ///     guint button, double x, double y, guint press_count);`
    ///
    /// Constructs a pointer button-down/up event. `x`/`y` are in the view's
    /// logical coordinate space (top-left origin; page zoom included, the
    /// output/device scale `wpe_view_get_scale` applied inside WebKit, not
    /// here) - which is exactly what the `ViewportMapping::to_view` produces.
    /// Verified against WPE 2.52.5 `WebEventFactoryWPE`/`WPEWaylandSeat`, which
    /// forward `wpe_event_get_position` / `wl_fixed_to_double` unscaled.
    /// `press_count` must be non-zero
    /// for `WPE_EVENT_POINTER_DOWN` and zero for `WPE_EVENT_POINTER_UP` (WPE
    /// asserts `!press_count || type == WPE_EVENT_POINTER_DOWN`). Returns a
    /// new ref-counted event.
    ///
    /// Source: `/usr/include/wpe-webkit-2.0/wpe-platform/wpe/WPEEvent.h`
    pub fn wpe_event_pointer_button_new(
        event_type: c_int,
        view: *mut WPEView,
        source: c_int,
        time: u32,
        modifiers: c_uint,
        button: c_uint,
        x: f64,
        y: f64,
        press_count: c_uint,
    ) -> *mut WPEEvent;

    /// `WPEEvent *wpe_event_pointer_move_new (WPEEventType type, WPEView *view,
    ///     WPEInputSource source, guint32 time, WPEModifiers modifiers,
    ///     double x, double y, double delta_x, double delta_y);`
    ///
    /// Source: `/usr/include/wpe-webkit-2.0/wpe-platform/wpe/WPEEvent.h`
    pub fn wpe_event_pointer_move_new(
        event_type: c_int,
        view: *mut WPEView,
        source: c_int,
        time: u32,
        modifiers: c_uint,
        x: f64,
        y: f64,
        delta_x: f64,
        delta_y: f64,
    ) -> *mut WPEEvent;

    /// `WPEEvent *wpe_event_scroll_new (WPEView *view, WPEInputSource source,
    ///     guint32 time, WPEModifiers modifiers, double delta_x, double delta_y,
    ///     gboolean precise_deltas, gboolean is_stop, double x, double y);`
    ///
    /// Note the argument order differs from the pointer/keyboard constructors:
    /// `view` comes first, there is no `WPEEventType` (a scroll is always
    /// `WPE_EVENT_SCROLL`), and `x`/`y` (the pointer position at scroll time)
    /// come LAST. `precise_deltas` = TRUE means the deltas are pixels rather
    /// than discrete wheel notches.
    ///
    /// Source: `/usr/include/wpe-webkit-2.0/wpe-platform/wpe/WPEEvent.h`
    pub fn wpe_event_scroll_new(
        view: *mut WPEView,
        source: c_int,
        time: u32,
        modifiers: c_uint,
        delta_x: f64,
        delta_y: f64,
        precise_deltas: GBoolean,
        is_stop: GBoolean,
        x: f64,
        y: f64,
    ) -> *mut WPEEvent;

    /// `WPEEvent *wpe_event_keyboard_new (WPEEventType type, WPEView *view,
    ///     WPEInputSource source, guint32 time, WPEModifiers modifiers,
    ///     guint keycode, guint keyval);`
    ///
    /// `keycode` is the hardware scancode in XKB space (evdev code + 8 on
    /// Linux). `keyval` is the resolved keysym (e.g. `XKB_KEY_space`). WebKit
    /// uses `keyval` to route the key to the page.
    ///
    /// Source: `/usr/include/wpe-webkit-2.0/wpe-platform/wpe/WPEEvent.h`
    pub fn wpe_event_keyboard_new(
        event_type: c_int,
        view: *mut WPEView,
        source: c_int,
        time: u32,
        modifiers: c_uint,
        keycode: c_uint,
        keyval: c_uint,
    ) -> *mut WPEEvent;

    /// `WPEEvent *wpe_event_touch_new (WPEEventType type, WPEView *view,
    ///     WPEInputSource source, guint32 time, WPEModifiers modifiers,
    ///     guint32 sequence_id, double x, double y);`
    ///
    /// A single touch point. `sequence_id` identifies the finger across a
    /// down → move* → up sequence (WebKit correlates them into one touch); a
    /// fixed id serves for a single-finger tap/drag. `x`/`y` are logical
    /// view coordinates (the same space pointer events use; output scale is
    /// applied inside WebKit, not here). `type` is one of the
    /// `WPE_EVENT_TOUCH_*` values.
    ///
    /// Source: `/usr/include/wpe-webkit-2.0/wpe-platform/wpe/WPEEvent.h`
    pub fn wpe_event_touch_new(
        event_type: c_int,
        view: *mut WPEView,
        source: c_int,
        time: u32,
        modifiers: c_uint,
        sequence_id: u32,
        x: f64,
        y: f64,
    ) -> *mut WPEEvent;
}

// ---------------------------------------------------------------------------
// WPE input enum values, mirrored as constants. The numeric
// values are the C enum declaration order in `WPEEvent.h`; each cites its
// position there.
// ---------------------------------------------------------------------------

/// `WPE_EVENT_POINTER_DOWN` = 1 (enum position in `WPEEventType`).
pub const WPE_EVENT_POINTER_DOWN: c_int = 1;
/// `WPE_EVENT_POINTER_UP` = 2.
pub const WPE_EVENT_POINTER_UP: c_int = 2;
/// `WPE_EVENT_POINTER_MOVE` = 3.
pub const WPE_EVENT_POINTER_MOVE: c_int = 3;
/// `WPE_EVENT_POINTER_LEAVE` = 5 (after `WPE_EVENT_POINTER_ENTER` = 4).
pub const WPE_EVENT_POINTER_LEAVE: c_int = 5;
/// `WPE_EVENT_SCROLL` = 6.
pub const WPE_EVENT_SCROLL: c_int = 6;
/// `WPE_EVENT_KEYBOARD_KEY_DOWN` = 7.
pub const WPE_EVENT_KEYBOARD_KEY_DOWN: c_int = 7;
/// `WPE_EVENT_KEYBOARD_KEY_UP` = 8.
pub const WPE_EVENT_KEYBOARD_KEY_UP: c_int = 8;
/// `WPE_EVENT_TOUCH_DOWN` = 9 (follows the two keyboard values in the enum).
pub const WPE_EVENT_TOUCH_DOWN: c_int = 9;
/// `WPE_EVENT_TOUCH_UP` = 10.
pub const WPE_EVENT_TOUCH_UP: c_int = 10;
/// `WPE_EVENT_TOUCH_MOVE` = 11.
pub const WPE_EVENT_TOUCH_MOVE: c_int = 11;

/// `WPE_INPUT_SOURCE_MOUSE` = 0 (enum position in `WPEInputSource`).
pub const WPE_INPUT_SOURCE_MOUSE: c_int = 0;
/// `WPE_INPUT_SOURCE_KEYBOARD` = 2.
pub const WPE_INPUT_SOURCE_KEYBOARD: c_int = 2;
/// `WPE_INPUT_SOURCE_TOUCHSCREEN` = 3 (MOUSE=0, PEN=1, KEYBOARD=2,
/// TOUCHSCREEN=3 in `WPEInputSource`).
pub const WPE_INPUT_SOURCE_TOUCHSCREEN: c_int = 3;

/// No modifier keys held. `WPEModifiers` is a flag bitset; 0 means "none".
///
/// Source: `/usr/include/wpe-webkit-2.0/wpe-platform/wpe/WPEEvent.h`
pub const WPE_MODIFIER_NONE: c_uint = 0;

/// `WPE_MODIFIER_KEYBOARD_CONTROL = 1 << 0`.
///
/// Source: `/usr/include/wpe-webkit-2.0/wpe-platform/wpe/WPEEvent.h`
pub const WPE_MODIFIER_KEYBOARD_CONTROL: c_uint = 1 << 0;
/// `WPE_MODIFIER_KEYBOARD_SHIFT = 1 << 1`.
pub const WPE_MODIFIER_KEYBOARD_SHIFT: c_uint = 1 << 1;
/// `WPE_MODIFIER_KEYBOARD_ALT = 1 << 2`.
pub const WPE_MODIFIER_KEYBOARD_ALT: c_uint = 1 << 2;
/// `WPE_MODIFIER_KEYBOARD_META = 1 << 3`.
pub const WPE_MODIFIER_KEYBOARD_META: c_uint = 1 << 3;
/// Primary pointer button held.
pub const WPE_MODIFIER_POINTER_BUTTON1: c_uint = 1 << 8;
/// Middle pointer button held.
pub const WPE_MODIFIER_POINTER_BUTTON2: c_uint = 1 << 9;
/// Secondary pointer button held.
pub const WPE_MODIFIER_POINTER_BUTTON3: c_uint = 1 << 10;
/// Fourth pointer button held.
pub const WPE_MODIFIER_POINTER_BUTTON4: c_uint = 1 << 11;
/// Fifth pointer button held.
pub const WPE_MODIFIER_POINTER_BUTTON5: c_uint = 1 << 12;

/// `WPE_EVENT_TOUCH_CANCEL = 12` (enum position: TOUCH_DOWN=9, TOUCH_UP=10,
/// TOUCH_MOVE=11, TOUCH_CANCEL=12).
///
/// Source: `/usr/include/wpe-webkit-2.0/wpe-platform/wpe/WPEEvent.h`
pub const WPE_EVENT_TOUCH_CANCEL: c_int = 12;

/// The WPE button code for the primary (left) mouse button.
///
/// WPE uses 1-based button numbers matching the kernel `BTN_*` convention
/// exposed via libinput: 1 = left, 2 = middle, 3 = right.
///
/// Source: `/usr/include/wpe-webkit-2.0/wpe-platform/wpe/WPEEvent.h` (button
///         parameter of `wpe_event_pointer_button_new`).
pub const WPE_BUTTON_PRIMARY: c_uint = 1;
/// Middle mouse button.
pub const WPE_BUTTON_MIDDLE: c_uint = 2;
/// Secondary (right) mouse button.
pub const WPE_BUTTON_SECONDARY: c_uint = 3;

/// XKB keysym for the space bar (`XKB_KEY_space` = 0x0020).
///
/// Source: `/usr/include/xkbcommon/xkbcommon-keysyms.h`
pub const XKB_KEY_SPACE: c_uint = 0x0020;

/// Hardware scancode for the space bar in XKB space: evdev `KEY_SPACE` (57)
/// plus the conventional +8 offset from evdev to XKB.
///
/// Source: `/usr/include/linux/input-event-codes.h` (`KEY_SPACE` = 57).
pub const XKB_SCANCODE_SPACE: c_uint = 57 + 8;

// ---------------------------------------------------------------------------
// WebKit enum values, mirrored as constants so the FFI stays typed-int-clean.
// ---------------------------------------------------------------------------

/// `WEBKIT_SNAPSHOT_REGION_VISIBLE` - snapshot only the visible viewport.
///
/// Source: `/usr/include/wpe-webkit-2.0/wpe/WebKitWebView.h`
pub const WEBKIT_SNAPSHOT_REGION_VISIBLE: c_int = 0;

/// `WEBKIT_SNAPSHOT_OPTIONS_NONE` - no special options.
///
/// Source: `/usr/include/wpe-webkit-2.0/wpe/WebKitWebView.h`
pub const WEBKIT_SNAPSHOT_OPTIONS_NONE: c_uint = 0;

/// `WEBKIT_SNAPSHOT_OPTIONS_INCLUDE_SELECTION_HIGHLIGHTING` = `1 << 0` -
/// paint the page's text selection into the snapshot.
///
/// Source: `/usr/include/wpe-webkit-2.0/wpe/WebKitWebView.h`
pub const WEBKIT_SNAPSHOT_OPTIONS_INCLUDE_SELECTION_HIGHLIGHTING: c_uint = 1 << 0;

/// `WEBKIT_LOAD_FINISHED` = 3 - the terminal `WebKitLoadEvent` value emitted
/// on `load-changed` when the page has finished loading.
///
/// Source: `/usr/include/wpe-webkit-2.0/wpe/WebKitWebView.h`
pub const WEBKIT_LOAD_FINISHED: c_int = 3;

/// A new main-resource navigation has started.
pub const WEBKIT_LOAD_STARTED: c_int = 0;

/// glib boolean constants.
pub const G_FALSE: GBoolean = 0;
/// glib boolean constants.
pub const G_TRUE: GBoolean = 1;

/// `WEBKIT_COOKIE_PERSISTENT_STORAGE_SQLITE` = 1 - persist cookies to a SQLite
/// file. Value 0 is `_TEXT`. A persistent session does not enable persistent
/// cookie storage automatically (established empirically); it must be
/// switched on with `webkit_cookie_manager_set_persistent_storage`.
///
/// Source: `/usr/include/wpe-webkit-2.0/wpe/WebKitCookieManager.h`
pub const WEBKIT_COOKIE_PERSISTENT_STORAGE_SQLITE: c_int = 1;

// ---------------------------------------------------------------------------
// Profile / storage isolation - network sessions & cookies.
//
// A `WebKitNetworkSession` is the storage boundary. Cookies go in via
// `webkit_cookie_manager_add_cookie` and come back via `..._get_cookies`, both
// async (GAsyncReadyCallback + a `_finish`), so each is driven on a bounded
// GMainLoop exactly like the snapshot path. `SoupCookie` is libsoup's value
// type, already linked via `-lsoup-3.0`.
// ---------------------------------------------------------------------------

unsafe extern "C" {
    /// `WebKitNetworkSession *webkit_network_session_new (const char *data_directory, const char *cache_directory);`
    ///
    /// A persistent session whose storage lives under the given
    /// directories. Ref-count 1 (transfer=full) - unref when done.
    ///
    /// Source: `/usr/include/wpe-webkit-2.0/wpe/WebKitNetworkSession.h`
    pub fn webkit_network_session_new(
        data_directory: *const c_char,
        cache_directory: *const c_char,
    ) -> *mut WebKitNetworkSession;

    /// `WebKitNetworkSession *webkit_network_session_new_ephemeral (void);`
    ///
    /// An ephemeral session: all storage in memory, nothing on disk.
    /// Ref-count 1 - unref when done.
    ///
    /// Source: `/usr/include/wpe-webkit-2.0/wpe/WebKitNetworkSession.h`
    pub fn webkit_network_session_new_ephemeral() -> *mut WebKitNetworkSession;

    /// `gboolean webkit_network_session_is_ephemeral (WebKitNetworkSession *session);`
    ///
    /// Source: `/usr/include/wpe-webkit-2.0/wpe/WebKitNetworkSession.h`
    pub fn webkit_network_session_is_ephemeral(session: *mut WebKitNetworkSession) -> GBoolean;

    /// `WebKitCookieManager *webkit_network_session_get_cookie_manager (WebKitNetworkSession *session);`
    ///
    /// Borrowed - owned by the session, never unref'd.
    ///
    /// Source: `/usr/include/wpe-webkit-2.0/wpe/WebKitNetworkSession.h`
    pub fn webkit_network_session_get_cookie_manager(
        session: *mut WebKitNetworkSession,
    ) -> *mut WebKitCookieManager;

    /// `void webkit_cookie_manager_set_persistent_storage (WebKitCookieManager*, const char *filename, WebKitCookiePersistentStorage storage);`
    ///
    /// Switches on persistent cookie storage at `filename`. Required for a
    /// persistent session to survive across process/session lifetimes - the
    /// data directory alone does not enable it (as established by the native profile probe).
    ///
    /// Source: `/usr/include/wpe-webkit-2.0/wpe/WebKitCookieManager.h`
    pub fn webkit_cookie_manager_set_persistent_storage(
        cookie_manager: *mut WebKitCookieManager,
        filename: *const c_char,
        storage: c_int,
    );

    /// `void webkit_cookie_manager_add_cookie (WebKitCookieManager*, SoupCookie*, GCancellable*, GAsyncReadyCallback, gpointer);`
    ///
    /// Adds a cookie (copies it - caller keeps ownership of the `SoupCookie`).
    /// Completion is delivered to the callback; pair with
    /// `webkit_cookie_manager_add_cookie_finish`.
    ///
    /// Source: `/usr/include/wpe-webkit-2.0/wpe/WebKitCookieManager.h`
    pub fn webkit_cookie_manager_add_cookie(
        cookie_manager: *mut WebKitCookieManager,
        cookie: *mut SoupCookie,
        cancellable: *mut c_void,
        callback: extern "C" fn(*mut c_void, *mut GAsyncResult, *mut c_void),
        user_data: *mut c_void,
    );

    /// `gboolean webkit_cookie_manager_add_cookie_finish (WebKitCookieManager*, GAsyncResult*, GError);`
    ///
    /// Source: `/usr/include/wpe-webkit-2.0/wpe/WebKitCookieManager.h`
    pub fn webkit_cookie_manager_add_cookie_finish(
        cookie_manager: *mut WebKitCookieManager,
        result: *mut GAsyncResult,
        error: *mut *mut GError,
    ) -> GBoolean;

    /// `void webkit_cookie_manager_get_cookies (WebKitCookieManager*, const gchar *uri, GCancellable*, GAsyncReadyCallback, gpointer);`
    ///
    /// Queries the cookies visible to `uri`. Pair with
    /// `webkit_cookie_manager_get_cookies_finish`.
    ///
    /// Source: `/usr/include/wpe-webkit-2.0/wpe/WebKitCookieManager.h`
    pub fn webkit_cookie_manager_get_cookies(
        cookie_manager: *mut WebKitCookieManager,
        uri: *const c_char,
        cancellable: *mut c_void,
        callback: extern "C" fn(*mut c_void, *mut GAsyncResult, *mut c_void),
        user_data: *mut c_void,
    );

    /// `GList *webkit_cookie_manager_get_cookies_finish (WebKitCookieManager*, GAsyncResult*, GError);`
    ///
    /// Returns a `GList` of `SoupCookie*` - transfer=full: free each
    /// cookie with `soup_cookie_free` and the list with `g_list_free`.
    ///
    /// Source: `/usr/include/wpe-webkit-2.0/wpe/WebKitCookieManager.h`
    pub fn webkit_cookie_manager_get_cookies_finish(
        cookie_manager: *mut WebKitCookieManager,
        result: *mut GAsyncResult,
        error: *mut *mut GError,
    ) -> *mut GList;

    /// `SoupCookie *soup_cookie_new (const char *name, const char *value, const char *domain, const char *path, int max_age);`
    ///
    /// `max_age > 0` makes a persistent cookie; ref-count/ownership is the
    /// caller's (free with `soup_cookie_free`).
    ///
    /// Source: `/usr/include/libsoup-3.0/libsoup/soup-cookie.h`
    pub fn soup_cookie_new(
        name: *const c_char,
        value: *const c_char,
        domain: *const c_char,
        path: *const c_char,
        max_age: c_int,
    ) -> *mut SoupCookie;

    /// `const char *soup_cookie_get_name (SoupCookie *cookie);`
    ///
    /// Borrowed - valid until the cookie is freed.
    ///
    /// Source: `/usr/include/libsoup-3.0/libsoup/soup-cookie.h`
    pub fn soup_cookie_get_name(cookie: *mut SoupCookie) -> *const c_char;

    /// `const char *soup_cookie_get_value (SoupCookie *cookie);`
    ///
    /// Borrowed - valid until the cookie is freed.
    ///
    /// Source: `/usr/include/libsoup-3.0/libsoup/soup-cookie.h`
    pub fn soup_cookie_get_value(cookie: *mut SoupCookie) -> *const c_char;

    /// `void soup_cookie_free (SoupCookie *cookie);`
    ///
    /// Source: `/usr/include/libsoup-3.0/libsoup/soup-cookie.h`
    pub fn soup_cookie_free(cookie: *mut SoupCookie);

    /// `void g_list_free (GList *list);`
    ///
    /// Frees the list nodes (not the elements - those this code frees with
    /// `soup_cookie_free` first).
    ///
    /// Source: `/usr/include/glib-2.0/glib/glist.h`
    pub fn g_list_free(list: *mut GList);
}

// ---------------------------------------------------------------------------
// The input-method seam: registering a WebKitInputMethodContext
// subclass, reading the field's purpose, and emitting compositions into the
// page.
// ---------------------------------------------------------------------------

unsafe extern "C" {
    /// `void g_type_query (GType type, GTypeQuery *query);`
    ///
    /// The ABI-safe way to learn a type's real class/instance sizes so a
    /// subclass can be registered without hardcoding a `sizeof` the header does
    /// not expose.
    ///
    /// Source: `/usr/include/glib-2.0/gobject/gtype.h`
    pub fn g_type_query(g_type: GType, query: *mut GTypeQuery);

    /// `GType g_type_register_static_simple (GType parent_type, const gchar *type_name,
    /// guint class_size, GClassInitFunc class_init, guint instance_size,
    /// GInstanceInitFunc instance_init, GTypeFlags flags);`
    ///
    /// Registers the IME context subclass. `class_init` is where the vfunc
    /// slots are overwritten; `instance_init` is NULL because per-instance
    /// state is kept in a pointer-keyed side table rather than in the instance
    /// struct (no instance-size arithmetic, no private-offset guessing).
    ///
    /// Source: `/usr/include/glib-2.0/gobject/gtype.h`
    pub fn g_type_register_static_simple(
        parent_type: GType,
        type_name: *const c_char,
        class_size: c_uint,
        class_init: Option<extern "C" fn(*mut c_void, *mut c_void)>,
        instance_size: c_uint,
        instance_init: Option<extern "C" fn(*mut c_void, *mut c_void)>,
        flags: c_uint,
    ) -> GType;

    /// `GType g_type_from_name (const gchar *name);`
    ///
    /// Returns 0 when the name is unregistered. Used for idempotency: a second
    /// registration of the same name is a glib critical, so the name is
    /// looked up first.
    ///
    /// Source: `/usr/include/glib-2.0/gobject/gtype.h`
    pub fn g_type_from_name(name: *const c_char) -> GType;

    /// `guint g_signal_lookup (const gchar *name, GType itype);`
    ///
    /// Resolves a signal name to its id so `g_signal_emitv` can be used
    /// instead of the variadic `g_signal_emit_by_name`. A zero result means the
    /// signal does not exist on that type - a typo caught immediately rather
    /// than a silently dropped emission.
    ///
    /// Source: `/usr/include/glib-2.0/gobject/gsignal.h`
    pub fn g_signal_lookup(name: *const c_char, itype: GType) -> c_uint;

    /// `void g_signal_emitv (const GValue *instance_and_params, guint signal_id,
    /// GQuark detail, GValue *return_value);`
    ///
    /// The non-variadic emission entry point: `instance_and_params[0]` is the
    /// instance, the rest are the signal's declared arguments.
    ///
    /// Source: `/usr/include/glib-2.0/gobject/gsignal.h`
    pub fn g_signal_emitv(
        instance_and_params: *const GValue,
        signal_id: c_uint,
        detail: u32,
        return_value: *mut GValue,
    );

    /// `void g_value_set_string (GValue *value, const gchar *v_string);`
    ///
    /// Copies the string into the value; the caller keeps ownership of its own
    /// buffer.
    ///
    /// Source: `/usr/include/glib-2.0/gobject/gvaluetypes.h`
    pub fn g_value_set_string(value: *mut GValue, v_string: *const c_char);

    /// `void g_value_set_int (GValue *value, gint v_int);`
    ///
    /// Source: `/usr/include/glib-2.0/gobject/gvaluetypes.h`
    pub fn g_value_set_int(value: *mut GValue, v_int: c_int);

    /// `void g_value_set_uint (GValue *value, guint v_uint);`
    ///
    /// Source: `/usr/include/glib-2.0/gobject/gvaluetypes.h`
    pub fn g_value_set_uint(value: *mut GValue, v_uint: c_uint);

    /// `void g_value_set_instance (GValue *value, gpointer instance);`
    ///
    /// Sets the instance slot of an emission array without needing the object's
    /// GType at the call site.
    ///
    /// Source: `/usr/include/glib-2.0/gobject/gvalue.h`
    pub fn g_value_set_instance(value: *mut GValue, instance: *mut c_void);

    /// `gchar *g_strdup (const gchar *str);`
    ///
    /// Needed because `get_preedit` hands WebKit a string it will `g_free`, so
    /// the buffer must come from glib's allocator, not Rust's.
    ///
    /// Source: `/usr/include/glib-2.0/glib/gstrfuncs.h`
    pub fn g_strdup(str_: *const c_char) -> *mut c_char;

    /// `GType webkit_input_method_context_get_type (void);`
    ///
    /// Source: `/usr/include/wpe-webkit-2.0/wpe/WebKitInputMethodContext.h`
    pub fn webkit_input_method_context_get_type() -> GType;

    /// `WebKitInputPurpose webkit_input_method_context_get_input_purpose
    /// (WebKitInputMethodContext *context);`
    ///
    /// WebKit sets this property on the context when an editable element is
    /// focused, so reading it back is how the page's input purpose (password vs
    /// free-form) reaches the host. Returned as the raw enum value; the mapping
    /// into iced's vocabulary is
    /// [`purpose_from_webkit`](crate::web::purpose_from_webkit).
    ///
    /// Source: `/usr/include/wpe-webkit-2.0/wpe/WebKitInputMethodContext.h`
    pub fn webkit_input_method_context_get_input_purpose(
        context: *mut WebKitInputMethodContext,
    ) -> c_int;

    /// `WebKitInputHints webkit_input_method_context_get_input_hints
    /// (WebKitInputMethodContext *context);`
    ///
    /// Source: `/usr/include/wpe-webkit-2.0/wpe/WebKitInputMethodContext.h`
    pub fn webkit_input_method_context_get_input_hints(
        context: *mut WebKitInputMethodContext,
    ) -> c_uint;

    /// `void webkit_web_view_set_input_method_context (WebKitWebView *web_view,
    /// WebKitInputMethodContext *context);`
    ///
    /// Installs the context on the view. Passing NULL detaches it, which is
    /// what teardown does before the context is unref'd so WebKit cannot
    /// call a vfunc on a freed object.
    ///
    /// Source: `/usr/include/wpe-webkit-2.0/wpe/WebKitWebView.h`
    pub fn webkit_web_view_set_input_method_context(
        web_view: *mut WebKitWebView,
        context: *mut WebKitInputMethodContext,
    );

    /// `WebKitInputMethodContext *webkit_web_view_get_input_method_context
    /// (WebKitWebView *web_view);`
    ///
    /// Borrowed. Read back after installation so a failed set is a typed error
    /// rather than a silently IME-less view.
    ///
    /// Source: `/usr/include/wpe-webkit-2.0/wpe/WebKitWebView.h`
    pub fn webkit_web_view_get_input_method_context(
        web_view: *mut WebKitWebView,
    ) -> *mut WebKitInputMethodContext;

    /// `const gchar *webkit_web_view_get_title (WebKitWebView *web_view);`
    ///
    /// Borrowed, owned by the view. The IME gate uses it as the page's own
    /// report channel: the test page assigns `document.title` from the focused
    /// input's `value`/`selectionStart`, so this getter observes the DOM
    /// after a commit rather than an internal Rust field.
    ///
    /// Source: `/usr/include/wpe-webkit-2.0/wpe/WebKitWebView.h`
    pub fn webkit_web_view_get_title(web_view: *mut WebKitWebView) -> *const c_char;

    /// `void wpe_view_focus_in (WPEView *view);`
    ///
    /// Marks the view keyboard-focused. WebKit's `InputMethodFilter` only
    /// becomes active for a focused view, so without this a focused DOM input
    /// reports no caret area at all.
    ///
    /// Source: `/usr/include/wpe-webkit-2.0/wpe-platform/wpe/WPEView.h`
    pub fn wpe_view_focus_in(view: *mut WPEView);

    /// `void wpe_view_focus_out (WPEView *view);`
    ///
    /// Source: `/usr/include/wpe-webkit-2.0/wpe-platform/wpe/WPEView.h`
    pub fn wpe_view_focus_out(view: *mut WPEView);

    /// `gboolean wpe_view_get_has_focus (WPEView *view);`
    ///
    /// Source: `/usr/include/wpe-webkit-2.0/wpe-platform/wpe/WPEView.h`
    pub fn wpe_view_get_has_focus(view: *mut WPEView) -> GBoolean;

    /// `gdouble wpe_view_get_scale (WPEView *view);`
    ///
    /// The view's output/device scale factor. Read-only: WPEPlatform
    /// exposes no `wpe_view_set_scale`; the value *follows* the view's
    /// toplevel/screen scale. On the headless platform there is no screen, so
    /// it defaults to 1; a non-1 value is reached by driving the toplevel (see
    /// [`wpe_toplevel_scale_changed`]). This scale does not appear in the
    /// IME caret callback - WebKit reports the caret in logical root-view
    /// pixels (see [`crate::input::ViewportMapping::to_window_rect`]).
    ///
    /// Source: `/usr/include/wpe-webkit-2.0/wpe-platform/wpe/WPEView.h:108`
    pub fn wpe_view_get_scale(view: *mut WPEView) -> f64;

    /// `WPEToplevel *wpe_view_get_toplevel (WPEView *view);`
    ///
    /// Borrowed - owned by the view, do not unref. NULL if the view has no
    /// toplevel yet.
    ///
    /// Source: `/usr/include/wpe-webkit-2.0/wpe-platform/wpe/WPEView.h:99`
    pub fn wpe_view_get_toplevel(view: *mut WPEView) -> *mut WPEToplevel;

    /// `void wpe_toplevel_get_size (WPEToplevel *toplevel, int *width, int *height);`
    ///
    /// Reads the current logical size of `toplevel`. Either out pointer may be
    /// NULL; both are written here so a caller can compare an intended request
    /// against WPE's actual current size before crossing the resize ABI.
    ///
    /// Source: `/usr/include/wpe-webkit-2.0/wpe-platform/wpe/WPEToplevel.h:106`
    /// and installed `WPEPlatform-2.0.gir` (`Toplevel.get_size`).
    pub fn wpe_toplevel_get_size(toplevel: *mut WPEToplevel, width: *mut c_int, height: *mut c_int);

    /// `gboolean wpe_toplevel_resize (WPEToplevel *toplevel, gint width, gint height);`
    ///
    /// Requests a new size in logical coordinates. WPE 2.52 returns %TRUE only
    /// when resizing is supported AND the requested dimensions differ from the
    /// current size, and %FALSE otherwise - so an equal-size request and a
    /// backend that refuses resize are the same C return value. A caller
    /// that wants to tell the two apart must read [`wpe_toplevel_get_size`]
    /// first and only invoke this when the dimensions actually differ.
    ///
    /// Source: `/usr/include/wpe-webkit-2.0/wpe-platform/wpe/WPEToplevel.h:109`
    /// and installed `WPEPlatform-2.0.gir` (`Toplevel.resize`).
    pub fn wpe_toplevel_resize(toplevel: *mut WPEToplevel, width: c_int, height: c_int)
    -> GBoolean;

    /// `void wpe_toplevel_scale_changed (WPEToplevel *toplevel, gdouble scale);`
    ///
    /// The entry point a platform backend calls when the output scale changes;
    /// it updates the toplevel and propagates to `WPEView:scale`. WPE's API docs
    /// restrict it to `WPEToplevel` derived classes in platform implementations.
    /// The doc-hidden coordinate-space test lever uses it only because the
    /// headless platform exposes no scaled screen of its own.
    ///
    /// Source: `/usr/include/wpe-webkit-2.0/wpe-platform/wpe/WPEToplevel.h:119`
    /// and installed `WPEPlatform-2.0.gir` (`Toplevel.scale_changed`).
    pub fn wpe_toplevel_scale_changed(toplevel: *mut WPEToplevel, scale: f64);

    /// `void webkit_web_view_set_zoom_level (WebKitWebView *web_view, gdouble zoom_level);`
    ///
    /// Page zoom: it multiplies CSS pixels into the view's own pixel space
    /// without changing the view's size, which is exactly the lever needed to
    /// tell "the caret rect is in CSS pixels" from "the caret rect is in view
    /// pixels".
    ///
    /// Source: `/usr/include/wpe-webkit-2.0/wpe/WebKitWebView.h:495`
    pub fn webkit_web_view_set_zoom_level(web_view: *mut WebKitWebView, zoom_level: f64);

    /// `gdouble webkit_web_view_get_zoom_level (WebKitWebView *web_view);`
    ///
    /// Source: `/usr/include/wpe-webkit-2.0/wpe/WebKitWebView.h`
    pub fn webkit_web_view_get_zoom_level(web_view: *mut WebKitWebView) -> f64;
}

unsafe extern "C" {
    /// Source: WPE WebKitWebView.h; the returned certificate is borrowed from the view.
    pub fn webkit_web_view_get_tls_info(
        view: *mut WebKitWebView,
        certificate: *mut *mut GTlsCertificate,
        errors: *mut u32,
    ) -> GBoolean;
    /// Source: gio/gtlscertificate.h; the caller owns the returned GLib string.
    pub fn g_tls_certificate_get_subject_name(certificate: *mut GTlsCertificate) -> *mut c_char;
    /// Source: gio/gtlscertificate.h; the caller owns the returned GLib string.
    pub fn g_tls_certificate_get_issuer_name(certificate: *mut GTlsCertificate) -> *mut c_char;
}

unsafe extern "C" {
    /// Source: glib/gobject/gobject.h; returns borrowed object-associated data.
    pub fn g_object_get_data(object: *mut c_void, key: *const c_char) -> *mut c_void;
    /// Source: glib/gmain.h; owns data until the source's destroy callback.
    pub fn g_timeout_add_full(
        priority: c_int,
        interval: c_uint,
        callback: Option<extern "C" fn(*mut c_void) -> GBoolean>,
        data: *mut c_void,
        destroy: Option<extern "C" fn(*mut c_void)>,
    ) -> c_uint;
    /// Source: WPE WebKitWebView.h; NONE (0) ends camera capture in this view.
    pub fn webkit_web_view_set_camera_capture_state(view: *mut WebKitWebView, state: c_int);
    /// Source: WPE WebKitWebView.h; NONE (0) ends microphone capture in this view.
    pub fn webkit_web_view_set_microphone_capture_state(view: *mut WebKitWebView, state: c_int);
}
