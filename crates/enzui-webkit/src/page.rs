//! What a page tells its host, and how the host answers.
//!
//! The policy layer decides what a page may *reach*. This module is the rest
//! of the conversation: load progress, the address and title, a sign-in
//! callback the host captured, a popup the page asked for, a script dialog, a
//! file chooser, an HTTP authentication challenge, script results and
//! messages, and find-in-page counts. A WPE `WebSession` queues these as
//! [`PageEvent`]s, bounded, and the host drains them after pumping.
//!
//! Requests that wait for the host (dialogs, file choosers, authentication)
//! are answered only when the host opted in through [`PagePrompts`]. Without
//! that, the engine declines at once, as a browser with no UI would: an alert
//! is closed, a confirm is false, a prompt is cancelled, a file chooser
//! selects nothing, and a challenge is cancelled. A page can never hang
//! waiting for a host that does not listen.
//!
//! Everything here is plain data and compiles without the `wpe` feature.

use std::fmt;

use crate::web::policy::PolicyUrl;
use enzui_security::secret::SecretText;

/// The most events a session queues before evicting the oldest notification
/// that does not advertise a live prompt. Held dialogs, choosers, authentication
/// challenges and option menus retain their answer IDs until drained or retired.
pub const PAGE_EVENT_CAPACITY: usize = 256;

/// The most prompts of one kind that may wait for the host at once; another
/// is declined.
pub const MAX_PENDING_PROMPTS: usize = 4;

/// The most redirect URIs one session captures.
pub const MAX_REDIRECT_CAPTURES: usize = 8;

/// The per-string ceiling for page-supplied text retained in native events.
pub const MAX_PAGE_TEXT_BYTES: usize = 64 * 1024;

/// The most entries a native option menu may expose to the host.
pub const MAX_OPTION_MENU_ITEMS: usize = 4096;

/// The combined label and tooltip bytes retained in one option menu event.
pub const MAX_OPTION_MENU_TEXT_BYTES: usize = 256 * 1024;

/// Correlates a waiting prompt, a script evaluation or a data-clear request
/// with its answer. Session-minted IDs do not repeat within the host process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PageRequestId(u64);

impl PageRequestId {
    /// Wraps a raw id. Sessions mint their own; this exists for hosts that
    /// persist or route ids.
    #[must_use]
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// The raw id.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// A stage of a main-frame load, as WebKit reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadStage {
    /// A load began.
    Started,
    /// The server redirected the load.
    Redirected,
    /// The first response arrived and the page is now this document.
    Committed,
    /// The load ended, successfully or not.
    Finished,
}

/// The navigation an embedded view stopped because it was a registered
/// redirect URI. The URL carries the authorization code and `state`, so it
/// is a secret and its formatting is redacted.
#[derive(Clone, PartialEq, Eq)]
pub struct CapturedRedirect {
    /// The full callback URL, for
    /// `enzui_services::oauth::PendingAuthorization::complete`.
    pub url: SecretText,
    /// Whether the page reached it from a person's gesture rather than a
    /// script or a server redirect.
    pub user_initiated: bool,
    /// Whether it arrived as a server redirect.
    pub redirect: bool,
    /// Whether the page tried to open it in a new window.
    pub popup: bool,
}

impl fmt::Debug for CapturedRedirect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CapturedRedirect")
            .field("url", &self.url)
            .field("user_initiated", &self.user_initiated)
            .field("redirect", &self.redirect)
            .field("popup", &self.popup)
            .finish()
    }
}

/// What a script dialog asks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptDialogKind {
    /// `alert()`: a message and OK.
    Alert,
    /// `confirm()`: OK or Cancel.
    Confirm,
    /// `prompt()`: a line of text, starting from `default_text`.
    Prompt {
        /// The page's suggested answer.
        default_text: String,
    },
    /// The page asks whether to leave it (`beforeunload`).
    BeforeUnload,
}

/// What a page asked of a window it opened (`window.open` features).
///
/// Read from the opened view with `WebSession::window_features`, once the
/// engine has applied them, which is as soon as it reports the window.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WindowFeatures {
    /// Whether the page asked for a popup window rather than a tab: it named a
    /// size or position, or turned bars off (the HTML "is popup" rule).
    pub popup: bool,
    /// The size asked for, in CSS pixels of the page area, when one was named.
    pub size: Option<(u32, u32)>,
    /// The position asked for, when one was named. Desktops may ignore it.
    pub position: Option<(i32, i32)>,
    /// Whether the window should have a location bar.
    pub location_bar: bool,
    /// Whether the window should have a toolbar.
    pub toolbar: bool,
    /// Whether the window may be resized.
    pub resizable: bool,
}

/// A script dialog waiting for the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptDialogRequest {
    /// Quote this in the answer.
    pub id: PageRequestId,
    /// What it asks.
    pub kind: ScriptDialogKind,
    /// The page's message. Page-controlled text: show it as the page's words,
    /// never as the app's.
    pub message: String,
}

/// How the host answers a script dialog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptDialogAnswer {
    /// OK (alert), OK (confirm), Leave (before-unload).
    Accept,
    /// Cancel, Stay, or closing the dialog.
    Dismiss,
    /// The text for a `prompt()`. For any other kind this is `Accept`.
    Text(String),
}

/// A file chooser (`<input type=file>`) waiting for the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileChooserRequest {
    /// Quote this in the answer.
    pub id: PageRequestId,
    /// Whether the page accepts more than one file.
    pub multiple: bool,
    /// The MIME types the page's `accept` names, if any.
    pub mime_types: Vec<String>,
}

/// The scheme of an HTTP authentication challenge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthScheme {
    /// HTTP Basic: the password crosses the wire as-is (over TLS, if any).
    Basic,
    /// HTTP Digest.
    Digest,
    /// NTLM.
    Ntlm,
    /// Negotiate (Kerberos/SPNEGO).
    Negotiate,
    /// A TLS client certificate was requested. The engine has no way to
    /// present one, so it is always cancelled and reported as
    /// [`PageEvent::PromptDeclined`] with [`DeclinedPrompt::Authentication`];
    /// it never reaches the host as a challenge.
    ClientCertificate,
    /// Anything else WebKit reports.
    Other,
}

/// An HTTP authentication challenge waiting for the host. The destination
/// guard's own proxy credentials are answered by the engine and never appear.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthChallenge {
    /// Quote this in the answer.
    pub id: PageRequestId,
    /// The host asking.
    pub host: String,
    /// Its port.
    pub port: u32,
    /// The realm it names. Server-controlled text.
    pub realm: String,
    /// The scheme.
    pub scheme: AuthScheme,
    /// Whether an earlier answer was refused.
    pub retry: bool,
}

/// How the host answers an authentication challenge.
#[derive(Clone, PartialEq, Eq)]
pub enum AuthAnswer {
    /// Send these credentials for this challenge only; nothing is saved.
    Credentials {
        /// The user name.
        user: String,
        /// The password.
        password: SecretText,
    },
    /// Refuse; the page receives the server's 401.
    Cancel,
}

impl fmt::Debug for AuthAnswer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Credentials { user, password } => f
                .debug_struct("Credentials")
                .field("user", user)
                .field("password", password)
                .finish(),
            Self::Cancel => f.write_str("Cancel"),
        }
    }
}

/// What lies under the pointer when the page asked for a context menu.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ContextTarget {
    /// A link's target.
    pub link: Option<PolicyUrl>,
    /// An image's source.
    pub image: Option<PolicyUrl>,
    /// A media element's source.
    pub media: Option<PolicyUrl>,
    /// Whether the target is editable.
    pub editable: bool,
    /// Whether the target is inside a selection.
    pub selection: bool,
    /// For a word the spelling checker does not know: what it proposes
    /// instead, best first and at most [`MAX_SPELLING_GUESSES`]; empty where
    /// it has no proposal. `None` for anything else. Apply one with
    /// `WebSession::fix_spelling` before the next context menu.
    pub spelling: Option<Vec<String>>,
}

/// The most replacements reported for one misspelled word.
pub const MAX_SPELLING_GUESSES: usize = 8;

/// What to do about the misspelled word of the last
/// [`PageEvent::ContextMenu`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpellingFix {
    /// Replace it with the proposal at this index of
    /// [`ContextTarget::spelling`].
    Guess(usize),
    /// Accept the word until the engine is restarted.
    Ignore,
    /// Add the word to the person's dictionary.
    Learn,
}

/// A colour field (`<input type=color>`) the person opened, waiting for the
/// host's colour picker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ColorChooserRequest {
    /// Quote this in the answer.
    pub id: PageRequestId,
    /// The field's colour now: red, green, blue, alpha.
    pub color: [u8; 4],
    /// Whether the field takes an alpha other than opaque.
    pub alpha: bool,
    /// Where the field is, to place the picker against.
    pub area: ViewRect,
}

/// Why a script evaluation produced no value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptError {
    /// The script threw, or did not parse. Carries WebKit's message.
    Failed(String),
    /// Evaluation returned, but native preview transport cannot return the value.
    /// A returned Promise may still be pending; this does not await or retry it.
    /// Retrying the expression would repeat its side effects.
    Unavailable,
    /// The session closed or the page navigated first.
    Cancelled,
    /// The serialized result exceeds [`MAX_PAGE_TEXT_BYTES`]; JSON and preview
    /// envelopes are refused rather than truncated.
    TooLarge,
}

/// Why a view's WebProcess ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TerminationReason {
    /// It crashed.
    Crashed,
    /// It exceeded its memory limit.
    ExceededMemory,
    /// The host terminated it.
    TerminatedByHost,
}

/// Which JavaScript world a script runs in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptWorld {
    /// The page's own world: the script sees and can change page globals, and
    /// the page can see what it leaves behind.
    Page,
    /// A named isolated world: same DOM, separate globals, so the page cannot
    /// tamper with the script's functions. Globals persist across evaluations
    /// in this document and reset on navigation.
    Isolated(String),
}

/// One document in one frame of a page, as reported with a
/// [`PageEvent::FrameSecretMessage`]. It stops matching once the frame shows
/// another document.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FrameDocument {
    pub(crate) frame: u64,
    pub(crate) document: String,
}

/// Host script input that cannot be represented faithfully by WebKit's C API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptInputError {
    /// WebKit could not initialize a stable named isolated world.
    WorldInitializationFailed,
    /// A user script contains an embedded NUL byte.
    SourceContainsNul,
    /// An isolated world name contains an embedded NUL byte.
    WorldContainsNul,
    /// An isolated world name is empty.
    EmptyWorld,
}

impl fmt::Display for ScriptInputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::WorldInitializationFailed => "isolated script world could not be initialized",
            Self::SourceContainsNul => "user script source contains a NUL byte",
            Self::WorldContainsNul => "isolated script world contains a NUL byte",
            Self::EmptyWorld => "isolated script world is empty",
        })
    }
}

impl std::error::Error for ScriptInputError {}

/// Which frames a user script is injected into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptFrames {
    /// The top frame only.
    TopFrame,
    /// Every frame, third-party iframes included.
    AllFrames,
}

/// When a user script runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptTiming {
    /// Before any page script, as soon as the document exists.
    DocumentStart,
    /// After the document has parsed.
    DocumentEnd,
}

/// A script injected into every document this view loads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserScript {
    /// The source.
    pub source: String,
    /// The frames it runs in.
    pub frames: ScriptFrames,
    /// When.
    pub timing: ScriptTiming,
    /// The world.
    pub world: ScriptWorld,
}

/// Most URL patterns one content script or style accepts in each list.
pub const MAX_CONTENT_PATTERNS: usize = 64;
/// Longest URL pattern a content script or style accepts.
pub const MAX_CONTENT_PATTERN_BYTES: usize = 2048;

/// A browser-extension content script: injected only into pages whose URL
/// matches `matches` and none of `excludes`, in its own isolated world.
///
/// Patterns use WebKit's user-content syntax, `scheme://host/path` with `*`
/// wildcards (for example `https://*.example.com/*`). The isolated world
/// shares the DOM with the page but not its JavaScript globals. Native patterns
/// match the path without the query; they are not WebExtensions match patterns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentScript {
    /// The JavaScript source.
    pub source: String,
    /// The frames it runs in.
    pub frames: ScriptFrames,
    /// When it runs.
    pub timing: ScriptTiming,
    /// The isolated world, one per extension.
    pub world: String,
    /// Pages it runs on; at least one pattern.
    pub matches: Vec<String>,
    /// Pages it never runs on, even when matched.
    pub excludes: Vec<String>,
}

/// A browser-extension style sheet, applied at user level only to matching pages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentStyle {
    /// The CSS source.
    pub source: String,
    /// The frames it applies to.
    pub frames: ScriptFrames,
    /// Pages it applies to; at least one pattern.
    pub matches: Vec<String>,
    /// Pages it never applies to, even when matched.
    pub excludes: Vec<String>,
}

/// One installed content script or style, for removal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ContentInjectionId(pub(crate) u64);

/// A content script or style the host cannot install.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ContentInjectionError {
    /// The source or world name is not representable.
    Script(ScriptInputError),
    /// No `matches` pattern was given.
    NoMatches,
    /// A list exceeds [`MAX_CONTENT_PATTERNS`].
    TooManyPatterns,
    /// A pattern is empty, longer than [`MAX_CONTENT_PATTERN_BYTES`], contains
    /// NUL, or lacks `scheme://`.
    InvalidPattern,
}

impl fmt::Display for ContentInjectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Script(error) => error.fmt(f),
            Self::NoMatches => f.write_str("content injection has no match pattern"),
            Self::TooManyPatterns => f.write_str("content injection has too many patterns"),
            Self::InvalidPattern => f.write_str("content injection pattern is invalid"),
        }
    }
}

impl std::error::Error for ContentInjectionError {}

/// Website data kinds a host may clear.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WebsiteData(u32);

impl WebsiteData {
    /// Memory and disk caches.
    pub const CACHE: Self = Self(1 | 2);
    /// Cookies.
    pub const COOKIES: Self = Self(1 << 6);
    /// Local/session storage, IndexedDB, DOM cache, service workers and origin-private files.
    pub const STORAGE: Self =
        Self((1 << 3) | (1 << 4) | (1 << 5) | (1 << 10) | (1 << 11) | (1 << 12));
    /// Storage associated with one scheme, host and port.
    pub const LOCAL_STORAGE: Self = Self(1 << 4);
    /// HTTPS upgrade state associated with a hostname rather than a port.
    pub const HSTS_CACHE: Self = Self(1 << 8);
    /// Origin-private file system storage on runtimes that expose it.
    pub const FILE_SYSTEM: Self = Self(1 << 12);
    /// Everything WebKit keeps, HSTS and tracking-prevention state included.
    /// This is what "sign out of everything" clears.
    pub const ALL: Self = Self((1 << 13) - 1);

    /// Both sets.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// The WebKit `WebKitWebsiteDataTypes` bits.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }
}

/// Which cookies a profile accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CookiePolicy {
    /// Every cookie.
    Always,
    /// None.
    Never,
    /// Only the top-level site's.
    NoThirdParty,
}

/// Which requests the host answers instead of the engine declining them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PagePrompts {
    /// Script dialogs (`alert`, `confirm`, `prompt`, `beforeunload`).
    pub script_dialogs: bool,
    /// File choosers.
    pub file_chooser: bool,
    /// HTTP authentication.
    pub authentication: bool,
    /// `<select>` dropdowns. WPE draws none: without a host menu a person
    /// cannot pick an option with the pointer.
    pub option_menus: bool,
    /// Colour fields. WPE draws no picker: without a host one a colour
    /// field keeps its colour.
    pub color_chooser: bool,
}

impl PagePrompts {
    /// The host answers everything.
    pub const ALL: Self = Self {
        script_dialogs: true,
        file_chooser: true,
        authentication: true,
        option_menus: true,
        color_chooser: true,
    };
}

/// A rectangle in view coordinates (logical pixels from the view's top
/// left).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ViewRect {
    /// Left edge.
    pub x: i32,
    /// Top edge.
    pub y: i32,
    /// Width.
    pub width: i32,
    /// Height.
    pub height: i32,
}

/// One entry of a `<select>` dropdown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptionMenuItem {
    /// The option's text.
    pub label: String,
    /// Its `title`, if any.
    pub tooltip: Option<String>,
    /// An `<optgroup>` heading, not choosable.
    pub group_label: bool,
    /// Inside an `<optgroup>`.
    pub group_child: bool,
    /// Choosable.
    pub enabled: bool,
    /// The current choice.
    pub selected: bool,
}

/// A `<select>` dropdown waiting for the host to draw it.
/// Menus exceeding [`MAX_OPTION_MENU_ITEMS`] or [`MAX_OPTION_MENU_TEXT_BYTES`]
/// are declined as a whole and reported as [`PageEvent::PromptDeclined`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptionMenuRequest {
    /// Quote this in the answer.
    pub id: PageRequestId,
    /// The entries, in order; answer with an index into this list.
    pub items: Vec<OptionMenuItem>,
    /// Where the `<select>` is, to place the menu against.
    pub area: ViewRect,
}

/// A notification a page shows (`new Notification(..)`), once the policy
/// granted the notification permission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotificationRequest {
    /// WebKit's identifier for it, for `WebSession::notification_clicked`,
    /// `WebSession::close_notification` and [`PageEvent::NotificationClosed`].
    pub id: u64,
    /// The origin of the document that showed it, from WebKit's own record;
    /// `None` on a runtime without it.
    pub origin: Option<crate::site_permissions::PermissionOrigin>,
    /// The title. Page-controlled text.
    pub title: String,
    /// The body. Page-controlled text.
    pub body: String,
    /// The page's tag, which replaces an earlier notification with the same
    /// tag.
    pub tag: Option<String>,
}

/// Insecure (HTTP) content on an HTTPS page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsecureContent {
    /// Active content (a script, a stylesheet) ran.
    Ran,
    /// Passive content (an image) was displayed.
    Displayed,
}

/// A prompt declined because it was disabled or exceeded session limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeclinedPrompt {
    /// A script dialog.
    ScriptDialog,
    /// A file chooser.
    FileChooser,
    /// An authentication challenge.
    Authentication,
    /// A `<select>` dropdown.
    OptionMenu,
    /// A colour field's picker.
    ColorChooser,
}

/// The user agent a view sends.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum UserAgent {
    /// WebKit's own, which sites recognise as Safari-compatible.
    #[default]
    Default,
    /// WebKit's own with `name/version` appended, as browsers identify
    /// themselves.
    Application {
        /// The application name.
        name: String,
        /// Its version.
        version: String,
    },
    /// Exactly this string.
    Custom(String),
}

/// Per-view engine settings. [`Default`] is what a `WebSession` starts with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebSettings {
    /// The user agent.
    pub user_agent: UserAgent,
    /// Whether page JavaScript runs. Host scripts run regardless.
    pub javascript: bool,
    /// Whether a script may open a window without a gesture.
    pub javascript_opens_windows: bool,
    /// Whether the Web Inspector is available.
    pub developer_extras: bool,
    /// Whether media waits for a person's gesture before playing.
    pub media_requires_gesture: bool,
    /// Whether WebGL is available.
    pub webgl: bool,
    /// Whether `mediaDevices`/WebRTC are available, with encoded transforms
    /// (`RTCRtpScriptTransform`) where the runtime has WebRTC, speaker
    /// selection (`setSinkId`) and screen sharing (`getDisplayMedia`). The
    /// permission policy still decides each camera, microphone and screen
    /// request.
    pub webrtc: bool,
    /// Whether back/forward keeps pages alive for instant return.
    pub page_cache: bool,
    /// Whether text zoom leaves images at their size.
    pub zoom_text_only: bool,
    /// Whether `navigator.requestMediaKeySystemAccess` is available. Only a
    /// runtime built with encrypted media offers it, and each key-system
    /// request still needs [`crate::web::policy::PermissionKind::MediaKeySystem`].
    pub encrypted_media: bool,
}

impl Default for WebSettings {
    fn default() -> Self {
        Self {
            user_agent: UserAgent::Default,
            javascript: true,
            javascript_opens_windows: false,
            developer_extras: false,
            media_requires_gesture: true,
            webgl: true,
            webrtc: false,
            page_cache: true,
            zoom_text_only: false,
            encrypted_media: false,
        }
    }
}

/// Something a page told its host.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum PageEvent {
    /// Native geolocation permission state changed across this view's processes.
    GeolocationPermissionChanged {
        /// The reset operation, returned by `WebSession::revoke_geolocation`.
        id: PageRequestId,
        /// Whether this operation stopped watches (`true`) or reset cached denials (`false`).
        revoked: bool,
        /// Success after acknowledgement, or a bounded failure description.
        result: Result<(), String>,
    },
    /// An origin-scoped native permission request awaiting a host answer.
    PermissionRequested(crate::site_permissions::SitePermissionRequest),
    /// Tab past the page's last focusable element, or Shift+Tab past its
    /// first, took focus out of the page (see `WebSession::set_focus_handoff`).
    FocusLeftPage {
        /// Shift+Tab: focus left before the first element.
        backward: bool,
        /// The page's load generation when focus left.
        load: u64,
    },
    /// A notification the host shows was closed by the page, replaced by one
    /// with the same tag, or closed with `WebSession::close_notification`;
    /// its desktop entry goes.
    NotificationClosed {
        /// The [`NotificationRequest::id`].
        id: u64,
    },
    /// The bound inspector frontend closed, from its own UI or the session;
    /// its id no longer receives frames or input.
    InspectorClosed {
        /// The id the frontend was bound to.
        view: crate::web::ViewId,
    },
    /// A held permission request expired or was invalidated before an answer.
    PermissionCancelled {
        /// The request to remove from host UI.
        id: PageRequestId,
    },
    /// A paginated PDF export completed or failed; bytes are returned without writing files.
    PdfExportFinished {
        /// The export operation.
        id: crate::printing::PdfPrintId,
        /// PDF bytes or a typed failure, including cancellation.
        result: Result<crate::printing::PdfDocument, crate::printing::PdfPrintError>,
    },
    /// The main-frame load moved to `stage`.
    Load(LoadStage),
    /// The main-frame load failed. `url` is redacted in `Debug`.
    LoadFailed {
        /// The failing URL.
        url: PolicyUrl,
        /// WebKit's error message.
        message: String,
        /// Whether the load was cancelled rather than failed (a new navigation,
        /// `stop`, or a policy refusal).
        cancelled: bool,
    },
    /// The estimated load progress, from 0.0 to 1.0.
    Progress(f64),
    /// The view's address changed (navigation, redirect, `history.pushState`).
    UriChanged(PolicyUrl),
    /// The document title changed.
    TitleChanged(String),
    /// A registered redirect URI was reached and stopped before loading.
    RedirectCaptured(CapturedRedirect),
    /// The page asked to open a window and the policy allowed it. The engine
    /// opens none; the host may load `url` here or elsewhere.
    PopupRequested {
        /// The window's URL. `about:blank` for a script-built window.
        url: PolicyUrl,
        /// Whether a person's gesture opened it.
        user_initiated: bool,
        /// The person asked for it without leaving the page: a link opened
        /// with the middle button. A browser opens it behind the page in
        /// view.
        background: bool,
    },
    /// The page opened a window and the engine made it a real view
    /// (`WebSession::set_popups` enabled
    /// popups). It is loading `url`, with `window.opener` working; take it with
    /// `WebSession::take_popup(id)` and show it, or drop it to close it.
    PopupOpened {
        /// Quote this to take it.
        id: PageRequestId,
        /// The URL it opened on.
        url: PolicyUrl,
        /// Whether a person's gesture opened it.
        user_initiated: bool,
        /// Opened with the middle button; see
        /// [`PageEvent::PopupRequested::background`].
        background: bool,
    },
    /// A popup that was never taken closed itself (`window.close()`) and
    /// was released, or the host discarded it.
    PopupClosed {
        /// The popup's id from [`PageEvent::PopupOpened`].
        id: PageRequestId,
    },
    /// The page called `window.close()`.
    CloseRequested,
    /// The view's WebProcess ended. The next reload, back or forward starts a
    /// fresh, attested renderer and returns to the page that was showing.
    WebProcessTerminated(TerminationReason),
    /// A message posted to a handler was longer than
    /// [`MAX_PAGE_TEXT_BYTES`] and was dropped rather than cut.
    ScriptMessageTooLarge {
        /// The handler it was posted to.
        handler: String,
    },
    /// A script dialog waits for [`ScriptDialogAnswer`].
    ScriptDialog(ScriptDialogRequest),
    /// A file chooser waits for files or a cancel.
    FileChooser(FileChooserRequest),
    /// A colour field waits for `WebSession::answer_color_chooser`.
    ColorChooser(ColorChooserRequest),
    /// An authentication challenge waits for [`AuthAnswer`].
    Authentication(AuthChallenge),
    /// A prompt was disabled or exceeded session limits.
    PromptDeclined(DeclinedPrompt),
    /// The page asked for a context menu. The engine draws none.
    ContextMenu(ContextTarget),
    /// A `<select>` was opened; draw its dropdown and answer with
    /// `WebSession::answer_option_menu`.
    OptionMenu(OptionMenuRequest),
    /// WebKit closed a dropdown the host was showing (the page changed or
    /// went away); dismiss it.
    OptionMenuClosed {
        /// The dropdown's id.
        id: PageRequestId,
    },
    /// A popup's page is ready to be shown; before this it may still be
    /// blank.
    ReadyToShow,
    /// The page asks to run as a modal window (`showModalDialog`-style
    /// popups).
    RunAsModal,
    /// The page entered (`true`) or left (`false`) fullscreen. The host owns
    /// the window state.
    Fullscreen(bool),
    /// The page shows a notification, once the policy granted
    /// [`PermissionKind::Notifications`](crate::web::policy::PermissionKind).
    /// Only a persistent profile can: WebKit refuses notification permission
    /// in an ephemeral session before any request reaches the policy.
    Notification(NotificationRequest),
    /// The page mixed insecure content into a secure one.
    InsecureContent(InsecureContent),
    /// The link under the pointer changed (`None`: no link). For a status
    /// line.
    HoveredLink(Option<PolicyUrl>),
    /// The page started (`true`) or stopped (`false`) playing audio.
    PlayingAudio(bool),
    /// A script evaluation finished; the value is JSON (`undefined` is
    /// `null`).
    ScriptResult {
        /// The evaluation it answers.
        id: PageRequestId,
        /// The JSON value or why there is none.
        result: Result<String, ScriptError>,
    },
    /// The page posted to a registered handler
    /// (`window.webkit.messageHandlers.NAME.postMessage(value)`). Any frame
    /// in the handler's world can post: treat `json` as untrusted input.
    ScriptMessage {
        /// The handler name.
        handler: String,
        /// The posted value as JSON.
        json: String,
    },
    /// A bounded JSON message from a host-registered isolated secret handler.
    ///
    /// The body is wiped on final drop and redacted in diagnostics. It remains
    /// untrusted input; hosts must validate the document and origin separately.
    SecretScriptMessage {
        /// The registered handler name.
        handler: String,
        /// The private JSON payload.
        json: SecretText,
    },
    /// A protected message from a frame-scoped secret handler, with the frame,
    /// document and origins WebKit recorded for the post.
    ///
    /// Only documents with HTTPS origins inside HTTPS top documents are
    /// delivered. The body is wiped on final drop and redacted in diagnostics;
    /// it is still untrusted input from that document.
    FrameSecretMessage {
        /// The registered handler name.
        handler: String,
        /// The posting document, for [`crate::ffi::runtime::WebSession::evaluate_secret_script_in_frame`].
        frame: FrameDocument,
        /// The posting document's origin.
        origin: crate::site_permissions::PermissionOrigin,
        /// The top document's origin.
        top_origin: crate::site_permissions::PermissionOrigin,
        /// Whether the post came from the top document.
        main_frame: bool,
        /// The private JSON payload.
        json: SecretText,
    },
    /// Find-in-page matched `matches` times (`None` when there were more than
    /// the search's limit), answering `find`.
    FindMatches(Option<u32>),
    /// A `count_matches` count (`None` when over its limit).
    MatchesCounted(Option<u32>),
    /// Find-in-page matched nothing.
    FindFailed,
    /// A download the policy allowed was refused because the host set no
    /// download directory. Nothing was written.
    DownloadDeclined {
        /// What the page tried to download.
        url: PolicyUrl,
    },
    /// A profile-owned native transfer was accepted, before its response or filename is known.
    DownloadRequested {
        /// Identity shared by all later transfer events.
        id: PageRequestId,
        /// Original native request URI.
        url: PolicyUrl,
    },
    /// A download began, into a file reserved for it in the host's download
    /// directory.
    DownloadStarted {
        /// Quote this to cancel it.
        id: PageRequestId,
        /// Where it comes from.
        url: PolicyUrl,
        /// The server's suggested name, before it was made safe.
        suggested_name: String,
        /// The file being written: inside the download directory, a fresh
        /// name the engine created exclusively.
        path: std::path::PathBuf,
    },
    /// Bounded protocol metadata for a native download response.
    DownloadResponse {
        id: PageRequestId,
        response: DownloadResponse,
    },
    /// A cancelled native transfer retained an immutable, unlinked prefix for continuation.
    DownloadPaused {
        id: PageRequestId,
        partial: PartialDownload,
    },
    /// A failed native transfer retained a resumable prefix.
    DownloadInterrupted {
        id: PageRequestId,
        partial: PartialDownload,
        message: String,
    },
    /// A download received more bytes.
    DownloadProgress {
        /// The download.
        id: PageRequestId,
        /// Bytes so far.
        received: u64,
        /// The expected total, when the server said.
        expected: Option<u64>,
    },
    /// A download completed; its file is whole.
    DownloadFinished {
        /// The download.
        id: PageRequestId,
        /// The finished file. Hand it to the person through the save portal
        /// (`enzui_core::download_destination`).
        path: std::path::PathBuf,
    },
    /// A download failed or was cancelled; its file was removed.
    DownloadFailed {
        /// The download.
        id: PageRequestId,
        /// WebKit's message.
        message: String,
        /// Whether it was cancelled rather than failed.
        cancelled: bool,
    },
    /// A website-data clear finished.
    DataCleared {
        /// The request it answers.
        id: PageRequestId,
        /// WebKit's message on failure.
        result: Result<(), String>,
    },
}

/// The longest file name a download is given, in bytes.
pub const MAX_DOWNLOAD_NAME_BYTES: usize = 200;

/// Makes a server-suggested download name safe to create inside a directory:
/// the last path component only, no control or Unicode format characters
/// (bidi overrides, isolates, zero-width marks), no leading dots (no hidden
/// files, no `..`), at most [`MAX_DOWNLOAD_NAME_BYTES`], and `download` when
/// nothing is left.
#[must_use]
pub fn safe_download_name(suggested: &str) -> String {
    let last = suggested.rsplit(['/', '\\']).next().unwrap_or_default();
    let cleaned: String = last
        .chars()
        .filter(|&c| !c.is_control() && !is_format_char(c))
        .collect::<String>()
        .trim()
        .trim_start_matches('.')
        .trim()
        .to_owned();
    let mut name = bounded_text(cleaned, MAX_DOWNLOAD_NAME_BYTES);
    if name.is_empty() {
        name = "download".into();
    }
    name
}

// General category Cf as of Unicode 16.
fn is_format_char(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{0600}'..='\u{0605}'
            | '\u{061C}'
            | '\u{06DD}'
            | '\u{070F}'
            | '\u{0890}'..='\u{0891}'
            | '\u{08E2}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206F}'
            | '\u{FEFF}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{110BD}'
            | '\u{110CD}'
            | '\u{13430}'..='\u{1343F}'
            | '\u{1BCA0}'..='\u{1BCA3}'
            | '\u{1D173}'..='\u{1D17A}'
            | '\u{E0001}'
            | '\u{E0020}'..='\u{E007F}'
    )
}

fn bounded_text(mut text: String, max: usize) -> String {
    if text.len() > max {
        let mut cut = max;
        while !text.is_char_boundary(cut) {
            cut -= 1;
        }
        text.truncate(cut);
    }
    text
}

/// Cuts page-supplied text to [`MAX_PAGE_TEXT_BYTES`] at a character
/// boundary.
#[must_use]
pub fn bounded_page_text(text: String) -> String {
    bounded_text(text, MAX_PAGE_TEXT_BYTES)
}

/// HTTP metadata sufficient to qualify an identity-preserving byte-range continuation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadResponse {
    /// Final response URI, screened by the native destination policy.
    pub url: PolicyUrl,
    /// Native HTTP status, zero for non-HTTP sources.
    pub status: u32,
    /// Announced response body length; a range response reports the part length.
    pub length: Option<u64>,
    /// Whether the server advertised byte ranges.
    pub ranges: bool,
    /// Bounded entity tag, when supplied.
    pub etag: Option<String>,
    /// Bounded Last-Modified validator, when supplied.
    pub modified: Option<String>,
    /// Bounded Content-Range, when supplied.
    pub range: Option<String>,
    /// Bounded Content-Encoding, when supplied.
    pub coding: Option<String>,
}
impl DownloadResponse {
    /// Whether an identity-coded HTTP representation supplied a usable range validator.
    pub fn resumable(&self) -> bool {
        self.status == 200
            && self.ranges
            && self
                .coding
                .as_deref()
                .is_none_or(|v| v.eq_ignore_ascii_case("identity"))
            && (self
                .etag
                .as_deref()
                .is_some_and(|v| v.starts_with('"') && v.ends_with('"'))
                || self
                    .modified
                    .as_deref()
                    .is_some_and(|v| v.ends_with(" GMT")))
    }
}
/// A read-only retained prefix after the native writer has stopped and unlinked its path.
#[derive(Debug, Clone)]
pub struct PartialDownload {
    file: std::sync::Arc<std::fs::File>,
    /// Exact retained prefix length, measured after native cancellation/failure.
    pub received: u64,
    /// Original response identity and coding.
    pub response: DownloadResponse,
    /// Original suggested destination; continuation must publish without clobbering another file.
    pub path: std::path::PathBuf,
}
impl PartialDownload {
    #[cfg(feature = "wpe")]
    pub(crate) fn new(
        file: std::sync::Arc<std::fs::File>,
        response: DownloadResponse,
        path: std::path::PathBuf,
    ) -> Option<Self> {
        let received = file.metadata().ok()?.len();
        if received == 0 || response.length.is_some_and(|n| received > n) {
            return None;
        }
        Some(Self {
            file,
            received,
            response,
            path,
        })
    }
    /// Borrow the stopped writer's retained inode; use positional reads when sharing it.
    pub fn file(&self) -> &std::fs::File {
        &self.file
    }
}
impl PartialEq for PartialDownload {
    fn eq(&self, other: &Self) -> bool {
        std::sync::Arc::ptr_eq(&self.file, &other.file)
            && self.received == other.received
            && self.response == other.response
            && self.path == other.path
    }
}

#[cfg(test)]
mod tests {
    use super::safe_download_name;

    #[test]
    fn download_names_drop_format_characters_that_disguise_the_extension() {
        assert_eq!(
            safe_download_name("invoice\u{202E}fdp.exe"),
            "invoicefdp.exe"
        );
        assert_eq!(
            safe_download_name("report\u{2067}\u{2066}cod.\u{2069}scr"),
            "reportcod.scr"
        );
        assert_eq!(
            safe_download_name("a\u{200B}b\u{200D}c\u{FEFF}.txt"),
            "abc.txt"
        );
        assert_eq!(
            safe_download_name("\u{061C}\u{E0041}.\u{00AD}bashrc"),
            "bashrc"
        );
        assert_eq!(safe_download_name("\u{202D}\u{2060}"), "download");
        assert_eq!(safe_download_name("Résumé – 日本.pdf"), "Résumé – 日本.pdf");
    }
}
