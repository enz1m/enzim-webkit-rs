//! The native half of [`crate::page`]: WebKit's page signals, queued for the
//! host, and the host's answers applied back.
//!
//! `PageHub` is the shared, thread-affine queue. The policy binding holds it
//! too, to stop a registered redirect before it loads and to report a popup the
//! policy allowed. `PageBinding` owns the signal handlers on the view, its
//! find controller and its user content manager, and every prompt still
//! waiting for the host; dropping it answers each one (decline) before
//! disconnecting, so no page is left waiting.
//!
//! No `RefCell` borrow is held across a WebKit call: answering a prompt takes
//! the native object out of the hub first, because closing a dialog can emit
//! the next signal synchronously.

use core::ffi::{c_char, c_int, c_uint, c_void};
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, VecDeque};
use std::ffi::CString;
use std::rc::{Rc, Weak};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::web::RedirectCapture;
use crate::web::policy::PolicyUrl;
use enzui_security::secret::SecretText;

use super::wpe as ffi;
use crate::page::{
    AuthAnswer, AuthChallenge, AuthScheme, CapturedRedirect, ColorChooserRequest, ContextTarget,
    CookiePolicy, DeclinedPrompt, FileChooserRequest, InsecureContent, LoadStage,
    MAX_PENDING_PROMPTS, MAX_REDIRECT_CAPTURES, MAX_SPELLING_GUESSES, NotificationRequest,
    OptionMenuItem, OptionMenuRequest, PAGE_EVENT_CAPACITY, PageEvent, PagePrompts, PageRequestId,
    ScriptDialogAnswer, ScriptDialogKind, ScriptDialogRequest, ScriptError, ScriptFrames,
    ScriptInputError, ScriptTiming, ScriptWorld, SpellingFix, UserAgent, UserScript, ViewRect,
    WebSettings, WebsiteData, bounded_page_text,
};

/// WebKit declarations beyond [`super::wpe`].
#[allow(missing_docs)]
pub(crate) mod sys;

use sys::*;
mod color_chooser;
mod frame_secrets;
use color_chooser::{WebKitColor, WebKitColorChooserRequest};
mod notifications;
pub(crate) mod permissions;
pub use notifications::MAX_SHOWN_NOTIFICATIONS;

macro_rules! callback {
    ($f:expr, fn($($arg:ty),*) $(-> $ret:ty)?) => {{
        // SAFETY: GSignal erases callbacks to `void (*)(void)`; the concrete
        // function matches the signal's documented ABI.
        unsafe {
            core::mem::transmute::<extern "C" fn($($arg),*) $(-> $ret)?, extern "C" fn()>($f)
        }
    }};
}

/// A prompt waiting for the host, holding one native reference.
enum Pending {
    Dialog(*mut WebKitScriptDialog, c_int),
    Chooser(*mut WebKitFileChooserRequest),
    Challenge(*mut ffi::WebKitAuthenticationRequest),
    /// A dropdown, with its `close` handler and that handler's data.
    Menu(*mut WebKitOptionMenu, u64, *mut MenuData),
    Color(*mut WebKitColorChooserRequest),
}

/// A colour as the page has it, in bytes: red, green, blue, alpha.
fn color_bytes(color: WebKitColor) -> [u8; 4] {
    // The cast saturates: a part out of range ends at 0 or 255, and one
    // that is not a number at 0.
    let byte = |part: f64| (part * 255.0).round() as u8;
    [
        byte(color.red),
        byte(color.green),
        byte(color.blue),
        byte(color.alpha),
    ]
}

fn native_color(color: [u8; 4], alpha: bool) -> WebKitColor {
    let part = |byte: u8| f64::from(byte) / 255.0;
    WebKitColor {
        red: part(color[0]),
        green: part(color[1]),
        blue: part(color[2]),
        // A field without alpha is opaque whatever the host sends.
        alpha: if alpha { part(color[3]) } else { 1.0 },
    }
}

/// What an entry of WebKit's proposed context menu does about spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SpellingEntry {
    Guess,
    NoGuesses,
    Ignore,
    Learn,
}

fn spelling_entry(stock_action: c_int) -> Option<SpellingEntry> {
    match stock_action {
        WEBKIT_CONTEXT_MENU_ACTION_SPELLING_GUESS => Some(SpellingEntry::Guess),
        WEBKIT_CONTEXT_MENU_ACTION_NO_GUESSES_FOUND => Some(SpellingEntry::NoGuesses),
        WEBKIT_CONTEXT_MENU_ACTION_IGNORE_SPELLING => Some(SpellingEntry::Ignore),
        WEBKIT_CONTEXT_MENU_ACTION_LEARN_SPELLING => Some(SpellingEntry::Learn),
        _ => None,
    }
}

/// The most navigations a popup holds for its host; a further one is
/// decided at once.
const MAX_HELD_NAVIGATIONS: usize = 8;

/// The navigations of a popup that wait for its host. `T` is the native
/// decision; the bookkeeping does not look inside it.
struct HeldNavigations<T> {
    /// The view is a popup its host has not set up yet.
    awaiting_host: bool,
    held: Vec<T>,
}

impl<T> Default for HeldNavigations<T> {
    fn default() -> Self {
        Self {
            awaiting_host: false,
            held: Vec::new(),
        }
    }
}

impl<T> HeldNavigations<T> {
    /// Keeps `decision` for later, where the view still waits for its host
    /// and has room; otherwise hands it back to be decided now.
    fn hold(&mut self, decision: T) -> Result<(), T> {
        if !self.awaiting_host || self.held.len() >= MAX_HELD_NAVIGATIONS {
            return Err(decision);
        }
        self.held.push(decision);
        Ok(())
    }

    /// The host is ready: nothing is held from now on, and what was held is
    /// returned in the order it arrived.
    fn release(&mut self) -> Vec<T> {
        self.awaiting_host = false;
        std::mem::take(&mut self.held)
    }
}

/// Data for a held dropdown's `close` signal.
struct MenuData {
    hub: Weak<PageHub>,
    id: PageRequestId,
}

/// Disconnects a held dropdown's `close` handler, then closes it (`choice`
/// `None`) or activates `choice`, and releases it.
///
/// # Safety
///
/// The three values come from one `Pending::Menu`, released once.
unsafe fn finish_menu(
    menu: *mut WebKitOptionMenu,
    handler: u64,
    data: *mut MenuData,
    choice: Option<c_uint>,
) {
    // SAFETY: forwarded to the caller's contract; the handler goes first so
    // closing cannot re-enter this binding.
    unsafe {
        ffi::g_signal_handler_disconnect(menu.cast(), handler);
        drop(Box::from_raw(data));
        // WebKit expects `close` after `activate_item` too; activation alone
        // leaves its popup open until the next one replaces it.
        if let Some(index) = choice {
            webkit_option_menu_activate_item(menu, index);
        }
        webkit_option_menu_close(menu);
        ffi::g_object_unref(menu.cast());
    }
}

impl Pending {
    fn kind(&self) -> DeclinedPrompt {
        match self {
            Self::Dialog(..) => DeclinedPrompt::ScriptDialog,
            Self::Chooser(_) => DeclinedPrompt::FileChooser,
            Self::Challenge(_) => DeclinedPrompt::Authentication,
            Self::Menu(..) => DeclinedPrompt::OptionMenu,
            Self::Color(_) => DeclinedPrompt::ColorChooser,
        }
    }

    /// Answers with the engine's decline and releases the reference.
    ///
    /// # Safety
    ///
    /// The pointer is the live, referenced object this `Pending` was made for.
    unsafe fn decline(self) {
        // SAFETY: forwarded to the caller's contract.
        unsafe {
            match self {
                Self::Dialog(dialog, kind) => {
                    set_dialog_answer(dialog, kind, &ScriptDialogAnswer::Dismiss, true);
                    webkit_script_dialog_close(dialog);
                    webkit_script_dialog_unref(dialog);
                }
                Self::Menu(menu, handler, data) => finish_menu(menu, handler, data, None),
                Self::Chooser(request) => {
                    webkit_file_chooser_request_cancel(request);
                    ffi::g_object_unref(request.cast());
                }
                Self::Challenge(request) => {
                    webkit_authentication_request_cancel(request);
                    ffi::g_object_unref(request.cast());
                }
                Self::Color(request) => {
                    // A request is only ever held where the runtime has
                    // these functions.
                    if let Some(api) = color_chooser::api() {
                        (api.cancel)(request);
                    }
                    ffi::g_object_unref(request.cast());
                }
            }
        }
    }
}

/// Sets a script dialog's answer. `engine` marks the engine's own decline,
/// which leaves a before-unload page rather than letting the page keep the
/// person on it.
///
/// Inside the `script-dialog` handler this is the whole answer: WebKit
/// completes the dialog when the handler returns. A dialog held for the host
/// is then closed (`webkit_script_dialog_close`) and unreferenced. Closing
/// inside the handler is wrong: it clears the view's current dialog, and
/// WebKit's own release after the handler then dereferences NULL.
///
/// # Safety
///
/// `dialog` is live.
unsafe fn set_dialog_answer(
    dialog: *mut WebKitScriptDialog,
    kind: c_int,
    answer: &ScriptDialogAnswer,
    engine: bool,
) {
    let accept = !matches!(answer, ScriptDialogAnswer::Dismiss);
    // SAFETY: `dialog` is live per the caller; each setter matches its kind.
    unsafe {
        match kind {
            WEBKIT_SCRIPT_DIALOG_CONFIRM => {
                webkit_script_dialog_confirm_set_confirmed(dialog, gbool(accept));
            }
            WEBKIT_SCRIPT_DIALOG_BEFORE_UNLOAD_CONFIRM => {
                webkit_script_dialog_confirm_set_confirmed(dialog, gbool(accept || engine));
            }
            WEBKIT_SCRIPT_DIALOG_PROMPT => {
                if let ScriptDialogAnswer::Text(text) = answer {
                    let text = c_text(text);
                    webkit_script_dialog_prompt_set_text(dialog, text.as_ptr());
                } else if accept {
                    let default = webkit_script_dialog_prompt_get_default_text(dialog);
                    webkit_script_dialog_prompt_set_text(dialog, default);
                }
                // Dismiss leaves the text unset, which `prompt()` returns as
                // `null`.
            }
            _ => {}
        }
    }
}

fn gbool(value: bool) -> ffi::GBoolean {
    if value { ffi::G_TRUE } else { ffi::G_FALSE }
}

/// A C string from host text, dropping any interior NUL rather than failing.
fn c_text(text: &str) -> CString {
    CString::new(text.replace('\0', "")).expect("NULs were removed")
}

fn script_world_name(world: &ScriptWorld) -> Result<Option<CString>, ScriptInputError> {
    match world {
        ScriptWorld::Page => Ok(None),
        ScriptWorld::Isolated(name) if name.is_empty() => Err(ScriptInputError::EmptyWorld),
        ScriptWorld::Isolated(name) => CString::new(name.as_str())
            .map(Some)
            .map_err(|_| ScriptInputError::WorldContainsNul),
    }
}

fn script_frames(frames: ScriptFrames) -> c_int {
    match frames {
        ScriptFrames::AllFrames => 0,
        ScriptFrames::TopFrame => 1,
    }
}

fn script_timing(timing: ScriptTiming) -> c_int {
    match timing {
        ScriptTiming::DocumentStart => 0,
        ScriptTiming::DocumentEnd => 1,
    }
}

/// A bounded owned copy of a borrowed native string; `None` for NULL.
///
/// # Safety
///
/// A non-null `value` is a live NUL-terminated string.
unsafe fn native_text(value: *const c_char) -> Option<String> {
    if value.is_null() {
        return None;
    }
    // SAFETY: forwarded to the caller's contract; the read is bounded.
    let text = unsafe {
        crate::native_diagnostic::read_bounded_diagnostic(value, crate::page::MAX_PAGE_TEXT_BYTES)
    };
    Some(bounded_page_text(text))
}

/// Reads a native URI through the policy layer's bounded scanner.
///
/// # Safety
///
/// A non-null `value` is a live NUL-terminated string.
unsafe fn native_uri(value: *const c_char) -> Option<PolicyUrl> {
    if value.is_null() {
        return None;
    }
    // SAFETY: forwarded to the caller's contract.
    unsafe {
        crate::ffi::policy::scan_bounded_native_uri(value, crate::ffi::policy::MAX_POLICY_URI_BYTES)
    }
    .ok()
    .map(PolicyUrl::new)
}

/// How many URLs of one document the hub remembers for favicon lookup.
const MAX_DOCUMENT_URIS: usize = 8;

#[derive(Default)]
struct HubState {
    export_canceller: Option<Rc<dyn Fn()>>,
    site_permissions: permissions::SitePermissions,
    /// Notifications the host shows, for click and close relay.
    notifications: Vec<notifications::ShownNotification>,
    /// The host turned website notifications off: no prompt, no delivery.
    notifications_blocked: bool,
    events: VecDeque<PageEvent>,
    dropped: u64,
    captures: Vec<RedirectCapture>,
    prompts: PagePrompts,
    pending: Vec<(PageRequestId, Pending)>,
    last_progress: Option<f64>,
    downloads_dir: Option<std::path::PathBuf>,
    downloads: Vec<DownloadSlot>,
    /// The policy the host last installed, for popups opened from now on.
    popup_policy: Option<crate::web::WebPolicy>,
    /// Present while the host wants popups opened as real views.
    popup_template: Option<PopupTemplate>,
    /// Popups opened and not yet taken by the host.
    popups: Vec<(PageRequestId, crate::ffi::runtime::WebSession)>,
    /// For a popup: the hub of the view that opened it. Its redirect
    /// captures apply here too, and report there.
    opener: Option<Weak<PageHub>>,
    /// The settings the host last applied, which a popup starts with.
    settings: Option<WebSettings>,
    /// The last committed non-inert address, which a reload after a renderer
    /// crash returns to.
    last_committed: Option<String>,
    /// The URLs the current document has had, oldest first, including
    /// same-document `pushState`/`replaceState` changes; restarted when a
    /// document commits and bounded to [`MAX_DOCUMENT_URIS`].
    document_uris: VecDeque<String>,
    load_generation: u64,
    load_failures: u64,
    load_failure: Option<(String, c_int)>,
    /// Sticky: the page called `window.close()`. Read for held popups, so a
    /// page that keeps emitting events cannot push it out of the queue.
    close_requested: bool,
    /// The spelling entries of the last context menu, each holding one
    /// native reference.
    spelling: Vec<(SpellingEntry, *mut WebKitContextMenuItem)>,
    /// Whether popups this view opens hold their navigations for the host.
    hold_popups: bool,
    /// For a popup: its navigations the host has not let through yet, each
    /// holding one native reference, with the address it goes to.
    navigations: HeldNavigations<(*mut ffi::WebKitPolicyDecision, String)>,
}

/// What a popup inherits from its opener.
#[derive(Clone)]
pub(crate) struct PopupTemplate {
    pub(crate) profile: Option<crate::web::WebProfile>,
    pub(crate) network_session: Rc<crate::ffi::profile::NetworkSession>,
    pub(crate) outer: crate::sandbox::OuterSandbox,
    pub(crate) destination_policy: crate::web::DestinationPolicy,
    pub(crate) sandbox_baseline: Vec<crate::sandbox::ProcessIdentity>,
    pub(crate) policy: crate::web::WebPolicy,
}

/// The most popups waiting for the host at once; another is refused.
pub const MAX_PENDING_POPUPS: usize = 4;

/// One download this session adopted, holding a reference to it.
struct DownloadSlot {
    id: PageRequestId,
    download: *mut ffi::WebKitDownload,
    data: *mut DownloadData,
    handlers: Vec<u64>,
    url: PolicyUrl,
    path: Option<std::path::PathBuf>,
    failure: Option<(String, bool)>,
    reported: u64,
    response: Option<crate::page::DownloadResponse>,
    reserved: Option<std::fs::File>,
    partial: Option<std::sync::Arc<std::fs::File>>,
    pause_requested: bool,
}

/// Callback data for one download's signals.
struct DownloadData {
    hub: Weak<PageHub>,
    id: PageRequestId,
}

/// The most downloads one session runs at once; another is declined.
pub const MAX_ACTIVE_DOWNLOADS: usize = 16;

/// The session's page-event queue and its waiting prompts.
#[derive(Default)]
pub(crate) struct PageHub {
    state: RefCell<HubState>,
    metadata_revision: Cell<u64>,
    private_bootstrap_document: Cell<bool>,
    navigation_intent: Cell<u64>,
    host_navigation_pending: Cell<bool>,
}

impl PageHub {
    // Native load notifications may arrive after the initiating host call returns.
    pub(crate) fn begin_host_navigation(&self) {
        self.navigation_intent
            .set(self.navigation_intent.get().wrapping_add(1));
        self.host_navigation_pending.set(true);
    }

    pub(crate) fn navigation_intent(&self) -> u64 {
        self.navigation_intent.get()
    }
    pub(crate) fn host_navigation_pending(&self) -> bool {
        self.host_navigation_pending.get()
    }

    pub(crate) fn mark_private_bootstrap_document(&self) {
        self.private_bootstrap_document.set(true);
        self.mark_metadata_changed();
    }

    pub(crate) fn is_private_bootstrap_document(&self) -> bool {
        self.private_bootstrap_document.get()
    }

    pub(crate) fn set_export_canceller(&self, cancel: Rc<dyn Fn()>) {
        self.state.borrow_mut().export_canceller = Some(cancel);
    }
    pub(crate) fn cancel_exports(&self) {
        let cancel = self.state.borrow().export_canceller.clone();
        if let Some(cancel) = cancel {
            cancel();
        }
    }

    pub(crate) fn mark_metadata_changed(&self) {
        self.metadata_revision
            .set(self.metadata_revision.get().wrapping_add(1));
    }

    pub(crate) fn metadata_revision(&self) -> u64 {
        self.metadata_revision.get()
    }

    pub(crate) fn load_failure_revision(&self) -> u64 {
        self.state.borrow().load_failures
    }

    pub(crate) fn push(&self, event: PageEvent) {
        if matches!(
            event,
            PageEvent::Load(LoadStage::Finished) | PageEvent::LoadFailed { .. }
        ) {
            self.host_navigation_pending.set(false);
        }
        if matches!(
            &event,
            PageEvent::TitleChanged(_)
                | PageEvent::UriChanged(_)
                | PageEvent::Load(LoadStage::Started)
        ) {
            self.mark_metadata_changed();
        }
        if matches!(event, PageEvent::Load(LoadStage::Committed))
            && self.private_bootstrap_document.replace(false)
        {
            self.mark_metadata_changed();
        }
        let mut state = self.state.borrow_mut();
        if matches!(event, PageEvent::Load(LoadStage::Started)) {
            state.load_generation = state.load_generation.wrapping_add(1);
        }
        if let PageEvent::UriChanged(uri) = &event {
            let uri = uri.as_str();
            state.document_uris.retain(|known| known != uri);
            if state.document_uris.len() >= MAX_DOCUMENT_URIS {
                state.document_uris.pop_front();
            }
            state.document_uris.push_back(uri.to_owned());
        }
        if state.events.len() >= PAGE_EVENT_CAPACITY {
            // Five prompt kinds are protected, with at most one queued
            // notification per retained native reference.
            const { assert!(PAGE_EVENT_CAPACITY > 5 * MAX_PENDING_PROMPTS) };
            let index = crate::page_event_queue::eviction_index(&state.events, |id| {
                state.pending.iter().any(|(pending, _)| *pending == id)
                    || state.site_permissions.has_pending(id)
            })
            .expect("held prompt notifications cannot fill the event queue");
            state.events.remove(index);
            state.dropped = state.dropped.saturating_add(1);
        }
        state.events.push_back(event);
    }

    pub(crate) fn has_pdf_export_result(&self) -> bool {
        self.state
            .borrow()
            .events
            .iter()
            .any(|event| matches!(event, PageEvent::PdfExportFinished { .. }))
    }

    pub(crate) fn has_events(&self) -> bool {
        !self.state.borrow().events.is_empty()
    }

    pub(crate) fn take_events(&self) -> Vec<PageEvent> {
        self.state.borrow_mut().events.drain(..).collect()
    }

    /// Removes and returns only the result of evaluation `id`, leaving every
    /// other event queued for the host.
    pub(crate) fn take_script_result(
        &self,
        id: PageRequestId,
    ) -> Option<Result<String, crate::page::ScriptError>> {
        let mut state = self.state.borrow_mut();
        let index = state.events.iter().position(
            |event| matches!(event, PageEvent::ScriptResult { id: found, .. } if *found == id),
        )?;
        match state.events.remove(index)? {
            PageEvent::ScriptResult { result, .. } => Some(result),
            _ => None,
        }
    }

    pub(crate) fn dropped(&self) -> u64 {
        self.state.borrow().dropped
    }

    pub(crate) fn new_operation_id(&self) -> PageRequestId {
        self.mint()
    }

    fn mint(&self) -> PageRequestId {
        static NEXT_ID: AtomicU64 = AtomicU64::new(1);
        let id = NEXT_ID
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .expect("page request identifier space exhausted");
        PageRequestId::new(id)
    }

    pub(crate) fn set_prompts(&self, prompts: PagePrompts) {
        self.state.borrow_mut().prompts = prompts;
    }

    pub(crate) fn prompts(&self) -> PagePrompts {
        self.state.borrow().prompts
    }

    /// Adds a redirect URI to capture. `false` when the session already holds
    /// [`MAX_REDIRECT_CAPTURES`].
    pub(crate) fn add_capture(&self, capture: RedirectCapture) -> bool {
        let mut state = self.state.borrow_mut();
        if state.captures.contains(&capture) {
            return true;
        }
        if state.captures.len() >= MAX_REDIRECT_CAPTURES {
            return false;
        }
        state.captures.push(capture);
        true
    }

    pub(crate) fn clear_captures(&self) {
        self.state.borrow_mut().captures.clear();
    }

    /// Whether `uri` is a registered redirect. When it is, queues the capture
    /// and returns `true`; the caller must then stop the navigation.
    pub(crate) fn capture(
        &self,
        uri: &str,
        user_initiated: bool,
        redirect: bool,
        popup: bool,
    ) -> bool {
        let (matched, opener) = {
            let state = self.state.borrow();
            (
                state.captures.iter().any(|c| c.matches(uri)),
                state.opener.as_ref().and_then(Weak::upgrade),
            )
        };
        if matched {
            self.push(PageEvent::RedirectCaptured(CapturedRedirect {
                url: SecretText::new(uri.to_owned()),
                user_initiated,
                redirect,
                popup,
            }));
            return true;
        }
        // A popup's navigation to its opener's redirect (the provider's
        // sign-in page redirecting back) is the opener's capture.
        opener.is_some_and(|opener| opener.capture(uri, user_initiated, redirect, true))
    }

    /// Whether `uri` is a redirect this view or an opener captures, without
    /// reporting it: such a URL must not leak through other events.
    pub(crate) fn is_captured_url(&self, uri: &str) -> bool {
        let (matched, opener) = {
            let state = self.state.borrow();
            (
                state.captures.iter().any(|c| c.matches(uri)),
                state.opener.as_ref().and_then(Weak::upgrade),
            )
        };
        matched || opener.is_some_and(|opener| opener.is_captured_url(uri))
    }

    pub(crate) fn record_settings(&self, settings: &WebSettings) {
        self.state.borrow_mut().settings = Some(settings.clone());
    }

    pub(crate) fn load_state(&self) -> (u64, u64, Option<(String, c_int)>) {
        let state = self.state.borrow();
        (
            state.load_generation,
            state.load_failures,
            state.load_failure.clone(),
        )
    }

    /// The URLs the current document has had, newest first.
    pub(crate) fn document_uris(&self) -> Vec<String> {
        self.state
            .borrow()
            .document_uris
            .iter()
            .rev()
            .cloned()
            .collect()
    }

    pub(crate) fn last_committed(&self) -> Option<String> {
        self.state.borrow().last_committed.clone()
    }

    /// Makes this (a new popup's) hub inherit from its opener's: captures
    /// apply through the link, and prompts and settings are copied. The
    /// download directory is not: a popup the host has not taken would write
    /// files into it that nobody is told about. The host sets one on the
    /// popup it takes.
    pub(crate) fn inherit(&self, opener: &Rc<PageHub>) -> Option<WebSettings> {
        self.inherit_site_permissions(opener);
        let (prompts, settings) = {
            let state = opener.state.borrow();
            (state.prompts, state.settings.clone())
        };
        let hold = opener.state.borrow().hold_popups;
        let mut state = self.state.borrow_mut();
        state.opener = Some(Rc::downgrade(opener));
        state.prompts = prompts;
        state.settings = settings.clone();
        state.hold_popups = hold;
        state.navigations.awaiting_host = hold;
        settings
    }

    pub(crate) fn set_hold_popups(&self, hold: bool) {
        self.state.borrow_mut().hold_popups = hold;
    }

    /// For a popup whose host is not ready: keeps an allowed navigation to
    /// `url` undecided. `false` when it is to be decided now.
    pub(crate) fn hold_navigation(
        &self,
        decision: *mut ffi::WebKitPolicyDecision,
        url: &str,
    ) -> bool {
        if self
            .state
            .borrow_mut()
            .navigations
            .hold((decision, url.to_owned()))
            .is_err()
        {
            return false;
        }
        // SAFETY: the decision is live for the callback that offers it; this
        // reference keeps it until it is used or ignored.
        unsafe { ffi::g_object_ref(decision.cast()) };
        true
    }

    /// Lets the navigations a popup held go ahead, and holds none from now
    /// on. `allowed` hears each address first, in the order they arrived.
    /// Returns how many were waiting.
    pub(crate) fn resume_navigations(&self, mut allowed: impl FnMut(&str)) -> usize {
        let held = self.state.borrow_mut().navigations.release();
        for (decision, url) in &held {
            allowed(url);
            // SAFETY: each was referenced when it was held and is answered
            // once, here.
            unsafe {
                ffi::webkit_policy_decision_use(*decision);
                ffi::g_object_unref(decision.cast());
            }
        }
        held.len()
    }

    /// Refuses the navigations a popup still holds: its host went away.
    pub(crate) fn drop_held_navigations(&self) {
        let held = self.state.borrow_mut().navigations.release();
        for (decision, _) in held {
            // SAFETY: as in `resume_navigations`.
            unsafe {
                ffi::webkit_policy_decision_ignore(decision);
                ffi::g_object_unref(decision.cast());
            }
        }
    }

    fn release_spelling(&self) {
        let entries = std::mem::take(&mut self.state.borrow_mut().spelling);
        for (_, item) in entries {
            // SAFETY: each entry holds the reference taken when it was kept.
            unsafe { ffi::g_object_unref(item.cast()) };
        }
    }

    /// Runs WebKit's own action for a spelling entry of the last context
    /// menu. `false` when that menu had no such entry.
    pub(crate) fn fix_spelling(&self, fix: SpellingFix) -> bool {
        let item = {
            let state = self.state.borrow();
            let mut guesses = state
                .spelling
                .iter()
                .filter(|(entry, _)| *entry == SpellingEntry::Guess);
            let found = match fix {
                SpellingFix::Guess(index) => guesses.nth(index),
                SpellingFix::Ignore => state
                    .spelling
                    .iter()
                    .find(|(entry, _)| *entry == SpellingEntry::Ignore),
                SpellingFix::Learn => state
                    .spelling
                    .iter()
                    .find(|(entry, _)| *entry == SpellingEntry::Learn),
            };
            found.map(|(_, item)| *item)
        };
        let Some(item) = item else {
            return false;
        };
        // SAFETY: the kept reference holds the item; its action belongs to
        // it. WebKit attached the page to the action when the menu signal
        // returned, and ignores an activation after that menu was replaced.
        unsafe {
            let action = webkit_context_menu_item_get_gaction(item);
            if action.is_null() {
                return false;
            }
            g_action_activate(action, core::ptr::null_mut());
        }
        // One word is fixed once.
        self.release_spelling();
        true
    }

    pub(crate) fn has_close_request(&self) -> bool {
        self.state.borrow().close_requested
    }

    /// Releases held popups that closed themselves, reporting each.
    pub(crate) fn reap_closed_popups(&self) {
        let closed: Vec<_> = {
            let mut state = self.state.borrow_mut();
            let mut closed = Vec::new();
            let mut index = 0;
            while index < state.popups.len() {
                if state.popups[index].1.page_closed() {
                    closed.push(state.popups.remove(index));
                } else {
                    index += 1;
                }
            }
            closed
        };
        for (id, popup) in closed {
            drop(popup);
            self.push(PageEvent::PopupClosed { id });
        }
    }

    pub(crate) fn discard_popup(&self, id: PageRequestId) -> bool {
        let popup = {
            let mut state = self.state.borrow_mut();
            let Some(index) = state.popups.iter().position(|(popup, _)| *popup == id) else {
                return false;
            };
            state.popups.remove(index)
        };
        drop(popup);
        self.push(PageEvent::PopupClosed { id });
        true
    }

    /// Whether the host takes a prompt of `kind`: it opted in and has fewer
    /// than [`MAX_PENDING_PROMPTS`] of that kind waiting. A refusal is
    /// reported as [`PageEvent::PromptDeclined`].
    fn admit(&self, kind: DeclinedPrompt) -> bool {
        let admitted = {
            let state = self.state.borrow();
            let prompts = state.prompts;
            let open = state
                .pending
                .iter()
                .filter(|(_, p)| p.kind() == kind)
                .count();
            open < MAX_PENDING_PROMPTS
                && match kind {
                    DeclinedPrompt::ScriptDialog => prompts.script_dialogs,
                    DeclinedPrompt::FileChooser => prompts.file_chooser,
                    DeclinedPrompt::Authentication => prompts.authentication,
                    DeclinedPrompt::OptionMenu => prompts.option_menus,
                    DeclinedPrompt::ColorChooser => prompts.color_chooser,
                }
        };
        if !admitted {
            self.push(PageEvent::PromptDeclined(kind));
        }
        admitted
    }

    /// Holds an admitted prompt for the host.
    fn hold(&self, pending: Pending) -> PageRequestId {
        let id = self.mint();
        self.state.borrow_mut().pending.push((id, pending));
        id
    }

    pub(crate) fn set_popup_policy(&self, policy: crate::web::WebPolicy) {
        let mut state = self.state.borrow_mut();
        if let Some(template) = &mut state.popup_template {
            template.policy = policy.clone();
        }
        state.popup_policy = Some(policy);
    }

    pub(crate) fn popup_policy(&self) -> Option<crate::web::WebPolicy> {
        self.state.borrow().popup_policy.clone()
    }

    pub(crate) fn set_popup_template(&self, template: Option<PopupTemplate>) {
        self.state.borrow_mut().popup_template = template;
    }

    /// Opens a popup the policy allowed as a real view related to `opener`,
    /// when the host asked for that. Returns the view for WebKit (with the
    /// reference `create` transfers) or NULL, in which case the host was told
    /// of the request as [`PageEvent::PopupRequested`].
    pub(crate) fn open_popup(
        this: &Rc<Self>,
        opener: *mut ffi::WebKitWebView,
        url: PolicyUrl,
        user_initiated: bool,
    ) -> *mut ffi::WebKitWebView {
        let template = {
            let state = this.state.borrow();
            state
                .popup_template
                .clone()
                .filter(|_| state.popups.len() < MAX_PENDING_POPUPS)
        };
        let Some(template) = template else {
            this.push(PageEvent::PopupRequested {
                url,
                user_initiated,
            });
            return core::ptr::null_mut();
        };
        match crate::ffi::runtime::WebSession::open_popup(&template, opener, this) {
            Ok(popup) => {
                // The session keeps the view's only reference. `create` is
                // annotated transfer-full, but WebKit never releases what it
                // is handed (WPE's MiniBrowser returns its only reference
                // too); an extra reference here leaked every popup.
                let view = popup.raw_web_view();
                let id = this.mint();
                this.state.borrow_mut().popups.push((id, popup));
                this.push(PageEvent::PopupOpened {
                    id,
                    url,
                    user_initiated,
                });
                view
            }
            Err(_) => {
                this.push(PageEvent::PopupRequested {
                    url,
                    user_initiated,
                });
                core::ptr::null_mut()
            }
        }
    }

    pub(crate) fn take_popup(&self, id: PageRequestId) -> Option<crate::ffi::runtime::WebSession> {
        let mut state = self.state.borrow_mut();
        let index = state.popups.iter().position(|(popup, _)| *popup == id)?;
        Some(state.popups.remove(index).1)
    }

    /// Drops every popup the host never took.
    pub(crate) fn release_popups(&self) {
        let popups = std::mem::take(&mut self.state.borrow_mut().popups);
        drop(popups);
    }

    pub(crate) fn set_download_dir(&self, dir: Option<std::path::PathBuf>) {
        self.state.borrow_mut().downloads_dir = dir;
    }

    /// Takes over a download the policy allowed for this view: its file goes
    /// into the host's download directory. `false` (and nothing connected)
    /// when the host set no directory or the session already runs
    /// [`MAX_ACTIVE_DOWNLOADS`]; the caller then cancels it.
    pub(crate) fn adopt_download(
        this: &Rc<Self>,
        download: *mut ffi::WebKitDownload,
        url: &str,
    ) -> bool {
        {
            let state = this.state.borrow();
            if state.downloads_dir.is_none() || state.downloads.len() >= MAX_ACTIVE_DOWNLOADS {
                return false;
            }
        }
        let id = this.mint();
        let data = Box::into_raw(Box::new(DownloadData {
            hub: Rc::downgrade(this),
            id,
        }));
        type W = *mut ffi::WebKitDownload;
        type D = *mut c_void;
        let signals: [(&'static str, extern "C" fn()); 4] = [
            (
                "decide-destination",
                callback!(
                    on_download_destination,
                    fn(W, *const c_char, D) -> ffi::GBoolean
                ),
            ),
            ("received-data", callback!(on_download_data, fn(W, u64, D))),
            (
                "failed",
                callback!(on_download_failed, fn(W, *mut ffi::GError, D)),
            ),
            ("finished", callback!(on_download_finished, fn(W, D))),
        ];
        let mut binder = super::signal::SignalBinder::new();
        let mut handlers = Vec::with_capacity(signals.len());
        for (name, f) in signals {
            // SAFETY: each callback matches `name`'s ABI on WebKitDownload, and
            // `data` lives until the slot is released.
            match unsafe { binder.connect(download.cast(), name, f, data.cast()) } {
                Ok(id) => handlers.push(id),
                Err(_) => {
                    // SAFETY: the binder disconnected what it connected.
                    drop(unsafe { Box::from_raw(data) });
                    return false;
                }
            }
        }
        // SAFETY: the slot's reference keeps the download live until release.
        unsafe { ffi::g_object_ref(download.cast()) };
        this.state.borrow_mut().downloads.push(DownloadSlot {
            id,
            download,
            data,
            handlers,
            url: PolicyUrl::new(url.to_owned()),
            path: None,
            failure: None,
            reported: 0,
            response: None,
            reserved: None,
            partial: None,
            pause_requested: false,
        });
        this.push(PageEvent::DownloadRequested {
            id,
            url: PolicyUrl::new(url),
        });
        true
    }

    pub(crate) fn pause_download(&self, id: PageRequestId) -> bool {
        let download = {
            let mut state = self.state.borrow_mut();
            let Some(slot) = state.downloads.iter_mut().find(|slot| slot.id == id) else {
                return false;
            };
            if slot.partial.is_none()
                || !slot
                    .response
                    .as_ref()
                    .is_some_and(crate::page::DownloadResponse::resumable)
            {
                return false;
            }
            if slot
                .partial
                .as_ref()
                .and_then(|file| file.metadata().ok())
                .zip(slot.response.as_ref().and_then(|r| r.length))
                .is_some_and(|(meta, total)| meta.len() >= total)
            {
                return false;
            }
            slot.pause_requested = true;
            slot.download
        };
        // SAFETY: the hub retains this owner-thread download; the borrow ended before cancellation can reenter callbacks.
        unsafe { ffi::webkit_download_cancel(download) };
        true
    }
    pub(crate) fn cancel_download(&self, id: PageRequestId) -> bool {
        let download = self
            .state
            .borrow()
            .downloads
            .iter()
            .find(|slot| slot.id == id)
            .map(|slot| slot.download);
        match download {
            Some(download) => {
                // SAFETY: the slot holds a reference; cancelling emits
                // `failed` and `finished`, which release the slot.
                unsafe { ffi::webkit_download_cancel(download) };
                true
            }
            None => false,
        }
    }

    fn take_download(&self, id: PageRequestId) -> Option<DownloadSlot> {
        let mut state = self.state.borrow_mut();
        let index = state.downloads.iter().position(|slot| slot.id == id)?;
        Some(state.downloads.remove(index))
    }

    /// Cancels every running download and removes its partial file, with
    /// its handlers disconnected first so no event outlives the session.
    pub(crate) fn release_all_downloads(&self) {
        let slots = std::mem::take(&mut self.state.borrow_mut().downloads);
        for slot in slots {
            let path = slot.path.clone();
            // SAFETY: the slot owns its reference, handlers and data.
            unsafe {
                release_slot(slot, true);
            }
            if let Some(path) = path {
                let _ = std::fs::remove_file(path);
            }
        }
    }

    fn take_pending(&self, id: PageRequestId) -> Option<Pending> {
        let mut state = self.state.borrow_mut();
        let index = state
            .pending
            .iter()
            .position(|(pending, _)| *pending == id)?;
        Some(state.pending.remove(index).1)
    }

    fn take_all_pending(&self) -> Vec<Pending> {
        self.state
            .borrow_mut()
            .pending
            .drain(..)
            .map(|(_, pending)| pending)
            .collect()
    }
}

/// Why the host's answer was not applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AnswerError {
    /// No prompt with that id is waiting (answered, declined at teardown, or
    /// never this session's).
    Unknown,
    /// The id names a different kind of prompt.
    WrongKind,
    /// A file path is not absolute or is not valid text.
    InvalidPath,
    /// Credentials contain a NUL byte; the challenge remains pending.
    InvalidCredentials,
}

impl std::fmt::Display for AnswerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Unknown => "no such prompt is waiting",
            Self::WrongKind => "the answer is for another kind of prompt",
            Self::InvalidPath => "a chosen file path is not an absolute UTF-8 path",
            Self::InvalidCredentials => "authentication credentials contain a NUL byte",
        })
    }
}

impl std::error::Error for AnswerError {}

/// Boxed callback data for every page signal; freed after disconnection.
struct SignalData {
    hub: Rc<PageHub>,
}

struct SecretScriptState {
    value: RefCell<Option<Result<SecretText, ScriptError>>>,
    hub: Weak<PageHub>,
    generation: u64,
    navigation_intent: u64,
}

/// An isolated evaluation whose JSON result never enters the public event queue.
///
/// Dropping the handle discards unconsumed protected results. Navigation and
/// session destruction cancel it, including a host navigation not yet committed.
/// The handle is owner-thread-only, like its originating session.
pub struct SecretScriptJob {
    state: Rc<SecretScriptState>,
    finished: bool,
}
impl std::fmt::Debug for SecretScriptJob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretScriptJob([redacted])")
    }
}
impl SecretScriptJob {
    /// Takes the protected JSON once, or returns `None` while still pending.
    ///
    /// Errors contain no page-supplied exception text. A cancelled result is
    /// returned once when the document or session is no longer current.
    pub fn take(&mut self) -> Option<Result<SecretText, ScriptError>> {
        if self.finished {
            return None;
        }
        let valid = self.state.hub.upgrade().is_some_and(|hub| {
            hub.state.borrow().load_generation == self.state.generation
                && hub.navigation_intent() == self.state.navigation_intent
        });
        let result = if valid {
            self.state.value.borrow_mut().take()
        } else {
            self.state.value.borrow_mut().take();
            Some(Err(ScriptError::Cancelled))
        };
        self.finished = result.is_some();
        result
    }
}

type ScriptReply = RefCell<Option<Result<String, ScriptError>>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NativeDocumentReadiness {
    Ready,
    Busy,
    Unavailable,
    Failed,
}
fn decode_native_readiness(name: Option<&str>, has_error: bool) -> NativeDocumentReadiness {
    if has_error {
        return NativeDocumentReadiness::Failed;
    }
    match name {
        Some("enzui-document-ready-v1") => NativeDocumentReadiness::Ready,
        Some("enzui-document-busy-v1") => NativeDocumentReadiness::Busy,
        Some("enzui-document-probe-unavailable-v1") => NativeDocumentReadiness::Unavailable,
        _ => NativeDocumentReadiness::Failed,
    }
}

type NativeReadinessReply = RefCell<Option<NativeDocumentReadiness>>;

static NATIVE_READINESS_UNAVAILABLE: AtomicBool = AtomicBool::new(false);

// Native callbacks retain this allocation after the session can be dropped.
struct AsyncData {
    preview: bool,
    hub: Weak<PageHub>,
    id: PageRequestId,
    private_reply: Option<Weak<ScriptReply>>,
    secret_reply: Option<Weak<SecretScriptState>>,
}

/// The most script message handlers one session registers.
pub const MAX_MESSAGE_HANDLERS: usize = 16;

/// Data for one `script-message-received::NAME` handler: the signal does not
/// pass the name, so each registration carries its own.
struct MessageData {
    hub: Rc<PageHub>,
    name: String,
    secret: bool,
    frame_scoped: bool,
}

struct MessageHandler {
    name: CString,
    world: Option<CString>,
    handler: u64,
    data: *mut MessageData,
}

// The manager is live and the handler is removed from its owning binding.
unsafe fn release_message_handler(content: *mut WebKitUserContentManager, handler: MessageHandler) {
    // SAFETY: disconnection precedes releasing callback data owned by this registration.
    unsafe {
        ffi::g_signal_handler_disconnect(content.cast(), handler.handler);
        webkit_user_content_manager_unregister_script_message_handler(
            content,
            handler.name.as_ptr(),
            handler
                .world
                .as_ref()
                .map_or(core::ptr::null(), |w| w.as_ptr()),
        );
        drop(Box::from_raw(handler.data));
    }
}

/// The page signal handlers on one WebView.
pub(crate) struct PageBinding {
    web_view: *mut ffi::WebKitWebView,
    find: *mut WebKitFindController,
    content: *mut WebKitUserContentManager,
    hub: Rc<PageHub>,
    data: *mut SignalData,
    view_handlers: Vec<u64>,
    find_handlers: Vec<u64>,
    message_handlers: Vec<MessageHandler>,
    evaluation_worlds: RefCell<HashMap<CString, *mut WebKitUserScript>>,
    content_injections: RefCell<HashMap<u64, ContentInjection>>,
    next_content_injection: Cell<u64>,
    cancellable: *mut c_void,
}

/// A host-owned reference to one installed content script or style.
enum ContentInjection {
    Script(*mut WebKitUserScript),
    Style(*mut WebKitUserStyleSheet),
}

/// A validated, NUL-terminated pattern list for WebKit; NULL when empty.
struct PatternList {
    _owned: Vec<CString>,
    pointers: Vec<*const c_char>,
}

impl PatternList {
    fn new(patterns: &[String]) -> Result<Self, crate::page::ContentInjectionError> {
        use crate::page::{ContentInjectionError, MAX_CONTENT_PATTERN_BYTES, MAX_CONTENT_PATTERNS};
        if patterns.len() > MAX_CONTENT_PATTERNS {
            return Err(ContentInjectionError::TooManyPatterns);
        }
        let owned = patterns
            .iter()
            .map(|pattern| {
                if pattern.len() > MAX_CONTENT_PATTERN_BYTES || !pattern.contains("://") {
                    return Err(ContentInjectionError::InvalidPattern);
                }
                CString::new(pattern.as_str()).map_err(|_| ContentInjectionError::InvalidPattern)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut pointers: Vec<*const c_char> = owned.iter().map(|value| value.as_ptr()).collect();
        pointers.push(core::ptr::null());
        Ok(Self {
            _owned: owned,
            pointers,
        })
    }

    fn as_ptr(&self) -> *const *const c_char {
        if self.pointers.len() == 1 {
            core::ptr::null()
        } else {
            self.pointers.as_ptr()
        }
    }
}

impl PageBinding {
    /// Connects every page signal on `web_view`, or none.
    pub(crate) fn new(
        web_view: *mut ffi::WebKitWebView,
        hub: Rc<PageHub>,
    ) -> Result<Self, super::signal::SignalBindError> {
        let data = Box::into_raw(Box::new(SignalData {
            hub: Rc::clone(&hub),
        }));
        // SAFETY: borrowed from the live view, which owns them.
        let (find, content) = unsafe {
            (
                webkit_web_view_get_find_controller(web_view),
                webkit_web_view_get_user_content_manager(web_view),
            )
        };
        type V = *mut ffi::WebKitWebView;
        type D = *mut c_void;
        let view_signals: [(&'static str, extern "C" fn()); 21] = [
            (
                "show-option-menu",
                callback!(
                    on_show_option_menu,
                    fn(V, *mut WebKitOptionMenu, *mut WebKitRectangle, D) -> ffi::GBoolean
                ),
            ),
            ("ready-to-show", callback!(on_ready_to_show, fn(V, D))),
            ("run-as-modal", callback!(on_run_as_modal, fn(V, D))),
            (
                "enter-fullscreen",
                callback!(on_enter_fullscreen, fn(V, D) -> ffi::GBoolean),
            ),
            (
                "leave-fullscreen",
                callback!(on_leave_fullscreen, fn(V, D) -> ffi::GBoolean),
            ),
            (
                "show-notification",
                callback!(
                    on_show_notification,
                    fn(V, *mut WebKitNotification, D) -> ffi::GBoolean
                ),
            ),
            (
                "query-permission-state",
                callback!(
                    on_query_permission_state,
                    fn(V, *mut WebKitPermissionStateQuery, D) -> ffi::GBoolean
                ),
            ),
            (
                "insecure-content-detected",
                callback!(on_insecure_content, fn(V, c_int, D)),
            ),
            (
                "mouse-target-changed",
                callback!(
                    on_mouse_target_changed,
                    fn(V, *mut WebKitHitTestResult, c_uint, D)
                ),
            ),
            (
                "web-process-terminated",
                callback!(on_web_process_terminated, fn(V, c_int, D)),
            ),
            ("load-changed", callback!(on_load_changed, fn(V, c_int, D))),
            (
                "load-failed",
                callback!(
                    on_load_failed,
                    fn(V, c_int, *const c_char, *mut ffi::GError, D) -> ffi::GBoolean
                ),
            ),
            (
                "notify::uri",
                callback!(on_notify_uri, fn(*mut c_void, *mut GParamSpec, D)),
            ),
            (
                "notify::title",
                callback!(on_notify_title, fn(*mut c_void, *mut GParamSpec, D)),
            ),
            (
                "notify::estimated-load-progress",
                callback!(on_notify_progress, fn(*mut c_void, *mut GParamSpec, D)),
            ),
            (
                "notify::is-playing-audio",
                callback!(on_notify_playing_audio, fn(*mut c_void, *mut GParamSpec, D)),
            ),
            (
                "script-dialog",
                callback!(
                    on_script_dialog,
                    fn(V, *mut WebKitScriptDialog, D) -> ffi::GBoolean
                ),
            ),
            (
                "run-file-chooser",
                callback!(
                    on_file_chooser,
                    fn(V, *mut WebKitFileChooserRequest, D) -> ffi::GBoolean
                ),
            ),
            (
                "authenticate",
                callback!(
                    on_authenticate,
                    fn(V, *mut ffi::WebKitAuthenticationRequest, D) -> ffi::GBoolean
                ),
            ),
            ("close", callback!(on_close, fn(V, D))),
            (
                "context-menu",
                callback!(
                    on_context_menu,
                    fn(V, *mut WebKitContextMenu, *mut WebKitHitTestResult, D) -> ffi::GBoolean
                ),
            ),
        ];
        let find_signals: [(&'static str, extern "C" fn()); 3] = [
            (
                "found-text",
                callback!(on_found_text, fn(*mut WebKitFindController, c_uint, D)),
            ),
            (
                "failed-to-find-text",
                callback!(on_failed_to_find, fn(*mut WebKitFindController, D)),
            ),
            (
                "counted-matches",
                callback!(on_counted_matches, fn(*mut WebKitFindController, c_uint, D)),
            ),
        ];
        let mut binder = super::signal::SignalBinder::new();
        let connected = (|| {
            let mut view_handlers = Vec::with_capacity(view_signals.len());
            for (name, f) in view_signals {
                // SAFETY: each callback matches `name`'s ABI and `data` lives
                // until Drop disconnects.
                view_handlers
                    .push(unsafe { binder.connect(web_view.cast(), name, f, data.cast())? });
            }
            // Only a runtime that has the colour chooser has its signal.
            if color_chooser::api().is_some() {
                let chooser = callback!(
                    on_color_chooser,
                    fn(V, *mut WebKitColorChooserRequest, D) -> ffi::GBoolean
                );
                // SAFETY: as above; the callback matches `run-color-chooser`.
                view_handlers.push(unsafe {
                    binder.connect(web_view.cast(), "run-color-chooser", chooser, data.cast())?
                });
            }
            let mut find_handlers = Vec::with_capacity(find_signals.len());
            for (name, f) in find_signals {
                // SAFETY: as above, on the view's find controller.
                find_handlers.push(unsafe { binder.connect(find.cast(), name, f, data.cast())? });
            }
            Ok((view_handlers, find_handlers))
        })();
        let (view_handlers, find_handlers) = match connected {
            Ok(handlers) => handlers,
            Err(error) => {
                // SAFETY: the binder disconnected everything; nothing holds
                // `data`.
                drop(unsafe { Box::from_raw(data) });
                return Err(error);
            }
        };
        // SAFETY: a fresh cancellable, owned by this binding.
        let cancellable = unsafe { ffi::g_cancellable_new() };
        Ok(Self {
            web_view,
            find,
            content,
            hub,
            data,
            view_handlers,
            find_handlers,
            message_handlers: Vec::new(),
            evaluation_worlds: RefCell::default(),
            content_injections: RefCell::default(),
            next_content_injection: Cell::new(1),
            cancellable,
        })
    }

    /// Declines every prompt still waiting for the host, as teardown does.
    /// Returns how many there were.
    pub(crate) fn decline_pending(&self) -> usize {
        let pending = self.hub.take_all_pending();
        let count = pending.len() + self.hub.cancel_site_permissions();
        for pending in pending {
            // SAFETY: each pending object holds its own reference.
            unsafe { pending.decline() };
        }
        count
    }

    pub(crate) fn answer_option_menu(
        &self,
        id: PageRequestId,
        choice: Option<usize>,
    ) -> Result<(), AnswerError> {
        match self.hub.take_pending(id) {
            Some(Pending::Menu(menu, handler, data)) => {
                // SAFETY: the held reference keeps the menu live.
                let choice = choice.and_then(|index| {
                    let count = unsafe { webkit_option_menu_get_n_items(menu) } as usize;
                    (index < count).then_some(index as c_uint)
                });
                // SAFETY: taken from the hub, so released once.
                unsafe { finish_menu(menu, handler, data, choice) };
                Ok(())
            }
            Some(other) => self.restore(id, other),
            None => Err(AnswerError::Unknown),
        }
    }

    pub(crate) fn answer_script_dialog(
        &self,
        id: PageRequestId,
        answer: &ScriptDialogAnswer,
    ) -> Result<(), AnswerError> {
        match self.hub.take_pending(id) {
            Some(Pending::Dialog(dialog, kind)) => {
                // SAFETY: the held reference keeps `dialog` live. Closing runs
                // the page's completion; the unref releases the reference.
                unsafe {
                    set_dialog_answer(dialog, kind, answer, false);
                    webkit_script_dialog_close(dialog);
                    webkit_script_dialog_unref(dialog);
                }
                Ok(())
            }
            Some(other) => self.restore(id, other),
            None => Err(AnswerError::Unknown),
        }
    }

    /// Shows `color` in the page while the person is still choosing; the
    /// request stays open.
    pub(crate) fn preview_color(
        &self,
        id: PageRequestId,
        color: [u8; 4],
    ) -> Result<(), AnswerError> {
        let state = self.hub.state.borrow();
        match state.pending.iter().find(|(pending, _)| *pending == id) {
            Some((_, Pending::Color(request))) => {
                let Some(api) = color_chooser::api() else {
                    return Err(AnswerError::Unknown);
                };
                // SAFETY: the held reference keeps `request` live.
                unsafe {
                    let alpha = (api.get_supports_alpha)(*request) != 0;
                    (api.set_color)(*request, &native_color(color, alpha));
                }
                Ok(())
            }
            Some(_) => Err(AnswerError::WrongKind),
            None => Err(AnswerError::Unknown),
        }
    }

    pub(crate) fn answer_color_chooser(
        &self,
        id: PageRequestId,
        color: Option<[u8; 4]>,
    ) -> Result<(), AnswerError> {
        match self.hub.take_pending(id) {
            Some(Pending::Color(request)) => {
                // SAFETY: the held reference keeps `request` live; it is
                // finished or cancelled once and released.
                unsafe {
                    if let Some(api) = color_chooser::api() {
                        match color {
                            Some(color) => {
                                let alpha = (api.get_supports_alpha)(request) != 0;
                                (api.set_color)(request, &native_color(color, alpha));
                                (api.finish)(request);
                            }
                            None => (api.cancel)(request),
                        }
                    }
                    ffi::g_object_unref(request.cast());
                }
                Ok(())
            }
            Some(other) => self.restore(id, other),
            None => Err(AnswerError::Unknown),
        }
    }

    pub(crate) fn answer_file_chooser(
        &self,
        id: PageRequestId,
        files: Option<&[std::path::PathBuf]>,
    ) -> Result<(), AnswerError> {
        let paths = match files {
            Some(files) => {
                let mut paths = Vec::with_capacity(files.len());
                for file in files {
                    let text = file.to_str().filter(|_| file.is_absolute());
                    let Some(text) = text.and_then(|text| CString::new(text).ok()) else {
                        return Err(AnswerError::InvalidPath);
                    };
                    paths.push(text);
                }
                Some(paths)
            }
            None => None,
        };
        match self.hub.take_pending(id) {
            Some(Pending::Chooser(request)) => {
                // SAFETY: the held reference keeps `request` live; the path
                // array is NULL-terminated and outlives the call.
                unsafe {
                    match &paths {
                        Some(paths) if !paths.is_empty() => {
                            let mut pointers: Vec<*const c_char> =
                                paths.iter().map(|path| path.as_ptr()).collect();
                            let multiple =
                                webkit_file_chooser_request_get_select_multiple(request) != 0;
                            if !multiple {
                                pointers.truncate(1);
                            }
                            pointers.push(core::ptr::null());
                            webkit_file_chooser_request_select_files(request, pointers.as_ptr());
                        }
                        _ => webkit_file_chooser_request_cancel(request),
                    }
                    ffi::g_object_unref(request.cast());
                }
                Ok(())
            }
            Some(other) => self.restore(id, other),
            None => Err(AnswerError::Unknown),
        }
    }

    pub(crate) fn answer_authentication(
        &self,
        id: PageRequestId,
        answer: &AuthAnswer,
    ) -> Result<(), AnswerError> {
        if let AuthAnswer::Credentials { user, password } = answer
            && (user.contains('\0') || password.expose_secret().contains('\0'))
        {
            return Err(AnswerError::InvalidCredentials);
        }
        match self.hub.take_pending(id) {
            Some(Pending::Challenge(request)) => {
                // SAFETY: the held reference keeps `request` live. Zero is
                // WEBKIT_CREDENTIAL_PERSISTENCE_NONE: nothing reaches disk.
                unsafe {
                    match answer {
                        AuthAnswer::Credentials { user, password } => {
                            let user = CString::new(user.as_str()).expect("credentials validated");
                            // Straight into one owned buffer that is wiped
                            // after use; a NUL cannot be sent, so refuse.
                            // Room for the terminator up front: `CString::new` would
                            // otherwise grow the Vec and free the first copy unwiped.
                            let mut buffer = Vec::with_capacity(password.expose_secret().len() + 1);
                            buffer.extend_from_slice(password.expose_secret().as_bytes());
                            match CString::new(buffer) {
                                Ok(password) => {
                                    let credential = ffi::webkit_credential_new(
                                        user.as_ptr(),
                                        password.as_ptr(),
                                        0,
                                    );
                                    if credential.is_null() {
                                        webkit_authentication_request_cancel(request);
                                    } else {
                                        ffi::webkit_authentication_request_authenticate(
                                            request, credential,
                                        );
                                        ffi::webkit_credential_free(credential);
                                    }
                                    let mut bytes = password.into_bytes();
                                    enzui_security::secret::wipe_bytes(&mut bytes);
                                }
                                Err(error) => {
                                    let mut bytes = error.into_vec();
                                    enzui_security::secret::wipe_bytes(&mut bytes);
                                    webkit_authentication_request_cancel(request);
                                }
                            }
                        }
                        AuthAnswer::Cancel => webkit_authentication_request_cancel(request),
                    }
                    ffi::g_object_unref(request.cast());
                }
                Ok(())
            }
            Some(other) => self.restore(id, other),
            None => Err(AnswerError::Unknown),
        }
    }

    fn restore(&self, id: PageRequestId, pending: Pending) -> Result<(), AnswerError> {
        self.hub.state.borrow_mut().pending.push((id, pending));
        Err(AnswerError::WrongKind)
    }

    pub(crate) fn evaluate(
        &self,
        script: &str,
        world: &ScriptWorld,
    ) -> Result<PageRequestId, ScriptInputError> {
        self.evaluate_with_reply(script, world, None, false)
    }

    pub(crate) fn evaluate_secret(
        &self,
        source: &SecretText,
        world_name: &str,
    ) -> Result<SecretScriptJob, ScriptInputError> {
        let world = ScriptWorld::Isolated(world_name.to_owned());
        let world = script_world_name(&world)?;
        if let Some(name) = &world {
            self.ensure_evaluation_world(name)?;
        }
        let state = Rc::new(SecretScriptState {
            value: RefCell::new(None),
            hub: Rc::downgrade(&self.hub),
            generation: self.hub.state.borrow().load_generation,
            navigation_intent: self.hub.navigation_intent(),
        });
        let data = Box::into_raw(Box::new(AsyncData {
            preview: false,
            hub: Rc::downgrade(&self.hub),
            id: self.hub.mint(),
            private_reply: None,
            secret_reply: Some(Rc::downgrade(&state)),
        }));
        let source = source.expose_secret();
        // SAFETY: the live view copies the length-delimited source/world; its
        // cancellable callback reclaims data exactly once, even after view drop.
        unsafe {
            webkit_web_view_evaluate_javascript(
                self.web_view,
                source.as_ptr().cast(),
                source.len() as isize,
                world.as_ref().map_or(core::ptr::null(), |w| w.as_ptr()),
                core::ptr::null(),
                self.cancellable,
                on_script_finished,
                data.cast(),
            );
        }
        Ok(SecretScriptJob {
            state,
            finished: false,
        })
    }

    pub(crate) fn evaluate_preview(
        &self,
        script: &str,
        world: &ScriptWorld,
    ) -> Result<PageRequestId, ScriptInputError> {
        self.evaluate_with_reply(script, world, None, true)
    }

    pub(crate) fn native_document_readiness(&self) -> Rc<NativeReadinessReply> {
        let reply = Rc::new(RefCell::new(None));
        if NATIVE_READINESS_UNAVAILABLE.load(Ordering::Relaxed) {
            *reply.borrow_mut() = Some(NativeDocumentReadiness::Unavailable);
            return reply;
        }
        // SAFETY: the constant name is NUL-terminated and no payload is supplied.
        let message = unsafe {
            ffi::webkit_user_message_new(c"enzui-document-probe-v1".as_ptr(), core::ptr::null_mut())
        };
        if message.is_null() {
            *reply.borrow_mut() = Some(NativeDocumentReadiness::Failed);
            return reply;
        }
        let data = Box::into_raw(Box::new(Rc::downgrade(&reply)));
        // SAFETY: sending consumes the floating message; the task owns its source view
        // and reclaims data once through the callback, including cancellation.
        unsafe {
            ffi::webkit_web_view_send_message_to_page(
                self.web_view,
                message,
                self.cancellable,
                Some(on_native_readiness_finished),
                data.cast(),
            );
        }
        reply
    }

    /// Run an async function body once in `world`, answering with a preview
    /// `ScriptResult` after its Promise settles.
    pub(crate) fn evaluate_async_preview(
        &self,
        body: &str,
        world: &ScriptWorld,
    ) -> Result<PageRequestId, ScriptInputError> {
        let world = script_world_name(world)?;
        if let Some(name) = &world {
            self.ensure_evaluation_world(name)?;
        }
        let id = self.hub.mint();
        let data = Box::into_raw(Box::new(AsyncData {
            preview: true,
            hub: Rc::downgrade(&self.hub),
            id,
            private_reply: None,
            secret_reply: None,
        }));
        // SAFETY: WebKit copies the length-delimited body and world name; the
        // callback reclaims data once, including cancellation after session drop.
        unsafe {
            webkit_web_view_call_async_javascript_function(
                self.web_view,
                body.as_ptr().cast(),
                body.len() as isize,
                core::ptr::null_mut(),
                world.as_ref().map_or(core::ptr::null(), |w| w.as_ptr()),
                core::ptr::null(),
                self.cancellable,
                on_async_script_finished,
                data.cast(),
            );
        }
        Ok(id)
    }

    pub(crate) fn call_private_async(
        &self,
        body: &str,
        world: &ScriptWorld,
    ) -> Result<Rc<ScriptReply>, ScriptInputError> {
        let world = script_world_name(world)?;
        if let Some(name) = &world {
            self.ensure_evaluation_world(name)?;
        }
        let reply = Rc::new(RefCell::new(None));
        let data = Box::into_raw(Box::new(AsyncData {
            preview: false,
            hub: Rc::downgrade(&self.hub),
            id: self.hub.mint(),
            private_reply: Some(Rc::downgrade(&reply)),
            secret_reply: None,
        }));
        // SAFETY: WebKit copies the length-delimited body and world name; the
        // callback reclaims data once, including cancellation after session drop.
        unsafe {
            webkit_web_view_call_async_javascript_function(
                self.web_view,
                body.as_ptr().cast(),
                body.len() as isize,
                core::ptr::null_mut(),
                world.as_ref().map_or(core::ptr::null(), |w| w.as_ptr()),
                core::ptr::null(),
                self.cancellable,
                on_async_script_finished,
                data.cast(),
            );
        }
        Ok(reply)
    }

    fn evaluate_with_reply(
        &self,
        script: &str,
        world: &ScriptWorld,
        private_reply: Option<Weak<ScriptReply>>,
        preview: bool,
    ) -> Result<PageRequestId, ScriptInputError> {
        let world = script_world_name(world)?;
        if let Some(name) = &world {
            self.ensure_evaluation_world(name)?;
        }
        let id = self.hub.mint();
        let data = Box::into_raw(Box::new(AsyncData {
            preview,
            hub: Rc::downgrade(&self.hub),
            id,
            private_reply,
            secret_reply: None,
        }));
        // SAFETY: the script is passed with its length (it may hold NULs); the
        // callback frees `data` exactly once, and runs even when cancelled.
        unsafe {
            webkit_web_view_evaluate_javascript(
                self.web_view,
                script.as_ptr().cast(),
                script.len() as isize,
                world.as_ref().map_or(core::ptr::null(), |w| w.as_ptr()),
                core::ptr::null(),
                self.cancellable,
                on_script_finished,
                data.cast(),
            );
        }
        Ok(id)
    }

    fn ensure_evaluation_world(&self, name: &CString) -> Result<(), ScriptInputError> {
        let mut worlds = self.evaluation_worlds.borrow_mut();
        if worlds.contains_key(name) {
            return Ok(());
        }
        // Bare evaluations use a weak native world registry. A user-script
        // owner registers and retains that identity without injecting content.
        // SAFETY: valid strings and enum values; the returned boxed script is
        // owned here, never added to the content manager, and unref'd in Drop.
        let anchor = unsafe {
            webkit_user_script_new_for_world(
                c"".as_ptr(),
                1,
                0,
                name.as_ptr(),
                core::ptr::null(),
                core::ptr::null(),
            )
        };
        if anchor.is_null() {
            return Err(ScriptInputError::WorldInitializationFailed);
        }
        worlds.insert(name.clone(), anchor);
        Ok(())
    }

    pub(crate) fn add_user_script(&self, script: &UserScript) -> Result<(), ScriptInputError> {
        self.install_user_script(script, None, None)
    }

    pub(crate) fn add_user_script_matching(
        &self,
        script: &UserScript,
        matches: &[String],
        excludes: &[String],
    ) -> Result<(), crate::page::ContentInjectionError> {
        use crate::page::ContentInjectionError;
        if matches.is_empty() {
            return Err(ContentInjectionError::NoMatches);
        }
        let allow = PatternList::new(matches)?;
        let block = PatternList::new(excludes)?;
        self.install_user_script(script, Some(&allow), Some(&block))
            .map_err(ContentInjectionError::Script)
    }

    fn install_user_script(
        &self,
        script: &UserScript,
        allow: Option<&PatternList>,
        block: Option<&PatternList>,
    ) -> Result<(), ScriptInputError> {
        let source = CString::new(script.source.as_str())
            .map_err(|_| ScriptInputError::SourceContainsNul)?;
        let world = script_world_name(&script.world)?;
        let frames = script_frames(script.frames);
        let timing = script_timing(script.timing);
        let allow = allow.map_or(core::ptr::null(), PatternList::as_ptr);
        let block = block.map_or(core::ptr::null(), PatternList::as_ptr);
        // SAFETY: source/world strings and NULL-terminated pattern lists outlive
        // the constructors, which copy them into the returned owned script.
        let native = unsafe {
            match &world {
                None => webkit_user_script_new(source.as_ptr(), frames, timing, allow, block),
                Some(name) => webkit_user_script_new_for_world(
                    source.as_ptr(),
                    frames,
                    timing,
                    name.as_ptr(),
                    allow,
                    block,
                ),
            }
        };
        if native.is_null() {
            return Err(ScriptInputError::WorldInitializationFailed);
        }
        // SAFETY: the live view owns the manager; it retains the script before
        // this constructor-owned reference is released exactly once.
        unsafe {
            webkit_user_content_manager_add_script(self.content, native);
            webkit_user_script_unref(native);
        }
        Ok(())
    }

    pub(crate) fn add_content_script(
        &self,
        script: &crate::page::ContentScript,
    ) -> Result<crate::page::ContentInjectionId, crate::page::ContentInjectionError> {
        use crate::page::ContentInjectionError;
        if script.matches.is_empty() {
            return Err(ContentInjectionError::NoMatches);
        }
        let source = CString::new(script.source.as_str())
            .map_err(|_| ContentInjectionError::Script(ScriptInputError::SourceContainsNul))?;
        let world = script_world_name(&ScriptWorld::Isolated(script.world.clone()))
            .map_err(ContentInjectionError::Script)?
            .expect("an isolated world has a name");
        let (allow, block) = (
            PatternList::new(&script.matches)?,
            PatternList::new(&script.excludes)?,
        );
        // SAFETY: every string and NULL-terminated list outlives the call; the
        // manager takes its own reference and this binding keeps one for removal.
        let native = unsafe {
            webkit_user_script_new_for_world(
                source.as_ptr(),
                script_frames(script.frames),
                script_timing(script.timing),
                world.as_ptr(),
                allow.as_ptr(),
                block.as_ptr(),
            )
        };
        if native.is_null() {
            return Err(ContentInjectionError::Script(
                ScriptInputError::WorldInitializationFailed,
            ));
        }
        // SAFETY: the manager is owned by the live view; `native` is live.
        unsafe { webkit_user_content_manager_add_script(self.content, native) };
        Ok(self.record_content_injection(ContentInjection::Script(native)))
    }

    pub(crate) fn add_user_style(
        &self,
        source: &str,
        frames: ScriptFrames,
    ) -> Result<crate::page::ContentInjectionId, crate::page::ContentInjectionError> {
        let source = CString::new(source).map_err(|_| {
            crate::page::ContentInjectionError::Script(ScriptInputError::SourceContainsNul)
        })?;
        // SAFETY: WebKit copies the source; null lists apply user-level CSS to every document.
        let native = unsafe {
            webkit_user_style_sheet_new(
                source.as_ptr(),
                script_frames(frames),
                0,
                core::ptr::null(),
                core::ptr::null(),
            )
        };
        if native.is_null() {
            return Err(crate::page::ContentInjectionError::Script(
                ScriptInputError::WorldInitializationFailed,
            ));
        }
        // SAFETY: the live manager retains this style; the binding owns its initial reference.
        unsafe { webkit_user_content_manager_add_style_sheet(self.content, native) };
        Ok(self.record_content_injection(ContentInjection::Style(native)))
    }

    pub(crate) fn add_content_style(
        &self,
        style: &crate::page::ContentStyle,
    ) -> Result<crate::page::ContentInjectionId, crate::page::ContentInjectionError> {
        use crate::page::ContentInjectionError;
        if style.matches.is_empty() {
            return Err(ContentInjectionError::NoMatches);
        }
        let source = CString::new(style.source.as_str())
            .map_err(|_| ContentInjectionError::Script(ScriptInputError::SourceContainsNul))?;
        let (allow, block) = (
            PatternList::new(&style.matches)?,
            PatternList::new(&style.excludes)?,
        );
        // SAFETY: as in `add_content_script`; level 0 is WEBKIT_USER_STYLE_LEVEL_USER.
        let native = unsafe {
            webkit_user_style_sheet_new(
                source.as_ptr(),
                script_frames(style.frames),
                0,
                allow.as_ptr(),
                block.as_ptr(),
            )
        };
        if native.is_null() {
            return Err(ContentInjectionError::Script(
                ScriptInputError::WorldInitializationFailed,
            ));
        }
        // SAFETY: the manager is owned by the live view; `native` is live.
        unsafe { webkit_user_content_manager_add_style_sheet(self.content, native) };
        Ok(self.record_content_injection(ContentInjection::Style(native)))
    }

    fn record_content_injection(
        &self,
        injection: ContentInjection,
    ) -> crate::page::ContentInjectionId {
        let id = self.next_content_injection.get();
        self.next_content_injection.set(id + 1);
        self.content_injections.borrow_mut().insert(id, injection);
        crate::page::ContentInjectionId(id)
    }

    /// Remove one content script or style from future documents; false if unknown.
    pub(crate) fn remove_content_injection(&self, id: crate::page::ContentInjectionId) -> bool {
        let Some(injection) = self.content_injections.borrow_mut().remove(&id.0) else {
            return false;
        };
        // SAFETY: the manager is owned by the live view and each reference is owned here.
        unsafe {
            match injection {
                ContentInjection::Script(script) => {
                    webkit_user_content_manager_remove_script(self.content, script);
                    webkit_user_script_unref(script);
                }
                ContentInjection::Style(sheet) => {
                    webkit_user_content_manager_remove_style_sheet(self.content, sheet);
                    webkit_user_style_sheet_unref(sheet);
                }
            }
        }
        true
    }

    pub(crate) fn remove_user_scripts(&self) {
        // SAFETY: the manager is owned by the live view.
        unsafe { webkit_user_content_manager_remove_all_scripts(self.content) };
    }

    /// Registers `window.webkit.messageHandlers.NAME`. `false` when WebKit
    /// refused (the name is already registered in that world), the signal
    /// did not connect, or the session already has
    /// [`MAX_MESSAGE_HANDLERS`].
    pub(crate) fn register_message_handler(&mut self, name: &str, world: &ScriptWorld) -> bool {
        self.register_handler(name, world, false, false)
    }
    pub(crate) fn register_secret_message_handler(&mut self, name: &str, world: &str) -> bool {
        self.register_handler(name, &ScriptWorld::Isolated(world.to_owned()), true, false)
    }
    pub(crate) fn register_frame_secret_message_handler(
        &mut self,
        name: &str,
        world: &str,
    ) -> bool {
        frame_secrets::available()
            && self.register_handler(name, &ScriptWorld::Isolated(world.to_owned()), true, true)
    }
    fn register_handler(
        &mut self,
        name: &str,
        world: &ScriptWorld,
        secret: bool,
        frame_scoped: bool,
    ) -> bool {
        let Ok(name_c) = CString::new(name) else {
            return false;
        };
        let Ok(world_c) = script_world_name(world) else {
            return false;
        };
        if let Some(existing) = self
            .message_handlers
            .iter()
            .find(|handler| handler.name == name_c)
        {
            // `script-message-received::NAME` does not say which world posted,
            // so one name lives in one world: the host can always tell a
            // trusted isolated-world post from a page-world one.
            // SAFETY: registration retains MessageData until disconnection.
            return existing.world == world_c
                && unsafe {
                    (*existing.data).secret == secret
                        && (*existing.data).frame_scoped == frame_scoped
                };
        }
        if self.message_handlers.len() >= MAX_MESSAGE_HANDLERS || name_c.as_bytes().is_empty() {
            return false;
        }
        let data = Box::into_raw(Box::new(MessageData {
            hub: Rc::clone(&self.hub),
            name: name_c.to_string_lossy().into_owned(),
            secret,
            frame_scoped,
        }));
        let signal = c_text(&format!(
            "script-message-received::{}",
            name_c.to_string_lossy()
        ));
        let handler = callback!(
            on_script_message,
            fn(*mut WebKitUserContentManager, *mut JSCValue, *mut c_void)
        );
        // SAFETY: the manager is live; the callback matches the signal ABI and
        // `data` lives until the handler is disconnected.
        let id = unsafe {
            ffi::g_signal_connect_data(
                self.content.cast(),
                signal.as_ptr(),
                handler,
                data.cast(),
                core::ptr::null_mut(),
                0,
            )
        };
        if super::signal::require_nonzero(id, "script-message-received").is_err() {
            // SAFETY: nothing was connected, so nothing holds `data`.
            drop(unsafe { Box::from_raw(data) });
            return false;
        }
        // SAFETY: as above.
        let registered = unsafe {
            webkit_user_content_manager_register_script_message_handler(
                self.content,
                name_c.as_ptr(),
                world_c.as_ref().map_or(core::ptr::null(), |w| w.as_ptr()),
            )
        } != 0;
        if !registered {
            // SAFETY: disconnect the handler just connected, then free its data.
            unsafe {
                ffi::g_signal_handler_disconnect(self.content.cast(), id);
                drop(Box::from_raw(data));
            }
            return false;
        }
        self.message_handlers.push(MessageHandler {
            name: name_c,
            world: world_c,
            handler: id,
            data,
        });
        true
    }

    pub(crate) fn unregister_message_handler(&mut self, name: &str, world: &ScriptWorld) -> bool {
        let Ok(name) = CString::new(name) else {
            return false;
        };
        let Ok(world) = script_world_name(world) else {
            return false;
        };
        let Some(index) = self
            .message_handlers
            .iter()
            .position(|handler| handler.name == name && handler.world == world)
        else {
            return false;
        };
        let handler = self.message_handlers.remove(index);
        // SAFETY: the live view owns the manager; the removed registration is released once.
        unsafe { release_message_handler(self.content, handler) };
        true
    }

    pub(crate) fn find(&self, text: &str, case_sensitive: bool, backwards: bool, max: u32) {
        let text = c_text(text);
        let mut options = WEBKIT_FIND_OPTIONS_WRAP_AROUND;
        if !case_sensitive {
            options |= WEBKIT_FIND_OPTIONS_CASE_INSENSITIVE;
        }
        if backwards {
            options |= WEBKIT_FIND_OPTIONS_BACKWARDS;
        }
        // SAFETY: the controller belongs to the live view.
        unsafe { webkit_find_controller_search(self.find, text.as_ptr(), options, max) };
    }

    pub(crate) fn find_step(&self, backwards: bool) {
        // SAFETY: as above.
        unsafe {
            if backwards {
                webkit_find_controller_search_previous(self.find);
            } else {
                webkit_find_controller_search_next(self.find);
            }
        }
    }

    pub(crate) fn find_finish(&self) {
        // SAFETY: as above.
        unsafe { webkit_find_controller_search_finish(self.find) };
    }

    pub(crate) fn count_matches(&self, text: &str, case_sensitive: bool, max: u32) {
        let text = c_text(text);
        let options = if case_sensitive {
            0
        } else {
            WEBKIT_FIND_OPTIONS_CASE_INSENSITIVE
        };
        // SAFETY: as above.
        unsafe { webkit_find_controller_count_matches(self.find, text.as_ptr(), options, max) };
    }

    pub(crate) fn clear_website_data(
        &self,
        network_session: *mut ffi::WebKitNetworkSession,
        data: WebsiteData,
        since: Option<std::time::Duration>,
    ) -> PageRequestId {
        let id = self.hub.mint();
        // Native zero clears all ages; an explicit empty window must preserve data.
        if since.is_some_and(|duration| duration.as_micros() == 0) {
            self.hub.push(PageEvent::DataCleared { id, result: Ok(()) });
            return id;
        }
        if since.is_some() && data.bits() & WebsiteData::COOKIES.bits() != 0 {
            self.hub.push(PageEvent::DataCleared {
                id,
                result: Err("native cookie creation-time filtering is unavailable; use all ages or selective cookie deletion".into()),
            });
            return id;
        }
        let payload = Box::into_raw(Box::new(AsyncData {
            preview: false,
            hub: Rc::downgrade(&self.hub),
            id,
            private_reply: None,
            secret_reply: None,
        }));
        // GTimeSpan is microseconds; 0 clears everything ever stored.
        let timespan = since.map_or(0, |d| i64::try_from(d.as_micros()).unwrap_or(i64::MAX));
        // SAFETY: the manager belongs to the live session; the callback frees
        // `payload` exactly once.
        unsafe {
            let manager = webkit_network_session_get_website_data_manager(network_session);
            webkit_website_data_manager_clear(
                manager,
                data.bits(),
                timespan,
                self.cancellable,
                on_data_cleared,
                payload.cast(),
            );
        }
        id
    }
}

impl Drop for PageBinding {
    fn drop(&mut self) {
        // Decline everything still waiting while the view is live, so no page
        // stays blocked on a host that went away, and stop its downloads.
        self.decline_pending();
        // Legacy terminal callbacks can admit scoped requests after the initial cancellation.
        self.hub.cancel_site_permissions();
        self.hub.release_all_downloads();
        self.hub.release_popups();
        self.hub.drop_held_navigations();
        self.hub.release_spelling();
        self.hub.release_notifications();
        // SAFETY: each handler was connected on exactly this instance; the
        // cancellable is owned here. Async callbacks hold only a `Weak`.
        unsafe {
            for handler in self.message_handlers.drain(..) {
                release_message_handler(self.content, handler);
            }
            for handler in self.find_handlers.drain(..) {
                ffi::g_signal_handler_disconnect(self.find.cast(), handler);
            }
            for handler in self.view_handlers.drain(..) {
                ffi::g_signal_handler_disconnect(self.web_view.cast(), handler);
            }
            ffi::g_cancellable_cancel(self.cancellable);
            for (_, anchor) in self.evaluation_worlds.get_mut().drain() {
                webkit_user_script_unref(anchor);
            }
            for (_, injection) in self.content_injections.get_mut().drain() {
                match injection {
                    ContentInjection::Script(script) => webkit_user_script_unref(script),
                    ContentInjection::Style(sheet) => webkit_user_style_sheet_unref(sheet),
                }
            }
            ffi::g_object_unref(self.cancellable);
            drop(Box::from_raw(self.data));
        }
    }
}

/// Counts `web_view`'s finalization in [`crate::native_release`], so a gate
/// can tell a released view from a leaked reference.
///
/// # Safety
///
/// `web_view` is live.
pub(crate) unsafe fn watch_finalization(web_view: *mut ffi::WebKitWebView) {
    extern "C" fn finalized(_data: *mut c_void, _object: *mut c_void) {
        crate::native_release::record_web_view_finalized();
    }
    // SAFETY: a live GObject; the notify takes no data.
    unsafe { g_object_weak_ref(web_view.cast(), finalized, core::ptr::null_mut()) };
}

/// Applies `settings` to a view.
///
/// # Safety
///
/// `web_view` is live.
pub(crate) unsafe fn apply_settings(web_view: *mut ffi::WebKitWebView, settings: &WebSettings) {
    // SAFETY: the settings object belongs to the live view.
    unsafe {
        let native = webkit_web_view_get_settings(web_view);
        match &settings.user_agent {
            UserAgent::Default => webkit_settings_set_user_agent(native, core::ptr::null()),
            UserAgent::Application { name, version } => {
                webkit_settings_set_user_agent(native, core::ptr::null());
                let (name, version) = (c_text(name), c_text(version));
                webkit_settings_set_user_agent_with_application_details(
                    native,
                    name.as_ptr(),
                    version.as_ptr(),
                );
            }
            UserAgent::Custom(agent) => {
                let agent = c_text(agent);
                webkit_settings_set_user_agent(native, agent.as_ptr());
            }
        }
        webkit_settings_set_enable_javascript(native, gbool(settings.javascript));
        webkit_settings_set_javascript_can_open_windows_automatically(
            native,
            gbool(settings.javascript_opens_windows),
        );
        webkit_settings_set_enable_developer_extras(native, gbool(settings.developer_extras));
        webkit_settings_set_media_playback_requires_user_gesture(
            native,
            gbool(settings.media_requires_gesture),
        );
        webkit_settings_set_enable_webgl(native, gbool(settings.webgl));
        webkit_settings_set_enable_encrypted_media(native, gbool(settings.encrypted_media));
        webkit_settings_set_enable_webrtc(native, gbool(settings.webrtc));
        webkit_settings_set_enable_media_stream(native, gbool(settings.webrtc));
        // Encoded transforms (`RTCRtpScriptTransform`) and speaker selection
        // (`setSinkId`) are on in Safari but off by default on WPE; calls with
        // end-to-end encryption need the first, call sites the second. WebKit
        // lists speakers only to a frame granted the microphone in this
        // session; Safari's further rule, a speaker paired with that
        // microphone, matches no device here, as GStreamer pairs none.
        set_feature(web_view, "WebRTCEncodedTransform", settings.webrtc);
        set_feature(web_view, "ExposeSpeakers", settings.webrtc);
        set_feature(web_view, "ExposeSpeakersWithoutMicrophone", settings.webrtc);
        webkit_settings_set_enable_page_cache(native, gbool(settings.page_cache));
        webkit_settings_set_zoom_text_only(native, gbool(settings.zoom_text_only));
    }
}

/// Every feature identifier with its default, for diagnostics.
pub(crate) fn feature_defaults() -> Result<Vec<(String, bool)>, super::NativeThreadError> {
    super::threading::claim()?;
    let mut out = Vec::new();
    // SAFETY: the list is owned here and released after the walk; its features stay valid while it lives.
    unsafe {
        let list = webkit_settings_get_all_features();
        if list.is_null() {
            return Ok(out);
        }
        for index in 0..webkit_feature_list_get_length(list) {
            let feature = webkit_feature_list_get(list, index);
            if let Some(id) = native_text(webkit_feature_get_identifier(feature)) {
                out.push((id, webkit_feature_get_default_value(feature) != 0));
            }
        }
        webkit_feature_list_unref(list);
    }
    Ok(out)
}

pub(crate) unsafe fn enable_compression_dictionary_transport(
    web_view: *mut ffi::WebKitWebView,
) -> bool {
    // SAFETY: the caller's contract is this function's.
    unsafe { enable_feature(web_view, "CompressionDictionary") }
}

/// Enable the WebKit feature `identifier` on the view; whether it took.
///
/// # Safety
///
/// `web_view` is live.
pub(crate) unsafe fn enable_feature(web_view: *mut ffi::WebKitWebView, identifier: &str) -> bool {
    // SAFETY: the caller's contract is this function's.
    unsafe { set_feature(web_view, identifier, true) }
}

/// Set the WebKit feature `identifier` on the view; whether it now has that
/// state. An identifier the loaded engine does not know is left alone.
///
/// # Safety
///
/// `web_view` is live.
pub(crate) unsafe fn set_feature(
    web_view: *mut ffi::WebKitWebView,
    identifier: &str,
    enabled: bool,
) -> bool {
    // SAFETY: the owner borrows a live view; features stay valid until their list is released.
    unsafe {
        let settings = webkit_web_view_get_settings(web_view);
        let list = webkit_settings_get_all_features();
        if list.is_null() {
            return false;
        }
        let mut result = false;
        for index in 0..webkit_feature_list_get_length(list) {
            let feature = webkit_feature_list_get(list, index);
            if native_text(webkit_feature_get_identifier(feature)).as_deref() != Some(identifier) {
                continue;
            }
            webkit_settings_set_feature_enabled(settings, feature, gbool(enabled));
            result = (webkit_settings_get_feature_enabled(settings, feature) != 0) == enabled;
            break;
        }
        webkit_feature_list_unref(list);
        result
    }
}

/// WebKit's window properties, resolved from the loaded engine: the
/// `has_custom_geometry` and `is_popup` getters are newer than some engines a
/// build links against.
struct WindowPropertiesApi {
    properties: PropertiesOf,
    geometry: GeometryOf,
    custom_geometry: FlagOf,
    popup: FlagOf,
    location_bar: FlagOf,
    toolbar: FlagOf,
    resizable: FlagOf,
}

type PropertiesOf = unsafe extern "C" fn(*mut ffi::WebKitWebView) -> *mut c_void;
type GeometryOf = unsafe extern "C" fn(*mut c_void, *mut WebKitRectangle);
type FlagOf = unsafe extern "C" fn(*mut c_void) -> ffi::GBoolean;

fn window_properties_api() -> Option<&'static WindowPropertiesApi> {
    #[link(name = "dl")]
    unsafe extern "C" {
        fn dlsym(handle: *mut c_void, name: *const core::ffi::c_char) -> *mut c_void;
    }
    static API: std::sync::OnceLock<Option<WindowPropertiesApi>> = std::sync::OnceLock::new();
    API.get_or_init(|| {
        let symbol = |name: &core::ffi::CStr| {
            // SAFETY: a fixed WebKit symbol looked up in the loaded libraries.
            let found = unsafe { dlsym(core::ptr::null_mut(), name.as_ptr()) };
            (!found.is_null()).then_some(found)
        };
        // SAFETY: each symbol, when present, has the C signature of
        // WebKitWebView.h and WebKitWindowProperties.h.
        unsafe {
            Some(WindowPropertiesApi {
                properties: core::mem::transmute::<*mut c_void, PropertiesOf>(symbol(
                    c"webkit_web_view_get_window_properties",
                )?),
                geometry: core::mem::transmute::<*mut c_void, GeometryOf>(symbol(
                    c"webkit_window_properties_get_geometry",
                )?),
                custom_geometry: core::mem::transmute::<*mut c_void, FlagOf>(symbol(
                    c"webkit_window_properties_get_has_custom_geometry",
                )?),
                popup: core::mem::transmute::<*mut c_void, FlagOf>(symbol(
                    c"webkit_window_properties_get_is_popup",
                )?),
                location_bar: core::mem::transmute::<*mut c_void, FlagOf>(symbol(
                    c"webkit_window_properties_get_locationbar_visible",
                )?),
                toolbar: core::mem::transmute::<*mut c_void, FlagOf>(symbol(
                    c"webkit_window_properties_get_toolbar_visible",
                )?),
                resizable: core::mem::transmute::<*mut c_void, FlagOf>(symbol(
                    c"webkit_window_properties_get_resizable",
                )?),
            })
        }
    })
    .as_ref()
}

/// What the page that opened `web_view` asked of its window; the defaults
/// (no popup) on an engine without the getters.
///
/// # Safety
/// `web_view` is a live view.
pub(crate) unsafe fn window_features(
    web_view: *mut ffi::WebKitWebView,
) -> crate::page::WindowFeatures {
    let Some(api) = window_properties_api() else {
        return crate::page::WindowFeatures::default();
    };
    // SAFETY: the properties object belongs to the live view and lives as long.
    unsafe {
        let properties = (api.properties)(web_view);
        if properties.is_null() {
            return crate::page::WindowFeatures::default();
        }
        let mut geometry = WebKitRectangle {
            x: 0,
            y: 0,
            width: 0,
            height: 0,
        };
        (api.geometry)(properties, &mut geometry);
        let custom = (api.custom_geometry)(properties) != 0;
        let size = (custom && geometry.width > 0 && geometry.height > 0).then(|| {
            (
                geometry.width.unsigned_abs(),
                geometry.height.unsigned_abs(),
            )
        });
        crate::page::WindowFeatures {
            popup: (api.popup)(properties) != 0,
            size,
            position: custom.then_some((geometry.x, geometry.y)),
            location_bar: (api.location_bar)(properties) != 0,
            toolbar: (api.toolbar)(properties) != 0,
            resizable: (api.resizable)(properties) != 0,
        }
    }
}

/// The user agent the view sends now.
///
/// # Safety
///
/// `web_view` is live.
pub(crate) unsafe fn user_agent(web_view: *mut ffi::WebKitWebView) -> String {
    // SAFETY: borrowed from the live settings object.
    unsafe {
        native_text(webkit_settings_get_user_agent(
            webkit_web_view_get_settings(web_view),
        ))
    }
    .unwrap_or_default()
}

/// Sets the profile's cookie policy and tracking prevention.
///
/// # Safety
///
/// `network_session` is live.
pub(crate) unsafe fn apply_cookie_policy(
    network_session: *mut ffi::WebKitNetworkSession,
    policy: CookiePolicy,
    tracking_prevention: bool,
) {
    let policy = match policy {
        CookiePolicy::Always => 0,
        CookiePolicy::Never => 1,
        CookiePolicy::NoThirdParty => 2,
    };
    // SAFETY: the cookie manager belongs to the live session.
    unsafe {
        webkit_cookie_manager_set_accept_policy(
            ffi::webkit_network_session_get_cookie_manager(network_session),
            policy,
        );
        webkit_network_session_set_itp_enabled(network_session, gbool(tracking_prevention));
    }
}

/// The hub behind a signal's data pointer.
///
/// # Safety
///
/// `data` is a live `SignalData` installed by [`PageBinding::new`].
unsafe fn hub<'a>(data: *mut c_void) -> &'a PageHub {
    // SAFETY: forwarded to the caller's contract.
    unsafe { &(*data.cast::<SignalData>()).hub }
}

extern "C" fn on_load_changed(view: *mut ffi::WebKitWebView, event: c_int, data: *mut c_void) {
    let stage = match event {
        0 => LoadStage::Started,
        1 => LoadStage::Redirected,
        2 => LoadStage::Committed,
        3 => LoadStage::Finished,
        _ => return,
    };
    // SAFETY: GSignal passes the installed data pointer.
    let hub = unsafe { hub(data) };
    if stage == LoadStage::Started {
        hub.cancel_exports();
        hub.cancel_site_permissions();
    }
    if stage == LoadStage::Committed {
        // SAFETY: the emitting view is live; its URI is copied, bounded.
        let uri = unsafe { native_uri(ffi::webkit_web_view_get_uri(view).cast()) };
        let mut state = hub.state.borrow_mut();
        // A new document: its URL history starts at the committed URL.
        state.document_uris.clear();
        if let Some(uri) = uri {
            state.document_uris.push_back(uri.as_str().to_owned());
            if !crate::ffi::runtime::is_inert_url(uri.as_str()) {
                state.last_committed = Some(uri.as_str().to_owned());
            }
        }
    }
    hub.push(PageEvent::Load(stage));
}

extern "C" fn on_web_process_terminated(
    _view: *mut ffi::WebKitWebView,
    reason: c_int,
    data: *mut c_void,
) {
    let reason = match reason {
        0 => crate::page::TerminationReason::Crashed,
        1 => crate::page::TerminationReason::ExceededMemory,
        _ => crate::page::TerminationReason::TerminatedByHost,
    };
    // SAFETY: GSignal passes the installed data pointer.
    let hub = unsafe { hub(data) };
    hub.cancel_exports();
    hub.cancel_site_permissions();
    hub.push(PageEvent::WebProcessTerminated(reason));
}

extern "C" fn on_load_failed(
    _view: *mut ffi::WebKitWebView,
    _event: c_int,
    uri: *const c_char,
    error: *mut ffi::GError,
    data: *mut c_void,
) -> ffi::GBoolean {
    // SAFETY: WebKit passes a live URI and error for this callback.
    let (url, message, code, domain) = unsafe {
        let url = native_uri(uri).unwrap_or_else(|| PolicyUrl::new(String::new()));
        if error.is_null() {
            (url, String::new(), 0, String::new())
        } else {
            (
                url,
                native_text((*error).message).unwrap_or_default(),
                (*error).code,
                native_text(ffi::g_quark_to_string((*error).domain)).unwrap_or_default(),
            )
        }
    };
    // WEBKIT_NETWORK_ERROR_CANCELLED (302) and the policy's frame-load
    // interruption (WEBKIT_POLICY_ERROR_FRAME_LOAD_INTERRUPTED_BY_POLICY_CHANGE,
    // 102) are cancellations, not failures.
    let cancelled = (domain == "WebKitNetworkError" && code == 302)
        || (domain == "WebKitPolicyError" && code == 102);
    // SAFETY: GSignal passes the installed data pointer.
    let hub = unsafe { hub(data) };
    // A captured redirect carries the authorization code; it reaches the host
    // once, as `RedirectCaptured`, and never through another event.
    if hub.is_captured_url(url.as_str()) {
        return ffi::G_FALSE;
    }
    if !(domain == "WebKitNetworkError" && code == 302) {
        let mut state = hub.state.borrow_mut();
        state.load_failures = state.load_failures.wrapping_add(1);
        state.load_failure = Some((domain, code));
    }
    hub.push(PageEvent::LoadFailed {
        url,
        message,
        cancelled,
    });
    // Leave WebKit's own handling (its error page) in place.
    ffi::G_FALSE
}

extern "C" fn on_notify_uri(object: *mut c_void, _spec: *mut GParamSpec, data: *mut c_void) {
    // SAFETY: the signal data retains this hub; null or refused URIs must also invalidate snapshots.
    unsafe { hub(data) }.mark_metadata_changed();
    // SAFETY: `object` is the live view emitting the notification.
    let uri = unsafe { native_uri(ffi::webkit_web_view_get_uri(object.cast()).cast()) };
    if let Some(uri) = uri {
        // SAFETY: GSignal passes the installed data pointer.
        let hub = unsafe { hub(data) };
        if !hub.is_captured_url(uri.as_str()) {
            hub.push(PageEvent::UriChanged(uri));
        }
    }
}

extern "C" fn on_notify_title(object: *mut c_void, _spec: *mut GParamSpec, data: *mut c_void) {
    // SAFETY: `object` is the live view emitting the notification.
    let title = unsafe { native_text(ffi::webkit_web_view_get_title(object.cast()).cast()) };
    // SAFETY: GSignal passes the installed data pointer.
    unsafe { hub(data) }.push(PageEvent::TitleChanged(title.unwrap_or_default()));
}

extern "C" fn on_notify_progress(object: *mut c_void, _spec: *mut GParamSpec, data: *mut c_void) {
    // SAFETY: `object` is the live view emitting the notification.
    let progress = unsafe { webkit_web_view_get_estimated_load_progress(object.cast()) };
    // SAFETY: GSignal passes the installed data pointer.
    let hub = unsafe { hub(data) };
    let changed = {
        let mut state = hub.state.borrow_mut();
        let changed = state.last_progress != Some(progress);
        state.last_progress = Some(progress);
        changed
    };
    if changed {
        hub.push(PageEvent::Progress(progress.clamp(0.0, 1.0)));
    }
}

extern "C" fn on_script_dialog(
    _view: *mut ffi::WebKitWebView,
    dialog: *mut WebKitScriptDialog,
    data: *mut c_void,
) -> ffi::GBoolean {
    if dialog.is_null() {
        return ffi::G_FALSE;
    }
    // SAFETY: GSignal passes the installed data pointer.
    let hub = unsafe { hub(data) };
    // SAFETY: the dialog is live for this callback; the reference taken here
    // keeps it live until it is answered.
    let (kind_raw, message, kind) = unsafe {
        let kind_raw = webkit_script_dialog_get_dialog_type(dialog);
        let message = native_text(webkit_script_dialog_get_message(dialog)).unwrap_or_default();
        let kind = match kind_raw {
            WEBKIT_SCRIPT_DIALOG_ALERT => ScriptDialogKind::Alert,
            WEBKIT_SCRIPT_DIALOG_CONFIRM => ScriptDialogKind::Confirm,
            WEBKIT_SCRIPT_DIALOG_PROMPT => ScriptDialogKind::Prompt {
                default_text: native_text(webkit_script_dialog_prompt_get_default_text(dialog))
                    .unwrap_or_default(),
            },
            _ => ScriptDialogKind::BeforeUnload,
        };
        (kind_raw, message, kind)
    };
    if !hub.admit(DeclinedPrompt::ScriptDialog) {
        // Answered in place; WebKit completes it when this handler returns.
        // SAFETY: the dialog is live for this callback.
        unsafe { set_dialog_answer(dialog, kind_raw, &ScriptDialogAnswer::Dismiss, true) };
        return ffi::G_TRUE;
    }
    // SAFETY: the reference keeps the dialog live until the host answers.
    unsafe { webkit_script_dialog_ref(dialog) };
    let id = hub.hold(Pending::Dialog(dialog, kind_raw));
    hub.push(PageEvent::ScriptDialog(ScriptDialogRequest {
        id,
        kind,
        message,
    }));
    ffi::G_TRUE
}

extern "C" fn on_file_chooser(
    _view: *mut ffi::WebKitWebView,
    request: *mut WebKitFileChooserRequest,
    data: *mut c_void,
) -> ffi::GBoolean {
    if request.is_null() {
        return ffi::G_FALSE;
    }
    // SAFETY: GSignal passes the installed data pointer.
    let hub = unsafe { hub(data) };
    // SAFETY: the request is live for this callback; the reference taken here
    // keeps it live until it is answered.
    let (multiple, mime_types) = unsafe {
        let multiple = webkit_file_chooser_request_get_select_multiple(request) != 0;
        let mut mime_types = Vec::new();
        let list = webkit_file_chooser_request_get_mime_types(request);
        if !list.is_null() {
            let mut at = list;
            while !(*at).is_null() && mime_types.len() < 64 {
                if let Some(mime) = native_text(*at) {
                    mime_types.push(mime);
                }
                at = at.add(1);
            }
        }
        (multiple, mime_types)
    };
    if !hub.admit(DeclinedPrompt::FileChooser) {
        // SAFETY: the request is live; one terminal action.
        unsafe { webkit_file_chooser_request_cancel(request) };
        return ffi::G_TRUE;
    }
    // SAFETY: the reference keeps the request live until the host answers.
    unsafe { ffi::g_object_ref(request.cast()) };
    let id = hub.hold(Pending::Chooser(request));
    hub.push(PageEvent::FileChooser(FileChooserRequest {
        id,
        multiple,
        mime_types,
    }));
    ffi::G_TRUE
}

extern "C" fn on_color_chooser(
    _view: *mut ffi::WebKitWebView,
    request: *mut WebKitColorChooserRequest,
    data: *mut c_void,
) -> ffi::GBoolean {
    if request.is_null() {
        return ffi::G_FALSE;
    }
    // SAFETY: GSignal passes the installed data pointer.
    let hub = unsafe { hub(data) };
    // The signal is connected only where the runtime has these functions.
    let Some(api) = color_chooser::api() else {
        return ffi::G_FALSE;
    };
    if !hub.admit(DeclinedPrompt::ColorChooser) {
        // WebKit's own handling: the field keeps its colour.
        return ffi::G_FALSE;
    }
    // SAFETY: the request is live for this callback and fills both values;
    // the reference keeps it live until the host answers.
    let (color, alpha, area) = unsafe {
        let mut color = WebKitColor::default();
        (api.get_color)(request, &mut color);
        let mut rect = WebKitRectangle {
            x: 0,
            y: 0,
            width: 0,
            height: 0,
        };
        (api.get_element_rectangle)(request, &mut rect);
        ffi::g_object_ref(request.cast());
        (
            color_bytes(color),
            (api.get_supports_alpha)(request) != 0,
            ViewRect {
                x: rect.x,
                y: rect.y,
                width: rect.width,
                height: rect.height,
            },
        )
    };
    let id = hub.hold(Pending::Color(request));
    hub.push(PageEvent::ColorChooser(ColorChooserRequest {
        id,
        color,
        alpha,
        area,
    }));
    ffi::G_TRUE
}

extern "C" fn on_authenticate(
    _view: *mut ffi::WebKitWebView,
    request: *mut ffi::WebKitAuthenticationRequest,
    data: *mut c_void,
) -> ffi::GBoolean {
    if request.is_null() {
        return ffi::G_FALSE;
    }
    // SAFETY: GSignal passes the installed data pointer.
    let hub = unsafe { hub(data) };
    // SAFETY: the request is live for this callback.
    let (proxy, scheme_raw) = unsafe {
        (
            ffi::webkit_authentication_request_is_for_proxy(request) != 0,
            webkit_authentication_request_get_scheme(request),
        )
    };
    let scheme = match scheme_raw {
        1 | 2 => AuthScheme::Basic,
        3 => AuthScheme::Digest,
        5 => AuthScheme::Ntlm,
        6 => AuthScheme::Negotiate,
        7 | 9 => AuthScheme::ClientCertificate,
        _ => AuthScheme::Other,
    };
    // The destination guard's proxy is answered by its own handler, which
    // runs first; any proxy challenge reaching here is not one the host may
    // answer. A client certificate cannot be answered with a password.
    if proxy || scheme == AuthScheme::ClientCertificate {
        if scheme == AuthScheme::ClientCertificate {
            hub.push(PageEvent::PromptDeclined(DeclinedPrompt::Authentication));
        }
        // SAFETY: the request is live; one terminal action.
        unsafe { webkit_authentication_request_cancel(request) };
        return ffi::G_TRUE;
    }
    // SAFETY: borrowed strings of the live request, copied here.
    let (host, port, realm, retry) = unsafe {
        (
            native_text(ffi::webkit_authentication_request_get_host(request)).unwrap_or_default(),
            ffi::webkit_authentication_request_get_port(request),
            native_text(webkit_authentication_request_get_realm(request)).unwrap_or_default(),
            ffi::webkit_authentication_request_is_retry(request) != 0,
        )
    };
    if !hub.admit(DeclinedPrompt::Authentication) {
        // SAFETY: the request is live; one terminal action.
        unsafe { webkit_authentication_request_cancel(request) };
        return ffi::G_TRUE;
    }
    // SAFETY: the reference keeps the request live until the host answers.
    unsafe { ffi::g_object_ref(request.cast()) };
    let id = hub.hold(Pending::Challenge(request));
    hub.push(PageEvent::Authentication(AuthChallenge {
        id,
        host,
        port,
        realm,
        scheme,
        retry,
    }));
    ffi::G_TRUE
}

extern "C" fn on_close(_view: *mut ffi::WebKitWebView, data: *mut c_void) {
    // SAFETY: GSignal passes the installed data pointer.
    let hub = unsafe { hub(data) };
    hub.state.borrow_mut().close_requested = true;
    hub.push(PageEvent::CloseRequested);
}

extern "C" fn on_context_menu(
    _view: *mut ffi::WebKitWebView,
    menu: *mut WebKitContextMenu,
    hit: *mut WebKitHitTestResult,
    data: *mut c_void,
) -> ffi::GBoolean {
    let mut target = ContextTarget::default();
    // SAFETY: GSignal passes the installed data pointer.
    let spelling_hub = unsafe { hub(data) };
    spelling_hub.release_spelling();
    // A page that answers a right-click itself (`preventDefault` on
    // `contextmenu`) leaves WebKit nothing to propose. Once a menu has been
    // shown in the page WebKit announces one all the same, with no entries
    // and the place of that earlier menu. It is the page's menu that shows,
    // and the host is told of none.
    // SAFETY: a non-null menu is live for this callback.
    if !menu.is_null() && unsafe { webkit_context_menu_get_n_items(menu) } == 0 {
        return ffi::G_TRUE;
    }
    if !menu.is_null() {
        let mut kept = Vec::new();
        let mut guesses = Vec::new();
        // SAFETY: the menu and its items are live for this callback. An item
        // kept past it is referenced here; WebKit attaches the page to its
        // action when this handler returns, before it empties the menu.
        unsafe {
            for position in 0..webkit_context_menu_get_n_items(menu).min(64) {
                let item = webkit_context_menu_get_item_at_position(menu, position);
                if item.is_null() {
                    continue;
                }
                let Some(entry) = spelling_entry(webkit_context_menu_item_get_stock_action(item))
                else {
                    continue;
                };
                target.spelling.get_or_insert_with(Vec::new);
                match entry {
                    SpellingEntry::NoGuesses => continue,
                    SpellingEntry::Guess => {
                        if guesses.len() >= MAX_SPELLING_GUESSES {
                            continue;
                        }
                        let Some(word) = native_text(webkit_context_menu_item_get_title(item))
                        else {
                            continue;
                        };
                        guesses.push(word);
                    }
                    SpellingEntry::Ignore | SpellingEntry::Learn => {}
                }
                ffi::g_object_ref(item.cast());
                kept.push((entry, item));
            }
        }
        if let Some(spelling) = &mut target.spelling {
            *spelling = guesses;
        }
        spelling_hub.state.borrow_mut().spelling = kept;
    }
    if !hit.is_null() {
        // SAFETY: the hit-test result is live for this callback.
        unsafe {
            let context = webkit_hit_test_result_get_context(hit);
            if context & WEBKIT_HIT_TEST_RESULT_CONTEXT_LINK != 0 {
                target.link = native_uri(webkit_hit_test_result_get_link_uri(hit));
            }
            if context & WEBKIT_HIT_TEST_RESULT_CONTEXT_IMAGE != 0 {
                target.image = native_uri(webkit_hit_test_result_get_image_uri(hit));
            }
            if context & WEBKIT_HIT_TEST_RESULT_CONTEXT_MEDIA != 0 {
                target.media = native_uri(webkit_hit_test_result_get_media_uri(hit));
            }
            target.editable = context & WEBKIT_HIT_TEST_RESULT_CONTEXT_EDITABLE != 0;
            target.selection = context & WEBKIT_HIT_TEST_RESULT_CONTEXT_SELECTION != 0;
        }
    }
    // SAFETY: GSignal passes the installed data pointer.
    unsafe { hub(data) }.push(PageEvent::ContextMenu(target));
    // The host draws its own menu.
    ffi::G_TRUE
}

extern "C" fn on_found_text(_find: *mut WebKitFindController, matches: c_uint, data: *mut c_void) {
    // WebKit reports G_MAXUINT when there were more than the search's limit.
    let matches = (matches != c_uint::MAX).then_some(matches);
    // SAFETY: GSignal passes the installed data pointer.
    unsafe { hub(data) }.push(PageEvent::FindMatches(matches));
}

extern "C" fn on_counted_matches(
    _find: *mut WebKitFindController,
    matches: c_uint,
    data: *mut c_void,
) {
    let matches = (matches != c_uint::MAX).then_some(matches);
    // SAFETY: GSignal passes the installed data pointer.
    unsafe { hub(data) }.push(PageEvent::MatchesCounted(matches));
}

extern "C" fn on_failed_to_find(_find: *mut WebKitFindController, data: *mut c_void) {
    // SAFETY: GSignal passes the installed data pointer.
    unsafe { hub(data) }.push(PageEvent::FindFailed);
}

/// JSON for a JS value; `undefined` (which JSON lacks) is `null`. `None`
/// when the JSON is longer than [`crate::page::MAX_PAGE_TEXT_BYTES`]: cutting
/// it would hand the host invalid JSON.
///
/// # Safety
///
/// `value` is a live `JSCValue`.
unsafe fn value_json(value: *mut JSCValue) -> Option<String> {
    // SAFETY: the caller supplies a live JSCValue; ordinary results need no wipe.
    unsafe { value_json_mode(value, false) }
}

// SAFETY: the caller owns a writable, NUL-terminated GLib string until its next free.
unsafe fn wipe_native_text(value: *mut c_char) {
    if value.is_null() {
        return;
    }
    // SAFETY: the native string contract establishes the complete readable length.
    let len = unsafe { std::ffi::CStr::from_ptr(value).to_bytes().len() };
    for offset in 0..len {
        // SAFETY: each byte is inside the owned allocation and no native call observes it.
        unsafe {
            core::ptr::write_volatile(value.add(offset), 0);
        }
    }
    std::sync::atomic::compiler_fence(Ordering::SeqCst);
}

// SAFETY: value is live for the call; the returned GLib string is exclusively owned here.
unsafe fn value_json_mode(value: *mut JSCValue, secret: bool) -> Option<String> {
    // SAFETY: forwarded to the caller's contract; the returned string is owned
    // here and must be freed.
    unsafe {
        if jsc_value_is_undefined(value) != 0 {
            return Some("null".into());
        }
        let json = jsc_value_to_json(value, 0);
        if json.is_null() {
            return Some("null".into());
        }
        let text =
            crate::ffi::policy::scan_bounded_native_bytes(json, crate::page::MAX_PAGE_TEXT_BYTES)
                .map(|bytes| String::from_utf8_lossy(bytes).into_owned());
        if secret {
            wipe_native_text(json);
        }
        ffi::g_free(json.cast());
        text
    }
}

extern "C" fn on_script_message(
    manager: *mut WebKitUserContentManager,
    value: *mut JSCValue,
    data: *mut c_void,
) {
    if value.is_null() {
        return;
    }
    // SAFETY: `data` is this registration's live `MessageData`; `value` is
    // live for the callback.
    let (data, json) = unsafe {
        let data = &*data.cast::<MessageData>();
        (data, value_json_mode(value, data.secret))
    };
    if data.frame_scoped {
        // SAFETY: called inside the script-message-received emission.
        let Some(source) = (unsafe { frame_secrets::message_source(manager) }) else {
            return;
        };
        data.hub.push(match json {
            Some(json) => PageEvent::FrameSecretMessage {
                handler: data.name.clone(),
                frame: source.frame,
                origin: source.origin,
                top_origin: source.top_origin,
                main_frame: source.main_frame,
                json: SecretText::new(json),
            },
            None => PageEvent::ScriptMessageTooLarge {
                handler: data.name.clone(),
            },
        });
        return;
    }
    data.hub.push(match json {
        Some(json) if data.secret => PageEvent::SecretScriptMessage {
            handler: data.name.clone(),
            json: SecretText::new(json),
        },
        Some(json) => PageEvent::ScriptMessage {
            handler: data.name.clone(),
            json,
        },
        None => PageEvent::ScriptMessageTooLarge {
            handler: data.name.clone(),
        },
    });
}

// The caller must retain the result and its JSCContext throughout conversion.
unsafe fn value_preview_json(value: *mut JSCValue) -> Option<String> {
    // SAFETY: all predicates borrow the live result; allocated strings are copied before release.
    let (kind, preview) = unsafe {
        if jsc_value_is_undefined(value) != 0 {
            ("undefined", "undefined".to_owned())
        } else {
            let json = value_json(value)?;
            if json != "null" || jsc_value_is_null(value) != 0 {
                ("json", json)
            } else {
                let context = jsc_value_get_context(value);
                jsc_context_clear_exception(context);
                let pointer = jsc_value_to_string(value);
                let preview = if pointer.is_null() {
                    "Preview unavailable".into()
                } else {
                    let text = crate::ffi::policy::scan_bounded_native_bytes(
                        pointer,
                        crate::page::MAX_PAGE_TEXT_BYTES,
                    )
                    .map(|bytes| String::from_utf8_lossy(bytes).into_owned());
                    ffi::g_free(pointer.cast());
                    text?
                };
                jsc_context_clear_exception(context);
                ("display", format!("[Non-JSON value] {preview}"))
            }
        }
    };
    let json = serde_json::json!({"kind":kind,"preview":preview}).to_string();
    (json.len() <= crate::page::MAX_PAGE_TEXT_BYTES).then_some(json)
}

extern "C" fn on_native_readiness_finished(
    source: *mut c_void,
    result: *mut ffi::GAsyncResult,
    data: *mut c_void,
) {
    // SAFETY: each native probe transfers one boxed weak reply to this callback.
    let reply = unsafe { Box::from_raw(data.cast::<Weak<NativeReadinessReply>>()) };
    let mut error = core::ptr::null_mut();
    // SAFETY: the GTask keeps source alive; the returned message and error are owned.
    let state = unsafe {
        let message =
            ffi::webkit_web_view_send_message_to_page_finish(source.cast(), result, &mut error);
        let name = if message.is_null() {
            None
        } else {
            native_text(ffi::webkit_user_message_get_name(message))
        };
        let state = decode_native_readiness(name.as_deref(), !error.is_null());
        if state == NativeDocumentReadiness::Unavailable {
            NATIVE_READINESS_UNAVAILABLE.store(true, Ordering::Relaxed);
        }
        if !message.is_null() {
            ffi::g_object_unref(message.cast());
        }
        if !error.is_null() {
            ffi::g_error_free(error);
        }
        state
    };
    if let Some(reply) = reply.upgrade() {
        *reply.borrow_mut() = Some(state);
    }
}

extern "C" fn on_script_finished(
    source: *mut c_void,
    result: *mut ffi::GAsyncResult,
    data: *mut c_void,
) {
    finish_script(source, result, data, false);
}

extern "C" fn on_async_script_finished(
    source: *mut c_void,
    result: *mut ffi::GAsyncResult,
    data: *mut c_void,
) {
    finish_script(source, result, data, true);
}

fn finish_script(
    source: *mut c_void,
    result: *mut ffi::GAsyncResult,
    data: *mut c_void,
    asynchronous: bool,
) {
    // SAFETY: each script submission transfers one AsyncData box to this callback.
    let data = unsafe { Box::from_raw(data.cast::<AsyncData>()) };
    let mut error: *mut ffi::GError = core::ptr::null_mut();
    // SAFETY: `source` is the view the task was started on, kept alive by the
    // task; the value and error are owned here and released.
    let outcome = unsafe {
        let value = if asynchronous {
            webkit_web_view_call_async_javascript_function_finish(source.cast(), result, &mut error)
        } else {
            webkit_web_view_evaluate_javascript_finish(source.cast(), result, &mut error)
        };
        if value.is_null() {
            let (message, cancelled, unavailable) = if error.is_null() {
                (String::new(), false, false)
            } else {
                let message = native_text((*error).message).unwrap_or_default();
                let domain =
                    native_text(ffi::g_quark_to_string((*error).domain)).unwrap_or_default();
                // G_IO_ERROR_CANCELLED is 19 in the g-io-error-quark domain.
                let cancelled = domain == "g-io-error-quark" && (*error).code == 19;
                let unavailable = data.preview
                    && (*error).domain == webkit_javascript_error_quark()
                    && (*error).code == 601;
                if data.secret_reply.is_some() {
                    wipe_native_text((*error).message);
                }
                ffi::g_error_free(error);
                (message, cancelled, unavailable)
            };
            Err(if cancelled {
                ScriptError::Cancelled
            } else if unavailable {
                ScriptError::Unavailable
            } else {
                ScriptError::Failed(message)
            })
        } else {
            let json = if data.preview {
                value_preview_json(value)
            } else {
                value_json_mode(value, data.secret_reply.is_some())
            };
            ffi::g_object_unref(value.cast());
            json.ok_or(ScriptError::TooLarge)
        }
    };
    if let Some(reply) = data.secret_reply {
        let outcome = outcome.map(SecretText::new).map_err(|error| match error {
            ScriptError::Failed(message) => {
                drop(SecretText::new(message));
                ScriptError::Failed("Private script evaluation failed.".into())
            }
            error => error,
        });
        if let Some(reply) = reply.upgrade() {
            *reply.value.borrow_mut() = Some(outcome);
        }
    } else if let Some(reply) = data.private_reply {
        if let Some(reply) = reply.upgrade() {
            *reply.borrow_mut() = Some(outcome);
        }
    } else if let Some(hub) = data.hub.upgrade() {
        hub.push(PageEvent::ScriptResult {
            id: data.id,
            result: outcome,
        });
    }
}

extern "C" fn on_data_cleared(
    source: *mut c_void,
    result: *mut ffi::GAsyncResult,
    data: *mut c_void,
) {
    // SAFETY: `data` is the box `clear_website_data` leaked; reclaimed once.
    let data = unsafe { Box::from_raw(data.cast::<AsyncData>()) };
    let mut error: *mut ffi::GError = core::ptr::null_mut();
    // SAFETY: `source` is the data manager the task was started on.
    let outcome = unsafe {
        if webkit_website_data_manager_clear_finish(source.cast(), result, &mut error) != 0 {
            Ok(())
        } else {
            let message = if error.is_null() {
                String::new()
            } else {
                let message = native_text((*error).message).unwrap_or_default();
                ffi::g_error_free(error);
                message
            };
            Err(message)
        }
    };
    if let Some(hub) = data.hub.upgrade() {
        hub.push(PageEvent::DataCleared {
            id: data.id,
            result: outcome,
        });
    }
}

/// Disconnects a download's handlers, optionally cancels it, and releases
/// the slot's reference and callback data.
///
/// # Safety
///
/// `slot` came from [`PageHub::adopt_download`] and is released once.
unsafe fn release_slot(slot: DownloadSlot, cancel: bool) {
    // SAFETY: forwarded to the caller's contract. Handlers go first, so a
    // cancel's `failed`/`finished` emissions reach nothing owned here.
    unsafe {
        for handler in &slot.handlers {
            ffi::g_signal_handler_disconnect(slot.download.cast(), *handler);
        }
        if cancel {
            ffi::webkit_download_cancel(slot.download);
        }
        ffi::g_object_unref(slot.download.cast());
        drop(Box::from_raw(slot.data));
    }
}

/// Creates a fresh file for a download in `dir`: the safe name, or
/// `name (2).ext` and so on when it is taken. Exclusive creation, so an
/// existing file (or a link planted under that name) is never written.
fn reserve_download_file(
    dir: &std::path::Path,
    suggested: &str,
) -> std::io::Result<(std::path::PathBuf, std::fs::File)> {
    let name = crate::page::safe_download_name(suggested);
    let (stem, extension) = match name.rsplit_once('.') {
        Some((stem, extension)) if !stem.is_empty() => (stem.to_owned(), format!(".{extension}")),
        _ => (name.clone(), String::new()),
    };
    for attempt in 1..=100u32 {
        let candidate = if attempt == 1 {
            name.clone()
        } else {
            format!("{stem} ({attempt}){extension}")
        };
        let path = dir.join(candidate);
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "no free name for the download",
    ))
}

/// The hub and id behind a download signal, if the session still exists.
///
/// # Safety
///
/// `data` is a live `DownloadData`.
unsafe fn download_hub(data: *mut c_void) -> Option<(Rc<PageHub>, PageRequestId)> {
    // SAFETY: forwarded to the caller's contract.
    let data = unsafe { &*data.cast::<DownloadData>() };
    data.hub.upgrade().map(|hub| (hub, data.id))
}

fn download_response(download: *mut ffi::WebKitDownload) -> Option<crate::page::DownloadResponse> {
    // SAFETY: callers retain this native download for synchronous response/header lookup.
    let response = unsafe { webkit_download_get_response(download) };
    if response.is_null() {
        return None;
    }
    // SAFETY: every returned pointer is borrowed from the retained response during this function.
    let (url, status, length, headers) = unsafe {
        (
            super::policy::scan_bounded_native_uri(
                ffi::webkit_uri_response_get_uri(response),
                super::policy::MAX_POLICY_URI_BYTES,
            )
            .ok()?,
            ffi::webkit_uri_response_get_status_code(response),
            webkit_uri_response_get_content_length(response),
            ffi::webkit_uri_response_get_http_headers(response),
        )
    };
    let header = |name: &std::ffi::CStr| -> Option<String> {
        if headers.is_null() {
            return None;
        }
        // SAFETY: the borrowed headers and static NUL-terminated name remain live through this lookup and bounded scan.
        let value = unsafe {
            super::policy::scan_bounded_native_uri(
                ffi::soup_message_headers_get_one(headers, name.as_ptr()),
                2048,
            )
            .ok()?
        };
        (value.len() <= 2048 && !value.contains(['\r', '\n'])).then_some(value)
    };
    Some(crate::page::DownloadResponse {
        url: PolicyUrl::new(url),
        status,
        length: (length > 0).then_some(length),
        ranges: header(c"Accept-Ranges").is_some_and(|v| v.eq_ignore_ascii_case("bytes")),
        etag: header(c"ETag"),
        modified: header(c"Last-Modified"),
        range: header(c"Content-Range"),
        coding: header(c"Content-Encoding"),
    })
}

extern "C" fn on_download_destination(
    download: *mut ffi::WebKitDownload,
    suggested: *const c_char,
    data: *mut c_void,
) -> ffi::GBoolean {
    // SAFETY: GSignal passes this download's live data.
    let Some((hub, id)) = (unsafe { download_hub(data) }) else {
        // The session is gone: refuse, rather than let WebKit's default put
        // the file in ~/Downloads.
        // SAFETY: the download is live for this callback.
        unsafe { ffi::webkit_download_cancel(download) };
        return ffi::G_TRUE;
    };
    // SAFETY: WebKit passes a live suggested name for this callback.
    let suggested = unsafe { native_text(suggested) }.unwrap_or_default();
    if let Some(response) = download_response(download) {
        if let Some(slot) = hub
            .state
            .borrow_mut()
            .downloads
            .iter_mut()
            .find(|slot| slot.id == id)
        {
            slot.response = Some(response.clone());
        }
        hub.push(PageEvent::DownloadResponse { id, response });
    }
    let dir = hub.state.borrow().downloads_dir.clone();
    let reserved = dir
        .as_deref()
        .map(|dir| reserve_download_file(dir, &suggested));
    match reserved {
        Some(Ok((path, reservation))) => {
            let destination = c_text(&path.to_string_lossy());
            // SAFETY: the download is live; the file was created for it, so
            // WebKit may replace it.
            unsafe {
                webkit_download_set_allow_overwrite(download, ffi::G_TRUE);
                webkit_download_set_destination(download, destination.as_ptr());
            }
            let url = {
                let mut state = hub.state.borrow_mut();
                let slot = state.downloads.iter_mut().find(|slot| slot.id == id);
                slot.map(|slot| {
                    slot.path = Some(path.clone());
                    slot.reserved = Some(reservation);
                    slot.url.clone()
                })
            };
            if let Some(url) = url {
                hub.push(PageEvent::DownloadStarted {
                    id,
                    url,
                    suggested_name: suggested,
                    path,
                });
            }
        }
        // No directory any more, or no file could be made: refuse it.
        // SAFETY: the download is live.
        _ => unsafe { ffi::webkit_download_cancel(download) },
    }
    ffi::G_TRUE
}

extern "C" fn on_download_data(
    download: *mut ffi::WebKitDownload,
    _length: u64,
    data: *mut c_void,
) {
    // SAFETY: GSignal passes this download's live data.
    let Some((hub, id)) = (unsafe { download_hub(data) }) else {
        return;
    };
    // SAFETY: the download and its response are live for this callback.
    let (received, expected) = unsafe {
        let response = webkit_download_get_response(download);
        let expected = if response.is_null() {
            0
        } else {
            webkit_uri_response_get_content_length(response)
        };
        (webkit_download_get_received_data_length(download), expected)
    };
    let identity = hub
        .state
        .borrow()
        .downloads
        .iter()
        .find(|s| s.id == id)
        .and_then(|s| s.response.as_ref())
        .is_none_or(|r| {
            r.coding
                .as_deref()
                .is_none_or(|v| v.eq_ignore_ascii_case("identity"))
        });
    let expected = (identity && expected > 0).then_some(expected);
    {
        let mut state = hub.state.borrow_mut();
        if let Some(slot) = state.downloads.iter_mut().find(|slot| slot.id == id)
            && slot.partial.is_none()
            && let Some(path) = &slot.path
        {
            // WebKit writes a sibling .wkdownload and renames it only after successful completion.
            let mut writing = path.as_os_str().to_os_string();
            writing.push(".wkdownload");
            if let Ok(file) = rustix::fs::open(
                std::path::Path::new(&writing),
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map(std::fs::File::from)
                && file.metadata().is_ok_and(|m| m.is_file() && m.len() > 0)
            {
                slot.partial = Some(std::sync::Arc::new(file));
            }
        }
    }
    // Report about every 1 % (and at least every 256 KiB of growth), not
    // every network read.
    let step = expected.map_or(256 * 1024, |total| (total / 100).max(1));
    let report = {
        let mut state = hub.state.borrow_mut();
        state
            .downloads
            .iter_mut()
            .find(|slot| slot.id == id)
            .is_some_and(|slot| {
                let due =
                    received.saturating_sub(slot.reported) >= step || expected == Some(received);
                if due {
                    slot.reported = received;
                }
                due
            })
    };
    if report {
        hub.push(PageEvent::DownloadProgress {
            id,
            received,
            expected,
        });
    }
}

extern "C" fn on_download_failed(
    _download: *mut ffi::WebKitDownload,
    error: *mut ffi::GError,
    data: *mut c_void,
) {
    // SAFETY: GSignal passes this download's live data.
    let Some((hub, id)) = (unsafe { download_hub(data) }) else {
        return;
    };
    // SAFETY: WebKit passes a live error for this callback.
    let (message, cancelled) = unsafe {
        if error.is_null() {
            (String::new(), false)
        } else {
            let domain = native_text(ffi::g_quark_to_string((*error).domain)).unwrap_or_default();
            (
                native_text((*error).message).unwrap_or_default(),
                // WEBKIT_DOWNLOAD_ERROR_CANCELLED_BY_USER
                domain == "WebKitDownloadError" && (*error).code == 400,
            )
        }
    };
    let mut state = hub.state.borrow_mut();
    if let Some(slot) = state.downloads.iter_mut().find(|slot| slot.id == id) {
        slot.failure = Some((message, cancelled));
    }
}

extern "C" fn on_download_finished(download: *mut ffi::WebKitDownload, data: *mut c_void) {
    // SAFETY: GSignal passes this download's live data.
    let Some((hub, id)) = (unsafe { download_hub(data) }) else {
        return;
    };
    let Some(mut slot) = hub.take_download(id) else {
        return;
    };
    if slot.failure.is_none() {
        // SAFETY: the taken slot retains the native download and its borrowed response through this callback.
        let (received, expected) = unsafe {
            let response = webkit_download_get_response(download);
            (
                webkit_download_get_received_data_length(download),
                if response.is_null() {
                    0
                } else {
                    webkit_uri_response_get_content_length(response)
                },
            )
        };
        let identity = slot.response.as_ref().is_none_or(|r| {
            r.coding
                .as_deref()
                .is_none_or(|v| v.eq_ignore_ascii_case("identity"))
        });
        let received = slot
            .partial
            .as_ref()
            .and_then(|f| f.metadata().ok())
            .map_or(received, |m| m.len());
        hub.push(PageEvent::DownloadProgress {
            id,
            received,
            expected: (identity && expected > 0).then_some(expected),
        });
        if slot.response.as_ref().is_some_and(|r| {
            r.coding
                .as_deref()
                .is_none_or(|v| v.eq_ignore_ascii_case("identity"))
        }) && expected > 0
            && received != expected
        {
            slot.failure = Some(("The server sent an incomplete response body".into(), false));
        }
    }
    let event = match (&slot.failure, &slot.path) {
        (None, Some(path)) => PageEvent::DownloadFinished {
            id,
            path: path.clone(),
        },
        (failure, path) => {
            if let Some(path) = path {
                if let Some(file) = &slot.partial {
                    let _ = enzui_security::tempstage::remove_if_path_names_file(path, file);
                }
                if let Some(file) = &slot.reserved {
                    let _ = enzui_security::tempstage::remove_if_path_names_file(path, file);
                }
            }
            let (message, cancelled) = failure.clone().unwrap_or_default();
            let partial = slot
                .partial
                .as_ref()
                .zip(slot.response.as_ref().filter(|r| r.resumable()))
                .zip(slot.path.as_ref())
                .and_then(|((file, response), path)| {
                    crate::page::PartialDownload::new(
                        std::sync::Arc::clone(file),
                        response.clone(),
                        path.clone(),
                    )
                });
            if let Some(partial) = partial.filter(|_| !cancelled || slot.pause_requested) {
                if slot.pause_requested && cancelled {
                    PageEvent::DownloadPaused { id, partial }
                } else {
                    PageEvent::DownloadInterrupted {
                        id,
                        partial,
                        message,
                    }
                }
            } else {
                PageEvent::DownloadFailed {
                    id,
                    message,
                    cancelled,
                }
            }
        }
    };
    hub.push(event);
    // SAFETY: the slot was taken from the hub, so it is released once; `data`
    // is not used after this.
    unsafe { release_slot(slot, false) };
}

extern "C" fn on_show_option_menu(
    _view: *mut ffi::WebKitWebView,
    menu: *mut WebKitOptionMenu,
    area: *mut WebKitRectangle,
    data: *mut c_void,
) -> ffi::GBoolean {
    if menu.is_null() {
        return ffi::G_FALSE;
    }
    // SAFETY: GSignal passes the installed data pointer.
    let hub = unsafe { hub(data) };
    if !hub.admit(DeclinedPrompt::OptionMenu) {
        // WebKit's own handling: WPE draws nothing.
        return ffi::G_FALSE;
    }
    // SAFETY: the menu, its items and the rectangle are live for this
    // callback; every string is copied, bounded.
    let (items, area) = unsafe {
        let count = webkit_option_menu_get_n_items(menu);
        if count as usize > crate::page::MAX_OPTION_MENU_ITEMS {
            hub.push(PageEvent::PromptDeclined(DeclinedPrompt::OptionMenu));
            return ffi::G_FALSE;
        }
        let mut items = Vec::with_capacity(count as usize);
        let mut text_bytes = 0usize;
        for index in 0..count {
            let item = webkit_option_menu_get_item(menu, index);
            if item.is_null() {
                hub.push(PageEvent::PromptDeclined(DeclinedPrompt::OptionMenu));
                return ffi::G_FALSE;
            }
            let label = native_text(webkit_option_menu_item_get_label(item)).unwrap_or_default();
            let tooltip = native_text(webkit_option_menu_item_get_tooltip(item))
                .filter(|tip| !tip.is_empty());
            text_bytes = text_bytes
                .saturating_add(label.len())
                .saturating_add(tooltip.as_ref().map_or(0, String::len));
            if text_bytes > crate::page::MAX_OPTION_MENU_TEXT_BYTES {
                hub.push(PageEvent::PromptDeclined(DeclinedPrompt::OptionMenu));
                return ffi::G_FALSE;
            }
            items.push(OptionMenuItem {
                label,
                tooltip,
                group_label: webkit_option_menu_item_is_group_label(item) != 0,
                group_child: webkit_option_menu_item_is_group_child(item) != 0,
                enabled: webkit_option_menu_item_is_enabled(item) != 0,
                selected: webkit_option_menu_item_is_selected(item) != 0,
            });
        }
        let area = if area.is_null() {
            ViewRect::default()
        } else {
            ViewRect {
                x: (*area).x,
                y: (*area).y,
                width: (*area).width,
                height: (*area).height,
            }
        };
        (items, area)
    };
    let id = hub.mint();
    let menu_data = Box::into_raw(Box::new(MenuData {
        // SAFETY: GSignal passes the installed data pointer.
        hub: Rc::downgrade(&unsafe { data_hub_rc(data) }),
        id,
    }));
    let close = callback!(on_option_menu_close, fn(*mut WebKitOptionMenu, *mut c_void));
    // SAFETY: the menu is live; the reference below keeps it so until the
    // handler is disconnected.
    let handler = unsafe {
        ffi::g_object_ref(menu.cast());
        let name = c"close";
        ffi::g_signal_connect_data(
            menu.cast(),
            name.as_ptr(),
            close,
            menu_data.cast(),
            core::ptr::null_mut(),
            0,
        )
    };
    if handler == 0 {
        // SAFETY: nothing connected; release what was taken.
        unsafe {
            drop(Box::from_raw(menu_data));
            ffi::g_object_unref(menu.cast());
        }
        return ffi::G_FALSE;
    }
    hub.state
        .borrow_mut()
        .pending
        .push((id, Pending::Menu(menu, handler, menu_data)));
    hub.push(PageEvent::OptionMenu(OptionMenuRequest { id, items, area }));
    ffi::G_TRUE
}

/// The `Rc` behind a signal's data pointer.
///
/// # Safety
///
/// `data` is a live `SignalData`.
unsafe fn data_hub_rc(data: *mut c_void) -> Rc<PageHub> {
    // SAFETY: forwarded to the caller's contract.
    Rc::clone(unsafe { &(*data.cast::<SignalData>()).hub })
}

extern "C" fn on_option_menu_close(_menu: *mut WebKitOptionMenu, data: *mut c_void) {
    // SAFETY: `data` is this menu's live `MenuData`; copied before release.
    let (hub, id) = unsafe {
        let data = &*data.cast::<MenuData>();
        (data.hub.upgrade(), data.id)
    };
    let Some(hub) = hub else {
        return;
    };
    if let Some(Pending::Menu(menu, handler, data)) = hub.take_pending(id) {
        // SAFETY: taken from the hub, so released once. Disconnecting the
        // handler from inside its own emission is allowed; `close` is not
        // called again for a menu WebKit is closing.
        unsafe {
            ffi::g_signal_handler_disconnect(menu.cast(), handler);
            drop(Box::from_raw(data));
            ffi::g_object_unref(menu.cast());
        }
        hub.push(PageEvent::OptionMenuClosed { id });
    }
}

extern "C" fn on_ready_to_show(_view: *mut ffi::WebKitWebView, data: *mut c_void) {
    // SAFETY: GSignal passes the installed data pointer.
    unsafe { hub(data) }.push(PageEvent::ReadyToShow);
}

extern "C" fn on_run_as_modal(_view: *mut ffi::WebKitWebView, data: *mut c_void) {
    // SAFETY: GSignal passes the installed data pointer.
    unsafe { hub(data) }.push(PageEvent::RunAsModal);
}

extern "C" fn on_enter_fullscreen(
    _view: *mut ffi::WebKitWebView,
    data: *mut c_void,
) -> ffi::GBoolean {
    // SAFETY: GSignal passes the installed data pointer.
    unsafe { hub(data) }.push(PageEvent::Fullscreen(true));
    // Allow it; the host decides what the window does.
    ffi::G_FALSE
}

extern "C" fn on_leave_fullscreen(
    _view: *mut ffi::WebKitWebView,
    data: *mut c_void,
) -> ffi::GBoolean {
    // SAFETY: GSignal passes the installed data pointer.
    unsafe { hub(data) }.push(PageEvent::Fullscreen(false));
    ffi::G_FALSE
}

extern "C" fn on_show_notification(
    _view: *mut ffi::WebKitWebView,
    notification: *mut WebKitNotification,
    data: *mut c_void,
) -> ffi::GBoolean {
    if notification.is_null() {
        return ffi::G_FALSE;
    }
    // SAFETY: GSignal supplies the live binding payload on its owner thread.
    let page = unsafe { &(*data.cast::<SignalData>()).hub };
    // SAFETY: the notification is live for this callback.
    let origin = unsafe { notifications::native_origin(notification) };
    let globally_blocked = page.state.borrow().notifications_blocked;
    if globally_blocked || page.site_permissions_enabled() {
        // WebKit's process cache can still hold an earlier grant, so the host
        // table must hold a current grant for the origin WebKit recorded for
        // the document that showed it.
        let refused = origin.as_ref().is_none_or(|origin| {
            page.site_permission_grant(&crate::site_permissions::SitePermission {
                requesting_origin: origin.clone(),
                top_origin: origin.clone(),
                kind: crate::web::policy::PermissionKind::Notifications,
            }) != Some(true)
        });
        if refused {
            // SAFETY: the live native notification accepts closure during the show callback.
            unsafe { webkit_notification_close(notification) };
            return ffi::G_TRUE;
        }
    }
    // SAFETY: the notification is live for this callback; strings copied.
    let request = unsafe {
        NotificationRequest {
            id: webkit_notification_get_id(notification),
            origin,
            title: native_text(webkit_notification_get_title(notification)).unwrap_or_default(),
            body: native_text(webkit_notification_get_body(notification)).unwrap_or_default(),
            tag: native_text(webkit_notification_get_tag(notification))
                .filter(|tag| !tag.is_empty()),
        }
    };
    page.keep_notification(notification, request.id, request.origin.clone());
    page.push(PageEvent::Notification(request));
    // Shown by the host; WPE has no notification UI of its own.
    ffi::G_TRUE
}

extern "C" fn on_query_permission_state(
    _view: *mut ffi::WebKitWebView,
    query: *mut WebKitPermissionStateQuery,
    data: *mut c_void,
) -> ffi::GBoolean {
    if query.is_null() {
        return ffi::G_FALSE;
    }
    // SAFETY: the query is live for this callback; its name is copied.
    let name =
        unsafe { native_text(webkit_permission_state_query_get_name(query)) }.unwrap_or_default();
    use crate::web::policy::{PermissionKind, RequestKind};
    let kind = match name.as_str() {
        "geolocation" => Some(PermissionKind::Geolocation),
        "notifications" => Some(PermissionKind::Notifications),
        "camera" => Some(PermissionKind::Camera),
        "microphone" => Some(PermissionKind::Microphone),
        _ => None,
    };
    // SAFETY: GSignal passes the installed data pointer.
    let hub = unsafe { hub(data) };
    if hub.site_permissions_enabled() {
        let permission = kind.and_then(|kind| {
            // SAFETY: the view is live and the fork exposes scoped origin snapshots for this query callback.
            unsafe {
                permissions::native_permission(
                    _view.cast(),
                    kind,
                    c"enzui-permission-query-requesting-origin-v1",
                    c"enzui-permission-query-top-origin-v1",
                )
            }
        });
        let state = match permission
            .as_ref()
            .and_then(|p| hub.site_permission_grant(p))
        {
            Some(true) => WEBKIT_PERMISSION_STATE_GRANTED,
            Some(false) => WEBKIT_PERMISSION_STATE_DENIED,
            _ => 2,
        };
        // SAFETY: this is the one terminal answer to the live permission query.
        unsafe { webkit_permission_state_query_finish(query, state) };
        return ffi::G_TRUE;
    }
    let globally_blocked =
        kind == Some(PermissionKind::Notifications) && hub.state.borrow().notifications_blocked;
    let granted = !globally_blocked
        && kind.is_some_and(|kind| {
            hub.popup_policy().is_some_and(|policy| {
                policy.decide(&RequestKind::Permission(kind)) == crate::web::Decision::Allow
            })
        });
    let state = if granted {
        WEBKIT_PERMISSION_STATE_GRANTED
    } else {
        WEBKIT_PERMISSION_STATE_DENIED
    };
    // SAFETY: one terminal answer for the live query.
    unsafe { webkit_permission_state_query_finish(query, state) };
    ffi::G_TRUE
}

extern "C" fn on_insecure_content(_view: *mut ffi::WebKitWebView, event: c_int, data: *mut c_void) {
    let kind = if event == 0 {
        InsecureContent::Ran
    } else {
        InsecureContent::Displayed
    };
    // SAFETY: GSignal passes the installed data pointer.
    unsafe { hub(data) }.push(PageEvent::InsecureContent(kind));
}

extern "C" fn on_mouse_target_changed(
    _view: *mut ffi::WebKitWebView,
    hit: *mut WebKitHitTestResult,
    _modifiers: c_uint,
    data: *mut c_void,
) {
    // SAFETY: the hit-test result is live for this callback.
    let link = unsafe {
        if hit.is_null()
            || webkit_hit_test_result_get_context(hit) & WEBKIT_HIT_TEST_RESULT_CONTEXT_LINK == 0
        {
            None
        } else {
            native_uri(webkit_hit_test_result_get_link_uri(hit))
        }
    };
    // WebKit emits this only when what is under the pointer changes in a way
    // that matters (the gate moves across plain elements and sees one event,
    // for the link), so each emission is a change.
    // SAFETY: GSignal passes the installed data pointer.
    unsafe { hub(data) }.push(PageEvent::HoveredLink(link));
}

extern "C" fn on_notify_playing_audio(
    object: *mut c_void,
    _spec: *mut GParamSpec,
    data: *mut c_void,
) {
    // SAFETY: `object` is the live view emitting the notification.
    let playing = unsafe { webkit_web_view_is_playing_audio(object.cast()) } != 0;
    // SAFETY: GSignal passes the installed data pointer.
    unsafe { hub(data) }.push(PageEvent::PlayingAudio(playing));
}

#[cfg(test)]
mod metadata_revision_tests {
    use super::*;

    #[test]
    fn native_readiness_rejects_unknown_missing_and_error_replies() {
        use NativeDocumentReadiness::*;
        assert_eq!(
            decode_native_readiness(Some("enzui-document-ready-v1"), false),
            Ready
        );
        assert_eq!(
            decode_native_readiness(Some("enzui-document-busy-v1"), false),
            Busy
        );
        assert_eq!(
            decode_native_readiness(Some("enzui-document-probe-unavailable-v1"), false),
            Unavailable
        );
        for name in [
            None,
            Some("enzui-document-unknown-v1"),
            Some("enzui-document-ready-v1-extra"),
        ] {
            assert_eq!(
                decode_native_readiness(name, false),
                Failed,
                "unrecognized readiness reply was accepted"
            );
        }
        for name in [
            Some("enzui-document-ready-v1"),
            Some("enzui-document-probe-unavailable-v1"),
        ] {
            assert_eq!(
                decode_native_readiness(name, true),
                Failed,
                "failed native operation became a successful readiness reply"
            );
        }
    }

    #[test]
    fn metadata_revision_survives_title_event_eviction_and_drain() {
        let hub = PageHub::default();
        let before = hub.metadata_revision();
        hub.push(PageEvent::TitleChanged("current title".into()));
        let changed = hub.metadata_revision();
        assert_ne!(
            changed, before,
            "title publication advances the independent revision"
        );
        for _ in 0..=PAGE_EVENT_CAPACITY {
            hub.push(PageEvent::Progress(0.5));
        }
        assert!(hub.dropped() > 0);
        assert!(
            !hub.take_events()
                .iter()
                .any(|event| matches!(event, PageEvent::TitleChanged(_)))
        );
        assert_eq!(
            hub.metadata_revision(),
            changed,
            "draining or evicting the event does not consume current-state revision"
        );
        hub.push(PageEvent::UriChanged(PolicyUrl::new(
            "https://example.com/next",
        )));
        assert_ne!(hub.metadata_revision(), changed);
    }
}

#[cfg(test)]
mod secret_buffer_tests {
    #[test]
    fn private_native_text_is_cleared_before_free() {
        let mut allocation = b"fixture-private-native-json\0".to_vec();
        // SAFETY: the vector exclusively owns a writable NUL-terminated allocation throughout the call.
        unsafe {
            super::wipe_native_text(allocation.as_mut_ptr().cast());
        }
        assert!(
            allocation.iter().all(|byte| *byte == 0),
            "private native JSON must be wiped before GLib frees it"
        );
    }
}

#[cfg(test)]
mod host_request_tests {
    use super::*;

    #[test]
    fn a_popup_holds_navigations_only_until_its_host_lets_them_through() {
        let mut navigations = HeldNavigations::default();
        // An ordinary view decides at once.
        assert_eq!(navigations.hold(1), Err(1));
        navigations.awaiting_host = true;
        assert_eq!(navigations.hold(1), Ok(()));
        assert_eq!(navigations.hold(2), Ok(()));
        assert_eq!(navigations.release(), [1, 2]);
        // Released: the next one is decided at once, and nothing is left.
        assert_eq!(navigations.hold(3), Err(3));
        assert!(navigations.release().is_empty());
        // A page cannot pile up decisions without end.
        navigations.awaiting_host = true;
        for decision in 0..MAX_HELD_NAVIGATIONS {
            assert_eq!(navigations.hold(decision), Ok(()));
        }
        assert_eq!(navigations.hold(99), Err(99));
    }
}
