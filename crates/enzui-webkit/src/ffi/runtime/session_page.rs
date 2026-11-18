//! The page conversation on [`WebSession`]: events, navigation,
//! settings, prompts, scripts, find and website data. Vocabulary lives in
//! [`crate::page`]; the native half in [`crate::ffi::page`].

use std::path::PathBuf;
use std::time::Duration;

use crate::web::RedirectCapture;

use super::*;
use crate::ffi::page::{AnswerError, PageBinding};
use crate::page::{
    AuthAnswer, CookiePolicy, PageEvent, PagePrompts, PageRequestId, ScriptDialogAnswer,
    ScriptWorld, UserScript, WebSettings, WebsiteData,
};

impl WebSession {
    /// Sets this page's fallback families for unstyled, serif, sans-serif and code text.
    ///
    /// Author-requested named fonts and CSS sizes remain unchanged.
    ///
    /// # Errors
    /// Returns `FontSettingsUnavailable` for empty/interior-NUL names or unavailable settings.
    pub fn set_font_families(
        &self,
        standard: &str,
        serif: &str,
        sans_serif: &str,
        monospace: &str,
    ) -> Result<(), SessionError> {
        let mut families = Vec::with_capacity(4);
        for name in [standard, serif, sans_serif, monospace] {
            if name.trim().is_empty() {
                return Err(SessionError::FontSettingsUnavailable);
            }
            families.push(CString::new(name).map_err(|_| SessionError::FontSettingsUnavailable)?);
        }
        // SAFETY: the owner-thread session retains the view/settings; setters copy
        // each NUL-terminated family before its backing CString is dropped.
        unsafe {
            let settings = crate::ffi::page::sys::webkit_web_view_get_settings(self.web_view);
            if settings.is_null() {
                return Err(SessionError::FontSettingsUnavailable);
            }
            crate::ffi::page::sys::webkit_settings_set_default_font_family(
                settings,
                families[0].as_ptr(),
            );
            crate::ffi::page::sys::webkit_settings_set_serif_font_family(
                settings,
                families[1].as_ptr(),
            );
            crate::ffi::page::sys::webkit_settings_set_sans_serif_font_family(
                settings,
                families[2].as_ptr(),
            );
            crate::ffi::page::sys::webkit_settings_set_monospace_font_family(
                settings,
                families[3].as_ptr(),
            );
        }
        Ok(())
    }

    /// Sets the display's desktop font description used by CSS `system-ui`.
    ///
    /// Accepts a family followed by a point size, such as `Adwaita Sans 11`.
    /// The size does not override author-specified CSS sizes. All sessions on
    /// this display share the preference. Set it before loading content: a
    /// loaded page keeps the family it already resolved for `system-ui` until
    /// WebKit invalidates its system-font matches.
    ///
    /// # Errors
    /// Returns `FontSettingsUnavailable` for an empty/interior-NUL description
    /// or when the native display rejects the setting.
    pub fn set_system_font_name(&self, description: &str) -> Result<(), SessionError> {
        if description.trim().is_empty() {
            return Err(SessionError::FontSettingsUnavailable);
        }
        let value = CString::new(description).map_err(|_| SessionError::FontSettingsUnavailable)?;
        // SAFETY: the owner-thread session retains its view/display/settings;
        // the key and copied UTF-8 value outlive the call, and GError is freed once.
        let applied = unsafe {
            let display = crate::ffi::page::sys::webkit_web_view_get_display(self.web_view);
            if display.is_null() {
                return Err(SessionError::FontSettingsUnavailable);
            }
            let settings = ffi::wpe_display_get_settings(display);
            if settings.is_null() {
                return Err(SessionError::FontSettingsUnavailable);
            }
            let mut error = std::ptr::null_mut();
            let result = ffi::wpe_settings_set_string(
                settings,
                c"/wpe-platform/font-name".as_ptr(),
                value.as_ptr(),
                ffi::WPE_SETTINGS_SOURCE_APPLICATION,
                &mut error,
            );
            if !error.is_null() {
                ffi::g_error_free(error);
            }
            result != 0
        };
        if applied {
            Ok(())
        } else {
            Err(SessionError::FontSettingsUnavailable)
        }
    }

    /// Set the display's website color preference (`prefers-color-scheme`),
    /// including pages already loaded, which receive `matchMedia` change events.
    /// Every view on this session's display shares the preference.
    ///
    /// # Errors
    /// Returns `ThemeSettingsUnavailable` when the native display rejects the setting.
    pub fn set_preferred_dark(&self, dark: bool) -> Result<(), SessionError> {
        // SAFETY: the owner-thread session retains the view/display/settings; the static key lives through the call and any returned GError is freed once.
        let applied = unsafe {
            let display = crate::ffi::page::sys::webkit_web_view_get_display(self.web_view);
            if display.is_null() {
                return Err(SessionError::ThemeSettingsUnavailable);
            }
            let settings = ffi::wpe_display_get_settings(display);
            if settings.is_null() {
                return Err(SessionError::ThemeSettingsUnavailable);
            }
            let mut error = std::ptr::null_mut();
            let result = ffi::wpe_settings_set_boolean(
                settings,
                c"/wpe-platform/dark-mode".as_ptr(),
                i32::from(dark),
                ffi::WPE_SETTINGS_SOURCE_APPLICATION,
                &mut error,
            );
            if !error.is_null() {
                ffi::g_error_free(error);
            }
            result != 0
        };
        if applied {
            Ok(())
        } else {
            Err(SessionError::ThemeSettingsUnavailable)
        }
    }

    pub(super) fn page_binding(&self) -> &PageBinding {
        self.page
            .as_ref()
            .expect("the page binding is connected before a session is returned")
    }

    /// Whether page events await delivery, independently of metadata or frame changes.
    #[must_use]
    pub fn has_page_events(&self) -> bool {
        self.page_hub.has_events()
    }

    /// Everything the page has told the host since the last call, oldest
    /// first. Pump the session first; events arrive from its main context.
    /// Overflow preserves notifications for prompts still awaiting an answer;
    /// other oldest events may be dropped.
    pub fn take_page_events(&self) -> Vec<PageEvent> {
        // A popup the host never took that closed itself is released here.
        self.page_hub.reap_closed_popups();
        self.page_hub.take_events()
    }

    /// How many events were dropped because the host did not drain the
    /// queue ([`PAGE_EVENT_CAPACITY`](crate::page::PAGE_EVENT_CAPACITY)).
    #[must_use]
    pub fn page_events_dropped(&self) -> u64 {
        self.page_hub.dropped()
    }

    /// Stops any navigation to `capture` (a sign-in redirect URI) before it
    /// loads, in this view or a popup it opens, and reports it as
    /// [`PageEvent::RedirectCaptured`]. The capture runs before the
    /// navigation policy, so a loopback redirect the destination policy would
    /// refuse still reaches the host, and nothing connects to it.
    ///
    /// Returns `false` when the session already captures
    /// [`MAX_REDIRECT_CAPTURES`](crate::page::MAX_REDIRECT_CAPTURES) URIs.
    pub fn capture_redirect(&self, capture: RedirectCapture) -> bool {
        self.page_hub.add_capture(capture)
    }

    /// Stops capturing every redirect URI.
    pub fn clear_redirect_captures(&self) {
        self.page_hub.clear_captures();
    }

    /// Which page requests the host answers. Anything else is declined at
    /// once (see [`crate::page`]).
    pub fn set_page_prompts(&self, prompts: PagePrompts) {
        self.page_hub.set_prompts(prompts);
    }

    /// The prompts the host currently answers.
    #[must_use]
    pub fn page_prompts(&self) -> PagePrompts {
        self.page_hub.prompts()
    }

    /// Declines every prompt still waiting for the host (a dialog is
    /// dismissed, a chooser selects nothing, a challenge is cancelled), for a
    /// host that closed its prompt UI. Dropping the session does the same.
    /// Returns how many were waiting.
    pub fn decline_pending_prompts(&self) -> usize {
        self.page_binding().decline_pending()
    }

    /// Answers a [`PageEvent::OptionMenu`]: `Some(index)` picks that entry
    /// (as a person's click would, firing `change`), `None` dismisses the
    /// dropdown unchanged. An index past the list dismisses.
    pub fn answer_option_menu(
        &self,
        id: PageRequestId,
        choice: Option<usize>,
    ) -> Result<(), AnswerError> {
        self.page_binding().answer_option_menu(id, choice)
    }

    /// Mutes or unmutes the page's audio.
    pub fn set_muted(&self, muted: bool) {
        // SAFETY: a live view.
        unsafe {
            crate::ffi::page::sys::webkit_web_view_set_is_muted(
                self.web_view,
                if muted { ffi::G_TRUE } else { ffi::G_FALSE },
            );
        }
    }

    /// Whether the page's audio is muted.
    #[must_use]
    pub fn is_muted(&self) -> bool {
        // SAFETY: a live view.
        unsafe { crate::ffi::page::sys::webkit_web_view_get_is_muted(self.web_view) != 0 }
    }

    /// Tells the page the user clicked the notification with this
    /// [`crate::page::NotificationRequest::id`]; `false` when it is no longer shown.
    pub fn notification_clicked(&self, id: u64) -> bool {
        self.page_hub.click_notification(id)
    }

    /// Closes a notification the host shows, as when the user dismisses its
    /// desktop entry; [`PageEvent::NotificationClosed`] follows. `false` when
    /// it is no longer shown.
    pub fn close_notification(&self, id: u64) -> bool {
        self.page_hub.close_notification(id)
    }

    /// Clears this view's notification choices, cancels pending notification
    /// prompts and closes the notifications it shows; camera, microphone and
    /// location choices stay.
    pub fn reset_notification_permissions(&self) {
        self.page_hub.reset_notification_permissions();
    }

    /// Turns website notifications on or off for this view. Off, requests are
    /// denied without a prompt, nothing is delivered and shown notifications
    /// close; stored site choices survive turning them off and on again.
    pub fn set_notifications_enabled(&self, enabled: bool) {
        self.page_hub.set_notifications_enabled(enabled);
    }

    /// Whether the page is playing audio now.
    #[must_use]
    pub fn is_playing_audio(&self) -> bool {
        // SAFETY: a live view.
        unsafe { crate::ffi::page::sys::webkit_web_view_is_playing_audio(self.web_view) != 0 }
    }

    /// Answers a [`PageEvent::ScriptDialog`].
    pub fn answer_script_dialog(
        &self,
        id: PageRequestId,
        answer: &ScriptDialogAnswer,
    ) -> Result<(), AnswerError> {
        self.page_binding().answer_script_dialog(id, answer)
    }

    /// Shows `color` (red, green, blue, alpha) in the field of a
    /// [`PageEvent::ColorChooser`] while the person is still choosing: the
    /// page sees `input` events. The request stays open.
    pub fn preview_color(&self, id: PageRequestId, color: [u8; 4]) -> Result<(), AnswerError> {
        self.page_binding().preview_color(id, color)
    }

    /// Answers a [`PageEvent::ColorChooser`]: `Some(color)` sets the field
    /// and fires `change`, `None` puts back the colour it had.
    pub fn answer_color_chooser(
        &self,
        id: PageRequestId,
        color: Option<[u8; 4]>,
    ) -> Result<(), AnswerError> {
        self.page_binding().answer_color_chooser(id, color)
    }

    /// Does `fix` to the misspelled word the last [`PageEvent::ContextMenu`]
    /// reported in [`crate::page::ContextTarget::spelling`]. `false` when
    /// there is no such word any more: a context menu's word is fixed once,
    /// and the next menu replaces it.
    pub fn fix_spelling(&self, fix: crate::page::SpellingFix) -> bool {
        self.page_hub.fix_spelling(fix)
    }

    /// Turns spelling marks in editable text on, for the languages given as
    /// locale names (`en_US`), or off with an empty list. The setting belongs
    /// to the engine context, so it reaches every view. Words are checked
    /// with the dictionaries the system's spelling service (enchant) finds;
    /// a language it has no dictionary for is ignored.
    pub fn set_spell_checking(&self, languages: &[String]) {
        let names: Vec<CString> = languages
            .iter()
            .filter_map(|language| CString::new(language.as_str()).ok())
            .collect();
        let mut pointers: Vec<*const core::ffi::c_char> =
            names.iter().map(|name| name.as_ptr()).collect();
        pointers.push(core::ptr::null());
        // SAFETY: a live view's context is borrowed from it; the language
        // array is NULL-terminated and outlives the calls, which copy it.
        unsafe {
            let context = crate::ffi::page::sys::webkit_web_view_get_context(self.web_view);
            if context.is_null() {
                return;
            }
            if !names.is_empty() {
                crate::ffi::page::sys::webkit_web_context_set_spell_checking_languages(
                    context,
                    pointers.as_ptr(),
                );
            }
            crate::ffi::page::sys::webkit_web_context_set_spell_checking_enabled(
                context,
                if names.is_empty() {
                    ffi::G_FALSE
                } else {
                    ffi::G_TRUE
                },
            );
        }
    }

    /// Answers a [`PageEvent::FileChooser`] with absolute paths (the first
    /// only, unless the page accepts several), or `None` to cancel. The page
    /// receives the files' contents, so pass only what the person chose,
    /// through the file-chooser portal.
    pub fn answer_file_chooser(
        &self,
        id: PageRequestId,
        files: Option<&[PathBuf]>,
    ) -> Result<(), AnswerError> {
        self.page_binding().answer_file_chooser(id, files)
    }

    /// Answers a [`PageEvent::Authentication`]. Credentials are used for this
    /// challenge only and never stored by WebKit.
    /// NUL-bearing credentials return [`AnswerError::InvalidCredentials`]
    /// without consuming the challenge, so the host can correct its answer.
    pub fn answer_authentication(
        &self,
        id: PageRequestId,
        answer: &AuthAnswer,
    ) -> Result<(), AnswerError> {
        self.page_binding().answer_authentication(id, answer)
    }

    /// Reloads the page; `bypass_cache` revalidates every resource.
    ///
    /// After the renderer was lost ([`PageEvent::WebProcessTerminated`]) a
    /// fresh renderer is started and attested, and the page that was showing
    /// is loaded again.
    pub fn reload(&self, bypass_cache: bool) -> Result<(), SessionError> {
        if self.restore_after_renderer_loss()? {
            return Ok(());
        }
        self.require_navigable()?;
        self.page_hub.begin_host_navigation();
        // SAFETY: a live view.
        unsafe {
            if bypass_cache {
                crate::ffi::page::sys::webkit_web_view_reload_bypass_cache(self.web_view);
            } else {
                crate::ffi::page::sys::webkit_web_view_reload(self.web_view);
            }
        }
        Ok(())
    }

    /// Stops the current load.
    pub fn stop_loading(&self) {
        // SAFETY: a live view.
        unsafe { ffi::webkit_web_view_stop_loading(self.web_view) };
    }

    /// Goes back one history entry, through the navigation policy like any
    /// other navigation. Does nothing when [`can_go_back`](Self::can_go_back)
    /// is false.
    ///
    /// After the renderer was lost this returns to the page that was showing
    /// instead, as [`reload`](Self::reload) does: history steps are not
    /// replayed into a fresh renderer.
    pub fn go_back(&self) -> Result<(), SessionError> {
        if self.restore_after_renderer_loss()? {
            return Ok(());
        }
        self.require_navigable()?;
        self.navigate_document_history(-1)
    }

    /// Goes forward one history entry; after a renderer loss, see
    /// [`go_back`](Self::go_back).
    pub fn go_forward(&self) -> Result<(), SessionError> {
        if self.restore_after_renderer_loss()? {
            return Ok(());
        }
        self.require_navigable()?;
        self.navigate_document_history(1)
    }

    /// Whether a caller document precedes this one, excluding private attestation loads.
    #[must_use]
    pub fn can_go_back(&self) -> bool {
        !self.document_history_item(-1).is_null()
    }

    /// Whether a caller document follows this one, excluding private attestation loads.
    #[must_use]
    pub fn can_go_forward(&self) -> bool {
        !self.document_history_item(1).is_null()
    }

    /// Whether a load is in progress.
    #[must_use]
    pub fn is_loading(&self) -> bool {
        // SAFETY: a live view.
        unsafe { crate::ffi::page::sys::webkit_web_view_is_loading(self.web_view) != 0 }
    }

    /// The estimated load progress, from 0.0 to 1.0.
    #[must_use]
    pub fn load_progress(&self) -> f64 {
        // SAFETY: a live view.
        unsafe { crate::ffi::page::sys::webkit_web_view_get_estimated_load_progress(self.web_view) }
            .clamp(0.0, 1.0)
    }

    /// Asks the page to close, running its `beforeunload` handler. With no
    /// handler (or one that does not object) [`PageEvent::CloseRequested`]
    /// follows. A page that objects raises a before-unload
    /// [`PageEvent::ScriptDialog`]: answering `Accept` closes it
    /// (`CloseRequested`), `Dismiss` keeps it open and nothing follows. A host
    /// that did not opt into script dialogs gets the engine's decline, which
    /// leaves. The host still owns closing the session.
    pub fn try_close(&self) {
        // SAFETY: a live view.
        unsafe { crate::ffi::page::sys::webkit_web_view_try_close(self.web_view) };
    }

    /// Applies per-view engine settings. Popups opened from now on start
    /// with them too.
    pub fn apply_settings(&self, settings: &WebSettings) {
        // SAFETY: a live view.
        unsafe { crate::ffi::page::apply_settings(self.web_view, settings) };
        self.page_hub.record_settings(settings);
    }

    /// When the renderer was lost: starts and attests a fresh one (what any
    /// navigation does) and loads the last committed page, returning `true`.
    /// Without this, the bootstrap's inert page would be what a reload
    /// reloads.
    fn restore_after_renderer_loss(&self) -> Result<bool, SessionError> {
        if !self.renderer_lost() {
            return Ok(false);
        }
        let last = self.page_hub.last_committed();
        self.require_navigable()?;
        if let Some(uri) = last {
            self.begin_load_uri(&uri)?;
        }
        Ok(true)
    }

    /// Closes a popup reported as [`PageEvent::PopupOpened`] that the host
    /// does not want; it ends as [`PageEvent::PopupClosed`]. `false` when no
    /// such popup waits.
    pub fn discard_popup(&self, id: PageRequestId) -> bool {
        self.page_hub.discard_popup(id)
    }

    /// Every WebKit feature flag this build knows, with its default, for
    /// diagnostics.
    ///
    /// # Errors
    /// Returns [`crate::ffi::NativeThreadError`] if another thread owns WPE.
    /// Calling this before any display or session claims the runtime thread.
    pub fn feature_defaults() -> Result<Vec<(String, bool)>, crate::ffi::NativeThreadError> {
        crate::ffi::page::feature_defaults()
    }

    /// Opt in to experimental dictionary transport for cooperating HTTPS origins.
    /// WebKit retains its cache, privacy and request-eligibility checks. The
    /// default is disabled. Enabling affects the native process and can also
    /// affect other views sharing that process; it cannot be revoked in place.
    /// Returns `false` if the runtime lacks the feature or rejects the opt-in.
    #[must_use]
    pub fn enable_compression_dictionary_transport(&self) -> bool {
        // SAFETY: this session retains the view on its native owner thread.
        unsafe { crate::ffi::page::enable_compression_dictionary_transport(self.web_view) }
    }

    /// What the page that opened this view asked of its window: for a popup
    /// taken with [`Self::take_popup`], whether it wanted a popup window and
    /// of what size. A view no page opened reports the defaults.
    #[must_use]
    pub fn window_features(&self) -> crate::page::WindowFeatures {
        // SAFETY: a live view.
        unsafe { crate::ffi::page::window_features(self.web_view) }
    }

    /// The user agent the view sends now.
    #[must_use]
    pub fn user_agent(&self) -> String {
        // SAFETY: a live view.
        unsafe { crate::ffi::page::user_agent(self.web_view) }
    }

    /// Runs `script` in the page; its value arrives as
    /// [`PageEvent::ScriptResult`] with the returned id. Empty or NUL-bearing
    /// isolated world names are refused before execution.
    pub fn evaluate_script(
        &self,
        script: &str,
        world: &ScriptWorld,
    ) -> Result<PageRequestId, SessionError> {
        self.require_navigable()?;
        self.page_binding()
            .evaluate(script, world)
            .map_err(SessionError::InvalidScriptInput)
    }

    /// Evaluates private source in a named isolated world without public result events.
    ///
    /// Returns an owner-thread handle for protected JSON, cancelled by document
    /// navigation or session destruction. Page exception text is never returned.
    /// The host remains responsible for origin, document and user-approval checks.
    ///
    /// # Errors
    /// As [`Self::evaluate_script`]; an empty or NUL-bearing world is refused.
    pub fn evaluate_secret_script(
        &self,
        source: &enzui_security::secret::SecretText,
        world: &str,
    ) -> Result<crate::ffi::page::SecretScriptJob, SessionError> {
        self.require_navigable()?;
        self.page_binding()
            .evaluate_secret(source, world)
            .map_err(SessionError::InvalidScriptInput)
    }

    /// Evaluates private source in a named isolated world of one frame, while it
    /// still shows the document that posted a [`PageEvent::FrameSecretMessage`].
    ///
    /// Works like [`Self::evaluate_secret_script`]; the job is cancelled when the
    /// frame shows another document or the page navigates, and returns
    /// [`crate::page::ScriptError::Unavailable`] on a runtime without frame
    /// evaluation.
    ///
    /// # Errors
    /// As [`Self::evaluate_secret_script`].
    pub fn evaluate_secret_script_in_frame(
        &self,
        frame: &crate::page::FrameDocument,
        source: &enzui_security::secret::SecretText,
        world: &str,
    ) -> Result<crate::ffi::page::SecretScriptJob, SessionError> {
        self.require_navigable()?;
        self.page_binding()
            .evaluate_secret_in_frame(frame, source, world)
            .map_err(SessionError::InvalidScriptInput)
    }

    /// Evaluates once and returns a bounded preview through `PageEvent::ScriptResult`.
    ///
    /// The JSON object contains `kind` and `preview` strings. Kind `json` carries
    /// serialized JSON; `undefined` and `display` carry human-readable text.
    /// Unsupported result serialization returns [`crate::page::ScriptError::Unavailable`].
    /// Source effects or pending Promise work may already exist; this does not
    /// await a Promise or retry the source.
    ///
    /// # Errors
    /// As [`Self::evaluate_script`]; previews have the same bounded completion event.
    pub fn evaluate_script_preview(
        &self,
        script: &str,
        world: &ScriptWorld,
    ) -> Result<PageRequestId, SessionError> {
        self.require_navigable()?;
        self.page_binding()
            .evaluate_preview(script, world)
            .map_err(SessionError::InvalidScriptInput)
    }

    /// Runs an async function body once and returns a bounded preview of its
    /// settled value through `PageEvent::ScriptResult`.
    ///
    /// The body may `await` and must `return` its result; without a `return`
    /// the preview is `undefined`. A rejection arrives as
    /// [`crate::page::ScriptError::Failed`]. Unlike
    /// [`Self::evaluate_script_preview`], top-level declarations stay local to
    /// the body. Navigation or session drop cancels the pending result.
    ///
    /// # Errors
    /// As [`Self::evaluate_script_preview`].
    pub fn evaluate_async_function_preview(
        &self,
        body: &str,
        world: &ScriptWorld,
    ) -> Result<PageRequestId, SessionError> {
        self.require_navigable()?;
        self.page_binding()
            .evaluate_async_preview(body, world)
            .map_err(SessionError::InvalidScriptInput)
    }

    /// Injects `script` into every document this view loads from now on.
    ///
    /// # Errors
    ///
    /// Refuses embedded NUL bytes in source or world names, and empty isolated
    /// world names. No script is installed when validation fails.
    pub fn add_user_script(
        &self,
        script: &UserScript,
    ) -> Result<(), crate::page::ScriptInputError> {
        self.page_binding().add_user_script(script)
    }

    /// Injects a script only into documents matching the supplied URL patterns.
    ///
    /// Accepts page and isolated worlds. Patterns use WebKit user-content syntax,
    /// as described by [`crate::page::ContentScript`], and are checked before
    /// executing the script. Removal uses [`Self::remove_user_scripts`].
    ///
    /// # Errors
    /// Refuses empty match lists, invalid or excessive patterns, embedded NUL
    /// bytes, and invalid isolated-world names before installing anything.
    pub fn add_user_script_matching(
        &self,
        script: &UserScript,
        matches: &[String],
        excludes: &[String],
    ) -> Result<(), crate::page::ContentInjectionError> {
        self.page_binding()
            .add_user_script_matching(script, matches, excludes)
    }

    /// Install a browser-extension content script, limited to matching pages
    /// and isolated from page JavaScript, for documents loaded from now on.
    ///
    /// # Errors
    /// Refuses a missing or invalid match pattern, too many patterns, an empty
    /// world, or NUL bytes, before anything is installed.
    pub fn add_content_script(
        &self,
        script: &crate::page::ContentScript,
    ) -> Result<crate::page::ContentInjectionId, crate::page::ContentInjectionError> {
        self.page_binding().add_content_script(script)
    }

    /// Install user-level CSS in this view, including opaque documents in selected frames.
    ///
    /// Applies to existing and future documents until removed with
    /// [`Self::remove_content_injection`]. User-level `!important` rules override
    /// author inline styles and do not depend on the document's CSP. Scope the
    /// CSS when different documents in the view require different rules.
    ///
    /// # Errors
    /// Refuses NUL bytes in source or a native stylesheet allocation failure.
    pub fn add_user_style(
        &self,
        source: &str,
        frames: crate::page::ScriptFrames,
    ) -> Result<crate::page::ContentInjectionId, crate::page::ContentInjectionError> {
        self.page_binding().add_user_style(source, frames)
    }

    /// Install a browser-extension style sheet at user level, limited to matching pages.
    ///
    /// # Errors
    /// As [`Self::add_content_script`].
    pub fn add_content_style(
        &self,
        style: &crate::page::ContentStyle,
    ) -> Result<crate::page::ContentInjectionId, crate::page::ContentInjectionError> {
        self.page_binding().add_content_style(style)
    }

    /// Remove one injection: styles update live documents; scripts stop in future documents.
    /// Returns false for an unknown or already removed identity.
    pub fn remove_content_injection(&self, id: crate::page::ContentInjectionId) -> bool {
        self.page_binding().remove_content_injection(id)
    }

    /// Removes every injected user script.
    pub fn remove_user_scripts(&self) {
        self.page_binding().remove_user_scripts();
    }

    /// Lets the page post to the host through
    /// `window.webkit.messageHandlers.NAME.postMessage(value)`; each post
    /// arrives as [`PageEvent::ScriptMessage`]. Every frame in `world` can
    /// post, third-party iframes included.
    /// Returns `false` for empty handler or isolated-world names, embedded NUL
    /// bytes in either name, or a handler already registered in another world.
    pub fn register_message_handler(&mut self, name: &str, world: &ScriptWorld) -> bool {
        self.page
            .as_mut()
            .expect("the page binding is connected before a session is returned")
            .register_message_handler(name, world)
    }

    /// Registers an isolated bridge with protected, redacted JSON message payloads.
    ///
    /// Messages arrive as [`PageEvent::SecretScriptMessage`]. They remain
    /// untrusted input from any frame in the isolated world. The page world is
    /// never registered, and a normal handler cannot share this registration.
    /// Returns `false` for invalid names, conflicting modes/worlds or exhausted slots.
    pub fn register_secret_message_handler(&mut self, name: &str, world: &str) -> bool {
        self.page
            .as_mut()
            .expect("page binding is connected before session return")
            .register_secret_message_handler(name, world)
    }

    /// Registers an isolated bridge like [`Self::register_secret_message_handler`]
    /// whose messages carry the frame, document and origins WebKit recorded.
    ///
    /// Messages arrive as [`PageEvent::FrameSecretMessage`], from any frame
    /// whose document runs a script in `world`; register a user script for all
    /// frames to reach embedded sign-in forms. Posts from documents without an
    /// HTTPS origin, or inside a top document without one, are dropped. Returns
    /// `false` as the secret handler does, and on a runtime without frame sources.
    pub fn register_frame_secret_message_handler(&mut self, name: &str, world: &str) -> bool {
        self.page
            .as_mut()
            .expect("page binding is connected before session return")
            .register_frame_secret_message_handler(name, world)
    }

    /// Removes a host message bridge and releases its registration slot.
    ///
    /// Returns `false` for malformed names or if this exact name and world were
    /// not registered. Already queued messages remain available to the host.
    pub fn unregister_message_handler(&mut self, name: &str, world: &ScriptWorld) -> bool {
        self.page
            .as_mut()
            .expect("the page binding is connected before a session is returned")
            .unregister_message_handler(name, world)
    }

    /// Highlights matches of `text` and selects the first; the count arrives
    /// as [`PageEvent::FindMatches`] or [`PageEvent::FindFailed`]. `max`
    /// bounds the count.
    pub fn find(&self, text: &str, case_sensitive: bool, max: u32) {
        self.page_binding().find(text, case_sensitive, false, max);
    }

    /// Moves to the next (or previous) match of the current search.
    pub fn find_next(&self, backwards: bool) {
        self.page_binding().find_step(backwards);
    }

    /// Ends the search and removes its highlight.
    pub fn find_finish(&self) {
        self.page_binding().find_finish();
    }

    /// Counts matches of `text` without highlighting them.
    pub fn count_matches(&self, text: &str, case_sensitive: bool, max: u32) {
        self.page_binding().count_matches(text, case_sensitive, max);
    }

    /// Clears this session's website data of the kinds in `data`, stored in
    /// the last `since` (or ever). It is the whole profile's data, shared by
    /// every view on the same profile. The result arrives as
    /// [`PageEvent::DataCleared`].
    /// `None` includes all ages; zero and sub-microsecond windows are no-ops.
    /// Positive time windows containing cookies fail before deleting anything:
    /// the native API cannot filter cookies by creation time. Use an all-age
    /// cookie clear or selective deletion instead of claiming a timed cookie clear.
    pub fn clear_website_data(&self, data: WebsiteData, since: Option<Duration>) -> PageRequestId {
        // SAFETY: borrowed from the live view.
        let network_session = unsafe { ffi::webkit_web_view_get_network_session(self.web_view) };
        self.page_binding()
            .clear_website_data(network_session, data, since)
    }

    /// Lets downloads the policy allows run, each into a fresh file in `dir`
    /// (which the host creates and owns, ideally private to the app). `None`
    /// declines them, which is the default. The host gets
    /// [`PageEvent::DownloadStarted`], progress, and
    /// [`PageEvent::DownloadFinished`] with the file to hand to the person
    /// through the save portal.
    ///
    /// # Errors
    ///
    /// `dir` is not an absolute path to an existing directory.
    pub fn set_download_directory(&self, dir: Option<PathBuf>) -> Result<(), std::io::Error> {
        // WebKit takes the destination as text; a directory whose name is
        // not UTF-8 would be written through a lossy, never-reserved path.
        if let Some(dir) = &dir
            && (!dir.is_absolute() || dir.to_str().is_none() || !std::fs::metadata(dir)?.is_dir())
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "the download directory must be an absolute, UTF-8 path to a directory",
            ));
        }
        self.page_hub.set_download_dir(dir);
        Ok(())
    }

    /// Start a native HTTP(S) download in this view's existing profile without navigating it.
    ///
    /// # Errors
    /// Refuses a non-network URL, unavailable renderer, denied policy, invalid URI or absent native download.
    pub fn start_download(&self, uri: &str) -> Result<(), String> {
        let parsed = crate::web::DestinationPolicy::trusted_local()
            .screen_request(uri)
            .map_err(|e| format!("{e:?}"))?;
        if !matches!(
            parsed.scheme(),
            enzui_security::url_policy::Scheme::Http | enzui_security::url_policy::Scheme::Https
        ) || uri.len() > crate::ffi::policy::MAX_POLICY_URI_BYTES
        {
            return Err("Only a bounded HTTP(S) download can be restarted".into());
        }
        self.require_navigable().map_err(|e| e.to_string())?;
        let encoded = std::ffi::CString::new(uri).map_err(|e| e.to_string())?;
        if !self
            .native_policy
            .as_ref()
            .is_some_and(|policy| policy.approve_host_download(uri))
        {
            return Err("Download refused by this profile's destination policy".into());
        }
        // SAFETY: the live view retains its native profile; encoded is borrowed only for synchronous dispatch.
        let download =
            unsafe { ffi::webkit_web_view_download_uri(self.web_view, encoded.as_ptr()) };
        if download.is_null() {
            return Err("The native download could not be created".into());
        }
        // SAFETY: download_uri transfers one reference; the native session/adoption owns any ongoing transfer.
        unsafe { ffi::g_object_unref(download.cast()) };
        Ok(())
    }

    /// Stop a range-capable native writer while retaining its prefix until the paused event is released.
    /// Returns false before cancellation if headers or a live partial file cannot support continuation.
    pub fn pause_download(&self, id: PageRequestId) -> bool {
        self.page_hub.pause_download(id)
    }

    /// Cancel an unadopted continuation without stopping an unrelated page navigation.
    /// Returns false once its response has become a download or its navigation was superseded.
    pub fn cancel_range_download(&self, uri: &str) -> bool {
        if self
            .native_policy
            .as_ref()
            .is_some_and(|p| p.retire_download_continuation(uri))
        {
            self.stop_loading();
            true
        } else {
            false
        }
    }

    /// Load a conditional byte range and route its response exclusively to a native download.
    /// The current document remains intact when its response becomes a download.
    ///
    /// # Errors
    /// Refuses invalid headers, concurrent requests, non-network destinations, denied policy or an unavailable renderer.
    pub fn start_range_download(
        &self,
        uri: &str,
        offset: u64,
        validator: &str,
    ) -> Result<(), String> {
        let parsed = crate::web::DestinationPolicy::trusted_local()
            .screen_request(uri)
            .map_err(|e| format!("{e:?}"))?;
        if !matches!(
            parsed.scheme(),
            enzui_security::url_policy::Scheme::Http | enzui_security::url_policy::Scheme::Https
        ) || uri.len() > crate::ffi::policy::MAX_POLICY_URI_BYTES
            || offset == 0
            || validator.is_empty()
            || validator.len() > 2048
            || validator.chars().any(char::is_control)
        {
            return Err("Invalid range continuation".into());
        }
        self.require_navigable().map_err(|e| e.to_string())?;
        let encoded = std::ffi::CString::new(uri).map_err(|e| e.to_string())?;
        let range =
            std::ffi::CString::new(format!("bytes={offset}-")).map_err(|e| e.to_string())?;
        let validator = std::ffi::CString::new(validator).map_err(|e| e.to_string())?;
        let policy = self
            .native_policy
            .as_ref()
            .ok_or("No native download policy")?;
        if !policy.approve_host_download(uri) {
            return Err("Download continuation refused".into());
        }
        // SAFETY: the bounded, validated URI initializes a new caller-owned native request.
        let request = unsafe { ffi::webkit_uri_request_new(encoded.as_ptr()) };
        if request.is_null() {
            return Err("No native URI request".into());
        }
        // SAFETY: request owns mutable headers until load_request synchronously copies its resource request.
        unsafe {
            let headers = ffi::webkit_uri_request_get_http_headers(request);
            if headers.is_null() || !policy.force_download_response(uri) {
                ffi::g_object_unref(request.cast());
                return Err("No HTTP headers or another continuation is pending".into());
            }
            ffi::soup_message_headers_replace(headers, c"Range".as_ptr(), range.as_ptr());
            ffi::soup_message_headers_replace(headers, c"If-Range".as_ptr(), validator.as_ptr());
            ffi::soup_message_headers_replace(
                headers,
                c"Accept-Encoding".as_ptr(),
                c"identity".as_ptr(),
            );
            ffi::webkit_web_view_load_request(self.web_view, request);
            ffi::g_object_unref(request.cast());
        }
        Ok(())
    }

    /// Cancels a running download; it ends as [`PageEvent::DownloadFailed`]
    /// with `cancelled` and its file removed. `false` when no such download
    /// runs.
    pub fn cancel_download(&self, id: PageRequestId) -> bool {
        self.page_hub.cancel_download(id)
    }

    /// Whether `window.open` and `target=_blank` links the policy allows
    /// open real views (`true`) or are only reported as
    /// [`PageEvent::PopupRequested`] (`false`, the default). A real popup
    /// shares this view's renderer, profile, destination rule and sandbox
    /// posture, and starts with this session's current policy; it arrives as
    /// [`PageEvent::PopupOpened`] for [`take_popup`](Self::take_popup). That
    /// is what a "Sign in with …" popup needs: `window.opener` works.
    pub fn set_popups(&self, open: bool) {
        let template = if open {
            self.network_session
                .as_ref()
                .map(|network_session| crate::ffi::page::PopupTemplate {
                    profile: self.profile.clone(),
                    network_session: Rc::clone(network_session),
                    outer: self.sandbox_policy,
                    destination_policy: self.destination_policy,
                    sandbox_baseline: self.sandbox_baseline.clone(),
                    policy: self.page_hub.popup_policy().unwrap_or_else(|| {
                        crate::web::WebPolicy::strict().with_destination(self.destination_policy)
                    }),
                })
        } else {
            None
        };
        self.page_hub.set_popup_template(template);
    }

    /// Whether a popup this view opens waits for its host before it loads
    /// (`false`, the default, lets WebKit load it at once). A waiting popup's
    /// navigations are judged by the opener's policy as they arrive, and
    /// those it allows are kept undecided until
    /// [`resume_popup`](Self::resume_popup) on the popup: the host can take
    /// it, install its scripts, content filters and policy, and only then
    /// let the first request out. Popups of that popup wait the same way.
    pub fn hold_popup_navigations(&self, hold: bool) {
        self.page_hub.set_hold_popups(hold);
    }

    /// For a popup taken with [`take_popup`](Self::take_popup) from an
    /// opener that holds popup navigations: lets what it held go ahead and
    /// holds nothing from now on. Returns how many navigations waited; a
    /// popup opened on `about:blank` has none.
    pub fn resume_popup(&self) -> usize {
        self.page_hub.resume_navigations(|url| {
            if let Some(policy) = &self.native_policy {
                policy.note_allowed_navigation(url);
            }
        })
    }

    /// Takes a popup reported as [`PageEvent::PopupOpened`]. Before it is
    /// returned, the page's credential hook must have answered and the
    /// renderer must attest as isolated, as for any session; a failure
    /// closes it. Bind a view and install its policy as for a new session.
    /// `None` when no such popup waits.
    pub fn take_popup(&self, id: PageRequestId) -> Option<Result<WebSession, SessionError>> {
        let popup = self.page_hub.take_popup(id)?;
        Some(popup.finish_popup())
    }

    /// The raw view, for the popup handshake with WebKit.
    pub(crate) fn raw_web_view(&self) -> *mut ffi::WebKitWebView {
        self.web_view
    }

    /// Sets which cookies this session's profile accepts, and whether
    /// WebKit's tracking prevention (ITP) runs. Shared by every view on the
    /// same profile.
    pub fn set_cookie_policy(&self, policy: CookiePolicy, tracking_prevention: bool) {
        // SAFETY: borrowed from the live view.
        unsafe {
            let network_session = ffi::webkit_web_view_get_network_session(self.web_view);
            crate::ffi::page::apply_cookie_policy(network_session, policy, tracking_prevention);
        }
    }
}

impl WebSession {
    /// Native TLS certificate details for the current main-resource connection.
    ///
    /// Returns `None` when WebKit exposes no TLS information, including inert
    /// and cleartext pages. Host-installed certificate exceptions may suppress
    /// validation errors; a zero error mask does not establish public trust.
    pub fn connection_tls_info(&self) -> Option<ConnectionTlsInfo> {
        let mut certificate = std::ptr::null_mut();
        let mut errors = 0;
        // SAFETY: this session owns the live view; both outputs remain valid for this call.
        if unsafe {
            ffi::webkit_web_view_get_tls_info(self.web_view, &mut certificate, &mut errors)
        } == 0
            || certificate.is_null()
        {
            return None;
        }
        // SAFETY: the certificate is borrowed from the live view; both getters return owned GLib strings.
        let (subject, issuer) = unsafe {
            let subject = ffi::g_tls_certificate_get_subject_name(certificate);
            let issuer = ffi::g_tls_certificate_get_issuer_name(certificate);
            let subject_name = if subject.is_null() {
                None
            } else {
                Some(
                    std::ffi::CStr::from_ptr(subject)
                        .to_string_lossy()
                        .into_owned(),
                )
            };
            let issuer_name = if issuer.is_null() {
                None
            } else {
                Some(
                    std::ffi::CStr::from_ptr(issuer)
                        .to_string_lossy()
                        .into_owned(),
                )
            };
            ffi::g_free(subject.cast());
            ffi::g_free(issuer.cast());
            (subject_name, issuer_name)
        };
        Some(ConnectionTlsInfo {
            errors,
            subject,
            issuer,
        })
    }

    /// Human-readable certificate details, or `None` without native TLS information.
    /// Host-installed exceptions may suppress validation errors.
    pub fn connection_tls_details(&self) -> Option<String> {
        self.connection_tls_info().map(|info| {
            format!(
                "WebKit TLS error flags: {}\nSubject: {}\nIssuer: {}",
                info.errors,
                info.subject.as_deref().unwrap_or("unavailable"),
                info.issuer.as_deref().unwrap_or("unavailable")
            )
        })
    }

    /// Routes selected main-document MIME types through existing download policy.
    ///
    /// Use for host-provided viewers. Downloads still require policy approval and
    /// a validated destination directory. The default list is empty. Up to 32
    /// ASCII MIME types of at most 128 bytes are accepted, ignoring parameters
    /// and case. Invalid types are omitted. Reapply after replacing native policy.
    pub fn set_download_mime_types(&self, types: &[&str]) {
        if let Some(policy) = &self.native_policy {
            policy.set_download_mime_types(types);
        }
    }
}

/// Owned certificate identity and native verification flags for a main-resource connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionTlsInfo {
    /// WebKit's `GTlsCertificateFlags` mask; host exceptions may suppress errors.
    pub errors: u32,
    /// The certificate's subject distinguished name, when exposed by GIO.
    pub subject: Option<String>,
    /// The certificate's issuer distinguished name, when exposed by GIO.
    pub issuer: Option<String>,
}

impl WebSession {
    /// Enables camera, microphone and location permissions keyed by requesting and top-document origins.
    ///
    /// Requests without trustworthy native origin metadata are denied. These
    /// capabilities use origin choices instead of legacy global grants. Disabling
    /// this mode explicitly restores the legacy global permission policy. Pending
    /// prompts expire after 30 seconds or navigation and are capped at four.
    /// Changing this mode denies pending prompts, clears both Rust and native
    /// camera/microphone/location history, stops media capture and revokes location watches.
    /// Geolocation completion arrives as `PageEvent::GeolocationPermissionChanged`. Popups and renderer recovery inherit this
    /// mode and its origin-scoped grants, without pending requests.
    ///
    /// # Errors
    /// Returns `OriginPermissionsUnsupported` before changing policy on an older runtime.
    pub fn set_origin_permission_mode(&self, enabled: bool) -> Result<(), SessionError> {
        if self.page_hub.site_permissions_enabled() == enabled {
            return Ok(());
        }
        self.reconfigure_origin_permissions(enabled)
    }

    /// Enable origin mode with an empty choice table, retiring prompts and native approvals.
    /// Geolocation completion arrives as `PageEvent::GeolocationPermissionChanged`.
    ///
    /// # Errors
    /// Returns `OriginPermissionsUnsupported` without changing an older runtime's policy.
    pub fn reset_origin_permissions(&self) -> Result<(), SessionError> {
        self.reconfigure_origin_permissions(true)
    }

    fn reconfigure_origin_permissions(&self, enabled: bool) -> Result<(), SessionError> {
        if !self.supports_origin_permissions() {
            return Err(SessionError::OriginPermissionsUnsupported);
        }
        self.page_hub.enable_site_permissions(enabled);
        // SAFETY: the live view accepts explicit NONE to stop capture and clear native permission history.
        unsafe {
            ffi::webkit_web_view_set_camera_capture_state(self.web_view, 0);
            ffi::webkit_web_view_set_microphone_capture_state(self.web_view, 0);
        }
        self.revoke_geolocation()?;
        Ok(())
    }

    /// Answers one current-document permission request. A notifications
    /// answer is also stored as this view's choice for that origin, because
    /// WebKit delivers only to an origin the host table allows.
    /// Returns [`AnswerError::Unknown`] for expired, answered or invalidated requests.
    pub fn answer_permission(&self, id: PageRequestId, allowed: bool) -> Result<(), AnswerError> {
        self.page_hub.answer_site_permission(id, allowed)
    }

    /// Stores a session-only permission for one exact requester/top-origin pair.
    ///
    /// Camera, microphone, location, and notifications for a top-level origin
    /// (requesting and top origin the same) are supported; a notifications
    /// denial closes and refuses that origin's notifications. Returns `false` for
    /// other kinds or a full 128-entry table. Combined
    /// camera/microphone requests require both primitive grants. Media grants clear
    /// stale native denials without stopping active capture. A media denial stops
    /// that capability throughout this view and clears native history; denying location
    /// revokes active watches and reports `PageEvent::GeolocationPermissionChanged`. Profile-wide persistent choices are
    /// the host's responsibility. Enable origin prompts before using this table.
    pub fn set_site_permission(
        &self,
        permission: crate::site_permissions::SitePermission,
        allowed: bool,
    ) -> Result<bool, SessionError> {
        if !self.page_hub.site_permissions_enabled() {
            return Ok(false);
        }
        let kind = permission.kind;
        let supported = match kind {
            crate::web::policy::PermissionKind::Camera
            | crate::web::policy::PermissionKind::Microphone
            | crate::web::policy::PermissionKind::Geolocation => true,
            crate::web::policy::PermissionKind::Notifications => {
                permission.requesting_origin == permission.top_origin
            }
            _ => false,
        };
        if !supported {
            return Ok(false);
        }
        let previous = self.page_hub.site_permission_grant(&permission);
        if previous == Some(allowed) {
            return Ok(true);
        }
        if allowed
            && matches!(
                kind,
                crate::web::policy::PermissionKind::Camera
                    | crate::web::policy::PermissionKind::Microphone
            )
            && !crate::ffi::page::permissions::clear_media_permission_history(
                self.web_view,
                kind == crate::web::policy::PermissionKind::Camera,
            )
        {
            return Ok(false);
        }

        let notification_origin = permission.requesting_origin.clone();
        let inserted = self.page_hub.set_site_permission(permission, allowed);
        if inserted && !allowed && kind == crate::web::policy::PermissionKind::Notifications {
            self.page_hub
                .close_notifications_for_origin(&notification_origin);
        }
        if inserted && allowed && kind == crate::web::policy::PermissionKind::Geolocation {
            self.change_geolocation_permission(false)?;
        }
        if inserted && previous != Some(allowed) && !allowed {
            if kind == crate::web::policy::PermissionKind::Notifications {
                self.page_hub.cancel_notification_permissions();
            } else {
                self.page_hub.cancel_site_permissions();
            }
            // SAFETY: this owner retains a live view; state zero is WebKitMediaCaptureState::NONE.
            unsafe {
                if kind == crate::web::policy::PermissionKind::Camera {
                    ffi::webkit_web_view_set_camera_capture_state(self.web_view, 0);
                }
                if kind == crate::web::policy::PermissionKind::Microphone {
                    ffi::webkit_web_view_set_microphone_capture_state(self.web_view, 0);
                }
            }
            if !allowed && kind == crate::web::policy::PermissionKind::Geolocation {
                self.revoke_geolocation()?;
            }
        }
        Ok(inserted)
    }
}

impl WebSession {
    /// Shared exact-origin LAN destination capabilities for this session's profile.
    ///
    /// The table starts empty. Grant only an explicitly authorized HTTP(S) origin.
    /// Unrelated local origins remain denied; clones and profile-sharing views
    /// share grants. The proxy cannot identify a CONNECT tunnel's initiating
    /// document. Isolate unrelated content in separate profiles when needed.
    /// Revocation applies to future setup, not existing connections or cache.
    pub fn local_origins(&self) -> Option<crate::local_origins::LocalOriginAllowlist> {
        self.network_session
            .as_ref()
            .and_then(|network| network.local_origins())
    }
}

impl WebSession {
    /// Selects WebKit's synthetic capture devices for automation on this view.
    ///
    /// Returns the effective mock-device setting. This does not grant camera or
    /// microphone permission. Enable it before media requests in tests to avoid
    /// using real hardware; it defaults off and is not inherited by popups.
    pub fn set_mock_capture_devices(&self, enabled: bool) -> bool {
        // SAFETY: the live view owns its settings; these getters/setters use the stable WebKitSettings ABI.
        unsafe {
            let settings = crate::ffi::page::sys::webkit_web_view_get_settings(self.web_view);
            crate::ffi::page::sys::webkit_settings_set_enable_mock_capture_devices(
                settings,
                i32::from(enabled),
            );
            crate::ffi::page::sys::webkit_settings_get_enable_mock_capture_devices(settings) != 0
        }
    }
}
