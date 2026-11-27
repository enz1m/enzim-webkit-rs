//! Private WebSession input-method plumbing: installing the context, the
//! page's composition requests, and the host's edits applied back.
//!
//! The public methods remain inherent methods on `runtime::WebSession`; this
//! module is private so the split does not create a second API surface.

use super::*;

impl WebSession {
    /// Install the real `WebKitInputMethodContext` seam on this view.
    ///
    /// Installation deliberately does not focus the native view. Toolkit
    /// focus is the sole authority: only a generation-checked
    /// [`InputEvent::FocusGained`](crate::input::InputEvent::FocusGained)
    /// forwarded by the owning widget may call `wpe_view_focus_in`. Eager focus
    /// here let a newly opened or hidden page own keyboard and IME before iced
    /// had focused its web area.
    ///
    /// Idempotent: a second call on an already-enabled session is a no-op.
    ///
    /// # Errors
    ///
    /// [`SessionError::ImeInstall`] when the context cannot be registered,
    /// constructed, or installed. There is deliberately no degraded mode: a
    /// silently IME-less view is indistinguishable from a page that never
    /// focused an input, which is precisely the failure this seam exists to
    /// make observable.
    pub fn enable_input_method(&mut self) -> Result<(), SessionError> {
        if self.ime.is_some() {
            return Ok(());
        }
        // SAFETY: `web_view` is live and outlives the context (Drop order in
        // `Drop for WebSession` releases the context first).
        let ctx = unsafe { crate::ffi::ime::ImeContext::install(self.web_view) }
            .map_err(SessionError::ImeInstall)?;
        self.ime = Some(ctx);
        Ok(())
    }

    /// Whether the input-method seam is installed on this view.
    #[must_use]
    pub fn has_input_method(&self) -> bool {
        self.ime.is_some()
    }

    /// Whether the WPE view holds keyboard focus. Read back from WPE rather
    /// than remembered, so "this code called focus_in" cannot pass for "the view is
    /// focused".
    #[must_use]
    pub fn view_has_focus(&self) -> bool {
        // SAFETY: live WPEView*.
        unsafe { ffi::wpe_view_get_has_focus(self.wpe_view) != ffi::G_FALSE }
    }

    /// Drop the view's keyboard focus, which is what a toolkit does when the
    /// widget loses focus or the window deactivates. WebKit responds by calling
    /// `notify_focus_out` on the context, so the recorded caret is cleared by
    /// the engine, not by this code hoping to remember.
    pub fn blur_view(&self) {
        // SAFETY: live WPEView*.
        unsafe { ffi::wpe_view_focus_out(self.wpe_view) };
    }

    /// Give the view keyboard focus again (widget refocused).
    pub fn focus_view(&self) {
        // SAFETY: live WPEView*.
        unsafe { ffi::wpe_view_focus_in(self.wpe_view) };
    }

    /// The view's output/device scale factor, read from WPE.
    ///
    /// WPEPlatform has no `wpe_view_set_scale`; the value follows the view's
    /// toplevel/screen scale. The headless platform exposes no screen so this
    /// defaults to 1 until the embedding window supplies its scale.
    #[must_use]
    pub fn view_scale(&self) -> f64 {
        // SAFETY: live WPEView*.
        unsafe { ffi::wpe_view_get_scale(self.wpe_view) }
    }

    /// Set the headless view's density in device pixels per logical pixel.
    ///
    /// Returns the effective scale, or `None` for an invalid scale or a missing toplevel.
    pub fn set_device_scale(&self, scale: f64) -> Option<f64> {
        if !scale.is_finite() || scale < f64::from(f32::EPSILON) || scale > f64::from(f32::MAX) {
            return None;
        }
        // SAFETY: live WPEView*; `wpe_view_get_toplevel` returns a borrowed
        // pointer (owned by the view) or NULL.
        let toplevel = unsafe { ffi::wpe_view_get_toplevel(self.wpe_view) };
        if toplevel.is_null() {
            return None;
        }
        if let Some(presentation) = &self.gpu_presentation {
            presentation.record_viewport(self.viewport_at_scale(self.view_scale() as f32));
            presentation.record_viewport(self.viewport_at_scale(scale as f32));
        }
        // SAFETY: the headless toplevel is live and its output is managed by the host.
        unsafe { ffi::wpe_toplevel_scale_changed(toplevel, scale) };
        Some(self.view_scale())
    }

    /// Set the headless scale for native input contract tests.
    #[doc(hidden)]
    pub fn force_output_scale(&self, scale: f64) -> Option<f64> {
        self.set_device_scale(scale)
    }

    pub(in crate::ffi) fn viewport_at_scale(&self, scale: f32) -> Option<crate::ViewportSize> {
        // SAFETY: the live view retains the borrowed toplevel.
        let toplevel = unsafe { ffi::wpe_view_get_toplevel(self.wpe_view) };
        if toplevel.is_null() {
            return None;
        }
        let (mut width, mut height) = (0, 0);
        // SAFETY: the toplevel and both out-parameters are live for the read.
        unsafe { ffi::wpe_toplevel_get_size(toplevel, &mut width, &mut height) };
        crate::ViewportSize::from_logical(width as f32, height as f32)
            .ok()
            .map(|size| size.with_device_scale(scale))
    }

    /// Set the page's zoom level (logical view pixels per CSS pixel).
    ///
    /// This is the lever that makes the caret rectangle's coordinate space
    /// *measurable*: zoom changes where a field lands in the view without
    /// changing the view's size, so a caret reported in view pixels moves with
    /// it while a caret reported in CSS pixels would not.
    pub fn set_page_zoom(&self, zoom: f64) {
        // SAFETY: live WebKitWebView*.
        unsafe { ffi::webkit_web_view_set_zoom_level(self.web_view, zoom) };
    }

    /// The page's current zoom level, read back from WebKit.
    #[must_use]
    pub fn page_zoom(&self) -> f64 {
        // SAFETY: live WebKitWebView*.
        unsafe { ffi::webkit_web_view_get_zoom_level(self.web_view) }
    }

    /// What the real page has reported through the input-method seam: whether
    /// an editable element is focused, its caret rectangle in logical view
    /// pixels (the measured space - see
    /// [`crate::web::CaretRect`]; page zoom is applied but the view's
    /// output/device scale is not, so a consumer maps by the view's
    /// translation only and does not divide by the output scale), its input
    /// purpose/hints, and the surrounding text.
    ///
    /// `None` when the seam is not installed - distinguishable from "installed
    /// but the page has focused nothing", which reports a default
    /// [`PageImeReport`](crate::ffi::ime::PageImeReport).
    #[must_use]
    pub fn page_ime_report(&self) -> Option<crate::ffi::ime::PageImeReport> {
        self.ime.as_ref().map(crate::ffi::ime::ImeContext::report)
    }

    /// The generation gate every host→page IME command passes.
    ///
    /// Identical in shape to [`deliver_page_accessibility`](Self::deliver_page_accessibility)'s
    /// guard, and for the same reason: a command is refused before it
    /// reaches WebKit if this session is unbound, is bound to a different id, or
    /// is bound to a generation the router has superseded. The last case is the
    /// one that matters here - a toolkit commit that raced a WebProcess crash
    /// would otherwise type the user's characters into the page that replaced
    /// the one they were typing into.
    fn authorize_ime(
        &self,
        router: &crate::web::ViewRouter,
        view: crate::web::ViewId,
    ) -> Result<&crate::ffi::ime::ImeContext, ImeCommandError> {
        match self.bound_view {
            None => return Err(ImeCommandError::ViewNotBound),
            Some(bound) if bound != view => {
                return Err(ImeCommandError::ForeignSession { bound, asked: view });
            }
            Some(_) => {}
        }
        if !router.accepts(view) {
            return Err(ImeCommandError::ViewNotLive { view });
        }
        let ctx = self.ime.as_ref().ok_or(ImeCommandError::NotEnabled)?;
        if !ctx.report().focused {
            return Err(ImeCommandError::NoFocusedField);
        }
        Ok(ctx)
    }

    /// Show a composition in the focused page field (the toolkit's IME is
    /// preediting).
    ///
    /// `caret` is iced's own vocabulary: a byte offset into `text`, taken
    /// from `iced_core::input_method::Preedit::selection`'s endpoint (`None`
    /// means "caret at the end", which is what winit reports when the IME does
    /// not place one). This is the single routing boundary where that offset is
    /// converted to the UTF-16 code-unit offset WebKit indexes with - see
    /// [`crate::input::utf16_caret`].
    ///
    /// # Errors
    ///
    /// [`ImeCommandError`] when the command is not authorised for `view`.
    pub fn ime_set_preedit(
        &self,
        router: &crate::web::ViewRouter,
        view: crate::web::ViewId,
        text: &str,
        caret: Option<usize>,
    ) -> Result<(), ImeCommandError> {
        let ctx = self.authorize_ime(router, view)?;
        ctx.set_preedit(text, crate::input::utf16_caret(text, caret));
        Ok(())
    }

    /// End a composition without inserting it (the IME cancelled).
    ///
    /// # Errors
    ///
    /// [`ImeCommandError`] when the command is not authorised for `view`.
    pub fn ime_cancel_preedit(
        &self,
        router: &crate::web::ViewRouter,
        view: crate::web::ViewId,
    ) -> Result<(), ImeCommandError> {
        self.authorize_ime(router, view)?.finish_preedit();
        Ok(())
    }

    /// Commit `text` into the focused page field.
    ///
    /// # Errors
    ///
    /// [`ImeCommandError`] when the command is not authorised for `view`. A
    /// refusal means nothing was typed, which is the whole point.
    pub fn ime_commit(
        &self,
        router: &crate::web::ViewRouter,
        view: crate::web::ViewId,
        text: &str,
    ) -> Result<(), ImeCommandError> {
        self.authorize_ime(router, view)?.commit(text);
        Ok(())
    }

    /// Ask the page to delete `n_chars` characters starting `offset`
    /// characters from the caret (negative is before it).
    ///
    /// # No iced/winit event source exists today - verified, not assumed
    ///
    /// Unlike preedit/commit/cancel, this command has no toolkit event that
    /// can trigger it, so it is deliberately not claimed as "routed". The
    /// chain was traced end to end in the pinned dependencies:
    ///
    /// * Wayland's `zwp_text_input_v3` *does* carry `delete_surrounding_text`.
    /// * The pinned winit (`iced-rs/winit` rev `05b8ff17`) receives it and
    ///   drops it on the floor:
    ///   `src/platform_impl/linux/wayland/seat/text_input/mod.rs` matches
    ///   `TextInputEvent::DeleteSurroundingText { .. } => { // Not handled. }`.
    /// * `iced_core::input_method::Event` therefore has only `Opened`,
    ///   `Preedit`, `Commit` and `Closed` - there is no variant to convert it
    ///   into (`vendor/iced/core/src/input_method.rs`).
    ///
    /// Closing that gap needs a change in winit, which is an upstream
    /// `iced-rs/winit` git dependency and not one of this repo's forks
    /// (`vendor/iced` is), plus a new `iced_core` event variant and a
    /// conversion. That is a cross-repo protocol change outside this crate; it
    /// is reported as a platform limitation instead of being simulated.
    ///
    /// What this method *is*: the page-side half, exercised end to end against
    /// a real page by the native gate (composition `にほんご` → delete 1
    /// character before the caret → the DOM value becomes `にほん`). When the
    /// toolkit event appears, this is what it will call.
    ///
    /// # Errors
    ///
    /// [`ImeCommandError`] when the command is not authorised for `view`.
    pub fn ime_delete_surrounding(
        &self,
        router: &crate::web::ViewRouter,
        view: crate::web::ViewId,
        offset: i32,
        n_chars: u32,
    ) -> Result<(), ImeCommandError> {
        self.authorize_ime(router, view)?
            .delete_surrounding(offset, n_chars);
        Ok(())
    }

    /// The page's input-method state in the app-facing vocabulary.
    ///
    /// The bridge type ([`crate::ime_bridge::NativeImeReport`]) exists
    /// feature-off, so an application's IME code compiles and is exercised in
    /// both modes; this is the one place the FFI report is read.
    #[must_use]
    pub fn native_ime_report(&self) -> Option<crate::ime_bridge::NativeImeReport> {
        self.ime
            .as_ref()
            .map(crate::ffi::ime::ImeContext::native_report)
    }

    /// Perform an [`crate::ime_bridge::ImeEffect`] the widget's routed iced
    /// event produced.
    ///
    /// This is the far end of the app-facing route: a real
    /// `iced::Event::InputMethod` reaches `EnzWebView`, the widget publishes it
    /// as a message, the application asks
    /// [`crate::ime_bridge::WebViewIme::route_event`] what it means, and this
    /// executes it against the real page - through the same generation check
    /// every other host→page command passes, so a late event cannot type into a
    /// recreated page.
    ///
    /// # Errors
    ///
    /// [`ImeCommandError`] when the effect is not authorised for `view`.
    /// [`crate::ime_bridge::ImeEffect::Ignored`] is `Ok(())` and does nothing.
    pub fn apply_ime_effect(
        &self,
        router: &crate::web::ViewRouter,
        view: crate::web::ViewId,
        effect: &crate::ime_bridge::ImeEffect,
    ) -> Result<(), ImeCommandError> {
        use crate::ime_bridge::ImeEffect;
        match effect {
            ImeEffect::Ignored => Ok(()),
            ImeEffect::SetPreedit { text, caret } => {
                self.ime_set_preedit(router, view, text, *caret)
            }
            ImeEffect::Commit(text) => self.ime_commit(router, view, text),
            // A cancel and a window-close both end the composition in the page;
            // the ownership half of `Close` is the bridge's
            // (`WebViewIme::settle`), not WebKit's.
            ImeEffect::Cancel | ImeEffect::Close => self.ime_cancel_preedit(router, view),
        }
    }
}
