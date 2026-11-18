//! A generation-checked web surface with translated, clipped input.
//!

pub mod convert;
pub mod gpu;
pub mod seam;
mod viewport_frame;

use enzui_core::live_region::Announcement;
use enzui_core::media::Rgba8Frame;
use enzui_core::semantics::{Role, Semantics};
use enzui_webkit::input::{
    InputEvent, KeyCode, Modifiers, PointerButton, ViewportMapping, pointer_moved_with_modifiers,
    pointer_pressed_with_modifiers, pointer_released_with_modifiers, wheel_scrolled_with_modifiers,
};
use enzui_webkit::page_a11y::{PageA11y, PageNodeKey};
use enzui_webkit::page_delivery::PublishedPage;
use enzui_webkit::web::ViewId;
use iced::widget::{container, image as iced_image};
use iced::{Element, Length, Padding, Theme};

/// The default 4:3-ish web content shape used before a frame reports its own.
pub const DEFAULT_ASPECT_RATIO: f32 = 4.0 / 3.0;

/// The default cap on the web surface's width, in logical pixels.
///
/// # Why a cap is required, not merely nice
///
/// The surface is aspect-ratio-shaped, so its height is derived from its
/// width. Under an uncapped `Length::Fill`, a wide column produces a very
/// tall surface that pushes sibling chrome (and any surrounding page
/// controls) out of the viewport; an uncapped surface was measured at
/// 77.2% of a 1400x900 window. Capping the width caps the derived height.
/// `Fill` is honoured up to the cap, so the surface stays responsive on
/// narrow layouts.
pub const DEFAULT_MAX_SURFACE_WIDTH: f32 = 800.0;

/// What the web area should show for a given state.
///
/// A named enum rather than branches inside the view, so the presentation policy
/// is a pure, inspectable function ([`WebSurface::for_state`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebSurface {
    /// A decoded frame is displayed: present it.
    Frame,
    /// No frame has arrived yet: show a placeholder that does not claim to be
    /// page content.
    AwaitingFirstFrame,
    /// The view is hidden/quiescent: present nothing (a hidden tab shows no
    /// live surface and requests no frames).
    Hidden,
}

impl WebSurface {
    /// The presentation policy, as a pure function.
    ///
    /// `visible` is whether the view is currently on screen; `has_frame` is
    /// whether a decoded frame is displayed. Visibility is checked first: a
    /// hidden view shows nothing even if a stale frame is still in the sink,
    /// because a hidden tab must be quiescent.
    #[must_use]
    pub fn for_state(visible: bool, has_frame: bool) -> WebSurface {
        if !visible {
            WebSurface::Hidden
        } else if has_frame {
            WebSurface::Frame
        } else {
            WebSurface::AwaitingFirstFrame
        }
    }

    /// Whether this surface presents actual page pixels.
    #[must_use]
    pub fn shows_content(self) -> bool {
        matches!(self, WebSurface::Frame)
    }
}

/// Build the single renderer handle for one decoded web frame.
///
/// One call site on purpose (the same discipline as the video widget): every
/// `Handle::from_rgba` mints a fresh renderer identity, so the number of handles
/// minted per rendered frame is one, here, from the buffer the
/// [`BoundedFrameSink`](enzui_core::media::BoundedFrameSink) owns.
#[must_use]
pub fn web_frame_handle(frame: &Rgba8Frame) -> iced_image::Handle {
    iced_image::Handle::from_rgba(frame.width(), frame.height(), frame.pixels().to_vec())
}

/// One renderer handle per engine frame, kept across view rebuilds.
///
/// Hold one per web view beside its frame sink and pass
/// [`handle_for`](Self::handle_for)'s result to [`EnzWebView::presented`].
/// The handle is reused while the frame keeps its generation and sequence,
/// and also when a re-snapshot arrives with identical pixels, so redraws and
/// unchanged snapshots upload nothing. A new generation or new pixels mint a
/// fresh handle; it never outlives the holder.
#[derive(Debug, Default)]
pub struct RetainedFrameHandle {
    retained: std::cell::RefCell<Option<Retained>>,
}

#[derive(Debug)]
struct Retained {
    generation: enzui_core::media::Generation,
    seq: enzui_core::media::FrameSeq,
    size: (u32, u32),
    digest: u64,
    handle: iced_image::Handle,
}

impl RetainedFrameHandle {
    /// The handle showing `frame`: the retained one when `frame` is the same
    /// engine frame or the same pixels in the same generation, else a new one.
    pub fn handle_for(&self, frame: &Rgba8Frame) -> iced_image::Handle {
        let mut retained = self.retained.borrow_mut();
        let size = (frame.width(), frame.height());
        let mut candidate_digest = None;
        if let Some(kept) = retained.as_mut()
            && kept.generation == frame.generation()
            && kept.size == size
        {
            if kept.seq == frame.seq() {
                return kept.handle.clone();
            }
            let digest = pixel_digest(frame.pixels());
            candidate_digest = Some(digest);
            if kept.digest == digest {
                kept.seq = frame.seq();
                return kept.handle.clone();
            }
        }
        let handle = web_frame_handle(frame);
        *retained = Some(Retained {
            generation: frame.generation(),
            seq: frame.seq(),
            size,
            digest: candidate_digest.unwrap_or_else(|| pixel_digest(frame.pixels())),
            handle: handle.clone(),
        });
        handle
    }

    /// Drops the retained handle, for a view that closed or was recreated.
    pub fn clear(&self) {
        *self.retained.borrow_mut() = None;
    }
}

fn pixel_digest(pixels: &[u8]) -> u64 {
    #[cfg(test)]
    PIXEL_DIGEST_CALLS.with(|count| count.set(count.get() + 1));
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    pixels.hash(&mut hasher);
    hasher.finish()
}

#[cfg(test)]
std::thread_local! {
    static PIXEL_DIGEST_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// The aspect ratio to render at: the frame's own if present, else the default.
#[must_use]
pub fn aspect_ratio_for(frame: Option<&Rgba8Frame>) -> f32 {
    match frame {
        Some(f) => f.width() as f32 / f.height() as f32,
        None => DEFAULT_ASPECT_RATIO,
    }
}

/// The accessible name for the web surface.
///
/// The name-from-content rule forbids inventing a description of content the
/// framework cannot see. This code cannot read the page's DOM in this slice, so the
/// name states role and state only; a host that knows the page title
/// supplies it via [`EnzWebView::title`].
#[must_use]
pub fn surface_name(surface: WebSurface, title: Option<&str>) -> String {
    match (surface, title) {
        (WebSurface::Frame, Some(t)) => format!("Web view: {t}"),
        (WebSurface::Frame, None) => "Web view".to_string(),
        (WebSurface::AwaitingFirstFrame, Some(t)) => format!("Loading web view: {t}"),
        (WebSurface::AwaitingFirstFrame, None) => "Loading web view".to_string(),
        (WebSurface::Hidden, Some(t)) => format!("Hidden web view: {t}"),
        (WebSurface::Hidden, None) => "Hidden web view".to_string(),
    }
}

/// A web content surface with leased GPU or CPU frames and translated input.
///
/// Construct with [`enz_web_view`]. Holds no state of its own - the frame is
/// borrowed from the host's sink, and visibility is passed in - so a stale
/// engine event the host discards cannot leave a widget-local copy on screen.
pub struct EnzWebView<'a, Message = ()> {
    view: ViewId,
    frame: Option<WebFrameRef<'a>>,
    visible: bool,
    title: Option<String>,
    max_surface_width: f32,
    fill_viewport: bool,
    scale_factor: f32,
    page_a11y: Option<PageA11y>,
    ime: Option<seam::PageInputState>,
    page_cursor: Option<iced::mouse::Interaction>,
    /// Maps a window IME event into the host's message. Boxed rather than a
    /// generic parameter on every method so the builder stays one type; the
    /// `Message` parameter defaults to `()` for the many call sites that do not
    /// route IME events at all.
    on_input_method: Option<Box<dyn Fn(enzui_webkit::web::ToolkitImeEvent) -> Message + 'a>>,
    /// Maps real iced pointer/touch/wheel/keyboard events into the host's
    /// message. Geometry translation and focus gating happen in `WebViewSeam`.
    on_input: Option<Box<dyn Fn(InputEvent) -> Message + 'a>>,
    /// Publishes the widget's checked integer logical size when it changes.
    /// The host forwards this generation-keyed request to its web session.
    on_viewport_resize: Option<Box<dyn Fn(ViewId, enzui_webkit::ViewportSize) -> Message + 'a>>,
    /// A host-retained handle showing `frame`, drawn instead of a fresh one.
    presented: Option<iced_image::Handle>,
    gpu: Option<gpu::GpuFrame>,
    gpu_source: Option<gpu::GpuFrameSource>,
}

/// How the widget holds the frame it presents.
///
/// Mirrors `EnzVideo`'s `FrameRef`: the borrowed case is preferred (the
/// sink owns the buffer, the widget borrows it for the view call), but an
/// [`Element<'a>`] cannot borrow a local that a `view` fn drops on return - so a
/// caller that reads a frame out of a `RefCell` borrow inside its own `view`
/// needs an owned value. Both render identically ([`web_frame_handle`] is
/// called exactly once either way).
pub enum WebFrameRef<'a> {
    /// A borrow of a frame the sink owns.
    Borrowed(&'a Rgba8Frame),
    /// A frame owned for the duration of the view call.
    Owned(Rgba8Frame),
}

impl<'a> WebFrameRef<'a> {
    /// The frame, however held.
    #[must_use]
    pub fn get(&self) -> &Rgba8Frame {
        match self {
            WebFrameRef::Borrowed(f) => f,
            WebFrameRef::Owned(f) => f,
        }
    }
}

impl<'a> From<&'a Rgba8Frame> for WebFrameRef<'a> {
    fn from(f: &'a Rgba8Frame) -> Self {
        WebFrameRef::Borrowed(f)
    }
}

impl From<Rgba8Frame> for WebFrameRef<'_> {
    fn from(f: Rgba8Frame) -> Self {
        WebFrameRef::Owned(f)
    }
}

/// Construct a web view for `view`, presenting `frame` (the sink's displayed
/// frame, or `None` if none yet).
///
/// `visible` is whether the view is currently on screen; a hidden view presents
/// nothing. `frame` is a borrow of the frame the
/// [`BoundedFrameSink`](enzui_core::media::BoundedFrameSink) owns - the
/// widget copies nothing extra and holds it only for this view call.
#[must_use]
pub fn enz_web_view<Message>(
    view: ViewId,
    frame: Option<&Rgba8Frame>,
    visible: bool,
) -> EnzWebView<'_, Message> {
    EnzWebView {
        view,
        frame: frame.map(WebFrameRef::Borrowed),
        visible,
        title: None,
        max_surface_width: DEFAULT_MAX_SURFACE_WIDTH,
        fill_viewport: false,
        scale_factor: 1.0,
        page_a11y: None,
        ime: None,
        page_cursor: None,
        on_input_method: None,
        on_input: None,
        on_viewport_resize: None,
        presented: None,
        gpu: None,
        gpu_source: None,
    }
}

/// Construct a web view presenting an owned frame.
///
/// For a caller that reads the frame out of a `RefCell`/`Ref` inside its own
/// `view` function, where a borrow cannot outlive the returned element. The
/// frame is cloned by the caller; the widget still mints exactly one handle.
#[must_use]
pub fn enz_web_view_owned<Message>(
    view: ViewId,
    frame: Rgba8Frame,
    visible: bool,
) -> EnzWebView<'static, Message> {
    EnzWebView {
        view,
        frame: Some(WebFrameRef::Owned(frame)),
        visible,
        title: None,
        max_surface_width: DEFAULT_MAX_SURFACE_WIDTH,
        fill_viewport: false,
        scale_factor: 1.0,
        page_a11y: None,
        ime: None,
        page_cursor: None,
        on_input_method: None,
        on_input: None,
        on_viewport_resize: None,
        presented: None,
        gpu: None,
        gpu_source: None,
    }
}

impl<'a, Message> EnzWebView<'a, Message> {
    /// Fill the parent's allocated width and height instead of using a capped aspect ratio.
    ///
    /// The parent must provide finite bounds, such as a browser window's content pane.
    /// Retained CPU and GPU frames keep their pixel size and top-left origin
    /// during resize until a frame at the new size arrives.
    #[must_use]
    pub fn fill_viewport(mut self, fill: bool) -> Self {
        self.fill_viewport = fill;
        self
    }

    /// Prefer a leased GPU frame belonging to this live view.
    ///
    /// A supplied CPU frame remains the import fallback. Frames from a foreign
    /// or superseded view are refused at this publication boundary.
    #[must_use]
    pub fn gpu_frame(
        mut self,
        frame: &gpu::GpuFrame,
        router: &enzui_webkit::web::ViewRouter,
    ) -> Self {
        if frame.view() == self.view && router.accepts(self.view) {
            self.gpu = Some(frame.clone());
        }
        self
    }

    /// Mount a live source belonging to this view without rebuilding for each frame.
    ///
    /// Publication validates the generation again. A supplied CPU frame remains
    /// the import fallback; host geometry and metadata changes still need normal updates.
    #[must_use]
    pub fn gpu_source(
        mut self,
        source: &gpu::GpuFrameSource,
        router: &enzui_webkit::web::ViewRouter,
    ) -> Self {
        if source.view() == self.view && router.accepts(self.view) {
            self.gpu_source = Some(source.clone());
        }
        self
    }

    /// Supply a human page title, used in the surface's accessible name. Without
    /// it the name states role and state only.
    #[must_use]
    pub fn title(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }

    /// Supply the page's accessible tree, so the page's headings, buttons,
    /// links and fields are published into the host's accessibility tree as
    /// descendants of the web area.
    ///
    /// # Only a router-checked snapshot may be published
    ///
    /// This takes a [`PublishedPage`] - the unforgeable witness that a tree
    /// passed [`PageA11yDelivery`](enzui_webkit::page_delivery::PageA11yDelivery)'s
    /// generation/ownership check for a live view. There is no
    /// bare-[`PageA11y`] entry point that would let a host publish
    /// a snapshot cloned before a crash - a dead page's controls,
    /// straight past the router - so a stale tree cannot reach the
    /// host accessibility tree through this widget.
    ///
    /// Without a page the web area publishes a node saying the page's content is
    /// not exposed ([`WEB_AREA_NOT_EXPOSED`]) - a stated absence, never a
    /// silent one and never an invented child.
    ///
    /// A bare [`PageA11y`] is
    /// rejected at compile time - there is no way to publish a tree that did not
    /// pass the delivery layer's live-view check:
    ///
    /// ```compile_fail
    /// # use enzui_webview::enz_web_view;
    /// # use enzui_webkit::page_a11y::PageA11y;
    /// # use enzui_webkit::web::{ViewId, ViewRouter};
    /// # fn demo(view: ViewId, router: &ViewRouter, bare: PageA11y) {
    /// // error[E0308]: expected `PublishedPage`, found `PageA11y`
    /// let _ = enz_web_view(view, None, true).page_a11y(bare, router);
    /// # }
    /// ```
    ///
    /// # Live generation is consulted at consumption
    ///
    /// `router` is checked here, at the moment of publication - not only
    /// when the witness was minted. A witness proves the page was live
    /// when it was made; between then and this render the view can crash
    /// and be recreated. Re-checking
    /// [`ViewRouter::accepts`](enzui_webkit::web::ViewRouter::accepts)
    /// refuses a witness whose generation has since been superseded, even
    /// in the corner case where the widget was itself (wrongly) constructed
    /// with the same now-stale id - the stale-original-widget case that a
    /// bare `witness.view() == self.view` comparison alone would let
    /// through.
    #[must_use]
    pub fn page_a11y(
        mut self,
        published: PublishedPage,
        router: &enzui_webkit::web::ViewRouter,
    ) -> Self {
        // The witness rule: the witness is bound to the exact view it was minted
        // for. A witness for another view id - a different slot, or a
        // generation a host held across a crash and re-presented - is refused
        // here, so the web area publishes the not-exposed node rather than a
        // foreign or dead view's controls.
        //
        // Stale original widget: the widget's own view must still be
        // the router's live generation. This consults live state at consumption
        // rather than trusting the mint-time check, so a witness retained across
        // a recreate cannot publish even when handed to a widget that kept the
        // stale id.
        if published.view() == self.view && router.accepts(self.view) {
            self.page_a11y = Some(published.into_page());
        }
        self
    }

    /// Publish the page's caret rectangle, input purpose and composition to
    /// iced's window input method.
    ///
    /// # Only a router-checked witness may be published
    ///
    /// This takes a [`PublishedIme`](enzui_webkit::web::PublishedIme) - the witness
    /// [`PageIme::published`](enzui_webkit::web::PageIme::published) mints
    /// only for the live generation. There is deliberately no entry point that
    /// takes a bare caret rectangle, because a host must not publish geometry
    /// captured before a crash
    /// or a focus loss.
    ///
    /// `router` is consulted here, at the moment of publication, for the
    /// same reason [`page_a11y`](Self::page_a11y) does it: a witness proves
    /// the page was live when it was made, and between then and this render
    /// the
    /// view can crash and be recreated. A witness for another view id, or for a
    /// generation the router has since superseded, publishes nothing - which
    /// closes the IME rather than leaving a stale rectangle on screen.
    ///
    /// A hidden view publishes nothing regardless of the witness.
    #[must_use]
    pub fn input_method(
        mut self,
        published: &enzui_webkit::web::PublishedIme,
        router: &enzui_webkit::web::ViewRouter,
    ) -> Self {
        if published.view() != self.view || !router.accepts(self.view) {
            return self;
        }
        let input = published.input();
        self.ime = Some(seam::PageInputState {
            caret: (
                input.caret.x,
                input.caret.y,
                input.caret.width,
                input.caret.height,
            ),
            purpose: convert::purpose(input.purpose),
            preedit: published.preedit().map(convert::preedit),
            scale_factor: self.scale_factor,
        });
        self
    }

    /// Route the window's IME events (`Opened` / `Preedit` / `Commit` /
    /// `Closed`) to the host, which forwards them to the engine.
    ///
    /// This is the inbound half of the IME path: the toolkit's input
    /// method
    /// produces the composition, and only the widget can see it, because iced
    /// delivers `Event::InputMethod` through widget `update` and nowhere else.
    /// Without a handler the event is dropped rather than synthesised into
    /// something - the page must not receive text nobody routed.
    #[must_use]
    pub fn on_input_method(
        mut self,
        f: impl Fn(enzui_webkit::web::ToolkitImeEvent) -> Message + 'a,
    ) -> Self {
        self.on_input_method = Some(Box::new(f));
        self
    }

    /// Route real iced pointer, wheel, touch and keyboard events to the host as
    /// generation-keyed engine [`InputEvent`]s.
    ///
    /// Unlike [`pointer_event`](Self::pointer_event), this is not a geometry
    /// helper that the application must call from some unrelated control. The
    /// widget's retained input seam receives iced events with its actual layout
    /// bounds, translates and clips positioned input, takes focus on an inside
    /// press, and forwards keys only while focused. Handled events are captured
    /// so a click or keystroke cannot also activate a control behind the web
    /// surface.
    #[must_use]
    pub fn on_input(mut self, f: impl Fn(InputEvent) -> Message + 'a) -> Self {
        self.on_input = Some(Box::new(f));
        self
    }

    /// Report this widget's actual laid-out viewport when its integer logical
    /// dimensions change.
    ///
    /// The callback carries the widget's [`ViewId`] so a queued resize remains
    /// generation-safe at the app/engine boundary. Fractional layout bounds
    /// are rounded once by [`ViewportSize::from_logical`](enzui_webkit::ViewportSize::from_logical);
    /// zero, non-finite and overflowing dimensions produce no message. Reports
    /// are driven by iced resize/redraw events and deduplicated after conversion, so
    /// there is no timer/poll loop and subpixel churn cannot flood the engine.
    #[must_use]
    pub fn on_viewport_resize(
        mut self,
        f: impl Fn(ViewId, enzui_webkit::ViewportSize) -> Message + 'a,
    ) -> Self {
        self.on_viewport_resize = Some(Box::new(f));
        self
    }

    /// Route the page's requested cursor into iced while the pointer is inside
    /// the visible widget.
    ///
    /// `name` is the WPE/CSS cursor name the engine recorded (see
    /// `WebSession::requested_cursor`),
    /// translated by the single table in
    /// [`enzui_webkit::web::cursor::page_cursor`]. An unknown name
    /// resolves to the ordinary arrow rather than panicking, and `None` leaves
    /// the host's own cursor entirely alone - "the page asked for nothing" and
    /// "the page asked for something I do not know" are different statements.
    #[must_use]
    pub fn page_cursor(mut self, name: Option<&str>) -> Self {
        self.page_cursor =
            name.map(|name| convert::interaction(enzui_webkit::web::page_cursor(name)));
        self
    }

    /// The `Interaction` (`iced::mouse::Interaction`) this widget will apply
    /// while the pointer is over it, without rendering. `None` means the host's
    /// own cursor stands.
    #[must_use]
    pub fn resolved_page_cursor(&self) -> Option<iced::mouse::Interaction> {
        self.page_cursor
    }

    /// The window-logical IME rectangle this widget would publish for
    /// `bounds`/`viewport`, or `None` when it would publish nothing (closed,
    /// hidden, stale, clipped away, or off-surface).
    ///
    /// The observable the IME tests assert: it is the same function the widget's
    /// `update` calls, so a test cannot pass against a second copy of the
    /// mapping.
    #[must_use]
    pub fn ime_rectangle(
        &self,
        bounds: iced::Rectangle,
        viewport: iced::Rectangle,
    ) -> Option<iced::Rectangle> {
        if !self.visible {
            return None;
        }
        seam::window_ime_rect(self.ime.as_ref()?, bounds, viewport)
    }

    /// Cap the surface width, in logical pixels. Defaults to
    /// [`DEFAULT_MAX_SURFACE_WIDTH`]. A non-finite or non-positive value is
    /// ignored (the default is kept) rather than collapsing the surface.
    #[must_use]
    pub fn max_width(mut self, px: f32) -> Self {
        if px.is_finite() && px > 0.0 {
            self.max_surface_width = px;
        }
        self
    }

    /// Set the view's output/device scale (e.g. 2.0 on HiDPI). It is carried on
    /// the [`ViewportMapping`] for validation and future framebuffer sizing but
    /// is not multiplied into pointer/caret coordinates: WPE consumes
    /// logical view coordinates and applies the output scale itself, so doubling
    /// it here would miss the target at scale 2. A non-finite or
    /// non-positive value is ignored (1.0 is kept).
    #[must_use]
    pub fn scale_factor(mut self, scale: f32) -> Self {
        if scale.is_finite() && scale > 0.0 {
            self.scale_factor = scale;
        }
        self
    }

    /// The width cap currently in force.
    #[must_use]
    pub fn max_surface_width(&self) -> f32 {
        self.max_surface_width
    }

    /// Which surface this widget will render, without rendering it.
    #[must_use]
    pub fn surface(&self) -> WebSurface {
        WebSurface::for_state(self.visible, self.frame.is_some())
    }

    /// The accessible name this widget will publish.
    #[must_use]
    pub fn surface_name(&self) -> String {
        surface_name(self.surface(), self.title.as_deref())
    }

    /// The viewport mapping for a surface laid out at window-logical
    /// `(origin_x, origin_y)` of logical size `width x height`.
    ///
    /// This is the transform the input path uses: the host passes the widget's
    /// laid-out bounds (which iced gives it after layout) and the mapping
    /// translates every pointer by the view origin and clips it to the bounds
    /// (no output-scale multiply; WPE owns that). Returns `None` only for an
    /// incoherent geometry (non-finite bounds); a normal bound always yields a
    /// mapping.
    #[must_use]
    pub fn mapping(
        &self,
        origin_x: f32,
        origin_y: f32,
        width: f32,
        height: f32,
    ) -> Option<ViewportMapping> {
        ViewportMapping::new(origin_x, origin_y, width, height, self.scale_factor)
    }

    /// Translate a toolkit pointer event at window-logical `(x, y)` into a
    /// typed, translated, clipped [`InputEvent`] for this view - or `None` if the
    /// point is outside the surface bounds (a click on a neighbour) or the view
    /// is hidden.
    ///
    /// This is the widget's input path. The `phase` selects moved / pressed /
    /// released; the translation and clipping are done by the engine crate's
    /// tested [`ViewportMapping`], not re-derived here.
    #[must_use]
    pub fn pointer_event(
        &self,
        bounds: (f32, f32, f32, f32),
        x: f32,
        y: f32,
        phase: PointerPhase,
    ) -> Option<InputEvent> {
        self.pointer_event_with_modifiers(bounds, x, y, phase, Modifiers::NONE)
    }

    /// The same helper, with an explicit modifier snapshot. The retained widget
    /// route pulls modifiers from its own latch and does not use this helper;
    /// this is the entry point for hosts synthesising events out of band.
    #[must_use]
    pub fn pointer_event_with_modifiers(
        &self,
        bounds: (f32, f32, f32, f32),
        x: f32,
        y: f32,
        phase: PointerPhase,
        modifiers: Modifiers,
    ) -> Option<InputEvent> {
        if !self.visible {
            // A hidden view receives no input - it is quiescent.
            return None;
        }
        let (ox, oy, w, h) = bounds;
        let mapping = self.mapping(ox, oy, w, h)?;
        match phase {
            PointerPhase::Moved => {
                pointer_moved_with_modifiers(self.view, &mapping, x, y, modifiers)
            }
            PointerPhase::Pressed(button) => {
                pointer_pressed_with_modifiers(self.view, &mapping, x, y, button, modifiers)
            }
            PointerPhase::Released(button) => {
                pointer_released_with_modifiers(self.view, &mapping, x, y, button, modifiers)
            }
        }
    }

    /// Translate a toolkit wheel event into a typed [`InputEvent`].
    /// A wheel delta is neither translated nor output-scaled; there is no bounds clip on a
    /// delta (the host calls this only while the pointer is over the surface). A
    /// hidden view receives nothing.
    #[must_use]
    pub fn wheel_event(
        &self,
        bounds: (f32, f32, f32, f32),
        delta_x: f32,
        delta_y: f32,
    ) -> Option<InputEvent> {
        if !self.visible {
            return None;
        }
        let (ox, oy, w, h) = bounds;
        let mapping = self.mapping(ox, oy, w, h)?;
        Some(wheel_scrolled_with_modifiers(
            self.view,
            &mapping,
            delta_x,
            delta_y,
            Modifiers::NONE,
        ))
    }

    /// Translate a toolkit key event into a typed [`InputEvent`] for this
    /// view. Routed only when the view holds keyboard focus (the host enforces
    /// that) and is visible.
    #[must_use]
    pub fn key_event(&self, key: KeyCode, pressed: bool) -> Option<InputEvent> {
        self.key_event_with_modifiers(key, pressed, Modifiers::NONE)
    }

    /// The same helper with an explicit modifier snapshot.
    #[must_use]
    pub fn key_event_with_modifiers(
        &self,
        key: KeyCode,
        pressed: bool,
        modifiers: Modifiers,
    ) -> Option<InputEvent> {
        if !self.visible {
            return None;
        }
        Some(if pressed {
            InputEvent::KeyPressed {
                view: self.view,
                key,
                modifiers,
            }
        } else {
            InputEvent::KeyReleased {
                view: self.view,
                key,
                modifiers,
            }
        })
    }
}

/// Which pointer phase a translated event represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PointerPhase {
    /// The pointer moved.
    Moved,
    /// A button was pressed.
    Pressed(PointerButton),
    /// A button was released.
    Released(PointerButton),
}

impl<'a, Message> EnzWebView<'a, Message> {
    /// Draws `handle`, which the host retains for the current frame, instead of
    /// copying the frame into a fresh handle on every view.
    ///
    /// Without it, each view copies the frame's pixels and mints a new
    /// renderer identity, so every redraw uploads the frame again even when
    /// the page has not painted. A host that mints one handle per frame
    /// arrival, for example through
    /// [`LatestFramePresenter`](enzui_widgets::video::LatestFramePresenter),
    /// keeps one upload per engine frame. The frame still decides
    /// geometry and the surface state, and the handle must show that frame.
    #[must_use]
    pub fn presented(mut self, handle: iced_image::Handle) -> Self {
        self.presented = Some(handle);
        self
    }

    /// Finish the builder and hand back the [`Element`], which is step 3 of
    /// the build pattern every widget in this crate follows (`docs/widgets.md`).
    ///
    /// This forwards to the `From<Self> for Element` impl below, so the two
    /// spellings are one implementation and cannot drift apart. Prefer this
    /// one inside `row![]` / `column![]`, where `.into()` has no target type
    /// to infer.
    #[must_use]
    pub fn into_element(self) -> Element<'a, Message, Theme>
    where
        Message: 'a,
    {
        Element::from(self)
    }
}

impl<'a, Message: 'a> From<EnzWebView<'a, Message>> for Element<'a, Message, Theme> {
    fn from(v: EnzWebView<'a, Message>) -> Self {
        let surface = WebSurface::for_state(
            v.visible,
            v.frame.is_some()
                || v.gpu.is_some()
                || v.gpu_source
                    .as_ref()
                    .is_some_and(|source| source.size().is_some()),
        );
        let name = surface_name(surface, v.title.as_deref());
        let ratio = v.gpu.as_ref().map_or_else(
            || aspect_ratio_for(v.frame.as_ref().map(WebFrameRef::get)),
            |frame| {
                frame.external().buffer().width as f32 / frame.external().buffer().height as f32
            },
        );

        let surface_element: Element<'a, Message, Theme> = match surface {
            WebSurface::Frame if v.gpu_source.is_some() => {
                let source = v.gpu_source.as_ref().expect("GPU surface has a source");
                let mut image = enzui_external_image::enz_external_image_source(source.external())
                    .content_fit(frame_fit(v.fill_viewport))
                    .align_x(frame_align(v.fill_viewport).0)
                    .align_y(frame_align(v.fill_viewport).1)
                    .width(Length::Fill)
                    .height(Length::Fill);
                if let Some(fallback) = v.frame.as_ref() {
                    image = image.fallback(
                        v.presented
                            .clone()
                            .unwrap_or_else(|| web_frame_handle(fallback.get())),
                    );
                }
                if v.fill_viewport {
                    image.into()
                } else {
                    let ratio = source.size().map_or(ratio, |(w, h)| w as f32 / h as f32);
                    enzui_widgets::aspect_ratio::enz_aspect_ratio(image, ratio).into()
                }
            }
            WebSurface::Frame if v.gpu.is_some() => {
                let frame = v.gpu.as_ref().expect("GPU surface has a frame");
                let mut image = enzui_external_image::enz_external_image(frame.external())
                    .content_fit(frame_fit(v.fill_viewport))
                    .align_x(frame_align(v.fill_viewport).0)
                    .align_y(frame_align(v.fill_viewport).1)
                    .width(Length::Fill)
                    .height(Length::Fill);
                if let Some(fallback) = v.frame.as_ref() {
                    image = image.fallback(
                        v.presented
                            .clone()
                            .unwrap_or_else(|| web_frame_handle(fallback.get())),
                    );
                }
                if v.fill_viewport {
                    image.into()
                } else {
                    enzui_widgets::aspect_ratio::enz_aspect_ratio(image, ratio).into()
                }
            }
            WebSurface::Frame => {
                let frame = v
                    .frame
                    .as_ref()
                    .expect("WebSurface::Frame implies a frame")
                    .get();
                // The host's retained handle, or exactly one fresh handle per
                // view from the buffer the sink owns.
                let handle = v
                    .presented
                    .clone()
                    .unwrap_or_else(|| web_frame_handle(frame));
                if v.fill_viewport {
                    viewport_frame::ViewportFrame::new(handle).into()
                } else {
                    let element = enzui_widgets::image::enz_image_handle(handle)
                        .fit(enzui_widgets::image::EnzImageFit::Contain)
                        .alt_text(name.clone())
                        .width(Length::Fill)
                        .height(Length::Fill)
                        .into_element();
                    enzui_widgets::aspect_ratio::enz_aspect_ratio(element, ratio).into()
                }
            }
            WebSurface::AwaitingFirstFrame => {
                // The loading surface must paint the same allocated height as a loaded page.
                let skeleton: Element<'a, Message, Theme> = enzui_widgets::skeleton::enz_skeleton(
                    enzui_widgets::skeleton::SkeletonKind::Card,
                )
                .label(name.clone())
                .fill_height(true)
                .into_element();
                let shaped: Element<'a, Message, Theme> = if v.fill_viewport {
                    container(skeleton)
                        .width(Length::Fill)
                        .height(Length::Fill)
                        .into()
                } else {
                    enzui_widgets::aspect_ratio::enz_aspect_ratio(skeleton, ratio).into()
                };
                enzui_widgets::semantics_container::SemanticsContainer::new(
                    shaped,
                    Announcement::Status.region(name.clone()),
                )
                .into()
            }
            WebSurface::Hidden => {
                // A hidden view presents no surface at all - quiescent. A named
                // live region tells AT the view is hidden rather than broken.
                let notice: Element<'a, Message, Theme> =
                    enzui_widgets::text::enz_text(name.clone())
                        .size_px(enzui_theme::text_scale::ui_px(12.0))
                        .announce(false)
                        .into_element();
                let boxed: Element<'a, Message, Theme> = container(notice)
                    .padding(Padding::new(12.0))
                    .width(Length::Fill)
                    .into();
                enzui_widgets::semantics_container::SemanticsContainer::leaf(
                    boxed,
                    Announcement::Status.region(name.clone()),
                )
                .into()
            }
        };

        // Publish the web area, and beneath it the page's own accessible tree
        // when the host has one. A hidden view publishes no
        // page nodes at all: a quiescent tab exposes no live document.
        let page_root = if surface == WebSurface::Hidden {
            None
        } else {
            v.page_a11y.as_ref().map(|p| p.root().clone())
        };
        let area = web_area_semantics(surface, &name, v.page_a11y.as_ref());
        let seamed = seam::WebViewSeam::new(surface_element, area, page_root, v.view)
            .input_method(if surface == WebSurface::Hidden {
                // A hidden view publishes no caret at all: a quiescent tab
                // must not hold the window's input method open.
                None
            } else {
                v.ime.clone()
            })
            .page_cursor(if surface == WebSurface::Hidden {
                None
            } else {
                v.page_cursor
            });
        let seamed = match v.on_input_method {
            Some(handler) => seamed.on_input_method(handler),
            None => seamed,
        };
        let seamed = match v.on_input {
            Some(handler) => {
                seamed.on_input(v.scale_factor, surface != WebSurface::Hidden, handler)
            }
            None => seamed,
        };
        let seamed = match v.on_viewport_resize {
            Some(handler) => seamed.on_viewport_resize(surface != WebSurface::Hidden, handler),
            None => seamed,
        };
        let published: Element<'a, Message, Theme> = seamed.into();

        if v.fill_viewport {
            container(published)
                .width(Length::Fill)
                .height(Length::Fill)
                .into()
        } else {
            enzui_widgets::max_width::max_width(published, v.max_surface_width).into()
        }
    }
}

/// The semantics a caller can attach to an externally-composed surface.
pub fn surface_semantics(surface: WebSurface, title: Option<&str>) -> Semantics {
    Announcement::Status.region(surface_name(surface, title))
}

/// The published id of the page node identified by `key` inside `view`.
///
/// # One page-node id recipe
///
/// Two places need it: [`seam`] when it publishes a node, and
/// [`page_node_key_for_id`] when it resolves an AT action back to one. A
/// second copy of the recipe would be a damaging source of identity drift - the two would agree until one was edited, and then an activation
/// would resolve to a node other than the one the screen reader was reading.
///
/// # Keyed on the node's address, not its position
///
/// The `key` is
/// [`PageNodeKey`], which is
/// derived from the node's AT-SPI object address. Keying the id on the
/// node's tree position instead would let ordinary DOM mutation defeat it:
/// inserting one element at the top of a document shifts every following
/// sibling, so the id AT was given for one control would name a different one
/// on the next publish, and an activation queued across the mutation would
/// press the wrong thing.
///
/// # Keyed on the slot, not the generation
///
/// A [`ViewId`]'s slot survives a crash and recreate; its generation does not.
/// Keying on the slot means a recovered view republishes the same identities,
/// so AT is not handed a wholly new tree after a WebProcess restart. Staleness
/// is not this function's job - it belongs to
/// [`PageA11yDelivery`](enzui_webkit::page_delivery::PageA11yDelivery),
/// which refuses to publish or route a superseded generation at all. Putting
/// the generation in the id as well would make every recovery look like a
/// brand-new document to a screen reader for no added safety.
///
/// # The recipe lives in core
///
/// This delegates to [`enzui_core::identity::web_page_node_id`] so the
/// engine's native activation gate can resolve an AccessKit id through the
/// exact same recipe without depending on this widget crate - the reverse
/// dev-dependency cycle the shortcut would otherwise require.
#[must_use]
pub fn page_node_id(view: ViewId, key: &PageNodeKey) -> iced::advanced::widget::Id {
    enzui_core::identity::web_page_node_id(view.slot(), key.as_str())
}

/// Resolve a published page-node `Id` (`iced::advanced::widget::Id`) back to the
/// [`PageNodeKey`] it was
/// derived from.
///
/// This is the production step between an
/// `AccessibilityAction::Activate(id)` and a routed page action: the runtime
/// hands the application a widget id, and only this function can say which page
/// node - if any - that id names.
///
/// Returns `None` for ids outside this `view`'s published tree, including other
/// widgets, other view slots, and nodes removed from the page.
///
/// # Why a search and not a reverse function
///
/// [`page_node_id`] hashes into an opaque `Id` (`iced::advanced::widget::Id`);
/// there is nothing to invert. So the published tree is enumerated and each
/// node's id recomputed with the same recipe, which has the useful property
/// that a node not in the current tree cannot resolve at all. The walk is
/// bounded by [`PageLimits`](enzui_webkit::page_a11y::PageLimits).
#[must_use]
pub fn page_node_key_for_id(
    page: &PageA11y,
    view: ViewId,
    id: &iced::advanced::widget::Id,
) -> Option<PageNodeKey> {
    page.keys()
        .into_iter()
        .find(|key| page_node_id(view, key) == *id)
}

/// What the web area says when the host has no accessible tree for the
/// page: the absence is published, not hidden.
///
/// A web area that published nothing at all would be indistinguishable from an
/// empty page, and a placeholder child would be a lie. Stating the absence lets
/// a screen-reader user know the content exists but is unreachable, which is
/// the only honest answer available.
pub const WEB_AREA_NOT_EXPOSED: &str = "The page's content is not exposed to assistive technology.";

/// What the web area says while the view is hidden.
pub const WEB_AREA_HIDDEN: &str =
    "The web view is hidden; its page publishes no content while quiescent.";

/// The web area's own accessibility node - the parent of every published page
/// node.
///
/// The description channel carries the state of the bridge, because AT-SPI on
/// Linux reads descriptions and there is no other place to say "the tree you
/// are reading is incomplete". Truncation and unmapped roles are reported for
/// the same reason: a short tree that says nothing is a silent failure.
pub fn web_area_semantics(surface: WebSurface, name: &str, page: Option<&PageA11y>) -> Semantics {
    let base = Semantics::new(Role::Group).label(name.to_owned());
    if surface == WebSurface::Hidden {
        return base.description(WEB_AREA_HIDDEN);
    }
    match page {
        None => base.description(WEB_AREA_NOT_EXPOSED),
        Some(page) => {
            let mut notes: Vec<String> = Vec::new();
            if page.truncated() {
                notes.push("Page content is truncated; not every element is listed.".to_owned());
            }
            if !page.unmapped_roles().is_empty() {
                notes.push(format!(
                    "{} page element kind(s) have no host role and are listed as groups.",
                    page.unmapped_roles().len()
                ));
            }
            if page.unnamed_actionable() > 0 {
                notes.push(format!(
                    "{} unnamed page control(s) are listed as groups.",
                    page.unnamed_actionable()
                ));
            }
            if notes.is_empty() {
                base
            } else {
                base.description(notes.join(" "))
            }
        }
    }
}

#[cfg(test)]
mod tests;

/// How a retained GPU frame fits its allocation. A viewport-filling view
/// draws a frame from the previous size at its own pixel size, anchored
/// top-left and clipped (see [`frame_align`]), as the CPU path does; other
/// views keep the aspect-fitted frame.
fn frame_fit(fill_viewport: bool) -> iced::ContentFit {
    if fill_viewport {
        iced::ContentFit::None
    } else {
        iced::ContentFit::Contain
    }
}

/// Where a retained GPU frame sits in its allocation: top-left for a
/// viewport-filling view, centred otherwise.
fn frame_align(fill_viewport: bool) -> (iced::alignment::Horizontal, iced::alignment::Vertical) {
    if fill_viewport {
        (
            iced::alignment::Horizontal::Left,
            iced::alignment::Vertical::Top,
        )
    } else {
        (
            iced::alignment::Horizontal::Center,
            iced::alignment::Vertical::Center,
        )
    }
}
