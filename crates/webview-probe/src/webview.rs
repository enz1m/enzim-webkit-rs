//! Webview protocol host: the runtime consumer of [`enzui_webkit::web`].
//!
//! Connects the five pure pieces (generation-keyed view ids, correlated
//! default-deny policy, profile isolation, bounded latest-frame transport,
//! focus/IME handoff) to the rendered route: every button emits a real
//! `Message` driving the real protocol types, so a broken policy changes the
//! screen and the wire test sees it.
//!
//! Feature-off the route stays deterministic with canned events and no browser;
//! with `wpe`, `NativePage` adds a real WebSession across the same seams.
//! Failed native requests say so loudly - never a silent canned substitution.

use enzui_core::media::{BoundedFrameSink, Delivery, Generation as MediaGeneration, Rgba8Frame};
use enzui_webkit::ime_bridge::{ImeEffect, ImeTransition, NativeImeReport, WebViewIme};
use enzui_webkit::visibility::{ViewLifecycle, ViewVisibility};
use enzui_webkit::web::Traversal;
use enzui_webkit::web::focus::{FocusHandoff, HandoffOutcome, TabReply};
use enzui_webkit::web::frame::{FramePlan, FrameSeq};
use enzui_webkit::web::ime::{
    CaretRect, IME_TEXT_REDACTION, ImeClose, PageInput, Preedit, PublishedIme, Purpose,
    ToolkitImeEvent, diagnostic_ime_event,
};
use enzui_webkit::web::policy::{NavContext, PermissionKind, PolicyUrl, RequestKind, WebPolicy};
use enzui_webkit::web::profile::WebProfile;
use enzui_webkit::web::view_id::{Generation, ViewId, ViewRouter};
use enzui_webview::convert;

// The route drives the typed engine/protocol layer: backend mode, view-scoped
// policy session, and `EngineCommand`/`EngineEvent` exchange with a canned engine.
use enzui_webkit::mode::{self, BackendMode, ModeError, ResolvedBackend};
use enzui_webkit::page_a11y::{AccessibleSource, PageA11y, PageNodeAddress, PageNodeKey, atspi};
use enzui_webkit::page_action::{PageActionDispatch, PageActionDispatchOutcome};
use enzui_webkit::page_delivery::{PageA11yDelivery, PageActionRoute, PageDelivery, PublishedPage};
use enzui_webkit::protocol::{EngineCommand, EngineEvent};
use enzui_webkit::session::{PolicySession, SessionResolve};

/// One node of the AT-SPI tree the route delivers: a real page's shape,
/// verified against the live tree the native gate reads.
#[derive(Debug)]
pub struct CannedAtspiNode {
    role: u32,
    name: String,
    children: Vec<CannedAtspiNode>,
    address: Option<PageNodeAddress>,
    actions: Vec<String>,
}

impl CannedAtspiNode {
    fn leaf(role: u32, name: &str) -> Self {
        Self {
            role,
            name: name.to_owned(),
            children: Vec::new(),
            // Every node the walk produces has an address; whether it is
            // *operable* is decided by its actions, below.
            address: Some(PageNodeAddress::new(
                ":1.196",
                format!("/org/a11y/atspi/accessible/{}", name.replace(' ', "-")),
            )),
            actions: Vec::new(),
        }
    }
    /// A control that reports a real machine-readable AT-SPI action.
    fn actionable(role: u32, name: &str, action: &str) -> Self {
        let mut node = Self::leaf(role, name);
        node.actions.push(action.to_owned());
        node
    }
}

impl AccessibleSource for CannedAtspiNode {
    fn atspi_role(&self) -> u32 {
        self.role
    }
    fn accessible_name(&self) -> &str {
        &self.name
    }
    fn accessible_children(&self) -> &[Self] {
        &self.children
    }
    fn accessible_address(&self) -> Option<PageNodeAddress> {
        self.address.clone()
    }
    fn accessible_actions(&self) -> &[String] {
        &self.actions
    }
}

/// Canned page: heading, button, link, field. Only button/link carry real
/// actions - the mix lets the gate prove it discriminates.
fn demo_page() -> CannedAtspiNode {
    let mut root = CannedAtspiNode::leaf(atspi::DOCUMENT_WEB, "Probe Demo Page");
    root.children = vec![
        CannedAtspiNode::leaf(atspi::HEADING, "Demo Page Heading"),
        CannedAtspiNode::actionable(atspi::PUSH_BUTTON, "Demo Page Button", "click"),
        CannedAtspiNode::actionable(atspi::LINK, "Demo Page Link", "jump"),
        CannedAtspiNode::leaf(atspi::ENTRY, "Demo Page Field"),
    ];
    root
}

/// Pre-attestation status: neither empty nor a pass, so a never-asked route
/// never reads as asked-and-satisfied.
pub const NEVER_CHECKED: &str = "not checked yet";

/// Host state for the webview protocol route: canned events drive every piece
/// of `enzui_webkit::web`, as `DownloadService` drives `download` from ticks.
#[derive(Debug)]
#[allow(dead_code)]
pub struct WebViewService {
    /// The view router managing live/stale generations.
    pub router: ViewRouter,
    pub live_view: Option<ViewId>,
    /// Starts strict (default-deny).
    pub policy: WebPolicy,
    pub focus: FocusHandoff,
    pub frame_plan: Option<FramePlan>,
    pub next_seq: u64,
    pub profile: WebProfile,
    /// The newest 256 diagnostics, limited to 2048 UTF-8 bytes per line.
    pub log: crate::diagnostic_log::DiagnosticLog,
    /// The last policy decision result, for display.
    pub last_decision: Option<String>,
    /// The last focus outcome, for display.
    pub last_focus_outcome: Option<String>,
    /// The last frame verdict, for display.
    pub last_frame_verdict: Option<String>,

    // -- The engine/protocol crate, driven from this route --
    //
    /// Backend resolved at construction: [`BackendMode::Native`] by name -
    /// feature-off the typed [`ModeError::NativeUnavailable`], never a mock.
    pub backend: Result<ResolvedBackend, ModeError>,
    /// The view-scoped session granting Camera: requests would be allowed live -
    /// which is what makes the `ViewGone` case load-bearing.
    pub session: PolicySession,
    /// Last engine-mediated policy outcome, for display; `None` until an engine
    /// flow runs.
    pub last_engine_outcome: Option<String>,
    /// Last app-to-engine command, for display: proves the direction is exercised.
    pub last_engine_command: Option<String>,

    // -- The ACTUAL presented surface --
    //
    /// Bounded CPU-RGBA sink of the real decoded buffers; the widget borrows
    /// `displayed`, so discarded stale frames never reach the screen.
    pub sink: BoundedFrameSink,
    /// Sink generation, lockstepped with the view generation on recreate; a
    /// distinct type from `web::Generation`, tracked explicitly.
    pub sink_generation: MediaGeneration,
    /// View lifecycle: hidden views go quiescent, closing releases buffers;
    /// drives whether the route presents a live surface.
    pub lifecycle: ViewLifecycle,
    /// Device-pixel scale forwarded to `ViewportMapping`; 2.0 exercises the
    /// non-identity path in a running probe.
    pub scale_factor: f32,
    /// Last forwarded input event, for display: proves real-geometry driving.
    pub last_input: Option<String>,
    /// Generation-owned page-a11y snapshot: delivery tags by producing `ViewId`,
    /// refusing stale offers and reads; feature-off source is the same translation.
    pub page_delivery: PageA11yDelivery,
    /// What the last page-a11y delivery attempt did, for the route to render.
    pub last_page_delivery: Option<String>,
    /// Last routed AT action, for display: proves activation reached a specific
    /// object rather than being dropped.
    pub last_page_action: Option<String>,
    /// Generation-owned page IME: owning `ViewId`, caret, composition. The widget
    /// translates through real bounds/clip; stale claims reach neither.
    pub page_ime: WebViewIme,
    /// Live native page (`wpe` build, opened route): pump, reports, snapshots and
    /// effects turn this service from typed model into real page adopter.
    pub native: Option<crate::webview_native::NativePage>,
    /// Most recent valid integer allocation from the real view; retained pageless
    /// so session open/recreate can size WPE before first load.
    pub native_viewport: Option<enzui_webkit::ViewportSize>,
    /// Secure per-process scratch rooting the profile store (leased clone); timed-out
    /// detached jobs and crash residue retained - see [`crate::webview_scratch`]..
    pub native_scratch: Option<std::sync::Arc<crate::webview_scratch::SecureScratch>>,
    /// No-native-page reason, verbatim on screen: failures must not read as
    /// unloaded pages.
    pub native_error: Option<String>,
    /// Typed refusal from the synchronous native bootstrap-dispatch seam.
    pub native_open_error: Option<crate::webview_native::NativeOpenError>,
    /// Most recent worker failure, typed: rendered as `native_error`, while gates
    /// inspect this - timeouts never read as missing updates.
    pub native_worker_error: Option<crate::webview_native::NativeWorkerError>,
    /// Cached sandbox verdict, never attested inside `view`; explicit refreshes,
    /// timestamped so stale verdicts read as stale.
    pub sandbox_status: String,
    /// How many times [`WebViewService::refresh_sandbox`] has run. `0` means
    /// the status line is showing "never checked", not a pass.
    pub sandbox_checks: u32,
    /// Document title, including the diagnostic fixture's focus reports.
    pub dom_report: Option<String>,
    pub location: Option<String>,
    /// Last `apply_ime_effect` result, truthfully: `Ok` or the typed refusal.
    pub last_effect_result: Option<String>,
    /// Last session clipboard outcome, typed not prose: page-copy text, host-paste
    /// bytes, or the refusal - refusals never read as completed hops.
    pub last_clipboard: Option<enzui_webkit::ClipboardOutcome>,
    /// Native WPE focus observed on the most recent worker update.
    pub native_view_focused: Option<bool>,
    /// Tick counter, so snapshots are throttled below the frame rate.
    pub native_ticks: u64,
    pub native_visual_revision: u64,
    native_metadata: Option<std::sync::Arc<crate::webview_native::NativeMetadata>>,
    /// Last routed iced IME effect, for display: feature-off records what native
    /// would apply - typed, testable, identical to the native gate's.
    pub last_ime_effect: Option<ImeEffect>,
    /// What the last page-IME transition did, for the route to render.
    pub last_ime: Option<String>,
    /// Last page-requested cursor name (`None` clears). Either the button-set demo
    /// value or `WebSession::requested_cursor()` - same string, one table.
    pub page_cursor: Option<String>,
    pub gpu_frame: Option<enzui_webview::gpu::GpuFrame>,
    pub gpu_source: Option<enzui_webview::gpu::GpuFrameSource>,
    /// Frames offered while HIDDEN: the quiescence counter. Correct routes hold it
    /// at 0; non-zero is a wakeup that should not have happened.
    pub hidden_offer_attempts: u64,
}

/// Production dispatch port: authorizes through the same generation-owned
/// delivery the native port uses - one composition, not two paths.
#[derive(Debug, Default)]
struct RoutedActionPort;

impl PageActionDispatch for RoutedActionPort {
    fn dispatch_page_action(
        &mut self,
        router: &ViewRouter,
        live: ViewId,
        delivery: &PageA11yDelivery,
        key: &PageNodeKey,
    ) -> PageActionDispatchOutcome {
        match delivery.route_action(router, live, key) {
            PageActionRoute::Routed { view, .. } => PageActionDispatchOutcome::Dispatched {
                view,
                key: key.clone(),
            },
            PageActionRoute::NoPublishedPage => PageActionDispatchOutcome::Refused {
                reason: format!("{key}: no page published; nothing activated"),
            },
            PageActionRoute::StaleView { published, live } => PageActionDispatchOutcome::Refused {
                reason: format!(
                    "{key}: REFUSED stale page (published generation {}, live {})",
                    published.0, live.0
                ),
            },
            PageActionRoute::ViewNotLive { slot, asked, live } => {
                PageActionDispatchOutcome::Refused {
                    reason: format!(
                        "{key}: REFUSED, view slot {slot} generation {} is not live (live: {:?})",
                        asked.0,
                        live.map(|g| g.0)
                    ),
                }
            }
            PageActionRoute::UnknownNode { key } => PageActionDispatchOutcome::Refused {
                reason: format!("{key}: no such node in the live page"),
            },
            PageActionRoute::NotActionable { key } => PageActionDispatchOutcome::Refused {
                reason: format!("{key}: node is not actionable"),
            },
        }
    }
}

impl Default for WebViewService {
    fn default() -> Self {
        Self::new()
    }
}

impl WebViewService {
    /// Create a fresh service with a view in slot 0 and a strict policy.
    #[must_use]
    pub fn new() -> Self {
        let mut router = ViewRouter::new();
        let view = router.create(0);
        let profile = WebProfile::shared();
        let frame_plan = FramePlan::new(view.generation());

        // Name `Native` explicitly and keep the typed error: no mock fall-back,
        // so feature-off surfaces the mismatch honestly.
        let backend = mode::resolve(BackendMode::Native);

        // The engine's session grants Camera: allowed live, turned `ViewGone` by the
        // view-scoped guard after a crash-recreate.
        let mut session = PolicySession::new(WebPolicy::strict().grant(PermissionKind::Camera));
        session.open_view(view);

        // First page snapshot delivered here - it borrows `router`, so it cannot
        // live in the struct literal.
        let mut page_delivery = PageA11yDelivery::new();
        page_delivery.offer(&router, view, PageA11y::from_source(&demo_page()));

        let mut log = crate::diagnostic_log::DiagnosticLog::default();
        log.push("Service created with view in slot 0".to_owned());
        log.push(format!(
            "Backend mode resolve(Native) → {}",
            match &backend {
                Ok(b) => format!("Ok({:?})", b.mode()),
                Err(e) => format!("Err({e:?})"),
            }
        ));

        WebViewService {
            router,
            live_view: Some(view),
            policy: WebPolicy::strict(),
            focus: FocusHandoff::new(),
            frame_plan: Some(frame_plan),
            next_seq: 1,
            profile,
            log,
            last_decision: None,
            last_focus_outcome: None,
            last_frame_verdict: None,
            backend,
            session,
            last_engine_outcome: None,
            last_engine_command: None,
            page_delivery,
            last_page_delivery: None,
            last_page_action: None,
            sink: BoundedFrameSink::new(MediaGeneration::FIRST),
            sink_generation: MediaGeneration::FIRST,
            lifecycle: ViewLifecycle::new(),
            scale_factor: 2.0,
            last_input: None,
            page_ime: WebViewIme::new(),
            native: None,
            native_viewport: None,
            native_scratch: None,
            native_view_focused: None,
            native_ticks: 0,
            native_visual_revision: 0,
            native_metadata: None,
            native_error: None,
            native_open_error: None,
            native_worker_error: None,
            sandbox_status: NEVER_CHECKED.to_owned(),
            sandbox_checks: 0,
            dom_report: None,
            location: None,
            last_effect_result: None,
            last_clipboard: None,
            last_ime_effect: None,
            last_ime: None,
            page_cursor: None,
            gpu_frame: None,
            gpu_source: None,
            hidden_offer_attempts: 0,
        }
    }

    /// Deterministic demo surface dimensions, in device pixels: fixed literals the
    /// perf gate pins its workload by.
    pub const FRAME_W: u32 = 64;
    /// See [`FRAME_W`](Self::FRAME_W).
    pub const FRAME_H: u32 = 48;

    /// Deterministic RGBA8 demo frame at `seq`: a shifting horizontal gradient,
    /// reproducible from `seq` alone - a stand-in the path carries end to end.
    fn demo_frame(&self, seq: u64) -> Rgba8Frame {
        let (w, h) = (Self::FRAME_W, Self::FRAME_H);
        let mut pixels = Vec::with_capacity((w * h * 4) as usize);
        for y in 0..h {
            for x in 0..w {
                // A gradient that shifts with seq, so consecutive frames differ.
                let r = ((x * 255 / w) as u8).wrapping_add(seq as u8);
                let g = (y * 255 / h) as u8;
                let b = 0x80u8;
                pixels.extend_from_slice(&[r, g, b, 0xFF]);
            }
        }
        Rgba8Frame::new(
            self.sink_generation,
            enzui_core::frame_plan::FrameSeq(seq),
            w,
            h,
            pixels,
        )
        .expect("a fixed-geometry demo frame is always valid")
    }

    /// Navigate to an HTTPS URL - should be allowed by the strict policy.
    pub fn navigate_https(&mut self) {
        let url = "https://example.com/page";
        let id = self.policy.open(RequestKind::Navigation(NavContext {
            url: PolicyUrl::new(url),
            user_initiated: true,
        }));
        let outcome = self.policy.resolve(id);
        let msg = format!("Navigate {url}: {outcome:?}");
        self.log.push(msg.clone());
        self.last_decision = Some(msg);
    }

    /// Navigate to a novel unknown scheme - must be denied by the allow-list.
    pub fn navigate_bad_scheme(&mut self) {
        let url = "weirdproto://payload/evil";
        let id = self.policy.open(RequestKind::Navigation(NavContext {
            url: PolicyUrl::new(url),
            user_initiated: true,
        }));
        let outcome = self.policy.resolve(id);
        let msg = format!("Navigate {url}: {outcome:?}");
        self.log.push(msg.clone());
        self.last_decision = Some(msg);
    }

    /// Request an unknown permission - must be denied.
    pub fn request_unknown_permission(&mut self) {
        let id = self
            .policy
            .open(RequestKind::Permission(PermissionKind::Unknown(9999)));
        let outcome = self.policy.resolve(id);
        let msg = format!("Unknown permission: {outcome:?}");
        self.log.push(msg.clone());
        self.last_decision = Some(msg);
    }

    /// Gain focus with a page focusable.
    pub fn focus_gained(&mut self) {
        let outcome = self.focus.focus_gained(true);
        let msg = format!(
            "Focus gained → {outcome:?}, key_target={:?}",
            self.focus.key_target()
        );
        self.log.push(msg.clone());
        self.last_focus_outcome = Some(msg);
    }

    /// Forward a Tab to the page (the Tab protocol).
    pub fn forward_tab(&mut self) {
        let outcome = self.focus.tab(Traversal::Next);
        let msg = format!("Tab → {outcome:?}");
        self.log.push(msg.clone());
        self.last_focus_outcome = Some(msg);
    }

    /// Page answers "Consumed" to a Tab - focus stays.
    pub fn page_consumed_tab(&mut self) {
        let generation = self.focus.generation();
        let outcome = self.focus.page_tab_reply(generation, TabReply::Consumed);
        let msg = format!("Page consumed Tab → {outcome:?}");
        self.log.push(msg.clone());
        self.last_focus_outcome = Some(msg);
    }

    /// Page answers "Exhausted" - focus leaves the widget.
    pub fn page_exhausted_tab(&mut self) {
        let generation = self.focus.generation();
        let outcome = self.focus.page_tab_reply(generation, TabReply::Exhausted);
        let msg = format!("Page exhausted Tab → {outcome:?}");
        self.log.push(msg.clone());
        self.last_focus_outcome = Some(msg);
    }

    /// Deliver a stale Tab reply (from the PREVIOUS generation) - must be
    /// discarded.
    pub fn deliver_stale_tab_reply(&mut self) {
        // Use generation 0 which is always stale after any event.
        let outcome = self
            .focus
            .page_tab_reply(Generation::FIRST, TabReply::Consumed);
        let msg = format!("Stale Tab reply (generation 0) → {outcome:?}");
        self.log.push(msg.clone());
        self.last_focus_outcome = Some(msg);
    }

    pub fn focus_lost(&mut self) {
        let outcome = self.focus.focus_lost();
        let msg = format!(
            "Focus lost → {outcome:?}, preedit={:?}",
            self.focus.preedit_owner()
        );
        self.log.push(msg.clone());
        self.last_focus_outcome = Some(msg);
    }

    /// Offer a frame at the current generation.
    pub fn offer_frame(&mut self) {
        // Hidden views request no frames: count and refuse instead of decoding
        // pixels nobody sees.
        if !self.lifecycle.frame_request().is_request() {
            self.hidden_offer_attempts += 1;
            let msg = format!(
                "Offer frame SUPPRESSED (view {:?}); hidden_offer_attempts={}",
                self.lifecycle.visibility(),
                self.hidden_offer_attempts
            );
            self.log.push(msg.clone());
            self.last_frame_verdict = Some(msg);
            return;
        }
        let seq = self.next_seq;
        self.next_seq += 1;
        let frame = self.demo_frame(seq);
        let delivery = self.sink.deliver(frame);
        self.lifecycle.acquire_buffer();
        // Dual-report consistency: diagnostics read plan and sink, which must agree.
        if let Some(ref mut plan) = self.frame_plan {
            let generation = plan.generation();
            plan.offer(FrameSeq(seq), generation);
        }
        let msg = format!(
            "Offer frame seq={seq} → {delivery:?}, sink_retained={} ({} bytes)",
            self.sink.retained_buffers(),
            self.sink.retained_bytes()
        );
        self.log.push(msg.clone());
        self.last_frame_verdict = Some(msg);
    }

    /// Present the in-flight frame (mark displayed) in the real sink.
    pub fn present_frame(&mut self) {
        let displayed_seq = self.sink.present().map(|f| f.seq().0);
        if let Some(ref mut plan) = self.frame_plan {
            plan.present();
        }
        let msg = format!(
            "Present → displayed_seq={displayed_seq:?}, sink_retained={} ({} bytes)",
            self.sink.retained_buffers(),
            self.sink.retained_bytes()
        );
        self.log.push(msg.clone());
        self.last_frame_verdict = Some(msg);
    }

    /// Offer a frame at a stale generation - must be discarded by the sink and
    /// never become the displayed frame the widget presents.
    pub fn offer_stale_frame(&mut self) {
        let seq = self.next_seq;
        self.next_seq += 1;
        // A frame carrying the FIRST generation, which is stale after a recreate.
        let (w, h) = (Self::FRAME_W, Self::FRAME_H);
        let stale = Rgba8Frame::new(
            MediaGeneration::FIRST,
            enzui_core::frame_plan::FrameSeq(seq),
            w,
            h,
            vec![0u8; (w * h * 4) as usize],
        )
        .expect("fixed-geometry stale frame is valid");
        let delivery = self.sink.deliver(stale);
        if let Some(ref mut plan) = self.frame_plan {
            plan.offer(FrameSeq(seq), Generation::FIRST);
        }
        let msg = format!("Stale frame (generation 0) seq={seq} → {delivery:?}");
        self.log.push(msg.clone());
        self.last_frame_verdict = Some(msg);
    }

    /// Recreate the view (simulate crash recovery).
    pub fn recreate_view(&mut self) {
        let was_closed = self.lifecycle.is_shut_down();
        let new_view = self.router.recreate(0);
        // The old view's generation is now stale.
        if let Some(old) = self.live_view {
            self.log.push(format!(
                "Recreated view: old generation={}, new generation={}",
                old.generation().0,
                new_view.generation().0
            ));
        }
        self.live_view = Some(new_view);
        self.discard_gpu_frame();
        // Closed-then-recreated reopens visibly; ordinary crashes preserve the
        // old hidden/visible state.
        if was_closed {
            self.lifecycle = ViewLifecycle::new();
        }

        // Generation-bound native page: focus out, drop, and rebind a replacement
        // - never dispatch into the old session under the fresh id.
        if let Some(old_native) = self.native.take() {
            match old_native.recreate(&self.router, new_view, self.native_viewport) {
                Ok(page) => {
                    self.native = Some(page);
                    self.native_error = None;
                }
                Err(error) => {
                    self.native_error = Some(format!(
                        "native page recreation for generation {} failed: {error}",
                        new_view.generation().0
                    ));
                }
            }
        }
        self.frame_plan = Some(FramePlan::new(new_view.generation()));
        // Advance the sink: crashed-generation buffers freed, displayed kept
        // against flashing; late FIRST-generation frames now discard.
        if was_closed {
            debug_assert_eq!(self.sink.retained_buffers(), 0);
            debug_assert_eq!(self.sink.generation(), self.sink_generation);
        } else {
            self.sink_generation = self.sink_generation.next();
            self.sink.replace_source(self.sink_generation);
        }
        // Fresh generation restarts focus and IME - first of two guards against
        // a dead page's composition outliving its view.
        self.focus = FocusHandoff::new();
        let closed = self.page_ime.close(&mut self.focus, ImeClose::Crash);
        self.last_ime_effect = None;
        self.last_ime = Some(format!("closed={closed} (crash recovery)"));
        // Teach the session the new generation: the old generation's late requests
        // now resolve to `ViewGone` and cannot authorise the recreated view.
        self.session.open_view(new_view);
        // Drop the crashed tree so nothing publishes pre-walk: first of two guards;
        // deleting this only delays unpublishing, never leaks dead controls.
        if self.page_delivery.invalidate(new_view.slot()) {
            self.log
                .push("Page a11y tree invalidated (crashed generation)".to_owned());
        }
        self.last_page_delivery = Some(format!(
            "page a11y cleared on recreate to generation {}",
            new_view.generation().0
        ));
    }

    // Page IME/cursor entry points - same `PageIme` model feature-off as the
    // native callbacks drive feature-on: one producer here, one there.

    /// The page focused a text field whose caret is at `(x, y)` in logical view
    /// pixels. `secure` marks a password field.
    pub fn page_focus_input(&mut self, x: f32, y: f32, secure: bool) {
        let Some(view) = self.live_view else {
            self.last_ime = Some("no live view: nothing to focus".to_owned());
            return;
        };
        // Real page open: focusing means clicking the field - the caret comes from
        // WebKit's own notification, never a host-announced rectangle.
        if self.native.is_some() {
            let css_y = if secure {
                crate::webview_native::PASSWORD_TOP
            } else {
                crate::webview_native::TEXT_TOP
            } + crate::webview_native::FIELD_HEIGHT / 2.0;
            self.native_click(200.0, css_y);
            return;
        }
        // Same native report shape and bridge as the wpe build: raw WebKit purpose
        // value, no second model.
        #[expect(
            clippy::cast_possible_truncation,
            reason = "demo caret coordinates, well inside i32"
        )]
        let report = NativeImeReport {
            focused: true,
            // Logical extents: device extents divided by the 2x scale would shrink
            // the caret twice under the translation-only contract.
            caret: Some((x as i32, y as i32, 1, 18)),
            purpose: if secure {
                enzui_webkit::web::ime::WEBKIT_INPUT_PURPOSE_PASSWORD
            } else {
                0
            },
        };
        let transition = self
            .page_ime
            .apply_report(&self.router, view, &mut self.focus, &report);
        let purpose = enzui_webkit::web::purpose_from_webkit(report.purpose);
        self.last_ime = Some(format!("{transition:?} ({purpose:?})"));
        self.log.push(format!(
            "page IME: focus at ({x}, {y}) purpose={purpose:?} -> {transition:?}"
        ));
    }

    /// Page composing `text`: with a real page open this round-trips as the system
    /// IME event through the one route, generation-checked.
    pub fn page_preedit(&mut self, text: &str) {
        if self.native.is_some() {
            let event = ToolkitImeEvent::Preedit(text.to_owned(), Some(0..text.len()));
            self.route_toolkit_ime(&event);
            return;
        }
        let Some(view) = self.live_view else {
            self.last_ime = Some("no live view: nothing to compose".to_owned());
            return;
        };
        let preedit = Preedit {
            content: text.to_owned(),
            selection: Some(0..text.len()),
        };
        let outcome = self
            .page_ime
            .set_preedit(&self.router, view, &mut self.focus, preedit);
        self.last_ime = Some(format!("preedit {IME_TEXT_REDACTION} -> {outcome:?}"));
    }

    /// Composition finished; `text` goes into the page - natively as iced's own
    /// `Commit` event through the one route.
    pub fn page_commit(&mut self, text: &str) {
        if self.native.is_some() {
            self.route_toolkit_ime(&ToolkitImeEvent::Commit(text.to_owned()));
            return;
        }
        let Some(view) = self.live_view else {
            self.last_ime = Some("no live view: nothing to commit".to_owned());
            return;
        };
        let outcome = self
            .page_ime
            .commit(&self.router, view, &mut self.focus, text);
        self.last_ime = Some(format!("commit {IME_TEXT_REDACTION} -> {outcome:?}"));
    }

    /// Close the page IME for `why` (focus loss, blur, hide, crash).
    pub fn page_close_ime(&mut self, why: ImeClose) {
        let was_open = self.page_ime.close(&mut self.focus, why);
        self.last_ime = Some(format!("closed={was_open} ({why:?})"));
    }

    // The real page, behind this route.

    /// Re-read the WebProcess sandbox verdict: the one sandbox-I/O place, called
    /// from messages and page-open - never from `view`.
    pub fn refresh_sandbox(&mut self) {
        self.sandbox_status = match enzui_webkit::sandbox::preflight() {
            Ok(()) => enzui_webkit::sandbox::attest_current_process().summary(),
            Err(refusal) => format!("start refused: {refusal}"),
        };
        self.sandbox_checks += 1;
    }

    /// Open a live WPE page for the current view. Feature-off stores the typed
    /// refusal and changes nothing else - the same answer `mode::resolve` gives.
    pub fn open_native(&mut self) {
        let Some(view) = self.live_view else {
            self.native_error = Some("no live view to bind a native page to".to_owned());
            return;
        };
        self.native_open_error = None;
        self.native_worker_error = None;
        // Fail closed before constructing anything native: no page in an
        // unconfined WebProcess. App-level refusal so the route can say why.
        if let Err(refusal) = enzui_webkit::sandbox::preflight() {
            let why = refusal.to_string();
            self.log.push(format!("native page refused: {why}"));
            self.native_error = Some(why);
            self.sandbox_status = format!("start refused: {refusal}");
            self.sandbox_checks += 1;
            return;
        }
        // No shared temp dir on a shipping path: the profile scratch must be a
        // 0700 per-uid exclusive directory - see `crate::webview_scratch`.
        let scratch = match crate::webview_scratch::SecureScratch::open_for_native_webview() {
            Ok(s) => s,
            Err(e) => {
                self.native = None;
                self.native_scratch = None;
                self.native_error = Some(e.clone());
                self.log.push(format!("native page refused: {e}"));
                self.refresh_sandbox();
                return;
            }
        };
        // Surface XDG refusals even when WPE construction fails: the fallback
        // stays a verified owner-only directory, with the reason logged.
        if let Some(note) = scratch.refusal_note() {
            self.log.push(note);
        }
        let scratch = std::sync::Arc::new(scratch);
        let scratch_note = scratch.path().to_owned();
        match crate::webview_native::NativePage::open(
            &self.router,
            view,
            std::sync::Arc::clone(&scratch),
            self.native_viewport,
            self.sink_generation,
        ) {
            Ok(page) => {
                self.native = Some(page);
                self.native_scratch = Some(scratch);
                self.native_error = None;
                self.native_open_error = None;
                self.native_worker_error = None;
                self.log.push(format!(
                    "native WPE page opened (real WebSession bound, profile \
                         scratch {})",
                    // Name the 0700 per-uid profile leaf: the security property is
                    // otherwise invisible, and close must remove it.
                    scratch_note.display()
                ));
                // Never focus/click here: only the widget's real FocusGained/press path
                // may activate native ownership; opening never pumps or snapshots.
                self.refresh_sandbox();
            }
            Err(e) => {
                self.native = None;
                // Unwound constructor state: drop the scratch rather than retaining an
                // owner for a never-opened page.
                self.native_scratch = None;
                self.native_error = Some(e.to_string());
                self.native_open_error = Some(e.clone());
                self.log.push(format!("native page refused: {e}"));
                self.refresh_sandbox();
            }
        }
    }

    /// Forward a measured viewport to the matching native page: retained pre-open,
    /// refused-stale at both queue boundaries, committed only on success.
    pub fn resize_native(&mut self, view: ViewId, size: enzui_webkit::ViewportSize) {
        if self.live_view != Some(view) || !self.router.accepts(view) {
            self.log.push(format!(
                "stale native viewport refused: slot {}/gen {}",
                view.slot(),
                view.generation().0
            ));
            return;
        }
        if self.native_viewport == Some(size) {
            return;
        }
        let Some(page) = &self.native else {
            // Retain-before-open: no worker yet, so caching drops nothing;
            // `open_native`/`recreate` hand it back before first load.
            self.native_viewport = Some(size);
            return;
        };
        match page.resize(&self.router, view, size) {
            Ok(()) => {
                self.native_viewport = Some(size);
            }
            Err(error) => {
                self.native_error = Some(error.clone());
                self.log
                    .push(format!("native viewport not queued: {error}"));
            }
        }
    }

    pub(crate) fn apply_native_metadata(
        &mut self,
        metadata: std::sync::Arc<crate::webview_native::NativeMetadata>,
    ) -> bool {
        if self
            .native_metadata
            .as_ref()
            .is_some_and(|current| std::sync::Arc::ptr_eq(current, &metadata))
        {
            return false;
        }
        self.page_cursor = metadata.cursor.clone();
        self.page_ime.set_cursor(self.page_cursor.as_deref());
        self.dom_report = metadata.dom_report.clone();
        self.location = metadata.location.clone();
        self.native_metadata = Some(metadata);
        true
    }

    /// Apply coalesced native updates and return any requested host traversal.
    pub fn ingest_native(&mut self) -> Option<enzui_core::focus::Traversal> {
        let view = self.live_view?;
        let Some(page) = &self.native else {
            return None;
        };
        let updates = page.take_updates();
        let first_publication = self.native_ticks == 0 && !updates.is_empty();
        let mut traversal = None;
        for update in updates {
            self.native_ticks += 1;
            if update.view != view || !self.router.accepts(update.view) {
                self.log.push(format!(
                    "stale native notification refused: {:?}",
                    update.view
                ));
                continue;
            }
            let mut visual_changed = false;
            if let Some(error) = update.error {
                visual_changed = true;
                self.native_error = Some(error.to_string());
                self.native_worker_error = Some(error.clone());
                self.log.push(format!("native worker failed: {error}"));
            }
            if let Some(report) = update.report {
                let transition =
                    self.page_ime
                        .apply_report(&self.router, view, &mut self.focus, &report);
                if transition != ImeTransition::Unchanged {
                    visual_changed = true;
                    self.last_ime = Some(format!("{transition:?} (real WPE report)"));
                    self.log
                        .push(format!("native IME report -> {transition:?}"));
                }
            }
            if let Some(outcome) = update.clipboard {
                visual_changed = true;
                self.log.push(format!("native clipboard -> {outcome:?}"));
                self.last_clipboard = Some(outcome);
            }
            if let Some(metadata) = update.metadata {
                visual_changed |= self.apply_native_metadata(metadata);
            }
            visual_changed |= self.native_view_focused != update.view_focused;
            self.native_view_focused = update.view_focused;
            if let Some((query, reply)) = update.tab_reply {
                visual_changed = true;
                let outcome = self.focus.page_tab_reply(query, reply);
                self.last_focus_outcome = Some(format!("DOM Tab {reply:?} -> {outcome:?}"));
                if let HandoffOutcome::LeavesWidget { direction } = outcome {
                    // Only a live view + live query may blur native WPE; the worker only
                    // reports - blurring there let stale replies unfocus a focused widget.
                    if let Some(page) = &self.native {
                        page.focus_out(view);
                    }
                    traversal = Some(direction);
                }
            }
            if let Some(frame) = update.gpu_frame
                && self.is_visible()
                && frame.view() == view
            {
                if crate::webview_native::live_gpu_source_enabled() {
                    visual_changed |= self.gpu_source.is_none()
                        || self
                            .gpu_frame
                            .as_ref()
                            .is_none_or(|old| old.size() != frame.size());
                    let source = self
                        .gpu_source
                        .get_or_insert_with(|| enzui_webview::gpu::GpuFrameSource::new(view));
                    if !source.publish(&frame, &self.router) {
                        visual_changed = true;
                    }
                } else {
                    self.detach_gpu_source();
                    visual_changed = true;
                }
                if let Some(previous) = self.gpu_frame.replace(frame) {
                    previous.discard();
                }
            }
            if let Some(frame) = update.frame {
                visual_changed = true;
                self.discard_gpu_frame();
                match frame {
                    Ok(frame) => {
                        let seq = frame.seq().0;
                        match self.sink.deliver(frame) {
                            Delivery::Retained | Delivery::RetainedFreeingOlder { .. } => {
                                self.lifecycle.acquire_buffer();
                                if let Some(ref mut plan) = self.frame_plan {
                                    plan.present();
                                }
                                let _ = self.sink.present();
                                self.log
                                    .push(format!("native snapshot seq={seq} presented"));
                            }
                            other => self
                                .log
                                .push(format!("native snapshot seq={seq} refused: {other:?}")),
                        }
                    }
                    Err(error) => {
                        self.native_error = Some(error.clone());
                        self.native_worker_error =
                            Some(crate::webview_native::NativeWorkerError::Command {
                                operation: "snapshot",
                                detail: error.clone(),
                            });
                        self.log.push(format!("native snapshot failed: {error}"));
                    }
                }
            }
            if visual_changed {
                self.native_visual_revision = self.native_visual_revision.wrapping_add(1);
            }
        }
        if first_publication {
            self.refresh_sandbox();
        }
        traversal.map(convert::core_traversal)
    }

    pub(crate) fn detach_gpu_source(&mut self) {
        if let Some(source) = self.gpu_source.take() {
            source.clear();
        }
    }

    fn discard_gpu_frame(&mut self) {
        if let Some(frame) = self.gpu_frame.take() {
            frame.discard();
        }
        self.detach_gpu_source();
    }

    pub(crate) fn discard_refused_gpu_frame(&mut self) -> bool {
        if self.gpu_frame.as_ref().is_some_and(|frame| {
            matches!(frame.status(), enzui_webview::gpu::GpuStatus::Refused(_))
        }) {
            self.discard_gpu_frame();
            true
        } else {
            false
        }
    }

    /// Click into the real page at CSS `(x, y)` so the DOM focuses a field.
    pub fn native_click(&mut self, x: f32, y: f32) {
        self.log
            .push(format!("native click requested at CSS ({x}, {y})"));
        let Some(view) = self.live_view else { return };
        if let Some(page) = &self.native {
            page.click(&self.router, view, x, y);
            self.log.push(format!(
                "native click at CSS ({x}, {y}) queued on WPE worker"
            ));
        } else {
            self.last_ime = Some("no native page: click has nowhere to go".to_owned());
        }
    }

    /// Copy the real page's selection to the HOST clipboard. The reaching
    /// button IS the host gesture, so nothing page-driven can ride this path.
    pub fn native_copy(&mut self) {
        let Some(view) = self.live_view else {
            self.last_clipboard = None;
            self.log
                .push("no live view: clipboard copy has nothing to copy from".to_owned());
            return;
        };
        match &self.native {
            Some(page) => {
                if let Err(e) =
                    page.copy_to_host(&self.router, view, enzui_webkit::HostGesture::Present)
                {
                    self.log.push(format!("clipboard copy not queued: {e}"));
                }
            }
            None => self
                .log
                .push("no native page: clipboard copy has nowhere to go".to_owned()),
        }
    }

    /// Paste host text into the real page's focused DOM field.
    pub fn native_paste(&mut self, text: &str) {
        let Some(view) = self.live_view else {
            self.last_clipboard = None;
            self.log
                .push("no live view: clipboard paste has nowhere to land".to_owned());
            return;
        };
        match &self.native {
            Some(page) => {
                if let Err(e) = page.paste_from_host(
                    &self.router,
                    view,
                    enzui_webkit::HostGesture::Present,
                    text,
                ) {
                    self.log.push(format!("clipboard paste not queued: {e}"));
                }
            }
            None => self
                .log
                .push("no native page: clipboard paste has nowhere to go".to_owned()),
        }
    }

    /// Move the pointer inside the real page, which is what makes it request a
    /// cursor shape.
    pub fn native_hover(&mut self, x: f32, y: f32) {
        let Some(view) = self.live_view else { return };
        if let Some(page) = &self.native {
            page.hover(view, x, y);
        }
    }

    /// App-facing IME route: the bridge generation-checks the event's meaning,
    /// the app performs it - recorded, never simulated, when feature-off.
    pub fn route_toolkit_ime(&mut self, event: &ToolkitImeEvent) {
        let Some(view) = self.live_view else {
            self.last_ime = Some("no live view: the window's IME event is refused".to_owned());
            self.last_ime_effect = Some(ImeEffect::Ignored);
            return;
        };
        let effect = self.page_ime.route_event(&self.router, view, event);
        // Non-`Ignored` only: ignored events are refusals and must not reach WebKit.
        if !matches!(effect, ImeEffect::Ignored) {
            self.last_effect_result = Some(match &self.native {
                Some(page) => match page.apply(&self.router, view, &effect) {
                    Ok(()) => "queued on the native worker".to_owned(),
                    Err(e) => format!("REFUSED by the session: {e}"),
                },
                None => match &self.native_error {
                    Some(e) => format!("not performed ({e})"),
                    None => "not performed (no native page opened)".to_owned(),
                },
            });
        }
        self.page_ime.settle(&mut self.focus, &effect);
        self.last_ime = Some(match &effect {
            ImeEffect::Ignored => format!(
                "{:?} refused (page owns no IME)",
                diagnostic_ime_event(event)
            ),
            other => format!("{:?} -> {other:?}", diagnostic_ime_event(event)),
        });
        self.last_ime_effect = Some(effect);
    }

    /// Stale caret claim from a superseded generation: refused, IME stays shut.
    pub fn page_stale_ime_claim(&mut self) {
        let Some(live) = self.live_view else {
            return;
        };
        // FIRST generation of the slot: what an in-flight crashed-process caret
        // callback carries.
        let stale = ViewId::new(live.slot());
        if stale.generation() == live.generation() {
            self.last_ime =
                Some("no superseded generation yet — recreate the view first".to_owned());
            return;
        }
        let caret = CaretRect::new(9999.0, 9999.0, 2.0, 36.0).expect("finite");
        let outcome =
            self.page_ime
                .claim(&self.router, stale, PageInput::new(caret, Purpose::Normal));
        self.last_ime = Some(format!(
            "STALE claim (generation {}) -> {outcome:?}",
            stale.generation().0
        ));
        self.log.push(format!(
            "page IME: stale claim from generation {} -> {outcome:?}",
            stale.generation().0
        ));
    }

    /// Router-checked IME witness for the widget; `None` when nothing may
    /// publish (closed, stale, foreign, no live view).
    #[must_use]
    pub fn published_ime(&self) -> Option<PublishedIme> {
        self.page_ime.published(&self.router, self.live_view?)
    }

    /// The page requested `name` as its cursor (`None` clears it).
    pub fn set_page_cursor(&mut self, name: Option<&str>) {
        self.page_cursor = name.map(str::to_owned);
    }

    // Live page-a11y delivery and routed AT actions: the engine hands results
    // tagged by producing view; one entry accepts, one performs.

    /// Page tree for the live view, or `None`: read through the delivery's
    /// router-against generation check, so superseded snapshots never publish.
    #[must_use]
    pub fn page_a11y(&self) -> Option<&PageA11y> {
        self.page_delivery.published(&self.router, self.live_view?)
    }

    /// Router-checked snapshot as the unforgeable `PublishedPage` witness - the
    /// only tree shape the widget accepts, so no bypass is publishable.
    #[must_use]
    pub fn published_page(&self) -> Option<PublishedPage> {
        self.page_delivery
            .published_page(&self.router, self.live_view?)
    }

    /// Freshly walked page tree for `view` - the generation the walk started on,
    /// possibly no longer live by finish: the whole point.
    pub fn deliver_page_a11y(&mut self, view: ViewId) {
        let page = PageA11y::from_source(&demo_page());
        let outcome = self.page_delivery.offer(&self.router, view, page);
        let msg = match &outcome {
            PageDelivery::Accepted { view, nodes } => format!(
                "page a11y accepted: {nodes} nodes for generation {}",
                view.generation().0
            ),
            PageDelivery::RejectedStale { offered, live } => format!(
                "page a11y REJECTED stale: offered generation {}, live {}",
                offered.0, live.0
            ),
            PageDelivery::RejectedNoLiveView { slot } => {
                format!("page a11y REJECTED: slot {slot} has no live view")
            }
        };
        self.log.push(msg.clone());
        self.last_page_delivery = Some(msg);
    }

    /// Previous-generation tree arriving post-recreate: the stale-delivery button
    /// reproduces the real outliving-walk race, not just a unit assertion.
    pub fn deliver_stale_page_a11y(&mut self) {
        let Some(live) = self.live_view else {
            self.last_page_delivery = Some("no live view".to_owned());
            return;
        };
        // One generation behind live: what a crashed-process in-flight walk carries.
        let stale = ViewId::new(live.slot());
        if stale.generation() == live.generation() {
            // No older generation to forge: say so instead of delivering a LIVE tree
            // mislabelled stale.
            self.last_page_delivery =
                Some("no superseded generation yet — recreate the view first".to_owned());
            return;
        }
        self.deliver_page_a11y(stale);
    }

    /// Routed AT action on the node `key`: live-tree lookup, performed on its own
    /// action and address - recorded feature-off, real `DoAction` feature-on.
    pub fn activate_page_node(&mut self, key: &PageNodeKey) {
        let Some(live) = self.live_view else {
            self.last_page_action = Some("no live view".to_owned());
            return;
        };
        // Dispatch through the port - the trait the native session implements -
        // not a direct log format. Only `Dispatched` yields an activated line.
        let mut port = RoutedActionPort;
        let outcome = port.dispatch_page_action(&self.router, live, &self.page_delivery, key);
        let msg = match outcome {
            PageActionDispatchOutcome::Dispatched { view, key } => {
                // Log detail from the same delivery the port authorized against.
                match self.page_delivery.route_action(&self.router, view, &key) {
                    PageActionRoute::Routed { view, target } => format!(
                        "activated {key}: {}#{} on {} (generation {})",
                        target.action().name(),
                        target.action().index(),
                        target.address().path,
                        view.generation().0
                    ),
                    _ => format!("activated {key} (generation {})", view.generation().0),
                }
            }
            PageActionDispatchOutcome::Refused { reason } => reason,
        };
        self.log.push(msg.clone());
        self.last_page_action = Some(msg);
    }

    /// Demo-button activation at positional `path`: resolves to the stable key
    /// first, so even the demo routes on identity, not tree index.
    pub fn activate_page_node_at_path(&mut self, path: &str) {
        // Published-vs-position are distinct facts; post-crash the first fails
        // first. Reporting them apart keeps gone-page distinct from bad-position.
        let (published, key) = match self.page_a11y() {
            Some(page) => (true, page.key_at_path(path)),
            None => (false, None),
        };
        match key {
            Some(key) => self.activate_page_node(&key),
            None => {
                let msg = if published {
                    format!("{path}: no such node in the live page")
                } else {
                    format!("{path}: no page published; nothing activated")
                };
                self.log.push(msg.clone());
                self.last_page_action = Some(msg);
            }
        }
    }

    /// Production activation for a runtime-resolved widget `id` - page controls have
    /// no tree element, so only the recipe owner names the node; foreign ids return `false`.
    pub fn activate_published_node(&mut self, id: &iced::advanced::widget::Id) -> bool {
        let Some(live) = self.live_view else {
            return false;
        };
        // Resolve against the *published* tree (router-checked), then drop the
        // borrow before mutating the log.
        let key = match self.page_a11y() {
            Some(page) => enzui_webview::page_node_key_for_id(page, live, id),
            None => None,
        };
        match key {
            Some(key) => {
                self.activate_page_node(&key);
                true
            }
            None => false,
        }
    }

    // Engine/protocol flows from the route: canned engine raises `PolicyRequest`,
    // the app answers `ResolvePolicy`; decisions go through the session.

    /// Camera request on the live view, resolved through the session and answered
    /// `ResolvePolicy`: granted-Camera allows - the positive engine-path control.
    pub fn engine_request_camera_live(&mut self) {
        let Some(view) = self.live_view else {
            self.last_engine_outcome = Some("Engine camera request: no live view".to_owned());
            return;
        };
        // (1) App opens the engine's would-be request, minting the view-scoped
        // correlation id.
        let id = self
            .session
            .open(view, RequestKind::Permission(PermissionKind::Camera));
        // (2) The canned engine event that carries that request back to the app.
        let event = EngineEvent::PolicyRequest {
            request: id,
            kind: RequestKind::Permission(PermissionKind::Camera),
        };
        self.log.push(format!("← Engine event: {event:?}"));
        // (3) The app resolves it through the session.
        let outcome = self.session.resolve(id);
        // (4) App answers with a typed command carrying the decision - only when
        // one was reached.
        self.answer_engine(id, outcome);
    }

    /// Decisive correlation case: camera requested live, view goes away
    /// mid-request - the late reply resolves `ViewGone` undecided, though granted.
    pub fn engine_request_camera_view_gone(&mut self) {
        let Some(view) = self.live_view else {
            self.last_engine_outcome = Some("Engine camera request: no live view".to_owned());
            return;
        };
        // (1) The engine raises the request on the CURRENT (soon-to-crash) view.
        let id = self
            .session
            .open(view, RequestKind::Permission(PermissionKind::Camera));
        let event = EngineEvent::PolicyRequest {
            request: id,
            kind: RequestKind::Permission(PermissionKind::Camera),
        };
        self.log
            .push(format!("← Engine event (pre-crash): {event:?}"));
        // (2) Crash-recreate: real router mint advancing the generation, updating
        // the session's live view.
        self.recreate_view();
        // (3) Dead view's late reply: superseded generation rejects as ViewGone -
        // undecided despite the granted permission.
        let outcome = self.session.resolve(id);
        self.answer_engine(id, outcome);
    }

    /// Answer a resolved engine request: `ResolvePolicy` only on a reached
    /// decision - `ViewGone`/`Unknown` authorise nothing and send nothing.
    fn answer_engine(&mut self, id: enzui_webkit::session::ViewRequestId, outcome: SessionResolve) {
        match outcome {
            SessionResolve::Decided { decision, .. } => {
                let cmd = EngineCommand::ResolvePolicy {
                    request: id,
                    decision,
                };
                let msg = format!("→ Engine command: {cmd:?}");
                self.log.push(msg.clone());
                self.last_engine_command = Some(msg);
                self.last_engine_outcome = Some(format!("Engine policy → Decided: {decision:?}"));
            }
            SessionResolve::ViewGone { .. } => {
                // The view went away: NO command is sent, NO decision leaks.
                let msg = "Engine policy → ViewGone (no decision, no command sent)".to_owned();
                self.log.push(msg.clone());
                self.last_engine_outcome = Some(msg);
            }
            SessionResolve::Unknown { .. } => {
                let msg = "Engine policy → Unknown (correlation failed)".to_owned();
                self.log.push(msg.clone());
                self.last_engine_outcome = Some(msg);
            }
        }
    }

    // Visibility, shutdown, input: the surface the route renders.

    /// Frame for the widget to present: a borrow of the sink's displayed frame
    /// (`None` if none yet) - the presentation wiring the sabotage severs.
    #[must_use]
    pub fn displayed_frame(&self) -> Option<&Rgba8Frame> {
        self.sink.displayed()
    }

    /// Whether the view is currently visible (drives whether the route presents
    /// a live surface at all).
    #[must_use]
    pub fn is_visible(&self) -> bool {
        !self.lifecycle.is_shut_down() && self.lifecycle.visibility() == ViewVisibility::Visible
    }

    /// Hide the view: it goes quiescent (requests no frames).
    pub fn hide_view(&mut self) {
        self.discard_gpu_frame();
        if let (Some(page), Some(view)) = (&self.native, self.live_view) {
            page.set_visibility(&self.router, view, false);
        }
        self.lifecycle.set_visibility(ViewVisibility::Hidden);
        if let (Some(native), Some(view)) = (&self.native, self.live_view) {
            native.focus_out(view);
        }
        self.log
            .push("View hidden — quiescent, no frame requests".to_owned());
    }

    /// Show the view: frame requests resume.
    pub fn show_view(&mut self) {
        if let (Some(page), Some(view)) = (&self.native, self.live_view) {
            page.set_visibility(&self.router, view, true);
        }
        self.lifecycle.set_visibility(ViewVisibility::Visible);
        self.log
            .push("View shown — frame requests resume".to_owned());
    }

    /// Close the view, revoking every authority: routing invalidates first, then
    /// the page drop; sink replaced wholesale to free all buffers alike.
    pub fn close_view(&mut self) {
        let closing = self.live_view.take();
        let mut dropped_policy = 0;
        let mut dropped_a11y = false;
        if let Some(view) = closing {
            let destroyed = self.router.destroy(view.slot());
            debug_assert_eq!(destroyed, Some(view));
            dropped_policy = self.session.close_view(view);
            dropped_a11y = self.page_delivery.invalidate(view.slot());
        }
        // No view wrapper at route level: replacing the policy is its invalidate
        // operation, consuming unresolved correlation ids.
        self.policy = WebPolicy::strict();

        let ime_closed = self.page_ime.close(&mut self.focus, ImeClose::Destroyed);
        self.focus = FocusHandoff::new();
        self.page_cursor = None;
        self.discard_gpu_frame();
        self.last_input = None;
        self.last_focus_outcome = None;
        self.last_ime_effect = None;
        self.last_ime = Some(format!("closed={ime_closed} (view destroyed)"));

        let released = self.lifecycle.shut_down();

        // Out-of-band stop and bounded wait live in `drop`; separate statements keep
        // the take-and-bind in-place drop (feature-off no-op read) honest.
        let _ = self.native.take();
        drop(self.native_scratch.take());
        self.native_viewport = None;
        self.native_view_focused = None;
        self.native_error = None;
        self.native_open_error = None;
        self.native_worker_error = None;
        self.native_ticks = 0;
        self.native_metadata = None;
        self.dom_report = None;
        self.last_effect_result = None;
        self.last_clipboard = None;
        self.sandbox_status = NEVER_CHECKED.to_owned();
        self.sandbox_checks = 0;

        self.frame_plan = None;
        // Only a destroyed live generation prepares the next sink generation:
        // repeated close must not move the sink ahead of the tombstone.
        if closing.is_some() {
            self.sink_generation = self.sink_generation.next();
        }
        // Wholesale replacement drops every buffer, displayed included.
        self.sink = BoundedFrameSink::new(self.sink_generation);
        let msg = format!(
            "View closed — released {released} lifecycle buffers; policy_dropped={dropped_policy}; \
             a11y_dropped={dropped_a11y}; sink_retained={}",
            self.sink.retained_buffers()
        );
        self.last_frame_verdict = Some(msg.clone());
        self.log.push(msg);
    }

    /// Forward a pointer press at window-logical `(x, y)` through the widget's
    /// scaled/clipped path, built with the rendered visibility and scale.
    pub fn forward_pointer_press(&mut self, bounds: (f32, f32, f32, f32), x: f32, y: f32) {
        use enzui_webkit::input::PointerButton;
        use enzui_webview::{PointerPhase, enz_web_view};
        let frame = self.sink.displayed();
        let wv = enz_web_view::<crate::message::Message>(
            self.effective_view(),
            frame,
            self.is_visible(),
        )
        .scale_factor(self.scale_factor);
        let ev = wv.pointer_event(bounds, x, y, PointerPhase::Pressed(PointerButton::Primary));
        let msg = match &ev {
            Some(e) => format!("Pointer press ({x},{y}) → {e:?}"),
            None => format!("Pointer press ({x},{y}) → dropped (out of bounds or hidden)"),
        };
        self.log.push(msg.clone());
        self.last_input = Some(msg);
    }

    /// Route a real-widget event to the live native page: recorded even
    /// feature-off; native dispatch needs the exact live generation.
    pub fn route_widget_input(
        &mut self,
        event: &enzui_webkit::input::InputEvent,
    ) -> Option<enzui_core::focus::Traversal> {
        let live = self.live_view;
        if live != Some(event.view()) || !self.router.accepts(event.view()) {
            self.last_input = Some(format!("stale widget input refused: {event:?}"));
            return None;
        }
        if !self.is_visible() && !event.is_terminal() {
            self.last_input = Some(format!("hidden widget input refused: {event:?}"));
            return None;
        }
        self.last_input = Some(format!("widget input → {event:?}"));

        let mut tab_query = None;
        match event {
            enzui_webkit::input::InputEvent::FocusGained { .. } => {
                let outcome = self.focus.focus_gained(true);
                self.last_focus_outcome = Some(format!("toolkit focus -> {outcome:?}"));
            }
            enzui_webkit::input::InputEvent::FocusLost { .. } => {
                let outcome = self.focus.focus_lost();
                self.last_focus_outcome = Some(format!("toolkit blur -> {outcome:?}"));
            }
            enzui_webkit::input::InputEvent::KeyPressed {
                key: enzui_webkit::input::KeyCode::Named(enzui_webkit::input::NamedKey::Tab),
                modifiers,
                ..
            } => {
                let direction = if modifiers.shift() {
                    Traversal::Previous
                } else {
                    Traversal::Next
                };
                match self.focus.tab(direction) {
                    HandoffOutcome::ForwardedToPage { query, .. } => {
                        tab_query = Some((query, direction));
                    }
                    HandoffOutcome::LeavesWidget { direction } => {
                        self.last_focus_outcome =
                            Some(format!("unanswered DOM Tab released -> {direction:?}"));
                        // Already generation-accepted locally: queue one native blur, then
                        // return the single toolkit traversal.
                        if let Some(page) = &self.native {
                            page.focus_out(event.view());
                        }
                        return Some(convert::core_traversal(direction));
                    }
                    outcome => self.last_focus_outcome = Some(format!("Tab -> {outcome:?}")),
                }
            }
            enzui_webkit::input::InputEvent::KeyPressed { .. } => {
                let _ = self.focus.key();
            }
            _ => {}
        }

        let forwarded = self
            .native
            .as_ref()
            .is_some_and(|page| page.forward_input(&self.router, event, tab_query));
        if !forwarded && self.native.is_some() {
            self.last_input = Some(format!("native binding refused widget input: {event:?}"));
        }
        None
    }

    /// Surface-renders view id: live view, else the sink's generation-bearing
    /// fallback so the input path keeps a target.
    #[must_use]
    fn effective_view(&self) -> ViewId {
        self.live_view.unwrap_or_else(|| {
            // No live view: a stable id keeps the input path targeted.
            ViewId::new(0)
        })
    }

    /// Profile isolation check: does this profile share storage with another
    /// named persistent profile?
    pub fn check_profile_isolation(&mut self) -> bool {
        let other = WebProfile::persistent("other-profile");
        let shares = self.profile.shares_storage(&other);
        self.log.push(format!(
            "Profile isolation: shared with 'other-profile'? {shares}"
        ));
        shares
    }

    /// Switch to a named persistent profile.
    #[allow(dead_code)]
    pub fn switch_to_persistent_profile(&mut self, name: &str) {
        self.profile = WebProfile::persistent(name);
        self.log
            .push(format!("Switched to persistent profile '{name}'"));
    }

    /// Switch to an ephemeral profile.
    pub fn switch_to_ephemeral(&mut self) {
        self.profile = WebProfile::ephemeral();
        self.log.push("Switched to ephemeral profile".to_owned());
    }

    /// Whether the current live view is accepted by the router.
    #[allow(dead_code)]
    pub fn live_view_accepted(&self) -> bool {
        self.live_view.is_some_and(|v| self.router.accepts(v))
    }

    /// Short state summary for display.
    pub fn status_line(&self) -> String {
        let view_status = match self.live_view {
            Some(v) => format!(
                "slot={} generation={} accepted={}",
                v.slot(),
                v.generation().0,
                self.router.accepts(v)
            ),
            None => "no live view".to_owned(),
        };
        let focus_status = format!(
            "focused={} key_target={:?} preedit={:?}",
            self.focus.is_focused(),
            self.focus.key_target(),
            self.focus.preedit_owner()
        );
        let frame_status = match &self.frame_plan {
            Some(p) => format!("retained={}", p.retained()),
            None => "no frame plan".to_owned(),
        };
        let profile_status = if self.profile.persists() {
            "persistent"
        } else {
            "ephemeral"
        };
        let backend_status = match &self.backend {
            Ok(b) => format!("{:?}", b.mode()),
            Err(e) => format!("Err({e:?})"),
        };
        // Verdict read from cache: attesting scans the process table, so per-frame
        // `view` calls would put blocking I/O on the UI thread.
        let sandbox_status = format!("{} (checks={})", self.sandbox_status, self.sandbox_checks);
        format!(
            "View: {view_status} | Focus: {focus_status} | \
             Frames: {frame_status} | Profile: {profile_status} | \
             Outstanding policy: {} | Backend(Native): {backend_status} | \
             Sandbox: {sandbox_status}",
            self.policy.outstanding_count()
        )
    }
}
