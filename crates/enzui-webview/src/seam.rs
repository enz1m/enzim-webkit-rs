//! The widget behind [`EnzWebView`](super::EnzWebView), where a page's
//! out-of-tree state (accessible nodes, caret and IME state, requested cursor)
//! enters iced.
//!

use enzui_core::collect::SemanticsNode;
use enzui_core::semantics::Semantics;
use enzui_webkit::input::{
    InputEvent, KeyCode, Modifiers, NamedKey, PointerButton, ScrollUnit, ViewPoint,
    ViewportMapping, pointer_moved_grabbed, pointer_moved_with_modifiers,
    pointer_pressed_with_modifiers, pointer_released_with_modifiers, touch_cancel,
    touch_down_with_modifiers, touch_moved_grabbed, touch_moved_with_modifiers, touch_up_grabbed,
    touch_up_with_modifiers, wheel_scrolled_at_with_modifiers,
};
use enzui_webkit::page_a11y::PageNode;
use enzui_webkit::web::ViewId;
use iced::advanced::widget::{Operation, Tree, tree};
use iced::advanced::{Layout, Shell, Widget, layout, mouse, overlay, renderer};
use iced::{Element, Event, Length, Rectangle, Size, Vector, keyboard, touch};

/// The page-owned state this seam routes into iced, already reduced to what
/// the widget layer needs.
///
/// Assembled by [`EnzWebView`](super::EnzWebView) from a generation-checked
/// witness; the seam cannot construct one from a bare caret rectangle.
#[derive(Debug, Clone, PartialEq)]
pub struct PageInputState {
    /// The caret rectangle in logical view pixels: page zoom is baked in
    /// (it changes layout) but the output/device scale is not - WebKit
    /// reports the caret from logical root-view coordinates (see
    /// `enzui_webkit::web::CaretRect` and
    /// [`ViewportMapping::to_window_rect`]). It maps to the window
    /// rectangle by translation only; `scale_factor` below does not
    /// divide it.
    pub caret: (f32, f32, f32, f32),
    /// The field's purpose, in iced's vocabulary.
    pub purpose: iced::advanced::input_method::Purpose,
    /// The active composition, if the page is composing.
    pub preedit: Option<iced::advanced::input_method::Preedit>,
    /// The device-pixel scale factor the surface renders at.
    pub scale_factor: f32,
}

/// A transparent wrapper that publishes the web-area node, the page's
/// translated accessible tree, the page's window IME state, and the page's
/// requested cursor.
pub struct WebViewSeam<'a, Message, Theme = iced::Theme, Renderer = iced::Renderer> {
    child: Element<'a, Message, Theme, Renderer>,
    area: Semantics,
    page: Option<PageNode>,
    view: ViewId,
    id: iced::advanced::widget::Id,
    ime: Option<PageInputState>,
    cursor: Option<mouse::Interaction>,
    on_input_method: Option<Box<dyn Fn(enzui_webkit::web::ToolkitImeEvent) -> Message + 'a>>,
    on_input: Option<Box<dyn Fn(InputEvent) -> Message + 'a>>,
    on_viewport_resize: Option<Box<dyn Fn(ViewId, enzui_webkit::ViewportSize) -> Message + 'a>>,
    input_visible: bool,
    resize_visible: bool,
    scale_factor: f32,
}

/// Retained keyboard-focus state for the web area.
///
/// The page is one toolkit Tab stop even though its DOM contains its own focus
/// ring. Keeping this in iced's widget tree (instead of on the rebuilt builder)
/// lets ordinary `focus_next`/`focus_previous` operations discover it.
///
/// The state also carries the implicit pointer/touch grab and the
/// modifier latch, both of which are per-widget-tree properties that
/// must survive the builder being rebuilt every frame. A grab that
/// lived on the throwaway builder would forget the pending drag on the
/// next re-render.
#[derive(Debug)]
struct WebViewState {
    view: ViewId,
    input_visible: bool,
    focused: bool,
    window_focused: bool,
    // Native window deactivation suspends ownership without transferring it to a sibling.
    resume_focus: Option<ViewId>,
    // Deferred lifecycle events produced by `diff`/focus operations. This is a
    // bounded, coalescing queue: repeated rebuilds before the next iced event
    // cannot grow memory without bound, and only the newest generation's
    // terminal cleanup is useful at the engine boundary.
    pending: Vec<InputEvent>,
    last_pointer: Option<ViewPoint>,
    /// The page last saw the pointer inside its visible area, so leaving that
    /// area, the window, or the view owes it exactly one `PointerLeft`.
    hovering: bool,
    /// Buttons currently pressed inside this widget's bounds. Their subsequent
    /// moves and release are routed even when the pointer is outside the
    /// widget - the implicit-grab contract WebKit and every DOM implementation
    /// depend on for drag interactions.
    pointer_grab: PointerGrab,
    /// Finger sequence ids currently pressed inside this widget's bounds.
    /// Bounded to a small ring; a device that opens more concurrent touches
    /// than the ring holds falls back to the ordinary clip, which is still
    /// correct (worst case: a drag continuation on the excess finger is
    /// dropped, never a phantom touch).
    touch_grab: TouchGrab,
    /// The latch iced updates via `ModifiersChanged`. Every routed event
    /// carries this value - iced does not attach modifiers to pointer or
    /// wheel events on its own.
    modifiers: Modifiers,
    /// Last emitted integer logical viewport for this generation. Stored in
    /// retained widget state so rebuilt builders do not duplicate traffic.
    last_viewport_size: Option<enzui_webkit::ViewportSize>,
}

impl WebViewState {
    fn new(view: ViewId, input_visible: bool) -> Self {
        Self {
            view,
            input_visible,
            focused: false,
            window_focused: true,
            resume_focus: None,
            pending: Vec::new(),
            last_pointer: None,
            hovering: false,
            pointer_grab: PointerGrab::default(),
            touch_grab: TouchGrab::default(),
            modifiers: Modifiers::NONE,
            last_viewport_size: None,
        }
    }

    fn terminal_events(&mut self) -> Vec<InputEvent> {
        self.resume_focus = None;
        let mut events = Vec::new();
        let at = self.last_pointer.unwrap_or(ViewPoint { x: 0.0, y: 0.0 });
        while let Some(button) = self.pointer_grab.pop() {
            events.push(InputEvent::PointerReleased {
                view: self.view,
                at,
                button,
                modifiers: self.modifiers | self.pointer_grab.modifiers(),
            });
        }
        for seq in self.touch_grab.take_all() {
            events.push(touch_cancel(self.view, seq, self.modifiers));
        }
        if self.focused {
            self.focused = false;
            events.push(InputEvent::FocusLost {
                view: self.view,
                modifiers: self.modifiers,
            });
        }
        events
    }

    fn leave(&mut self) -> Option<InputEvent> {
        std::mem::take(&mut self.hovering).then_some(InputEvent::PointerLeft {
            view: self.view,
            modifiers: self.modifiers,
        })
    }

    fn queue_terminal(&mut self, events: Vec<InputEvent>) {
        const MAX_PENDING_LIFECYCLE: usize = 17; // 5 buttons + 10 fingers + focus + leave
        for event in events {
            if self.pending.iter().any(|queued| queued == &event) {
                continue;
            }
            if self.pending.len() == MAX_PENDING_LIFECYCLE {
                // Preserve the newest lifecycle boundary. Older entries name a
                // session that has already been superseded and will be refused
                // by `WebSession::forward_input` in any event.
                self.pending.remove(0);
            }
            self.pending.push(event);
        }
    }

    fn reset_for(&mut self, view: ViewId, input_visible: bool) {
        if self.view != view {
            // Nothing queued for an older generation may be replayed after a
            // second recreate. Coalesce the backlog to the one generation being
            // terminally closed.
            self.pending.clear();
            let mut terminal = self.terminal_events();
            terminal.extend(self.leave());
            self.queue_terminal(terminal);
            self.modifiers = Modifiers::NONE;
            self.last_pointer = None;
            // The same dimensions belong to a different native page now and
            // must cross the generation-safe session boundary again.
            self.last_viewport_size = None;
        } else if self.input_visible && !input_visible {
            let mut terminal = self.terminal_events();
            terminal.extend(self.leave());
            self.queue_terminal(terminal);
        }
        self.view = view;
        self.input_visible = input_visible;
    }
}

/// The buttons currently grabbed by an in-bounds press.
///
/// Stored as a small fixed-capacity array rather than a `Vec` so the state has
/// no heap footprint and so allocation cannot fail while a drag is in flight.
/// Five slots cover WPE's complete button-state vocabulary: primary, middle,
/// secondary, back, and forward. An additional unknown button is refused at
/// down rather than creating a sequence whose terminal release cannot be kept.
#[derive(Debug, Default, Clone, Copy)]
struct PointerGrab {
    slots: [Option<PointerButton>; 5],
}

impl PointerGrab {
    fn contains(&self, button: PointerButton) -> bool {
        self.slots.iter().any(|s| s == &Some(button))
    }

    fn insert(&mut self, button: PointerButton) -> bool {
        if self.contains(button) {
            return true;
        }
        if let Some(slot) = self.slots.iter_mut().find(|s| s.is_none()) {
            *slot = Some(button);
            true
        } else {
            false
        }
    }

    fn remove(&mut self, button: PointerButton) -> bool {
        let mut removed = false;
        for slot in &mut self.slots {
            if *slot == Some(button) {
                *slot = None;
                removed = true;
            }
        }
        removed
    }

    fn any(&self) -> bool {
        self.slots.iter().any(|s| s.is_some())
    }

    fn modifiers(&self) -> Modifiers {
        self.slots
            .iter()
            .flatten()
            .fold(Modifiers::NONE, |mods, button| {
                mods | match button {
                    PointerButton::Primary => Modifiers::BUTTON1,
                    PointerButton::Middle => Modifiers::BUTTON2,
                    PointerButton::Secondary => Modifiers::BUTTON3,
                    PointerButton::Other(4) => Modifiers::BUTTON4,
                    PointerButton::Other(5) => Modifiers::BUTTON5,
                    PointerButton::Other(_) => Modifiers::NONE,
                }
            })
    }

    fn pop(&mut self) -> Option<PointerButton> {
        let slot = self.slots.iter_mut().find(|slot| slot.is_some())?;
        slot.take()
    }
}

/// Finger sequence ids currently held by an in-bounds touch press.
///
/// Same rationale as [`PointerGrab`]: a fixed-capacity array so a drag
/// state cannot fail to allocate. Ten covers a two-hand gesture. An eleventh
/// down is refused instead of creating a touch that cannot later be ended.
#[derive(Debug, Default, Clone, Copy)]
struct TouchGrab {
    slots: [Option<u32>; 10],
}

impl TouchGrab {
    fn contains(&self, seq: u32) -> bool {
        self.slots.iter().any(|s| s == &Some(seq))
    }

    fn insert(&mut self, seq: u32) -> bool {
        if self.contains(seq) {
            return true;
        }
        if let Some(slot) = self.slots.iter_mut().find(|s| s.is_none()) {
            *slot = Some(seq);
            true
        } else {
            false
        }
    }

    fn remove(&mut self, seq: u32) -> bool {
        let mut removed = false;
        for slot in &mut self.slots {
            if *slot == Some(seq) {
                *slot = None;
                removed = true;
            }
        }
        removed
    }

    fn take_all(&mut self) -> Vec<u32> {
        self.slots.iter_mut().filter_map(Option::take).collect()
    }
}

impl iced::advanced::widget::operation::Focusable for WebViewState {
    fn is_focused(&self) -> bool {
        self.focused || self.resume_focus == Some(self.view)
    }

    fn focus(&mut self) {
        if self.input_visible && !self.is_focused() {
            if !self.window_focused {
                self.resume_focus = Some(self.view);
                return;
            }
            self.focused = true;
            self.pending.push(InputEvent::FocusGained {
                view: self.view,
                modifiers: self.modifiers,
            });
        }
    }

    fn unfocus(&mut self) {
        let terminal = self.terminal_events();
        self.pending.extend(terminal);
    }
}

impl<'a, Message, Theme, Renderer> WebViewSeam<'a, Message, Theme, Renderer> {
    /// Wrap `child`, publishing `area` as the web area's node and `page` (when
    /// present) as its accessible descendants.
    pub fn new(
        child: impl Into<Element<'a, Message, Theme, Renderer>>,
        area: Semantics,
        page: Option<PageNode>,
        view: ViewId,
    ) -> Self {
        Self {
            child: child.into(),
            area,
            page,
            view,
            id: iced::advanced::widget::Id::from(format!("enz-web-view-{}", view.slot())),
            ime: None,
            cursor: None,
            on_input_method: None,
            on_input: None,
            on_viewport_resize: None,
            input_visible: false,
            resize_visible: false,
            scale_factor: 1.0,
        }
    }

    /// Publish `state` to the window input method while the caret is visible.
    #[must_use]
    pub fn input_method(mut self, state: Option<PageInputState>) -> Self {
        self.ime = state;
        self
    }

    /// Override the host cursor with the page's requested one while the pointer
    /// is inside the visible widget.
    #[must_use]
    pub fn page_cursor(mut self, cursor: Option<mouse::Interaction>) -> Self {
        self.cursor = cursor;
        self
    }

    /// Route the window's IME events (`Opened`/`Preedit`/`Commit`/`Closed`) to
    /// the application, which forwards them to the engine.
    ///
    /// Routing is gated on the page actually owning the window input method
    /// this pass (a live claim whose caret is not clipped away); see
    /// [`Widget::update`].
    #[must_use]
    pub fn on_input_method(
        mut self,
        f: impl Fn(enzui_webkit::web::ToolkitImeEvent) -> Message + 'a,
    ) -> Self {
        self.on_input_method = Some(Box::new(f));
        self
    }

    /// Route iced input through this widget's real bounds and retained focus.
    #[must_use]
    pub fn on_input(
        mut self,
        scale_factor: f32,
        visible: bool,
        f: impl Fn(InputEvent) -> Message + 'a,
    ) -> Self {
        self.scale_factor = scale_factor;
        self.input_visible = visible;
        self.on_input = Some(Box::new(f));
        self
    }

    /// Publish a generation-tagged viewport size on redraw only when its
    /// checked integer logical dimensions changed.
    #[must_use]
    pub fn on_viewport_resize(
        mut self,
        visible: bool,
        f: impl Fn(ViewId, enzui_webkit::ViewportSize) -> Message + 'a,
    ) -> Self {
        self.resize_visible = visible;
        self.on_viewport_resize = Some(Box::new(f));
        self
    }
}

impl<Message, Theme, Renderer> WebViewSeam<'_, Message, Theme, Renderer> {
    /// Ask iced's window input method for `rect` with this page's purpose and
    /// composition. One place, so the captured-event path and the ordinary path
    /// cannot drift apart.
    fn request_ime(&self, shell: &mut Shell<'_, Message>, rect: Rectangle) {
        let Some(state) = &self.ime else { return };
        shell.request_input_method(&iced::advanced::input_method::InputMethod::Enabled {
            cursor: rect,
            purpose: state.purpose,
            preedit: state.preedit.clone(),
        });
    }
}

/// The window-logical IME rectangle for a page caret laid out at `bounds` and
/// clipped by `viewport`, or `None` when nothing may be published.
///
/// Exposed so the widget tests can assert the mapping and the
/// clip against real bounds rather than through a rendered frame.
pub fn window_ime_rect(
    state: &PageInputState,
    bounds: Rectangle,
    viewport: Rectangle,
) -> Option<Rectangle> {
    // The visible part of the widget: a scrolled container's viewport can cover
    // only a slice of it, and a caret in the hidden slice must not be published.
    let visible = bounds.intersection(&viewport)?;
    if visible.width <= 0.0 || visible.height <= 0.0 {
        return None;
    }
    // The mapping is built from the WHOLE widget bounds, because that is the
    // rectangle the page surface occupies; the clip is applied afterwards.
    let mapping = ViewportMapping::new(
        bounds.x,
        bounds.y,
        bounds.width,
        bounds.height,
        state.scale_factor,
    )?;
    let (cx, cy, cw, ch) = state.caret;
    let (x, y, w, h) = mapping.to_window_rect(cx, cy, cw, ch)?;
    let caret = Rectangle {
        x,
        y,
        width: w,
        height: h,
    };
    // Clip to the VISIBLE slice, not to the full bounds: a caret scrolled out
    // of a container is off-screen even though it is inside the widget.
    let clipped = caret.intersection(&visible)?;
    if clipped.width <= 0.0 || clipped.height <= 0.0 {
        return None;
    }
    Some(clipped)
}

/// Publish one translated page node and its subtree at the current depth.
///
/// # Every page node carries a stable id, and that is load-bearing
///
/// An interactive node with no id is the repo's "anonymous actionable" defect:
/// AT can hear the control and has no handle to name it across frames, and the
/// published tree degrades it to a read-only announcement
/// ([`SemanticsCollector::anonymous_actionable`](enzui_core::collect::SemanticsCollector::anonymous_actionable)).
/// The page's buttons and fields are interactive by role, so each gets
/// an id derived from its path in the page tree under the view's slot.
///
/// The slot, not the whole [`ViewId`]: a slot survives a crash/recreate, so a
/// recovered view republishes the same identities instead of presenting AT with
/// a wholly new tree. The node's key disambiguates two controls with the same
/// label, which `duplicate_ids` would otherwise flag.
fn publish(node: &PageNode, view: ViewId, bounds: Rectangle, operation: &mut dyn Operation) {
    let has_children = !node.children().is_empty();
    let mut published = if has_children {
        SemanticsNode::group(super::convert::semantics(node.semantics()))
    } else {
        SemanticsNode::new(super::convert::semantics(node.semantics()))
    };
    // The key comes from the node itself rather than being
    // recomputed while descending. The tree that is published and the tree an
    // action is resolved against are then indexed by the *same* keys, so a
    // routed action cannot land on a different node than the one AT was shown --
    // and because the key is the node's AT-SPI address rather than its
    // position, that stays true across DOM insertion and reorder.
    let id = super::page_node_id(view, node.key());
    operation.custom(Some(&id), bounds, &mut published);
    if !has_children {
        return;
    }
    operation.container(Some(&id), bounds, &bounds);
    operation.traverse(&mut |operation| {
        for child in node.children() {
            publish(child, view, bounds, operation);
        }
    });
}

fn pointer_button(button: mouse::Button) -> PointerButton {
    match button {
        mouse::Button::Left => PointerButton::Primary,
        mouse::Button::Right => PointerButton::Secondary,
        mouse::Button::Middle => PointerButton::Middle,
        mouse::Button::Back => PointerButton::Other(4),
        mouse::Button::Forward => PointerButton::Other(5),
        mouse::Button::Other(code) => PointerButton::Other(code),
    }
}

pub(super) const NAMED_KEY_MAP: &[(keyboard::key::Named, NamedKey)] = &[
    (keyboard::key::Named::Alt, NamedKey::Alt),
    (keyboard::key::Named::AltGraph, NamedKey::AltGraph),
    (keyboard::key::Named::CapsLock, NamedKey::CapsLock),
    (keyboard::key::Named::Control, NamedKey::Control),
    (keyboard::key::Named::NumLock, NamedKey::NumLock),
    (keyboard::key::Named::ScrollLock, NamedKey::ScrollLock),
    (keyboard::key::Named::Shift, NamedKey::Shift),
    (keyboard::key::Named::Meta, NamedKey::Meta),
    (keyboard::key::Named::Super, NamedKey::Super),
    (keyboard::key::Named::Enter, NamedKey::Enter),
    (keyboard::key::Named::Tab, NamedKey::Tab),
    (keyboard::key::Named::Backspace, NamedKey::Backspace),
    (keyboard::key::Named::Escape, NamedKey::Escape),
    (keyboard::key::Named::Space, NamedKey::Space),
    (keyboard::key::Named::ArrowUp, NamedKey::ArrowUp),
    (keyboard::key::Named::ArrowDown, NamedKey::ArrowDown),
    (keyboard::key::Named::ArrowLeft, NamedKey::ArrowLeft),
    (keyboard::key::Named::ArrowRight, NamedKey::ArrowRight),
    (keyboard::key::Named::Home, NamedKey::Home),
    (keyboard::key::Named::End, NamedKey::End),
    (keyboard::key::Named::PageUp, NamedKey::PageUp),
    (keyboard::key::Named::PageDown, NamedKey::PageDown),
    (keyboard::key::Named::Delete, NamedKey::Delete),
    (keyboard::key::Named::Insert, NamedKey::Insert),
    (keyboard::key::Named::ContextMenu, NamedKey::ContextMenu),
    (keyboard::key::Named::Cut, NamedKey::Cut),
    (keyboard::key::Named::Copy, NamedKey::Copy),
    (keyboard::key::Named::Paste, NamedKey::Paste),
    (keyboard::key::Named::Undo, NamedKey::Undo),
    (keyboard::key::Named::Redo, NamedKey::Redo),
    (keyboard::key::Named::Clear, NamedKey::Clear),
    (keyboard::key::Named::Accept, NamedKey::Accept),
    (keyboard::key::Named::Again, NamedKey::Again),
    (keyboard::key::Named::Cancel, NamedKey::Cancel),
    (keyboard::key::Named::Execute, NamedKey::Execute),
    (keyboard::key::Named::Find, NamedKey::Find),
    (keyboard::key::Named::Help, NamedKey::Help),
    (keyboard::key::Named::Pause, NamedKey::Pause),
    (keyboard::key::Named::Select, NamedKey::Select),
    (keyboard::key::Named::PrintScreen, NamedKey::PrintScreen),
    (keyboard::key::Named::BrowserBack, NamedKey::BrowserBack),
    (
        keyboard::key::Named::BrowserForward,
        NamedKey::BrowserForward,
    ),
    (
        keyboard::key::Named::BrowserRefresh,
        NamedKey::BrowserRefresh,
    ),
    (keyboard::key::Named::BrowserStop, NamedKey::BrowserStop),
    (keyboard::key::Named::BrowserSearch, NamedKey::BrowserSearch),
    (
        keyboard::key::Named::BrowserFavorites,
        NamedKey::BrowserFavorites,
    ),
    (keyboard::key::Named::BrowserHome, NamedKey::BrowserHome),
    (keyboard::key::Named::ZoomIn, NamedKey::ZoomIn),
    (keyboard::key::Named::ZoomOut, NamedKey::ZoomOut),
    (keyboard::key::Named::F1, NamedKey::F1),
    (keyboard::key::Named::F2, NamedKey::F2),
    (keyboard::key::Named::F3, NamedKey::F3),
    (keyboard::key::Named::F4, NamedKey::F4),
    (keyboard::key::Named::F5, NamedKey::F5),
    (keyboard::key::Named::F6, NamedKey::F6),
    (keyboard::key::Named::F7, NamedKey::F7),
    (keyboard::key::Named::F8, NamedKey::F8),
    (keyboard::key::Named::F9, NamedKey::F9),
    (keyboard::key::Named::F10, NamedKey::F10),
    (keyboard::key::Named::F11, NamedKey::F11),
    (keyboard::key::Named::F12, NamedKey::F12),
    (keyboard::key::Named::F13, NamedKey::F13),
    (keyboard::key::Named::F14, NamedKey::F14),
    (keyboard::key::Named::F15, NamedKey::F15),
    (keyboard::key::Named::F16, NamedKey::F16),
    (keyboard::key::Named::F17, NamedKey::F17),
    (keyboard::key::Named::F18, NamedKey::F18),
    (keyboard::key::Named::F19, NamedKey::F19),
    (keyboard::key::Named::F20, NamedKey::F20),
    (keyboard::key::Named::F21, NamedKey::F21),
    (keyboard::key::Named::F22, NamedKey::F22),
    (keyboard::key::Named::F23, NamedKey::F23),
    (keyboard::key::Named::F24, NamedKey::F24),
    (keyboard::key::Named::F25, NamedKey::F25),
    (keyboard::key::Named::F26, NamedKey::F26),
    (keyboard::key::Named::F27, NamedKey::F27),
    (keyboard::key::Named::F28, NamedKey::F28),
    (keyboard::key::Named::F29, NamedKey::F29),
    (keyboard::key::Named::F30, NamedKey::F30),
    (keyboard::key::Named::F31, NamedKey::F31),
    (keyboard::key::Named::F32, NamedKey::F32),
    (keyboard::key::Named::F33, NamedKey::F33),
    (keyboard::key::Named::F34, NamedKey::F34),
    (keyboard::key::Named::F35, NamedKey::F35),
];

pub(super) fn key_code(key: &keyboard::Key) -> Option<KeyCode> {
    match key {
        keyboard::Key::Character(text) => Some(KeyCode::Character(text.to_string())),
        keyboard::Key::Named(named) => NAMED_KEY_MAP
            .iter()
            .find_map(|(iced, protocol)| (*iced == *named).then_some(KeyCode::Named(*protocol))),
        keyboard::Key::Unidentified => None,
    }
}

/// Decode the character a key press actually produced. `key` is the logical
/// key before Shift is applied; using it made Shift+1 reach WebKit as `1`
/// instead of `!`. Iced's `text` is authoritative for printable input (and
/// handles keyboard layouts), with `modified_key` as the fallback for presses
/// that intentionally carry no text. Control remains a modifier on the event;
/// it must not erase Shift's printable/punctuation mapping.
fn pressed_key_code<T: AsRef<str>>(
    key: &keyboard::Key,
    modified_key: &keyboard::Key,
    text: Option<&T>,
) -> Option<KeyCode> {
    // Named keys remain named even if a backend supplies control text (Tab is
    // the important case: turning it into Character("\\t") bypasses the focus
    // transfer entirely).
    if matches!(key, keyboard::Key::Named(_)) {
        return key_code(modified_key).or_else(|| key_code(key));
    }
    // Only printable text is authoritative: a backend reports Ctrl+C as
    // U+0003, and the page must see the logical `c` with Ctrl instead.
    text.map(AsRef::as_ref)
        .filter(|text| !text.is_empty() && !text.chars().any(char::is_control))
        .map(|text| KeyCode::Character(text.to_string()))
        .or_else(|| key_code(modified_key))
        .or_else(|| key_code(key))
}

/// Translate iced's modifier bitset into the protocol's.
fn modifiers_of(iced: keyboard::Modifiers) -> Modifiers {
    let mut out = Modifiers::NONE;
    if iced.shift() {
        out |= Modifiers::SHIFT;
    }
    if iced.control() {
        out |= Modifiers::CTRL;
    }
    if iced.alt() {
        out |= Modifiers::ALT;
    }
    if iced.logo() {
        out |= Modifiers::META;
    }
    out
}

impl<Message, Theme, Renderer> Widget<Message, Theme, Renderer>
    for WebViewSeam<'_, Message, Theme, Renderer>
where
    Renderer: iced::advanced::Renderer,
{
    fn tag(&self) -> tree::Tag {
        tree::Tag::of::<WebViewState>()
    }

    fn state(&self) -> tree::State {
        tree::State::new(WebViewState::new(self.view, self.input_visible))
    }

    fn diff(&mut self, tree: &mut Tree) {
        tree.state
            .downcast_mut::<WebViewState>()
            .reset_for(self.view, self.input_visible);
        tree.diff_children(std::slice::from_mut(&mut self.child));
    }

    fn size(&self) -> Size<Length> {
        self.child.as_widget().size()
    }

    fn layout(&mut self, tree: &mut Tree, renderer: &Renderer, limits: &layout::Limits) {
        self.child
            .as_widget_mut()
            .layout(&mut tree.children[0], renderer, limits);
        iced::advanced::layout::pass_through(tree, 0);
    }

    fn operate(
        &mut self,
        tree: &mut Tree,
        layout: Layout,
        viewport: &Rectangle,
        renderer: &Renderer,
        operation: &mut dyn Operation,
    ) {
        let bounds = layout.bounds();
        let state = tree.state.downcast_mut::<WebViewState>();
        if self.on_input.is_some() && self.input_visible {
            operation.focusable(Some(&self.id), bounds, state);
        }
        let mut area = SemanticsNode::group(self.area.clone().focused(state.focused));
        operation.custom(Some(&self.id), bounds, &mut area);

        operation.container(Some(&self.id), bounds, viewport);
        operation.traverse(&mut |operation| {
            if let Some(page) = &self.page {
                publish(page, self.view, bounds, operation);
            }
            self.child.as_widget_mut().operate(
                &mut tree.children[0],
                layout,
                viewport,
                renderer,
                operation,
            );
        });
    }

    fn update(
        &mut self,
        tree: &mut Tree,
        event: &Event,
        layout: Layout,
        cursor: mouse::Cursor,
        renderer: &Renderer,
        shell: &mut Shell<'_, Message>,
        viewport: &Rectangle,
    ) {
        let bounds = layout.bounds();
        let visible = bounds.intersection(viewport);
        let state = tree.state.downcast_mut::<WebViewState>();

        // Redraw catches sidebar and dock geometry changes without a window resize.
        if matches!(
            event,
            Event::Window(
                iced::window::Event::Resized(_) | iced::window::Event::RedrawRequested(_)
            )
        ) && self.resize_visible
            && let Some(handler) = &self.on_viewport_resize
            && let Ok(size) = enzui_webkit::ViewportSize::from_logical(bounds.width, bounds.height)
            && state.last_viewport_size != Some(size)
        {
            state.last_viewport_size = Some(size);
            shell.publish(handler(self.view, size));
        }

        // Operations and a preceding diff cannot publish directly. Flush their
        // lifecycle events at the next update before handling fresh input.
        if let Some(handler) = &self.on_input {
            for pending in state.pending.drain(..) {
                shell.publish(handler(pending));
            }
        } else {
            state.pending.clear();
        }

        // The modifier latch. iced ships `ModifiersChanged` and then
        // attaches the resolved bitset to keyboard events;
        // pointer/wheel/touch carry no modifier, so a widget that wants
        // Ctrl-click has to keep the latch itself. Kept on the retained
        // state so the value survives the builder being rebuilt each
        // frame.
        if let Event::Keyboard(keyboard::Event::ModifiersChanged(m)) = event {
            state.modifiers = modifiers_of(*m);
        }
        if let Event::Keyboard(
            keyboard::Event::KeyPressed { modifiers: m, .. }
            | keyboard::Event::KeyReleased { modifiers: m, .. },
        ) = event
        {
            // A key event carries its own modifier snapshot, and iced does
            // not always emit `ModifiersChanged` first (winit occasionally
            // synthesises a keydown with the modifier already applied). Take
            // this as the authoritative value for the following pointer/wheel
            // events too.
            state.modifiers = modifiers_of(*m);
        }

        // Synchronise toolkit focus with the native view. Losing focus is also
        // the terminal boundary for every sequence owned by this widget.
        let was_focused = state.focused;
        let interactive = self.on_input.is_some() && self.input_visible;
        let mut lifecycle = Vec::new();
        match event {
            Event::Mouse(mouse::Event::ButtonPressed(_)) if interactive && state.window_focused => {
                // A press on a layer that covers this view (a scrolled-away
                // or overlaid region) belongs to that layer: end the page's
                // grabs, IME and focus as any outside press does. Hover and
                // leave alone keep ownership.
                if matches!(
                    cursor,
                    mouse::Cursor::Levitating(_) | mouse::Cursor::Obstructed(_)
                ) {
                    lifecycle.extend(state.terminal_events());
                }
                if let Some(position) = cursor.position() {
                    let inside = visible.is_some_and(|clip| clip.contains(position));
                    if inside && !state.focused {
                        state.focused = true;
                        lifecycle.push(InputEvent::FocusGained {
                            view: self.view,
                            modifiers: state.modifiers,
                        });
                    } else if !inside && state.focused {
                        lifecycle.extend(state.terminal_events());
                    }
                }
            }
            Event::Touch(touch::Event::FingerPressed { position, .. })
                if interactive && state.window_focused =>
            {
                let inside = visible.is_some_and(|clip| clip.contains(*position));
                if inside && !state.focused {
                    state.focused = true;
                    lifecycle.push(InputEvent::FocusGained {
                        view: self.view,
                        modifiers: state.modifiers,
                    });
                } else if !inside && state.focused {
                    lifecycle.extend(state.terminal_events());
                }
            }
            Event::Window(iced::window::Event::Unfocused) => {
                let restore = state.focused || state.resume_focus == Some(state.view);
                lifecycle.extend(state.terminal_events());
                state.window_focused = false;
                state.modifiers = Modifiers::NONE;
                state.resume_focus = restore.then_some(state.view);
            }
            Event::Window(iced::window::Event::Focused) => {
                state.window_focused = true;
                if state.resume_focus.take() == Some(state.view)
                    && interactive
                    && visible.is_some_and(|clip| clip.width > 0.0 && clip.height > 0.0)
                {
                    state.focused = true;
                    lifecycle.push(InputEvent::FocusGained {
                        view: state.view,
                        modifiers: state.modifiers,
                    });
                }
            }
            _ => {}
        }
        if let Some(handler) = &self.on_input {
            for event in lifecycle {
                shell.publish(handler(event));
            }
        }
        if state.focused != was_focused {
            shell.request_redraw();
        }

        // What this widget may publish this pass. Computed once, because
        // it is simultaneously the answer to "does the page own the
        // window IME?" and the rectangle to request. `None` means the
        // page owns nothing: no live claim, or a caret that is
        // clipped/hidden/offscreen.
        let owned = self
            .ime
            .as_ref()
            .filter(|_| state.window_focused)
            .and_then(|ime| window_ime_rect(ime, bounds, *viewport));

        // The window's IME events go to the application, which forwards
        // them to the engine, but only while this page actually owns the
        // window input method.
        if let Event::InputMethod(ime_event) = event
            && let (Some(rect), Some(handler)) = (owned, &self.on_input_method)
        {
            shell.publish(handler(super::convert::toolkit_ime_event(ime_event)));
            shell.capture_event();
            self.request_ime(shell, rect);
            return;
        }

        // Hover boundary. A pointer that leaves the visible slice or the
        // window ends page hover, even while the window is unfocused, because
        // a later re-entry may land on a different element. A drag keeps its
        // implicit grab; its leave follows the release instead.
        let in_clip = |point: iced::Point| visible.is_some_and(|clip| clip.contains(point));
        if state.hovering
            && !state.pointer_grab.any()
            && match event {
                Event::Mouse(mouse::Event::CursorLeft) => true,
                // The cursor, not the event: a Scrollable translates the
                // cursor into content space and leaves the event in window
                // space. A covered cursor has no position and ends hover.
                Event::Mouse(mouse::Event::CursorMoved { .. }) => {
                    cursor.position().is_none_or(|point| !in_clip(point))
                }
                _ => false,
            }
            && let (Some(left), Some(handler)) = (state.leave(), &self.on_input)
        {
            shell.publish(handler(left));
        }

        // This is the actual iced -> engine input route. It uses the
        // widget's resolved bounds (not app-supplied guessed geometry),
        // clips positioned input to the visible slice for the ordinary
        // path, and gates keyboard input on retained iced focus. The
        // grabbed path (a drag that started with an in-bounds press)
        // intentionally does not clip: a press paired with its release
        // is a single interaction the page owns until the button lifts.
        // Hovered wheels scroll without acquiring keyboard or IME ownership.
        let accepts_input = state.window_focused
            || matches!(event, Event::Mouse(mouse::Event::WheelScrolled { .. }));
        let routed = (self.input_visible && self.on_input.is_some() && accepts_input)
            .then_some(())
            .and_then(|_| {
                let mapping = ViewportMapping::new(
                    bounds.x,
                    bounds.y,
                    bounds.width,
                    bounds.height,
                    self.scale_factor,
                )?;
                let in_visible =
                    |point: iced::Point| visible.is_some_and(|clip| clip.contains(point));
                match event {
                    Event::Mouse(mouse::Event::CursorMoved { .. }) => {
                        // Translated like press and release, so a drag stays
                        // in one coordinate space inside a Scrollable. A drag
                        // continues while covered; a new hover does not.
                        let position = if state.pointer_grab.any() {
                            cursor.observe().position()?
                        } else {
                            cursor.position()?
                        };
                        if state.pointer_grab.any() {
                            // Drag continuation: forward the translated point
                            // regardless of whether it is inside the widget.
                            Some(pointer_moved_grabbed(
                                self.view,
                                &mapping,
                                position.x,
                                position.y,
                                state.modifiers | state.pointer_grab.modifiers(),
                            ))
                        } else if in_visible(position) {
                            pointer_moved_with_modifiers(
                                self.view,
                                &mapping,
                                position.x,
                                position.y,
                                state.modifiers | state.pointer_grab.modifiers(),
                            )
                        } else {
                            None
                        }
                    }
                    Event::Mouse(mouse::Event::ButtonPressed(button)) => {
                        let point = cursor.position()?;
                        if !in_visible(point) {
                            return None;
                        }
                        let button = pointer_button(*button);
                        // Register the grab before emitting: the paired
                        // release may arrive at an outside position, and
                        // only a grabbed release is unclipped.
                        if !state.pointer_grab.insert(button) {
                            return None;
                        }
                        pointer_pressed_with_modifiers(
                            self.view,
                            &mapping,
                            point.x,
                            point.y,
                            button,
                            state.modifiers | state.pointer_grab.modifiers(),
                        )
                    }
                    Event::Mouse(mouse::Event::ButtonReleased(button)) => {
                        let button = pointer_button(*button);
                        // Remove first: WPE's mouse-up `buttons` state excludes the
                        // button being released but retains any other held button.
                        let was_grabbed = state.pointer_grab.remove(button);
                        if was_grabbed {
                            let at = cursor
                                .position()
                                .map(|point| mapping.to_view(point.x, point.y))
                                .or(state.last_pointer)?;
                            Some(InputEvent::PointerReleased {
                                view: self.view,
                                at,
                                button,
                                modifiers: state.modifiers | state.pointer_grab.modifiers(),
                            })
                        } else {
                            let point = cursor.position()?;
                            if in_visible(point) {
                                pointer_released_with_modifiers(
                                    self.view,
                                    &mapping,
                                    point.x,
                                    point.y,
                                    button,
                                    state.modifiers | state.pointer_grab.modifiers(),
                                )
                            } else {
                                None
                            }
                        }
                    }
                    Event::Mouse(mouse::Event::WheelScrolled { delta }) => {
                        let point = cursor.position()?;
                        if !in_visible(point) {
                            return None;
                        }
                        let (x, y, unit) = match delta {
                            mouse::ScrollDelta::Lines { x, y } => (*x, *y, ScrollUnit::Lines),
                            mouse::ScrollDelta::Pixels { x, y } => (*x, *y, ScrollUnit::Pixels),
                        };
                        wheel_scrolled_at_with_modifiers(
                            self.view,
                            &mapping,
                            point.x,
                            point.y,
                            x,
                            y,
                            unit,
                            state.modifiers | state.pointer_grab.modifiers(),
                        )
                    }
                    Event::Touch(touch::Event::FingerPressed { id, position }) => {
                        if !in_visible(*position) {
                            return None;
                        }
                        let seq = u32::try_from(id.0).ok()?;
                        if !state.touch_grab.insert(seq) {
                            return None;
                        }
                        touch_down_with_modifiers(
                            self.view,
                            &mapping,
                            seq,
                            position.x,
                            position.y,
                            state.modifiers | state.pointer_grab.modifiers(),
                        )
                    }
                    Event::Touch(touch::Event::FingerMoved { id, position }) => {
                        let seq = u32::try_from(id.0).ok()?;
                        if state.touch_grab.contains(seq) {
                            Some(touch_moved_grabbed(
                                self.view,
                                &mapping,
                                seq,
                                position.x,
                                position.y,
                                state.modifiers | state.pointer_grab.modifiers(),
                            ))
                        } else if in_visible(*position) {
                            touch_moved_with_modifiers(
                                self.view,
                                &mapping,
                                seq,
                                position.x,
                                position.y,
                                state.modifiers | state.pointer_grab.modifiers(),
                            )
                        } else {
                            None
                        }
                    }
                    Event::Touch(touch::Event::FingerLifted { id, position }) => {
                        let seq = u32::try_from(id.0).ok()?;
                        let was_grabbed = state.touch_grab.remove(seq);
                        if was_grabbed {
                            Some(touch_up_grabbed(
                                self.view,
                                &mapping,
                                seq,
                                position.x,
                                position.y,
                                state.modifiers | state.pointer_grab.modifiers(),
                            ))
                        } else if in_visible(*position) {
                            touch_up_with_modifiers(
                                self.view,
                                &mapping,
                                seq,
                                position.x,
                                position.y,
                                state.modifiers | state.pointer_grab.modifiers(),
                            )
                        } else {
                            None
                        }
                    }
                    Event::Touch(touch::Event::FingerLost { id, .. }) => {
                        // OS-side cancel of a live finger. Emit TouchCancel for
                        // every grabbed sequence with this id - the position
                        // reported by the OS is unreliable so the protocol drops
                        // it. A cancel for an ungrabbed sequence is silent (a
                        // cancel on a finger the page never saw is a no-op).
                        let seq = u32::try_from(id.0).ok()?;
                        if state.touch_grab.remove(seq) {
                            Some(touch_cancel(
                                self.view,
                                seq,
                                state.modifiers | state.pointer_grab.modifiers(),
                            ))
                        } else {
                            None
                        }
                    }
                    Event::Keyboard(keyboard::Event::KeyPressed {
                        key,
                        modified_key,
                        text,
                        ..
                    }) if state.focused => Some(InputEvent::KeyPressed {
                        view: self.view,
                        key: pressed_key_code(key, modified_key, text.as_ref())?,
                        modifiers: state.modifiers | state.pointer_grab.modifiers(),
                    }),
                    Event::Keyboard(keyboard::Event::KeyReleased {
                        modified_key, key, ..
                    }) if state.focused => {
                        Some(InputEvent::KeyReleased {
                            view: self.view,
                            // Releases carry no `text`; `modified_key` is the
                            // only representation that preserves Shift-applied
                            // punctuation and uppercase characters.
                            key: key_code(modified_key).or_else(|| key_code(key))?,
                            modifiers: state.modifiers | state.pointer_grab.modifiers(),
                        })
                    }
                    _ => None,
                }
            });
        let pointer = matches!(
            routed.as_ref(),
            Some(
                InputEvent::PointerMoved { .. }
                    | InputEvent::PointerPressed { .. }
                    | InputEvent::PointerReleased { .. }
            )
        );
        if let Some(at) = routed.as_ref().and_then(InputEvent::view_point)
            && pointer
        {
            state.last_pointer = Some(at);
        }
        // A routed pointer event inside the slice enters; a drag released
        // outside it leaves once the grab is over.
        let inside = cursor.position().is_some_and(in_clip);
        if pointer && inside {
            state.hovering = true;
        }
        let trailing = (matches!(routed, Some(InputEvent::PointerReleased { .. }))
            && !state.pointer_grab.any()
            && !inside)
            .then(|| state.leave())
            .flatten();
        if let (Some(input), Some(handler)) = (routed, &self.on_input) {
            shell.publish(handler(input));
            if let Some(left) = trailing {
                shell.publish(handler(left));
            }
            shell.capture_event();
            if let Some(rect) = owned {
                self.request_ime(shell, rect);
            }
            return;
        }

        self.child.as_widget_mut().update(
            &mut tree.children[0],
            event,
            layout,
            cursor,
            renderer,
            shell,
            viewport,
        );

        // Publish the page's caret to the window IME. Requested on every
        // pass that reaches here, because iced resets the strategy each
        // frame and merges what widgets request; not requesting is how a
        // widget says "closed", which is why a clipped or hidden caret
        // simply falls through.
        if let Some(rect) = owned {
            self.request_ime(shell, rect);
        }
    }

    fn draw(
        &self,
        tree: &Tree,
        renderer: &mut Renderer,
        theme: &Theme,
        style: &renderer::Style,
        layout: Layout,
        cursor: mouse::Cursor,
        viewport: &Rectangle,
    ) {
        self.child.as_widget().draw(
            &tree.children[0],
            renderer,
            theme,
            style,
            layout,
            cursor,
            viewport,
        );
    }

    fn mouse_interaction(
        &self,
        tree: &Tree,
        layout: Layout,
        cursor: mouse::Cursor,
        viewport: &Rectangle,
        renderer: &Renderer,
    ) -> mouse::Interaction {
        // The page's cursor applies only while the pointer is inside the
        // visible part of this widget. Outside it - over a neighbour, or
        // over a clipped-away slice - the host's own cursor stands,
        // which is what "restore the host cursor on leave" means
        // concretely.
        if let Some(page_cursor) = self.cursor
            && let Some(visible) = layout.bounds().intersection(viewport)
            && cursor.is_over(visible)
        {
            return page_cursor;
        }
        self.child.as_widget().mouse_interaction(
            &tree.children[0],
            layout,
            cursor,
            viewport,
            renderer,
        )
    }

    fn overlay<'b>(
        &'b mut self,
        tree: &'b mut Tree,
        layout: Layout,
        renderer: &Renderer,
        viewport: &Rectangle,
        translation: Vector,
        window: Size,
    ) -> Vec<overlay::Element<'b, Message, Theme, Renderer>> {
        self.child.as_widget_mut().overlay(
            &mut tree.children[0],
            layout,
            renderer,
            viewport,
            translation,
            window,
        )
    }
}

impl<'a, Message, Theme, Renderer> From<WebViewSeam<'a, Message, Theme, Renderer>>
    for Element<'a, Message, Theme, Renderer>
where
    Message: 'a,
    Theme: 'a,
    Renderer: iced::advanced::Renderer + 'a,
{
    fn from(layer: WebViewSeam<'a, Message, Theme, Renderer>) -> Self {
        Element::new(layer)
    }
}
