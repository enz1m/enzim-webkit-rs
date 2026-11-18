//! Translated, clipped pointer, wheel, keyboard and touch input, forwarded to
//! the engine as typed protocol.
//!

use crate::web::ViewId;

/// A point in a view's logical coordinate space, relative to the view's
/// top-left - the space WPE's `wpe_event_*` pointer/touch constructors consume
/// (page zoom baked in, output/device scale not applied; see the module
/// docs).
///
/// This is what the engine forwards to WPE. It is deliberately a distinct type
/// from any window coordinate so the two cannot be confused at a call site: a
/// value of this type has already been through [`ViewportMapping::to_view`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ViewPoint {
    /// Horizontal position in logical view pixels from the view's left edge.
    pub x: f32,
    /// Vertical position in logical view pixels from the view's top edge.
    pub y: f32,
}

/// The transform from window-logical coordinates to a view's logical
/// coordinate space.
///
/// A view occupies a rectangle in the window (its widget bounds, in logical
/// pixels). WPE consumes pointer/caret geometry in the view's own logical
/// coordinate space, so the mapping is a pure translation by the view origin:
///
/// ```text
/// view = window_point - bounds_origin      // NO output-scale multiply
/// ```
///
/// Subtracting the origin is what makes a view away from the window corner
/// correct, and it is exercised with non-trivial values in the tests. An
/// origin-`(0,0)` mapping is a *special case*, not the contract.
///
/// The output/device scale deliberately does not enter any transform on
/// this type (pointer, touch, caret or wheel delta): WPE applies
/// `wpe_view_get_scale` inside WebKit, so applying it here too would
/// double-count it and, at output scale 2, land every click at twice the
/// intended coordinate. `scale_factor` is retained only to reject
/// incoherent values at construction and to let the invariance tests build
/// distinct-scale mappings that must produce identical results.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ViewportMapping {
    /// The view's top-left in window-logical pixels.
    origin_x: f32,
    origin_y: f32,
    /// The view's size in window-logical pixels.
    width: f32,
    height: f32,
    /// The view's output/device scale (e.g. 2.0 on a HiDPI display). Validated
    /// at construction but not applied to any coordinate transform - WPE
    /// owns output scaling. See the type docs.
    scale_factor: f32,
}

impl ViewportMapping {
    /// A mapping for a view at logical `(origin_x, origin_y)` of logical size
    /// `width x height`, rendering at `scale_factor` device pixels per logical
    /// pixel.
    ///
    /// A non-finite or non-positive `scale_factor` is refused - there is no
    /// coherent transform for it - via `None`. A zero-area bound is allowed
    /// (a collapsed view) but then [`map_pointer`](Self::map_pointer) accepts no
    /// point, because no point is inside a zero-area rectangle.
    #[must_use]
    pub fn new(
        origin_x: f32,
        origin_y: f32,
        width: f32,
        height: f32,
        scale_factor: f32,
    ) -> Option<ViewportMapping> {
        if !scale_factor.is_finite() || scale_factor <= 0.0 {
            return None;
        }
        if !origin_x.is_finite()
            || !origin_y.is_finite()
            || !width.is_finite()
            || !height.is_finite()
            || width < 0.0
            || height < 0.0
        {
            return None;
        }
        Some(ViewportMapping {
            origin_x,
            origin_y,
            width,
            height,
            scale_factor,
        })
    }

    /// The scale factor this mapping applies.
    #[must_use]
    pub fn scale_factor(&self) -> f32 {
        self.scale_factor
    }

    /// Whether a window-logical point lies inside the view's bounds.
    ///
    /// The right/bottom edges are exclusive so two adjacent views never both
    /// claim a point on their shared border.
    #[must_use]
    pub fn contains(&self, window_x: f32, window_y: f32) -> bool {
        window_x >= self.origin_x
            && window_y >= self.origin_y
            && window_x < self.origin_x + self.width
            && window_y < self.origin_y + self.height
    }

    /// Translate a window-logical point into the view's logical
    /// coordinate space, *without* the bounds check.
    ///
    /// This is the raw transform (subtract the view origin; no output-scale
    /// multiply), exposed so a test can assert the arithmetic directly with an
    /// absolute anchor. Most callers want [`map_pointer`](Self::map_pointer),
    /// which also clips.
    #[must_use]
    pub fn to_view(&self, window_x: f32, window_y: f32) -> ViewPoint {
        ViewPoint {
            x: window_x - self.origin_x,
            y: window_y - self.origin_y,
        }
    }

    /// Map a window-logical pointer position to a view-logical point, or
    /// `None` if it is outside the view's bounds.
    ///
    /// The clip is the security-relevant part: a pointer over a neighbouring
    /// widget must not be forwarded to this page. Returning `None` drops the
    /// event before it becomes an [`InputEvent`].
    #[must_use]
    pub fn map_pointer(&self, window_x: f32, window_y: f32) -> Option<ViewPoint> {
        if self.contains(window_x, window_y) {
            Some(self.to_view(window_x, window_y))
        } else {
            None
        }
    }

    /// Map a rectangle in logical view pixels (the page caret) to a
    /// window-logical rectangle, clipped to the view's bounds - the direction
    /// the page caret needs to reach the window IME.
    ///
    /// # The caret is logical, so the transform is translation only
    ///
    /// The pointer path is also translation only (`view = window - origin`); the
    /// caret is the same transform read backwards. WebKit's WPE port
    /// reports the caret from `editorState.visualData->caretRectAtStart`, which
    /// is in logical root-view pixels: page zoom is baked in (it changes
    /// layout), but the output/device scale is not - the WPE
    /// `platformTransformCursorRectToViewCoordinates` returns the rect
    /// unchanged and `notifyCursorRect` applies no scale (verified against
    /// WebKit `UIProcess/API/wpe/InputMethodFilterWPE.cpp` and
    /// `UIProcess/API/glib/InputMethodFilter.cpp`). The window IME also wants
    /// window-logical pixels, so the two spaces differ only by the view's
    /// origin:
    ///
    /// ```text
    /// window = bounds_origin + caret_view   // NO division by scale_factor
    /// ```
    ///
    /// Dividing by `scale_factor` here (the previous contract) was correct only
    /// because every test pinned the scale at 1; at a real output scale 2 it
    /// halved an already-logical caret. This is why the discriminating gate
    /// forces a non-1 `wpe_view_get_scale()` while page zoom stays 1: the caret
    /// must land in the *same* window rectangle regardless of output scale.
    ///
    /// # The clip is the load-bearing part
    ///
    /// A caret can be scrolled out of the visible surface, or sit in a page
    /// region the widget's bounds do not cover. Returning the un-clipped
    /// rectangle would publish an IME candidate window floating outside the
    /// widget - over a neighbour, or off-window. So the result is intersected
    /// with the view's own bounds and `None` is returned when the intersection
    /// is empty. `None` means "close the IME", never "publish it anyway".
    ///
    /// A zero-width caret (a collapsed insertion point, which is the normal
    /// case) is not empty for this purpose: it is inflated to a minimum of one
    /// logical pixel so a legitimate caret is not mistaken for an off-screen
    /// one. A zero-height caret is empty, because a field with no line
    /// height is not rendering.
    #[must_use]
    pub fn to_window_rect(
        &self,
        view_x: f32,
        view_y: f32,
        view_w: f32,
        view_h: f32,
    ) -> Option<(f32, f32, f32, f32)> {
        if !view_x.is_finite()
            || !view_y.is_finite()
            || !view_w.is_finite()
            || !view_h.is_finite()
            || view_w < 0.0
            || view_h < 0.0
        {
            return None;
        }
        // Logical caret -> window-logical: translate by the view origin only.
        // NO division by `scale_factor` - the caret is already in logical view
        // pixels (see the method doc). `scale_factor` deliberately does not
        // appear here, so the result is invariant under output scale.
        let x = self.origin_x + view_x;
        let y = self.origin_y + view_y;
        let w = view_w.max(1.0);
        let h = view_h;
        if h <= 0.0 {
            return None;
        }
        // Intersect with the view's bounds.
        let left = x.max(self.origin_x);
        let top = y.max(self.origin_y);
        let right = (x + w).min(self.origin_x + self.width);
        let bottom = (y + h).min(self.origin_y + self.height);
        if right <= left || bottom <= top {
            return None;
        }
        Some((left, top, right - left, bottom - top))
    }

    /// Map a logical scroll delta for WPE.
    ///
    /// A wheel event carries a delta, not an absolute position, so there is no
    /// origin to subtract. There is also no output-scale multiply: WPE's
    /// `wpe_event_scroll_new` consumes logical wheel ticks / pixels and applies
    /// its own step scaling inside WebKit (`WebEventFactoryWPE`), so multiplying
    /// by the output scale here would double-count it exactly as it would for a
    /// pointer position. Kept as its own method so the "a delta is
    /// neither translated nor output-scaled" rule is explicit and testable.
    #[must_use]
    pub fn map_delta(&self, dx: f32, dy: f32) -> (f32, f32) {
        (dx, dy)
    }
}

/// The keyboard and pointer-button state carried alongside a keystroke,
/// click, wheel or touch. It mirrors the useful subset of WPE's modifier
/// vocabulary without making the protocol depend on iced or the native ABI.
/// Conversion to WPE flags is explicit because iced and WPE assign different
/// bit positions to Shift and Control.
///
/// The engine needs the modifier bits with every event, not just the four
/// dedicated modifier keys: a bare `A` and a `Ctrl-A` are different
/// intents. Iced drops modifiers on the floor unless the widget explicitly
/// carries a `keyboard::Modifiers` alongside each key, and `ModifiersChanged`
/// updates a widget-side latch - this is the value that latch produces.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Modifiers {
    bits: u32,
}

impl Modifiers {
    /// No modifiers held.
    pub const NONE: Modifiers = Modifiers { bits: 0 };
    /// Shift.
    pub const SHIFT: Modifiers = Modifiers { bits: 1 << 0 };
    /// Ctrl.
    pub const CTRL: Modifiers = Modifiers { bits: 1 << 1 };
    /// Alt (Option).
    pub const ALT: Modifiers = Modifiers { bits: 1 << 2 };
    /// The platform's "logo" key (Super on X11/Wayland, Command on macOS,
    /// Windows key on Windows). Meta at the protocol level.
    pub const META: Modifiers = Modifiers { bits: 1 << 3 };
    /// Primary pointer button held.
    pub const BUTTON1: Modifiers = Modifiers { bits: 1 << 8 };
    /// Middle pointer button held.
    pub const BUTTON2: Modifiers = Modifiers { bits: 1 << 9 };
    /// Secondary pointer button held.
    pub const BUTTON3: Modifiers = Modifiers { bits: 1 << 10 };
    /// Fourth pointer button held.
    pub const BUTTON4: Modifiers = Modifiers { bits: 1 << 11 };
    /// Fifth pointer button held.
    pub const BUTTON5: Modifiers = Modifiers { bits: 1 << 12 };

    /// A modifier set from the raw bit pattern.
    #[must_use]
    pub const fn from_bits(bits: u32) -> Modifiers {
        Modifiers { bits }
    }

    /// The raw bit pattern.
    #[must_use]
    pub const fn bits(&self) -> u32 {
        self.bits
    }

    /// Whether every flag in `other` is set.
    #[must_use]
    pub const fn contains(&self, other: Modifiers) -> bool {
        (self.bits & other.bits) == other.bits
    }

    /// Whether no modifier is held.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bits == 0
    }

    /// Return this set without the supplied flags.
    #[must_use]
    pub const fn without(self, other: Modifiers) -> Modifiers {
        Modifiers {
            bits: self.bits & !other.bits,
        }
    }

    /// Shift alone.
    #[must_use]
    pub const fn shift(&self) -> bool {
        self.contains(Modifiers::SHIFT)
    }
    /// Ctrl alone.
    #[must_use]
    pub const fn ctrl(&self) -> bool {
        self.contains(Modifiers::CTRL)
    }
    /// Alt alone.
    #[must_use]
    pub const fn alt(&self) -> bool {
        self.contains(Modifiers::ALT)
    }
    /// The platform logo modifier alone.
    #[must_use]
    pub const fn meta(&self) -> bool {
        self.contains(Modifiers::META)
    }
    /// Primary pointer button.
    #[must_use]
    pub const fn button1(&self) -> bool {
        self.contains(Modifiers::BUTTON1)
    }
    /// Middle pointer button.
    #[must_use]
    pub const fn button2(&self) -> bool {
        self.contains(Modifiers::BUTTON2)
    }
    /// Secondary pointer button.
    #[must_use]
    pub const fn button3(&self) -> bool {
        self.contains(Modifiers::BUTTON3)
    }
    /// Fourth pointer button.
    #[must_use]
    pub const fn button4(&self) -> bool {
        self.contains(Modifiers::BUTTON4)
    }
    /// Fifth pointer button.
    #[must_use]
    pub const fn button5(&self) -> bool {
        self.contains(Modifiers::BUTTON5)
    }
}

impl core::ops::BitOr for Modifiers {
    type Output = Modifiers;
    fn bitor(self, rhs: Modifiers) -> Modifiers {
        Modifiers {
            bits: self.bits | rhs.bits,
        }
    }
}

impl core::ops::BitOrAssign for Modifiers {
    fn bitor_assign(&mut self, rhs: Modifiers) {
        self.bits |= rhs.bits;
    }
}

/// A pointer button, mirrored from the toolkit without depending on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PointerButton {
    /// The primary (usually left) button.
    Primary,
    /// The secondary (usually right) button.
    Secondary,
    /// The middle button.
    Middle,
    /// Any other button, identified by its raw code.
    Other(u16),
}

/// A key identity, mirrored from the toolkit without depending on it.
///
/// The engine needs enough to route a keystroke: a named key (Enter, Tab, an
/// arrow) or a produced character. This is not a full keymap - that is the
/// engine's job - it is the vocabulary the protocol carries.
///
/// `Debug` preserves named keys but renders every [`KeyCode::Character`]
/// payload as `Character([REDACTED])`. The stored string remains unchanged for
/// native forwarding; only diagnostics are redacted.
#[derive(Clone, PartialEq, Eq)]
pub enum KeyCode {
    /// A key that produced text (the string the toolkit resolved).
    Character(String),
    /// A named non-text key.
    Named(NamedKey),
}

impl core::fmt::Debug for KeyCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            // Character payloads can contain passwords or other private text.
            // Keep the functional value intact for forwarding, but stop it at
            // the shared diagnostic boundary used by every enclosing event.
            Self::Character(_) => f.write_str("Character([REDACTED])"),
            Self::Named(key) => f.debug_tuple("Named").field(key).finish(),
        }
    }
}

/// The named keys the input path routes explicitly.
///
/// # Coverage policy
///
/// The routed vocabulary covers browser-visible modifier, navigation, editing,
/// application, clipboard, and F1–F35 keys. Hardware/system controls such as
/// brightness and media transport remain host-owned. [`NamedKey::ALL`] is the
/// exhaustive table used by mapping tests; adding a variant requires updating
/// every toolkit and native mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NamedKey {
    /// Alt/Option.
    Alt,
    /// AltGraph / ISO level-three shift.
    AltGraph,
    /// Caps Lock.
    CapsLock,
    /// Control.
    Control,
    /// Num Lock.
    NumLock,
    /// Scroll Lock.
    ScrollLock,
    /// Shift.
    Shift,
    /// Meta.
    Meta,
    /// Super/Command/Windows key.
    Super,
    /// The Enter/Return key.
    Enter,
    /// The Tab key (the page's Tab, distinct from toolkit traversal - see
    /// `focus.rs`).
    Tab,
    /// Backspace.
    Backspace,
    /// Escape.
    Escape,
    /// Space bar (also produced by `KeyCode::Character(" ")`; retained as a
    /// distinct named key for callers that only see the named form).
    Space,
    /// Arrow up.
    ArrowUp,
    /// Arrow down.
    ArrowDown,
    /// Arrow left.
    ArrowLeft,
    /// Arrow right.
    ArrowRight,
    /// Home.
    Home,
    /// End.
    End,
    /// Page up.
    PageUp,
    /// Page down.
    PageDown,
    /// Delete (forward-delete).
    Delete,
    /// Insert.
    Insert,
    /// The keyboard's context-menu / application key.
    ContextMenu,
    /// Cut.
    Cut,
    /// Copy.
    Copy,
    /// Paste.
    Paste,
    /// Undo.
    Undo,
    /// Redo.
    Redo,
    /// Clear.
    Clear,
    /// Accept/commit.
    Accept,
    /// Repeat the previous action.
    Again,
    /// Cancel.
    Cancel,
    /// Execute.
    Execute,
    /// Find.
    Find,
    /// Help.
    Help,
    /// Pause/Break.
    Pause,
    /// Select.
    Select,
    /// Print Screen.
    PrintScreen,
    /// Browser Back.
    BrowserBack,
    /// Browser Forward.
    BrowserForward,
    /// Browser Refresh.
    BrowserRefresh,
    /// Browser Stop.
    BrowserStop,
    /// Browser Search.
    BrowserSearch,
    /// Browser Favorites.
    BrowserFavorites,
    /// Browser Home.
    BrowserHome,
    /// Zoom in.
    ZoomIn,
    /// Zoom out.
    ZoomOut,
    /// F1.
    F1,
    /// F2.
    F2,
    /// F3.
    F3,
    /// F4.
    F4,
    /// F5.
    F5,
    /// F6.
    F6,
    /// F7.
    F7,
    /// F8.
    F8,
    /// F9.
    F9,
    /// F10.
    F10,
    /// F11.
    F11,
    /// F12.
    F12,
    /// F13.
    F13,
    /// F14.
    F14,
    /// F15.
    F15,
    /// F16.
    F16,
    /// F17.
    F17,
    /// F18.
    F18,
    /// F19.
    F19,
    /// F20.
    F20,
    /// F21.
    F21,
    /// F22.
    F22,
    /// F23.
    F23,
    /// F24.
    F24,
    /// F25.
    F25,
    /// F26.
    F26,
    /// F27.
    F27,
    /// F28.
    F28,
    /// F29.
    F29,
    /// F30.
    F30,
    /// F31.
    F31,
    /// F32.
    F32,
    /// F33.
    F33,
    /// F34.
    F34,
    /// F35.
    F35,
}

impl NamedKey {
    /// Every named key carried by the protocol, in declaration order.
    pub const ALL: &'static [NamedKey] = &[
        Self::Alt,
        Self::AltGraph,
        Self::CapsLock,
        Self::Control,
        Self::NumLock,
        Self::ScrollLock,
        Self::Shift,
        Self::Meta,
        Self::Super,
        Self::Enter,
        Self::Tab,
        Self::Backspace,
        Self::Escape,
        Self::Space,
        Self::ArrowUp,
        Self::ArrowDown,
        Self::ArrowLeft,
        Self::ArrowRight,
        Self::Home,
        Self::End,
        Self::PageUp,
        Self::PageDown,
        Self::Delete,
        Self::Insert,
        Self::ContextMenu,
        Self::Cut,
        Self::Copy,
        Self::Paste,
        Self::Undo,
        Self::Redo,
        Self::Clear,
        Self::Accept,
        Self::Again,
        Self::Cancel,
        Self::Execute,
        Self::Find,
        Self::Help,
        Self::Pause,
        Self::Select,
        Self::PrintScreen,
        Self::BrowserBack,
        Self::BrowserForward,
        Self::BrowserRefresh,
        Self::BrowserStop,
        Self::BrowserSearch,
        Self::BrowserFavorites,
        Self::BrowserHome,
        Self::ZoomIn,
        Self::ZoomOut,
        Self::F1,
        Self::F2,
        Self::F3,
        Self::F4,
        Self::F5,
        Self::F6,
        Self::F7,
        Self::F8,
        Self::F9,
        Self::F10,
        Self::F11,
        Self::F12,
        Self::F13,
        Self::F14,
        Self::F15,
        Self::F16,
        Self::F17,
        Self::F18,
        Self::F19,
        Self::F20,
        Self::F21,
        Self::F22,
        Self::F23,
        Self::F24,
        Self::F25,
        Self::F26,
        Self::F27,
        Self::F28,
        Self::F29,
        Self::F30,
        Self::F31,
        Self::F32,
        Self::F33,
        Self::F34,
        Self::F35,
    ];
}

/// Native wheel delta units, independent of output scale.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScrollUnit {
    /// Precise logical pixel deltas from a touchpad or programmatic scroll.
    Pixels,
    /// Discrete wheel steps; WPE applies the native line-step conversion.
    Lines,
}

/// A typed input event forwarded to a specific view's engine surface.
///
/// Every variant names the [`ViewId`] it targets, so an event built against a
/// crashed generation is distinguishable from a live one (the same
/// generation-keyed discipline as frames and policy). Pointer variants carry
/// view-logical coordinates: ordinary events are translated and clipped by
/// [`ViewportMapping`], while a sequence captured by an in-bounds down may carry
/// translated out-of-bounds move/up coordinates until its terminal event. The
/// output/device scale is applied by WPE, not baked in here.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum InputEvent {
    /// The toolkit focus ring gave keyboard focus to the web area.
    FocusGained {
        /// The target view.
        view: ViewId,
        /// Current modifier state.
        modifiers: Modifiers,
    },
    /// The toolkit focus ring, window, or visibility lifecycle removed focus.
    FocusLost {
        /// The target view.
        view: ViewId,
        /// Current modifier state.
        modifiers: Modifiers,
    },
    /// The pointer moved to a view-logical position on the surface.
    PointerMoved {
        /// The target view.
        view: ViewId,
        /// View-logical position on the surface.
        at: ViewPoint,
        /// Modifiers held while the pointer moved.
        modifiers: Modifiers,
    },
    /// The pointer left the view: it moved out of the visible area or the
    /// window, or the view was hidden or replaced. Clears page hover state;
    /// the next [`Self::PointerMoved`] enters again at its own position.
    PointerLeft {
        /// The target view.
        view: ViewId,
        /// Current modifier state.
        modifiers: Modifiers,
    },
    /// A pointer button was pressed at a view-logical position.
    PointerPressed {
        /// The target view.
        view: ViewId,
        /// View-logical position on the surface.
        at: ViewPoint,
        /// Which button.
        button: PointerButton,
        /// Modifiers held while the button was pressed.
        modifiers: Modifiers,
    },
    /// A pointer button was released at a view-logical position.
    PointerReleased {
        /// The target view.
        view: ViewId,
        /// View-logical position on the surface. May be outside the widget's
        /// bounds when the button was pressed inside - an implicit grab keeps
        /// the release paired with its press regardless of the pointer's
        /// current location.
        at: ViewPoint,
        /// Which button.
        button: PointerButton,
        /// Modifiers held while the button was released.
        modifiers: Modifiers,
    },
    /// Origin-based precise-pixel scroll retained for programmatic callers.
    /// Use [`Self::WheelScrolledAt`] to target the point under a real cursor.
    WheelScrolled {
        /// The target view.
        view: ViewId,
        /// Logical horizontal delta.
        delta_x: f32,
        /// Logical vertical delta.
        delta_y: f32,
        /// Modifiers held while the wheel was scrolled.
        modifiers: Modifiers,
    },
    /// Wheel input at a view-logical point with its original delta units.
    WheelScrolledAt {
        /// The target view.
        view: ViewId,
        /// Position under the wheel cursor, translated from the window origin.
        at: ViewPoint,
        /// Horizontal delta in `unit`.
        delta_x: f32,
        /// Vertical delta in `unit`.
        delta_y: f32,
        /// Pixel or discrete wheel-step units.
        unit: ScrollUnit,
        /// Keyboard and pressed-button modifiers.
        modifiers: Modifiers,
    },
    /// A key was pressed. Routed only while the view holds keyboard focus (the
    /// widget enforces that); the engine receives the key identity.
    KeyPressed {
        /// The target view.
        view: ViewId,
        /// The key identity.
        key: KeyCode,
        /// Modifiers held while the key was pressed. A bare `A` and a `Ctrl-A`
        /// carry the same `key` and different `modifiers`.
        modifiers: Modifiers,
    },
    /// A key was released.
    KeyReleased {
        /// The target view.
        view: ViewId,
        /// The key identity.
        key: KeyCode,
        /// Modifiers held while the key was released.
        modifiers: Modifiers,
    },
    /// A touch point went down. `seq` identifies the finger across the
    /// down → move* → up|cancel sequence so the engine correlates them into
    /// one touch.
    TouchDown {
        /// The target view.
        view: ViewId,
        /// Which finger (sequence id).
        seq: u32,
        /// View-logical position on the surface.
        at: ViewPoint,
        /// Modifiers held.
        modifiers: Modifiers,
    },
    /// A touch point moved.
    TouchMoved {
        /// The target view.
        view: ViewId,
        /// Which finger (sequence id).
        seq: u32,
        /// View-logical position on the surface. May be outside the widget's
        /// bounds when the finger was pressed inside - an implicit grab keeps
        /// the move paired with its down regardless of the finger's current
        /// location.
        at: ViewPoint,
        /// Modifiers held.
        modifiers: Modifiers,
    },
    /// A touch point lifted.
    TouchUp {
        /// The target view.
        view: ViewId,
        /// Which finger (sequence id).
        seq: u32,
        /// View-logical position on the surface. May be outside the widget's
        /// bounds when the finger was pressed inside - an implicit grab keeps
        /// the release paired with its press regardless of the finger's
        /// current location.
        at: ViewPoint,
        /// Modifiers held.
        modifiers: Modifiers,
    },
    /// A touch point was cancelled by the OS (window minimised, gesture
    /// take-over, external input takeover). The page must end its tracking of
    /// `seq`; without this variant a cancelled finger looks perpetually
    /// down. Carries no position: the toolkit reports the last known point
    /// but the meaningful information is only the identity of the ended
    /// sequence.
    TouchCancel {
        /// The target view.
        view: ViewId,
        /// Which finger (sequence id).
        seq: u32,
        /// Modifiers held.
        modifiers: Modifiers,
    },
}

impl InputEvent {
    /// The view this event targets.
    #[must_use]
    pub fn view(&self) -> ViewId {
        match self {
            InputEvent::FocusGained { view, .. }
            | InputEvent::FocusLost { view, .. }
            | InputEvent::PointerMoved { view, .. }
            | InputEvent::PointerLeft { view, .. }
            | InputEvent::PointerPressed { view, .. }
            | InputEvent::PointerReleased { view, .. }
            | InputEvent::WheelScrolled { view, .. }
            | InputEvent::WheelScrolledAt { view, .. }
            | InputEvent::KeyPressed { view, .. }
            | InputEvent::KeyReleased { view, .. }
            | InputEvent::TouchDown { view, .. }
            | InputEvent::TouchMoved { view, .. }
            | InputEvent::TouchUp { view, .. }
            | InputEvent::TouchCancel { view, .. } => *view,
        }
    }

    /// The modifier set carried on this event.
    #[must_use]
    pub fn modifiers(&self) -> Modifiers {
        match self {
            InputEvent::FocusGained { modifiers, .. }
            | InputEvent::FocusLost { modifiers, .. }
            | InputEvent::PointerMoved { modifiers, .. }
            | InputEvent::PointerLeft { modifiers, .. }
            | InputEvent::PointerPressed { modifiers, .. }
            | InputEvent::PointerReleased { modifiers, .. }
            | InputEvent::WheelScrolled { modifiers, .. }
            | InputEvent::WheelScrolledAt { modifiers, .. }
            | InputEvent::KeyPressed { modifiers, .. }
            | InputEvent::KeyReleased { modifiers, .. }
            | InputEvent::TouchDown { modifiers, .. }
            | InputEvent::TouchMoved { modifiers, .. }
            | InputEvent::TouchUp { modifiers, .. }
            | InputEvent::TouchCancel { modifiers, .. } => *modifiers,
        }
    }

    /// Whether this event ends focus, hover, or an in-flight pointer/touch
    /// sequence.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            InputEvent::FocusLost { .. }
                | InputEvent::PointerLeft { .. }
                | InputEvent::PointerReleased { .. }
                | InputEvent::TouchUp { .. }
                | InputEvent::TouchCancel { .. }
        )
    }

    /// The view-logical point this event occurred at, if it is a positioned
    /// event (pointer, touch, or wheel).
    #[must_use]
    pub fn view_point(&self) -> Option<ViewPoint> {
        match self {
            InputEvent::PointerMoved { at, .. }
            | InputEvent::PointerPressed { at, .. }
            | InputEvent::PointerReleased { at, .. }
            | InputEvent::TouchDown { at, .. }
            | InputEvent::TouchMoved { at, .. }
            | InputEvent::TouchUp { at, .. }
            | InputEvent::WheelScrolledAt { at, .. } => Some(*at),
            _ => None,
        }
    }
}

/// Build a pointer-moved event for `view` from a window-logical position,
/// translating and clipping through `mapping`. Returns `None` for a point outside
/// the view - the drop that keeps a neighbour's pointer out of this page.
#[must_use]
pub fn pointer_moved(
    view: ViewId,
    mapping: &ViewportMapping,
    window_x: f32,
    window_y: f32,
) -> Option<InputEvent> {
    pointer_moved_with_modifiers(view, mapping, window_x, window_y, Modifiers::NONE)
}

/// Modifier-aware form of [`pointer_moved`].
#[must_use]
pub fn pointer_moved_with_modifiers(
    view: ViewId,
    mapping: &ViewportMapping,
    window_x: f32,
    window_y: f32,
    modifiers: Modifiers,
) -> Option<InputEvent> {
    let at = mapping.map_pointer(window_x, window_y)?;
    Some(InputEvent::PointerMoved {
        view,
        at,
        modifiers,
    })
}

/// Build a pointer-pressed event, translated and clipped. `None` if outside bounds.
#[must_use]
pub fn pointer_pressed(
    view: ViewId,
    mapping: &ViewportMapping,
    window_x: f32,
    window_y: f32,
    button: PointerButton,
) -> Option<InputEvent> {
    pointer_pressed_with_modifiers(view, mapping, window_x, window_y, button, Modifiers::NONE)
}

/// Modifier-aware form of [`pointer_pressed`].
#[must_use]
pub fn pointer_pressed_with_modifiers(
    view: ViewId,
    mapping: &ViewportMapping,
    window_x: f32,
    window_y: f32,
    button: PointerButton,
    modifiers: Modifiers,
) -> Option<InputEvent> {
    let at = mapping.map_pointer(window_x, window_y)?;
    Some(InputEvent::PointerPressed {
        view,
        at,
        button,
        modifiers: modifiers | pointer_button_modifier(button),
    })
}

/// Build a pointer-released event, translated and clipped by `mapping`. `None`
/// if outside bounds - which is the ordinary-release case; a release paired
/// with an in-bounds press is emitted by [`pointer_released_grabbed`] and is
/// not clipped, because a drag that started inside must end even if the
/// pointer left the widget.
#[must_use]
pub fn pointer_released(
    view: ViewId,
    mapping: &ViewportMapping,
    window_x: f32,
    window_y: f32,
    button: PointerButton,
) -> Option<InputEvent> {
    pointer_released_with_modifiers(view, mapping, window_x, window_y, button, Modifiers::NONE)
}

/// Modifier-aware form of [`pointer_released`].
#[must_use]
pub fn pointer_released_with_modifiers(
    view: ViewId,
    mapping: &ViewportMapping,
    window_x: f32,
    window_y: f32,
    button: PointerButton,
    modifiers: Modifiers,
) -> Option<InputEvent> {
    let at = mapping.map_pointer(window_x, window_y)?;
    Some(InputEvent::PointerReleased {
        view,
        at,
        button,
        modifiers: modifiers.without(pointer_button_modifier(button)),
    })
}

/// Build a pointer event under an implicit grab - the point is translated
/// but *not* clipped. Used by the widget when a press already landed inside
/// its bounds and a subsequent move/release arrives at a position outside
/// them: the page owns the drag until the button lifts, so an outside move or
/// the outside release must still reach it. The FFI/protocol contract is the
/// same as [`pointer_released`]; the caller is responsible for only forwarding
/// grabbed events between the paired press and release.
#[must_use]
pub fn pointer_moved_grabbed(
    view: ViewId,
    mapping: &ViewportMapping,
    window_x: f32,
    window_y: f32,
    modifiers: Modifiers,
) -> InputEvent {
    let at = mapping.to_view(window_x, window_y);
    InputEvent::PointerMoved {
        view,
        at,
        modifiers,
    }
}

/// Build a pointer-released event under an implicit grab; not clipped. See
/// [`pointer_moved_grabbed`].
#[must_use]
pub fn pointer_released_grabbed(
    view: ViewId,
    mapping: &ViewportMapping,
    window_x: f32,
    window_y: f32,
    button: PointerButton,
    modifiers: Modifiers,
) -> InputEvent {
    let at = mapping.to_view(window_x, window_y);
    InputEvent::PointerReleased {
        view,
        at,
        button,
        modifiers: modifiers.without(pointer_button_modifier(button)),
    }
}

fn pointer_button_modifier(button: PointerButton) -> Modifiers {
    match button {
        PointerButton::Primary => Modifiers::BUTTON1,
        PointerButton::Middle => Modifiers::BUTTON2,
        PointerButton::Secondary => Modifiers::BUTTON3,
        PointerButton::Other(4) => Modifiers::BUTTON4,
        PointerButton::Other(5) => Modifiers::BUTTON5,
        PointerButton::Other(_) => Modifiers::NONE,
    }
}

/// Build a touch-down event, translated and clipped through `mapping`. `seq` is the
/// finger identity carried across the whole down → move* → up sequence. `None`
/// if the point is outside the view - the same clip that keeps a neighbour's
/// touch out of this page.
#[must_use]
pub fn touch_down(
    view: ViewId,
    mapping: &ViewportMapping,
    seq: u32,
    window_x: f32,
    window_y: f32,
) -> Option<InputEvent> {
    touch_down_with_modifiers(view, mapping, seq, window_x, window_y, Modifiers::NONE)
}

/// Modifier-aware form of [`touch_down`].
#[must_use]
pub fn touch_down_with_modifiers(
    view: ViewId,
    mapping: &ViewportMapping,
    seq: u32,
    window_x: f32,
    window_y: f32,
    modifiers: Modifiers,
) -> Option<InputEvent> {
    let at = mapping.map_pointer(window_x, window_y)?;
    Some(InputEvent::TouchDown {
        view,
        seq,
        at,
        modifiers,
    })
}

/// Build a touch-move event, translated and clipped. `None` if outside bounds.
#[must_use]
pub fn touch_moved(
    view: ViewId,
    mapping: &ViewportMapping,
    seq: u32,
    window_x: f32,
    window_y: f32,
) -> Option<InputEvent> {
    touch_moved_with_modifiers(view, mapping, seq, window_x, window_y, Modifiers::NONE)
}

/// Modifier-aware form of [`touch_moved`].
#[must_use]
pub fn touch_moved_with_modifiers(
    view: ViewId,
    mapping: &ViewportMapping,
    seq: u32,
    window_x: f32,
    window_y: f32,
    modifiers: Modifiers,
) -> Option<InputEvent> {
    let at = mapping.map_pointer(window_x, window_y)?;
    Some(InputEvent::TouchMoved {
        view,
        seq,
        at,
        modifiers,
    })
}

/// Build a touch-up event, translated and clipped. `None` if outside bounds.
#[must_use]
pub fn touch_up(
    view: ViewId,
    mapping: &ViewportMapping,
    seq: u32,
    window_x: f32,
    window_y: f32,
) -> Option<InputEvent> {
    touch_up_with_modifiers(view, mapping, seq, window_x, window_y, Modifiers::NONE)
}

/// Modifier-aware form of [`touch_up`].
#[must_use]
pub fn touch_up_with_modifiers(
    view: ViewId,
    mapping: &ViewportMapping,
    seq: u32,
    window_x: f32,
    window_y: f32,
    modifiers: Modifiers,
) -> Option<InputEvent> {
    let at = mapping.map_pointer(window_x, window_y)?;
    Some(InputEvent::TouchUp {
        view,
        seq,
        at,
        modifiers,
    })
}

/// Build a touch-move/up event under an implicit grab - not clipped, so a
/// drag started inside continues even when the finger crosses the widget
/// boundary. See [`pointer_moved_grabbed`] for the pointer analogue.
#[must_use]
pub fn touch_moved_grabbed(
    view: ViewId,
    mapping: &ViewportMapping,
    seq: u32,
    window_x: f32,
    window_y: f32,
    modifiers: Modifiers,
) -> InputEvent {
    let at = mapping.to_view(window_x, window_y);
    InputEvent::TouchMoved {
        view,
        seq,
        at,
        modifiers,
    }
}

/// Build a touch-up event under an implicit grab; not clipped. See
/// [`pointer_moved_grabbed`].
#[must_use]
pub fn touch_up_grabbed(
    view: ViewId,
    mapping: &ViewportMapping,
    seq: u32,
    window_x: f32,
    window_y: f32,
    modifiers: Modifiers,
) -> InputEvent {
    let at = mapping.to_view(window_x, window_y);
    InputEvent::TouchUp {
        view,
        seq,
        at,
        modifiers,
    }
}

/// Build a touch-cancel event; no position (cancellation is identity-only).
#[must_use]
pub fn touch_cancel(view: ViewId, seq: u32, modifiers: Modifiers) -> InputEvent {
    InputEvent::TouchCancel {
        view,
        seq,
        modifiers,
    }
}

/// Build precise logical-pixel scrolling at the view origin without clipping.
/// Use [`wheel_scrolled_at_with_modifiers`] for cursor-targeted wheel input.
/// Output scale is not applied to either helper's deltas.
#[must_use]
pub fn wheel_scrolled(
    view: ViewId,
    mapping: &ViewportMapping,
    delta_x: f32,
    delta_y: f32,
) -> InputEvent {
    wheel_scrolled_with_modifiers(view, mapping, delta_x, delta_y, Modifiers::NONE)
}

/// Modifier-aware form of [`wheel_scrolled`].
#[must_use]
pub fn wheel_scrolled_with_modifiers(
    view: ViewId,
    mapping: &ViewportMapping,
    delta_x: f32,
    delta_y: f32,
    modifiers: Modifiers,
) -> InputEvent {
    let (delta_x, delta_y) = mapping.map_delta(delta_x, delta_y);
    InputEvent::WheelScrolled {
        view,
        delta_x,
        delta_y,
        modifiers,
    }
}

/// Build positioned wheel input from a clipped window-logical cursor.
/// The delta retains its unit and is never multiplied by output scale.
#[must_use]
#[allow(
    clippy::too_many_arguments,
    reason = "coordinates, delta, unit and modifiers are separate fields in the public input API"
)]
pub fn wheel_scrolled_at_with_modifiers(
    view: ViewId,
    mapping: &ViewportMapping,
    window_x: f32,
    window_y: f32,
    delta_x: f32,
    delta_y: f32,
    unit: ScrollUnit,
    modifiers: Modifiers,
) -> Option<InputEvent> {
    let at = mapping.map_pointer(window_x, window_y)?;
    let (delta_x, delta_y) = mapping.map_delta(delta_x, delta_y);
    Some(InputEvent::WheelScrolledAt {
        view,
        at,
        delta_x,
        delta_y,
        unit,
        modifiers,
    })
}

/// Convert an iced composition caret from a Rust byte offset to the
/// UTF-16 code-unit offset WebKit indexes compositions with.
///
/// # Why a conversion exists at all
///
/// The two sides of this seam count text differently and both call the result
/// "the cursor offset":
///
/// * iced/winit carry `iced_core::input_method::Preedit::selection` as a
///   `Range<usize>` of bytes into a Rust `String`.
/// * WebKit's `InputMethodFilter::preeditChanged` (verified against
///   `Source/WebKit/UIProcess/API/glib/InputMethodFilter.cpp`) does
///   `m_preedit.cursorOffset = std::min(cursorOffset, m_preedit.text.length())`
///   and then `EditingRange(m_preedit.cursorOffset, 1)`. `WTF::String::length()`
///   counts UTF-16 code units, so both the clamp and the DOM composition
///   selection are UTF-16 indexed.
///
/// Three plausible-looking values differ for the same caret, which is why this
/// is a real defect and not a rename. For `"\u{1d11e}\u{306b}"` with the caret
/// after the second character: the byte offset is `7`, `chars().count()` is `2`,
/// and the correct UTF-16 offset is `3` (the astral character is a surrogate
/// pair). Passing the byte offset lands past the end (WebKit clamps to 3 here
/// only by luck of the string being short); passing the char count puts the
/// caret inside the first character.
///
/// `caret` is `None` when the IME placed no selection, which iced documents as
/// "caret at the end of the preedit". A byte offset that is out of range or
/// lands mid-sequence is clamped and floored to a char boundary rather than
/// panicking: it arrives from another process's IME.
#[must_use]
pub fn utf16_caret(text: &str, caret: Option<usize>) -> u32 {
    let mut byte = caret.unwrap_or(text.len()).min(text.len());
    while byte > 0 && !text.is_char_boundary(byte) {
        byte -= 1;
    }
    let units = text[..byte].encode_utf16().count();
    u32::try_from(units).unwrap_or(u32::MAX)
}
