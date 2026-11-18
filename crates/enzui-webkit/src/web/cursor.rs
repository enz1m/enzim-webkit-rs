//! CSS/WPE cursor-name translation into a toolkit-neutral [`PageCursor`].
//!
//! Unknown names use [`PageCursor::Idle`], while an absent page request is handled by the caller.

/// The pointer shape a page asks for, decoded from its CSS cursor name. A
/// host maps it onto its toolkit's cursor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PageCursor {
    /// The default arrow (`default`, and any unknown name).
    Idle,
    /// No visible pointer (`none`).
    Hidden,
    /// `context-menu`.
    ContextMenu,
    /// `help`.
    Help,
    /// A link or button (`pointer`).
    Pointer,
    /// Busy, still interactive (`progress`).
    Progress,
    /// Busy (`wait`).
    Wait,
    /// `cell`.
    Cell,
    /// `crosshair`.
    Crosshair,
    /// A text insertion bar (`text`, `vertical-text`).
    Text,
    /// `alias`.
    Alias,
    /// `copy`.
    Copy,
    /// `move`.
    Move,
    /// `no-drop`.
    NoDrop,
    /// `not-allowed`.
    NotAllowed,
    /// `grab`.
    Grab,
    /// `grabbing`.
    Grabbing,
    /// `ew-resize`, `col-resize`.
    ResizingHorizontally,
    /// `ns-resize`, `row-resize`.
    ResizingVertically,
    /// `nesw-resize`, `ne-resize`, `sw-resize`.
    ResizingDiagonallyUp,
    /// `nwse-resize`, `nw-resize`, `se-resize`.
    ResizingDiagonallyDown,
    /// `all-scroll`.
    AllScroll,
    /// `zoom-in`.
    ZoomIn,
    /// `zoom-out`.
    ZoomOut,
}

/// The sentinel [`crate::web`]'s engine records for WPE's "hide the cursor"
/// request (a NULL cursor name). A real CSS name can never collide with it
/// because it starts with a NUL byte.
pub const HIDDEN_CURSOR_SENTINEL: &str = "\u{0}hidden";

/// Translates a WPE/CSS cursor name, returning [`PageCursor::Idle`] for unknown names.
#[must_use]
pub fn page_cursor(name: &str) -> PageCursor {
    match name {
        HIDDEN_CURSOR_SENTINEL | "none" => PageCursor::Hidden,
        "default" => PageCursor::Idle,
        "context-menu" => PageCursor::ContextMenu,
        "help" => PageCursor::Help,
        "pointer" => PageCursor::Pointer,
        "progress" => PageCursor::Progress,
        "wait" => PageCursor::Wait,
        "cell" => PageCursor::Cell,
        "crosshair" => PageCursor::Crosshair,
        "text" | "vertical-text" => PageCursor::Text,
        "alias" => PageCursor::Alias,
        "copy" => PageCursor::Copy,
        "move" => PageCursor::Move,
        "no-drop" => PageCursor::NoDrop,
        "not-allowed" => PageCursor::NotAllowed,
        "grab" => PageCursor::Grab,
        "grabbing" => PageCursor::Grabbing,
        "ew-resize" | "col-resize" => PageCursor::ResizingHorizontally,
        "ns-resize" | "row-resize" => PageCursor::ResizingVertically,
        "nesw-resize" | "ne-resize" | "sw-resize" => PageCursor::ResizingDiagonallyUp,
        "nwse-resize" | "nw-resize" | "se-resize" => PageCursor::ResizingDiagonallyDown,
        "all-scroll" => PageCursor::AllScroll,
        "zoom-in" => PageCursor::ZoomIn,
        "zoom-out" => PageCursor::ZoomOut,
        _ => PageCursor::Idle,
    }
}

/// Reports whether `name` is explicitly recognized, distinguishing `default` from an unknown name.
#[must_use]
pub fn is_known_page_cursor(name: &str) -> bool {
    !matches!(page_cursor(name), PageCursor::Idle) || name == "default"
}
