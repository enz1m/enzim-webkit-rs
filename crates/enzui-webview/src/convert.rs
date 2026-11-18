//! The edge between the toolkit-neutral web engine and iced plus enzUI
//! semantics: each conversion in one place, so the widget and its hosts
//! never mix the two vocabularies.

use enzui_core::semantics::{Role, Semantics};
use enzui_webkit::page_a11y::{PageRole, PageSemantics};
use enzui_webkit::web::{PageCursor, Preedit, Purpose, ToolkitImeEvent};
use iced::advanced::input_method;
use iced::advanced::mouse::Interaction;

/// The enzUI media frame for an engine frame, moving its pixels.
///
/// # Panics
///
/// Never: the engine checked the same geometry rules when it built the frame.
#[must_use]
pub fn media_frame(frame: enzui_webkit::frame::Rgba8Frame) -> enzui_core::media::Rgba8Frame {
    let generation = enzui_core::media::Generation::from_raw(frame.generation().raw());
    let seq = enzui_core::frame_plan::FrameSeq(frame.seq().0);
    let (width, height) = (frame.width(), frame.height());
    enzui_core::media::Rgba8Frame::new(generation, seq, width, height, frame.into_pixels())
        .expect("the engine checked this frame's geometry")
}

/// The engine's frame-source generation for a host's media generation.
#[must_use]
pub fn engine_generation(
    generation: enzui_core::media::Generation,
) -> enzui_webkit::frame::Generation {
    enzui_webkit::frame::Generation::from_raw(generation.raw())
}

/// The enzUI traversal for the engine's.
#[must_use]
pub fn core_traversal(traversal: enzui_webkit::web::Traversal) -> enzui_core::focus::Traversal {
    match traversal {
        enzui_webkit::web::Traversal::Next => enzui_core::focus::Traversal::Next,
        enzui_webkit::web::Traversal::Previous => enzui_core::focus::Traversal::Previous,
    }
}

/// The engine's traversal for enzUI's.
#[must_use]
pub fn engine_traversal(traversal: enzui_core::focus::Traversal) -> enzui_webkit::web::Traversal {
    match traversal {
        enzui_core::focus::Traversal::Next => enzui_webkit::web::Traversal::Next,
        enzui_core::focus::Traversal::Previous => enzui_webkit::web::Traversal::Previous,
    }
}

/// The iced cursor for a page's requested cursor.
#[must_use]
pub fn interaction(cursor: PageCursor) -> Interaction {
    match cursor {
        PageCursor::Idle => Interaction::Idle,
        PageCursor::Hidden => Interaction::Hidden,
        PageCursor::ContextMenu => Interaction::ContextMenu,
        PageCursor::Help => Interaction::Help,
        PageCursor::Pointer => Interaction::Pointer,
        PageCursor::Progress => Interaction::Progress,
        PageCursor::Wait => Interaction::Wait,
        PageCursor::Cell => Interaction::Cell,
        PageCursor::Crosshair => Interaction::Crosshair,
        PageCursor::Text => Interaction::Text,
        PageCursor::Alias => Interaction::Alias,
        PageCursor::Copy => Interaction::Copy,
        PageCursor::Move => Interaction::Move,
        PageCursor::NoDrop => Interaction::NoDrop,
        PageCursor::NotAllowed => Interaction::NotAllowed,
        PageCursor::Grab => Interaction::Grab,
        PageCursor::Grabbing => Interaction::Grabbing,
        PageCursor::ResizingHorizontally => Interaction::ResizingHorizontally,
        PageCursor::ResizingVertically => Interaction::ResizingVertically,
        PageCursor::ResizingDiagonallyUp => Interaction::ResizingDiagonallyUp,
        PageCursor::ResizingDiagonallyDown => Interaction::ResizingDiagonallyDown,
        PageCursor::AllScroll => Interaction::AllScroll,
        PageCursor::ZoomIn => Interaction::ZoomIn,
        PageCursor::ZoomOut => Interaction::ZoomOut,
    }
}

/// The iced input-method purpose for a page field's purpose.
#[must_use]
pub fn purpose(purpose: Purpose) -> input_method::Purpose {
    match purpose {
        Purpose::Normal => input_method::Purpose::Normal,
        Purpose::Secure => input_method::Purpose::Secure,
        Purpose::Terminal => input_method::Purpose::Terminal,
    }
}

/// The iced composition for a page's preedit; iced picks the text size.
#[must_use]
pub fn preedit(preedit: &Preedit) -> input_method::Preedit {
    input_method::Preedit {
        content: preedit.content.clone(),
        selection: preedit.selection.clone(),
        text_size: None,
    }
}

/// The engine's form of a window input-method event.
#[must_use]
pub fn toolkit_ime_event(event: &input_method::Event) -> ToolkitImeEvent {
    match event {
        input_method::Event::Opened => ToolkitImeEvent::Opened,
        input_method::Event::Preedit(text, selection) => {
            ToolkitImeEvent::Preedit(text.clone(), selection.clone())
        }
        input_method::Event::Commit(text) => ToolkitImeEvent::Commit(text.clone()),
        input_method::Event::Closed => ToolkitImeEvent::Closed,
    }
}

/// The enzUI role for a page node's role.
#[must_use]
pub fn role(role: PageRole) -> Role {
    match role {
        PageRole::Button => Role::Button,
        PageRole::CheckBox => Role::CheckBox,
        PageRole::ColumnHeader => Role::ColumnHeader,
        PageRole::ComboBox => Role::ComboBox,
        PageRole::Grid => Role::Grid,
        PageRole::GridCell => Role::GridCell,
        PageRole::GridRow => Role::GridRow,
        PageRole::Group => Role::Group,
        PageRole::Heading => Role::Heading,
        PageRole::Image => Role::Image,
        PageRole::Label => Role::Label,
        PageRole::Link => Role::Link,
        PageRole::ListItem => Role::ListItem,
        PageRole::PasswordInput => Role::PasswordInput,
        PageRole::ProgressIndicator => Role::ProgressIndicator,
        PageRole::RadioButton => Role::RadioButton,
        PageRole::Slider => Role::Slider,
        PageRole::Switch => Role::Switch,
        PageRole::TextInput => Role::TextInput,
    }
}

/// The enzUI semantics a page node publishes.
pub fn semantics(page: &PageSemantics) -> Semantics {
    let mut semantics = Semantics::new(role(page.role));
    if let Some(label) = &page.label {
        semantics = semantics.label(label.clone());
    }
    if page.supports_default_action {
        semantics = semantics.default_action();
    }
    semantics
}
