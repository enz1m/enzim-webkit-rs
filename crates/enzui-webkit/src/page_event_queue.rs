use std::collections::VecDeque;

use crate::page::{PageEvent, PageRequestId};

pub(crate) fn eviction_index(
    events: &VecDeque<PageEvent>,
    pending: impl Fn(PageRequestId) -> bool,
) -> Option<usize> {
    events.iter().position(|event| {
        let id = match event {
            PageEvent::PermissionRequested(request) => Some(request.id),
            PageEvent::ScriptDialog(request) => Some(request.id),
            PageEvent::FileChooser(request) => Some(request.id),
            PageEvent::Authentication(request) => Some(request.id),
            PageEvent::OptionMenu(request) => Some(request.id),
            _ => None,
        };
        id.is_none_or(|id| !pending(id))
    })
}
