//! Post-loop retirement of a bounded native operation's GLib deadline source.
//!
//! GLib may dispatch a deadline and its operation's completion from one pending
//! batch, and a dispatched deadline returned `G_SOURCE_REMOVE`, destroying its
//! source. Removing that id emits a `g_source_remove` critical, fatal under
//! `G_DEBUG=fatal-criticals`, and GLib reuses ids, so the stale removal can
//! disarm an unrelated operation's deadline.

use core::ffi::c_uint;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CompletionState {
    Pending,
    Resolved,
}

impl CompletionState {
    pub(crate) fn from_resolved(resolved: bool) -> Self {
        if resolved {
            Self::Resolved
        } else {
            Self::Pending
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DeadlineSourceState {
    Armed,
    Fired,
}

impl DeadlineSourceState {
    pub(crate) fn from_fired(fired: bool) -> Self {
        if fired { Self::Fired } else { Self::Armed }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DeadlineRetirement {
    RemoveSource,
    SelfRetired,
    AwaitCompletion,
}

impl DeadlineRetirement {
    pub(crate) fn completion_resolved(self) -> bool {
        matches!(self, Self::RemoveSource | Self::SelfRetired)
    }
}

pub(crate) fn classify_deadline_source(
    completion: CompletionState,
    deadline: DeadlineSourceState,
) -> DeadlineRetirement {
    match (completion, deadline) {
        (CompletionState::Resolved, DeadlineSourceState::Armed) => DeadlineRetirement::RemoveSource,
        (CompletionState::Resolved, DeadlineSourceState::Fired) => DeadlineRetirement::SelfRetired,
        // Only these two callbacks quit the loop, so a pending completion means
        // the operation is still outstanding and its drain owns the state box.
        (CompletionState::Pending, _) => DeadlineRetirement::AwaitCompletion,
    }
}

pub(crate) fn retire_deadline<R>(
    completion: CompletionState,
    deadline: DeadlineSourceState,
    source_id: c_uint,
    remover: &mut R,
) -> DeadlineRetirement
where
    R: SourceRemover + ?Sized,
{
    let retirement = classify_deadline_source(completion, deadline);
    if retirement == DeadlineRetirement::RemoveSource {
        remover.remove_source(source_id);
    }
    retirement
}

// Exists so a loop's retirement decision can be driven with no main context.
pub(crate) trait SourceRemover {
    fn remove_source(&mut self, source_id: c_uint);
}

#[cfg(feature = "wpe")]
pub(crate) struct NativeSourceRemover;

#[cfg(feature = "wpe")]
impl SourceRemover for NativeSourceRemover {
    fn remove_source(&mut self, source_id: c_uint) {
        // SAFETY: `retire_deadline` calls this only when the deadline source
        // has not dispatched, so `source_id` still names the timeout this
        // thread armed and GLib cannot have reused it.
        unsafe { crate::ffi::wpe::g_source_remove(source_id) };
    }
}

#[cfg(test)]
#[derive(Default)]
pub(crate) struct RecordingRemover {
    pub(crate) removed: Vec<c_uint>,
}

#[cfg(test)]
impl SourceRemover for RecordingRemover {
    fn remove_source(&mut self, source_id: c_uint) {
        self.removed.push(source_id);
    }
}
