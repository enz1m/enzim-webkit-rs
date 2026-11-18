//! Bounded latest-frame planning for web views.
//!
//! This specializes [`crate::frame_plan::FramePlan`] with web-view generations; recreation starts blank.

use crate::frame_plan;
use crate::web::view_id::Generation;

/// A web-view frame plan: the shared [`crate::frame_plan::FramePlan`] keyed on
/// the web-view [`Generation`].
pub type FramePlan = frame_plan::FramePlan<Generation>;

/// The verdict of offering a frame to a web-view [`FramePlan`].
pub type FrameVerdict = frame_plan::FrameVerdict<Generation>;

pub use crate::frame_plan::{FrameBounds, FrameSeq};
