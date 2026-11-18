//! Hidden-view quiescence and orderly shutdown: a hidden view stops requesting
//! frames, and shutdown releases native owners in order.
//!

/// Whether a view is currently visible to the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewVisibility {
    /// The view is on screen; it should receive frames.
    Visible,
    /// The view is hidden (a background tab, an occluded pane); it must go
    /// quiescent and stop requesting frames.
    Hidden,
}

/// Whether the runtime should ask the engine for the next frame.
///
/// A separate type from a bare `bool` so a call site reads as the decision it is
/// ("frames are suppressed"), and so a future third state (throttled) has a home
/// without churning every caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameRequest {
    /// Request the next frame from the engine.
    Request,
    /// Do not request a frame: the view is hidden or shut down. This is the
    /// quiescent state - a suppressed request is a frame the
    /// engine is never asked to decode.
    Suppressed,
}

impl FrameRequest {
    /// Whether this is a real request (the engine will be asked for a frame).
    #[must_use]
    pub fn is_request(self) -> bool {
        matches!(self, FrameRequest::Request)
    }
}

/// The lifecycle of a single view's frame requesting and shutdown.
///
/// Tracks visibility and whether the view has been shut down, and derives from
/// those two facts whether a frame should be requested and how many buffers are
/// still held. It owns a small integer buffer count as a stand-in for real
/// buffers so the release-on-close rule is observable in a unit test without a
/// live engine; the real widget releases its frame buffers at the same point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViewLifecycle {
    visibility: ViewVisibility,
    /// Once shut down, a view never requests frames again and holds no buffers.
    shut_down: bool,
    /// The number of frame buffers currently held. A proxy for the sink's
    /// retained buffers, so shutdown ordering is testable.
    held_buffers: usize,
}

impl Default for ViewLifecycle {
    fn default() -> Self {
        Self::new()
    }
}

impl ViewLifecycle {
    /// A fresh, visible view holding no buffers.
    #[must_use]
    pub fn new() -> ViewLifecycle {
        ViewLifecycle {
            visibility: ViewVisibility::Visible,
            shut_down: false,
            held_buffers: 0,
        }
    }

    /// The current visibility.
    #[must_use]
    pub fn visibility(&self) -> ViewVisibility {
        self.visibility
    }

    /// Whether this view has been shut down.
    #[must_use]
    pub fn is_shut_down(&self) -> bool {
        self.shut_down
    }

    /// How many frame buffers the view currently holds.
    #[must_use]
    pub fn held_buffers(&self) -> usize {
        self.held_buffers
    }

    /// Record that the view acquired a frame buffer (a decoded frame retained).
    ///
    /// A shut-down view refuses to acquire buffers - nothing may re-arm a closed
    /// view. Returns whether the buffer was recorded.
    pub fn acquire_buffer(&mut self) -> bool {
        if self.shut_down {
            return false;
        }
        self.held_buffers += 1;
        true
    }

    /// Set the view's visibility. Idempotent; a shut-down view stays quiescent
    /// regardless (showing a closed view does not resurrect it).
    pub fn set_visibility(&mut self, visibility: ViewVisibility) {
        if self.shut_down {
            return;
        }
        self.visibility = visibility;
    }

    /// Whether the runtime should request the next frame for this view.
    ///
    /// The quiescence rule, as a pure function of state: a `Hidden` view or a
    /// shut-down view is [`FrameRequest::Suppressed`]; only a live `Visible`
    /// view is [`FrameRequest::Request`]. No clock is consulted.
    #[must_use]
    pub fn frame_request(&self) -> FrameRequest {
        if self.shut_down || self.visibility == ViewVisibility::Hidden {
            FrameRequest::Suppressed
        } else {
            FrameRequest::Request
        }
    }

    /// Release every held buffer, returning how many were freed.
    ///
    /// This refuses to run once the view is shut down - a closed view's
    /// buffers are not this method's to touch, and more importantly the refusal
    /// is what makes the shutdown *ordering* load-bearing: if [`shut_down`](Self::shut_down)
    /// sets the flag before calling this, the release becomes a no-op and the
    /// buffers leak. So the guard here turns an otherwise-invisible statement
    /// swap into an observable one.
    fn release_buffers(&mut self) -> usize {
        if self.shut_down {
            // A shut-down view's buffers are already considered gone; refuse to
            // account for a release that should have happened earlier.
            return 0;
        }
        let released = self.held_buffers;
        self.held_buffers = 0;
        released
    }

    /// Shut the view down: release its buffers first, then mark it closed.
    ///
    /// The ordering is the invariant. `release_buffers` (private)
    /// refuses to run on an already-shut-down view, so the buffers must be freed
    /// *before* the shutdown flag is set. Releasing after the flag is set leaves
    /// a shut-down view still holding memory - exactly the "closed-view RSS near
    /// pre-view level" failure. Returns the number of buffers released (`0` is a
    /// valid count: a view that never rendered).
    ///
    /// # The ordering, spelled out
    ///
    /// ```text
    /// let released = self.release_buffers();  // (A) free the buffers
    /// self.shut_down = true;                  // (B) THEN signal shutdown
    /// ```
    ///
    /// Swapping (A) and (B) - signalling shutdown before releasing - makes
    /// `release_buffers` a no-op that returns 0 and leaves `held_buffers`
    /// non-zero. It is caught by
    /// `crate::visibility::tests::shutdown_releases_buffers_before_signalling`.
    pub fn shut_down(&mut self) -> usize {
        // (A) Release the buffers FIRST, while the view is still live enough for
        //     release_buffers to act.
        let released = self.release_buffers();
        // (B) Only then signal shutdown.
        self.shut_down = true;
        released
    }
}
