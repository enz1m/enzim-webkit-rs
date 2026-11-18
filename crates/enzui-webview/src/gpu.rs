//! Generation-tagged frames for the shared DMA-BUF renderer.

#[cfg(feature = "wpe")]
use enzui_external_image::{DmaBuf, Lease, Plane};
use enzui_external_image::{ExternalFrame, Status};
use enzui_webkit::web::ViewId;
use std::sync::Arc;

#[cfg(feature = "diagnostics")]
static SHARED_NATIVE_ENCODINGS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Shared native frames whose first renderer command encoding has completed.
/// This process-wide diagnostic does not measure GPU completion or scanout.
#[cfg(feature = "diagnostics")]
pub fn shared_native_encoding_callbacks() -> u64 {
    SHARED_NATIVE_ENCODINGS.load(std::sync::atomic::Ordering::Relaxed)
}

/// A web compositor frame retained through the renderer's final GPU use.
#[derive(Clone, Debug)]
pub struct GpuFrame {
    view: ViewId,
    content: enzui_webkit::frame_damage::FrameContentInfo,
    frame: Arc<ExternalFrame>,
    #[cfg(feature = "wpe")]
    completion: enzui_webkit::ffi::presentation::GpuFrameCompletion,
}

impl GpuFrame {
    /// Wrap native descriptors for renderer import without reading pixels.
    ///
    /// `allocation` must be stable for this native buffer and disjoint from
    /// every other producer's allocations in the shared renderer. An app whose
    /// only external-image producer is WPE can use the native buffer ID.
    /// Native presentation is acknowledged immediately; the producer buffer
    /// remains leased through the renderer's final GPU use.
    #[cfg(feature = "wpe")]
    pub fn from_native(
        frame: enzui_webkit::ffi::presentation::ThreadSafeGpuFrame,
        allocation: u64,
    ) -> Self {
        let view = frame.view();
        let content = frame.content_info();
        let (width, height) = frame.size();
        let format = frame.format();
        let modifier = frame.modifier();
        let (planes, completion) = frame.into_parts();
        completion.presented();
        let buffer = DmaBuf {
            width,
            height,
            format,
            modifier,
            allocation,
            planes: planes
                .into_iter()
                .map(|plane| Plane::new(plane.fd, plane.offset, plane.stride))
                .collect(),
        };
        let discard = completion.clone();
        let frame = ExternalFrame::new(buffer, Lease::new(move || drop(completion)));
        Self {
            view,
            content,
            frame,
            completion: discard,
        }
    }

    /// Wrap shared native allocation metadata without duplicating plane descriptors.
    ///
    /// `allocation` has the same producer-identity requirements as [`Self::from_native`].
    /// Native completion is requested on first command encoding, separately from
    /// the producer lease retained through final GPU use. Call [`Self::discard`]
    /// when rejecting or superseding a frame, including an import refusal whose
    /// renderer may still retain the frame. Final drop also releases backpressure.
    #[cfg(feature = "wpe")]
    pub fn from_shared_native(
        frame: enzui_webkit::ffi::presentation::SharedGpuFrame,
        allocation: u64,
    ) -> Self {
        let view = frame.view();
        let content = frame.content_info();
        let (metadata, completion) = frame.into_parts();
        let (width, height) = metadata.size();
        let buffer = DmaBuf {
            width,
            height,
            format: metadata.format(),
            modifier: metadata.modifier(),
            allocation,
            planes: metadata
                .planes()
                .iter()
                .map(|plane| Plane {
                    fd: Arc::clone(&plane.fd),
                    offset: plane.offset,
                    stride: plane.stride,
                })
                .collect(),
        };
        let discard = completion.clone();
        let encoded = completion.clone();
        let frame = ExternalFrame::with_on_encoded(
            buffer,
            Lease::new(move || drop(completion)),
            move || {
                #[cfg(feature = "diagnostics")]
                SHARED_NATIVE_ENCODINGS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                encoded.presented();
            },
        );
        Self {
            view,
            content,
            frame,
            completion: discard,
        }
    }

    /// Resume production after refusing or superseding this presentation.
    ///
    /// This request is idempotent and does not release the producer lease.
    /// Renderer owners still retain the buffer through their final GPU use.
    pub fn discard(&self) {
        #[cfg(feature = "wpe")]
        self.completion.presented();
    }

    /// Content history for hosts with a preserved-target rendering contract.
    pub fn content_info(&self) -> enzui_webkit::frame_damage::FrameContentInfo {
        self.content
    }

    /// The exact engine view generation that supplied the frame.
    pub fn view(&self) -> ViewId {
        self.view
    }

    /// Physical pixel dimensions of the native compositor buffer.
    pub fn size(&self) -> (u32, u32) {
        (self.frame.buffer().width, self.frame.buffer().height)
    }

    /// Current import result, including an explicit software-renderer refusal.
    pub fn status(&self) -> Status {
        self.frame.status()
    }

    /// Observe whether Rust owners of this frame remain, without keeping it alive.
    /// Native buffer release additionally requires dispatch on its owning thread.
    #[cfg(feature = "diagnostics")]
    pub fn lifetime_probe(&self) -> impl Fn() -> bool + Send + Sync + 'static + use<> {
        let weak = Arc::downgrade(&self.frame);
        move || weak.strong_count() != 0
    }

    pub(crate) fn external(&self) -> &Arc<ExternalFrame> {
        &self.frame
    }
}

pub use enzui_external_image::enz_external_image_probe as renderer_probe;
pub use enzui_external_image::{
    DeviceMatch as GpuDeviceMatch, DrmDevice as GpuDrmDevice, DrmNode as GpuDrmNode,
};
pub use enzui_external_image::{Refusal as GpuRefusal, Status as GpuStatus};
pub use enzui_external_image::{Support as GpuSupport, support as renderer_support};

/// A generation-bound latest frame that wakes only its rendering windows.
///
/// Mount with [`crate::EnzWebView::gpu_source`]. Publishing same-size frames
/// permits cached scene rendering; resize and clearing still invalidate layout.
#[derive(Clone, Debug)]
pub struct GpuFrameSource {
    view: ViewId,
    source: enzui_external_image::ExternalFrameSource,
}

impl GpuFrameSource {
    /// Create an empty source for one exact engine generation.
    pub fn new(view: ViewId) -> Self {
        Self {
            view,
            source: enzui_external_image::ExternalFrameSource::new(),
        }
    }

    /// Publish a live matching frame; refuse foreign and revoked generations.
    pub fn publish(&self, frame: &GpuFrame, router: &enzui_webkit::web::ViewRouter) -> bool {
        if frame.view() != self.view || !router.accepts(self.view) {
            return false;
        }
        self.source.publish(Arc::clone(frame.external()));
        true
    }

    /// Release the queued frame and wake mounted consumers to clear it.
    pub fn clear(&self) {
        self.source.clear();
    }

    /// Exact engine generation accepted by this source.
    pub fn view(&self) -> ViewId {
        self.view
    }

    /// Dimensions of the latest queued image, or no image after clearing.
    pub fn size(&self) -> Option<(u32, u32)> {
        self.source
            .latest()
            .map(|frame| (frame.buffer().width, frame.buffer().height))
    }

    pub(crate) fn external(&self) -> &enzui_external_image::ExternalFrameSource {
        &self.source
    }
}
