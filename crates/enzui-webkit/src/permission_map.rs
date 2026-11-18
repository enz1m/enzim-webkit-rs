//! Classification of a WebKit media-permission request's device flags into
//! [`PermissionKind`]. Combined camera and microphone requests need both grants;
//! a request that names the display is [`PermissionKind::ScreenCapture`],
//! which only an answer to that request can allow.
//!

use crate::web::policy::PermissionKind;

/// Diagnostic tag for a media request that named no device: neither audio,
/// video nor display. Zero preserves the tag this case has always reported.
pub const NO_DEVICE_TAG: u32 = 0;

/// The three device flags a `WebKitUserMediaPermissionRequest` carries, read
/// independently. Every field is read at the FFI seam before any of them is
/// interpreted - the whole point is that no flag short-circuits another.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MediaCaptureFlags {
    /// `webkit_user_media_permission_is_for_audio_device`.
    pub audio: bool,
    /// `webkit_user_media_permission_is_for_video_device`.
    pub video: bool,
    /// `webkit_user_media_permission_is_for_display_device`.
    ///
    /// Fails closed when it cannot be determined: the caller must pass
    /// `true` (not `false`) if the native flag is unavailable, so an
    /// unclassifiable screen-share request is refused rather than treated as a
    /// plain camera request.
    pub display: bool,
}

impl MediaCaptureFlags {
    /// The flags of a request naming the given devices.
    #[must_use]
    pub const fn new(audio: bool, video: bool, display: bool) -> Self {
        Self {
            audio,
            video,
            display,
        }
    }
}

/// Classify one user-media request from its device flags.
///
/// See the module docs for the table. This is total, deterministic and pure:
/// the same flags always produce the same kind, and every kind it can produce
/// is judged by the core allow-list.
#[must_use]
pub const fn user_media_kind(flags: MediaCaptureFlags) -> PermissionKind {
    if flags.display {
        // Whatever else it names, a request for the display is judged as one:
        // a camera grant must never let a page see the screen, and the audio
        // of a shared surface is not the microphone.
        return PermissionKind::ScreenCapture;
    }
    match (flags.audio, flags.video) {
        (true, true) => PermissionKind::CameraAndMicrophone,
        (false, true) => PermissionKind::Camera,
        (true, false) => PermissionKind::Microphone,
        (false, false) => PermissionKind::Unknown(NO_DEVICE_TAG),
    }
}
