//! Frame-scoped secret messaging: which frame and document posted a protected
//! message, from WebKit's own records, and evaluation bound to that document,
//! so a credential bridge can serve a sign-in form in a cross-origin frame.
use super::*;
use crate::page::FrameDocument;
use crate::site_permissions::PermissionOrigin;

#[link(name = "dl")]
unsafe extern "C" {
    fn dlsym(handle: *mut c_void, name: *const c_char) -> *mut c_void;
}

type MessageFrame = unsafe extern "C" fn(
    *mut WebKitUserContentManager,
    *mut u64,
    *mut *const c_char,
    *mut *const c_char,
    *mut *const c_char,
    *mut ffi::GBoolean,
) -> ffi::GBoolean;
type EvaluateInFrame = unsafe extern "C" fn(
    *mut ffi::WebKitWebView,
    u64,
    *const c_char,
    *const c_char,
    isize,
    *const c_char,
    *mut c_void,
    AsyncReady,
    *mut c_void,
);

/// The longest document identifier accepted from WebKit.
const MAX_DOCUMENT_ID_BYTES: usize = 128;

pub(super) fn symbol(name: &core::ffi::CStr) -> *mut c_void {
    // SAFETY: a fixed fork symbol is resolved from already loaded native libraries.
    unsafe { dlsym(core::ptr::null_mut(), name.as_ptr()) }
}

fn api() -> Option<(MessageFrame, EvaluateInFrame)> {
    static API: std::sync::OnceLock<Option<(MessageFrame, EvaluateInFrame)>> =
        std::sync::OnceLock::new();
    *API.get_or_init(|| {
        let source = symbol(c"webkit_user_content_manager_enzui_message_frame_v1");
        let evaluate = symbol(c"webkit_web_view_enzui_evaluate_in_frame_v1");
        // SAFETY: both functions use the reviewed fork's exact C ABI.
        (!source.is_null() && !evaluate.is_null()).then(|| unsafe {
            (
                std::mem::transmute::<*mut c_void, MessageFrame>(source),
                std::mem::transmute::<*mut c_void, EvaluateInFrame>(evaluate),
            )
        })
    })
}

/// Whether the runtime reports message frames and evaluates in frames.
pub(super) fn available() -> bool {
    api().is_some()
}

pub(super) struct MessageSource {
    pub(super) frame: FrameDocument,
    pub(super) origin: PermissionOrigin,
    pub(super) top_origin: PermissionOrigin,
    pub(super) main_frame: bool,
}

fn https_origin(text: *const c_char) -> Option<PermissionOrigin> {
    // SAFETY: WebKit's NUL-terminated string, borrowed for the emission.
    let text = unsafe { native_text(text) }?;
    PermissionOrigin::parse(&text).filter(|origin| origin.as_str().starts_with("https://"))
}

/// The frame, document and origins of the message being delivered; `None` when
/// either origin is not HTTPS.
///
/// # Safety
/// Called inside a `script-message-received` emission of the live `manager`.
pub(super) unsafe fn message_source(
    manager: *mut WebKitUserContentManager,
) -> Option<MessageSource> {
    let (source, _) = api()?;
    let mut frame = 0;
    let mut document = core::ptr::null();
    let mut origin = core::ptr::null();
    let mut top_origin = core::ptr::null();
    let mut main_frame = ffi::G_FALSE;
    // SAFETY: the out pointers are valid; the strings are borrowed for the emission.
    let found = unsafe {
        source(
            manager,
            &mut frame,
            &mut document,
            &mut origin,
            &mut top_origin,
            &mut main_frame,
        )
    };
    if found == ffi::G_FALSE {
        return None;
    }
    // SAFETY: as above.
    let document = unsafe { native_text(document) }
        .filter(|document| !document.is_empty() && document.len() <= MAX_DOCUMENT_ID_BYTES)?;
    Some(MessageSource {
        frame: FrameDocument { frame, document },
        origin: https_origin(origin)?,
        top_origin: https_origin(top_origin)?,
        main_frame: main_frame != ffi::G_FALSE,
    })
}

impl PageBinding {
    pub(crate) fn evaluate_secret_in_frame(
        &self,
        frame: &FrameDocument,
        source: &SecretText,
        world_name: &str,
    ) -> Result<SecretScriptJob, ScriptInputError> {
        let world = script_world_name(&ScriptWorld::Isolated(world_name.to_owned()))?
            .ok_or(ScriptInputError::EmptyWorld)?;
        self.ensure_evaluation_world(&world)?;
        let state = Rc::new(SecretScriptState {
            value: RefCell::new(None),
            hub: Rc::downgrade(&self.hub),
            generation: self.hub.state.borrow().load_generation,
            navigation_intent: self.hub.navigation_intent(),
        });
        let job = SecretScriptJob {
            state: Rc::clone(&state),
            finished: false,
        };
        let (Some((_, evaluate)), Ok(document)) = (api(), CString::new(frame.document.as_str()))
        else {
            *state.value.borrow_mut() = Some(Err(ScriptError::Unavailable));
            return Ok(job);
        };
        let data = Box::into_raw(Box::new(AsyncData {
            preview: false,
            hub: Rc::downgrade(&self.hub),
            id: self.hub.mint(),
            private_reply: None,
            secret_reply: Some(Rc::downgrade(&state)),
        }));
        let source = source.expose_secret();
        // SAFETY: the live view copies the length-delimited source and the
        // strings; its cancellable callback reclaims data exactly once, even
        // after view drop.
        unsafe {
            evaluate(
                self.web_view,
                frame.frame,
                document.as_ptr(),
                source.as_ptr().cast(),
                source.len() as isize,
                world.as_ptr(),
                self.cancellable,
                on_script_finished,
                data.cast(),
            );
        }
        Ok(job)
    }
}
