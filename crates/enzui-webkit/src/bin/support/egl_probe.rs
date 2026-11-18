use core::ffi::{c_int, c_uint, c_void};
use enzui_webkit::ffi::presentation::DmaBufFrame;
use std::os::fd::AsRawFd;

#[link(name = "EGL")]
unsafe extern "C" {
    fn eglBindAPI(api: c_uint) -> c_uint;
    fn eglChooseConfig(
        display: *mut c_void,
        attributes: *const c_int,
        config: *mut *mut c_void,
        count: c_int,
        found: *mut c_int,
    ) -> c_uint;
    fn eglCreateContext(
        display: *mut c_void,
        config: *mut c_void,
        shared: *mut c_void,
        attributes: *const c_int,
    ) -> *mut c_void;
    fn eglMakeCurrent(
        display: *mut c_void,
        draw: *mut c_void,
        read: *mut c_void,
        context: *mut c_void,
    ) -> c_uint;
    fn eglDestroyContext(display: *mut c_void, context: *mut c_void) -> c_uint;
    fn eglGetProcAddress(name: *const i8) -> *const c_void;
}
#[link(name = "GLESv2")]
unsafe extern "C" {
    fn glGenTextures(count: c_int, textures: *mut c_uint);
    fn glBindTexture(target: c_uint, texture: c_uint);
    fn glDeleteTextures(count: c_int, textures: *const c_uint);
    fn glGenFramebuffers(count: c_int, buffers: *mut c_uint);
    fn glBindFramebuffer(target: c_uint, buffer: c_uint);
    fn glFramebufferTexture2D(
        target: c_uint,
        attachment: c_uint,
        texture_target: c_uint,
        texture: c_uint,
        level: c_int,
    );
    fn glCheckFramebufferStatus(target: c_uint) -> c_uint;
    fn glDeleteFramebuffers(count: c_int, buffers: *const c_uint);
    fn glReadPixels(
        x: c_int,
        y: c_int,
        width: c_int,
        height: c_int,
        format: c_uint,
        kind: c_uint,
        pixels: *mut c_void,
    );
    fn glGetError() -> c_uint;
    fn glGetString(name: c_uint) -> *const i8;
}

pub fn pixel(frame: &DmaBufFrame) -> [u8; 4] {
    let (display, _) = frame.egl_image().expect("native EGL image import");
    let mut config = std::ptr::null_mut();
    let mut found = 0;
    let mut pixel = [0_u8; 4];
    // SAFETY: WPE owns this initialized display and imported image for the live frame;
    // all temporary GL objects/context are destroyed before returning and the readback is four bytes.
    unsafe {
        assert_ne!(eglBindAPI(0x30A0), 0);
        let attributes = [0x3033, 0, 0x3040, 4, 0x3038];
        assert_ne!(
            eglChooseConfig(display, attributes.as_ptr(), &mut config, 1, &mut found),
            0
        );
        assert_eq!(found, 1);
        let context = eglCreateContext(
            display,
            config,
            std::ptr::null_mut(),
            [0x3098, 2, 0x3038].as_ptr(),
        );
        assert!(!context.is_null(), "GLES context");
        assert_ne!(
            eglMakeCurrent(display, std::ptr::null_mut(), std::ptr::null_mut(), context),
            0
        );
        let renderer = glGetString(0x1F01);
        assert!(!renderer.is_null());
        static REPORT_RENDERER: std::sync::Once = std::sync::Once::new();
        REPORT_RENDERER.call_once(|| {
            println!(
                "EGL renderer: {}",
                std::ffi::CStr::from_ptr(renderer).to_string_lossy()
            )
        });
        let mut attributes = vec![
            0x3057,
            frame.size().0 as i32,
            0x3056,
            frame.size().1 as i32,
            0x3271,
            frame.format() as i32,
        ];
        for (index, plane) in frame.planes().iter().enumerate() {
            let base = if index < 3 {
                0x3272 + index as i32 * 3
            } else {
                0x3440
            };
            attributes.extend([
                base,
                plane.fd.as_raw_fd(),
                base + 1,
                plane.offset as i32,
                base + 2,
                plane.stride as i32,
            ]);
            if frame.modifier() != u64::MAX {
                attributes.extend([
                    0x3443 + index as i32 * 2,
                    frame.modifier() as i32,
                    0x3444 + index as i32 * 2,
                    (frame.modifier() >> 32) as i32,
                ]);
            }
        }
        attributes.push(0x3038);
        let create = eglGetProcAddress(c"eglCreateImageKHR".as_ptr());
        let destroy = eglGetProcAddress(c"eglDestroyImageKHR".as_ptr());
        assert!(!create.is_null() && !destroy.is_null());
        let create: unsafe extern "C" fn(
            *mut c_void,
            *mut c_void,
            c_uint,
            *mut c_void,
            *const c_int,
        ) -> *mut c_void = std::mem::transmute(create);
        let destroy: unsafe extern "C" fn(*mut c_void, *mut c_void) -> c_uint =
            std::mem::transmute(destroy);
        let image = create(
            display,
            std::ptr::null_mut(),
            0x3270,
            std::ptr::null_mut(),
            attributes.as_ptr(),
        );
        assert!(
            !image.is_null(),
            "import the exported fd, format, modifier, offsets and strides"
        );
        let function = eglGetProcAddress(c"glEGLImageTargetTexture2DOES".as_ptr());
        assert!(!function.is_null());
        let import: unsafe extern "C" fn(c_uint, *mut c_void) = std::mem::transmute(function);
        let mut texture = 0;
        let mut framebuffer = 0;
        glGenTextures(1, &mut texture);
        glBindTexture(0x0DE1, texture);
        import(0x0DE1, image);
        glGenFramebuffers(1, &mut framebuffer);
        glBindFramebuffer(0x8D40, framebuffer);
        glFramebufferTexture2D(0x8D40, 0x8CE0, 0x0DE1, texture, 0);
        assert_eq!(glCheckFramebufferStatus(0x8D40), 0x8CD5);
        let (width, height) = frame.size();
        glReadPixels(
            (width / 2) as i32,
            (height / 2) as i32,
            1,
            1,
            0x1908,
            0x1401,
            pixel.as_mut_ptr().cast(),
        );
        assert_eq!(glGetError(), 0, "DMA-BUF texture readback");
        glDeleteFramebuffers(1, &framebuffer);
        glDeleteTextures(1, &texture);
        assert_ne!(
            eglMakeCurrent(
                display,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut()
            ),
            0
        );
        assert_ne!(destroy(display, image), 0);
        assert_ne!(eglDestroyContext(display, context), 0);
    }
    pixel
}
