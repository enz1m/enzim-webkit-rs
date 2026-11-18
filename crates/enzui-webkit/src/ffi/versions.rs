//! Versions of the native libraries loaded into this process.

/// Loaded native versions, independent of SDK metadata used during compilation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeRuntimeVersions {
    /// WPE WebKit major, minor and micro versions.
    pub webkit: [u32; 3],
    /// WPEPlatform major, minor and micro versions.
    pub platform: [u32; 3],
    /// libsoup major, minor and micro versions.
    pub network: [u32; 3],
}

unsafe extern "C" {
    fn webkit_get_major_version() -> u32;
    fn webkit_get_minor_version() -> u32;
    fn webkit_get_micro_version() -> u32;
    fn wpe_platform_get_major_version() -> u32;
    fn wpe_platform_get_minor_version() -> u32;
    fn wpe_platform_get_micro_version() -> u32;
    fn soup_get_major_version() -> u32;
    fn soup_get_minor_version() -> u32;
    fn soup_get_micro_version() -> u32;
}

/// Query loaded native versions without initializing or claiming the WPE runtime.
pub fn native_runtime_versions() -> NativeRuntimeVersions {
    // SAFETY: these native accessors return compile-time constants without global initialization.
    unsafe {
        NativeRuntimeVersions {
            webkit: [
                webkit_get_major_version(),
                webkit_get_minor_version(),
                webkit_get_micro_version(),
            ],
            platform: [
                wpe_platform_get_major_version(),
                wpe_platform_get_minor_version(),
                wpe_platform_get_micro_version(),
            ],
            network: [
                soup_get_major_version(),
                soup_get_minor_version(),
                soup_get_micro_version(),
            ],
        }
    }
}
