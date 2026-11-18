//! Resolve native WPE link flags and build the platform and credential-guard helpers.
//!
//! Feature-off builds perform no native probes or compilation. Feature-on
//! builds refuse an absent or incompatible SDK before compiling native code.

pub(crate) fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_PATH");

    #[cfg(feature = "wpe")]
    {
        // Probe the two libraries the FFI actually calls into. `probe` emits the
        // linker flags on stdout via cargo directives; a missing library is a
        // hard build failure (as it must be - see the module docs).
        //
        // `wpe-webkit-2.0` provides `libWPEWebKit-2.0.so` and (via
        // wpe-platform.h) `WPEDisplayHeadless`, `WPEBufferSHM`, etc.
        let webkit = pkg_config::Config::new()
            .atleast_version("2.52") // WebKitImage snapshots require the 2.52 ABI.
            .probe("wpe-webkit-2.0")
            .expect(
                "the `wpe` feature requires WPE WebKit 2.52 or newer for WebKitImage \
                 snapshots. pkg-config could not find a compatible wpe-webkit-2.0. \
                 Install matching development headers and libraries, or build without \
                 --features wpe.",
            );

        // The WPE Platform APIs (WPEDisplayHeadless etc.) live in the same
        // shared object but are exposed by their own .pc file so a caller can
        // link only the platform if it wants. This code links both so the crate is
        // self-sufficient.
        let platform = pkg_config::Config::new()
            .atleast_version("2.50") // WPEDisplay input-device declarations.
            .probe("wpe-platform-2.0")
            .expect(
                "the `wpe` feature requires `wpe-platform-2.0 >= 2.50`. \
                 The headless display used by the smoke test needs the WPE Platform \
                 API. Install the same package that provides wpe-webkit-2.0.",
            );

        // The WPE Platform headless plugin ships as a loadable module the WPE
        // Platform loader dlopens at runtime; there is no linker flag for it,
        // only a check that its .pc file exists (so a `wpe` build that will
        // fail at run time fails at build time instead).
        pkg_config::Config::new()
            .atleast_version("2.48")
            .probe("wpe-platform-headless-2.0")
            .expect(
                "the `wpe` feature is enabled but `wpe-platform-headless-2.0` is not \
                 installed. The headless smoke test needs this plugin to construct a \
                 WPEDisplay without a compositor.",
            );

        // `decide-policy` sees an HTTPS redirect only after WebKit has
        // normalised away URL userinfo. Build the tiny WebProcess extension
        // that owns WebKitWebPage::send-request, the documented synchronous,
        // cancellable pre-network boundary in the installed 2.52 ABI. Keeping
        // this as a standalone module is required: that signal exists in the
        // sandboxed WebProcess, not in this UI-process Rust library.
        println!("cargo:rerun-if-changed=native/credential_guard_extension.c");
        // Cargo tracks only the inputs a build script declares, so an
        // undeclared `CC` leaves the guard and the parser vectors below cached
        // from whichever compiler ran first.
        println!("cargo:rerun-if-env-changed=CC");
        let out_dir = std::path::PathBuf::from(
            std::env::var_os("OUT_DIR").expect("build scripts always receive OUT_DIR"),
        );
        println!("cargo:rerun-if-changed=native/presentation.c");
        let object = out_dir.join("presentation.o");
        let archive = out_dir.join("libenzui_wpe_presentation.a");
        let mut compiler =
            std::process::Command::new(std::env::var_os("CC").unwrap_or_else(|| "cc".into()));
        compiler
            .args([
                "-c",
                "-fPIC",
                "-O2",
                "-Wall",
                "-Wextra",
                "-Werror",
                "native/presentation.c",
                "-o",
            ])
            .arg(&object);
        for include in &platform.include_paths {
            compiler.arg("-I").arg(include);
        }
        assert!(
            compiler
                .status()
                .expect("presentation C compiler")
                .success(),
            "WPE presentation shim compilation failed"
        );
        println!("cargo:rerun-if-env-changed=AR");
        assert!(
            std::process::Command::new(std::env::var_os("AR").unwrap_or_else(|| "ar".into()))
                .arg("crs")
                .arg(&archive)
                .arg(&object)
                .status()
                .expect("presentation archiver")
                .success(),
            "WPE presentation archive failed"
        );
        println!("cargo:rustc-link-search=native={}", out_dir.display());
        println!("cargo:rustc-link-lib=static=enzui_wpe_presentation");
        let extension = out_dir.join("libenzui_credential_guard.so");
        let mut command =
            std::process::Command::new(std::env::var_os("CC").unwrap_or_else(|| "cc".into()));
        command
            .arg("-shared")
            .arg("-fPIC")
            .arg("-O2")
            .arg("-o")
            .arg(&extension)
            .arg("native/credential_guard_extension.c");
        for include in &webkit.include_paths {
            command.arg("-I").arg(include);
        }
        for path in &webkit.link_paths {
            command.arg("-L").arg(path);
        }
        for library in &webkit.libs {
            command.arg(format!("-l{library}"));
        }
        let status = command
            .status()
            .expect("failed to execute C compiler for the WPE credential guard extension");
        assert!(
            status.success(),
            "C compiler failed to build the WPE credential guard extension"
        );

        // Compile and execute the parser-only branch against static WHATWG
        // vectors. This makes slash/backslash or leading-C0 drift fail the WPE
        // build without printing any tested URL (and therefore no userinfo).
        let parser_test = out_dir.join("credential_guard_parser_test");
        let mut parser_command =
            std::process::Command::new(std::env::var_os("CC").unwrap_or_else(|| "cc".into()));
        parser_command
            .arg("-O2")
            .arg("-DENZUI_CREDENTIAL_GUARD_PARSER_TEST")
            .arg("-o")
            .arg(&parser_test)
            .arg("native/credential_guard_extension.c");
        for include in &webkit.include_paths {
            parser_command.arg("-I").arg(include);
        }
        for path in &webkit.link_paths {
            parser_command.arg("-L").arg(path);
        }
        for library in &webkit.libs {
            parser_command.arg(format!("-l{library}"));
        }
        let parser_status = parser_command
            .status()
            .expect("failed to compile WPE credential guard parser vectors");
        assert!(
            parser_status.success(),
            "C compiler failed to build the WPE credential guard parser vectors"
        );
        let parser_status = std::process::Command::new(&parser_test)
            .status()
            .expect("failed to execute WPE credential guard parser vectors");
        assert!(
            parser_status.success(),
            "WPE credential guard parser vector failed (exit status only; URL withheld)"
        );

        println!(
            "cargo:rustc-env=ENZUI_WPE_EXTENSION_DIR={}",
            out_dir.display()
        );
    }
}
