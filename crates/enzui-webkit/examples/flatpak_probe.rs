//! Render a page using a shared Flatpak engine and an application-local guard.

use enzui_webkit::ffi::deployment::{
    configure_flatpak_application, credential_guard_build_directory, set_application_id,
    set_credential_guard_directory,
};
use enzui_webkit::ffi::runtime::{HeadlessDisplay, WebSession};
use enzui_webkit::frame::Generation;
use enzui_webkit::frame_plan::FrameSeq;
use enzui_webkit::page::{PageEvent, ScriptWorld};
use enzui_webkit::sandbox::OuterSandbox;
use enzui_webkit::viewport::ViewportSize;
use enzui_webkit::web::ViewRouter;
use std::error::Error;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::time::{Duration, Instant};

fn evaluate(session: &WebSession, script: &str) -> Result<String, Box<dyn Error>> {
    let id = session.evaluate_script(script, &ScriptWorld::Isolated("flatpak-example".into()))?;
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        session.pump(5);
        for event in session.take_page_events() {
            if let PageEvent::ScriptResult { id: found, result } = event
                && found == id
            {
                return result.map_err(|error| format!("script failed: {error:?}").into());
            }
        }
    }
    Err("script execution timed out".into())
}

fn main() -> Result<(), Box<dyn Error>> {
    if std::env::args().any(|arg| arg == "--print-wpe-guard-directory") {
        println!("{}", credential_guard_build_directory().display());
        return Ok(());
    }
    let flatpak = std::fs::read_to_string("/.flatpak-info")?;
    let application = flatpak
        .lines()
        .find_map(|line| line.strip_prefix("name="))
        .ok_or("missing application identity")?;
    let prefix = PathBuf::from(std::env::var("ENZIM_WEBKIT_RUNTIME")?);
    let executable = std::env::current_exe()?;
    let app_prefix = executable
        .parent()
        .and_then(std::path::Path::parent)
        .ok_or("missing application prefix")?;
    let arguments: Vec<_> = std::env::args().collect();
    if arguments.iter().any(|arg| arg == "--wrong-identity") {
        configure_flatpak_application(
            "dev.enzim.WebKit.Wrong",
            app_prefix.join("lib/wpe-extensions"),
        )?;
    }
    if arguments
        .iter()
        .any(|arg| arg == "--without-flatpak-registration")
    {
        set_application_id(application)?;
        set_credential_guard_directory(app_prefix.join("lib/wpe-extensions"))?;
    } else {
        configure_flatpak_application(application, app_prefix.join("lib/wpe-extensions"))?;
    }
    enzui_webkit::sandbox::preflight().map_err(|error| format!("{error:?}"))?;
    for invalid in ["invalid", "dev.example.Bad\0Id"] {
        assert!(set_application_id(invalid).is_err());
    }
    assert!(set_application_id(application).is_ok());
    assert!(set_application_id("dev.enzim.WebKit.Conflicting").is_err());
    let data_home = PathBuf::from(std::env::var("XDG_DATA_HOME")?);
    std::fs::create_dir_all(&data_home)?;
    let identity_file = data_home.join("enzim-webkit-probe-identity");
    if identity_file.exists() {
        assert_eq!(std::fs::read_to_string(&identity_file)?, application);
    }
    std::fs::write(&identity_file, application)?;
    let display = HeadlessDisplay::new()?;
    assert!(
        set_application_id(application).is_err(),
        "identity must be frozen"
    );
    let mut profiles = enzui_webkit::ffi::profile::ProfileStore::new(data_home.join("profiles"));
    let deferred = arguments.iter().any(|arg| arg == "--deferred");
    let policy = if std::env::args().any(|arg| arg == "--require-inner-bwrap") {
        OuterSandbox::Rejected
    } else {
        OuterSandbox::AcceptedByHost
    };
    let mut session = if policy == OuterSandbox::Rejected {
        WebSession::new_with_sandbox_policy(&display, policy)?
    } else if deferred {
        let pending = WebSession::begin_profiled(
            &display,
            &mut profiles,
            &enzui_webkit::web::WebProfile::ephemeral(),
        )?;
        let deadline = Instant::now() + Duration::from_secs(25);
        loop {
            enzui_webkit::ffi::dispatch_pending_native_events()?;
            if let Some(result) = pending.take_result() {
                break result?;
            }
            if Instant::now() >= deadline {
                return Err("deferred bootstrap timed out".into());
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    } else {
        WebSession::new(&display)?
    };
    let mut router = ViewRouter::new();
    let view = router.create(1);
    session.bind_view(&router, view)?;
    session.resize_viewport(&router, view, ViewportSize::from_logical(640.0, 480.0)?)?;
    let html = "<!doctype html><meta charset=utf-8><title>Shared WebKit</title>\
        <style>html,body{margin:0;background:rgb(17,34,51)}\
        #paint{width:128px;height:128px;background:rgb(24,180,80)}</style>\
        <div id=paint></div><h1>Shared WebKit</h1>";
    session.load_html(html, "https://example.org/", 20_000)?;
    assert_eq!(
        serde_json::from_str::<String>(&evaluate(&session, "document.title")?)?,
        "Shared WebKit"
    );
    let frame = session.snapshot(Generation::FIRST, FrameSeq(1), 15_000)?;
    assert!(frame.width() >= 128 && frame.height() >= 128);
    let position = ((32 * frame.width() + 32) * 4) as usize;
    let pixel = &frame.pixels()[position..position + 4];
    assert!(
        pixel[1] > 150 && pixel[0] < 60 && pixel[2] < 110 && pixel[3] == 255,
        "painted marker: {pixel:?}"
    );
    let https = arguments.iter().any(|arg| arg == "--https");
    if https {
        session.load("https://example.com/", 30_000)?;
        assert_eq!(
            serde_json::from_str::<String>(&evaluate(&session, "location.protocol")?)?,
            "https:"
        );
        assert_eq!(
            serde_json::from_str::<String>(&evaluate(&session, "document.title")?)?,
            "Example Domain"
        );
    }
    let media = arguments
        .windows(2)
        .find(|args| args[0] == "--media-fixture");
    if let Some(args) = media {
        session.load_html(
            &std::fs::read_to_string(&args[1])?,
            "https://example.org/",
            20_000,
        )?;
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let result = evaluate(
                &session,
                "Boolean(document.querySelector('video')?.readyState >= 2 && document.querySelector('video').videoWidth === 64)",
            )?;
            if serde_json::from_str::<bool>(&result)? {
                break;
            }
            if Instant::now() >= deadline {
                return Err("WebM video did not decode".into());
            }
            session.pump(20);
        }
    }
    let renderer = session
        .attested_renderer()
        .ok_or("renderer identity not attested")?;
    let parent_pid_ns = std::fs::read_link("/proc/self/ns/pid")?;
    let renderer_pid_ns = std::fs::read_link(format!("/proc/{}/ns/pid", renderer.pid))?;
    let parent_net_ns = std::fs::read_link("/proc/self/ns/net")?;
    let renderer_net_ns = std::fs::read_link(format!("/proc/{}/ns/net", renderer.pid))?;
    assert_ne!(
        parent_pid_ns, renderer_pid_ns,
        "renderer PID namespace is not isolated"
    );
    assert_ne!(
        parent_net_ns, renderer_net_ns,
        "renderer network namespace is not isolated"
    );
    let library = prefix.join("lib/libWPEWebKit-2.0.so.1");
    let file = std::fs::metadata(&library)?;
    let descriptor = std::fs::read_to_string(prefix.join("share/enzim-webkit/runtime.ini"))?;
    let version = descriptor
        .lines()
        .find_map(|line| line.strip_prefix("Version="))
        .ok_or("missing runtime version")?;
    println!(
        "FLATPAK_RESULT {}",
        serde_json::json!({
            "application": application, "version": version, "data_home": data_home,
            "deferred": deferred, "identity_configuration": true,
            "library": library, "engine_device": file.dev(), "engine_inode": file.ino(),
            "javascript": true, "https": https, "webm": media.is_some(), "paint": pixel, "width": frame.width(), "height": frame.height(),
            "renderer_pid": renderer.pid, "renderer_pid_namespace_isolated": true,
            "renderer_network_namespace_isolated": true,
        })
    );
    Ok(())
}
