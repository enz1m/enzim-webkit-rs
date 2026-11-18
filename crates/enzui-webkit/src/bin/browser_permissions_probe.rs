//! Main-thread native browser origin and permission lifecycle probe.
#[path = "browser_permissions_probe/geolocation.rs"]
mod geolocation;
#[path = "browser_permissions_probe/notifications.rs"]
mod notifications;
use enzui_webkit::ffi::runtime::{HeadlessDisplay, WebSession};
use enzui_webkit::page::{PageEvent, ScriptWorld};
use enzui_webkit::site_permissions::{PermissionOrigin, SitePermission, SitePermissionRequest};
use enzui_webkit::web::policy::PermissionKind;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
thread_local! {
    static PENDING_EVENTS: std::cell::RefCell<Vec<PageEvent>> = const { std::cell::RefCell::new(Vec::new()) };
}
struct Origin(Child);
impl Drop for Origin {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn events_until(web: &WebSession, mut done: impl FnMut(&[PageEvent]) -> bool) -> Vec<PageEvent> {
    let end = Instant::now() + Duration::from_secs(8);
    let mut events = PENDING_EVENTS.with(|pending| std::mem::take(&mut *pending.borrow_mut()));
    loop {
        web.pump(10);
        events.extend(web.take_page_events());
        if done(&events) {
            return events;
        }
        assert!(
            Instant::now() < end,
            "native permissions deadline: {events:?}"
        );
    }
}
fn script(web: &WebSession, source: &str) -> String {
    let id = web.evaluate_script(source, &ScriptWorld::Page).unwrap();
    let events = events_until(web, |events| {
        events
            .iter()
            .any(|e| matches!(e,PageEvent::ScriptResult{id:got,..} if *got==id))
    });
    let mut reply = None;
    let mut pending = Vec::new();
    for event in events {
        match event {
            PageEvent::ScriptResult { id: got, result } if got == id => {
                reply = Some(result.unwrap().trim_matches('"').to_owned())
            }
            event => pending.push(event),
        }
    }
    PENDING_EVENTS.with(|queue| queue.borrow_mut().extend(pending));
    reply.unwrap()
}
fn request(web: &WebSession) -> SitePermissionRequest {
    let events = events_until(web, |events| {
        events
            .iter()
            .any(|e| matches!(e, PageEvent::PermissionRequested(_)))
    });
    events
        .into_iter()
        .find_map(|e| {
            if let PageEvent::PermissionRequested(r) = e {
                Some(r)
            } else {
                None
            }
        })
        .unwrap()
}
fn query(web: &WebSession, name: &str) -> String {
    script(
        web,
        &format!(
            "delete document.body.dataset.permission;navigator.permissions.query({{name:'{name}'}}).then(p=>document.body.dataset.permission=p.state);null"
        ),
    );
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        let result = script(web, "document.body.dataset.permission||''");
        if !result.is_empty() {
            return result;
        }
        assert!(Instant::now() < end);
        web.pump(10);
    }
}
fn wait_value(web: &WebSession, source: &str, expected: &str) {
    let end = Instant::now() + Duration::from_secs(8);
    loop {
        let value = script(web, source);
        if value == expected {
            return;
        }
        assert!(Instant::now() < end, "expected {expected}, got {value}");
        web.pump(10);
    }
}
fn main() {
    let root = PathBuf::from(std::env::args_os().nth(1).unwrap());
    let mut origin = Origin(
        Command::new("python3")
            .arg(
                Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/browser_permissions.py"),
            )
            .arg(&root)
            .stdout(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut line = String::new();
    BufReader::new(origin.0.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let urls: Vec<_> = line
        .split('"')
        .filter(|x| x.starts_with("https://"))
        .collect();
    assert_eq!(urls.len(), 2);
    let (main, child) = (urls[0], urls[1]);
    let plain = line
        .split('"')
        .find(|value| value.starts_with("http://"))
        .unwrap();
    let display = HeadlessDisplay::new().unwrap();
    let provider = geolocation::Provider::install(&root);
    if std::env::args().any(|arg| arg == "--notifications") {
        notifications::run(&root, &display, main);
        return;
    }
    let mut web = WebSession::new(&display).unwrap();
    let legacy = std::env::args().any(|a| a == "--legacy-control");
    let mut router = enzui_webkit::web::ViewRouter::new();
    let view = router.create(72);
    {
        web.bind_view(&router, view).unwrap();
        web.install_native_policy(
            &router,
            view,
            enzui_webkit::web::WebPolicy::strict()
                .grant(PermissionKind::Geolocation)
                .grant(PermissionKind::Camera)
                .grant(PermissionKind::Microphone),
            |r| Some(r.id),
        )
        .unwrap();
    }

    assert!(
        web.begin_load_uri(&format!("{main}/main")).is_err(),
        "strict destination default reached LAN"
    );
    let list = web.local_origins().unwrap();
    list.allow_origin(main).unwrap();
    web.allow_tls_certificate_for_host(&std::fs::read(root.join("cert.pem")).unwrap(), "127.0.0.1")
        .unwrap();
    web.load(&format!("{main}/main"), 10_000).unwrap();
    assert!(
        web.begin_load_uri(&format!("{child}/main")).is_err(),
        "port grant escaped its exact origin"
    );
    list.allow_origin(child).unwrap();
    assert!(web.begin_load_uri(&format!("{plain}/main")).is_err());
    list.allow_origin(plain).unwrap();
    web.load(&format!("{plain}/main"), 10_000).unwrap();
    assert_eq!(
        web.current_uri().unwrap().as_deref(),
        Some(format!("{plain}/main").as_str())
    );
    assert!(web.connection_tls_info().is_none());
    assert!(
        web.begin_load_uri(&format!(
            "{}/main",
            child.replacen("https://", "http://", 1)
        ))
        .is_err()
    );
    assert!(list.revoke_origin(plain).unwrap());
    assert!(web.begin_load_uri(&format!("{plain}/main")).is_err());
    web.load(&format!("{main}/main"), 10_000).unwrap();
    println!("Exact HTTP LAN navigation and revocation passed");

    if legacy {
        assert!(!web.supports_origin_permissions());
        assert_eq!(
            query(&web, "geolocation"),
            "granted",
            "legacy grant positive control"
        );
        assert!(
            matches!(
                web.set_origin_permission_mode(true),
                Err(enzui_webkit::ffi::runtime::SessionError::OriginPermissionsUnsupported)
            ),
            "unsupported activation unexpectedly succeeded"
        );
        assert_eq!(
            query(&web, "geolocation"),
            "granted",
            "unsupported activation changed existing policy"
        );
        assert!(!web.supports_pdf_export());
        println!(
            "Unpatched runtime explicitly refuses origin mode without changing existing policy"
        );
        return;
    }
    assert!(web.supports_origin_permissions());
    web.reset_origin_permissions().unwrap();
    web.load(&format!("{main}/main"), 10_000).unwrap();

    let top = PermissionOrigin::parse(main).unwrap();
    let requesting = PermissionOrigin::parse(child).unwrap();
    let main_permission = SitePermission {
        requesting_origin: top.clone(),
        top_origin: top.clone(),
        kind: PermissionKind::Geolocation,
    };
    assert!(
        web.set_site_permission(main_permission.clone(), true)
            .unwrap()
    );
    assert_eq!(
        query(&web, "geolocation"),
        "granted",
        "native query lost main origin grant"
    );
    web.begin_load_uri(&format!("{main}/frame")).unwrap();
    let prompt = request(&web);
    assert_eq!(
        prompt.permission.requesting_origin, requesting,
        "subframe origin was attributed to address-bar origin"
    );
    assert_eq!(
        prompt.permission.top_origin, top,
        "subframe top origin was attributed to the requester"
    );
    assert_eq!(prompt.permission.kind, PermissionKind::Geolocation);
    web.answer_permission(prompt.id, false).unwrap();
    assert!(
        web.answer_permission(prompt.id, true).is_err(),
        "permission answer reused"
    );
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        let result = script(&web, "document.body.dataset.child||''");
        if result == "child-error-1" {
            break;
        }
        assert!(Instant::now() < end, "denial did not reach child: {result}");
        web.pump(10);
    }
    println!("Exact LAN origins and native cross-origin permission attribution passed");
    web.load(&format!("{main}/main"), 10_000).unwrap();
    web.reset_origin_permissions().unwrap();
    web.evaluate_script(
        "navigator.geolocation.getCurrentPosition(()=>{},()=>{},{timeout:1000});null",
        &ScriptWorld::Page,
    )
    .unwrap();
    let pending = request(&web);
    web.load_html("<p>Replacement document</p>", "about:blank", 10_000)
        .unwrap();
    assert!(
        web.answer_permission(pending.id, true).is_err(),
        "navigation retained stale permission answer"
    );
    assert!(
        web.take_page_events()
            .iter()
            .any(|e| matches!(e,PageEvent::PermissionCancelled{id} if *id==pending.id)),
        "host did not receive cancellation"
    );
    println!("Navigation retires held permission requests passed");
    web.load(&format!("{main}/main"), 10_000).unwrap();
    assert!(
        web.set_site_permission(main_permission.clone(), true)
            .unwrap()
    );
    assert_eq!(query(&web, "geolocation"), "granted");
    let other = SitePermission {
        requesting_origin: PermissionOrigin::parse(child).unwrap(),
        ..main_permission.clone()
    };
    assert!(web.set_site_permission(other, false).unwrap());
    web.pump(20);
    assert_eq!(
        query(&web, "geolocation"),
        "granted",
        "other origin denial changed main grant"
    );
    assert!(web.set_site_permission(main_permission, false).unwrap());
    web.pump(300);
    let state = query(&web, "geolocation");
    assert_ne!(state, "granted", "revoked grant remained visible");
    println!("Origin-scoped query grants and revocation passed");
    web.load(&format!("{main}/main"), 10_000).unwrap();
    web.reset_origin_permissions().unwrap();
    let permission = SitePermission {
        requesting_origin: top.clone(),
        top_origin: top.clone(),
        kind: PermissionKind::Geolocation,
    };
    assert!(web.set_site_permission(permission.clone(), true).unwrap());
    let reset = web.reset_geolocation_permission().unwrap();
    events_until(&web, |events| {
        events.iter().any(|event| matches!(event, PageEvent::GeolocationPermissionChanged { id, revoked: false, result: Ok(()), .. } if *id == reset))
    });
    script(
        &web,
        "globalThis.positionCount=0;globalThis.geoError=0;globalThis.testWatch=navigator.geolocation.watchPosition(()=>++positionCount,e=>globalThis.geoError=e.code,{maximumAge:0,timeout:10000});null",
    );
    let end = Instant::now() + Duration::from_secs(5);
    while provider.counts().0 == 0 {
        web.pump(10);
        assert!(
            Instant::now() < end,
            "native synthetic provider never started"
        );
    }
    provider.push(0.0);
    wait_value(&web, "positionCount", "1");
    let before_stop = provider.counts().1;
    web.install_native_policy(
        &router,
        view,
        enzui_webkit::web::WebPolicy::strict(),
        |_| None,
    )
    .unwrap();
    assert!(web.set_site_permission(permission.clone(), false).unwrap());
    let revoked = web.revoke_geolocation().unwrap();
    let events = events_until(&web, |events| {
        events
            .iter()
            .any(|e| matches!(e,PageEvent::GeolocationPermissionChanged{id,..} if *id==revoked))
    });
    assert!(events.iter().any(|e|matches!(e,PageEvent::GeolocationPermissionChanged{id,revoked:true,result:Ok(()),..} if *id==revoked)));
    wait_value(&web, "geoError", "1");
    assert!(
        provider.counts().1 > before_stop,
        "native provider did not stop"
    );
    provider.push(1.0);
    web.pump(50);
    assert_eq!(
        script(&web, "positionCount"),
        "1",
        "position arrived after confirmed revocation"
    );
    assert_eq!(
        web.current_uri().unwrap().as_deref(),
        Some(format!("{main}/main").as_str()),
        "revocation relied on navigation"
    );
    let before_restart = provider.counts().0;
    assert!(web.set_site_permission(permission, true).unwrap());
    let reset = web.reset_geolocation_permission().unwrap();
    events_until(&web, |events| {
        events.iter().any(|event| matches!(event, PageEvent::GeolocationPermissionChanged { id, revoked: false, result: Ok(()), .. } if *id == reset))
    });
    script(
        &web,
        "globalThis.geoError=0;globalThis.retryPosition=0;navigator.geolocation.getCurrentPosition(()=>globalThis.retryPosition=1,e=>globalThis.geoError=e.code,{maximumAge:0,timeout:10000});null",
    );
    let end = Instant::now() + Duration::from_secs(5);
    while provider.counts().0 <= before_restart {
        web.pump(10);
        assert!(
            Instant::now() < end,
            "grant did not reset cached geolocation denial"
        );
    }
    provider.push(2.0);
    wait_value(&web, "retryPosition", "1");
    web.install_native_policy(
        &router,
        view,
        enzui_webkit::web::WebPolicy::strict().grant(PermissionKind::Geolocation),
        |r| Some(r.id),
    )
    .unwrap();
    println!("Native geolocation watch revocation, blocked navigation and regrant passed");
    web.reset_origin_permissions().unwrap();
    let fence = web.revoke_geolocation().unwrap();
    events_until(&web, |events| {
        events.iter().any(|event| matches!(event, PageEvent::GeolocationPermissionChanged { id, result: Ok(()), .. } if *id == fence))
    });
    script(
        &web,
        "globalThis.geoError=0;navigator.geolocation.getCurrentPosition(()=>null,e=>globalThis.geoError=e.code,{timeout:10000});null",
    );
    let pending = request(&web);
    assert_eq!(pending.permission.kind, PermissionKind::Geolocation);
    web.answer_permission(pending.id, false).unwrap();
    wait_value(&web, "geoError", "1");
    web.set_origin_permission_mode(false).unwrap();
    let fence = web.revoke_geolocation().unwrap();
    events_until(&web, |events| {
        events.iter().any(|event| matches!(event, PageEvent::GeolocationPermissionChanged { id, result: Ok(()), .. } if *id == fence))
    });
    let before_legacy = provider.counts().0;
    script(
        &web,
        "globalThis.legacyPosition=0;navigator.geolocation.getCurrentPosition(()=>globalThis.legacyPosition=1,e=>globalThis.geoError=e.code,{maximumAge:0,timeout:10000});null",
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    while provider.counts().0 <= before_legacy {
        web.pump(10);
        assert!(
            Instant::now() < deadline,
            "legacy permission remained blocked after origin mode was disabled"
        );
    }
    provider.push(3.0);
    wait_value(&web, "legacyPosition", "1");
    println!("Permission mode reset prompts again and mode-off restores legacy grant passed");
    web.load(&format!("{main}/main"), 10_000).unwrap();
    web.reset_origin_permissions().unwrap();
    web.pump(100);
    web.apply_settings(&enzui_webkit::page::WebSettings {
        webrtc: true,
        ..Default::default()
    });
    assert!(
        web.set_mock_capture_devices(true),
        "mock capture was not enabled; refuse physical-device test"
    );
    let camera = SitePermission {
        requesting_origin: top.clone(),
        top_origin: top.clone(),
        kind: PermissionKind::Camera,
    };
    let microphone = SitePermission {
        kind: PermissionKind::Microphone,
        ..camera.clone()
    };

    // MessagePort tasks do not forward WebKit's forced host-evaluation gesture.
    script(
        &web,
        "globalThis.captureChannel=new MessageChannel();captureChannel.port1.onmessage=e=>navigator.mediaDevices.getUserMedia(e.data).then(s=>{globalThis.testMedia=s;document.body.dataset.media='ok'},e=>document.body.dataset.media=e.name);null",
    );
    web.evaluate_script(
        "captureChannel.port2.postMessage({video:true});null",
        &ScriptWorld::Page,
    )
    .unwrap();
    let first = request(&web);
    assert_eq!(first.permission.kind, PermissionKind::Camera);
    web.answer_permission(first.id, true).unwrap();
    wait_value(&web, "document.body.dataset.media||''", "ok");
    assert!(web.set_site_permission(camera.clone(), true).unwrap());
    assert_eq!(
        script(&web, "testMedia.getTracks()[0].readyState"),
        "live",
        "remembering an allowed request stopped its active track"
    );
    script(&web, "testMedia.getTracks().forEach(t=>t.stop());null");

    let capture = "delete document.body.dataset.media;captureChannel.port2.postMessage({audio:true,video:true});null";
    web.evaluate_script(capture, &ScriptWorld::Page).unwrap();
    let combined = request(&web);
    assert_eq!(
        combined.permission.kind,
        PermissionKind::CameraAndMicrophone
    );
    web.answer_permission(combined.id, false).unwrap();
    wait_value(&web, "document.body.dataset.media||''", "NotAllowedError");
    let microphone_choice = microphone.clone();
    assert!(web.set_site_permission(microphone, true).unwrap());
    script(&web, capture);
    wait_value(&web, "document.body.dataset.media||''", "ok");
    assert_eq!(script(&web, "testMedia.getTracks().length"), "2");
    script(&web, "testMedia.getTracks().forEach(t=>t.stop());null");
    web.pump(50);
    assert!(web.set_site_permission(camera.clone(), false).unwrap());
    script(
        &web,
        "delete document.body.dataset.media;captureChannel.port2.postMessage({video:true});null",
    );
    wait_value(&web, "document.body.dataset.media||''", "NotAllowedError");
    assert!(web.set_site_permission(camera, true).unwrap());
    script(&web, capture);
    wait_value(&web, "document.body.dataset.media||''", "ok");
    script(&web, "testMedia.getTracks().forEach(t=>t.stop());null");
    println!("Mock capture combined grants and ended-track revocation passed");

    // Screen capture is asked for each request, even with the camera and
    // microphone granted, and no choice for it can be stored.
    let share = "delete document.body.dataset.screen;navigator.mediaDevices.getDisplayMedia({video:true}).then(s=>{globalThis.testScreen=s;document.body.dataset.screen='ok'},e=>document.body.dataset.screen=e.name);null";
    web.evaluate_script(share, &ScriptWorld::Page).unwrap();
    let refused = request(&web);
    assert_eq!(refused.permission.kind, PermissionKind::ScreenCapture);
    web.answer_permission(refused.id, false).unwrap();
    wait_value(&web, "document.body.dataset.screen||''", "NotAllowedError");
    for _ in 0..2 {
        web.evaluate_script(share, &ScriptWorld::Page).unwrap();
        let allowed = request(&web);
        assert_eq!(
            allowed.permission.kind,
            PermissionKind::ScreenCapture,
            "an earlier answer was remembered for screen capture"
        );
        web.answer_permission(allowed.id, true).unwrap();
        wait_value(&web, "document.body.dataset.screen||''", "ok");
        assert_eq!(script(&web, "testScreen.getVideoTracks().length"), "1");
        script(&web, "testScreen.getTracks().forEach(t=>t.stop());null");
        web.pump(50);
    }
    assert!(
        !web.set_site_permission(
            SitePermission {
                kind: PermissionKind::ScreenCapture,
                ..microphone_choice
            },
            true
        )
        .unwrap(),
        "a screen capture choice was stored"
    );
    println!("Screen capture is asked for every request and never remembered passed");
}
