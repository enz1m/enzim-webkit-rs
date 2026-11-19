//! `wpe_page` - the page conversation through a real WebKitWebView.
//!
//! ```text
//! cargo test --features wpe -p enzui-webview --test wpe_page \
//!     -- --ignored --nocapture
//! ```

#[cfg(feature = "wpe")]
#[path = "../../enzui-webkit/tests/wpe_native_support/mod.rs"]
mod wpe_native_support;

#[cfg(feature = "wpe")]
mod gates {
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use enzui_security::secret::SecretText;
    use enzui_services::oauth::{ClientConfig, Pkce};
    use enzui_webkit::ffi::runtime::{HeadlessDisplay, WebSession};
    use enzui_webkit::input::{self, PointerButton, ViewportMapping};
    use enzui_webkit::page::{
        AuthAnswer, AuthScheme, DeclinedPrompt, LoadStage, PageEvent, PagePrompts,
        ScriptDialogAnswer, ScriptDialogKind, ScriptError, ScriptWorld, UserAgent, WebSettings,
        WebsiteData,
    };
    use enzui_webkit::web::policy::WebPolicy;
    use enzui_webkit::web::{RedirectCapture, ViewRouter};

    const CALLBACK: &str = "com.example.app:/oauth2redirect";

    /// An HTTP origin with a few fixed routes. It records each request's
    /// `Authorization` header so the authentication gate can check what
    /// WebKit actually sent.
    struct Origin {
        address: SocketAddr,
        stop: Arc<AtomicBool>,
        authorization: Arc<Mutex<Vec<String>>>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    impl Origin {
        fn start(callback_port: u16) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind origin");
            listener.set_nonblocking(true).expect("nonblocking");
            let address = listener.local_addr().expect("address");
            let stop = Arc::new(AtomicBool::new(false));
            let authorization = Arc::new(Mutex::new(Vec::new()));
            let thread = {
                let stop = Arc::clone(&stop);
                let authorization = Arc::clone(&authorization);
                std::thread::spawn(move || serve(&listener, &stop, &authorization, callback_port))
            };
            Self {
                address,
                stop,
                authorization,
                thread: Some(thread),
            }
        }

        fn url(&self, path: &str) -> String {
            format!("http://{}{path}", self.address)
        }
    }

    impl Drop for Origin {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Release);
            let _ = TcpStream::connect(self.address);
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    /// The download fixture: 300 KiB, so progress is reported more than once.
    static REPORT: std::sync::LazyLock<String> =
        std::sync::LazyLock::new(|| "report line\n".repeat(300 * 1024 / 12));

    const PAGE: &str = "<style>html,body,button,input{margin:0;width:100%;height:100%}</style>";

    fn serve(
        listener: &TcpListener,
        stop: &AtomicBool,
        authorization: &Mutex<Vec<String>>,
        callback_port: u16,
    ) {
        while !stop.load(Ordering::Acquire) {
            let mut stream = match listener.accept() {
                Ok((stream, _)) => stream,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(2));
                    continue;
                }
                Err(_) => break,
            };
            let _ = stream.set_nonblocking(false);
            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
            let mut request = vec![0_u8; 8192];
            let count = stream.read(&mut request).unwrap_or(0);
            let text = String::from_utf8_lossy(&request[..count]).into_owned();
            let path = text.split_whitespace().nth(1).unwrap_or("/").to_owned();
            let auth = text
                .lines()
                .find_map(|line| line.strip_prefix("Authorization: "))
                .map(str::to_owned);
            if path == "/slow" {
                // 4 MiB, slowly, so the host can cancel mid-transfer.
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\
                     Content-Disposition: attachment; filename=\"slow.bin\"\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n",
                    4 * 1024 * 1024
                );
                for _ in 0..64 {
                    if stop.load(Ordering::Acquire) || stream.write_all(&[7u8; 64 * 1024]).is_err()
                    {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
                continue;
            }
            let mut status = "200 OK";
            let mut extra = String::new();
            let mut content_type = "text/html";
            let body = match path.as_str() {
                "/report" => {
                    content_type = "application/octet-stream";
                    extra =
                        "Content-Disposition: attachment; filename=\"../report.txt\"\r\n".into();
                    REPORT.clone()
                }
                "/authorize" => {
                    status = "302 Found";
                    extra = format!(
                        "Location: http://127.0.0.1:{callback_port}/cb?code=SERVER-CODE&state=st\r\n"
                    );
                    String::new()
                }
                "/titled" => format!("<title>Enz page</title>{PAGE}<p>needle Needle needle</p>"),
                "/provider" => {
                    status = "302 Found";
                    extra = format!(
                        "Location: http://127.0.0.1:{callback_port}/cb?code=POPUP-REDIRECT-CODE&state=st\r\n"
                    );
                    String::new()
                }
                "/signin-popup" => format!(
                    "{PAGE}<button onclick=\"window.open('/provider','_blank')\">sign in</button>"
                ),
                "/select" => "<style>html,body,select{margin:0;width:100%;height:100%}</style>\
                    <select onchange=\"document.title='picked:'+this.value\">\
                    <option value=a>Alpha</option><option value=b selected>Beta</option>\
                    <optgroup label=More><option value=c>Gamma</option></optgroup></select>".into(),
                "/permissions" => format!(
                    "<title>perm</title>{PAGE}<script>navigator.permissions.query({{name:'geolocation'}}).then(r => document.title = 'perm:' + r.state)</script>"
                ),
                // WebKit asks for notification permission only from a gesture.
                "/notify" => format!(
                    "<title>notify</title>{PAGE}<button onclick=\"Notification.requestPermission().then(p => {{ document.title = 'asked:' + p; if (p === 'granted') new Notification('Hi', {{body: 'There', tag: 't1'}}); }})\">notify</button>"
                ),
                "/leave" => format!(
                    "<title>leave</title>{PAGE}<script>addEventListener('beforeunload', e => {{ e.preventDefault(); e.returnValue = 'stay'; }})</script>"
                ),
                "/link" => "<style>html,body{margin:0;width:100%;height:100%}div,a{position:absolute;display:block}</style>\
                    <div style=\"left:0;top:0;width:50%;height:50%\">one</div>\
                    <div style=\"left:50%;top:0;width:50%;height:50%\">two</div>\
                    <a href=\"/b\" style=\"left:0;top:50%;width:100%;height:50%\">go</a>".into(),
                "/fullscreen" => format!(
                    "{PAGE}<button onclick=\"document.fullscreenElement ? document.exitFullscreen() : document.documentElement.requestFullscreen()\">fs</button>"
                ),
                "/closer" => format!(
                    "{PAGE}<button onclick=\"window.open('/closing-child','_blank')\">open</button>"
                ),
                "/closing-child" => {
                    format!("<title>closing</title>{PAGE}<script>window.close()</script>")
                }
                "/attachment-html" => {
                    extra = "Content-Disposition: attachment; filename=\"page.html\"\r\n".into();
                    "<p>keep</p>".into()
                }
                "/a" => format!("<title>A</title>{PAGE}"),
                "/opener" => format!(
                    "<title>opener</title>{PAGE}<script>addEventListener('message', e => document.title = 'got:' + e.data)</script><button onclick=\"window.open('/child','_blank')\">open</button>"
                ),
                "/child" => format!(
                    "<title>child</title>{PAGE}<script>window.opener.postMessage('hello from child', '*')</script>"
                ),
                "/b" => format!("<title>B</title>{PAGE}"),
                "/cookie" => format!(
                    "<title>cookie</title>{PAGE}<script>document.cookie='enz=1; max-age=3600'</script>"
                ),
                "/file" => format!("{PAGE}<input type=file>"),
                "/popup" => format!(
                    "{PAGE}<button onclick=\"window.open('/popped','_blank')\">open</button>"
                ),
                "/capture-popup" => format!(
                    "{PAGE}<button onclick=\"window.open('{CALLBACK}?code=POPUP-CODE&state=st','_blank')\">open</button>"
                ),
                "/protected" => {
                    authorization
                        .lock()
                        .expect("lock")
                        .push(auth.clone().unwrap_or_default());
                    // "ada:lovelace" in Basic.
                    if auth.as_deref() == Some("Basic YWRhOmxvdmVsYWNl") {
                        format!("<title>authed</title>{PAGE}")
                    } else {
                        status = "401 Unauthorized";
                        extra = "WWW-Authenticate: Basic realm=\"Enz realm\"\r\n".into();
                        "denied".into()
                    }
                }
                _ => format!("<title>other</title>{PAGE}"),
            };
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
        }
    }

    /// A listener that only counts connections: the loopback callback must
    /// never be reached.
    struct Counter {
        port: u16,
        accepted: Arc<AtomicUsize>,
        stop: Arc<AtomicBool>,
    }

    impl Counter {
        fn start() -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind counter");
            listener.set_nonblocking(true).expect("nonblocking");
            let port = listener.local_addr().expect("address").port();
            let accepted = Arc::new(AtomicUsize::new(0));
            let stop = Arc::new(AtomicBool::new(false));
            {
                let accepted = Arc::clone(&accepted);
                let stop = Arc::clone(&stop);
                std::thread::spawn(move || {
                    while !stop.load(Ordering::Acquire) {
                        match listener.accept() {
                            Ok(_) => {
                                accepted.fetch_add(1, Ordering::AcqRel);
                            }
                            Err(_) => std::thread::sleep(Duration::from_millis(2)),
                        }
                    }
                });
            }
            Self {
                port,
                accepted,
                stop,
            }
        }
    }

    impl Drop for Counter {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Release);
        }
    }

    /// Pumps until `done` holds over everything seen so far, or the deadline.
    fn pump_until(
        session: &WebSession,
        seen: &mut Vec<PageEvent>,
        what: &str,
        mut done: impl FnMut(&[PageEvent]) -> bool,
    ) -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            seen.extend(session.take_page_events());
            if done(seen) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!("{what}: not seen in 10 s; events: {seen:#?}"));
            }
            session.pump(50);
        }
    }

    /// Runs `source` and returns its result; every other event seen while
    /// waiting is appended to `seen`, so nothing the page said is lost.
    fn script_into(
        session: &WebSession,
        source: &str,
        seen: &mut Vec<PageEvent>,
    ) -> Result<Result<String, ScriptError>, String> {
        let id = session
            .evaluate_script(source, &ScriptWorld::Page)
            .map_err(|e| e.to_string())?;
        let mut mine = Vec::new();
        pump_until(session, &mut mine, source, |events| {
            events
                .iter()
                .any(|e| matches!(e, PageEvent::ScriptResult { id: got, .. } if *got == id))
        })?;
        let mut result = None;
        for event in mine {
            match event {
                PageEvent::ScriptResult { id: got, result: r } if got == id => result = Some(r),
                other => seen.push(other),
            }
        }
        Ok(result.expect("seen above"))
    }

    fn script(session: &WebSession, source: &str) -> Result<Result<String, ScriptError>, String> {
        script_into(session, source, &mut Vec::new())
    }

    /// Every URL or text an event other than `RedirectCaptured` carries
    /// that contains `needle`: a captured code must reach the host once.
    fn leaked(events: &[PageEvent], needle: &str) -> Vec<String> {
        events
            .iter()
            .filter_map(|e| match e {
                PageEvent::LoadFailed { url, .. }
                | PageEvent::UriChanged(url)
                | PageEvent::PopupRequested { url, .. }
                | PageEvent::PopupOpened { url, .. } => Some(url.as_str().to_owned()),
                PageEvent::TitleChanged(title) => Some(title.clone()),
                _ => None,
            })
            .filter(|text| text.contains(needle))
            .collect()
    }

    fn captured(events: &[PageEvent]) -> Vec<(String, bool, bool)> {
        events
            .iter()
            .filter_map(|e| match e {
                PageEvent::RedirectCaptured(c) => {
                    Some((c.url.expose_secret().to_owned(), c.redirect, c.popup))
                }
                _ => None,
            })
            .collect()
    }

    fn session(display: &HeadlessDisplay) -> Result<(WebSession, ViewRouter), String> {
        let mut web = WebSession::new_trusted_local(display).map_err(|e| e.to_string())?;
        let mut router = ViewRouter::new();
        let view = router.create(7);
        web.bind_view(&router, view).map_err(|e| e.to_string())?;
        let mut policy = WebPolicy::strict();
        policy.allow_http = true;
        policy.allow_popups = true;
        policy.allow_downloads = true;
        web.install_native_policy(&router, view, policy, |request| Some(request.id))
            .map_err(|e| e.to_string())?;
        Ok((web, router))
    }

    trait LoadOk {
        fn load_ok(self, url: &str) -> Result<(), String>;
    }

    impl LoadOk for WebSession {
        fn load_ok(mut self, url: &str) -> Result<(), String> {
            self.load(url, 10_000).map_err(|e| e.to_string())
        }
    }

    fn click_centre(web: &WebSession, router: &ViewRouter) -> Result<(), String> {
        let view = router.live_view(7).ok_or("view")?;
        let mapping = ViewportMapping::new(0.0, 0.0, 1024.0, 768.0, 1.0).expect("mapping");
        let (x, y) = (512.0, 384.0);
        let events = [
            input::pointer_moved(view, &mapping, x, y),
            input::pointer_pressed(view, &mapping, x, y, PointerButton::Primary),
            input::pointer_released(view, &mapping, x, y, PointerButton::Primary),
        ];
        for event in events {
            let event = event.ok_or("pointer out of bounds")?;
            if !web.forward_input(&event) {
                return Err("bound session refused input".into());
            }
            web.pump(100);
        }
        Ok(())
    }

    pub(super) fn run() -> Result<(), String> {
        let display = HeadlessDisplay::new().map_err(|e| e.to_string())?;
        let counter = Counter::start();
        let origin = Origin::start(counter.port);

        // ---- 1. sign-in redirects --------------------------------------
        let (mut web, router) = session(&display)?;
        let mut seen = Vec::new();
        // Control: no capture registered, so a script navigation to the
        // callback is not handed to the host.
        web.load(&origin.url("/a"), 10_000)
            .map_err(|e| e.to_string())?;
        web.take_page_events();
        let _ = script_into(
            &web,
            &format!("location.href='{CALLBACK}?code=UNREGISTERED&state=st'"),
            &mut seen,
        )?;
        web.pump(500);
        seen.extend(web.take_page_events());
        if !captured(&seen).is_empty() {
            return Err(format!("captured with no capture registered: {seen:?}"));
        }

        if !web.capture_redirect(RedirectCapture::parse(CALLBACK).map_err(|e| e.to_string())?) {
            return Err("capture refused".into());
        }
        let loopback = format!("http://127.0.0.1:{}/cb", counter.port);
        web.capture_redirect(RedirectCapture::parse(&loopback).map_err(|e| e.to_string())?);
        seen.clear();
        let _ = script_into(
            &web,
            &format!("location.href='{CALLBACK}-other?code=SIBLING'"),
            &mut seen,
        )?;
        web.pump(300);
        let _ = script_into(
            &web,
            &format!("location.href='{CALLBACK}?code=SCRIPT-CODE&state=st'"),
            &mut seen,
        )?;
        pump_until(&web, &mut seen, "script capture", |e| {
            !captured(e).is_empty()
        })?;
        let got = captured(&seen);
        if got
            != [(
                format!("{CALLBACK}?code=SCRIPT-CODE&state=st"),
                false,
                false,
            )]
        {
            return Err(format!("script capture: {got:?}"));
        }
        if format!("{seen:?}").contains("SCRIPT-CODE") {
            return Err("a captured code reached Debug output".into());
        }
        println!("page-gate1a: script navigation to the callback captured, sibling not OK");

        // A server redirect to the loopback callback: captured, and nothing
        // ever connects to the callback port.
        seen.clear();
        web.begin_load_uri(&origin.url("/authorize"))
            .map_err(|e| e.to_string())?;
        pump_until(&web, &mut seen, "server redirect capture", |e| {
            !captured(e).is_empty()
        })?;
        web.pump(300);
        let got = captured(&seen);
        let expected = format!("{loopback}?code=SERVER-CODE&state=st");
        if got != [(expected.clone(), true, false)] {
            return Err(format!("server redirect capture: {got:?}"));
        }
        let reached = counter.accepted.load(Ordering::Acquire);
        if reached != 0 {
            return Err(format!(
                "the loopback callback was connected to {reached} times"
            ));
        }
        // The captured URL completes a real OAuth flow.
        let pending = ClientConfig::new(
            "https://idp.example.test/a",
            "https://idp.example.test/t",
            "c",
        )
        .map_err(|e| e.to_string())?
        .begin_with(
            &loopback,
            &[],
            Pkce::from_verifier(SecretText::new("a".repeat(43))).map_err(|e| e.to_string())?,
            SecretText::new("st".into()),
        )
        .map_err(|e| e.to_string())?;
        let code = pending
            .complete(&SecretText::new(expected))
            .map_err(|e| e.to_string())?;
        if code.expose_secret() != "SERVER-CODE" {
            return Err("the captured redirect did not yield its code".into());
        }
        let leak = leaked(&seen, "SERVER-CODE");
        if !leak.is_empty() {
            return Err(format!("the captured code reached other events: {leak:?}"));
        }
        println!("page-gate1b: server 302 to loopback captured, 0 connections, code completes OK");

        // The usual "Sign in with…" shape: a popup opens the provider, which
        // redirects *the popup* to the callback. The popup carries its
        // opener's captures, the opener receives the capture, and nothing
        // connects to the callback.
        web.set_popups(true);
        seen.clear();
        web.load(&origin.url("/signin-popup"), 10_000)
            .map_err(|e| e.to_string())?;
        click_centre(&web, &router)?;
        pump_until(&web, &mut seen, "popup sign-in capture", |e| {
            !captured(e).is_empty()
        })?;
        let got = captured(&seen);
        if got.len() != 1 || !got[0].0.contains("POPUP-REDIRECT-CODE") || !got[0].1 || !got[0].2 {
            return Err(format!("popup sign-in capture: {got:?}"));
        }
        let reached = counter.accepted.load(Ordering::Acquire);
        if reached != 0 {
            return Err(format!("the popup reached the callback {reached} times"));
        }
        let leak = leaked(&seen, "POPUP-REDIRECT-CODE");
        if !leak.is_empty() {
            return Err(format!("the popup's code reached other events: {leak:?}"));
        }
        // The host has no use for the sign-in popup now: discard it.
        let signin_popup = seen
            .iter()
            .find_map(|e| match e {
                PageEvent::PopupOpened { id, .. } => Some(*id),
                _ => None,
            })
            .ok_or("the sign-in popup was not opened")?;
        let before = enzui_webkit::native_release::released();
        if !web.discard_popup(signin_popup) || web.discard_popup(signin_popup) {
            return Err("discard_popup did not discard exactly once".into());
        }
        web.pump(200);
        seen.extend(web.take_page_events());
        let released = enzui_webkit::native_release::released().since(before);
        if !seen.contains(&PageEvent::PopupClosed { id: signin_popup })
            || released.web_views_finalized != 1
        {
            return Err(format!("discarding the popup: {released:?} {seen:?}"));
        }
        web.set_popups(false);
        println!(
            "page-gate1d: a popup redirected to the callback is captured for its opener; discarded and freed OK"
        );

        // A popup to the callback is captured too.
        seen.clear();
        web.load(&origin.url("/capture-popup"), 10_000)
            .map_err(|e| e.to_string())?;
        click_centre(&web, &router)?;
        pump_until(&web, &mut seen, "popup capture", |e| {
            !captured(e).is_empty()
        })?;
        let got = captured(&seen);
        if got.len() != 1 || !got[0].0.contains("POPUP-CODE") || !got[0].2 {
            return Err(format!("popup capture: {got:?}"));
        }
        println!("page-gate1c: popup to the callback captured OK");
        web.clear_redirect_captures();

        // ---- 2. load, address and title --------------------------------
        seen.clear();
        web.begin_load_uri(&origin.url("/titled"))
            .map_err(|e| e.to_string())?;
        pump_until(&web, &mut seen, "load finished", |e| {
            e.contains(&PageEvent::Load(LoadStage::Finished))
        })?;
        let stages: Vec<_> = seen
            .iter()
            .filter_map(|e| match e {
                PageEvent::Load(stage) => Some(*stage),
                _ => None,
            })
            .collect();
        if stages
            != [
                LoadStage::Started,
                LoadStage::Committed,
                LoadStage::Finished,
            ]
        {
            return Err(format!("load stages: {stages:?}"));
        }
        if !seen.contains(&PageEvent::TitleChanged("Enz page".into())) {
            return Err(format!("no title event: {seen:?}"));
        }
        if !seen
            .iter()
            .any(|e| matches!(e, PageEvent::UriChanged(u) if u.as_str().ends_with("/titled")))
        {
            return Err(format!("no address event: {seen:?}"));
        }
        if !seen
            .iter()
            .any(|e| matches!(e, PageEvent::Progress(p) if *p >= 1.0))
        {
            return Err(format!("progress never reached 1: {seen:?}"));
        }
        println!("page-gate2: started/committed/finished, title, address, progress OK");

        // ---- 3. scripts ------------------------------------------------
        if script(&web, "1 + 2")? != Ok("3".into()) {
            return Err("1 + 2".into());
        }
        if script(&web, "document.title")? != Ok("\"Enz page\"".into()) {
            return Err("document.title".into());
        }
        if script(&web, "undefined")? != Ok("null".into()) {
            return Err("undefined".into());
        }
        match script(&web, "throw new Error('boom')")? {
            Err(ScriptError::Failed(message)) if message.contains("boom") => {}
            other => return Err(format!("a thrown error: {other:?}")),
        }
        if !web.register_message_handler("host", &ScriptWorld::Page) {
            return Err("message handler refused".into());
        }
        seen.clear();
        let _ = script_into(
            &web,
            "window.webkit.messageHandlers.host.postMessage([1, 'two', {a: true}])",
            &mut seen,
        )?;
        pump_until(&web, &mut seen, "script message", |e| {
            e.iter()
                .any(|e| matches!(e, PageEvent::ScriptMessage { .. }))
        })?;
        let message = seen.iter().find_map(|e| match e {
            PageEvent::ScriptMessage { handler, json } => Some((handler.clone(), json.clone())),
            _ => None,
        });
        if message != Some(("host".into(), "[1,\"two\",{\"a\":true}]".into())) {
            return Err(format!("script message: {message:?}"));
        }
        println!("page-gate3: values, page global, thrown error, posted message OK");

        // ---- 4. script dialogs -----------------------------------------
        seen.clear();
        if script_into(&web, "confirm('sure?')", &mut seen)? != Ok("false".into()) {
            return Err("an unanswered confirm must be false".into());
        }
        seen.extend(web.take_page_events());
        if !seen.contains(&PageEvent::PromptDeclined(DeclinedPrompt::ScriptDialog)) {
            return Err(format!("decline not reported: {seen:?}"));
        }
        web.set_page_prompts(PagePrompts::ALL);
        let id = web
            .evaluate_script("prompt('Your name?', 'nobody')", &ScriptWorld::Page)
            .map_err(|e| e.to_string())?;
        seen.clear();
        pump_until(&web, &mut seen, "prompt dialog", |e| {
            e.iter().any(|e| matches!(e, PageEvent::ScriptDialog(_)))
        })?;
        let dialog = seen
            .iter()
            .find_map(|e| match e {
                PageEvent::ScriptDialog(d) => Some(d.clone()),
                _ => None,
            })
            .expect("seen");
        if dialog.message != "Your name?"
            || dialog.kind
                != (ScriptDialogKind::Prompt {
                    default_text: "nobody".into(),
                })
        {
            return Err(format!("prompt request: {dialog:?}"));
        }
        web.answer_script_dialog(dialog.id, &ScriptDialogAnswer::Text("Ada".into()))
            .map_err(|e| e.to_string())?;
        if web
            .answer_script_dialog(dialog.id, &ScriptDialogAnswer::Accept)
            .is_ok()
        {
            return Err("a dialog was answered twice".into());
        }
        pump_until(&web, &mut seen, "prompt result", |e| {
            e.iter()
                .any(|e| matches!(e, PageEvent::ScriptResult { id: got, .. } if *got == id))
        })?;
        let answered = seen.iter().find_map(|e| match e {
            PageEvent::ScriptResult { id: got, result } if *got == id => Some(result.clone()),
            _ => None,
        });
        if answered != Some(Ok("\"Ada\"".into())) {
            return Err(format!("prompt answer: {answered:?}"));
        }
        println!(
            "page-gate4: unanswered confirm false + reported, host prompt answer reaches the page OK"
        );

        // ---- 5. history ------------------------------------------------
        web.load(&origin.url("/a"), 10_000)
            .map_err(|e| e.to_string())?;
        web.load(&origin.url("/b"), 10_000)
            .map_err(|e| e.to_string())?;
        if !web.can_go_back() || web.can_go_forward() {
            return Err("history flags after two loads".into());
        }
        seen.clear();
        web.take_page_events();
        web.go_back().map_err(|e| e.to_string())?;
        pump_until(&web, &mut seen, "back", |e| {
            e.contains(&PageEvent::TitleChanged("A".into()))
        })?;
        if !web.can_go_forward() {
            return Err("cannot go forward after back".into());
        }
        web.go_forward().map_err(|e| e.to_string())?;
        pump_until(&web, &mut seen, "forward", |e| {
            e.contains(&PageEvent::TitleChanged("B".into()))
        })?;
        println!("page-gate5: back and forward OK");

        // ---- 6. find ---------------------------------------------------
        web.load(&origin.url("/titled"), 10_000)
            .map_err(|e| e.to_string())?;
        seen.clear();
        web.take_page_events();
        web.count_matches("needle", false, 100);
        pump_until(&web, &mut seen, "count", |e| {
            e.iter().any(|e| matches!(e, PageEvent::MatchesCounted(_)))
        })?;
        if !seen.contains(&PageEvent::MatchesCounted(Some(3))) {
            return Err(format!("case-insensitive count: {seen:?}"));
        }
        seen.clear();
        web.count_matches("Needle", true, 100);
        pump_until(&web, &mut seen, "count", |e| {
            e.iter().any(|e| matches!(e, PageEvent::MatchesCounted(_)))
        })?;
        if !seen.contains(&PageEvent::MatchesCounted(Some(1))) {
            return Err(format!("case-sensitive count: {seen:?}"));
        }
        seen.clear();
        web.find("haystack", false, 100);
        pump_until(&web, &mut seen, "find failure", |e| {
            e.contains(&PageEvent::FindFailed)
        })?;
        seen.clear();
        web.find("needle", false, 100);
        pump_until(&web, &mut seen, "find", |e| {
            e.iter().any(|e| matches!(e, PageEvent::FindMatches(_)))
        })?;
        if !seen.contains(&PageEvent::FindMatches(Some(3)))
            || seen
                .iter()
                .any(|e| matches!(e, PageEvent::MatchesCounted(_)))
        {
            return Err(format!("find is not a count: {seen:?}"));
        }
        web.find_finish();
        println!("page-gate6: counts (3 / 1), a find (3) told apart from a count, none OK");

        // ---- 7. settings -----------------------------------------------
        web.apply_settings(&WebSettings {
            user_agent: UserAgent::Custom("EnzTest/1.0".into()),
            ..WebSettings::default()
        });
        if web.user_agent() != "EnzTest/1.0"
            || script(&web, "navigator.userAgent")? != Ok("\"EnzTest/1.0\"".into())
        {
            return Err("custom user agent did not reach the page".into());
        }
        web.apply_settings(&WebSettings::default());
        if web.user_agent() == "EnzTest/1.0" {
            return Err("the default user agent was not restored".into());
        }
        println!("page-gate7: custom user agent reaches navigator.userAgent OK");

        // ---- 8. website data -------------------------------------------
        web.load(&origin.url("/cookie"), 10_000)
            .map_err(|e| e.to_string())?;
        if script(&web, "document.cookie")? != Ok("\"enz=1\"".into()) {
            return Err("the fixture cookie was not set".into());
        }
        seen.clear();
        let id = web.clear_website_data(WebsiteData::COOKIES, None);
        pump_until(&web, &mut seen, "data cleared", |e| {
            e.iter()
                .any(|e| matches!(e, PageEvent::DataCleared { id: got, .. } if *got == id))
        })?;
        if !seen.contains(&PageEvent::DataCleared { id, result: Ok(()) }) {
            return Err(format!("data clear: {seen:?}"));
        }
        web.load(&origin.url("/a"), 10_000)
            .map_err(|e| e.to_string())?;
        if script(&web, "document.cookie")? != Ok("\"\"".into()) {
            return Err("the cookie survived the clear".into());
        }
        println!("page-gate8: page cookie cleared OK");

        // ---- 9. file chooser -------------------------------------------
        let dir = std::env::temp_dir().join(format!("wpe-page-{}", std::process::id()));
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let file = dir.join("chosen.txt");
        std::fs::write(&file, "hello").map_err(|e| e.to_string())?;
        web.load(&origin.url("/file"), 10_000)
            .map_err(|e| e.to_string())?;
        seen.clear();
        web.take_page_events();
        click_centre(&web, &router)?;
        pump_until(&web, &mut seen, "file chooser", |e| {
            e.iter().any(|e| matches!(e, PageEvent::FileChooser(_)))
        })?;
        let chooser = seen
            .iter()
            .find_map(|e| match e {
                PageEvent::FileChooser(c) => Some(c.clone()),
                _ => None,
            })
            .expect("seen");
        web.answer_file_chooser(chooser.id, Some(std::slice::from_ref(&file)))
            .map_err(|e| e.to_string())?;
        web.pump(300);
        let name = script(
            &web,
            "document.querySelector('input').files[0]?.name ?? null",
        )?;
        let _ = std::fs::remove_dir_all(&dir);
        if name != Ok("\"chosen.txt\"".into()) {
            return Err(format!("chosen file: {name:?}"));
        }
        println!(
            "page-gate9: a real click opened the chooser; the host's file reached input.files OK"
        );

        // ---- 10. HTTP authentication -----------------------------------
        seen.clear();
        web.begin_load_uri(&origin.url("/protected"))
            .map_err(|e| e.to_string())?;
        pump_until(&web, &mut seen, "challenge", |e| {
            e.iter().any(|e| matches!(e, PageEvent::Authentication(_)))
        })?;
        let challenge = seen
            .iter()
            .find_map(|e| match e {
                PageEvent::Authentication(c) => Some(c.clone()),
                _ => None,
            })
            .expect("seen");
        if challenge.realm != "Enz realm"
            || challenge.scheme != AuthScheme::Basic
            || challenge.retry
        {
            return Err(format!("challenge: {challenge:?}"));
        }
        web.answer_authentication(
            challenge.id,
            &AuthAnswer::Credentials {
                user: "ada".into(),
                password: SecretText::new("lovelace".into()),
            },
        )
        .map_err(|e| e.to_string())?;
        pump_until(&web, &mut seen, "authed page", |e| {
            e.contains(&PageEvent::TitleChanged("authed".into()))
        })?;
        let sent = origin.authorization.lock().expect("lock").clone();
        if sent.last().map(String::as_str) != Some("Basic YWRhOmxvdmVsYWNl") {
            return Err(format!("Authorization headers: {sent:?}"));
        }
        println!("page-gate10: 401 reached the host; its answer reached the origin OK");

        // ---- 11. allowed popups ----------------------------------------
        web.load(&origin.url("/popup"), 10_000)
            .map_err(|e| e.to_string())?;
        seen.clear();
        web.take_page_events();
        click_centre(&web, &router)?;
        pump_until(&web, &mut seen, "popup", |e| {
            e.iter()
                .any(|e| matches!(e, PageEvent::PopupRequested { .. }))
        })?;
        let popup = seen.iter().find_map(|e| match e {
            PageEvent::PopupRequested {
                url,
                user_initiated,
                ..
            } => Some((url.as_str().to_owned(), *user_initiated)),
            _ => None,
        });
        if popup != Some((origin.url("/popped"), true)) {
            return Err(format!("popup: {popup:?}"));
        }
        println!("page-gate11: an allowed popup is reported with its URL OK");

        // ---- 15. real popups ------------------------------------------
        // With popups enabled, `window.open` becomes a real related view the
        // host takes; `window.opener` reaches back to the opener.
        web.set_popups(true);
        web.apply_settings(&WebSettings {
            user_agent: UserAgent::Custom("EnzOpener/1".into()),
            ..WebSettings::default()
        });
        web.load(&origin.url("/opener"), 10_000)
            .map_err(|e| e.to_string())?;
        seen.clear();
        web.take_page_events();
        click_centre(&web, &router)?;
        pump_until(&web, &mut seen, "popup opened", |e| {
            e.iter().any(|e| matches!(e, PageEvent::PopupOpened { .. }))
        })?;
        let (popup_id, popup_url) = seen
            .iter()
            .find_map(|e| match e {
                PageEvent::PopupOpened { id, url, .. } => Some((*id, url.as_str().to_owned())),
                _ => None,
            })
            .expect("seen");
        if popup_url != origin.url("/child") {
            return Err(format!("popup url {popup_url}"));
        }
        let popup = web
            .take_popup(popup_id)
            .ok_or("the opened popup was not waiting")?
            .map_err(|e| format!("take popup: {e}"))?;
        if web.take_popup(popup_id).is_some() {
            return Err("a popup was taken twice".into());
        }
        pump_until(&web, &mut seen, "opener got the child's message", |e| {
            e.contains(&PageEvent::TitleChanged("got:hello from child".into()))
        })?;
        let mut popup_seen = Vec::new();
        pump_until(
            &popup,
            &mut popup_seen,
            "popup title and ready-to-show",
            |e| {
                e.contains(&PageEvent::TitleChanged("child".into()))
                    && e.contains(&PageEvent::ReadyToShow)
            },
        )?;
        if popup.current_uri().ok().flatten().as_deref() != Some(origin.url("/child").as_str()) {
            return Err("the popup is not at its URL".into());
        }
        // It started with the opener's settings, and its own are its own.
        if script(&popup, "navigator.userAgent")? != Ok("\"EnzOpener/1\"".into()) {
            return Err("the popup did not inherit the opener's user agent".into());
        }
        popup.apply_settings(&WebSettings {
            user_agent: UserAgent::Custom("EnzPopup/1".into()),
            ..WebSettings::default()
        });
        if script(&web, "navigator.userAgent")? != Ok("\"EnzOpener/1\"".into()) {
            return Err("changing the popup's settings changed the opener's".into());
        }
        let before = enzui_webkit::native_release::released();
        drop(popup);
        web.pump(200);
        let released = enzui_webkit::native_release::released().since(before);
        if released.web_sessions != 1 || released.web_views_finalized != 1 {
            return Err(format!(
                "dropping the popup did not free its view: {released:?}"
            ));
        }
        web.apply_settings(&WebSettings::default());
        println!(
            "page-gate15: window.open became a real view; window.opener reached the opener; settings inherited, not shared OK"
        );

        // ---- 16. a popup that closes itself ----------------------------
        seen.clear();
        web.load(&origin.url("/closer"), 10_000)
            .map_err(|e| e.to_string())?;
        web.take_page_events();
        let before = enzui_webkit::native_release::released();
        click_centre(&web, &router)?;
        pump_until(&web, &mut seen, "self-closed popup released", |e| {
            e.iter().any(|e| matches!(e, PageEvent::PopupClosed { .. }))
        })?;
        let opened = seen.iter().find_map(|e| match e {
            PageEvent::PopupOpened { id, .. } => Some(*id),
            _ => None,
        });
        let closed = seen.iter().find_map(|e| match e {
            PageEvent::PopupClosed { id } => Some(*id),
            _ => None,
        });
        web.pump(200);
        let released = enzui_webkit::native_release::released().since(before);
        if opened.is_none() || opened != closed || released.web_views_finalized != 1 {
            return Err(format!(
                "self-closed popup: opened {opened:?}, closed {closed:?}, {released:?}"
            ));
        }
        web.set_popups(false);
        println!(
            "page-gate16: a popup that called window.close() before being taken was released OK"
        );

        // ---- 17. renderer loss -----------------------------------------
        web.load(&origin.url("/titled"), 10_000)
            .map_err(|e| e.to_string())?;
        seen.clear();
        web.take_page_events();
        let attested_before = web.attested_renderer();
        web.terminate_web_process();
        pump_until(&web, &mut seen, "termination event", |e| {
            e.iter()
                .any(|e| matches!(e, PageEvent::WebProcessTerminated(_)))
        })?;
        seen.clear();
        web.reload(false)
            .map_err(|e| format!("reload after loss: {e}"))?;
        pump_until(&web, &mut seen, "page back after loss", |e| {
            e.contains(&PageEvent::TitleChanged("Enz page".into()))
        })?;
        if web.current_uri().ok().flatten().as_deref() != Some(origin.url("/titled").as_str()) {
            return Err(format!(
                "reload after a renderer loss is not at the page: {:?}",
                web.current_uri()
            ));
        }
        let attested_after = web.attested_renderer();
        if attested_after.is_none() || attested_after == attested_before {
            return Err(format!(
                "the reload did not attest a fresh renderer: {attested_before:?} -> {attested_after:?}"
            ));
        }
        println!(
            "page-gate17: a lost renderer is reported; reload brings the page back in a fresh, attested one OK"
        );

        // ---- 18. limits ------------------------------------------------
        match script(&web, "'x'.repeat(70000)")? {
            Err(ScriptError::TooLarge) => {}
            other => return Err(format!("an oversized result: {other:?}")),
        }
        if web.register_message_handler("host", &ScriptWorld::Isolated("other".into())) {
            return Err("one handler name was registered in two worlds".into());
        }
        if !web.register_message_handler("big", &ScriptWorld::Page) {
            return Err("handler refused".into());
        }
        seen.clear();
        let _ = script_into(
            &web,
            "window.webkit.messageHandlers.big.postMessage('y'.repeat(70000))",
            &mut seen,
        )?;
        pump_until(&web, &mut seen, "oversized message", |e| {
            e.iter()
                .any(|e| matches!(e, PageEvent::ScriptMessageTooLarge { .. }))
        })?;
        if seen
            .iter()
            .any(|e| matches!(e, PageEvent::ScriptMessage { handler, .. } if handler == "big"))
        {
            return Err("an oversized message was delivered cut".into());
        }
        println!(
            "page-gate18: an oversized result and message are refused, not cut; one world per handler OK"
        );

        // ---- 19. <select> --------------------------------------------
        // WPE draws no dropdown: the host gets the entries and answers.
        web.load(&origin.url("/select"), 10_000)
            .map_err(|e| e.to_string())?;
        seen.clear();
        web.take_page_events();
        click_centre(&web, &router)?;
        pump_until(&web, &mut seen, "option menu", |e| {
            e.iter().any(|e| matches!(e, PageEvent::OptionMenu(_)))
        })?;
        let menu = seen
            .iter()
            .find_map(|e| match e {
                PageEvent::OptionMenu(menu) => Some(menu.clone()),
                _ => None,
            })
            .expect("seen");
        let labels: Vec<_> = menu.items.iter().map(|item| item.label.as_str()).collect();
        let gamma = labels.iter().position(|label| *label == "Gamma");
        if labels != ["Alpha", "Beta", "More", "Gamma"]
            || !menu.items[1].selected
            || !menu.items[2].group_label
            || !menu.items[3].group_child
            || menu.area.width <= 0
        {
            return Err(format!("option menu: {menu:?}"));
        }
        web.answer_option_menu(menu.id, gamma)
            .map_err(|e| e.to_string())?;
        pump_until(&web, &mut seen, "option picked", |e| {
            e.contains(&PageEvent::TitleChanged("picked:c".into()))
        })?;
        // A dropdown open when the page goes away is closed by WebKit; the
        // host is told and the menu released.
        seen.clear();
        click_centre(&web, &router)?;
        pump_until(&web, &mut seen, "second option menu", |e| {
            e.iter().any(|e| matches!(e, PageEvent::OptionMenu(_)))
        })?;
        let second = seen
            .iter()
            .find_map(|e| match e {
                PageEvent::OptionMenu(menu) => Some(menu.id),
                _ => None,
            })
            .expect("seen");
        web.load(&origin.url("/a"), 10_000)
            .map_err(|e| e.to_string())?;
        pump_until(&web, &mut seen, "option menu closed by WebKit", |e| {
            e.contains(&PageEvent::OptionMenuClosed { id: second })
        })?;
        if web.answer_option_menu(second, Some(0)).is_ok() {
            return Err("a closed dropdown accepted an answer".into());
        }
        println!(
            "page-gate19: a <select> dropdown reaches the host; its pick fires change; a WebKit close is reported OK"
        );

        // ---- 20. permission queries and notifications ------------------
        seen.clear();
        web.load(&origin.url("/permissions"), 10_000)
            .map_err(|e| e.to_string())?;
        // WebKit reports a denial the page has not run into yet as
        // "prompt" (it hides denials from fingerprinting), so the
        // ungranted state reads "prompt"; a grant reads "granted".
        pump_until(&web, &mut seen, "ungranted query", |e| {
            e.contains(&PageEvent::TitleChanged("perm:prompt".into()))
        })?;
        {
            let view = router.live_view(7).ok_or("view")?;
            let mut policy = WebPolicy::strict()
                .grant(enzui_webkit::web::policy::PermissionKind::Geolocation)
                .grant(enzui_webkit::web::policy::PermissionKind::Notifications);
            policy.allow_http = true;
            policy.allow_popups = true;
            policy.allow_downloads = true;
            web.install_native_policy(&router, view, policy, |request| Some(request.id))
                .map_err(|e| e.to_string())?;
        }
        seen.clear();
        web.load(&origin.url("/permissions"), 10_000)
            .map_err(|e| e.to_string())?;
        pump_until(&web, &mut seen, "granted query", |e| {
            e.contains(&PageEvent::TitleChanged("perm:granted".into()))
        })?;
        println!(
            "page-gate20: permissions.query follows the policy (not granted, then granted) OK"
        );

        // ---- 22. notifications -----------------------------------------
        // WebKit refuses notification permission in an ephemeral (private)
        // session before any request reaches the policy; a persistent profile
        // asks, the policy grants, and the notification reaches the host.
        seen.clear();
        web.load(&origin.url("/notify"), 10_000)
            .map_err(|e| e.to_string())?;
        click_centre(&web, &router)?;
        pump_until(&web, &mut seen, "ephemeral refusal", |e| {
            e.contains(&PageEvent::TitleChanged("asked:denied".into()))
        })?;
        {
            let root =
                std::env::temp_dir().join(format!("wpe-page-profile-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            let mut profiles = enzui_webkit::ffi::profile::ProfileStore::new(&root);
            let profile = enzui_webkit::web::WebProfile::persistent("notify");
            let mut profiled =
                WebSession::new_profiled_trusted_local(&display, &mut profiles, &profile)
                    .map_err(|e| e.to_string())?;
            let mut profiled_router = ViewRouter::new();
            let view = profiled_router.create(7);
            profiled
                .bind_view(&profiled_router, view)
                .map_err(|e| e.to_string())?;
            let mut policy =
                WebPolicy::strict().grant(enzui_webkit::web::policy::PermissionKind::Notifications);
            policy.allow_http = true;
            profiled
                .install_native_policy(&profiled_router, view, policy, |request| Some(request.id))
                .map_err(|e| e.to_string())?;
            profiled
                .load(&origin.url("/notify"), 10_000)
                .map_err(|e| e.to_string())?;
            let mut events = Vec::new();
            click_centre(&profiled, &profiled_router)?;
            pump_until(&profiled, &mut events, "notification", |e| {
                e.iter().any(|e| matches!(e, PageEvent::Notification(_)))
            })?;
            let shown = events.iter().find_map(|e| match e {
                PageEvent::Notification(n) => Some(n.clone()),
                _ => None,
            });
            if shown
                .as_ref()
                .map(|n| (n.title.as_str(), n.body.as_str(), n.tag.as_deref()))
                != Some(("Hi", "There", Some("t1")))
                || shown.as_ref().is_some_and(|n| n.origin.is_none())
            {
                return Err(format!("notification: {shown:?}"));
            }
            drop(profiled);
            drop(profiles);
            let _ = std::fs::remove_dir_all(&root);
        }
        println!(
            "page-gate22: an ephemeral session is refused notifications; a profiled, granted one shows them to the host OK"
        );

        // ---- 21. hover, fullscreen, mute ------------------------------
        web.load(&origin.url("/link"), 10_000)
            .map_err(|e| e.to_string())?;
        seen.clear();
        web.take_page_events();
        {
            let view = router.live_view(7).ok_or("view")?;
            let mapping = ViewportMapping::new(0.0, 0.0, 1024.0, 768.0, 1.0).expect("mapping");
            // Across two elements that are not links, then onto the link.
            for (x, y) in [
                (200.0, 150.0),
                (800.0, 150.0),
                (500.0, 600.0),
                (520.0, 610.0),
            ] {
                let event = input::pointer_moved(view, &mapping, x, y).ok_or("pointer")?;
                if !web.forward_input(&event) {
                    return Err("bound session refused a pointer move".into());
                }
                web.pump(100);
            }
        }
        pump_until(&web, &mut seen, "hovered link", |e| {
            e.iter()
                .any(|e| matches!(e, PageEvent::HoveredLink(Some(_))))
        })?;
        let hovered: Vec<_> = seen
            .iter()
            .filter_map(|e| match e {
                PageEvent::HoveredLink(link) => Some(link.as_ref().map(|u| u.as_str().to_owned())),
                _ => None,
            })
            .collect();
        if hovered != [Some(origin.url("/b"))] {
            return Err(format!("hover is reported once per change: {hovered:?}"));
        }
        web.load(&origin.url("/fullscreen"), 10_000)
            .map_err(|e| e.to_string())?;
        seen.clear();
        web.take_page_events();
        click_centre(&web, &router)?;
        pump_until(&web, &mut seen, "fullscreen", |e| {
            e.contains(&PageEvent::Fullscreen(true))
        })?;
        web.set_muted(true);
        if !web.is_muted() {
            return Err("mute did not stick".into());
        }
        web.set_muted(false);
        println!("page-gate21: hovered link (once per change), fullscreen request, mute OK");

        // ---- 23. a page that objects to closing ------------------------
        web.load(&origin.url("/leave"), 10_000)
            .map_err(|e| e.to_string())?;
        // WebKit runs beforeunload prompts only for a page the person used.
        click_centre(&web, &router)?;
        for answer in [ScriptDialogAnswer::Dismiss, ScriptDialogAnswer::Accept] {
            seen.clear();
            web.take_page_events();
            web.try_close();
            pump_until(&web, &mut seen, "before-unload dialog", |e| {
                e.iter().any(|e| matches!(e, PageEvent::ScriptDialog(d) if d.kind == ScriptDialogKind::BeforeUnload))
            })?;
            let id = seen
                .iter()
                .find_map(|e| match e {
                    PageEvent::ScriptDialog(d) => Some(d.id),
                    _ => None,
                })
                .expect("seen");
            web.answer_script_dialog(id, &answer)
                .map_err(|e| e.to_string())?;
            let stay = answer == ScriptDialogAnswer::Dismiss;
            if stay {
                web.pump(800);
                seen.extend(web.take_page_events());
                if seen.contains(&PageEvent::CloseRequested) {
                    return Err("the page closed although the host kept it".into());
                }
            } else {
                pump_until(&web, &mut seen, "close after leave", |e| {
                    e.contains(&PageEvent::CloseRequested)
                })?;
            }
        }
        println!(
            "page-gate23: an objecting page raises a before-unload dialog; Dismiss keeps it, Accept closes OK"
        );

        // ---- 12. close -------------------------------------------------
        // Leaving `/leave` asks again; with dialogs off the engine's decline
        // leaves the page, so the load is not held by a prompt.
        web.set_page_prompts(PagePrompts::default());
        web.load(&origin.url("/a"), 10_000)
            .map_err(|e| e.to_string())?;
        web.set_page_prompts(PagePrompts::ALL);
        seen.clear();
        web.try_close();
        pump_until(&web, &mut seen, "close", |e| {
            e.contains(&PageEvent::CloseRequested)
        })?;
        println!("page-gate12: try_close reports CloseRequested OK");
        if web.page_events_dropped() != 0 {
            return Err("events were dropped".into());
        }

        // ---- 14. downloads ----------------------------------------------
        // No directory: the policy allows it, the engine declines it, and
        // nothing is written.
        seen.clear();
        web.take_page_events();
        web.begin_load_uri(&origin.url("/report"))
            .map_err(|e| e.to_string())?;
        pump_until(&web, &mut seen, "declined download", |e| {
            e.iter()
                .any(|e| matches!(e, PageEvent::DownloadDeclined { .. }))
        })?;
        let dir = std::env::temp_dir().join(format!("wpe-page-dl-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        // A file already holding the safe name must survive untouched.
        std::fs::write(dir.join("report.txt"), "keep me").map_err(|e| e.to_string())?;
        web.set_download_directory(Some(dir.clone()))
            .map_err(|e| e.to_string())?;
        seen.clear();
        web.begin_load_uri(&origin.url("/report"))
            .map_err(|e| e.to_string())?;
        pump_until(&web, &mut seen, "finished download", |e| {
            e.iter().any(|e| {
                matches!(
                    e,
                    PageEvent::DownloadFinished { .. } | PageEvent::DownloadFailed { .. }
                )
            })
        })?;
        let started = seen.iter().find_map(|e| match e {
            PageEvent::DownloadStarted {
                suggested_name,
                path,
                ..
            } => Some((suggested_name.clone(), path.clone())),
            _ => None,
        });
        let finished = seen.iter().find_map(|e| match e {
            PageEvent::DownloadFinished { path, .. } => Some(path.clone()),
            _ => None,
        });
        let expected_path = dir.join("report (2).txt");
        // WebKit already reduces the server's `../report.txt` to its last
        // component; the engine's own sanitiser is unit-tested in `page`.
        if started != Some(("report.txt".into(), expected_path.clone()))
            || finished.as_ref() != Some(&expected_path)
        {
            return Err(format!("download events: {seen:#?}"));
        }
        let written = std::fs::read_to_string(&expected_path).map_err(|e| e.to_string())?;
        let kept = std::fs::read_to_string(dir.join("report.txt")).map_err(|e| e.to_string())?;
        let progress = seen
            .iter()
            .filter(|e| matches!(e, PageEvent::DownloadProgress { .. }))
            .count();
        if written != *REPORT || kept != "keep me" || progress < 2 {
            return Err(format!(
                "download content {} bytes (want {}), kept {kept:?}, {progress} progress events",
                written.len(),
                REPORT.len()
            ));
        }
        // Cancel mid-transfer: the file is removed.
        seen.clear();
        web.begin_load_uri(&origin.url("/slow"))
            .map_err(|e| e.to_string())?;
        pump_until(&web, &mut seen, "slow download started", |e| {
            e.iter()
                .any(|e| matches!(e, PageEvent::DownloadProgress { .. }))
        })?;
        let (slow, slow_path) = seen
            .iter()
            .find_map(|e| match e {
                PageEvent::DownloadStarted { id, path, .. } => Some((*id, path.clone())),
                _ => None,
            })
            .ok_or("slow download not started")?;
        if !web.cancel_download(slow) {
            return Err("cancel refused".into());
        }
        pump_until(&web, &mut seen, "cancelled download", |e| {
            e.iter().any(|e| matches!(e, PageEvent::DownloadFailed { id, cancelled: true, .. } if *id == slow))
        })?;
        if slow_path.exists() {
            return Err("a cancelled download left its file".into());
        }
        // An HTML page the server marks as an attachment downloads instead of
        // replacing the page.
        seen.clear();
        web.begin_load_uri(&origin.url("/attachment-html"))
            .map_err(|e| e.to_string())?;
        pump_until(&web, &mut seen, "attachment download", |e| {
            e.iter().any(|e| {
                matches!(
                    e,
                    PageEvent::DownloadFinished { .. } | PageEvent::DownloadFailed { .. }
                )
            })
        })?;
        let attachment = seen.iter().find_map(|e| match e {
            PageEvent::DownloadFinished { path, .. } => Some(path.clone()),
            _ => None,
        });
        match attachment {
            Some(path) if std::fs::read_to_string(&path).ok().as_deref() == Some("<p>keep</p>") => {
            }
            other => {
                return Err(format!(
                    "attachment HTML was not downloaded: {other:?} {seen:?}"
                ));
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
        web.set_download_directory(None)
            .map_err(|e| e.to_string())?;
        println!(
            "page-gate14: declined without a directory; fresh name beside an existing file, content whole, progress; cancel leaves no file OK"
        );

        // ---- 13. declining what waits, and teardown --------------------
        // A host that closes its prompt UI declines what waits; the page's
        // `alert()` then returns, and a later dialog still reaches the host.
        web.load(&origin.url("/a"), 10_000)
            .map_err(|e| e.to_string())?;
        web.take_page_events();
        let id = web
            .evaluate_script(
                "alert('declined by the host'); 'returned'",
                &ScriptWorld::Page,
            )
            .map_err(|e| e.to_string())?;
        seen.clear();
        pump_until(&web, &mut seen, "alert to decline", |e| {
            e.iter().any(|e| matches!(e, PageEvent::ScriptDialog(_)))
        })?;
        if web.decline_pending_prompts() != 1 || web.decline_pending_prompts() != 0 {
            return Err("decline_pending_prompts did not take exactly the one alert".into());
        }
        pump_until(&web, &mut seen, "declined alert returns", |e| {
            e.contains(&PageEvent::ScriptResult {
                id,
                result: Ok("\"returned\"".into()),
            })
        })?;
        // Dropping the session declines what the host never answered.
        seen.clear();
        web.take_page_events();
        let _ = web.evaluate_script("alert('left waiting')", &ScriptWorld::Page);
        pump_until(&web, &mut seen, "waiting alert", |e| {
            e.iter().any(|e| matches!(e, PageEvent::ScriptDialog(_)))
        })?;
        drop(web);
        let (again, _) = session(&display)?;
        again.load_ok(&origin.url("/b"))?;
        println!(
            "page-gate13: a session dropped with a dialog waiting tears down; the next one loads OK"
        );
        Ok(())
    }
}

#[cfg(feature = "wpe")]
#[test]
#[ignore = "requires the confined WPE source runtime"]
fn wpe_page_conversation_reaches_the_host() {
    wpe_native_support::run("wpe_page_conversation_reaches_the_host", || {
        if let Err(error) = gates::run() {
            panic!("page gate failed: {error}");
        }
    });
}
