//! `wpe_frame_secrets` - a frame-scoped secret handler reports which frame,
//! document and HTTPS origins posted, evaluation reaches that document of a
//! cross-origin sign-in frame and no other, and the page world cannot post.
//!
//! ```text
//! cargo test --offline --locked --workspace --features enzui-webkit/wpe \
//!     --test wpe_frame_secrets -- --ignored --nocapture
//! ```

mod wpe_native_support;
mod wpe_tls_origin;

use enzui_security::secret::SecretText;
use enzui_webkit::{
    ffi::{
        page::SecretScriptJob,
        runtime::{HeadlessDisplay, WebSession},
    },
    page::{
        FrameDocument, PageEvent, ScriptError, ScriptFrames, ScriptTiming, ScriptWorld, UserScript,
    },
};
use std::time::{Duration, Instant};
use wpe_tls_origin::TlsRedirectOrigin;

const WORLD: &str = "frame-credentials";

struct Post {
    frame: FrameDocument,
    origin: String,
    top_origin: String,
    main_frame: bool,
    json: String,
}

thread_local! {
    /// Posts that arrived while `result` waited for an evaluation: a frame
    /// that navigates can post from its new document before the job ends.
    static EARLY_POSTS: std::cell::RefCell<Vec<PageEvent>> = const { std::cell::RefCell::new(Vec::new()) };
}

fn posts(session: &WebSession, wanted: usize) -> Vec<Post> {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut found = Vec::new();
    let mut early = EARLY_POSTS.with_borrow_mut(std::mem::take);
    while found.len() < wanted && Instant::now() < deadline {
        session.pump(20);
        early.extend(session.take_page_events());
        for event in std::mem::take(&mut early) {
            match event {
                PageEvent::FrameSecretMessage {
                    handler,
                    frame,
                    origin,
                    top_origin,
                    main_frame,
                    json,
                } => {
                    assert_eq!(handler, "frames");
                    found.push(Post {
                        frame,
                        origin: origin.as_str().to_owned(),
                        top_origin: top_origin.as_str().to_owned(),
                        main_frame,
                        json: json.expose_secret().to_owned(),
                    });
                }
                PageEvent::ScriptMessage { .. } | PageEvent::SecretScriptMessage { .. } => {
                    panic!("a frame-scoped post reached another event")
                }
                _ => {}
            }
        }
    }
    found
}

fn result(session: &WebSession, job: &mut SecretScriptJob) -> Result<SecretText, ScriptError> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        session.pump(10);
        for event in session.take_page_events() {
            if matches!(event, PageEvent::FrameSecretMessage { .. }) {
                EARLY_POSTS.with_borrow_mut(|early| early.push(event));
            }
        }
        if let Some(result) = job.take() {
            return result;
        }
        assert!(Instant::now() < deadline, "frame evaluation deadline");
    }
}

#[test]
#[ignore = "requires the confined WPE source runtime"]
fn frame_secrets_identify_and_reach_a_cross_origin_sign_in_frame() {
    wpe_native_support::run(
        "frame_secrets_identify_and_reach_a_cross_origin_sign_in_frame",
        || {
            let display = HeadlessDisplay::new().expect("display");
            let top = TlsRedirectOrigin::start().expect("top origin");
            let login = top.start_another().expect("sign-in origin");
            let mut session = WebSession::new_trusted_local(&display).expect("session");
            session
                .allow_tls_certificate_for_host(top.cert_pem(), "localhost")
                .expect("trust fixture certificate");
            assert!(
                session.register_frame_secret_message_handler("frames", WORLD),
                "frame-scoped handler registered"
            );
            session
                .add_user_script(&UserScript {
                    source: "window.webkit.messageHandlers.frames.postMessage(\
                             document.querySelector('#password') ? 'login' : 'other')"
                        .into(),
                    frames: ScriptFrames::AllFrames,
                    timing: ScriptTiming::DocumentEnd,
                    world: ScriptWorld::Isolated(WORLD.into()),
                })
                .expect("bridge script");
            let login_url =
                login.html_url("<!doctype html><form><input id=password type=password></form>");
            let page = top.html_url(&format!(
                "<!doctype html><p>top</p><iframe src=\"{login_url}\"></iframe>"
            ));
            session.load(&page, 10_000).expect("top document");

            let found = posts(&session, 2);
            assert_eq!(found.len(), 2, "both documents posted");
            let top_origin = format!("https://localhost:{}", top.port());
            let login_origin = format!("https://localhost:{}", login.port());
            let main = found.iter().find(|post| post.main_frame).expect("top post");
            let child = found
                .iter()
                .find(|post| !post.main_frame)
                .expect("frame post");
            assert_eq!(main.json, "\"other\"");
            assert_eq!(main.origin, top_origin, "top document origin");
            assert_eq!(child.json, "\"login\"");
            assert_eq!(
                child.origin, login_origin,
                "sign-in frame origin from WebKit"
            );
            assert_eq!(child.top_origin, top_origin, "embedding origin from WebKit");
            assert_ne!(main.frame, child.frame, "frames are told apart");

            let mut fill = session
                .evaluate_secret_script_in_frame(
                    &child.frame,
                    &SecretText::new("password.value = 'filled'; location.origin".into()),
                    WORLD,
                )
                .expect("frame evaluation");
            assert_eq!(
                result(&session, &mut fill)
                    .expect("frame result")
                    .expose_secret(),
                format!("{login_origin:?}"),
                "evaluation ran in the sign-in frame"
            );
            let mut wrong = session
                .evaluate_secret_script_in_frame(
                    &main.frame,
                    &SecretText::new("document.querySelector('#password') === null".into()),
                    WORLD,
                )
                .expect("top evaluation");
            assert_eq!(
                result(&session, &mut wrong)
                    .expect("top result")
                    .expose_secret(),
                "true",
                "evaluation in the top document stays there"
            );

            // The page world has no handler to forge posts with.
            session
                .evaluate_script(
                    "document.title = String(!!(window.webkit && window.webkit.messageHandlers \
                     && window.webkit.messageHandlers.frames))",
                    &ScriptWorld::Page,
                )
                .expect("page probe");
            session.pump(300);
            assert_eq!(
                session.page_title().ok().flatten().as_deref(),
                Some("false")
            );

            // A replaced document in the same frame no longer matches.
            let mut navigate = session
                .evaluate_secret_script_in_frame(
                    &child.frame,
                    &SecretText::new(format!(
                        "location.href = {:?}; true",
                        login.html_url("<!doctype html><p>replaced</p>")
                    )),
                    WORLD,
                )
                .expect("frame navigation");
            let _ = result(&session, &mut navigate);
            let replaced = posts(&session, 1);
            assert_eq!(replaced.len(), 1, "the replacement document posted");
            assert_eq!(replaced[0].json, "\"other\"");
            assert_eq!(replaced[0].origin, login_origin);
            let mut stale = session
                .evaluate_secret_script_in_frame(
                    &child.frame,
                    &SecretText::new("'stale'".into()),
                    WORLD,
                )
                .expect("stale evaluation");
            assert!(
                result(&session, &mut stale).is_err(),
                "evaluation for the replaced document was refused"
            );
            let mut current = session
                .evaluate_secret_script_in_frame(
                    &replaced[0].frame,
                    &SecretText::new("'current'".into()),
                    WORLD,
                )
                .expect("current evaluation");
            assert_eq!(
                result(&session, &mut current)
                    .expect("current result")
                    .expose_secret(),
                "\"current\""
            );
            println!("Frame secrets passed: sources, targeting, forgery, replacement");
        },
    );
}
