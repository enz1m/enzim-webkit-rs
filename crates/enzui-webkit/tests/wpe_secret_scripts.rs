//! Private isolated scripts preserve document custody and redact secret results.
//!
//! ```text
//! cargo test --offline --locked -p enzui-webkit --features wpe \
//!     --test wpe_secret_scripts -- --ignored --nocapture
//! ```

mod wpe_native_support;

use enzui_security::secret::SecretText;
use enzui_webkit::{
    ffi::{
        page::SecretScriptJob,
        runtime::{HeadlessDisplay, WebSession},
    },
    page::{PageEvent, ScriptError, ScriptWorld},
};
use std::time::{Duration, Instant};

const SENTINEL: &str = "fixture-only-private-credential-92813";
fn result(session: &WebSession, job: &mut SecretScriptJob) -> Result<SecretText, ScriptError> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        session.pump(10);
        for event in session.take_page_events() {
            assert!(
                !matches!(event, PageEvent::ScriptResult { .. }),
                "private evaluations must bypass the public result queue"
            );
            assert!(
                !format!("{event:?}").contains(SENTINEL),
                "public event diagnostics leaked private data"
            );
        }
        if let Some(result) = job.take() {
            return result;
        }
        assert!(Instant::now() < deadline, "private evaluation deadline");
    }
}

#[test]
#[ignore = "requires the confined WPE source runtime"]
fn secret_scripts_redact_results_messages_and_exceptions() {
    wpe_native_support::run(
        "secret_scripts_redact_results_messages_and_exceptions",
        || {
            let display = HeadlessDisplay::new().expect("display");
            let mut session = WebSession::new(&display).expect("session");
            session
                .load("data:text/html,<input type=password>", 10_000)
                .expect("document");
            let world = "credential-secret-test";
            assert!(
                session.register_secret_message_handler("credentials", world),
                "private handler registered"
            );
            assert!(
                !session.register_message_handler("credentials", &ScriptWorld::Page),
                "page-world spoof refused"
            );
            assert!(
                !session
                    .register_message_handler("credentials", &ScriptWorld::Isolated(world.into())),
                "ordinary handler cannot reuse private mode"
            );
            assert!(
                !session.register_secret_message_handler("credentials", ""),
                "empty isolated world refused"
            );
            let id = session
                .evaluate_script(
                    "typeof window.webkit?.messageHandlers?.credentials",
                    &ScriptWorld::Page,
                )
                .expect("page-world inspection");
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut hidden = false;
            while Instant::now() < deadline && !hidden {
                session.pump(10);
                for event in session.take_page_events() {
                    if let PageEvent::ScriptResult { id: found, result } = event
                        && found == id
                    {
                        assert_eq!(
                            result.expect("page-world result"),
                            "\"undefined\"",
                            "page JavaScript cannot access the secret handler"
                        );
                        hidden = true;
                    }
                }
            }
            assert!(hidden, "page-world inspection completed");
            let source = SecretText::new(format!("({SENTINEL:?})"));
            let mut evaluation = session
                .evaluate_secret_script(&source, world)
                .expect("private evaluation");
            assert!(
                !format!("{evaluation:?}").contains(SENTINEL),
                "private task diagnostics redact source/result"
            );
            assert_eq!(
                result(&session, &mut evaluation)
                    .expect("protected result")
                    .expose_secret(),
                format!("{SENTINEL:?}"),
                "private JSON roundtrip"
            );
            assert!(evaluation.take().is_none(), "result consumed exactly once");
            let mut failure = session
                .evaluate_secret_script(
                    &SecretText::new(format!("throw new Error({SENTINEL:?})")),
                    world,
                )
                .expect("throwing private evaluation");
            let error = result(&session, &mut failure).expect_err("script exception");
            assert!(
                !format!("{error:?}").contains(SENTINEL),
                "private page exception text is redacted"
            );
            let mut post = session
                .evaluate_secret_script(
                    &SecretText::new(format!(
                        "window.webkit.messageHandlers.credentials.postMessage({SENTINEL:?});true"
                    )),
                    world,
                )
                .expect("private post");
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut delivered = false;
            while Instant::now() < deadline && !delivered {
                session.pump(10);
                for event in session.take_page_events() {
                    assert!(
                        !format!("{event:?}").contains(SENTINEL),
                        "private message diagnostics redact data"
                    );
                    match event {
                        PageEvent::SecretScriptMessage { handler, json } => {
                            assert_eq!(handler, "credentials", "correct private handler");
                            assert_eq!(
                                json.expose_secret(),
                                format!("{SENTINEL:?}"),
                                "private payload preserved"
                            );
                            delivered = true;
                        }
                        PageEvent::ScriptMessage { .. } | PageEvent::ScriptResult { .. } => {
                            panic!("private operation reached ordinary events")
                        }
                        _ => {}
                    }
                }
            }
            assert!(delivered, "private message delivered");
            let _ = post.take();
            let mut oversized = session.evaluate_secret_script(&SecretText::new(format!("window.webkit.messageHandlers.credentials.postMessage('x'.repeat({}));true", enzui_webkit::page::MAX_PAGE_TEXT_BYTES + 10)), world).expect("oversized private post");
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut refused = false;
            while Instant::now() < deadline && !refused {
                session.pump(10);
                for event in session.take_page_events() {
                    match event {
                        PageEvent::ScriptMessageTooLarge { handler } => {
                            assert_eq!(
                                handler, "credentials",
                                "oversized private handler identified"
                            );
                            refused = true;
                        }
                        PageEvent::SecretScriptMessage { .. } => {
                            panic!("oversized private data was delivered")
                        }
                        _ => {}
                    }
                }
            }
            assert!(
                refused,
                "oversized private message rejected without content"
            );
            let _ = oversized.take();
            let mut page = session
                .evaluate_secret_script(
                    &SecretText::new("typeof window.__credential_secret_fixture".into()),
                    world,
                )
                .expect("separate globals");
            assert_eq!(
                result(&session, &mut page)
                    .expect("private globals")
                    .expose_secret(),
                "\"undefined\"",
                "fixture has no accidental page global"
            );
        },
    );
}

#[test]
#[ignore = "requires the confined WPE source runtime"]
fn secret_scripts_cancel_on_navigation_and_session_drop() {
    wpe_native_support::run(
        "secret_scripts_cancel_on_navigation_and_session_drop",
        || {
            let display = HeadlessDisplay::new().expect("display");
            let mut session = WebSession::new(&display).expect("session");
            session
                .load("data:text/html,first", 10_000)
                .expect("document");
            let mut old = session
                .evaluate_secret_script(&SecretText::new(format!("{SENTINEL:?}")), "private")
                .expect("pending private evaluation");
            session
                .begin_load_uri("data:text/html,next")
                .expect("navigation");
            assert!(
                matches!(old.take(), Some(Err(ScriptError::Cancelled))),
                "host navigation invalidates a pending private result"
            );
            let mut dropped = session
                .evaluate_secret_script(&SecretText::new(format!("{SENTINEL:?}")), "private")
                .expect("pending before close");
            drop(session);
            assert!(
                matches!(dropped.take(), Some(Err(ScriptError::Cancelled))),
                "session drop invalidates private custody"
            );
        },
    );
}
