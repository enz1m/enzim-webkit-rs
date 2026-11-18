//! Native URL scoping preserves script worlds and document-start ordering.
//!
//! ```text
//! cargo test --offline --locked -p enzui-webkit --features wpe \
//!   --test wpe_script_matching page_and_isolated_scripts_obey_native_url_scope \
//!   -- --exact --ignored --nocapture
//! ```

mod wpe_native_support;

use enzui_webkit::ffi::runtime::{HeadlessDisplay, WebSession};
use enzui_webkit::page::{
    ContentInjectionError, PageEvent, ScriptFrames, ScriptTiming, ScriptWorld, UserScript,
};
use serde_json::json;
use std::time::{Duration, Instant};

fn evaluate(session: &WebSession, world: &ScriptWorld, source: &str) -> serde_json::Value {
    let id = session
        .evaluate_script(source, world)
        .expect("scope evaluation");
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        session.pump(10);
        for event in session.take_page_events() {
            if let PageEvent::ScriptResult { id: found, result } = event
                && found == id
            {
                return serde_json::from_str(&result.expect("scope script result"))
                    .expect("scope JSON result");
            }
        }
        assert!(Instant::now() < deadline, "scope evaluation deadline");
    }
}

#[test]
#[ignore = "requires the confined WPE source runtime"]
fn page_and_isolated_scripts_obey_native_url_scope() {
    wpe_native_support::run("page_and_isolated_scripts_obey_native_url_scope", || {
        let display = HeadlessDisplay::new().expect("display");
        for world in [
            ScriptWorld::Page,
            ScriptWorld::Isolated("native-url-scope".into()),
        ] {
            let mut session = WebSession::new(&display).expect("scope session");
            let script = UserScript {
                source: "globalThis.__scopeCount=(globalThis.__scopeCount??0)+1".into(),
                frames: ScriptFrames::TopFrame,
                timing: ScriptTiming::DocumentStart,
                world: world.clone(),
            };
            let matches = vec!["https://scope.test/*".into()];
            let excludes = vec!["https://scope.test/*private*".into()];
            assert!(
                matches!(
                    session.add_user_script_matching(&script, &[], &[]),
                    Err(ContentInjectionError::NoMatches)
                ),
                "empty matches must not inject everywhere"
            );
            assert!(
                matches!(
                    session.add_user_script_matching(&script, &["invalid".into()], &[]),
                    Err(ContentInjectionError::InvalidPattern)
                ),
                "invalid pattern refused"
            );
            let mut invalid = script.clone();
            invalid.source.push('\0');
            assert!(
                matches!(
                    session.add_user_script_matching(&invalid, &matches, &excludes),
                    Err(ContentInjectionError::Script(_))
                ),
                "invalid source refused"
            );
            session
                .add_user_script_matching(&script, &matches, &excludes)
                .expect("install scoped script");
            let page = "<!doctype html><script>document.documentElement.dataset.inlineScope=String(globalThis.__scopeCount??0)</script>";
            for (url, expected) in [
                ("https://outside.test/", 0),
                ("https://scope.test/allowed", 1),
                ("https://scope.test/private/blocked", 0),
                ("https://scope.test/allowed?next=/private/blocked", 1),
            ] {
                session
                    .load_html(page, url, 10_000)
                    .expect("scope document");
                assert_eq!(
                    evaluate(&session, &world, "globalThis.__scopeCount??0"),
                    json!(expected),
                    "scope mismatch at {url} in {world:?}"
                );
                let page_expected = if world == ScriptWorld::Page {
                    expected
                } else {
                    0
                };
                assert_eq!(
                    evaluate(
                        &session,
                        &ScriptWorld::Page,
                        "document.documentElement.dataset.inlineScope"
                    ),
                    json!(page_expected.to_string()),
                    "injection must precede page scripts and preserve world isolation"
                );
            }
            session.remove_user_scripts();
            session
                .load_html(page, "https://scope.test/allowed", 10_000)
                .expect("removed script document");
            assert_eq!(
                evaluate(&session, &world, "globalThis.__scopeCount??0"),
                json!(0),
                "removal must include scoped scripts"
            );
        }
    });
}
