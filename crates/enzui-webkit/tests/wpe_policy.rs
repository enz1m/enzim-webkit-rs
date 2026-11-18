//! Native policy gate for real WPE callbacks.
//!
//! ```text
//! cargo test --features wpe -p enzui-webkit --test wpe_policy \
//!     -- --ignored --nocapture
//! ```

#[cfg(feature = "wpe")]
mod wpe_native_support;

#[cfg(feature = "wpe")]
use enzui_webkit::ffi::policy::{
    BoundedObservations, CertificateAction, CertificateLedger, NativePolicyOutcome,
};
#[cfg(feature = "wpe")]
use enzui_webkit::ffi::runtime::{HeadlessDisplay, SessionError, WebSession};
#[cfg(feature = "wpe")]
use enzui_webkit::frame::Generation;
#[cfg(feature = "wpe")]
use enzui_webkit::frame_plan::FrameSeq;
#[cfg(feature = "wpe")]
use enzui_webkit::input::{InputEvent, Modifiers, PointerButton, ViewPoint};
#[cfg(feature = "wpe")]
use enzui_webkit::web::ViewRouter;
#[cfg(feature = "wpe")]
use enzui_webkit::web::policy::{PermissionKind, RequestKind, WebPolicy};

#[cfg(feature = "wpe")]
#[test]
fn native_policy_diagnostic_api_returns_owned_snapshots() {
    let _: fn(&WebSession) -> Option<BoundedObservations> = WebSession::native_policy_observations;
    let _: fn(&WebSession) -> Option<CertificateLedger> = WebSession::native_certificate_ledger;
}

#[cfg(feature = "wpe")]
#[test]
#[ignore = "requires the confined WPE source runtime and openssl for a localhost TLS fixture"]
fn wpe_callbacks_are_correlated_generation_scoped_and_fail_closed() {
    wpe_native_support::run(
        "wpe_callbacks_are_correlated_generation_scoped_and_fail_closed",
        || {
            if let Err(error) = run() {
                panic!("native policy gate FAILED: {error}");
            }
            println!(
                "wpe_callbacks_are_correlated_generation_scoped_and_fail_closed: ALL GATES OK"
            );
        },
    );
}

#[cfg(feature = "wpe")]
fn run() -> Result<(), String> {
    use std::sync::{Arc, Mutex};

    let origin = Origin::start()?;
    let display = HeadlessDisplay::new().expect("headless WPE display");
    // Loopback fixtures require the explicit trusted-local destination posture.
    let mut web = WebSession::new_trusted_local(&display).map_err(|e| e.to_string())?;
    let mut router = ViewRouter::new();
    let first = router.create(41);
    let first_request = Arc::new(Mutex::new(None));
    let remembered = first_request.clone();
    let live_request = Arc::new(Mutex::new(None));
    let live_remembered = live_request.clone();

    let mut policy = WebPolicy::strict().grant(PermissionKind::Geolocation);
    policy.allow_http = true;
    policy.allow_popups = true;
    if !matches!(
        web.install_native_policy(
            &router,
            enzui_webkit::web::ViewId::new(99),
            WebPolicy::strict(),
            |_| None,
        ),
        Err(SessionError::PolicyViewGone)
    ) {
        return Err("policy installed for a view generation the router never opened".into());
    }
    web.bind_view(&router, first)
        .map_err(|e| format!("bind first view: {e}"))?;
    web.install_native_policy(&router, first, policy, move |request| {
        match &request.kind {
            RequestKind::Navigation(nav) if nav.url.as_str().contains("/green") => {
                *remembered.lock().unwrap() = Some(request.id);
                Some(request.id)
            }
            RequestKind::Navigation(nav) if nav.url.as_str().contains("/stale") => {
                // Deliberately answer generation 1's callback with generation
                // 0's real request id. The native navigation must be ignored.
                *remembered.lock().unwrap()
            }
            RequestKind::Navigation(nav) if nav.url.as_str().contains("/no-response") => None,
            RequestKind::Navigation(nav) if nav.url.as_str().contains("/actions") => {
                *live_remembered.lock().unwrap() = Some(request.id);
                Some(request.id)
            }
            RequestKind::Navigation(nav) if nav.url.as_str().contains("/mismatch") => {
                // Right generation, wrong correlation id.
                *live_remembered.lock().unwrap()
            }
            RequestKind::Popup(_) => None, // no response: immediate native deny
            _ => Some(request.id),
        }
    })
    .map_err(|e| format!("install policy: {e}"))?;

    // Positive control: an exact live-generation reply reaches native `use()`
    // and renders green.
    web.load(&origin.url("/green"), 10_000)
        .map_err(|e| format!("green load: {e}"))?;
    let green = centre(&mut web, 0)?;
    if green != (18, 170, 68, 255) {
        return Err(format!("positive control did not render green: {green:?}"));
    }
    let observations = web.native_policy_observations().unwrap();
    let nav = observations
        .iter()
        .find(|o| matches!(&o.request.kind, RequestKind::Navigation(n) if n.url.as_str().contains("/green")))
        .ok_or("real navigation callback was not observed")?;
    if nav.request.id.view() != first
        || nav.outcome != NativePolicyOutcome::Applied(enzui_webkit::web::Decision::Allow)
    {
        return Err(format!(
            "live navigation lost its generation/allow: {nav:?}"
        ));
    }
    println!("policy-gate1: real navigation callback carried {first:?} and rendered green OK");

    // Retain both the owned snapshot and references into it while a real
    // callback mutates the binding's raw state. The retained slices must stay
    // unchanged; a fresh snapshot must contain the new callback observation.
    let retained_observations: BoundedObservations = observations;
    let retained_before = retained_observations.to_vec();
    let retained_dropped = retained_observations.dropped();
    let retained_slices = retained_observations.as_slices();
    if retained_before.iter().any(|observation| {
        matches!(
            &observation.request.kind,
            RequestKind::Navigation(nav) if nav.url.as_str().contains("/no-response")
        )
    }) {
        return Err("the first policy snapshot already contained the next callback".into());
    }

    // No responder answer is an immediate native ignore, not WebKit's default.
    web.begin_load_uri(&origin.url("/no-response"))
        .map_err(|e| e.to_string())?;
    web.pump(500);
    let retained_after: Vec<_> = retained_slices
        .0
        .iter()
        .chain(retained_slices.1.iter())
        .cloned()
        .collect();
    if retained_after != retained_before || retained_observations.dropped() != retained_dropped {
        return Err("a retained policy snapshot changed after a native callback".into());
    }
    let updated_observations: BoundedObservations = web
        .native_policy_observations()
        .ok_or("policy binding lost its observation snapshot")?;
    if !updated_observations.iter().any(|observation| {
        matches!(
            &observation.request.kind,
            RequestKind::Navigation(nav) if nav.url.as_str().contains("/no-response")
        ) && observation.outcome == NativePolicyOutcome::NoResponseDenied
    }) {
        return Err(
            "a fresh policy snapshot omitted the callback that followed the retained snapshot"
                .into(),
        );
    }
    if centre(&mut web, 10)? != green {
        return Err("an unanswered navigation changed native rendered pixels".into());
    }
    require(&web, "navigation no-response deny", |kind, outcome| {
        matches!(kind, RequestKind::Navigation(n) if n.url.as_str().contains("/no-response"))
            && *outcome == NativePolicyOutcome::NoResponseDenied
    })?;
    println!("policy-gate2: no-response navigation was natively ignored; pixels unchanged OK");

    // Supersede the view generation, then return the old callback's id. The
    // native page must stay green, proving ignore() happened rather than merely
    // recording a helper verdict.
    let second = router.recreate(first.slot());
    if !matches!(
        web.replace_native_policy_view(&router, first),
        Err(SessionError::PolicyViewGone)
    ) {
        return Err("policy rebound to the superseded generation".into());
    }
    web.replace_native_policy_view(&router, second)
        .map_err(|e| format!("replace policy view: {e}"))?;
    web.bind_view(&router, second)
        .map_err(|e| format!("bind recreated view: {e}"))?;
    web.begin_load_uri(&origin.url("/stale"))
        .map_err(|e| e.to_string())?;
    web.pump(800);
    let after_stale = centre(&mut web, 1)?;
    if after_stale != green {
        return Err(format!(
            "stale response navigated native page: before={green:?}, after={after_stale:?}"
        ));
    }
    require(&web, "stale response", |kind, outcome| {
        matches!(kind, RequestKind::Navigation(n) if n.url.as_str().contains("/stale"))
            && *outcome == NativePolicyOutcome::StaleResponseDenied
    })?;
    println!("policy-gate2: stale generation reply was natively ignored; pixels unchanged OK");

    // A host-initiated file load is rejected before WebKit. `data:` is now a
    // private exact single-use capability needed by bootstrap and fixtures.
    match web.begin_load_uri("file:///etc/passwd") {
        Err(SessionError::DestinationRefused(_)) => {}
        other => return Err(format!("file URL was not refused before load: {other:?}")),
    }
    web.pump(200);
    if centre(&mut web, 2)? != green {
        return Err("refused file scheme changed rendered pixels".into());
    }
    println!("policy-gate3: refused scheme denied before navigation OK");

    // This real page asks geolocation and opens a popup without a user gesture.
    // Permission has an exact correlated reply; popup deliberately has none.
    web.load(&origin.url("/actions"), 10_000)
        .map_err(|e| format!("actions load: {e}"))?;
    web.pump(300);
    let at = ViewPoint { x: 40.0, y: 40.0 };
    if !web.forward_input(&InputEvent::PointerPressed {
        view: second,
        at,
        button: PointerButton::Primary,
        modifiers: Modifiers::BUTTON1,
    }) || !web.forward_input(&InputEvent::PointerReleased {
        view: second,
        at,
        button: PointerButton::Primary,
        modifiers: Modifiers::NONE,
    }) {
        return Err("bound policy session refused its live pointer click".into());
    }
    web.pump(800);
    require(&web, "permission", |kind, outcome| {
        matches!(kind, RequestKind::Permission(PermissionKind::Geolocation))
            && *outcome == NativePolicyOutcome::Applied(enzui_webkit::web::Decision::Allow)
    })?;
    require(&web, "popup no-response deny", |kind, outcome| {
        matches!(kind, RequestKind::Popup(_)) && *outcome == NativePolicyOutcome::NoResponseDenied
    })?;
    println!("policy-gate4/5: real permission allow and no-response popup deny callbacks OK");

    // A same-generation but different correlation id also fails closed.
    web.begin_load_uri(&origin.url("/mismatch"))
        .map_err(|e| e.to_string())?;
    web.pump(500);
    require(&web, "mismatched response", |kind, outcome| {
        matches!(kind, RequestKind::Navigation(n) if n.url.as_str().contains("/mismatch"))
            && *outcome == NativePolicyOutcome::MismatchedResponseDenied
    })?;
    println!("policy-gate6: mismatched same-generation response was denied OK");

    // Unsupported main-resource MIME becomes WebKit's response/download
    // decision. Strict policy refuses it and calls native ignore().
    web.begin_load_uri(&origin.url("/blob"))
        .map_err(|e| e.to_string())?;
    web.pump(800);
    require(&web, "download", |kind, outcome| {
        matches!(kind, RequestKind::Download { url } if url.as_str().contains("/blob"))
            && matches!(
                outcome,
                NativePolicyOutcome::Applied(enzui_webkit::web::Decision::Deny(_))
            )
    })?;
    println!("policy-gate7: real response/download callback denied OK");

    // ---------------------------------------------------------------
    // Gate 8: strict certificate denial, end to end.
    //
    // A self-signed localhost server deterministically reaches WebKit's TLS
    // failure callback. Exact correlation is not enough: strict cert policy
    // denies, so no certificate exception/reload is installed.
    //
    // the gate used to assert only "a Certificate Deny observation
    // exists". When that observation went missing on a real run there was no
    // evidence to say whether the callback was unwired or the fixture never
    // produced a TLS error, and the HTTPS URL showed up as an allowed
    // navigation followed by a denied download instead. So the fixture is now
    // measured independently BEFORE WebKit is pointed at it, and the native
    // certificate ledger records registration, firing count and the terminal
    // action, all of which the failure text prints.
    // ---------------------------------------------------------------
    let tls = TlsOrigin::start()?;
    let probe = tls.probe(TlsOrigin::HOST)?;
    if !probe.certificate_rejected || !probe.serves_content {
        return Err(format!(
            "policy-gate8: the TLS FIXTURE is the wrong side: {}. A certificate \
             callback cannot be required of WebKit unless a verifying client \
             really is refused and a non-verifying one really is served.",
            probe.describe()
        ));
    }
    let tls_url = tls.url();
    let before_tls = centre(&mut web, 3)?;
    let retained_ledger: CertificateLedger = web
        .native_certificate_ledger()
        .ok_or("strict session lost its pre-callback certificate ledger")?;
    let retained_ledger_before = retained_ledger.clone();
    if retained_ledger.callbacks() != 0 {
        return Err("strict certificate ledger was not empty before the TLS fixture".into());
    }
    web.begin_load_uri(&tls_url).map_err(|e| e.to_string())?;
    web.pump(1_500);
    require(&web, "certificate", |kind, outcome| {
        matches!(kind, RequestKind::Certificate(c) if c.host == "localhost" && c.validation_failed)
            && matches!(
                outcome,
                NativePolicyOutcome::Applied(enzui_webkit::web::Decision::Deny(_))
            )
    })
    .map_err(|e| format!("{e}\n{}", diagnose(&web, &probe, &tls_url)))?;

    // Exactly one callback, exactly one terminal native action, and that
    // action must be the denial: no per-host exception, no reload.
    if retained_ledger != retained_ledger_before || retained_ledger.callbacks() != 0 {
        return Err("a retained certificate snapshot changed after the TLS callback".into());
    }
    let ledger: CertificateLedger = web
        .native_certificate_ledger()
        .ok_or("strict session lost its certificate ledger")?;
    if !ledger.tls_callback_registered() {
        return Err(format!(
            "policy-gate8: `load-failed-with-tls-errors` was never connected \
             (handler id 0), so no certificate decision can be applied.\n{}",
            diagnose(&web, &probe, &tls_url)
        ));
    }
    if ledger.callbacks() != 1 {
        return Err(format!(
            "policy-gate8: expected exactly 1 real TLS callback, got {}.\n{}",
            ledger.callbacks(),
            diagnose(&web, &probe, &tls_url)
        ));
    }
    let events = ledger.events();
    let [event] = events.as_slice() else {
        return Err(format!(
            "policy-gate8: expected exactly 1 terminal native certificate \
             action, got {}.\n{}",
            events.len(),
            diagnose(&web, &probe, &tls_url)
        ));
    };
    if event.action != CertificateAction::Denied || event.host != "localhost" {
        return Err(format!(
            "policy-gate8: strict denial applied the wrong terminal action: \
             {event:?}\n{}",
            diagnose(&web, &probe, &tls_url)
        ));
    }

    // Correlated identity: the native action answered the SAME live-generation
    // request the observation ring recorded - not a slot-only identity and not
    // another callback's id.
    let observations = web.native_policy_observations().unwrap().to_vec();
    let cert_obs: Vec<_> = observations
        .iter()
        .filter(|o| matches!(&o.request.kind, RequestKind::Certificate(_)))
        .collect();
    let [cert_obs] = cert_obs.as_slice() else {
        return Err(format!(
            "policy-gate8: expected exactly 1 Certificate observation, got {}.\n{}",
            cert_obs.len(),
            diagnose(&web, &probe, &tls_url)
        ));
    };
    if event.request != cert_obs.request.id || cert_obs.request.id.view() != second {
        return Err(format!(
            "policy-gate8: certificate action {:?} is not correlated with the \
             live-generation observation {cert_obs:?} (live view {second:?})",
            event
        ));
    }

    // The consequence, not just the verdict: a denied certificate must not
    // continue. WebKit asks navigation policy BEFORE the handshake, so the
    // initial navigation is legitimately allowed once - what a denial must
    // never produce is the retry (gate 10 proves an allow produces exactly
    // two), nor a response for the document.
    let nav_allows = observations
        .iter()
        .filter(|o| {
            matches!(&o.request.kind, RequestKind::Navigation(n) if n.url.as_str().starts_with(&tls_url))
                && o.outcome == NativePolicyOutcome::Applied(enzui_webkit::web::Decision::Allow)
        })
        .count();
    if nav_allows != 1 {
        return Err(format!(
            "policy-gate8: expected exactly 1 Navigation Allow for {tls_url} \
             (the initial load, never a retry), got {nav_allows}.\n{}",
            diagnose(&web, &probe, &tls_url)
        ));
    }
    if let Some(served) = observations.iter().find(|o| {
        matches!(&o.request.kind, RequestKind::Resource { url, .. } if url.as_str().starts_with(&tls_url))
    }) {
        return Err(format!(
            "policy-gate8: a denied certificate still let a resource through \
             for the TLS URL: {served:?}"
        ));
    }
    let after_tls = centre(&mut web, 4)?;
    if after_tls != before_tls {
        return Err(format!(
            "policy-gate8: a denied certificate navigated the native page: \
             before={before_tls:?}, after={after_tls:?}"
        ));
    }
    println!(
        "policy-gate8: fixture proved hostile ({}); one real TLS callback, one \
         correlated terminal Denied action, no exception, no reload, pixels \
         unchanged OK",
        probe.describe()
    );

    // Every callback after recreation - across all six policy categories - is
    // stamped with the replacement generation, not a slot-only identity.
    let observations = web.native_policy_observations().unwrap();
    for observation in observations.iter().filter(|o| {
        matches!(
            o.request.kind,
            RequestKind::Navigation(_)
                | RequestKind::Permission(_)
                | RequestKind::Certificate(_)
                | RequestKind::Popup(_)
                | RequestKind::Download { .. }
        ) && o.request.id.view() != first
    }) {
        if observation.request.id.view() != second {
            return Err(format!(
                "callback did not carry live replacement generation: {observation:?}"
            ));
        }
    }
    println!(
        "policy-gate9: scheme/navigation/permission/certificate/popup/download all carry live ViewId generation OK"
    );

    // ---------------------------------------------------------------
    // Gate 10: TLS allow - a permissive certificate policy installs the
    // exception AND reloads. Exactly one Certificate Allow, exactly two
    // Navigation Allows for the TLS URL (initial + retry).
    // ---------------------------------------------------------------
    //
    // A separate ephemeral WebSession + a fresh TlsOrigin isolates this gate
    // from any prior TLS exception (WebKit caches TLS state per
    // NetworkSession, so reusing the previous session would make the gate
    // order-dependent).
    let tls2 = TlsOrigin::start()?;
    let probe2 = tls2.probe(TlsOrigin::HOST)?;
    if !probe2.certificate_rejected || !probe2.serves_content {
        return Err(format!(
            "policy-gate10: the TLS FIXTURE is the wrong side: {}",
            probe2.describe()
        ));
    }
    let mut web_tls = WebSession::new_trusted_local(&display).map_err(|e| e.to_string())?;
    let mut tls_router = ViewRouter::new();
    let tls_view = tls_router.create(50);
    let mut tls_policy = WebPolicy::strict().grant(PermissionKind::Geolocation);
    tls_policy.allow_http = true;
    tls_policy.allow_insecure_certificates = true;
    web_tls
        .bind_view(&tls_router, tls_view)
        .map_err(|e| format!("bind tls-allow view: {e}"))?;
    web_tls
        .install_native_policy(&tls_router, tls_view, tls_policy, |request| {
            Some(request.id)
        })
        .map_err(|e| format!("install tls-allow policy: {e}"))?;

    let tls_nav_url = tls2.url();
    web_tls
        .begin_load_uri(&tls_nav_url)
        .map_err(|e| e.to_string())?;
    // Pump long enough for the initial navigation, the TLS-failure callback,
    // and the retried navigation after the exception is installed.
    web_tls.pump(3_000);

    let tls_obs = web_tls
        .native_policy_observations()
        .ok_or("tls session missing observation ring")?
        .to_vec();

    // 10a: EXACTLY one Certificate Allow for localhost.
    let cert_allows = tls_obs
        .iter()
        .filter(|o| {
            matches!(&o.request.kind, RequestKind::Certificate(c) if c.host == "localhost" && c.validation_failed)
                && o.outcome == NativePolicyOutcome::Applied(enzui_webkit::web::Decision::Allow)
        })
        .count();
    if cert_allows != 1 {
        return Err(format!(
            "policy-gate10: expected exactly 1 Certificate Allow for localhost, got {cert_allows}.\n{}",
            diagnose(&web_tls, &probe2, &tls_nav_url)
        ));
    }

    // 10b: EXACTLY two Navigation Allows for the TLS URL - the initial
    // load, and the retry `load_uri` fired from the allow branch of the TLS
    // callback. Sabotaging that reload line (commenting out
    // `webkit_web_view_load_uri` in `on_tls_failure`) drops the second
    // navigation and this count falls to 1, failing the gate red.
    let nav_allows = tls_obs
        .iter()
        .filter(|o| {
            matches!(&o.request.kind, RequestKind::Navigation(n) if n.url.as_str().starts_with(&tls_nav_url))
                && o.outcome == NativePolicyOutcome::Applied(enzui_webkit::web::Decision::Allow)
        })
        .count();
    if nav_allows != 2 {
        return Err(format!(
            "policy-gate10: expected exactly 2 Navigation Allows for {tls_nav_url} (initial + retry), got {nav_allows}; observations = {tls_obs:?}\n{}",
            diagnose(&web_tls, &probe2, &tls_nav_url)
        ));
    }

    // 10c: the terminal native action, not just the decision. Exactly
    // one callback, exactly one action, and that action must have installed
    // the per-host exception AND issued the reload, correlated with the live
    // generation's certificate request. Sabotaging either native call in
    // `on_tls_failure` leaves the decision Allow but the action incomplete,
    // which this reads directly instead of inferring from a navigation count.
    let tls_ledger = web_tls
        .native_certificate_ledger()
        .ok_or("tls session lost its certificate ledger")?;
    if tls_ledger.callbacks() != 1 {
        return Err(format!(
            "policy-gate10: expected exactly 1 real TLS callback, got {}.\n{}",
            tls_ledger.callbacks(),
            diagnose(&web_tls, &probe2, &tls_nav_url)
        ));
    }
    let tls_events = tls_ledger.events();
    let [continued] = tls_events.as_slice() else {
        return Err(format!(
            "policy-gate10: expected exactly 1 terminal native certificate \
             action, got {}.\n{}",
            tls_events.len(),
            diagnose(&web_tls, &probe2, &tls_nav_url)
        ));
    };
    if continued.action != CertificateAction::ContinuedForHost || continued.host != "localhost" {
        return Err(format!(
            "policy-gate10: permissive continuation applied the wrong terminal \
             action: {continued:?}\n{}",
            diagnose(&web_tls, &probe2, &tls_nav_url)
        ));
    }
    let cert_allow_obs: Vec<_> = tls_obs
        .iter()
        .filter(|o| matches!(&o.request.kind, RequestKind::Certificate(_)))
        .collect();
    let [cert_allow_obs] = cert_allow_obs.as_slice() else {
        return Err(format!(
            "policy-gate10: expected exactly 1 Certificate observation, got {}",
            cert_allow_obs.len()
        ));
    };
    if continued.request != cert_allow_obs.request.id
        || cert_allow_obs.request.id.view() != tls_view
    {
        return Err(format!(
            "policy-gate10: the continuation action {continued:?} is not \
             correlated with the live-generation observation {cert_allow_obs:?} \
             (live view {tls_view:?})"
        ));
    }

    // 10d: the exception is scoped to ONE host. The same fixture,
    // same port, reached through a different host name must fail the handshake
    // again and raise its own certificate callback; if the allow branch had
    // installed a global exception this second callback would never fire.
    let other_host_url = format!("https://127.0.0.1:{}/", tls2.port);
    web_tls
        .begin_load_uri(&other_host_url)
        .map_err(|e| e.to_string())?;
    web_tls.pump(2_000);
    let tls_ledger = web_tls
        .native_certificate_ledger()
        .ok_or("tls session lost its certificate ledger")?;
    if tls_ledger.callbacks() != 2 {
        return Err(format!(
            "policy-gate10: a second host on the same fixture raised {} TLS \
             callback(s), not 2: the per-host exception is not host-scoped.\n{}",
            tls_ledger.callbacks(),
            diagnose(&web_tls, &probe2, &other_host_url)
        ));
    }
    let tls_events = tls_ledger.events();
    let hosts: Vec<&str> = tls_events.iter().map(|e| e.host.as_str()).collect();
    if hosts != ["localhost", "127.0.0.1"] {
        return Err(format!(
            "policy-gate10: expected one terminal action per host in order \
             [localhost, 127.0.0.1], got {hosts:?}: {tls_events:?}"
        ));
    }
    println!(
        "policy-gate10: 1 Certificate Allow + 2 Navigation Allows; \
         exception+reload applied once, correlated, and scoped to one host \
         (a second host re-raised the callback) OK"
    );

    // ---------------------------------------------------------------
    // Gate 11: download allow - a permissive download policy reaches
    // WebKit's native download-started callback, not merely the
    // decide-policy call site.
    // ---------------------------------------------------------------
    //
    // With `allow_downloads` set, the response-policy callback's
    // unsupported-main-resource arm calls `webkit_policy_decision_download`.
    // WebKit then creates a `WebKitDownload` and fires `download-started`
    // on the NetworkSession; the safe layer records a `DownloadStarted`
    // observation and cancels. Sabotaging the download arm (e.g. flipping
    // it back to `webkit_policy_decision_ignore`) drops the download-started
    // signal and fails this gate red.
    let third = router.recreate(second.slot());
    let mut dl_policy = WebPolicy::strict();
    dl_policy.allow_http = true;
    dl_policy.allow_downloads = true;
    web.bind_view(&router, third)
        .map_err(|e| format!("bind third view: {e}"))?;
    web.install_native_policy(&router, third, dl_policy, |request| Some(request.id))
        .map_err(|e| format!("install download-allow policy: {e}"))?;

    let dl_url = origin.url("/blob");
    web.begin_load_uri(&dl_url).map_err(|e| e.to_string())?;
    // WebKit's download-started fires shortly after the response-policy
    // decision selects download; pump long enough for both to run.
    web.pump(2_000);

    let dl_obs = web
        .native_policy_observations()
        .ok_or("download session missing observation ring")?
        .to_vec();

    // 11a: the response-policy Download decision must be Allow.
    let dl_allow = dl_obs.iter().any(|o| {
        matches!(&o.request.kind, RequestKind::Download { url } if url.as_str().contains("/blob"))
            && o.outcome == NativePolicyOutcome::Applied(enzui_webkit::web::Decision::Allow)
    });
    if !dl_allow {
        return Err(format!(
            "policy-gate11: expected a Download Allow for /blob; observations = {dl_obs:?}"
        ));
    }

    // 11b: WebKit's native download-started signal fired for this URL. This
    // is the native consequence of `webkit_policy_decision_download`; the
    // decide-policy observation alone would only prove this code chooses the download
    // branch, not that WebKit acted on it.
    let dl_started = dl_obs.iter().any(|o| {
        matches!(&o.request.kind, RequestKind::Download { url } if url.as_str().contains("/blob"))
            && o.outcome == NativePolicyOutcome::DownloadStarted
    });
    if !dl_started {
        return Err(format!(
            "policy-gate11: expected a DownloadStarted observation for /blob after webkit_policy_decision_download; observations = {dl_obs:?}"
        ));
    }
    println!("policy-gate11: download allow reached WebKit download-started callback OK");

    Ok(())
}

/// What the TLS fixture itself does, measured independently of WebKit.
///
/// A missing certificate observation has two possible causes with one symptom.
/// This measures the fixture's side with `openssl s_client` before WebKit is
/// pointed at it: a verifying client must be refused (so a browser *must* see
/// a certificate error) and a non-verifying client must be served (so a
/// permitted continuation has something to continue to).
#[cfg(feature = "wpe")]
struct FixtureProbe {
    certificate_rejected: bool,
    verify_error: String,
    serves_content: bool,
    families: String,
}

#[cfg(feature = "wpe")]
impl FixtureProbe {
    /// Bound on the diagnostic text kept from a probe's output.
    const DETAIL_MAX: usize = 160;

    fn measure(host: &str, port: u16) -> Result<Self, String> {
        // The exact spelling the gate loads: a name that resolves to an
        // address the fixture does not listen on is a fixture defect, and it
        // must be measured here rather than inferred from WebKit's behaviour.
        let address = format!("{host}:{port}");
        // A verifying client. `-verify_return_error` makes a validation
        // failure fatal, so a success here means the fixture is not hostile.
        let strict = Self::s_client(&address, &["-verify", "2", "-verify_return_error"], b"")?;
        let verify_error = strict
            .lines()
            .find(|line| line.starts_with("verify error:"))
            .unwrap_or("<no verify error reported>")
            .chars()
            .take(Self::DETAIL_MAX)
            .collect::<String>();
        // A non-verifying client, issuing the same request WebKit would.
        let served = Self::s_client(
            &address,
            &["-quiet", "-verify_quiet"],
            b"GET / HTTP/1.0\r\n\r\n",
        )?;
        Ok(Self {
            certificate_rejected: verify_error.starts_with("verify error:"),
            verify_error,
            serves_content: served.contains(" 200 "),
            families: String::new(),
        })
    }

    /// One bounded `openssl s_client` run. `timeout` caps it so a fixture that
    /// never answers fails the probe instead of hanging the gate.
    fn s_client(address: &str, extra: &[&str], request: &[u8]) -> Result<String, String> {
        use std::io::Write;
        let mut child = std::process::Command::new("timeout")
            .args([
                "5",
                "openssl",
                "s_client",
                "-connect",
                address,
                "-servername",
                TlsOrigin::HOST,
            ])
            .args(extra)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| format!("spawn openssl s_client: {e}"))?;
        if let Some(stdin) = child.stdin.as_mut() {
            let _ = stdin.write_all(request);
        }
        drop(child.stdin.take());
        let out = child
            .wait_with_output()
            .map_err(|e| format!("wait openssl s_client: {e}"))?;
        let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
        text.push('\n');
        text.push_str(&String::from_utf8_lossy(&out.stderr));
        Ok(text)
    }

    fn describe(&self) -> String {
        format!(
            "listening on [{}]; verifying client refused={} ({}); \
             non-verifying client served={}",
            self.families, self.certificate_rejected, self.verify_error, self.serves_content
        )
    }
}

/// Bounded diagnosis naming WHICH side of the certificate path is wrong:
/// the fixture, the callback registration, the callback firing, or
/// the terminal native action.
#[cfg(feature = "wpe")]
fn diagnose(web: &WebSession, probe: &FixtureProbe, url: &str) -> String {
    use enzui_webkit::ffi::policy::CertificateLedger as Ledger;
    let ledger = web.native_certificate_ledger();
    let registered = ledger.as_ref().is_some_and(Ledger::tls_callback_registered);
    let callbacks = ledger.as_ref().map_or(0, Ledger::callbacks);
    let events = ledger.as_ref().map(|l| l.events()).unwrap_or_default();
    let failures = ledger
        .as_ref()
        .map(|l| l.load_failures())
        .unwrap_or_default();
    let responses: Vec<_> = ledger
        .as_ref()
        .map(|l| l.main_responses())
        .unwrap_or_default()
        .into_iter()
        .rev()
        .take(8)
        .collect();
    let answered = responses
        .iter()
        .any(|r| r.url.as_str().starts_with(url) && r.status != 0);
    let tls_domain = failures
        .iter()
        .any(|f| f.domain.contains("tls") || f.domain.contains("TLS"));
    // The third side: WebKit reaches an HTTPS origin through this session's
    // destination guard (a loopback proxy), so a refused `CONNECT` produces no
    // handshake with the origin at all - and therefore no certificate
    // callback, however correctly the callback is wired.
    let host_port = url
        .split_once("://")
        .map_or(url, |(_, rest)| rest)
        .trim_end_matches('/');
    let guard: Vec<_> = web
        .destination_guard_events()
        .into_iter()
        .filter(|event| format!("{event:?}").contains(host_port))
        .rev()
        .take(8)
        .collect();
    let guard_denied = guard.iter().any(|event| {
        matches!(
            event,
            enzui_webkit::destination_guard::GuardEvent::Denied { .. }
                | enzui_webkit::destination_guard::GuardEvent::Malformed { .. }
        )
    });
    let verdict = if !probe.certificate_rejected {
        "FIXTURE side: a verifying client was NOT refused, so WebKit had no \
         certificate error to report."
    } else if ledger.is_none() {
        "ENGINE side: this session has no native policy binding at all."
    } else if !registered {
        "ENGINE side: `load-failed-with-tls-errors` was never connected \
         (handler id 0), so no certificate decision can ever be applied."
    } else if callbacks == 0 && answered {
        "FIXTURE/session side: the origin ANSWERED this URL (see response \
         below), so the handshake completed and no certificate was ever \
         questioned — this session is not validating the certificate."
    } else if callbacks == 0 && guard_denied {
        "GUARD side: this session's destination guard refused the proxy \
         request for this URL, so WebKit never completed a handshake with the \
         origin and no certificate could be judged."
    } else if callbacks == 0 && tls_domain {
        "ENGINE side: WebKit reported a TLS-domain failure through `load-failed` \
         instead, so the certificate handler did not claim it."
    } else if callbacks == 0 && !failures.is_empty() {
        "FIXTURE/transport side: WebKit's only failure for this load was not a \
         TLS-domain error (see load-failed below)."
    } else if callbacks == 0 {
        "NEITHER fired: WebKit reported no failure for this URL at all — the \
         load never started, or the certificate was trusted by this session."
    } else if events.is_empty() {
        "ENGINE side: the callback fired but applied no terminal native action."
    } else {
        "the callback fired and applied a terminal action; compare it with the \
         expected action above."
    };
    let observed: Vec<_> = web
        .native_policy_observations()
        .map(|o| o.to_vec())
        .unwrap_or_default()
        .into_iter()
        .rev()
        .take(12)
        .collect();
    format!(
        "certificate diagnosis for {url}:\n  \
         fixture   : {}\n  \
         callback  : registered={registered} fired={callbacks}\n  \
         actions   : {events:?} (dropped {})\n  \
         load-fail : {failures:?} (dropped {})\n  \
         response  : newest-first {responses:?} (dropped {})\n  \
         guard     : newest-first {guard:?} (dropped {})\n  \
         verdict   : {verdict}\n  \
         observed  : newest-first {observed:?}",
        probe.describe(),
        ledger.as_ref().map_or(0, Ledger::dropped_events),
        ledger.as_ref().map_or(0, Ledger::dropped_load_failures),
        ledger.as_ref().map_or(0, Ledger::dropped_main_responses),
        web.destination_guard_dropped(),
    )
}

#[cfg(feature = "wpe")]
fn require(
    web: &WebSession,
    label: &str,
    predicate: impl Fn(&RequestKind, &NativePolicyOutcome) -> bool,
) -> Result<(), String> {
    let obs = web.native_policy_observations();
    let found = obs
        .as_ref()
        .map(|o| o.iter().any(|o| predicate(&o.request.kind, &o.outcome)))
        .unwrap_or(false);
    if found {
        Ok(())
    } else {
        Err(format!(
            "{label}: callback/outcome absent; observed {:?}",
            obs.map(|o| o.to_vec())
        ))
    }
}

#[cfg(feature = "wpe")]
fn centre(web: &mut WebSession, seq: u64) -> Result<(u8, u8, u8, u8), String> {
    let frame = web
        .snapshot(Generation::FIRST, FrameSeq(seq), 10_000)
        .map_err(|e| format!("snapshot: {e}"))?;
    let x = frame.width() / 2;
    let y = frame.height() / 2;
    let offset = ((y * frame.width() + x) * 4) as usize;
    let p = frame.pixels();
    Ok((p[offset], p[offset + 1], p[offset + 2], p[offset + 3]))
}

#[cfg(feature = "wpe")]
struct Origin {
    address: std::net::SocketAddr,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

#[cfg(feature = "wpe")]
impl Origin {
    fn start() -> Result<Self, String> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
        listener.set_nonblocking(true).map_err(|e| e.to_string())?;
        let address = listener.local_addr().map_err(|e| e.to_string())?;
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let thread_stop = stop.clone();
        let thread = std::thread::spawn(move || serve(listener, &thread_stop));
        Ok(Self {
            address,
            stop,
            thread: Some(thread),
        })
    }
    fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.address, path)
    }
}

#[cfg(feature = "wpe")]
impl Drop for Origin {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Release);
        let _ = std::net::TcpStream::connect(self.address);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(feature = "wpe")]
fn serve(listener: std::net::TcpListener, stop: &std::sync::atomic::AtomicBool) {
    use std::io::{Read, Write};
    while !stop.load(std::sync::atomic::Ordering::Acquire) {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let mut request = [0_u8; 2048];
                let count = stream.read(&mut request).unwrap_or(0);
                let text = String::from_utf8_lossy(&request[..count]);
                let path = text.split_whitespace().nth(1).unwrap_or("/");
                let (content_type, body) = match path {
                    "/green" => (
                        "text/html",
                        "<style>html,body{margin:0;width:100%;height:100%;background:rgb(18,170,68)}</style>",
                    ),
                    "/stale" | "/mismatch" | "/no-response" => (
                        "text/html",
                        "<style>html,body{margin:0;width:100%;height:100%;background:rgb(220,20,20)}</style>",
                    ),
                    "/actions" => (
                        "text/html",
                        "<style>html,body,button{margin:0;width:100%;height:100%;background:rgb(80,40,120)}</style><button onclick=\"window.open('/popup','_blank')\">open</button><script>navigator.geolocation.getCurrentPosition(()=>{},()=>{})</script>",
                    ),
                    "/blob" => ("application/x-enzui-download", "download bytes"),
                    _ => ("text/html", "popup"),
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(2))
            }
            Err(_) => break,
        }
    }
}

#[cfg(feature = "wpe")]
struct TlsOrigin {
    port: u16,
    children: Vec<std::process::Child>,
    families: Vec<&'static str>,
    dir: std::path::PathBuf,
}

#[cfg(feature = "wpe")]
impl TlsOrigin {
    fn start() -> Result<Self, String> {
        // Test scratch goes to Cargo's per-target
        // scratch dir (real disk under `target/`), never `/tmp`, which the
        // tmpdir ratchet holds at zero for this crate.
        let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("enzui-policy-tls-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let cert = dir.join("cert.pem");
        let key = dir.join("key.pem");
        let status = std::process::Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-subj",
                "/CN=localhost",
                "-days",
                "1",
                "-keyout",
            ])
            .arg(&key)
            .arg("-out")
            .arg(&cert)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map_err(|e| format!("spawn openssl req: {e}"))?;
        if !status.success() {
            return Err(format!("openssl req failed: {status}"));
        }
        let probe = std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
        let port = probe.local_addr().map_err(|e| e.to_string())?.port();
        drop(probe);
        // listen on BOTH loopback families. `localhost` resolves to
        // `::1` alone on this host, and the session's destination guard
        // resolves the name once and pins exactly one address - which is the
        // whole point of the guard. A fixture bound only to `127.0.0.1` was
        // therefore unreachable through the pinned address, so the guard
        // answered `502` itself: WebKit received a real HTTP response with an
        // unrenderable MIME type instead of ever completing a handshake, which
        // is exactly why the certificate callback never fired and the same
        // HTTPS URL showed up as an allowed navigation followed by a denied
        // download. Binding both families makes the certificate path reachable
        // however the name resolves.
        let mut children = Vec::new();
        let mut families = Vec::new();
        for (family, accept) in [
            ("ipv4", format!("127.0.0.1:{port}")),
            ("ipv6", format!("[::1]:{port}")),
        ] {
            match std::process::Command::new("openssl")
                .args(["s_server", "-quiet", "-accept", &accept, "-cert"])
                .arg(&cert)
                .arg("-key")
                .arg(&key)
                .arg("-www")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
            {
                Ok(child) => {
                    children.push(child);
                    families.push(family);
                }
                // A host without one loopback family is not a gate failure by
                // itself; the probe below decides, because it measures the
                // exact host spelling the gate loads.
                Err(_) => continue,
            }
        }
        if children.is_empty() {
            return Err("spawn openssl s_server: no loopback family accepted".into());
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
        Ok(Self {
            port,
            children,
            families,
            dir,
        })
    }
    fn url(&self) -> String {
        format!("https://{}:{}/", Self::HOST, self.port)
    }
    /// The host name the gate loads, and the one the probe measures.
    const HOST: &'static str = "localhost";
    /// Measure what this fixture does to a verifying and a non-verifying
    /// client through the exact host spelling the gate loads.
    fn probe(&self, host: &str) -> Result<FixtureProbe, String> {
        let mut probe = FixtureProbe::measure(host, self.port)?;
        probe.families = self.families.join("+");
        Ok(probe)
    }
}

#[cfg(feature = "wpe")]
impl Drop for TlsOrigin {
    fn drop(&mut self) {
        for child in &mut self.children {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
