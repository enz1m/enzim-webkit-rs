//! Private tests for native policy callback state and bounded diagnostics.
//!
//! They stay beside `policy.rs` because they exercise callback state, inert-load
//! permits, and signal seams that are intentionally not public API.

use super::*;
use crate::web::policy::{NavContext, PermissionKind, PolicyUrl, RequestKind};
use crate::web::{Decision, ViewId, WebPolicy};

// ---------------------------------------------------------------
// BoundedObservations: bounding and dropped-count semantics.
// ---------------------------------------------------------------

fn dummy_session() -> (PolicySession, ViewId) {
    let mut s = PolicySession::new(WebPolicy::strict());
    let v = ViewId::new(0);
    s.open_view(v);
    (s, v)
}

fn decide_once(state: &mut State, kind: RequestKind) -> (NativePolicyRequest, NativePolicyOutcome) {
    let data: *mut c_void = (state as *mut State).cast();
    // SAFETY: the stack state remains live for this non-reentrant test call.
    let lease = unsafe { CallbackLease::enter(data) };
    lease.decide(kind)
}

fn route_uri_once(
    state: &mut State,
    route: UriRoute,
    uri: Result<String, NativeUriError>,
) -> (NativePolicyRequest, NativePolicyOutcome) {
    let data: *mut c_void = (state as *mut State).cast();
    // SAFETY: the stack state remains live for this non-reentrant test call.
    let lease = unsafe { CallbackLease::enter(data) };
    lease.route_uri(route, uri)
}

fn decide_permission_once(state: &mut State, source: &impl PermissionSource) -> PermissionAction {
    let data: *mut c_void = (state as *mut State).cast();
    // SAFETY: the stack state remains live for this non-reentrant test call.
    let lease = unsafe { CallbackLease::enter(data) };
    decide_permission(&lease, source)
}

fn observation_for_kind(
    session: &mut PolicySession,
    view: ViewId,
    kind: RequestKind,
) -> NativePolicyObservation {
    let id = session.open(view, kind.clone());
    NativePolicyObservation {
        request: NativePolicyRequest { id, kind },
        outcome: NativePolicyOutcome::NoResponseDenied,
    }
}

#[test]
fn bounded_observations_enforces_cumulative_request_byte_budget_for_every_kind() {
    fn spare(value: &str) -> String {
        let mut string = String::with_capacity(1024 * 1024);
        string.push_str(value);
        assert!(string.capacity() > BoundedObservations::DEFAULT_BYTE_BUDGET);
        string
    }

    let (mut session, view) = dummy_session();
    let mut ring = BoundedObservations::with_limits(20, 12);
    let kinds = [
        RequestKind::Navigation(NavContext {
            url: PolicyUrl::new(spare("12345678")),
            user_initiated: false,
        }),
        RequestKind::Permission(PermissionKind::Geolocation),
        RequestKind::Certificate(CertContext {
            host: spare("123456"),
            validation_failed: true,
        }),
        RequestKind::Popup(PopupContext {
            url: PolicyUrl::new(spare("1234567")),
            user_initiated: true,
        }),
        RequestKind::Download {
            url: PolicyUrl::new(spare("12345")),
        },
        RequestKind::Resource {
            url: PolicyUrl::new(spare("123456789")),
            main_frame: false,
        },
    ];

    let expected = [(8, 0), (8, 0), (6, 1), (7, 3), (12, 3), (9, 5)];
    for (kind, (capacity, dropped)) in kinds.into_iter().zip(expected) {
        ring.push(observation_for_kind(&mut session, view, kind));
        let measured: usize = ring.request_capacities.iter().sum();
        assert_eq!(ring.retained_request_capacity(), capacity);
        assert_eq!(ring.retained_request_capacity(), measured);
        assert_eq!(ring.dropped(), dropped);
        assert!(measured <= ring.byte_budget());
    }

    assert_eq!(ring.retained_request_capacity(), 9);
    assert_eq!(
        ring.len(),
        1,
        "only the newest resource fits after eviction"
    );
    assert_eq!(ring.dropped(), 5, "every evicted decision is counted");
    assert!(matches!(
        ring.iter().next().map(|o| &o.request.kind),
        Some(RequestKind::Resource { .. })
    ));

    let mut repeated = BoundedObservations::with_limits(256, 32);
    for _ in 0..100 {
        repeated.push(observation_for_kind(
            &mut session,
            view,
            RequestKind::Navigation(NavContext {
                url: PolicyUrl::new(spare("https://hostile.invalid/x")),
                user_initiated: false,
            }),
        ));
    }
    assert!(repeated.retained_request_capacity() <= repeated.byte_budget());
    assert_eq!(repeated.len(), 1);
    assert_eq!(repeated.dropped(), 99);

    let mut compacted = BoundedObservations::with_limits(4, 32);
    compacted.push(observation_for_kind(
        &mut session,
        view,
        RequestKind::Certificate(CertContext {
            host: spare("host"),
            validation_failed: true,
        }),
    ));
    let retained_host = match &compacted.iter().next().unwrap().request.kind {
        RequestKind::Certificate(context) => &context.host,
        other => panic!("expected certificate observation, got {other:?}"),
    };
    assert_eq!(retained_host, "host");
    assert_eq!(retained_host.capacity(), "host".len());
    assert_eq!(
        compacted.retained_request_capacity(),
        retained_host.capacity()
    );
}

fn uri_route_state(calls: std::sync::Arc<std::sync::atomic::AtomicU32>) -> State {
    let mut policy = WebPolicy::strict();
    policy.allow_popups = true;
    let mut session = PolicySession::new(policy);
    let view = ViewId::new(31);
    session.open_view(view);
    State {
        local_origins: Default::default(),
        download_mime_types: Vec::new(),
        blob_downloads: VecDeque::new(),
        forced_download: None,
        callback_lifetime: CallbackLifetime::new(),
        view,
        session,
        responder: Some(Box::new(move |request| {
            calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Some(request.id)
        })),
        poisoned: false,
        observations: BoundedObservations::with_capacity(BoundedObservations::DEFAULT_CAPACITY),
        web_view: std::ptr::null_mut(),
        network_session: std::ptr::null_mut(),
        outer_sandbox: crate::sandbox::OuterSandbox::Rejected,
        sandbox_baseline: Vec::new(),
        inert_permit: None,
        destination_policy: crate::web::DestinationPolicy::DEFAULT,
        last_navigation: None,
        redirect_hops: 0,
        credential_guard_ready: true,
        certificates: CertificateLedger::new(),
        page: Default::default(),
    }
}

#[test]
fn native_uri_exact_limit_routes_but_limit_plus_one_navigation_fails_closed() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    let prefix = "https://example.com/";
    let exact = CString::new(format!(
        "{prefix}{}",
        "a".repeat(MAX_POLICY_URI_BYTES - prefix.len())
    ))
    .unwrap();
    let over = CString::new(format!(
        "{prefix}{}",
        "b".repeat(MAX_POLICY_URI_BYTES + 1 - prefix.len())
    ))
    .unwrap();
    assert_eq!(exact.as_bytes().len(), MAX_POLICY_URI_BYTES);
    assert_eq!(over.as_bytes().len(), MAX_POLICY_URI_BYTES + 1);

    let calls = Arc::new(AtomicU32::new(0));
    let mut state = uri_route_state(calls.clone());
    let (_, exact_outcome) = route_uri_once(
        &mut state,
        UriRoute::Navigation {
            user_initiated: true,
        },
        // SAFETY: `exact` is a live `CString` for this call.
        unsafe { policy_uri(exact.as_ptr().cast()) },
    );
    assert_eq!(exact_outcome, NativePolicyOutcome::Applied(Decision::Allow));
    assert_eq!(calls.load(Ordering::Relaxed), 1);

    let (_, over_outcome) = route_uri_once(
        &mut state,
        UriRoute::Navigation {
            user_initiated: true,
        },
        // SAFETY: `over` is a live `CString` for this call.
        unsafe { policy_uri(over.as_ptr().cast()) },
    );
    assert_eq!(
        over_outcome,
        NativePolicyOutcome::UriRefused(NativeUriError::TooLong)
    );
    assert_eq!(
        calls.load(Ordering::Relaxed),
        1,
        "an over-limit URI must never reach the responder"
    );
    let latest = state.observations.iter().last().unwrap();
    let retained = match &latest.request.kind {
        RequestKind::Navigation(context) => context.url.as_str(),
        other => panic!("expected navigation observation, got {other:?}"),
    };
    assert_eq!(
        retained,
        NativeUriError::TooLong.diagnostic_url(),
        "the rejected URI prefix must not be retained"
    );
}

// ---------------------------------------------------------------
// Redaction in NativePolicyObservation Debug output.
// ---------------------------------------------------------------

#[test]
fn observation_debug_does_not_leak_query_credentials() {
    let (mut sess, view) = dummy_session();
    let id = sess.open(
        view,
        RequestKind::Navigation(NavContext {
            url: PolicyUrl::new("https://example.com/page?api_key=SUPER_SECRET_TOKEN&session=abc"),
            user_initiated: true,
        }),
    );
    let obs = NativePolicyObservation {
        request: NativePolicyRequest {
            id,
            kind: RequestKind::Navigation(NavContext {
                url: PolicyUrl::new(
                    "https://example.com/page?api_key=SUPER_SECRET_TOKEN&session=abc",
                ),
                user_initiated: true,
            }),
        },
        outcome: NativePolicyOutcome::Applied(Decision::Allow),
    };
    let debug = format!("{obs:?}");
    assert!(
        !debug.contains("SUPER_SECRET_TOKEN"),
        "query credential leaked into observation Debug: {debug}"
    );
    assert!(
        !debug.contains("session=abc"),
        "query parameter leaked into observation Debug: {debug}"
    );
    assert!(
        debug.contains("example.com/page"),
        "host/path must be present: {debug}"
    );
}

#[test]
fn cross_origin_redirect_strips_authorization_headers_in_native_storage() {
    let headers = unsafe { ffi::soup_message_headers_new(0) };
    assert!(!headers.is_null());
    for (name, value) in [
        ("Authorization", "Bearer TOP-SECRET"),
        ("Proxy-Authorization", "Basic ALSO-SECRET"),
        ("Accept", "text/html"),
    ] {
        let name = CString::new(name).unwrap();
        let value = CString::new(value).unwrap();
        unsafe { ffi::soup_message_headers_append(headers, name.as_ptr(), value.as_ptr()) };
    }
    strip_credential_headers(headers);
    for name in ["Authorization", "Proxy-Authorization"] {
        let name = CString::new(name).unwrap();
        assert!(unsafe { ffi::soup_message_headers_get_one(headers, name.as_ptr()) }.is_null());
    }
    let accept = CString::new("Accept").unwrap();
    assert!(!unsafe { ffi::soup_message_headers_get_one(headers, accept.as_ptr()) }.is_null());
    unsafe { ffi::soup_message_headers_unref(headers) };
}

#[test]
fn inert_capability_is_exact_single_use_and_mismatch_consumes_it() {
    let mut permit = Some("data:text/html,host-owned".to_owned());
    assert!(!consume_inert_permit(&mut permit, "data:text/html,other"));
    assert!(permit.is_none(), "a mismatch must consume the stale permit");

    permit = Some("data:text/html,host-owned".to_owned());
    assert!(consume_inert_permit(
        &mut permit,
        "data:text/html,host-owned"
    ));
    assert!(!consume_inert_permit(
        &mut permit,
        "data:text/html,host-owned"
    ));

    permit = Some("https://example.com/".to_owned());
    assert!(!consume_inert_permit(&mut permit, "https://example.com/"));
}

// ---------------------------------------------------------------
// Panic barrier: verify catch_unwind + poison logic.
// ---------------------------------------------------------------

#[test]
fn responder_panic_produces_denial_and_poisons_subsequent_calls() {
    // Build a State directly with null pointers (never dereferenced for
    // this test - this code only exercises decide(), not native actions).
    let mut session = PolicySession::new(WebPolicy::strict());
    let view = ViewId::new(0);
    session.open_view(view);

    let call_count = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
    let call_count2 = call_count.clone();
    let responder: Box<Responder> = Box::new(move |req: &NativePolicyRequest| {
        let n = call_count2.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
        if n == 2 {
            panic!("deliberate test panic on call {n}");
        }
        Some(req.id)
    });

    let mut state = State {
        local_origins: Default::default(),
        download_mime_types: Vec::new(),
        blob_downloads: VecDeque::new(),
        forced_download: None,
        callback_lifetime: CallbackLifetime::new(),
        view,
        session,
        responder: Some(responder),
        poisoned: false,
        observations: BoundedObservations::with_capacity(BoundedObservations::DEFAULT_CAPACITY),
        web_view: std::ptr::null_mut(),
        network_session: std::ptr::null_mut(),
        outer_sandbox: crate::sandbox::OuterSandbox::Rejected,
        sandbox_baseline: Vec::new(),
        inert_permit: None,
        destination_policy: crate::web::DestinationPolicy::DEFAULT,
        last_navigation: None,
        redirect_hops: 0,
        credential_guard_ready: true,
        certificates: CertificateLedger::new(),
        page: Default::default(),
    };

    // Call 1: normal decision (strict policy denies geolocation).
    let (_, outcome1) = decide_once(
        &mut state,
        RequestKind::Permission(PermissionKind::Geolocation),
    );
    assert_eq!(
        outcome1,
        NativePolicyOutcome::Applied(Decision::Deny(
            crate::web::policy::DenyReason::PermissionNotGranted
        )),
        "first call must produce a normal policy decision"
    );
    assert!(!state.poisoned, "not poisoned after normal call");

    // Call 2: responder panics.
    let (_, outcome2) = decide_once(
        &mut state,
        RequestKind::Permission(PermissionKind::Geolocation),
    );
    assert_eq!(
        outcome2,
        NativePolicyOutcome::ResponderPanicked,
        "panicking responder must produce ResponderPanicked"
    );
    assert!(state.poisoned, "state must be poisoned after panic");

    // Call 3: should be poisoned, never calls responder.
    let (_, outcome3) = decide_once(
        &mut state,
        RequestKind::Permission(PermissionKind::Geolocation),
    );
    assert_eq!(
        outcome3,
        NativePolicyOutcome::ResponderPanicked,
        "poisoned state must continue denying with ResponderPanicked"
    );

    // Verify exactly three observations recorded.
    assert_eq!(state.observations.len(), 3);
    // The responder was only called twice (once normal, once panic).
    assert_eq!(
        call_count.load(std::sync::atomic::Ordering::Relaxed),
        2,
        "responder must not be called after poisoning"
    );
}

// ---------------------------------------------------------------
// Allow-branch proof: TLS exception continuation.
// ---------------------------------------------------------------

// The seam replaces only reentrant attestation and native continuation;
// parsing, policy, callback state, retry accounting, and ledger writes remain
// on the real `on_tls_failure` path.

fn fire_tls_failure(state: &mut State, uri: &str) {
    let uri = CString::new(uri).expect("test URI has no NUL");
    let data: *mut c_void = (state as *mut State).cast();
    let claimed = on_tls_failure(
        std::ptr::null_mut(),
        uri.as_ptr(),
        std::ptr::null_mut(),
        0,
        data,
    );
    assert_eq!(
        claimed,
        ffi::G_TRUE,
        "the certificate callback must claim the failure, never fall \
         through to WebKit's default handler"
    );
}

#[test]
fn responder_retirement_defers_state_free_and_denies_the_outer_request() {
    let (_seam, evidence) = install_tls_test_seam(|_| false);
    let state_pointer = std::rc::Rc::new(Cell::new(std::ptr::null_mut::<State>()));
    let mut state = permission_state(&[]);
    state.responder = Some(Box::new({
        let state_pointer = state_pointer.clone();
        move |request: &NativePolicyRequest| {
            // SAFETY: the callback lease keeps the allocation alive; Cell
            // updates retirement without constructing a State reference.
            unsafe { (*state_pointer.get()).callback_lifetime.retire() };
            Some(request.id)
        }
    }));
    let state = Box::into_raw(Box::new(state));
    state_pointer.set(state);

    // SAFETY: `state` is live on entry and retirement cannot free it while the
    // lease remains active.
    let lease = unsafe { CallbackLease::enter(state.cast()) };
    let (_, outcome) = lease.decide(RequestKind::Permission(PermissionKind::Geolocation));
    assert_eq!(outcome, NativePolicyOutcome::StaleResponseDenied);
    // SAFETY: the active lease still owns the retired allocation.
    assert_eq!(
        unsafe { (*state).callback_lifetime.active_callbacks.get() },
        1
    );
    assert!(evidence.dropped_state.borrow().is_none());
    drop(lease);
    assert!(
        evidence.dropped_state.borrow().is_some(),
        "the last callback lease frees retired state"
    );
}

#[test]
fn responder_replacement_invalidates_only_the_outer_generation() {
    let state_pointer = std::rc::Rc::new(Cell::new(std::ptr::null_mut::<State>()));
    // The recreated view keeps the slot and advances only the generation, so
    // generation alone separates it from the view the outer request was raised
    // by. A different slot would be invalidated by slot identity instead.
    let mut router = crate::web::ViewRouter::new();
    let original = router.create(7);
    let recreated = router.recreate(7);
    assert_eq!(original, ViewId::new(7), "the fixture's live view");
    assert_eq!(recreated.slot(), original.slot(), "same slot");
    assert!(
        recreated.generation() > original.generation(),
        "the generation must advance"
    );
    let replaced = std::rc::Rc::new(Cell::new(false));
    let mut state = permission_state(&[]);
    state.responder = Some(Box::new({
        let state_pointer = state_pointer.clone();
        let replaced = replaced.clone();
        // Bumping on the first call only leaves the second dispatch running
        // against the settled generation, which is what separates "the outer
        // generation was invalidated" from "the binding was".
        move |request: &NativePolicyRequest| {
            if !replaced.replace(true) {
                // SAFETY: no State reference is live while the responder runs.
                let state = unsafe { &mut *state_pointer.get() };
                // Registering the newer generation for the slot is the whole
                // supersession; closing the old view would invalidate the
                // outer request by a different route.
                state.view = recreated;
                state.session.open_view(recreated);
            }
            Some(request.id)
        }
    }));
    let state = Box::into_raw(Box::new(state));
    state_pointer.set(state);

    // SAFETY: `state` remains allocated and binding-live for this dispatch.
    let lease = unsafe { CallbackLease::enter(state.cast()) };
    let (_, outcome) = lease.decide(RequestKind::Permission(PermissionKind::Geolocation));
    drop(lease);
    assert_eq!(outcome, NativePolicyOutcome::StaleResponseDenied);

    // SAFETY: the binding was never retired and no lease is active.
    let lease = unsafe { CallbackLease::enter(state.cast()) };
    let (_, settled) = lease.decide(RequestKind::Permission(PermissionKind::Geolocation));
    drop(lease);
    assert!(
        matches!(settled, NativePolicyOutcome::Applied(Decision::Deny(_))),
        "the replacement generation must still reach its own policy answer, got {settled:?}"
    );

    // SAFETY: no callback lease remains and the binding was not retired.
    let state = unsafe { Box::from_raw(state) };
    assert!(replaced.get());
    assert_eq!(state.view, recreated);
    assert!(
        !state.session.is_live(original),
        "the superseded generation must not be live"
    );
    assert!(
        state.session.is_live(recreated),
        "the recreated generation must be live in the same slot"
    );
    assert!(state.responder.is_some());
    assert!(!state.poisoned);
}

#[test]
fn certificate_host_identity_is_never_truncated_for_authorization() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    let exact_host = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61)
    );
    assert_eq!(exact_host.len(), MAX_CERTIFICATE_HOST_BYTES);
    let over_host = format!("{exact_host}.x");
    let exact_uri = format!("https://{exact_host}/");
    let over_uri = format!("https://{over_host}/");
    assert!(over_uri.len() < MAX_POLICY_URI_BYTES);

    let calls = Arc::new(AtomicU32::new(0));
    let mut state = uri_route_state(calls.clone());
    fire_tls_failure(&mut state, &exact_uri);
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    let exact_event = state.certificates.events().pop().unwrap();
    assert_eq!(exact_event.host, exact_host);
    assert_eq!(exact_event.host.capacity(), MAX_CERTIFICATE_HOST_BYTES);
    assert!(matches!(
        exact_event.outcome,
        NativePolicyOutcome::Applied(Decision::Deny(_))
    ));

    fire_tls_failure(&mut state, &over_uri);
    assert_eq!(
        calls.load(Ordering::Relaxed),
        1,
        "an over-limit host must not reach the responder as a prefix"
    );
    let event = state.certificates.events().pop().unwrap();
    assert_eq!(event.host, "", "no truncated routing identity is retained");
    assert_eq!(event.action, CertificateAction::Denied);
    assert_eq!(
        event.outcome,
        NativePolicyOutcome::UriRefused(NativeUriError::HostTooLong)
    );
    let observation = state.observations.iter().last().unwrap();
    assert!(matches!(
        &observation.request.kind,
        RequestKind::Certificate(context) if context.host.is_empty()
    ));
    assert_eq!(observation.outcome, event.outcome);

    fire_tls_failure(&mut state, "not-a-uri");
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    let malformed = state.certificates.events().pop().unwrap();
    assert_eq!(malformed.host, "");
    assert_eq!(
        malformed.outcome,
        NativePolicyOutcome::UriRefused(NativeUriError::InvalidHost)
    );
}

/// Same shape as [`strict_cert_state`], with a policy that allows a
/// failed certificate - the only path that can continue and reload, and
/// therefore the only path that can loop.
fn permissive_cert_state() -> State {
    let mut policy = WebPolicy::strict();
    policy.allow_insecure_certificates = true;
    let mut session = PolicySession::new(policy);
    let view = ViewId::new(9);
    session.open_view(view);
    State {
        local_origins: Default::default(),
        download_mime_types: Vec::new(),
        blob_downloads: VecDeque::new(),
        forced_download: None,
        callback_lifetime: CallbackLifetime::new(),
        view,
        session,
        responder: Some(Box::new(|req: &NativePolicyRequest| Some(req.id))),
        poisoned: false,
        observations: BoundedObservations::with_capacity(BoundedObservations::DEFAULT_CAPACITY),
        web_view: std::ptr::null_mut(),
        network_session: std::ptr::null_mut(),
        outer_sandbox: crate::sandbox::OuterSandbox::Rejected,
        sandbox_baseline: Vec::new(),
        inert_permit: None,
        destination_policy: crate::web::DestinationPolicy::DEFAULT,
        last_navigation: None,
        redirect_hops: 0,
        credential_guard_ready: true,
        certificates: CertificateLedger::new(),
        page: Default::default(),
    }
}

/// A state whose responder echoes the callback's own id, under a policy that
/// grants exactly `granted`.
fn permission_state(granted: &[PermissionKind]) -> State {
    let mut policy = WebPolicy::strict();
    for kind in granted {
        policy = policy.grant(*kind);
    }
    let mut session = PolicySession::new(policy);
    let view = ViewId::new(7);
    session.open_view(view);
    State {
        local_origins: Default::default(),
        download_mime_types: Vec::new(),
        blob_downloads: VecDeque::new(),
        forced_download: None,
        callback_lifetime: CallbackLifetime::new(),
        view,
        session,
        responder: Some(Box::new(|request: &NativePolicyRequest| Some(request.id))),
        poisoned: false,
        observations: BoundedObservations::with_capacity(BoundedObservations::DEFAULT_CAPACITY),
        web_view: std::ptr::null_mut(),
        network_session: std::ptr::null_mut(),
        outer_sandbox: crate::sandbox::OuterSandbox::Rejected,
        sandbox_baseline: Vec::new(),
        inert_permit: None,
        destination_policy: crate::web::DestinationPolicy::DEFAULT,
        last_navigation: None,
        redirect_hops: 0,
        credential_guard_ready: true,
        certificates: CertificateLedger::new(),
        page: Default::default(),
    }
}
mod decisions;

#[test]
fn blob_downloads_require_the_same_http_origin_including_effective_port() {
    assert_eq!(
        blob_download_origin(
            "blob:https://qwikpdf.com/object",
            "https://qwikpdf.com/page"
        )
        .as_deref(),
        Some("https://qwikpdf.com/object")
    );
    assert!(
        blob_download_origin(
            "blob:https://qwikpdf.com:443/object",
            "https://qwikpdf.com/page"
        )
        .is_some()
    );
    for source in [
        "blob:https://other.example/object",
        "blob:http://qwikpdf.com/object",
        "blob:https://qwikpdf.com:8443/object",
        "blob:null/object",
        "blob:file:///object",
        "blob:https://user:secret@qwikpdf.com/object",
    ] {
        assert!(
            blob_download_origin(source, "https://qwikpdf.com/page").is_none(),
            "{source}"
        );
    }
}

#[test]
fn tls_callback_reentry_records_outer_event_once_after_nested_binding_teardown() {
    let (_seam, evidence) = install_tls_test_seam(|data| {
        let nested_uri = CString::new("https://reentrant.invalid/nested").unwrap();
        assert_eq!(
            on_tls_failure(
                std::ptr::null_mut(),
                nested_uri.as_ptr(),
                std::ptr::null_mut(),
                0,
                data,
            ),
            ffi::G_TRUE
        );
        // SAFETY: the outer callback lease keeps the allocation live while
        // this seam performs the same retirement as binding teardown.
        let state = unsafe { &*data.cast::<State>() };
        assert_eq!(state.callback_lifetime.active_callbacks.get(), 1);
        state.callback_lifetime.retire();
        assert!(!state.callback_lifetime.can_free());
        true
    });
    let state = Box::into_raw(Box::new(permissive_cert_state()));
    let outer_uri = CString::new("https://reentrant.invalid/outer").unwrap();

    assert_eq!(
        on_tls_failure(
            std::ptr::null_mut(),
            outer_uri.as_ptr(),
            std::ptr::null_mut(),
            0,
            state.cast(),
        ),
        ffi::G_TRUE
    );

    assert_eq!(evidence.native_continuations.get(), 0);
    let dropped = evidence.dropped_state.borrow();
    let dropped = dropped
        .as_ref()
        .expect("retired callback state is freed after the outer callback");
    assert_eq!(dropped.certificates.callbacks(), 2);
    assert_eq!(dropped.certificates.continuation_hosts(), 1);
    assert_eq!(dropped.certificates.retries_refused(), 1);
    let events = dropped.certificates.events();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].action, CertificateAction::RetryBudgetExhausted);
    assert_eq!(events[1].action, CertificateAction::AttestationRefused);
    assert_eq!(
        events[1].outcome,
        NativePolicyOutcome::Applied(Decision::Allow)
    );
    assert_eq!(events[0].host, "reentrant.invalid");
    assert_eq!(events[1].host, "reentrant.invalid");
    let observations = dropped.observations.to_vec();
    assert_eq!(observations.len(), 2);
    assert_eq!(events[1].request, observations[0].request.id);
    assert_eq!(events[0].request, observations[1].request.id);
}
