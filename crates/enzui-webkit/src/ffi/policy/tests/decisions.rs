use super::*;

/// The TLS continuation is a retry of a security failure, issued with no
/// delay from inside the failure callback. Driven through the REAL
/// `on_tls_failure` body: a permissive policy, then repeated failures.
///
/// Three separate mechanisms, each with its own control:
///
/// 1. per-host attempt bound - with a positive control proving a *fresh*
///    host is still admitted, so "refuses everything" cannot pass;
/// 2. a saturated host table fails closed instead of evicting (eviction
///    would hand an exhausted host its budget back).
///
/// Host length is checked separately by
/// [`certificate_host_identity_is_never_truncated_for_authorization`].
#[test]
fn certificate_continuation_is_bounded_per_host_and_fails_closed() {
    // The WebKit `CRITICAL` lines this test prints are WebKit's own
    // null-pointer guard on the attestation-refusal path: an admitted
    // continuation asks the (absent) renderer to be attested and the
    // refusal terminates a view that is NULL here. They mark the admitted
    // firings, and their absence would mean nothing was admitted at all.
    let mut state = permissive_cert_state();

    // 1a. Positive control: a fresh host spends budget and is not refused.
    fire_tls_failure(&mut state, "https://rotating.invalid/first");
    let events = state.certificates.events();
    assert_eq!(events.len(), 1, "one callback, one terminal action");
    assert_ne!(
        events[0].action,
        CertificateAction::RetryBudgetExhausted,
        "the FIRST failure for a host must still be allowed to continue; \
         a budget that refuses everything is not a bound, it is a break"
    );
    assert_eq!(
        state.certificates.retries_refused(),
        0,
        "nothing is refused before the budget is spent"
    );
    assert_eq!(state.certificates.continuation_hosts(), 1);

    // 1b. The loop: the same host failing again proves the exception did
    // not settle the handshake, so no further exception and no reload.
    for i in 0..3 {
        fire_tls_failure(&mut state, &format!("https://rotating.invalid/{i}"));
    }
    let events = state.certificates.events();
    assert!(
        events[1..]
            .iter()
            .all(|e| e.action == CertificateAction::RetryBudgetExhausted
                && e.host == "rotating.invalid"),
        "every repeat failure for the host must be refused: {events:?}"
    );
    assert_eq!(
        state.certificates.retries_refused(),
        3,
        "each refusal is counted, and budget is never regained"
    );
    assert_eq!(
        state.certificates.continuation_hosts(),
        1,
        "a refused retry must not grow the table"
    );

    // 2. A saturated table refuses an untracked host instead of evicting.
    let mut wide = permissive_cert_state();
    for i in 0..CertificateLedger::RETRY_HOSTS_MAX {
        fire_tls_failure(&mut wide, &format!("https://h{i}.invalid/"));
    }
    assert_eq!(
        wide.certificates.continuation_hosts(),
        CertificateLedger::RETRY_HOSTS_MAX,
        "every distinct host up to the ceiling spends its own budget"
    );
    assert_eq!(
        wide.certificates.retries_refused(),
        0,
        "nothing below the ceiling is refused"
    );
    fire_tls_failure(&mut wide, "https://one-too-many.invalid/");
    assert_eq!(
        wide.certificates.events().last().map(|e| e.action),
        Some(CertificateAction::RetryBudgetExhausted),
        "a full table must refuse, not admit"
    );
    assert_eq!(
        wide.certificates.retries_refused(),
        1,
        "the refusal past the ceiling is counted"
    );
    // The eviction bypass: `h0` must still be exhausted, so cycling hosts
    // cannot flush an entry and reopen the loop it closed.
    fire_tls_failure(&mut wide, "https://h0.invalid/again");
    assert_eq!(
        wide.certificates.events().last().map(|e| e.action),
        Some(CertificateAction::RetryBudgetExhausted),
        "an exhausted host must not regain budget when the table saturates"
    );
    assert_eq!(
        wide.certificates.continuation_hosts(),
        CertificateLedger::RETRY_HOSTS_MAX,
        "the table stays at its ceiling"
    );
}

// ---------------------------------------------------------------
// Allow-branch proof: download start path.
// ---------------------------------------------------------------

fn native_policy_test_binding(
    view: ViewId,
    policy: WebPolicy,
    calls: std::rc::Rc<Cell<u32>>,
) -> Result<NativePolicyBinding, super::super::super::signal::SignalBindError> {
    NativePolicyBinding::new(
        core::ptr::dangling_mut::<ffi::WebKitWebView>(),
        2usize as *mut ffi::WebKitNetworkSession,
        view,
        policy,
        crate::sandbox::OuterSandbox::Rejected,
        Vec::new(),
        move |request| {
            calls.set(calls.get().saturating_add(1));
            Some(request.id)
        },
    )
}

fn native_policy_test_navigation() -> RequestKind {
    RequestKind::Navigation(NavContext {
        url: PolicyUrl::new("http://example.com/"),
        user_initiated: true,
    })
}

fn native_policy_test_http_policy() -> WebPolicy {
    let mut policy = WebPolicy::strict();
    policy.allow_http = true;
    policy
}

fn route_registered_decide_policy(
    handler_id: u64,
    kind: RequestKind,
) -> Option<NativePolicyOutcome> {
    let (callback, data) = super::super::super::signal::seam::registration(handler_id)?;
    assert_eq!(callback as usize, on_decide_policy as *const () as usize);
    // SAFETY: the seam returns callback data for this live registered handler,
    // and the test dispatches it on the callback thread.
    let lease = unsafe { CallbackLease::enter(data) };
    Some(lease.decide(kind).1)
}

#[test]
fn native_policy_binding_failed_replacement_keeps_old_handlers_and_decisions() {
    super::super::super::signal::seam::install(&[]);
    let old_calls = std::rc::Rc::new(Cell::new(0));
    let replacement_calls = std::rc::Rc::new(Cell::new(0));
    let mut installed = Some(
        native_policy_test_binding(ViewId::new(2), WebPolicy::strict(), old_calls.clone())
            .expect("mandatory binding"),
    );
    let old_ids = installed
        .as_ref()
        .expect("mandatory binding")
        .handler_ids_for_test();
    assert_eq!(old_ids.len(), VIEW_SIGNAL_COUNT + 1);
    let old_decide_handler = old_ids[0];
    super::super::super::signal::seam::fail_next(&["load-failed"]);
    let old_ids_during_build = old_ids.clone();

    let error = NativePolicyBinding::replace_transactionally(&mut installed, || {
        assert_eq!(
            super::super::super::signal::seam::active_ids(),
            old_ids_during_build
        );
        native_policy_test_binding(
            ViewId::new(2),
            native_policy_test_http_policy(),
            replacement_calls.clone(),
        )
    })
    .expect_err("a zero load-failed id must refuse the replacement");

    assert_eq!(error.signal, "load-failed");
    assert_eq!(super::super::super::signal::seam::active_ids(), old_ids);
    let partial_disconnects = super::super::super::signal::seam::disconnects();
    assert_eq!(partial_disconnects.len(), VIEW_SIGNAL_COUNT - 1);
    let unique_partial: std::collections::HashSet<_> =
        partial_disconnects.iter().copied().collect();
    assert_eq!(unique_partial.len(), partial_disconnects.len());
    assert!(
        partial_disconnects.iter().all(|id| !old_ids.contains(id)),
        "replacement rollback must not retire an old handler"
    );
    let outcome =
        route_registered_decide_policy(old_decide_handler, native_policy_test_navigation())
            .expect("failed replacement must preserve the registered decide-policy handler");
    assert!(matches!(
        outcome,
        NativePolicyOutcome::Applied(Decision::Deny(_))
    ));
    assert_eq!(old_calls.get(), 1);
    assert_eq!(replacement_calls.get(), 0);
}

// ---------------------------------------------------------------
// The permission callback seam: what the native request reports, what the
// classifier receives, and which terminal native action is selected.
// ---------------------------------------------------------------

/// A permission request whose native reads are recorded instead of performed.
///
/// It stands in for `NativePermissionRequest` at exactly the seam the callback
/// uses, so the assertions below run the real classification and the real
/// correlated policy decision - everything `on_permission_request` does before
/// it calls `webkit_permission_request_allow` or `..._deny`.
struct FakePermissionRequest {
    user_media: bool,
    media_key_system: bool,
    flags: MediaCaptureFlags,
    audio_reads: std::cell::Cell<u32>,
    video_reads: std::cell::Cell<u32>,
    display_reads: std::cell::Cell<u32>,
}

impl FakePermissionRequest {
    fn user_media(audio: bool, video: bool, display: bool) -> Self {
        Self {
            user_media: true,
            media_key_system: false,
            flags: MediaCaptureFlags::new(audio, video, display),
            audio_reads: std::cell::Cell::new(0),
            video_reads: std::cell::Cell::new(0),
            display_reads: std::cell::Cell::new(0),
        }
    }
}

impl PermissionSource for FakePermissionRequest {
    fn is_geolocation(&self) -> bool {
        false
    }

    fn is_notification(&self) -> bool {
        false
    }

    fn is_user_media(&self) -> bool {
        self.user_media
    }

    fn is_media_key_system(&self) -> bool {
        self.media_key_system
    }

    fn media_flags(&self) -> MediaCaptureFlags {
        self.audio_reads.set(self.audio_reads.get() + 1);
        self.video_reads.set(self.video_reads.get() + 1);
        self.display_reads.set(self.display_reads.get() + 1);
        self.flags
    }
}

impl FakePermissionRequest {}

/// The last permission kind the state actually correlated and decided.
fn last_permission(state: &State) -> (PermissionKind, NativePolicyOutcome) {
    let observation = state
        .observations
        .iter()
        .last()
        .expect("the callback records one observation per request");
    match &observation.request.kind {
        RequestKind::Permission(kind) => (*kind, observation.outcome),
        other => panic!("expected a permission observation, got {other:?}"),
    }
}

/// The three device booleans are independent inputs to the classifier: a
/// combined request under a Camera-only policy is classified as the combined
/// kind and its terminal native action is DENY - `webkit_permission_request_allow`
/// is selected only on the `Allow` arm.
#[test]
fn a_combined_media_request_reaches_the_classifier_and_denies_under_a_camera_grant() {
    let mut state = permission_state(&[PermissionKind::Camera]);
    let request = FakePermissionRequest::user_media(true, true, false);

    let action = decide_permission_once(&mut state, &request);

    assert_eq!(
        action,
        PermissionAction::Deny,
        "audio+video under a Camera-only policy must select the native deny action"
    );
    assert_eq!(
        last_permission(&state),
        (
            PermissionKind::CameraAndMicrophone,
            NativePolicyOutcome::Applied(Decision::Deny(
                crate::web::policy::DenyReason::PermissionNotGranted
            ))
        ),
        "the correlated request must be recorded as the combined kind, not Camera"
    );
    // Every flag was read before the decision: a priority chain that returned
    // Camera on the video flag would never have consulted the others.
    assert_eq!(
        (
            request.audio_reads.get(),
            request.video_reads.get(),
            request.display_reads.get()
        ),
        (1, 1, 1),
        "all three device flags must reach the classifier exactly once"
    );
}

/// Outside origin mode a display-capture request is refused at the seam even
/// when it also sets the video and audio flags and every device is granted:
/// only an answer to the request itself can allow it.
#[test]
fn a_display_capture_request_denies_through_the_callback_seam() {
    let mut state = permission_state(&[PermissionKind::Camera, PermissionKind::Microphone]);
    let request = FakePermissionRequest::user_media(true, true, true);

    assert_eq!(
        decide_permission_once(&mut state, &request),
        PermissionAction::Deny,
        "a static policy must select the native deny action for screen capture"
    );
    assert_eq!(
        last_permission(&state).0,
        PermissionKind::ScreenCapture,
        "a display request must be carried as screen capture, never as a camera"
    );
}

/// A permission class this build does not model still fails closed, and never
/// consults the media flags at all.
#[test]
fn an_unmodelled_permission_class_is_unknown_and_denied() {
    let mut state = permission_state(&[PermissionKind::Camera, PermissionKind::Microphone]);
    let request = FakePermissionRequest {
        user_media: false,
        ..FakePermissionRequest::user_media(true, true, false)
    };

    assert_eq!(
        decide_permission_once(&mut state, &request),
        PermissionAction::Deny
    );
    assert_eq!(last_permission(&state).0, PermissionKind::Unknown(0));
    assert_eq!(
        request.video_reads.get(),
        0,
        "a non-media request must not be classified from device flags"
    );
}

// ---------------------------------------------------------------
// The shared certificate-authorization host parser.
//
// WebKit compares the string an installer hands
// `webkit_network_session_allow_tls_certificate_for_host` against the
// request URL's own host: ASCII-case-insensitively, IPv6 brackets already
// stripped, byte-for-byte otherwise. A string that can never *be* such a
// host installs an exception nothing will ever match - a silent no-op
// advertised as pre-trust. Both installers now go through one parser.
// ---------------------------------------------------------------
