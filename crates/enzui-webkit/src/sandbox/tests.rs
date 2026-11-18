//! Pure unit tests for the sandbox preflight and attestation vocabulary.
//!
//! The refusal rules, the `/proc` walk, the ancestry rule and the PID-reuse
//! guard are tested here with fabricated inputs; the mechanism is then tested
//! against real isolated and non-isolated processes in
//! `tests/sandbox_process_controls.rs`, and against a real WebKit WebProcess in
//! `tests/wpe_sandbox.rs`.

use super::*;

use std::cell::{Cell, RefCell};
use std::collections::HashMap;

fn ns(mnt: &str, pid: &str, user: &str) -> ProcessNamespaces {
    ProcessNamespaces {
        mnt: mnt.to_string(),
        pid: pid.to_string(),
        user: user.to_string(),
    }
}

/// An injected environment: variables plus marker probe outcomes.
#[derive(Default)]
struct FakeEnv {
    vars: HashMap<String, OsString>,
    paths: Vec<String>,
    unknown_paths: Vec<String>,
}

impl FakeEnv {
    fn with_var(mut self, name: &str, value: impl Into<OsString>) -> Self {
        self.vars.insert(name.to_string(), value.into());
        self
    }
    fn with_path(mut self, path: &str) -> Self {
        self.paths.push(path.to_string());
        self
    }
    fn with_unknown_path(mut self, path: &str) -> Self {
        self.unknown_paths.push(path.to_string());
        self
    }
}

impl SandboxEnv for FakeEnv {
    fn var(&self, name: &str) -> Option<OsString> {
        self.vars.get(name).cloned()
    }
    fn marker_presence(&self, path: &str) -> MarkerPresence {
        if self.paths.iter().any(|p| p == path) {
            MarkerPresence::Present
        } else if self.unknown_paths.iter().any(|p| p == path) {
            MarkerPresence::Unknown(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "fixture marker probe failure",
            ))
        } else {
            MarkerPresence::Absent
        }
    }
}

fn reject(env: &FakeEnv) -> Result<(), SandboxRefusal> {
    preflight_in(env, OuterSandbox::Rejected)
}

// ---------------------------------------------------------------------------
// preflight - the disable variable
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// preflight - the two variables that WEAKEN the sandbox without disabling it
// ---------------------------------------------------------------------------

/// Each weakening variable is checked on its own, so a rule that only looked at
/// the disable variable fails here by name rather than passing three ways.
#[test]
fn every_weakening_variable_refuses_independently() {
    for name in [
        DISABLE_VARIABLE,
        DEBUG_PERMISSIONS_VARIABLE,
        INSPECTOR_VARIABLE,
        INSPECTOR_HTTP_VARIABLE,
    ] {
        assert!(
            reject(&FakeEnv::default().with_var(name, "1")).is_err(),
            "{name} must refuse on its own"
        );
    }
}

// ---------------------------------------------------------------------------
// preflight - containers where WebKit does not bubblewrap at all
// ---------------------------------------------------------------------------

#[test]
fn unknown_container_marker_probes_refuse_while_absent_and_present_keep_their_behavior() {
    match RealEnv.marker_presence("/dev/null/enzui-container-marker-probe") {
        MarkerPresence::Unknown(error) => assert_ne!(
            error.kind(),
            io::ErrorKind::NotFound,
            "a malformed path is indeterminate, not absent"
        ),
        other => panic!("a non-directory path component must be Unknown, got {other:?}"),
    }

    assert_eq!(
        reject(&FakeEnv::default()),
        Ok(()),
        "two absent markers must remain allowed"
    );

    for marker in [FLATPAK_MARKER, CONTAINER_MARKER] {
        assert_eq!(
            reject(&FakeEnv::default().with_unknown_path(marker)),
            Err(SandboxRefusal::BubblewrapNotUsedInContainer {
                container: ContainerKind::UnverifiedContainer,
            }),
            "an unknown probe for {marker} must fail closed"
        );
    }

    assert_eq!(
        reject(&FakeEnv::default().with_path(FLATPAK_MARKER)),
        Err(SandboxRefusal::BubblewrapNotUsedInContainer {
            container: ContainerKind::Flatpak,
        }),
        "a present Flatpak marker must retain its specific classification"
    );
    assert_eq!(
        reject(&FakeEnv::default().with_path(CONTAINER_MARKER)),
        Err(SandboxRefusal::BubblewrapNotUsedInContainer {
            container: ContainerKind::UnverifiedContainer,
        }),
        "a present generic container marker must remain a refusal"
    );
}

#[test]
fn flatpak_snap_and_container_markers_refuse_by_default() {
    let cases: [(FakeEnv, ContainerKind); 3] = [
        (
            FakeEnv::default().with_path(FLATPAK_MARKER),
            ContainerKind::Flatpak,
        ),
        (
            SNAP_VARIABLES
                .iter()
                .fold(FakeEnv::default(), |env, name| env.with_var(name, "x")),
            ContainerKind::Snap,
        ),
        (
            FakeEnv::default().with_path(CONTAINER_MARKER),
            ContainerKind::UnverifiedContainer,
        ),
    ];
    for (env, expected) in cases {
        assert_eq!(
            reject(&env),
            Err(SandboxRefusal::BubblewrapNotUsedInContainer {
                container: expected
            }),
            "{expected:?} must refuse by default"
        );
    }
}

/// The outer-sandbox acceptance is a typed, in-code decision: it admits the
/// container, and nothing else. A host that accepts an outer sandbox has still
/// not asked for `ptrace` in the renderer.
#[test]
fn accepting_an_outer_sandbox_admits_the_container_but_not_a_weakening_variable() {
    let container = FakeEnv::default().with_path(FLATPAK_MARKER);
    assert_eq!(
        preflight_in(&container, OuterSandbox::AcceptedByHost),
        Ok(())
    );

    let weakened = FakeEnv::default()
        .with_path(FLATPAK_MARKER)
        .with_var(DISABLE_VARIABLE, "1");
    assert!(
        preflight_in(&weakened, OuterSandbox::AcceptedByHost).is_err(),
        "an accepted outer sandbox must not admit {DISABLE_VARIABLE}"
    );
}

// ---------------------------------------------------------------------------
// the namespace comparison
// ---------------------------------------------------------------------------

/// A partial escape is not isolation. Each namespace is checked on its own so a
/// comparison that only looked at one of them fails here by name.
#[test]
fn sharing_any_single_namespace_is_reported() {
    let host = ns("mnt:[1]", "pid:[2]", "user:[3]");
    for (web, expected) in [
        (ns("mnt:[1]", "pid:[8]", "user:[7]"), NamespaceKind::Mount),
        (ns("mnt:[9]", "pid:[2]", "user:[7]"), NamespaceKind::Pid),
        (ns("mnt:[9]", "pid:[8]", "user:[3]"), NamespaceKind::User),
    ] {
        assert_eq!(
            shared_namespaces(&host, &web),
            vec![expected],
            "sharing {expected:?} must be reported"
        );
    }
}

// ---------------------------------------------------------------------------
// the process walk
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// the bwrap ancestry rule
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// fail-closed
// ---------------------------------------------------------------------------

/// PID reuse. The walk recorded a start time; the process at that pid now
/// has a different one, so it is a different process and no verdict may be
/// computed from its namespaces. Here the pid is real and readable - this
/// process itself - and only the start time disagrees, so a verdict keyed on
/// the pid alone would happily compare it and (sharing everything) report
/// "shares host namespaces" about a process that never existed.
#[test]
fn a_reused_pid_is_refused_rather_than_compared() {
    let me = std::process::id();
    let real = read_identity(me).expect("own identity");
    let impostor = ProcessIdentity {
        pid: me,
        start_ticks: real.start_ticks.wrapping_add(1),
    };
    assert_eq!(
        ProcessNamespaces::read_checked(impostor),
        Err(NamespaceReadError::IdentityChanged)
    );
    // Positive control: with the true start time the same read succeeds.
    assert!(ProcessNamespaces::read_checked(real).is_ok());
}

/// Enforcement refuses every non-attestation, including the benign-sounding
/// "no WebProcess found". A mapping that only refused `SharesHostNamespaces`
/// would let a broken discovery walk through as a pass.
#[test]
fn enforcement_allows_only_the_isolated_verdict() {
    let isolated = SandboxAttestation::BubblewrapIsolated {
        renderer: ProcessIdentity {
            pid: 7,
            start_ticks: 1,
        },
        bwrap_ancestor: ProcessIdentity {
            pid: 6,
            start_ticks: 1,
        },
        host: ns("mnt:[1]", "pid:[2]", "user:[3]"),
        web: ns("mnt:[9]", "pid:[8]", "user:[7]"),
    };
    assert_eq!(enforcement_decision(&isolated), Ok(()));

    for reason in [
        UnattestedReason::WebProcessNotFound,
        UnattestedReason::ProcessVanished { pid: 7 },
        UnattestedReason::NoBubblewrapAncestor {
            pid: 7,
            chain: vec!["unshare".to_string()],
        },
        UnattestedReason::NamespacesUnreadable {
            pid: 7,
            why: "denied".to_string(),
        },
        UnattestedReason::SharesHostNamespaces {
            pid: 7,
            shared: vec![NamespaceKind::Mount],
        },
    ] {
        assert_eq!(
            enforcement_decision(&SandboxAttestation::Unattested(reason.clone())),
            Err(reason.clone()),
            "{reason:?} must be refused, not tolerated"
        );
    }
}

/// Scoping: a renderer that already existed is not this session's, so its
/// verdict must not become this session's verdict - the caller would terminate
/// its own view for somebody else's renderer, sparing the offender.
#[test]
fn an_excluded_pre_existing_renderer_is_not_this_sessions_verdict() {
    let me = std::process::id();
    let real = read_identity(me).expect("own identity");
    // The own pid, presented as a WebProcess: it shares every namespace with
    // itself, so unscoped attestation reports SharesHostNamespaces.
    let table = ProcessTable::from_entries([
        (me, 1, "host".to_string(), real.start_ticks),
        (
            999_999_002,
            me,
            WEB_PROCESS_COMM.to_string(),
            real.start_ticks,
        ),
    ]);
    let unscoped = attest_tree(&table, me);
    assert!(
        !unscoped.is_isolated(),
        "control: unscoped attestation must see the pre-existing renderer"
    );
    let scoped = attest_tree_excluding(
        &table,
        me,
        &[ProcessIdentity {
            pid: 999_999_002,
            start_ticks: real.start_ticks,
        }],
    );
    assert_eq!(
        scoped,
        SandboxAttestation::Unattested(UnattestedReason::WebProcessNotFound),
        "an excluded renderer must leave this session with no renderer of its own"
    );
    // Exclusion is by IDENTITY: the same pid with a different start time is a
    // different process and must not be excluded.
    let recycled = attest_tree_excluding(
        &table,
        me,
        &[ProcessIdentity {
            pid: 999_999_002,
            start_ticks: real.start_ticks.wrapping_add(1),
        }],
    );
    assert!(
        !matches!(
            recycled,
            SandboxAttestation::Unattested(UnattestedReason::WebProcessNotFound)
        ),
        "a recycled pid must not inherit the exclusion"
    );
}

const NAMESPACE_KINDS: [&str; 3] = ["mnt", "pid", "user"];

fn fixture_identity() -> ProcessIdentity {
    ProcessIdentity {
        pid: 42,
        start_ticks: 9,
    }
}

#[test]
fn namespace_read_unreadable_identity_probe_after_success_fails_closed() {
    let expected = fixture_identity();
    let namespace_read = Cell::new(false);
    let ns_reader = |_pid: u32, kind: &str| -> Result<String, NamespaceReadError> {
        assert_eq!(kind, "mnt");
        namespace_read.set(true);
        Ok("mnt:[100]".to_owned())
    };
    let identity_reader = |_pid: u32| {
        if namespace_read.get() {
            Err(NamespaceReadError::Unreadable {
                why: "/proc/42/stat: Permission denied".to_owned(),
            })
        } else {
            Ok(Some(expected))
        }
    };

    assert_eq!(
        ProcessNamespaces::read_checked_with(expected, ns_reader, identity_reader),
        Err(NamespaceReadError::Unreadable {
            why: "/proc/42/stat: Permission denied".to_owned(),
        })
    );
}

#[test]
fn namespace_read_final_identity_check_catches_change_after_all_links() {
    let expected = fixture_identity();
    let namespace_reads = RefCell::new(Vec::new());
    let identity_reads = Cell::new(0_u32);
    let ns_reader = |_pid: u32, kind: &str| -> Result<String, NamespaceReadError> {
        namespace_reads.borrow_mut().push(kind.to_owned());
        Ok(format!("{kind}:[100]"))
    };
    let identity_reader = |_pid: u32| {
        let read = identity_reads.get();
        identity_reads.set(read.saturating_add(1));
        Ok(if read == 4 { None } else { Some(expected) })
    };

    assert_eq!(
        ProcessNamespaces::read_checked_with(expected, ns_reader, identity_reader),
        Err(NamespaceReadError::IdentityChanged)
    );
    assert_eq!(
        *namespace_reads.borrow(),
        NAMESPACE_KINDS
            .iter()
            .map(|kind| (*kind).to_owned())
            .collect::<Vec<_>>()
    );
    assert_eq!(identity_reads.get(), 5);
}
