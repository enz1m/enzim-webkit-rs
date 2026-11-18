//! Native entry points share one process-long runtime thread.
//!
//! ```text
//! cargo test --offline --locked --workspace --features enzui-webkit/wpe --test wpe_thread_ownership ownership_ -- --ignored --nocapture
//! ```

mod wpe_native_support;

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use enzui_webkit::destination_guard::{SystemResolver, TcpConnector};
use enzui_webkit::ffi::NativeThreadError;
use enzui_webkit::ffi::profile::{NetworkSession, ProfileError, ProfileStore};
use enzui_webkit::ffi::runtime::{DisplayError, HeadlessDisplay, WebSession};
use enzui_webkit::web::{DestinationPolicy, WebProfile};

enum First {
    Display,
    Network,
    Features,
}

fn foreign_attempts(root: &Path, untouched: &Path) {
    let root = root.to_owned();
    let untouched = untouched.to_owned();
    std::thread::spawn(move || {
        assert!(
            matches!(HeadlessDisplay::new(), Err(DisplayError::WrongThread(_))),
            "foreign display must be refused"
        );
        assert!(
            matches!(
                NetworkSession::new_ephemeral(),
                Err(ProfileError::WrongThread(_))
            ),
            "foreign ephemeral session must be refused"
        );
        assert!(
            matches!(
                NetworkSession::new_ephemeral_with_destination_seams(
                    DestinationPolicy::DEFAULT,
                    Arc::new(SystemResolver),
                    Arc::new(TcpConnector),
                ),
                Err(ProfileError::WrongThread(_))
            ),
            "foreign seam session must be refused"
        );
        assert!(
            matches!(
                NetworkSession::new_persistent(
                    root.join("direct-data").to_str().expect("UTF-8 data path"),
                    root.join("direct-cache")
                        .to_str()
                        .expect("UTF-8 cache path"),
                ),
                Err(ProfileError::WrongThread(_))
            ),
            "foreign persistent session must be refused"
        );
        assert!(
            matches!(
                ProfileStore::new(&root).session_for(&WebProfile::shared()),
                Err(ProfileError::WrongThread(_))
            ),
            "foreign profile store must be refused"
        );
        assert!(
            !root.exists(),
            "foreign attempt must not provision a profile"
        );
        assert!(matches!(
            ProfileStore::new(&untouched).session_for(&WebProfile::shared()),
            Err(ProfileError::WrongThread(_))
        ));
        assert_eq!(
            std::fs::metadata(&untouched)
                .expect("untouched root")
                .permissions()
                .mode()
                & 0o777,
            0o755,
            "foreign attempt must not tighten an existing root"
        );
        assert_eq!(WebSession::feature_defaults(), Err(NativeThreadError));
    })
    .join()
    .expect("foreign thread checks");
}

fn check(first: First, fixture: &Path) {
    let foreign_root = fixture.join("foreign");
    assert!(!foreign_root.exists());
    let untouched = foreign_root.with_extension("untouched");
    std::fs::create_dir(&untouched).expect("untouched root fixture");
    std::fs::set_permissions(&untouched, std::fs::Permissions::from_mode(0o755))
        .expect("fixture mode");

    let initial_display =
        matches!(first, First::Display).then(|| HeadlessDisplay::new().expect("first display"));
    let initial_network = matches!(first, First::Network)
        .then(|| NetworkSession::new_ephemeral().expect("first network session"));
    if matches!(first, First::Features) {
        assert!(
            !WebSession::feature_defaults()
                .expect("first feature query")
                .is_empty()
        );
    }

    foreign_attempts(&foreign_root, &untouched);
    let display = initial_display.unwrap_or_else(|| HeadlessDisplay::new().expect("owner display"));
    let mut session = WebSession::new(&display).expect("owner page session");
    session
        .load_html(
            "<title>owner survives refusals</title>",
            "about:blank",
            10_000,
        )
        .expect("owner loads a real page");
    let deadline = Instant::now() + Duration::from_secs(5);
    while session.page_title().expect("page title").as_deref() != Some("owner survives refusals") {
        assert!(
            Instant::now() < deadline,
            "owner receives the real page title"
        );
        session.pump(10);
    }
    assert!(
        !WebSession::feature_defaults()
            .expect("owner feature query")
            .is_empty()
    );
    let network =
        initial_network.unwrap_or_else(|| NetworkSession::new_ephemeral().expect("owner network"));
    assert!(network.is_ephemeral());
    let seams = NetworkSession::new_ephemeral_with_destination_seams(
        DestinationPolicy::DEFAULT,
        Arc::new(SystemResolver),
        Arc::new(TcpConnector),
    )
    .expect("owner seam session");
    assert!(seams.is_ephemeral());

    let owner_root = foreign_root.with_extension("owner");
    let mut profiles = ProfileStore::new(&owner_root);
    let persistent = profiles
        .session_for(&WebProfile::shared())
        .expect("owner persistent profile");
    assert!(!persistent.is_ephemeral());
    assert!(owner_root.join("shared/data").is_dir());
    drop((persistent, profiles, seams, network, session, display));
    foreign_attempts(&foreign_root, &untouched);
}

#[test]
#[ignore = "requires native WPE runtime"]
fn ownership_display_first() {
    wpe_native_support::run_with_fixture("ownership_display_first", |fixture| {
        check(First::Display, fixture)
    });
}

#[test]
#[ignore = "requires native WPE runtime"]
fn ownership_network_first() {
    wpe_native_support::run_with_fixture("ownership_network_first", |fixture| {
        check(First::Network, fixture)
    });
}

#[test]
#[ignore = "requires native WPE runtime"]
fn ownership_features_first() {
    wpe_native_support::run_with_fixture("ownership_features_first", |fixture| {
        check(First::Features, fixture)
    });
}
