//! Actual owner-thread profile inventories and exact native cleanup gate.

use enzui_webkit::ffi::dispatch_pending_native_events;
use enzui_webkit::ffi::profile::{NetworkSession, ProfileStore};
use enzui_webkit::ffi::runtime::{HeadlessDisplay, WebSession};
use enzui_webkit::ffi::site_data::SiteDataTask;
use enzui_webkit::page::WebsiteData;
use enzui_webkit::site_data::{
    CookieKey, CookieMetadata, CookieSameSite, SiteDataError, WebsiteDataSelection,
};
use enzui_webkit::web::WebProfile;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Origin(Child);
impl Drop for Origin {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn wait<T>(task: SiteDataTask<T>) -> Result<T, SiteDataError> {
    let deadline = Instant::now() + Duration::from_secs(17);
    loop {
        if let Some(result) = task.take_result() {
            return result;
        }
        dispatch_pending_native_events().expect("owner native dispatch");
        assert!(
            Instant::now() < deadline,
            "site-data task did not terminate"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn inventory(session: &NetworkSession) -> Vec<CookieMetadata> {
    wait(session.cookie_inventory().expect("cookie inventory launch")).expect("cookie inventory")
}

fn key(name: &str, domain: &str, path: &str) -> CookieKey {
    CookieKey {
        name: name.into(),
        domain: domain.into(),
        path: path.into(),
    }
}

fn assert_cookie(session: &NetworkSession, uri: &str, expected: (&str, &str)) {
    assert!(
        session
            .cookies_for(uri)
            .expect("native cookie value")
            .iter()
            .any(|(name, value)| name == expected.0 && value == expected.1),
        "positive cookie control missing: {uri} {expected:?}"
    );
}

fn main() {
    let root = PathBuf::from(std::env::args_os().nth(1).expect("fixture root"));
    let mut origin = Origin(
        Command::new("python3")
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/site_data.py"))
            .arg(&root)
            .stdout(Stdio::piped())
            .spawn()
            .expect("fixture origin"),
    );
    let mut url = String::new();
    BufReader::new(origin.0.stdout.take().unwrap())
        .read_line(&mut url)
        .expect("origin URL");
    let url = url.trim();
    let display = HeadlessDisplay::new().expect("native display");
    let mut profiles = ProfileStore::new(root.join("profiles"));
    let profile_a = WebProfile::persistent("inventory-A");
    let profile_b = WebProfile::persistent("inventory-B");
    let mut web =
        WebSession::new_profiled(&display, &mut profiles, &profile_a).expect("profiled view");
    web.local_origins()
        .expect("strict profile local capability")
        .allow_origin(url)
        .expect("allow exact fixture origin");
    web.allow_tls_certificate_for_host(&std::fs::read(root.join("cert.pem")).unwrap(), "127.0.0.1")
        .expect("owned TLS certificate");
    web.load(url, 10_000).expect("real TLS cookie page");
    let session_a = profiles.session_for(&profile_a).expect("profile A");
    let session_b = profiles.session_for(&profile_b).expect("profile B");
    for (name, domain, path, value) in [
        ("chosen", "alpha.test", "/", "A-root"),
        ("chosen", "alpha.test", "/keep", "A-path"),
        ("other", "alpha.test", "/", "A-name"),
        ("chosen", "beta.test", "/", "A-domain"),
    ] {
        session_a
            .add_cookie(domain, path, name, value)
            .expect("seed A");
    }
    session_b
        .add_cookie("alpha.test", "/", "chosen", "B-root")
        .expect("seed B");
    assert_cookie(&session_a, "https://alpha.test/", ("chosen", "A-root"));
    assert_cookie(&session_b, "https://alpha.test/", ("chosen", "B-root"));
    assert_cookie(&session_a, "https://alpha.test/keep", ("chosen", "A-path"));
    assert_cookie(&session_a, "https://beta.test/", ("chosen", "A-domain"));
    let before = inventory(&session_a);
    assert_eq!(before.len(), 5, "owned profile-A cookie inventory");
    assert_eq!(
        inventory(&session_b).len(),
        1,
        "isolated profile-B inventory"
    );
    let flags = before
        .iter()
        .find(|cookie| cookie.key.name == "native_flags")
        .expect("real HTTP-only secure cookie metadata");
    assert!(flags.http_only && flags.secure);
    assert_eq!(flags.same_site, CookieSameSite::Strict);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    assert!(
        flags
            .expires_unix_seconds
            .is_some_and(|expiry| expiry > now + 3000 && expiry < now + 4000)
    );
    assert!(
        before
            .iter()
            .any(|cookie| cookie.key == key("chosen", "alpha.test", "/"))
    );
    let from_view = wait(web.cookie_inventory().expect("view inventory launch"))
        .expect("view profile inventory");
    assert_eq!(
        before, from_view,
        "view uses exact selected network session"
    );
    let capabilities = web.site_data_capabilities();
    assert!(capabilities.cookie_metadata && capabilities.selective_cookie_deletion);
    assert!(!capabilities.cookie_creation_modification_times);
    println!("Owned cookie flags, expiry and two-profile positive controls passed");

    wait(
        web.delete_cookie(&key("chosen", "alpha.test", "/"))
            .expect("selective delete launch"),
    )
    .expect("exact cookie deletion");
    let after = inventory(&session_a);
    assert_eq!(after.len(), 4);
    assert!(
        !after
            .iter()
            .any(|cookie| cookie.key == key("chosen", "alpha.test", "/"))
    );
    for preserved in [
        key("chosen", "alpha.test", "/keep"),
        key("other", "alpha.test", "/"),
        key("chosen", "beta.test", "/"),
    ] {
        assert!(
            after.iter().any(|cookie| cookie.key == preserved),
            "selective cleanup removed {preserved:?}"
        );
    }
    assert_cookie(&session_b, "https://alpha.test/", ("chosen", "B-root"));
    assert_cookie(&session_a, "https://alpha.test/keep", ("chosen", "A-path"));
    assert_cookie(&session_a, "https://alpha.test/", ("other", "A-name"));
    assert_cookie(&session_a, "https://beta.test/", ("chosen", "A-domain"));
    assert!(matches!(
        wait(
            session_a
                .delete_cookie(&key("missing", "alpha.test", "/"))
                .unwrap()
        ),
        Err(SiteDataError::NotFound)
    ));
    println!("Exact cookie deletion preserves other profile, domain, path and name passed");

    let groups = wait(
        web.website_data_inventory(WebsiteData::COOKIES)
            .expect("group inventory launch"),
    )
    .expect("native group inventory");
    assert!(
        groups.iter().any(|group| group.group_name == "alpha.test"
            && group.types & WebsiteData::COOKIES.bits() != 0),
        "positive native group metadata: {groups:?}"
    );
    assert!(groups.iter().any(|group| group.group_name == "beta.test"));
    let unsupported = web.remove_website_data(
        &WebsiteDataSelection::ExactOrigin("https://alpha.test".into()),
        WebsiteData::COOKIES,
    );
    assert!(
        matches!(unsupported, Err(SiteDataError::UnsupportedScope(_))),
        "exact-origin refusal"
    );
    assert_eq!(
        inventory(&session_a),
        after,
        "unsupported scope must not delete"
    );
    wait(
        web.remove_website_data(
            &WebsiteDataSelection::NativeGroup("alpha.test".into()),
            WebsiteData::COOKIES,
        )
        .expect("group remove launch"),
    )
    .expect("native group removal");
    let grouped = inventory(&session_a);
    assert!(
        !grouped
            .iter()
            .any(|cookie| cookie.key.domain == "alpha.test")
    );
    assert_cookie(&session_a, "https://beta.test/", ("chosen", "A-domain"));
    assert_cookie(&session_b, "https://alpha.test/", ("chosen", "B-root"));
    println!("Native grouped cleanup and exact-origin typed refusal passed");

    let cancelled = session_a.cookie_inventory().unwrap();
    cancelled.cancel();
    assert!(matches!(wait(cancelled), Err(SiteDataError::Cancelled)));
    assert_cookie(&session_a, "https://beta.test/", ("chosen", "A-domain"));
    let private = WebProfile::ephemeral();
    let ephemeral = profiles.session_for(&private).expect("private profile");
    ephemeral
        .add_cookie("private.test", "/", "private_only", "positive")
        .unwrap();
    assert_cookie(
        &ephemeral,
        "https://private.test/",
        ("private_only", "positive"),
    );
    assert_eq!(inventory(&ephemeral).len(), 1);
    drop(ephemeral);
    profiles.prune_closed_profiles();
    let reopened = profiles
        .session_for(&private)
        .expect("fresh private session");
    assert!(
        inventory(&reopened).is_empty(),
        "private profile must reopen empty"
    );
    println!("Cancellation and ephemeral reopen-empty passed");
    let orphan = NetworkSession::new_ephemeral().expect("late-completion private session");
    orphan
        .add_cookie("lifetime.test", "/", "alive_until_finish", "positive")
        .unwrap();
    let pending = orphan.cookie_inventory().expect("pending inventory");
    drop(orphan);
    let late = wait(pending).expect("inventory after dropping last host session");
    assert_eq!(late.len(), 1);
    assert_eq!(late[0].key.name, "alive_until_finish");
    dispatch_pending_native_events().expect("native GTask release");
    println!("Pending cookie inventory retains session through native GTask teardown passed");
    drop(reopened);
    drop(web);
    drop(session_a);
    drop(session_b);
    drop(profiles);
    drop(display);
    drop(origin);
}
