//! Exercise profile metadata reclamation while native sessions remain shared.

use enzui_webkit::ffi::profile::ProfileStore;
use enzui_webkit::ffi::runtime::HeadlessDisplay;
use enzui_webkit::web::WebProfile;
use std::rc::Rc;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _display = HeadlessDisplay::new()?;
    let mut store = ProfileStore::new(
        std::env::args()
            .nth(1)
            .ok_or("private profile root required")?,
    );
    let first = WebProfile::ephemeral();
    let second = WebProfile::ephemeral();
    let first_session = store.session_for(&first)?;
    let second_session = store.session_for(&second)?;
    assert!(!Rc::ptr_eq(&first_session, &second_session));
    for _ in 0..128 {
        let session = store.session_for(&WebProfile::ephemeral())?;
        assert!(session.is_ephemeral());
        assert!(!Rc::ptr_eq(&session, &first_session));
        drop(session);
        assert!(
            Rc::ptr_eq(&first_session, &store.session_for(&first)?),
            "live profile lost its identity"
        );
        assert!(
            Rc::ptr_eq(&second_session, &store.session_for(&second)?),
            "another live profile lost its identity"
        );
    }
    let removed = store.prune_closed_profiles();
    assert_eq!(removed, 1, "dead profile metadata accumulated");
    assert_eq!(store.prune_closed_profiles(), 0);
    drop(first_session);
    drop(second_session);
    assert_eq!(
        store.prune_closed_profiles(),
        2,
        "live profile retention did not end with its final owners"
    );
    println!(
        "PROFILE_CACHE_RESULT {{\"closed_profiles\":128,\"stale_before_explicit_prune\":{removed},\"live_profiles_preserved\":2}}"
    );
    Ok(())
}
