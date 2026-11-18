use super::{events_until, query, script, wait_value};
use enzui_webkit::ffi::profile::ProfileStore;
use enzui_webkit::ffi::runtime::{HeadlessDisplay, WebSession};
use enzui_webkit::input::{self, PointerButton, ViewportMapping};
use enzui_webkit::page::PageEvent;
use enzui_webkit::site_permissions::{PermissionOrigin, SitePermission};
use enzui_webkit::web::{PermissionKind, ViewRouter, WebPolicy, WebProfile};
use std::path::Path;

pub(super) fn run(root: &Path, display: &HeadlessDisplay, origin: &str) {
    let mut profiles = ProfileStore::new(root.join("notification-profile"));
    let profile = WebProfile::persistent("notifications");
    let mut web = WebSession::new_profiled(display, &mut profiles, &profile).unwrap();
    web.local_origins().unwrap().allow_origin(origin).unwrap();
    web.allow_tls_certificate_for_host(&std::fs::read(root.join("cert.pem")).unwrap(), "127.0.0.1")
        .unwrap();
    let mut router = ViewRouter::new();
    let view = router.create(89);
    web.bind_view(&router, view).unwrap();
    web.install_native_policy(
        &router,
        view,
        WebPolicy::strict().grant(PermissionKind::Notifications),
        |request| Some(request.id),
    )
    .unwrap();
    web.load(&format!("{origin}/notify"), 10_000).unwrap();
    let mapping = ViewportMapping::new(0.0, 0.0, 1024.0, 768.0, 1.0).unwrap();
    for event in [
        input::pointer_moved(view, &mapping, 512.0, 384.0),
        input::pointer_pressed(view, &mapping, 512.0, 384.0, PointerButton::Primary),
        input::pointer_released(view, &mapping, 512.0, 384.0, PointerButton::Primary),
    ] {
        assert!(web.forward_input(&event.unwrap()));
        web.pump(10);
    }
    let events = events_until(&web, |events| {
        events.iter().any(|event| matches!(event, PageEvent::Notification(notification) if notification.title == "legacy-positive"))
    });
    assert!(events.iter().any(|event| matches!(event, PageEvent::Notification(notification) if notification.body == "positive-body" && notification.tag.as_deref() == Some("positive-tag"))));
    assert_eq!(script(&web, "Notification.permission"), "granted");
    web.set_origin_permission_mode(true).unwrap();
    let origin = PermissionOrigin::parse(origin).unwrap();
    assert_eq!(query(&web, "notifications"), "prompt");
    assert_eq!(
        script(&web, "Notification.permission"),
        "granted",
        "positive control: native legacy permission cache disappeared"
    );
    script(
        &web,
        "globalThis.notificationClosed=0;globalThis.cachedNotification=new Notification('cached-should-close',{body:'blocked',tag:'blocked'});cachedNotification.onclose=()=>globalThis.notificationClosed=1;null",
    );
    wait_value(&web, "notificationClosed", "1");
    let mut events =
        super::PENDING_EVENTS.with(|pending| std::mem::take(&mut *pending.borrow_mut()));
    events.extend(web.take_page_events());
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, PageEvent::Notification(_))),
        "cached notification escaped origin-mode suppression: {events:?}"
    );
    assert!(
        web.set_site_permission(
            SitePermission {
                requesting_origin: origin.clone(),
                top_origin: origin,
                kind: PermissionKind::Notifications,
            },
            false,
        )
        .unwrap()
    );
    assert_eq!(query(&web, "notifications"), "denied");
    script(
        &web,
        "globalThis.notificationClosed=0;globalThis.cachedNotification=new Notification('cached-denied',{body:'blocked',tag:'denied'});cachedNotification.onclose=()=>globalThis.notificationClosed=1;null",
    );
    wait_value(&web, "notificationClosed", "1");
    let mut events =
        super::PENDING_EVENTS.with(|pending| std::mem::take(&mut *pending.borrow_mut()));
    events.extend(web.take_page_events());
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, PageEvent::Notification(_))),
        "explicit denial did not suppress a cached native grant: {events:?}"
    );
    web.set_origin_permission_mode(false).unwrap();
    script(
        &web,
        "new Notification('legacy-restored',{body:'restored',tag:'restored'});null",
    );
    events_until(&web, |events| {
        events.iter().any(|event| matches!(event, PageEvent::Notification(notification) if notification.title == "legacy-restored"))
    });
    web.set_notifications_enabled(false);
    assert_eq!(query(&web, "notifications"), "denied");
    script(
        &web,
        "globalThis.notificationClosed=0;globalThis.cachedNotification=new Notification('globally-blocked-legacy',{body:'blocked',tag:'global'});cachedNotification.onclose=()=>globalThis.notificationClosed=1;null",
    );
    wait_value(&web, "notificationClosed", "1");
    let mut events =
        super::PENDING_EVENTS.with(|pending| std::mem::take(&mut *pending.borrow_mut()));
    events.extend(web.take_page_events());
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, PageEvent::Notification(_))),
        "global block did not suppress legacy cached permission: {events:?}"
    );
    println!(
        "Notification legacy delivery, cached-grant suppression and legacy restoration passed"
    );
}
