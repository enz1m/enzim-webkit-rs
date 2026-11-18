use super::*;

#[test]
fn local_origins_proxy_allows_only_explicit_http_destination_and_revokes_new_requests() {
    let fixture = Fixture::start(OK_RESPONSE);
    let private: SocketAddr = "127.0.0.1:8080".parse().unwrap();
    let resolver = ScriptedResolver::new(vec![vec![private]]);
    let connector = RecordingConnector::new(fixture.addr);
    let guard = DestinationGuard::start_with(
        DestinationPolicy::DEFAULT,
        resolver.clone(),
        connector.clone(),
    )
    .unwrap();
    let request = "GET http://dev.local:8080/app HTTP/1.1\r\nHost: dev.local:8080\r\nConnection: close\r\n\r\n";
    assert!(proxy(&guard, request).starts_with("HTTP/1.1 403"));
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 0);
    let list = guard.local_origins();
    assert!(list.allow_origin("http://dev.local:8080").unwrap());
    assert!(proxy(&guard, request).contains("FIXTURE"));
    assert_eq!(connector.seen(), vec![private]);
    assert_eq!(fixture.accepted(), 1);
    for request in [
        "GET http://dev.local:8081/app HTTP/1.1\r\nHost: dev.local:8081\r\n\r\n",
        "GET http://other.local:8080/app HTTP/1.1\r\nHost: other.local:8080\r\n\r\n",
        "GET http://127.0.0.1:8080/app HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n",
        "CONNECT dev.local:8080 HTTP/1.1\r\nHost: dev.local:8080\r\n\r\n",
    ] {
        assert!(
            proxy(&guard, request).starts_with("HTTP/1.1 403"),
            "{request}"
        );
    }
    assert_eq!(connector.seen(), vec![private]);
    assert_eq!(guard.upstream_connects(), 1);
    assert!(list.revoke_origin("http://dev.local:8080").unwrap());
    let before = resolver.calls.load(Ordering::SeqCst);
    assert!(proxy(&guard, request).starts_with("HTTP/1.1 403"));
    assert_eq!(resolver.calls.load(Ordering::SeqCst), before);
    assert_eq!(fixture.accepted(), 1);
}

#[test]
fn local_origins_proxy_checks_every_answer_port_and_keeps_other_resolved_names_private() {
    let fixture = Fixture::start(OK_RESPONSE);
    let private: SocketAddr = "127.0.0.1:8443".parse().unwrap();
    let wrong_port: SocketAddr = "127.0.0.1:8444".parse().unwrap();
    let resolver = ScriptedResolver::new(vec![
        vec![private, wrong_port],
        vec![private],
        vec![public_addr(8443), private],
    ]);
    let connector = RecordingConnector::new(fixture.addr);
    let guard = DestinationGuard::start_with(
        DestinationPolicy::DEFAULT,
        resolver.clone(),
        connector.clone(),
    )
    .unwrap();
    guard
        .local_origins()
        .allow_origin("https://dev.local:8443")
        .unwrap();
    let request = "CONNECT dev.local:8443 HTTP/1.1\r\nHost: dev.local:8443\r\n\r\n";
    let denied = proxy(&guard, request);
    assert_eq!(
        denial_reason(&denied).as_deref(),
        Some("resolver-port-mismatch")
    );
    assert_eq!(guard.upstream_connects(), 0);
    assert_eq!(fixture.accepted(), 0);
    assert!(proxy(&guard, request).starts_with("HTTP/1.1 200 Connection established"));
    assert_eq!(connector.seen(), vec![private]);
    let denied = proxy(
        &guard,
        "CONNECT other.local:8443 HTTP/1.1\r\nHost: other.local:8443\r\n\r\n",
    );
    assert_eq!(
        denial_reason(&denied).as_deref(),
        Some("destination-not-public")
    );
    assert_eq!(connector.seen(), vec![private]);
    assert_eq!(guard.upstream_connects(), 1);
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 3);
}

#[test]
fn local_origins_proxy_redirect_target_requires_its_own_destination_grant() {
    let fixture = Fixture::start(
        "HTTP/1.1 302 Found\r\nLocation: http://other.local:8080/next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
    let private: SocketAddr = "127.0.0.1:8080".parse().unwrap();
    let resolver = ScriptedResolver::new(vec![vec![private]]);
    let connector = RecordingConnector::new(fixture.addr);
    let guard = DestinationGuard::start_with(
        DestinationPolicy::DEFAULT,
        resolver.clone(),
        connector.clone(),
    )
    .unwrap();
    guard
        .local_origins()
        .allow_origin("http://dev.local:8080")
        .unwrap();
    assert!(proxy(&guard,"GET http://dev.local:8080/start HTTP/1.1\r\nHost: dev.local:8080\r\nConnection: close\r\n\r\n").starts_with("HTTP/1.1 302"));
    let denied = proxy(
        &guard,
        "GET http://other.local:8080/next HTTP/1.1\r\nHost: other.local:8080\r\nConnection: close\r\n\r\n",
    );
    assert!(denied.starts_with("HTTP/1.1 403"));
    assert_eq!(connector.seen(), vec![private]);
    assert_eq!(fixture.accepted(), 1);
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);
}
