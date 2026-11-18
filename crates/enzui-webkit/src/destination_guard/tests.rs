//! Network-boundary gates for the mandatory destination guard.
//!
//! Every gate drives the guard over real TCP with a real client socket.
//! Request-target denial gates pair it with a listening fixture whose accept
//! counter must stay at zero. The redirect gate permits exactly the redirector
//! request and proves the credential-bearing target remains untouched.
//!
//! The policy under test is `DestinationPolicy::default()` - the one a caller
//! who configures nothing receives.

use super::*;
use enzui_security::url_policy::UrlVerdict;
use std::io::{BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::AtomicUsize;

mod local_origins;
mod parallel_tunnels;
mod seam_cancellation;
mod upstream_proxy;

#[test]
fn recent_resolver_cached_answers_still_pass_whole_answer_pinning() {
    struct SharedResolver(Arc<ScriptedResolver>);
    impl Resolver for SharedResolver {
        fn resolve(&self, host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
            std::thread::sleep(Duration::from_millis(25));
            self.0.resolve(host, port)
        }
    }
    let fixture = Fixture::start(OK_RESPONSE);
    let private = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);
    let resolver = ScriptedResolver::new(vec![
        vec![public_addr(443)],
        vec![public_addr(443), private],
    ]);
    let connector = RecordingConnector::new(fixture.addr);
    let guard = DestinationGuard::start_with(
        DestinationPolicy::default(),
        Arc::new(recent_resolver::RecentResolver::new(SharedResolver(
            resolver.clone(),
        ))),
        connector.clone(),
    )
    .unwrap();
    for _ in 0..2 {
        assert!(
            proxy(
                &guard,
                "CONNECT public.example:443 HTTP/1.1\r\nHost: public.example:443\r\n\r\n"
            )
            .starts_with("HTTP/1.1 200")
        );
    }
    for _ in 0..2 {
        let response = proxy(
            &guard,
            "CONNECT mixed.example:443 HTTP/1.1\r\nHost: mixed.example:443\r\n\r\n",
        );
        assert_eq!(
            denial_reason(&response).as_deref(),
            Some("destination-not-public")
        );
    }
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 2);
    assert_eq!(connector.seen(), vec![public_addr(443); 2]);
    assert_eq!(guard.upstream_connects(), 2);
    let setups: Vec<_> = guard
        .events()
        .iter()
        .filter_map(|event| {
            if let GuardEvent::Allowed { setup, .. } = event {
                Some(*setup)
            } else {
                None
            }
        })
        .collect();
    assert_eq!(setups.len(), 2);
    println!(
        "recent DNS lookup milliseconds: cold={}, reused={}",
        setups[0].dns.as_secs_f64() * 1000.0,
        setups[1].dns.as_secs_f64() * 1000.0
    );
}

#[test]
fn production_connector_races_only_the_approved_answer_and_records_the_winner() {
    let fixture = Fixture::start(OK_RESPONSE);
    let stalled = TcpListener::bind(("127.0.0.2", fixture.addr.port())).unwrap();
    rustix::net::listen(&stalled, 0).unwrap();
    let first = stalled.local_addr().unwrap();
    let queued = TcpStream::connect_timeout(&first, Duration::from_secs(1)).unwrap();
    assert!(
        matches!(TcpStream::connect_timeout(&first, Duration::from_millis(60)),
        Err(error) if error.kind() == std::io::ErrorKind::TimedOut)
    );
    let resolver = ScriptedResolver::new(vec![vec![first, fixture.addr]]);
    let guard = DestinationGuard::start_with(
        DestinationPolicy::trusted_local(),
        resolver.clone(),
        Arc::new(TcpConnector),
    )
    .unwrap();
    let started = std::time::Instant::now();
    let response = proxy(
        &guard,
        &format!(
            "GET http://fallback.example:{0}/ HTTP/1.1\r\nHost: fallback.example:{0}\r\n\r\n",
            fixture.addr.port()
        ),
    );
    let elapsed = started.elapsed();
    assert!(
        response.contains("FIXTURE"),
        "approved fallback did not load: {response}"
    );
    assert!(
        elapsed < Duration::from_secs(1),
        "guard waited for the stalled address: {elapsed:?}"
    );
    assert_eq!(
        resolver.calls.load(Ordering::SeqCst),
        1,
        "fallback re-resolved the host"
    );
    assert_eq!(
        guard.upstream_connects(),
        2,
        "candidate attempts were not accounted"
    );
    assert!(
        matches!(guard.events().as_slice(), [GuardEvent::Allowed {addr, ..}] if *addr == fixture.addr)
    );
    println!(
        "APPROVED_FALLBACK elapsed_ms={:.3} attempts=2",
        elapsed.as_secs_f64() * 1000.0
    );
    drop(queued);
}

#[test]
fn late_private_or_wrong_port_answers_are_refused_before_candidate_selection() {
    let fixture = Fixture::start(OK_RESPONSE);
    let mut answers: Vec<_> = (1..=17)
        .map(|last| SocketAddr::from(([93, 184, 216, last], 443)))
        .collect();
    let mut private = answers.clone();
    private.push("127.0.0.1:443".parse().unwrap());
    answers.push("1.1.1.1:8443".parse().unwrap());
    let resolver = ScriptedResolver::new(vec![private, answers]);
    let connector = RecordingConnector::new(fixture.addr);
    let guard =
        DestinationGuard::start_with(DestinationPolicy::default(), resolver, connector.clone())
            .unwrap();
    for _ in 0..2 {
        let response = proxy(
            &guard,
            "CONNECT many.example:443 HTTP/1.1\r\nHost: many.example:443\r\n\r\n",
        );
        assert!(
            response.starts_with("HTTP/1.1 403"),
            "late invalid answer was ignored: {response}"
        );
    }
    assert_eq!(guard.upstream_connects(), 0);
    assert!(connector.seen().is_empty());
}

#[test]
fn a_connector_cannot_report_an_unapproved_winner() {
    struct Misreported(SocketAddr);
    impl Connector for Misreported {
        fn connect(&self, _addr: SocketAddr, timeout: Duration) -> std::io::Result<TcpStream> {
            TcpStream::connect_timeout(&self.0, timeout)
        }
        fn connect_candidates(
            &self,
            addresses: &[SocketAddr],
            timeout: Duration,
            attempt: &mut dyn FnMut(),
        ) -> std::io::Result<(TcpStream, SocketAddr)> {
            attempt();
            self.connect(addresses[0], timeout)
                .map(|stream| (stream, "1.1.1.1:443".parse().unwrap()))
        }
    }
    let fixture = Fixture::start(OK_RESPONSE);
    let resolver = ScriptedResolver::new(vec![vec![public_addr(443)]]);
    let guard = DestinationGuard::start_with(
        DestinationPolicy::default(),
        resolver,
        Arc::new(Misreported(fixture.addr)),
    )
    .unwrap();
    let response = proxy(
        &guard,
        "CONNECT winner.example:443 HTTP/1.1\r\nHost: winner.example:443\r\n\r\n",
    );
    assert!(
        response.starts_with("HTTP/1.1 502"),
        "unapproved winner was relayed: {response}"
    );
    assert!(
        !guard
            .events()
            .iter()
            .any(|event| matches!(event, GuardEvent::Allowed { .. }))
    );
}

/// A real HTTP server on loopback that counts every accepted connection.
///
/// The counter is the load-bearing observable: a guard that denied a request
/// but still opened the socket would move it.
struct Fixture {
    addr: SocketAddr,
    accepts: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    heads: Arc<Mutex<Vec<String>>>,
}

impl Fixture {
    fn start(response: &'static str) -> Fixture {
        Fixture::start_raw(response.as_bytes())
    }

    /// Like [`Fixture::start`] but writes exact bytes, so a gate can send a
    /// response whose header value is not valid UTF-8.
    fn start_raw(response: &'static [u8]) -> Fixture {
        Self::start_owned(response.to_vec())
    }

    fn start_owned(response: Vec<u8>) -> Fixture {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("fixture binds");
        let addr = listener.local_addr().expect("fixture addr");
        let accepts = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let heads = Arc::new(Mutex::new(Vec::new()));
        let counter = accepts.clone();
        let halt = stop.clone();
        let captured = heads.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                if halt.load(Ordering::SeqCst) {
                    return;
                }
                let Ok(mut stream) = stream else { continue };
                counter.fetch_add(1, Ordering::SeqCst);
                let mut reader = BufReader::new(stream.try_clone().expect("clone"));
                let mut line = String::new();
                let mut head = String::new();
                // Drain and retain the request head so header-secrecy gates
                // observe exactly what reached the upstream socket.
                while reader.read_line(&mut line).unwrap_or(0) > 0 {
                    head.push_str(&line);
                    if line == "\r\n" || line == "\n" {
                        break;
                    }
                    line.clear();
                }
                captured.lock().expect("captured heads").push(head);
                let _ = stream.write_all(&response);
                let _ = stream.flush();
                let _ = stream.shutdown(Shutdown::Both);
            }
        });
        Fixture {
            addr,
            accepts,
            stop,
            heads,
        }
    }

    fn accepted(&self) -> usize {
        self.accepts.load(Ordering::SeqCst)
    }

    fn heads(&self) -> Vec<String> {
        self.heads.lock().expect("fixture heads").clone()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect_timeout(&self.addr, Duration::from_millis(200));
    }
}

const OK_RESPONSE: &str = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 7\r\nConnection: close\r\n\r\nFIXTURE";

/// A resolver whose answers a gate controls, so "a public name resolves
/// private" and "the second lookup answers differently" are reachable without
/// touching DNS. Classification and pinning remain the policy's.
struct ScriptedResolver {
    answers: Mutex<Vec<Vec<SocketAddr>>>,
    calls: AtomicUsize,
}

impl ScriptedResolver {
    fn new(answers: Vec<Vec<SocketAddr>>) -> Arc<ScriptedResolver> {
        Arc::new(ScriptedResolver {
            answers: Mutex::new(answers),
            calls: AtomicUsize::new(0),
        })
    }
}

impl Resolver for ScriptedResolver {
    fn resolve(&self, _host: &str, _port: u16) -> std::io::Result<Vec<SocketAddr>> {
        let index = self.calls.fetch_add(1, Ordering::SeqCst);
        let answers = self.answers.lock().expect("resolver answers");
        Ok(answers
            .get(index)
            .cloned()
            .unwrap_or_else(|| answers.last().cloned().unwrap_or_default()))
    }
}

/// A connector that records the address the guard decided on and then connects
/// to a local fixture instead, so an *allowed public* destination can be
/// exercised without the test performing real internet I/O. It cannot mask a
/// denial: the guard only reaches a connector after the policy allowed.
struct RecordingConnector {
    seen: Mutex<Vec<SocketAddr>>,
    substitute: SocketAddr,
}

impl RecordingConnector {
    fn new(substitute: SocketAddr) -> Arc<RecordingConnector> {
        Arc::new(RecordingConnector {
            seen: Mutex::new(Vec::new()),
            substitute,
        })
    }

    fn seen(&self) -> Vec<SocketAddr> {
        self.seen.lock().expect("seen").clone()
    }
}

impl Connector for RecordingConnector {
    fn connect(&self, addr: SocketAddr, timeout: Duration) -> std::io::Result<TcpStream> {
        self.seen.lock().expect("seen").push(addr);
        TcpStream::connect_timeout(&self.substitute, timeout)
    }
}

fn public_addr(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), port)
}

fn base64(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::new();
    for chunk in input.chunks(3) {
        let a = chunk[0];
        let b = chunk.get(1).copied().unwrap_or(0);
        let c = chunk.get(2).copied().unwrap_or(0);
        output.push(char::from(ALPHABET[usize::from(a >> 2)]));
        output.push(char::from(ALPHABET[usize::from(((a & 3) << 4) | (b >> 4))]));
        output.push(if chunk.len() > 1 {
            char::from(ALPHABET[usize::from(((b & 15) << 2) | (c >> 6))])
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            char::from(ALPHABET[usize::from(c & 63)])
        } else {
            '='
        });
    }
    output
}

fn authorization_value(guard: &DestinationGuard) -> String {
    let capability = &guard.shared.capability;
    format!(
        "Basic {}",
        base64(format!("{}:{}", capability.username(), capability.password()).as_bytes())
    )
}

fn authorized_request(guard: &DestinationGuard, request: &[u8]) -> Vec<u8> {
    let first_line_end = request
        .windows(2)
        .position(|window| window == b"\r\n")
        .map(|position| position + 2)
        .expect("fixture request has a request line");
    let header = format!("Proxy-Authorization: {}\r\n", authorization_value(guard));
    let mut authenticated = Vec::with_capacity(request.len() + header.len());
    authenticated.extend_from_slice(&request[..first_line_end]);
    authenticated.extend_from_slice(header.as_bytes());
    authenticated.extend_from_slice(&request[first_line_end..]);
    authenticated
}

/// Send one authenticated raw proxy request and read the whole reply.
fn proxy(guard: &DestinationGuard, request: &str) -> String {
    proxy_bytes(guard, request.as_bytes())
}

fn proxy_bytes(guard: &DestinationGuard, request: &[u8]) -> String {
    proxy_raw_bytes(guard, &authorized_request(guard, request))
}

fn proxy_raw_bytes(guard: &DestinationGuard, request: &[u8]) -> String {
    let mut stream =
        TcpStream::connect_timeout(&guard.addr(), Duration::from_secs(5)).expect("guard accepts");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    stream.write_all(request).expect("send request");
    stream.flush().expect("flush");
    let mut out = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(read) => out.extend_from_slice(&chunk[..read]),
        }
        // An established tunnel carries no further bytes until the client
        // speaks TLS, so stop at the head rather than waiting for the timeout.
        if out.starts_with(b"HTTP/1.1 200 Connection established")
            && out.windows(4).any(|window| window == b"\r\n\r\n")
        {
            break;
        }
        if out.len() > 64 * 1024 {
            break;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn denial_reason(response: &str) -> Option<String> {
    response
        .lines()
        .find(|line| {
            line.to_ascii_lowercase()
                .starts_with("x-enzui-destination:")
        })
        .map(|line| line.split_once(':').unwrap().1.trim().to_owned())
}

#[test]
fn local_clients_must_authenticate_before_any_guard_or_network_consequence() {
    let fixture = Fixture::start(OK_RESPONSE);
    let connector = RecordingConnector::new(fixture.addr);
    let guard = DestinationGuard::start_with(
        DestinationPolicy::trusted_local(),
        ScriptedResolver::new(vec![vec![public_addr(80)]]),
        connector.clone(),
    )
    .expect("guard starts");
    let target = "GET http://source.example/ HTTP/1.1\r\nHost: source.example\r\n\r\n";
    let exact = authorization_value(&guard);
    let attempts = [
        target.to_owned(),
        "GET http://source.example/ HTTP/1.1\r\nHost: source.example\r\n\
         Proxy-Authorization: Basic wrong\r\n\r\n"
            .to_owned(),
        "GET http://source.example/ HTTP/1.1\r\nHost: source.example\r\n\
         Proxy-Authorization Basic malformed\r\n\r\n"
            .to_owned(),
        format!(
            "GET http://source.example/ HTTP/1.1\r\nHost: source.example\r\n\
             Proxy-Authorization: {exact}\r\nProxy-Authorization: {exact}\r\n\r\n"
        ),
    ];
    for request in attempts {
        let response = proxy_raw_bytes(&guard, request.as_bytes());
        assert!(
            response.starts_with("HTTP/1.1 407 Proxy Authentication Required"),
            "unauthenticated request was not challenged: {response:?}"
        );
    }
    assert!(
        connector.seen().is_empty(),
        "connector observed local attacker traffic"
    );
    assert_eq!(guard.upstream_connects(), 0);
    assert_eq!(fixture.accepted(), 0);
    assert!(
        guard.events().is_empty(),
        "authentication refusals published guard events"
    );

    // Positive control through the same real listener: the exact generated
    // capability reaches the fixture and the shared contract strips it before
    // forwarding the cleartext request.
    let response = proxy(&guard, target);
    assert!(
        response.contains("FIXTURE"),
        "authenticated request did not relay: {response}"
    );
    assert_eq!(connector.seen(), vec![public_addr(80)]);
    assert_eq!(guard.upstream_connects(), 1);
    assert_eq!(fixture.accepted(), 1);
    assert!(guard.events().iter().any(GuardEvent::is_allowed));
    let forwarded = fixture.heads().join("\n");
    assert!(
        !forwarded
            .to_ascii_lowercase()
            .contains("proxy-authorization")
    );
    let secret = guard.shared.capability.password();
    assert!(
        !forwarded.contains(secret),
        "upstream received the capability"
    );

    // Every public diagnostic/display surface is credential-free. The one
    // authenticated URI is private and used only for native configuration.
    for diagnostic in [
        format!("{guard:?}"),
        format!("{:?}", guard.events()),
        guard.proxy_uri(),
        response,
    ] {
        assert!(
            !diagnostic.contains(secret),
            "capability leaked: {diagnostic}"
        );
        assert!(
            !diagnostic.contains(&exact),
            "auth value leaked: {diagnostic}"
        );
    }
}

#[test]
fn credential_redirect_is_refused_from_wire_location_before_target_request() {
    let credential = Fixture::start(
        "HTTP/1.1 302 Found\r\n\
         Location: http://user:never-LOG-THIS@target.example/secret\r\n\
         Content-Length: 0\r\nConnection: close\r\n\r\n",
    );
    let connector = Arc::new(RecordingConnector {
        seen: Mutex::new(Vec::new()),
        substitute: credential.addr,
    });
    let guard = DestinationGuard::start_with(
        DestinationPolicy::trusted_local(),
        ScriptedResolver::new(vec![vec![public_addr(80)]]),
        connector,
    )
    .expect("guard starts");

    let response = proxy(
        &guard,
        "GET http://source.example/redirect HTTP/1.1\r\n\
         Host: source.example\r\nConnection: close\r\n\r\n",
    );
    assert!(
        response.starts_with("HTTP/1.1 403"),
        "credential redirect response was not replaced by a refusal"
    );
    assert_eq!(
        denial_reason(&response).as_deref(),
        Some("credentials-in-url")
    );
    assert_eq!(credential.accepted(), 1, "only the redirector is contacted");
    let events = guard.events();
    let denied_target = events.iter().find_map(|event| match event {
        GuardEvent::Denied {
            target,
            cause: DestinationDenial::Url(UrlVerdict::CredentialsInUrl),
        } => Some(target),
        _ => None,
    });
    let denied_target = denied_target.expect("typed CredentialsInUrl event");
    assert!(
        !denied_target.as_str().contains("NEVER-LOG-THIS"),
        "the event log retained credential bytes"
    );
    let debug = format!("{events:?}");
    assert!(
        !debug.contains("NEVER-LOG-THIS"),
        "credential leaked: {debug}"
    );

    // Positive control: a safe same-origin Location remains a 302 for WebKit
    // to follow; the hook is not a blanket redirect denial.
    let safe = Fixture::start(
        "HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
    let guard = DestinationGuard::start_with(
        DestinationPolicy::trusted_local(),
        ScriptedResolver::new(vec![vec![public_addr(80)]]),
        Arc::new(RecordingConnector {
            seen: Mutex::new(Vec::new()),
            substitute: safe.addr,
        }),
    )
    .expect("safe guard starts");
    let response = proxy(
        &guard,
        "GET http://source.example/redirect HTTP/1.1\r\n\
         Host: source.example\r\nConnection: close\r\n\r\n",
    );
    assert!(response.starts_with("HTTP/1.1 302"), "{response}");
    assert_eq!(safe.accepted(), 1);
    assert!(!guard.events().iter().any(|event| matches!(
        event,
        GuardEvent::Denied {
            cause: DestinationDenial::Url(UrlVerdict::CredentialsInUrl),
            ..
        }
    )));
}

/// Build a trusted-local guard whose upstream connect is redirected to `addr`,
/// so a fixture can stand in for an allowed public destination.
fn trusted_guard_to(addr: SocketAddr) -> DestinationGuard {
    DestinationGuard::start_with(
        DestinationPolicy::trusted_local(),
        ScriptedResolver::new(vec![vec![public_addr(80)]]),
        Arc::new(RecordingConnector {
            seen: Mutex::new(Vec::new()),
            substitute: addr,
        }),
    )
    .expect("guard starts")
}

#[test]
fn whatwg_credential_preparser_matches_special_authority_boundaries() {
    const HTTP_SOURCE: &str = "http://source.example/dir/page";
    const HTTPS_SOURCE: &str = "https://source.example/dir/page";
    const SECRET: &str = "NEVER-LOG-THIS";

    // WHATWG treats two or more mixed slash/backslash separators as a network
    // authority, regardless of how many precede it. A different special scheme
    // enters authority parsing even with zero separators.
    for (location, source) in [
        ("//user:NEVER-LOG-THIS@evil.example/next", HTTP_SOURCE),
        ("///user:NEVER-LOG-THIS@evil.example/next", HTTP_SOURCE),
        ("/////user:NEVER-LOG-THIS@evil.example/next", HTTP_SOURCE),
        ("/\\/\\user:NEVER-LOG-THIS@evil.example/next", HTTP_SOURCE),
        (
            "http:\\\\user:NEVER-LOG-THIS@evil.example\\next",
            HTTP_SOURCE,
        ),
        (
            "http:////user:NEVER-LOG-THIS@evil.example/next",
            HTTP_SOURCE,
        ),
        ("https:user:NEVER-LOG-THIS@evil.example/next", HTTP_SOURCE),
        ("https:/user:NEVER-LOG-THIS@evil.example/next", HTTP_SOURCE),
        ("http:user:NEVER-LOG-THIS@evil.example/next", HTTPS_SOURCE),
        ("http:/user:NEVER-LOG-THIS@evil.example/next", HTTPS_SOURCE),
    ] {
        let redacted = credential_location_redacted(location.as_bytes(), source)
            .unwrap_or_else(|| panic!("WHATWG authority credential was missed: {location}"));
        assert!(
            !redacted.contains(SECRET),
            "credential retained: {redacted}"
        );
        assert!(
            redacted.contains("evil.example"),
            "host identity lost: {redacted}"
        );
    }

    // Under a same-scheme HTTP base, zero or one separator stays in the base
    // origin's path. The `@` is path data, not userinfo, and must not be falsely
    // reported as CredentialsInUrl.
    for (location, source) in [
        ("http:user:NEVER-LOG-THIS@evil.example/next", HTTP_SOURCE),
        ("http:/user:NEVER-LOG-THIS@evil.example/next", HTTP_SOURCE),
        ("http:\\user:NEVER-LOG-THIS@evil.example\\next", HTTP_SOURCE),
        ("https:user:NEVER-LOG-THIS@evil.example/next", HTTPS_SOURCE),
        ("https:/user:NEVER-LOG-THIS@evil.example/next", HTTPS_SOURCE),
        ("/user:NEVER-LOG-THIS@evil.example/next", HTTP_SOURCE),
        (
            "relative/user:NEVER-LOG-THIS@evil.example/next",
            HTTP_SOURCE,
        ),
        ("mailto:user:NEVER-LOG-THIS@evil.example", HTTP_SOURCE),
    ] {
        assert_eq!(
            credential_location_redacted(location.as_bytes(), source),
            None,
            "same-origin path or non-special URL was falsely classified: {location}"
        );
    }
}

#[test]
fn upgrade_exchange_is_forwarded_and_spliced_bidirectionally() {
    // A cleartext WebSocket-style upgrade must reach upstream as a genuine
    // handshake before the 101 can open a splice.
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("upgrade fixture binds");
    let addr = listener.local_addr().expect("addr");
    let (head_send, head_receive) = std::sync::mpsc::sync_channel(1);
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("upgrade accept");
        let mut reader = BufReader::new(stream.try_clone().expect("clone"));
        let mut line = String::new();
        let mut head = String::new();
        while reader.read_line(&mut line).unwrap_or(0) > 0 {
            head.push_str(&line);
            if line == "\r\n" {
                break;
            }
            line.clear();
        }
        head_send.send(head).expect("publish upstream head");
        stream
            .write_all(
                b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
            )
            .expect("send 101");
        stream.flush().expect("flush 101");
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf).expect("post-upgrade frame");
        stream.write_all(&buf).expect("echo frame");
        stream.flush().expect("flush frame");
    });
    let guard = trusted_guard_to(addr);
    let mut stream =
        TcpStream::connect_timeout(&guard.addr(), Duration::from_secs(5)).expect("guard accepts");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    let request = authorized_request(
        &guard,
        b"GET http://source.example/ws HTTP/1.1\r\n\
          Host: source.example\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\n\r\n",
    );
    stream.write_all(&request).expect("send upgrade");
    stream.flush().expect("flush");
    let upstream_head = head_receive
        .recv_timeout(Duration::from_secs(2))
        .expect("upstream receives handshake")
        .to_ascii_lowercase();
    assert!(upstream_head.contains("upgrade: websocket\r\n"));
    assert!(upstream_head.contains("connection: upgrade\r\n"));
    assert!(!upstream_head.contains("connection: close"));

    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while stream.read(&mut byte).unwrap_or(0) == 1 {
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let head = String::from_utf8_lossy(&head);
    assert!(head.contains("101 Switching Protocols"), "no 101: {head}");
    stream.write_all(b"PING").expect("send frame");
    stream.flush().expect("flush frame");
    let mut echoed = [0u8; 4];
    stream.read_exact(&mut echoed).expect("echo returns");
    assert_eq!(
        &echoed, b"PING",
        "upgrade traffic was not spliced bidirectionally"
    );
    drop(stream);
    server.join().expect("upgrade fixture exits");
}

#[test]
fn dns_rebinding_cannot_swap_the_pinned_destination() {
    let fixture = Fixture::start(OK_RESPONSE);
    // First lookup answers public, the second answers loopback: the classic
    // rebind. The guard resolves once per request and connects to the address
    // it judged, so hop one goes to the judged public address and hop two is
    // refused outright.
    let resolver = ScriptedResolver::new(vec![
        vec![public_addr(443)],
        vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443)],
    ]);
    let connector = RecordingConnector::new(fixture.addr);
    let guard = DestinationGuard::start_with(
        DestinationPolicy::default(),
        resolver.clone(),
        connector.clone(),
    )
    .expect("guard starts");

    let first = proxy(
        &guard,
        "CONNECT rebind.example.com:443 HTTP/1.1\r\nHost: rebind.example.com:443\r\n\r\n",
    );
    assert!(first.starts_with("HTTP/1.1 200"), "first hop: {first}");
    assert_eq!(
        connector.seen(),
        vec![public_addr(443)],
        "the connect address must be the address the policy judged"
    );

    let second = proxy(
        &guard,
        "CONNECT rebind.example.com:443 HTTP/1.1\r\nHost: rebind.example.com:443\r\n\r\n",
    );
    assert!(second.starts_with("HTTP/1.1 403"), "rebound hop: {second}");
    assert_eq!(
        denial_reason(&second).as_deref(),
        Some("destination-not-public")
    );
    assert_eq!(
        connector.seen().len(),
        1,
        "the rebound answer reached connect"
    );
    assert_eq!(
        guard.upstream_connects(),
        1,
        "only the permitted hop may connect"
    );
}

#[test]
fn a_private_subresource_or_fetch_is_refused_after_an_allowed_document() {
    // The document is allowed; the page then fetches a metadata endpoint and a
    // loopback service. Each subresource is its own proxy request and is
    // screened on its own merits.
    let fixture = Fixture::start(OK_RESPONSE);
    let resolver = ScriptedResolver::new(vec![vec![public_addr(443)]]);
    let connector = RecordingConnector::new(fixture.addr);
    let guard =
        DestinationGuard::start_with(DestinationPolicy::default(), resolver, connector.clone())
            .expect("guard starts");

    let document = proxy(
        &guard,
        "CONNECT docs.example.com:443 HTTP/1.1\r\nHost: docs.example.com:443\r\n\r\n",
    );
    assert!(document.starts_with("HTTP/1.1 200"), "document: {document}");

    for subresource in [
        "CONNECT 169.254.169.254:443 HTTP/1.1\r\nHost: 169.254.169.254\r\n\r\n",
        "CONNECT 127.0.0.1:6379 HTTP/1.1\r\nHost: 127.0.0.1:6379\r\n\r\n",
    ] {
        let response = proxy(&guard, subresource);
        assert!(
            response.starts_with("HTTP/1.1 403"),
            "subresource was permitted: {response}"
        );
        assert_eq!(
            denial_reason(&response).as_deref(),
            Some("destination-not-public")
        );
    }
    let fetch = proxy(
        &guard,
        "GET http://169.254.169.254/latest/meta-data/ HTTP/1.1\r\nHost: 169.254.169.254\r\n\r\n",
    );
    assert!(fetch.starts_with("HTTP/1.1 403"), "fetch: {fetch}");
    assert_eq!(
        connector.seen(),
        vec![public_addr(443)],
        "only the document was permitted to connect"
    );
    assert_eq!(guard.upstream_connects(), 1);
}

// -----------------------------------------------------------------------
// Bounded diagnostic composition: the guard's own log obeys the same three rules as the
// native policy observation ring - redacted rendering, a bounded ring with a
// truthful drop count, and a poisoned host seam that fails closed.
// -----------------------------------------------------------------------

#[test]
fn a_guard_event_never_renders_the_credential_or_query_it_saw() {
    // A proxied request line is exactly where a signed-URL token and a
    // `user:pass@` credential appear, and this event is what a diagnostic
    // prints.
    let guard = DestinationGuard::start(DestinationPolicy::default()).expect("guard starts");
    let response = proxy(
        &guard,
        "GET https://user:hunter2@127.0.0.1/admin?token=SECRET-TOKEN HTTP/1.1\r\n\
         Host: 127.0.0.1\r\n\r\n",
    );
    assert!(response.starts_with("HTTP/1.1 403"), "{response}");
    // The response body/headers name the rule, never the URL.
    assert!(
        !response.contains("SECRET-TOKEN") && !response.contains("hunter2"),
        "the denial response echoed the secret: {response}"
    );
    let events = guard.events();
    let rendered = format!("{events:?}");
    assert!(
        !rendered.contains("SECRET-TOKEN") && !rendered.contains("hunter2"),
        "GuardEvent Debug leaked the query/userinfo: {rendered}"
    );
    assert!(
        rendered.contains("<redacted>"),
        "GuardEvent Debug did not mark the redaction: {rendered}"
    );
    // The event is still findable by its redacted target.
    assert!(
        events
            .iter()
            .any(|event| event.target().contains("127.0.0.1")),
        "the event lost its identity along with its secret: {events:?}"
    );
}

/// Concurrent requests through a panicking seam all fail closed and the seam
/// ends poisoned. Calls are not serialized, so the admission race may let both
/// reach the seam before the poison flag is observed; the invariant is that
/// neither opens an upstream socket and both are denied, not that the second
/// call is blocked. The count stays bounded by the two workers involved.
#[test]
fn concurrent_requests_through_a_panicking_seam_fail_closed_and_poison() {
    struct CountingPanic {
        calls: Arc<AtomicUsize>,
    }
    impl Resolver for CountingPanic {
        fn resolve(&self, _host: &str, _port: u16) -> std::io::Result<Vec<SocketAddr>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            panic!("concurrent secret=DO-NOT-LOG");
        }
    }
    let calls = Arc::new(AtomicUsize::new(0));
    let guard = Arc::new(
        DestinationGuard::start_with(
            DestinationPolicy::default(),
            Arc::new(CountingPanic {
                calls: calls.clone(),
            }),
            Arc::new(TcpConnector),
        )
        .unwrap(),
    );
    let replies: Vec<_> = ["one.example", "two.example"]
        .into_iter()
        .map(|host| {
            let guard = guard.clone();
            std::thread::spawn(move || {
                proxy(
                    &guard,
                    &format!("CONNECT {host}:443 HTTP/1.1\r\nHost: {host}\r\n\r\n"),
                )
            })
        })
        .collect();
    for reply in replies {
        assert!(reply.join().unwrap().starts_with("HTTP/1.1 403"));
    }
    assert!(guard.seam_poisoned(), "a panicking seam was not poisoned");
    assert_eq!(
        guard.upstream_connects(),
        0,
        "a panicking seam still opened an upstream socket"
    );
    let observed = calls.load(Ordering::SeqCst);
    assert!(
        (1..=2).contains(&observed),
        "the panicking seam was called {observed} times, outside the worker bound"
    );
    let rendered = format!("{:?}", guard.events());
    assert!(!rendered.contains("DO-NOT-LOG"), "panic payload retained");
}
