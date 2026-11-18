//! A profile's upstream proxy carries only guard-approved,
//! pinned numeric destinations, and every proxy failure fails closed.

use super::*;
use crate::destination_guard::upstream::UpstreamConnector;
use std::time::Instant;

struct Upstream {
    addr: SocketAddr,
    heads: Arc<Mutex<Vec<String>>>,
}

impl Upstream {
    fn start(reply: &'static str) -> Upstream {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("upstream binds");
        let addr = listener.local_addr().expect("upstream addr");
        let heads = Arc::new(Mutex::new(Vec::new()));
        let captured = heads.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(client) = stream else { continue };
                let captured = captured.clone();
                std::thread::spawn(move || serve(client, reply, &captured));
            }
        });
        Upstream { addr, heads }
    }

    fn proxy(&self) -> UpstreamProxy {
        UpstreamProxy::http_connect(self.addr)
    }

    fn heads(&self) -> Vec<String> {
        self.heads.lock().unwrap().clone()
    }
}

fn serve(mut client: TcpStream, reply: &str, heads: &Mutex<Vec<String>>) {
    let mut reader = BufReader::new(client.try_clone().expect("clone"));
    let mut head = String::new();
    let mut line = String::new();
    while reader.read_line(&mut line).unwrap_or(0) > 0 {
        head.push_str(&line);
        if line == "\r\n" {
            break;
        }
        line.clear();
    }
    heads.lock().unwrap().push(head.clone());
    if reply.is_empty() {
        std::thread::sleep(Duration::from_secs(3));
        return;
    }
    let _ = client.write_all(reply.as_bytes());
    if !reply.starts_with("HTTP/1.1 2") {
        return;
    }
    let target = head
        .split_whitespace()
        .nth(1)
        .and_then(|authority| authority.parse::<SocketAddr>().ok())
        .expect("CONNECT names a numeric address");
    let upstream = TcpStream::connect(target).expect("upstream reaches its target");
    let (mut a, mut b) = (client.try_clone().unwrap(), upstream.try_clone().unwrap());
    let mut upstream_reader = upstream;
    std::thread::spawn(move || {
        let _ = std::io::copy(&mut upstream_reader, &mut a);
        let _ = a.shutdown(std::net::Shutdown::Write);
    });
    let _ = std::io::copy(&mut reader, &mut b);
    let _ = b.shutdown(std::net::Shutdown::Write);
}

fn echo() -> SocketAddr {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("echo binds");
    let addr = listener.local_addr().expect("echo addr");
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut copy = stream.try_clone().unwrap();
            std::thread::spawn(move || {
                let _ = std::io::copy(&mut stream, &mut copy);
            });
        }
    });
    addr
}

#[test]
fn a_tunnel_reaches_the_pinned_numeric_address_through_the_upstream_proxy() {
    let upstream = Upstream::start("HTTP/1.1 200 Connection established\r\n\r\n");
    let target = echo();
    let guard =
        DestinationGuard::start_routed(DestinationPolicy::trusted_local(), Some(upstream.proxy()))
            .expect("guard starts");
    let mut stream = TcpStream::connect(guard.addr()).expect("guard accepts");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .write_all(&authorized_request(
            &guard,
            format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes(),
        ))
        .unwrap();
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).expect("guard answers");
        head.push(byte[0]);
    }
    assert!(
        head.starts_with(b"HTTP/1.1 200"),
        "{}",
        String::from_utf8_lossy(&head)
    );
    stream.write_all(b"through the chain").unwrap();
    let mut echoed = [0u8; 17];
    stream.read_exact(&mut echoed).expect("echo returns");
    assert_eq!(&echoed, b"through the chain");
    let heads = upstream.heads();
    assert_eq!(heads.len(), 1);
    assert!(
        heads[0].starts_with(&format!("CONNECT {target} HTTP/1.1\r\n")),
        "{heads:?}"
    );
    assert!(
        !heads[0]
            .to_ascii_lowercase()
            .contains("proxy-authorization"),
        "the guard capability leaked upstream: {heads:?}"
    );
}

#[test]
fn cleartext_http_is_tunneled_with_optional_proxy_authentication() {
    for credentials in [None, Some(("alice", "s3cret")), Some(("f", ""))] {
        let upstream = Upstream::start("HTTP/1.1 200 Connection established\r\n\r\n");
        let fixture = Fixture::start(OK_RESPONSE);
        let mut route = upstream.proxy();
        if let Some((user, pass)) = credentials {
            route = route.with_credentials(user, pass).unwrap();
        }
        let guard = DestinationGuard::start_routed(DestinationPolicy::trusted_local(), Some(route))
            .unwrap();
        let response = proxy_request(&guard, &fixture);
        assert!(response.contains("FIXTURE"), "{response}");
        assert_eq!(fixture.accepted(), 1);
        let heads = upstream.heads();
        assert!(
            !heads[0].contains(&authorization_value(&guard)),
            "local guard capability leaked to upstream proxy"
        );
        assert!(
            fixture
                .heads()
                .iter()
                .all(|head| !head.to_ascii_lowercase().contains("proxy-authorization")),
            "proxy credentials leaked to origin"
        );
        assert!(heads[0].starts_with(&format!("CONNECT {} HTTP/1.1\r\n", fixture.addr)));
        let expected = match credentials {
            None => None,
            Some(("alice", _)) => Some("YWxpY2U6czNjcmV0"),
            Some(_) => Some("Zjo="),
        };
        if let Some(encoded) = expected {
            assert!(heads[0].contains(&format!("\r\nProxy-Authorization: Basic {encoded}\r\n")));
        } else {
            assert!(
                !heads[0]
                    .to_ascii_lowercase()
                    .contains("proxy-authorization")
            );
        }
    }
}

#[test]
fn a_refusing_or_malformed_upstream_fails_closed_without_a_direct_connection() {
    for reply in [
        "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n",
        "SSH-2.0-not-a-proxy\r\n\r\n",
    ] {
        let upstream = Upstream::start(reply);
        let fixture = Fixture::start(OK_RESPONSE);
        let guard = DestinationGuard::start_routed(
            DestinationPolicy::trusted_local(),
            Some(upstream.proxy()),
        )
        .expect("guard starts");
        let response = proxy(
            &guard,
            &format!(
                "GET http://{addr}/hello HTTP/1.1\r\nHost: {addr}\r\n\r\n",
                addr = fixture.addr
            ),
        );
        assert!(!response.contains("FIXTURE"), "{reply:?}: {response}");
        assert!(response.contains("Content-Type: text/html; charset=utf-8"));
        assert!(response.contains("<title>Connection unavailable</title>"));
        assert!(response.contains("href=\"\""));
        assert!(!response.contains("<script"));
        assert_eq!(
            fixture.accepted(),
            0,
            "{reply:?} fell back to a direct connection"
        );
        assert_eq!(upstream.heads().len(), 1);
    }
}

#[test]
fn a_silent_upstream_is_bounded_by_the_connect_deadline_and_udp_is_refused() {
    let upstream = Upstream::start("");
    let connector = UpstreamConnector {
        proxy: upstream.proxy(),
    };
    let started = Instant::now();
    let error = connector
        .connect(public_addr(443), Duration::from_millis(300))
        .expect_err("a silent proxy cannot open a tunnel");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "{:?}",
        started.elapsed()
    );
    assert!(
        matches!(
            error.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ),
        "{error:?}"
    );
    assert_eq!(
        connector
            .connect_datagram(public_addr(443))
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::Unsupported
    );
}

fn proxy_request(guard: &DestinationGuard, fixture: &Fixture) -> String {
    proxy(
        guard,
        &format!(
            "GET http://{addr}/hello HTTP/1.1\r\nHost: {addr}\r\n\r\n",
            addr = fixture.addr
        ),
    )
}

fn socks5(login: Option<(&'static str, &'static str)>) -> SocketAddr {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("socks binds");
    let addr = listener.local_addr().expect("socks addr");
    std::thread::spawn(move || {
        let Ok((mut client, _)) = listener.accept() else {
            return;
        };
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut head = [0u8; 2];
        if client.read_exact(&mut head).is_err() {
            return;
        }
        let mut methods = vec![0u8; usize::from(head[1])];
        let _ = client.read_exact(&mut methods);
        let wanted = if login.is_some() { 2 } else { 0 };
        if !methods.contains(&wanted) {
            let _ = client.write_all(&[5, 0xff]);
            return;
        }
        let _ = client.write_all(&[5, wanted]);
        if let Some((user, pass)) = login {
            let field = |client: &mut TcpStream| {
                let mut length = [0u8; 1];
                client.read_exact(&mut length).ok()?;
                let mut value = vec![0u8; usize::from(length[0])];
                client.read_exact(&mut value).ok()?;
                String::from_utf8(value).ok()
            };
            let mut version = [0u8; 1];
            let _ = client.read_exact(&mut version);
            let (u, p) = (field(&mut client), field(&mut client));
            let ok = u.as_deref() == Some(user) && p.as_deref() == Some(pass);
            let _ = client.write_all(&[1, u8::from(!ok)]);
            if !ok {
                return;
            }
        }
        let mut request = [0u8; 4];
        if client.read_exact(&mut request).is_err() || request[3] != 1 {
            return;
        }
        let mut target = [0u8; 6];
        let _ = client.read_exact(&mut target);
        let target = SocketAddr::from((
            [target[0], target[1], target[2], target[3]],
            u16::from_be_bytes([target[4], target[5]]),
        ));
        let Ok(upstream) = TcpStream::connect(target) else {
            let _ = client.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]);
            return;
        };
        let _ = client.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0x1f, 0x90]);
        let (mut a, mut b) = (client.try_clone().unwrap(), upstream.try_clone().unwrap());
        let mut upstream_reader = upstream;
        std::thread::spawn(move || {
            let _ = std::io::copy(&mut upstream_reader, &mut a);
            let _ = a.shutdown(std::net::Shutdown::Write);
        });
        let _ = std::io::copy(&mut client, &mut b);
        let _ = b.shutdown(std::net::Shutdown::Write);
    });
    addr
}

#[test]
fn socks5_authentication_routes_or_refuses_without_direct_fallback() {
    for (login, credentials, success) in [
        (None, None, true),
        (Some(("bob", "hunter2")), Some(("bob", "hunter2")), true),
        (Some(("bob", "hunter2")), None, false),
        (Some(("bob", "hunter2")), Some(("bob", "wrong")), false),
    ] {
        let socks = socks5(login);
        let fixture = Fixture::start(OK_RESPONSE);
        let mut route = UpstreamProxy::socks5(socks);
        if let Some((user, pass)) = credentials {
            route = route.with_credentials(user, pass).unwrap();
        }
        let guard = DestinationGuard::start_routed(DestinationPolicy::trusted_local(), Some(route))
            .unwrap();
        let response = proxy_request(&guard, &fixture);
        assert_eq!(
            response.contains("FIXTURE"),
            success,
            "{credentials:?}: {response}"
        );
        assert_eq!(
            fixture.accepted(),
            usize::from(success),
            "direct fallback after refused authentication"
        );
        if !success {
            assert!(response.contains("<title>Connection unavailable</title>"));
        }
    }
}
