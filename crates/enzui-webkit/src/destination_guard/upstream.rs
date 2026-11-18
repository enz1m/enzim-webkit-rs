//! Chained upstream proxy for a guard's approved destinations.
//!
//! The guard still screens, resolves and pins every destination. This
//! connector only changes how a TCP stream to that pinned address is opened:
//! through an HTTP CONNECT tunnel or a SOCKS5 CONNECT to the configured
//! proxy, naming the pinned numeric address rather than asking for DNS.
//! There is no direct fallback, UDP is refused, and
//! the guard's own `Proxy-Authorization` is never forwarded because the
//! upstream request is generated here; the proxy's own credentials, when the
//! profile has them, are the only ones it sees.

use enzui_security::secret::{Secret, SecretText};
use std::hash::{Hash, Hasher};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use super::Connector;

const MAX_RESPONSE_HEAD: usize = 8 * 1024;
// RFC 1929 bounds each credential field to 255 bytes.
const MAX_CREDENTIAL: usize = 255;

/// How a profile's guard reaches its upstream proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProxyKind {
    /// An HTTP proxy, asked for a tunnel with `CONNECT`.
    HttpConnect,
    /// A SOCKS5 proxy (RFC 1928), asked to `CONNECT` to a numeric address.
    Socks5,
}

#[derive(Clone, PartialEq, Eq)]
struct ProxyCredentials {
    username: SecretText,
    password: SecretText,
}

impl Hash for ProxyCredentials {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.username.expose_secret().hash(state);
        self.password.expose_secret().hash(state);
    }
}

/// An upstream proxy that a profile's guard tunnels approved destinations through.
///
/// The proxy is at a numeric address. The proxy address is a configured hop,
/// not a page destination, so the destination policy does not screen it.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct UpstreamProxy {
    address: SocketAddr,
    kind: ProxyKind,
    credentials: Option<ProxyCredentials>,
}

impl std::fmt::Debug for UpstreamProxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamProxy")
            .field("address", &self.address)
            .field("kind", &self.kind)
            .field("authenticated", &self.credentials.is_some())
            .finish()
    }
}

impl UpstreamProxy {
    /// An HTTP CONNECT proxy without authentication.
    #[must_use]
    pub const fn http_connect(address: SocketAddr) -> Self {
        Self {
            address,
            kind: ProxyKind::HttpConnect,
            credentials: None,
        }
    }

    /// A SOCKS5 proxy without authentication.
    #[must_use]
    pub const fn socks5(address: SocketAddr) -> Self {
        Self {
            address,
            kind: ProxyKind::Socks5,
            credentials: None,
        }
    }

    /// Configure HTTP Basic or SOCKS5 username/password authentication.
    /// Credentials are redacted in debug output and wiped on last drop.
    /// Both protocols send credentials without transport encryption; use a trusted proxy connection.
    ///
    /// # Errors
    ///
    /// The username is empty, either is longer than 255 bytes or contains a
    /// control character, or, for an HTTP proxy, the username contains a
    /// colon, which HTTP Basic cannot carry. SOCKS5 also requires a nonempty password.
    pub fn with_credentials(
        mut self,
        username: &str,
        password: &str,
    ) -> Result<Self, &'static str> {
        if username.is_empty() {
            return Err("a proxy username is required with a password");
        }
        if username.len() > MAX_CREDENTIAL || password.len() > MAX_CREDENTIAL {
            return Err("a proxy username or password is longer than 255 bytes");
        }
        if username
            .chars()
            .chain(password.chars())
            .any(char::is_control)
        {
            return Err("a proxy username or password contains a control character");
        }
        if self.kind == ProxyKind::HttpConnect && username.contains(':') {
            return Err("an HTTP proxy username cannot contain a colon");
        }
        if self.kind == ProxyKind::Socks5 && password.is_empty() {
            return Err("a SOCKS5 proxy password cannot be empty");
        }
        self.credentials = Some(ProxyCredentials {
            username: SecretText::new(username.to_owned()),
            password: SecretText::new(password.to_owned()),
        });
        Ok(self)
    }

    /// The proxy's address.
    #[must_use]
    pub const fn address(&self) -> SocketAddr {
        self.address
    }

    /// The tunneling protocol used to reach the proxy.
    #[must_use]
    pub const fn kind(&self) -> ProxyKind {
        self.kind
    }

    /// Whether authentication credentials are configured.
    #[must_use]
    pub const fn authenticated(&self) -> bool {
        self.credentials.is_some()
    }
}

#[derive(Debug)]
pub(super) struct UpstreamConnector {
    pub(super) proxy: UpstreamProxy,
}

impl Connector for UpstreamConnector {
    fn connect(&self, addr: SocketAddr, timeout: Duration) -> std::io::Result<TcpStream> {
        let deadline = Instant::now() + timeout;
        let mut stream = TcpStream::connect_timeout(&self.proxy.address, timeout)?;
        let remaining = || {
            deadline
                .checked_duration_since(Instant::now())
                .filter(|left| !left.is_zero())
                .ok_or(std::io::ErrorKind::TimedOut)
        };
        stream.set_nodelay(true)?;
        stream.set_write_timeout(Some(remaining()?))?;
        match self.proxy.kind {
            ProxyKind::HttpConnect => {
                http_connect(
                    &mut stream,
                    addr,
                    self.proxy.credentials.as_ref(),
                    &remaining,
                )?;
            }
            ProxyKind::Socks5 => {
                socks5_connect(
                    &mut stream,
                    addr,
                    self.proxy.credentials.as_ref(),
                    &remaining,
                )?;
            }
        }
        stream.set_read_timeout(None)?;
        stream.set_write_timeout(None)?;
        Ok(stream)
    }
}

fn http_connect(
    stream: &mut TcpStream,
    addr: SocketAddr,
    credentials: Option<&ProxyCredentials>,
    remaining: &impl Fn() -> Result<Duration, std::io::ErrorKind>,
) -> std::io::Result<()> {
    let mut request = String::with_capacity(1024);
    request.push_str(&format!("CONNECT {addr} HTTP/1.1\r\nHost: {addr}\r\n"));
    if let Some(credentials) = credentials {
        let pair = SecretText::new(format!(
            "{}:{}",
            credentials.username.expose_secret(),
            credentials.password.expose_secret()
        ));
        let encoded = SecretText::new(base64(pair.expose_secret().as_bytes()));
        request.push_str("Proxy-Authorization: Basic ");
        request.push_str(encoded.expose_secret());
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    let request = SecretText::new(request);
    stream.write_all(request.expose_secret().as_bytes())?;
    // Read one byte at a time so no tunneled byte is consumed with the head.
    let mut head = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= MAX_RESPONSE_HEAD {
            return Err(refused("upstream proxy response head too long"));
        }
        stream.set_read_timeout(Some(remaining()?))?;
        match stream.read(&mut byte)? {
            0 => return Err(refused("upstream proxy closed before answering")),
            _ => head.push(byte[0]),
        }
    }
    let status = head
        .split(|&b| b == b'\r')
        .next()
        .and_then(|line| std::str::from_utf8(line).ok())
        .and_then(|line| {
            let mut parts = line.splitn(3, ' ');
            matches!(parts.next(), Some("HTTP/1.1" | "HTTP/1.0"))
                .then(|| parts.next())
                .flatten()
        })
        .filter(|code| code.len() == 3 && code.bytes().all(|b| b.is_ascii_digit()));
    match status {
        Some(code) if code.starts_with('2') => Ok(()),
        Some("407") => Err(denied(if credentials.is_some() {
            "upstream proxy rejected its username or password"
        } else {
            "upstream proxy needs a username and password"
        })),
        Some(_) => Err(refused("upstream proxy refused the tunnel")),
        None => Err(refused("malformed upstream proxy response")),
    }
}

fn socks5_connect(
    stream: &mut TcpStream,
    addr: SocketAddr,
    credentials: Option<&ProxyCredentials>,
    remaining: &impl Fn() -> Result<Duration, std::io::ErrorKind>,
) -> std::io::Result<()> {
    let read = |stream: &mut TcpStream, buf: &mut [u8]| -> std::io::Result<()> {
        let mut buf = buf;
        while !buf.is_empty() {
            stream.set_read_timeout(Some(remaining()?))?;
            match stream.read(buf) {
                Ok(0) => return Err(refused("upstream proxy closed before answering")),
                Ok(n) => buf = &mut buf[n..],
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
        Ok(())
    };
    // Configured credentials must not silently downgrade to anonymous access.
    let greeting: &[u8] = if credentials.is_some() {
        &[5, 1, 2]
    } else {
        &[5, 1, 0]
    };
    stream.write_all(greeting)?;
    let mut choice = [0u8; 2];
    read(stream, &mut choice)?;
    match (choice, credentials) {
        ([5, 0], None) => {}
        ([5, 2], Some(credentials)) => {
            let (user, pass) = (
                credentials.username.expose_secret().as_bytes(),
                credentials.password.expose_secret().as_bytes(),
            );
            let mut login = Vec::with_capacity(3 + user.len() + pass.len());
            login.push(1);
            // `with_credentials` bounds both to 255 bytes.
            login.push(u8::try_from(user.len()).map_err(|_| refused("proxy username too long"))?);
            login.extend_from_slice(user);
            login.push(u8::try_from(pass.len()).map_err(|_| refused("proxy password too long"))?);
            login.extend_from_slice(pass);
            let login = Secret::new(login);
            stream.set_write_timeout(Some(remaining()?))?;
            stream.write_all(login.as_bytes())?;
            let mut status = [0u8; 2];
            read(stream, &mut status)?;
            if status[0] != 1 {
                return Err(refused("malformed upstream proxy authentication response"));
            }
            if status[1] != 0 {
                return Err(denied("upstream proxy rejected its username or password"));
            }
        }
        ([5, 0xff], None) => return Err(denied("upstream proxy needs a username and password")),
        ([5, _], _) => {
            return Err(refused(
                "upstream proxy offered no authentication method this profile can use",
            ));
        }
        _ => return Err(refused("malformed upstream proxy response")),
    }
    let mut request = vec![5, 1, 0];
    match addr {
        SocketAddr::V4(v4) => {
            request.push(1);
            request.extend_from_slice(&v4.ip().octets());
        }
        SocketAddr::V6(v6) => {
            request.push(4);
            request.extend_from_slice(&v6.ip().octets());
        }
    }
    request.extend_from_slice(&addr.port().to_be_bytes());
    stream.set_write_timeout(Some(remaining()?))?;
    stream.write_all(&request)?;
    let mut reply = [0u8; 4];
    read(stream, &mut reply)?;
    if reply[0] != 5 || reply[2] != 0 {
        return Err(refused("malformed upstream proxy response"));
    }
    if reply[1] != 0 {
        return Err(refused("upstream proxy refused the tunnel"));
    }
    // Consume only the reply address; leave tunneled payload untouched.
    let bound = match reply[3] {
        1 => 4 + 2,
        4 => 16 + 2,
        3 => {
            let mut length = [0u8; 1];
            read(stream, &mut length)?;
            if length[0] == 0 {
                return Err(refused("malformed upstream proxy bound address"));
            }
            usize::from(length[0]) + 2
        }
        _ => return Err(refused("malformed upstream proxy response")),
    };
    let mut skipped = vec![0u8; bound];
    read(stream, &mut skipped)?;
    Ok(())
}

fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for (i, shift) in [18, 12, 6, 0].into_iter().enumerate() {
            if i <= chunk.len() {
                out.push(char::from(ALPHABET[((n >> shift) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn refused(reason: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::ConnectionRefused, reason)
}

fn denied(reason: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::PermissionDenied, reason)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_are_validated_encoded_and_redacted() {
        for (plain, encoded) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64(plain.as_bytes()), encoded);
        }
        let address: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let proxy = UpstreamProxy::http_connect(address)
            .with_credentials("alice", "s3cret")
            .unwrap();
        assert!(proxy.authenticated());
        for secret in ["alice", "s3cret"] {
            assert!(!format!("{proxy:?}").contains(secret));
        }
        for (user, password) in [
            ("a", ""),
            ("a\r", "x"),
            ("a", "x\n"),
            (&"a".repeat(256), "x"),
        ] {
            assert!(
                UpstreamProxy::socks5(address)
                    .with_credentials(user, password)
                    .is_err()
            );
        }
        assert!(
            UpstreamProxy::http_connect(address)
                .with_credentials("a:b", "x")
                .is_err()
        );
        assert!(
            UpstreamProxy::socks5(address)
                .with_credentials("a:b", "x")
                .is_ok()
        );
        assert!(
            UpstreamProxy::socks5(address)
                .with_credentials("", "x")
                .is_err()
        );
        assert!(
            UpstreamProxy::socks5(address)
                .with_credentials("a", &"x".repeat(256))
                .is_err()
        );
    }

    #[test]
    fn socks_handshakes_validate_replies_preserve_payload_and_bound_slow_peers() {
        type ReplyCase = (Option<[u8; 2]>, &'static [u8], bool, bool);
        let cases: &[ReplyCase] = &[
            (None, &[5, 0, 0, 1, 127, 0, 0, 1, 0, 80], true, false),
            (
                None,
                &[
                    5, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 80,
                ],
                true,
                false,
            ),
            (None, &[5, 0, 0, 3, 3, b'f', b'o', b'o', 0, 80], true, false),
            (
                Some([1, 0]),
                &[5, 0, 0, 1, 127, 0, 0, 1, 0, 80],
                true,
                false,
            ),
            (
                Some([2, 0]),
                &[5, 0, 0, 1, 127, 0, 0, 1, 0, 80],
                false,
                false,
            ),
            (Some([1, 1]), &[], false, false),
            (None, &[4, 0, 0, 1, 127, 0, 0, 1, 0, 80], false, false),
            (None, &[5, 0, 1, 1, 127, 0, 0, 1, 0, 80], false, false),
            (None, &[5, 0, 0, 9], false, false),
            (None, &[5, 0, 0, 3, 0, 0, 80], false, false),
            (None, &[5, 0, 0, 1, 127], false, false),
            (None, &[5, 0, 0, 1, 127, 0, 0, 1, 0, 80], false, true),
        ];
        for (index, &(auth, reply, success, slow)) in cases.iter().enumerate() {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let target: SocketAddr = if index == 1 {
                "[2001:db8::7]:443"
            } else {
                "203.0.113.7:443"
            }
            .parse()
            .unwrap();
            let server = std::thread::spawn(move || {
                let (mut peer, _) = listener.accept().unwrap();
                peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                let mut greeting = [0; 3];
                peer.read_exact(&mut greeting).unwrap();
                assert_eq!(greeting, [5, 1, if auth.is_some() { 2 } else { 0 }]);
                peer.write_all(&[5, if auth.is_some() { 2 } else { 0 }])
                    .unwrap();
                if let Some(status) = auth {
                    let mut login = [0; 5];
                    peer.read_exact(&mut login).unwrap();
                    assert_eq!(login, [1, 1, b'u', 1, b'p']);
                    peer.write_all(&status).unwrap();
                    if status[1] != 0 {
                        return;
                    }
                }
                let mut request = vec![0; if target.is_ipv6() { 22 } else { 10 }];
                if peer.read_exact(&mut request).is_err() {
                    return;
                }
                let mut expected = vec![5, 1, 0];
                match target.ip() {
                    std::net::IpAddr::V4(ip) => {
                        expected.push(1);
                        expected.extend_from_slice(&ip.octets());
                    }
                    std::net::IpAddr::V6(ip) => {
                        expected.push(4);
                        expected.extend_from_slice(&ip.octets());
                    }
                }
                expected.extend_from_slice(&target.port().to_be_bytes());
                assert_eq!(request, expected);
                if slow {
                    for byte in reply {
                        std::thread::sleep(Duration::from_millis(80));
                        if peer.write_all(&[*byte]).is_err() {
                            break;
                        }
                    }
                } else {
                    let _ = peer.write_all(reply);
                    if success {
                        let _ = peer.write_all(b"hello");
                    }
                }
            });
            let mut route = UpstreamProxy::socks5(address);
            if auth.is_some() {
                route = route.with_credentials("u", "p").unwrap();
            }
            let connector = UpstreamConnector { proxy: route };
            let started = Instant::now();
            let result = connector.connect(
                target,
                if slow {
                    Duration::from_millis(120)
                } else {
                    Duration::from_secs(2)
                },
            );
            let elapsed = started.elapsed();
            assert_eq!(result.is_ok(), success, "case {index}: {result:?}");
            if let Ok(mut tunnel) = result {
                tunnel
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut payload = [0; 5];
                tunnel.read_exact(&mut payload).unwrap();
                assert_eq!(&payload, b"hello");
            }
            server.join().unwrap();
            if slow {
                assert!(
                    elapsed < Duration::from_millis(280),
                    "slow proxy extended the handshake: {elapsed:?}"
                );
            }
        }
    }
}
