//! Chained upstream proxy for a guard's approved destinations.
//!
//! The guard still screens, resolves and pins every destination. This
//! connector only changes how a TCP stream to that pinned address is opened:
//! through an HTTP CONNECT tunnel to the configured proxy, naming the numeric
//! address, so the proxy performs no DNS and cannot substitute a destination.
//! There is no direct fallback, UDP is refused, and the guard's own
//! `Proxy-Authorization` is never forwarded because the upstream request is
//! generated here.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use super::Connector;

const MAX_RESPONSE_HEAD: usize = 8 * 1024;

/// An upstream proxy that a profile's guard tunnels approved destinations through.
///
/// Only an unauthenticated HTTP CONNECT proxy at a numeric address is
/// supported. The proxy address is a configured hop, not a page destination,
/// so the destination policy does not screen it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UpstreamProxy {
    address: SocketAddr,
}

impl UpstreamProxy {
    /// An HTTP CONNECT proxy without authentication.
    #[must_use]
    pub const fn http_connect(address: SocketAddr) -> Self {
        Self { address }
    }

    /// The proxy's address.
    #[must_use]
    pub const fn address(&self) -> SocketAddr {
        self.address
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
        write!(stream, "CONNECT {addr} HTTP/1.1\r\nHost: {addr}\r\n\r\n")?;
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
            Some(code) if code.starts_with('2') => {
                stream.set_read_timeout(None)?;
                stream.set_write_timeout(None)?;
                Ok(stream)
            }
            Some(_) => Err(refused("upstream proxy refused the tunnel")),
            None => Err(refused("malformed upstream proxy response")),
        }
    }
}

fn refused(reason: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::ConnectionRefused, reason)
}
