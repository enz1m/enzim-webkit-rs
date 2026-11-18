use super::*;
use std::net::UdpSocket;

const MAX_DATAGRAM: usize = 65_527;
const BUFFER_CAPACITY: usize = MAX_DATAGRAM + 24;

enum CapsuleState {
    Header,
    Context(u64),
    Data(usize),
    Skip(u64),
}

pub(super) struct Capsules {
    input: Vec<u8>,
    state: CapsuleState,
}

impl Capsules {
    pub fn new() -> Self {
        Self {
            input: Vec::new(),
            state: CapsuleState::Header,
        }
    }

    pub fn available(&self) -> usize {
        BUFFER_CAPACITY - self.input.len()
    }

    pub fn push(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        if bytes.len() > self.available() {
            return Err(std::io::ErrorKind::InvalidData.into());
        }
        self.input.extend_from_slice(bytes);
        Ok(())
    }

    pub fn take_into(&mut self, packet: &mut Vec<u8>) -> std::io::Result<bool> {
        loop {
            match self.state {
                CapsuleState::Header => {
                    let Some((kind, prefix)) = varint(&self.input) else {
                        return Ok(false);
                    };
                    let Some((length, suffix)) = varint(&self.input[prefix..]) else {
                        return Ok(false);
                    };
                    self.input.drain(..prefix + suffix);
                    self.state = if kind == 0 {
                        CapsuleState::Context(length)
                    } else {
                        CapsuleState::Skip(length)
                    };
                }
                CapsuleState::Context(length) => {
                    if length == 0 {
                        return Err(std::io::ErrorKind::InvalidData.into());
                    }
                    if let Some(first) = self.input.first()
                        && (1_u64 << (first >> 6)) > length
                    {
                        return Err(std::io::ErrorKind::InvalidData.into());
                    }
                    let Some((context, prefix)) = varint(&self.input) else {
                        return Ok(false);
                    };
                    self.input.drain(..prefix);
                    let length = length - prefix as u64;
                    self.state = if context != 0 {
                        CapsuleState::Skip(length)
                    } else if length > MAX_DATAGRAM as u64 {
                        return Err(std::io::ErrorKind::InvalidData.into());
                    } else {
                        CapsuleState::Data(length as usize)
                    };
                }
                CapsuleState::Data(length) => {
                    if self.input.len() < length {
                        return Ok(false);
                    }
                    packet.clear();
                    packet.extend_from_slice(&self.input[..length]);
                    self.input.drain(..length);
                    self.state = CapsuleState::Header;
                    return Ok(true);
                }
                CapsuleState::Skip(remaining) => {
                    let count = remaining.min(self.input.len() as u64) as usize;
                    self.input.drain(..count);
                    let remaining = remaining - count as u64;
                    self.state = if remaining == 0 {
                        CapsuleState::Header
                    } else {
                        CapsuleState::Skip(remaining)
                    };
                    if remaining != 0 {
                        return Ok(false);
                    }
                }
            }
        }
    }
}

fn varint(bytes: &[u8]) -> Option<(u64, usize)> {
    let first = *bytes.first()?;
    let count = 1 << (first >> 6);
    if bytes.len() < count {
        return None;
    }
    let mut value = u64::from(first & 63);
    for &byte in &bytes[1..count] {
        value = (value << 8) | u64::from(byte);
    }
    Some((value, count))
}

pub(super) fn encode(packet: &[u8], output: &mut Vec<u8>) {
    output.clear();
    output.push(0);
    let length = packet.len() + 1;
    if length < 64 {
        output.push(length as u8);
    } else if length < 16_384 {
        output.extend_from_slice(&((length as u16) | 0x4000).to_be_bytes());
    } else {
        output.extend_from_slice(&((length as u32) | 0x8000_0000).to_be_bytes());
    }
    output.push(0);
    output.extend_from_slice(packet);
}

pub(super) fn connect(socket: SocketAddr) -> std::io::Result<UdpSocket> {
    let bind = if socket.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let upstream = UdpSocket::bind(bind)?;
    upstream.connect(socket)?;
    Ok(upstream)
}

pub(super) struct Setup<'a> {
    pub request: &'a ProxyRequest,
    pub buffered: &'a [u8],
    pub candidates: Vec<SocketAddr>,
    pub queue: Duration,
    pub header: Duration,
    pub dns: Duration,
    pub started: std::time::Instant,
}

pub(super) fn serve(
    mut client: TcpStream,
    shared: &Arc<Shared>,
    tunnels: &TunnelSender,
    lease: ConnectionLease,
    setup: Setup<'_>,
) {
    let Setup {
        request,
        buffered,
        candidates,
        queue,
        header,
        dns,
        started,
    } = setup;
    let Some(permit) = tunnels.reserve() else {
        respond(&mut client, 503, "guard-capacity");
        return;
    };
    let checked = candidates.clone();
    let connector = shared.connector.clone();
    let accounting = shared.clone();
    let connect_started = std::time::Instant::now();
    let connection = shared.call_seam_bounded(shared.seam_call_timeout, move || {
        let mut last = std::io::ErrorKind::NotFound.into();
        for address in candidates {
            accounting.upstream_connects.fetch_add(1, Ordering::SeqCst);
            match connector.connect_datagram(address) {
                Ok(socket) => return Ok((socket, address)),
                Err(error) => last = error,
            }
        }
        Err(last)
    });
    let (upstream, pinned) = match connection {
        Ok(Ok(connection)) => connection,
        Ok(Err(_)) => {
            respond(&mut client, 502, "upstream-unreachable");
            return;
        }
        Err(failure) => {
            record_seam_failure(shared, &request.url, failure);
            respond(&mut client, 403, failure.reason());
            return;
        }
    };
    if !checked.contains(&pinned) || shared.stop.load(Ordering::SeqCst) {
        return;
    }
    if client.set_nodelay(true).is_err()
        || client
            .write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\nCapsule-Protocol: ?1\r\n\r\n")
            .is_err()
    {
        return;
    }
    if tunnels
        .relay_datagram(client, upstream, lease, permit, buffered)
        .is_err()
    {
        return;
    }
    shared.record(GuardEvent::Allowed {
        target: PolicyUrl::new(request.url.clone()),
        addr: pinned,
        setup: SetupTiming {
            queue,
            header,
            dns,
            connect: connect_started.elapsed(),
            total: started.elapsed(),
        },
    });
}
