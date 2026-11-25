use rustix::net::SendFlags;
use std::net::TcpStream;

/// Largest payload of one loopback packet toward the engine under generic XDP,
/// which can require a contiguous atomic allocation for the whole packet.
pub(super) const RECORD_BYTES: usize = 4096;

/// Sends the head of `bytes`, at most one record, as a packet of its own.
///
/// Linux merges no data across `MSG_EOR`, neither in the send queue nor on
/// retransmission. The packet size therefore holds however much is queued
/// behind a reader that falls behind, and the send queue keeps its normal size:
/// a queue of one record would make every record wait for the reader.
pub(super) fn send_record(socket: &TcpStream, bytes: &[u8]) -> std::io::Result<usize> {
    let record = &bytes[..bytes.len().min(RECORD_BYTES)];
    Ok(rustix::net::send(
        socket,
        record,
        SendFlags::EOR | SendFlags::NOSIGNAL,
    )?)
}

/// Whether `socket` reaches its peer through the loopback interface: a
/// loopback address, or one of this host's own addresses.
pub(super) fn reaches_peer_over_loopback(socket: &TcpStream) -> bool {
    match (socket.local_addr(), socket.peer_addr()) {
        (Ok(local), Ok(peer)) => peer.ip().is_loopback() || peer.ip() == local.ip(),
        _ => false,
    }
}

pub(super) fn needs_records() -> bool {
    if std::env::var_os("ENZUI_WEBKIT_LOOPBACK_SEND_BUDGET").is_some_and(|value| value == "0") {
        return false;
    }
    query_generic_xdp().unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn query_generic_xdp() -> Option<bool> {
    use rustix::net::{AddressFamily, RecvFlags, SendFlags, SocketFlags, SocketType, netlink};
    let socket = rustix::net::socket_with(
        AddressFamily::NETLINK,
        SocketType::RAW,
        SocketFlags::CLOEXEC,
        None,
    )
    .ok()?;
    rustix::net::sockopt::set_socket_timeout(
        &socket,
        rustix::net::sockopt::Timeout::Recv,
        Some(std::time::Duration::from_millis(25)),
    )
    .ok()?;
    // RTM_GETLINK selects the local interface by name without requesting a link dump.
    let mut request = [0u8; 40];
    request[..4].copy_from_slice(&40u32.to_ne_bytes());
    request[4..6].copy_from_slice(&18u16.to_ne_bytes());
    request[6..8].copy_from_slice(&1u16.to_ne_bytes());
    request[8..12].copy_from_slice(&1u32.to_ne_bytes());
    request[32..34].copy_from_slice(&7u16.to_ne_bytes());
    request[34..36].copy_from_slice(&3u16.to_ne_bytes());
    request[36..39].copy_from_slice(b"lo\0");
    rustix::net::sendto(
        &socket,
        &request,
        SendFlags::empty(),
        &netlink::SocketAddrNetlink::new(0, 0),
    )
    .ok()?;
    let mut reply = [0u8; 32 * 1024];
    let (_, length, sender) =
        rustix::net::recvfrom(&socket, &mut reply[..], RecvFlags::TRUNC).ok()?;
    let sender = netlink::SocketAddrNetlink::try_from(sender?).ok()?;
    if sender.pid() != 0 || length > reply.len() {
        return None;
    }
    generic_xdp_reply(&reply[..length])
}

#[cfg(not(target_os = "linux"))]
fn query_generic_xdp() -> Option<bool> {
    Some(false)
}

#[cfg(any(target_os = "linux", test))]
fn attributes(mut bytes: &[u8], mut visit: impl FnMut(u16, &[u8]) -> Option<()>) -> Option<()> {
    while !bytes.is_empty() {
        let header = bytes.get(..4)?;
        let length = u16::from_ne_bytes(header[..2].try_into().ok()?) as usize;
        let kind = u16::from_ne_bytes(header[2..4].try_into().ok()?) & 0x3fff;
        if length < 4 {
            return None;
        }
        visit(kind, bytes.get(4..length)?)?;
        bytes = bytes.get(length.next_multiple_of(4)..)?;
    }
    Some(())
}

#[cfg(any(target_os = "linux", test))]
fn generic_xdp_reply(bytes: &[u8]) -> Option<bool> {
    let length = u32::from_ne_bytes(bytes.get(..4)?.try_into().ok()?) as usize;
    let bytes = bytes.get(..length)?;
    let kind = u16::from_ne_bytes(bytes.get(4..6)?.try_into().ok()?);
    let sequence = u32::from_ne_bytes(bytes.get(8..12)?.try_into().ok()?);
    let flags = u32::from_ne_bytes(bytes.get(24..28)?.try_into().ok()?);
    if kind != 16 || sequence != 1 || flags & 8 == 0 {
        return None;
    }
    let mut loopback = false;
    let mut generic = false;
    attributes(bytes.get(32..)?, |kind, value| {
        if kind == 3 {
            loopback = value == b"lo\0";
        } else if kind == 43 {
            attributes(value, |kind, value| {
                if (kind == 2 && value == [2])
                    || (kind == 6 && u32::from_ne_bytes(value.try_into().ok()?) != 0)
                {
                    generic = true;
                }
                Some(())
            })?;
        }
        Some(())
    })?;
    loopback.then_some(generic)
}
