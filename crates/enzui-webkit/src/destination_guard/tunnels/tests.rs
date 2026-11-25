use super::*;

fn pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("private listener");
    let peer = TcpStream::connect(listener.local_addr().expect("local address")).expect("peer");
    let (relay, _) = listener.accept().expect("relay endpoint");
    for stream in [&peer, &relay] {
        rustix::net::sockopt::set_socket_recv_buffer_size(stream, 1024 * 1024)
            .expect("fixture receive window");
        stream.set_nodelay(true).expect("nodelay");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("read deadline");
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .expect("write deadline");
    }
    relay.set_nonblocking(true).expect("nonblocking relay");
    (peer, relay)
}

fn queued(stream: &TcpStream, bytes: usize) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while rustix::io::ioctl_fionread(stream).expect("queued bytes") < bytes as u64 {
        assert!(
            Instant::now() < deadline,
            "expected {bytes} queued bytes; observed {}",
            rustix::io::ioctl_fionread(stream).expect("queue accounting")
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn tunnel(guard: &DestinationGuard, client: TcpStream, upstream: TcpStream) -> Tunnel {
    let lease = guard
        .shared
        .register_connection(&client)
        .expect("client lease");
    guard.shared.register_upstream(lease.id, &upstream);
    Tunnel {
        client,
        upstream,
        _lease: lease,
        _permit: guard.tunnels.sender.reserve().expect("tunnel permit"),
        upload: Direction::new(),
        download: Direction::new(),
        last_activity: Instant::now(),
    }
}

#[test]
fn short_ready_messages_are_forwarded_without_empty_read_probes() {
    let guard = DestinationGuard::start(DestinationPolicy::trusted_local()).expect("guard");
    let (mut client, front) = pair();
    let (mut origin, back) = pair();
    let mut tunnel = tunnel(&guard, front, back);
    client.write_all(b"request").expect("small upload");
    origin.write_all(b"response").expect("small download");
    queued(&tunnel.client, 7);
    queued(&tunnel.upstream, 8);
    READ_ATTEMPTS.set(0);
    assert!(
        tunnel
            .step(PollFlags::IN, PollFlags::IN)
            .expect("short duplex turn")
    );
    let attempts = READ_ATTEMPTS.get();
    let mut response = [0; 8];
    client.read_exact(&mut response).expect("reply");
    assert_eq!(&response, b"response");
    let mut request = [0; 7];
    origin.read_exact(&mut request).expect("request");
    assert_eq!(&request, b"request");
    assert_eq!(
        attempts, 2,
        "drained short messages triggered empty socket reads"
    );
}

#[test]
fn ready_duplex_burst_crosses_more_than_one_buffer_without_another_poll() {
    let guard = DestinationGuard::start(DestinationPolicy::trusted_local()).expect("guard");
    let (mut client, front) = pair();
    let (mut origin, back) = pair();
    let mut tunnel = tunnel(&guard, front, back);
    let upload = vec![0x3a; 48 * 1024];
    let download = vec![0xc5; 48 * 1024];
    client.write_all(&upload).expect("upload fixture");
    origin.write_all(&download).expect("download fixture");
    queued(&tunnel.client, upload.len());
    queued(&tunnel.upstream, download.len());
    assert!(
        tunnel
            .step(PollFlags::IN, PollFlags::IN)
            .expect("one relay turn")
    );
    queued(&client, download.len());
    queued(&origin, upload.len());
    let mut found = vec![0; upload.len()];
    origin.read_exact(&mut found).expect("forwarded upload");
    assert_eq!(found, upload);
    client.read_exact(&mut found).expect("forwarded download");
    assert_eq!(found, download);
}

#[test]
fn ready_bulk_turn_yields_with_queued_bytes_after_64_kib_per_direction() {
    let guard = DestinationGuard::start(DestinationPolicy::trusted_local()).expect("guard");
    let (client, front) = pair();
    let (mut origin, back) = pair();
    let mut tunnel = tunnel(&guard, front, back);
    let payload = vec![0x7b; 96 * 1024];
    origin.write_all(&payload).expect("bulk fixture");
    queued(&tunnel.upstream, payload.len());
    assert!(
        tunnel
            .step(PollFlags::empty(), PollFlags::IN)
            .expect("bounded turn")
    );
    let remaining = rustix::io::ioctl_fionread(&tunnel.upstream).expect("remaining bulk bytes");
    assert!(
        remaining >= 32 * 1024,
        "one tunnel exceeded its 64 KiB turn allowance"
    );
    queued(&client, 16 * 1024);
}

#[test]
fn record_download_keeps_the_turn_allowance_and_the_byte_stream() {
    let guard = DestinationGuard::start(DestinationPolicy::trusted_local()).expect("guard");
    let (mut client, front) = pair();
    let (mut origin, back) = pair();
    let mut tunnel = tunnel(&guard, front, back);
    tunnel.download = Direction::new().in_records(true);
    let payload: Vec<u8> = (0..96 * 1024).map(|index| (index % 239) as u8).collect();
    origin.write_all(&payload).expect("bulk fixture");
    queued(&tunnel.upstream, payload.len());
    assert!(
        tunnel
            .step(PollFlags::empty(), PollFlags::IN)
            .expect("bounded turn")
    );
    let remaining = rustix::io::ioctl_fionread(&tunnel.upstream).expect("remaining bulk bytes");
    assert!(
        remaining >= 32 * 1024,
        "one tunnel exceeded its 64 KiB turn allowance"
    );
    // A buffer leaves as several records in the same turn, not one per poll.
    queued(&client, 64 * 1024);
    while tunnel.download.pending()
        || rustix::io::ioctl_fionread(&tunnel.upstream).expect("rest") != 0
    {
        tunnel
            .step(PollFlags::OUT, PollFlags::IN)
            .expect("remaining turns");
    }
    let mut received = vec![0; payload.len()];
    client.read_exact(&mut received).expect("forwarded bytes");
    assert!(received == payload, "records changed the byte stream");
}

/// Bytes and data segments the kernel counted as sent on `socket`, read from
/// its statistics by an independent tool.
#[cfg(target_os = "linux")]
fn sent(socket: &TcpStream) -> (u64, u64) {
    let port = socket.local_addr().expect("local address").port();
    let output = std::process::Command::new("ss")
        .args(["-H", "-tin", "sport", "=", &format!(":{port}")])
        .output()
        .expect("socket statistics");
    assert!(output.status.success(), "socket statistics command failed");
    let text = String::from_utf8(output.stdout).expect("statistics text");
    let field = |name: &str| -> u64 {
        text.split_whitespace()
            .find_map(|word| word.strip_prefix(name))
            .unwrap_or_else(|| panic!("{name} is absent"))
            .parse()
            .expect("counter")
    };
    (field("bytes_sent:"), field("data_segs_out:"))
}

#[cfg(target_os = "linux")]
#[test]
fn records_stay_separate_packets_behind_a_reader_that_falls_behind() {
    use std::io::{ErrorKind, Read};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listener");
    let sender = TcpStream::connect(listener.local_addr().expect("address")).expect("sender");
    let (mut receiver, _) = listener.accept().expect("receiver");
    sender.set_nodelay(true).expect("nodelay");
    sender.set_nonblocking(true).expect("nonblocking sender");
    receiver
        .set_nonblocking(true)
        .expect("nonblocking receiver");
    let payload: Vec<u8> = (0..768 * 1024).map(|index| (index % 251) as u8).collect();
    let mut received = Vec::with_capacity(payload.len());
    let mut chunk = vec![0; 64 * 1024];
    let mut offset = 0;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while received.len() < payload.len() {
        assert!(std::time::Instant::now() < deadline, "transfer stalled");
        // Send until the kernel refuses, so data waits unsent behind a closed
        // window: the state in which separate sends are merged into one packet.
        while offset < payload.len() {
            match loopback::send_record(&sender, &payload[offset..]) {
                Ok(count) => {
                    assert!((1..=loopback::RECORD_BYTES).contains(&count));
                    offset += count;
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(error) => panic!("record send failed: {error}"),
            }
        }
        match receiver.read(&mut chunk) {
            Ok(count) => received.extend_from_slice(&chunk[..count]),
            Err(error) if error.kind() == ErrorKind::WouldBlock => std::thread::yield_now(),
            Err(error) => panic!("receive failed: {error}"),
        }
    }
    assert!(received == payload, "records changed the byte stream");
    let (bytes, segments) = sent(&sender);
    assert_eq!(bytes, payload.len() as u64);
    assert!(
        bytes <= segments * loopback::RECORD_BYTES as u64,
        "{bytes} bytes left in {segments} packets: sends were merged"
    );
}

#[test]
fn loopback_records_cover_the_upload_toward_a_loopback_upstream() {
    let guard = DestinationGuard::start(DestinationPolicy::trusted_local()).expect("guard");
    let (_client, front) = pair();
    let (_origin, back) = pair();
    let lease = guard
        .shared
        .register_connection(&front)
        .expect("client lease");
    let mut sender = guard.tunnels.sender.clone();
    sender.loopback_records = true;
    let permit = sender.reserve().expect("tunnel permit");
    let tunnel = sender.tunnel(front, back, lease, permit);
    assert!(tunnel.download.records);
    assert!(
        tunnel.upload.records,
        "loopback upload left in coalesced packets"
    );
}

#[test]
fn only_a_loopback_peer_is_reached_over_loopback() {
    let (_peer, upstream) = pair();
    assert!(loopback::reaches_peer_over_loopback(&upstream));
    let unconnected = rustix::net::socket(
        rustix::net::AddressFamily::INET,
        rustix::net::SocketType::STREAM,
        None,
    )
    .expect("unconnected socket");
    assert!(!loopback::reaches_peer_over_loopback(&TcpStream::from(
        unconnected
    )));
}
