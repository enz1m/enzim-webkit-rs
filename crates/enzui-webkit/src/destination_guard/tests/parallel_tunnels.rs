use super::*;

struct IdleOrigin {
    addr: SocketAddr,
    peers: Arc<Mutex<Vec<TcpStream>>>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl IdleOrigin {
    fn start() -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("origin");
        listener.set_nonblocking(true).expect("nonblocking origin");
        let addr = listener.local_addr().expect("origin address");
        let peers = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let accepted = peers.clone();
        let halt = stop.clone();
        let thread = std::thread::spawn(move || {
            while !halt.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((peer, _)) => accepted.lock().expect("origin peers").push(peer),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(2));
                    }
                    Err(error) => panic!("origin accept: {error}"),
                }
            }
        });
        Self {
            addr,
            peers,
            stop,
            thread: Some(thread),
        }
    }
}

impl Drop for IdleOrigin {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.thread
            .take()
            .expect("origin thread")
            .join()
            .expect("origin stopped");
    }
}

fn establish(guard: &DestinationGuard, index: usize) -> TcpStream {
    let mut client = TcpStream::connect_timeout(&guard.addr(), Duration::from_secs(2))
        .expect("proxy connection");
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("client deadline");
    client
        .set_write_timeout(Some(Duration::from_secs(5)))
        .expect("client write deadline");
    let head = format!(
        "CONNECT origin{index}.example:443 HTTP/1.1\r\nHost: origin{index}.example:443\r\n\r\n"
    );
    client
        .write_all(&authorized_request(guard, head.as_bytes()))
        .expect("CONNECT");
    let mut response = [0; 39];
    client.read_exact(&mut response).unwrap_or_else(|error| {
        panic!("tunnel {index} must progress while earlier tunnels stay open: {error}")
    });
    assert_eq!(&response, b"HTTP/1.1 200 Connection established\r\n\r\n");
    client
}

fn wait_for_peers(origin: &IdleOrigin, count: usize) {
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while origin.peers.lock().expect("origin peers").len() != count {
        assert!(
            std::time::Instant::now() < deadline,
            "all pinned origins connected"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
}

#[test]
fn reactor_readiness_admits_tunnels_while_existing_peers_idle() {
    let origin = IdleOrigin::start();
    let guard = DestinationGuard::start_with(
        DestinationPolicy::default(),
        ScriptedResolver::new(vec![vec![public_addr(443)]]),
        RecordingConnector::new(origin.addr),
    )
    .unwrap();
    let _first = establish(&guard, 0);
    wait_for_peers(&origin, 1);
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while guard.shared.relay_wakes.load(Ordering::SeqCst) == 0 {
        assert!(std::time::Instant::now() < deadline, "first queue wake");
        std::thread::sleep(Duration::from_millis(1));
    }
    let wakes = guard.shared.relay_wakes.load(Ordering::SeqCst);
    let ready = guard.shared.accept_readiness.load(Ordering::SeqCst);
    let mut second = establish(&guard, 1);
    wait_for_peers(&origin, 2);
    let mut peer = origin.peers.lock().unwrap()[1].try_clone().unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    second.write_all(b"ready").unwrap();
    let mut bytes = [0; 5];
    peer.read_exact(&mut bytes).unwrap();
    assert_eq!(&bytes, b"ready");
    assert!(guard.shared.relay_wakes.load(Ordering::SeqCst) > wakes);
    assert!(guard.shared.accept_readiness.load(Ordering::SeqCst) > ready);
}

#[test]
fn reactor_admission_probe() {
    let origin = IdleOrigin::start();
    let guard = DestinationGuard::start_with(
        DestinationPolicy::default(),
        ScriptedResolver::new(vec![vec![public_addr(443)]]),
        RecordingConnector::new(origin.addr),
    )
    .unwrap();
    let mut clients = Vec::new();
    let mut milliseconds = Vec::new();
    for index in 0..64 {
        let start = std::time::Instant::now();
        let mut client = establish(&guard, index);
        wait_for_peers(&origin, index + 1);
        let mut peer = origin.peers.lock().unwrap()[index].try_clone().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        client.write_all(b"ping").unwrap();
        let mut bytes = [0; 4];
        peer.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"ping");
        peer.write_all(b"pong").unwrap();
        client.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"pong");
        milliseconds.push(start.elapsed().as_secs_f64() * 1000.0);
        clients.push(client);
    }
    assert_eq!(guard.upstream_connects(), 64);
    println!("REACTOR_ADMISSION_MS {milliseconds:?}");
}

#[test]
fn tunnel_disables_nagle_on_both_relay_endpoints() {
    let origin = IdleOrigin::start();
    let guard = DestinationGuard::start_with(
        DestinationPolicy::default(),
        ScriptedResolver::new(vec![vec![public_addr(443)]]),
        RecordingConnector::new(origin.addr),
    )
    .expect("guard");
    let mut client = establish(&guard, 0);
    wait_for_peers(&origin, 1);
    let mut upstream = origin.peers.lock().unwrap()[0].try_clone().unwrap();
    upstream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    client.write_all(b"ping").unwrap();
    let mut payload = [0; 4];
    upstream.read_exact(&mut payload).unwrap();
    assert_eq!(&payload, b"ping");
    upstream.write_all(b"pong").unwrap();
    client.read_exact(&mut payload).unwrap();
    assert_eq!(&payload, b"pong");
    let active = guard.shared.active_sockets.lock().unwrap();
    assert_eq!(active.len(), 1);
    let endpoints = active.values().next().unwrap();
    assert_eq!(endpoints.len(), 2);
    for (index, endpoint) in endpoints.iter().enumerate() {
        assert!(
            endpoint.nodelay().unwrap(),
            "relay endpoint {index} buffers small packets"
        );
    }
}

#[test]
fn tunnel_capacity_refuses_overflow_and_releases_closed_slots() {
    let origin = IdleOrigin::start();
    let guard = DestinationGuard::start_with(
        DestinationPolicy::default(),
        ScriptedResolver::new(vec![vec![public_addr(443)]]),
        RecordingConnector::new(origin.addr),
    )
    .expect("guard");
    let clients = (0..128)
        .map(|index| establish(&guard, index))
        .collect::<Vec<_>>();
    let response = proxy(
        &guard,
        "CONNECT excess.example:443 HTTP/1.1\r\nHost: excess.example:443\r\n\r\n",
    );
    assert!(
        response.starts_with("HTTP/1.1 503"),
        "tunnel capacity must fail closed: {response}"
    );
    drop(clients);
    wait_for_peers(&origin, 129);
    for peer in origin.peers.lock().expect("origin peers").iter() {
        peer.shutdown(Shutdown::Both).expect("close origin");
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while !guard
        .shared
        .active_sockets
        .lock()
        .expect("registered sockets")
        .is_empty()
    {
        assert!(
            std::time::Instant::now() < deadline,
            "closed tunnels release their leases"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
    let _recovered = establish(&guard, 130);
}

#[test]
fn tunnel_backpressure_preserves_bytes_and_half_closes() {
    let origin = IdleOrigin::start();
    let guard = DestinationGuard::start_with(
        DestinationPolicy::default(),
        ScriptedResolver::new(vec![vec![public_addr(443)]]),
        RecordingConnector::new(origin.addr),
    )
    .expect("guard");
    let mut client = establish(&guard, 0);
    wait_for_peers(&origin, 1);
    let mut upstream = origin.peers.lock().expect("origin peers")[0]
        .try_clone()
        .expect("origin stream");
    upstream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("origin deadline");
    upstream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .expect("origin write deadline");
    let upload = (0..4 * 1024 * 1024 + 13)
        .map(|index| (index % 251) as u8)
        .collect::<Vec<_>>();
    let download = (0..4 * 1024 * 1024 + 29)
        .map(|index| (index % 239) as u8)
        .collect::<Vec<_>>();
    std::thread::scope(|scope| {
        let mut writer = client.try_clone().expect("client writer");
        let payload = &upload;
        let sent = scope.spawn(move || {
            writer.write_all(payload).expect("upload");
            writer.shutdown(Shutdown::Write).expect("upload EOF");
        });
        std::thread::sleep(Duration::from_millis(100));
        let mut received = Vec::new();
        upstream.read_to_end(&mut received).unwrap_or_else(|error| {
            panic!(
                "upstream observes half-close after {} bytes: {error}",
                received.len()
            )
        });
        assert_eq!(received.len(), 4 * 1024 * 1024 + 13);
        assert!(
            received == upload,
            "upload bytes preserved under backpressure"
        );
        sent.join().expect("upload writer");
        let payload = &download;
        let sent = scope.spawn(move || {
            upstream
                .write_all(payload)
                .expect("download after upload EOF");
            upstream.shutdown(Shutdown::Write).expect("download EOF");
        });
        std::thread::sleep(Duration::from_millis(100));
        received.clear();
        client
            .read_to_end(&mut received)
            .expect("client observes half-close");
        assert_eq!(received.len(), 4 * 1024 * 1024 + 29);
        assert!(
            received == download,
            "download bytes preserved under backpressure"
        );
        sent.join().expect("download writer");
    });
}

#[test]
fn idle_tunnels_do_not_block_new_origins() {
    let origin = IdleOrigin::start();
    let connector = RecordingConnector::new(origin.addr);
    let guard = DestinationGuard::start_with(
        DestinationPolicy::default(),
        ScriptedResolver::new(vec![vec![public_addr(443)]]),
        connector.clone(),
    )
    .expect("guard");
    let mut clients = Vec::new();
    for index in 0..16 {
        let mut client = TcpStream::connect_timeout(&guard.addr(), Duration::from_secs(2))
            .expect("proxy connection");
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("client deadline");
        client
            .set_write_timeout(Some(Duration::from_secs(2)))
            .expect("client write deadline");
        let head = format!(
            "CONNECT origin{index}.example:443 HTTP/1.1\r\nHost: origin{index}.example:443\r\n\r\n"
        );
        client
            .write_all(&authorized_request(&guard, head.as_bytes()))
            .expect("CONNECT");
        let mut response = [0; 39];
        client.read_exact(&mut response).unwrap_or_else(|error| {
            panic!("tunnel {index} must progress while earlier tunnels stay open: {error}")
        });
        assert_eq!(&response, b"HTTP/1.1 200 Connection established\r\n\r\n");
        clients.push(client);
    }
    assert_eq!(connector.seen().len(), 16);
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while origin.peers.lock().expect("origin peers").len() != 16 {
        assert!(
            std::time::Instant::now() < deadline,
            "all pinned origins connected"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
    let mut peers = origin.peers.lock().expect("origin peers");
    let upstream = peers.last_mut().expect("last origin");
    upstream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("origin deadline");
    upstream.write_all(b"hello").expect("origin bytes");
    let client = clients.last_mut().expect("last client");
    let mut bytes = [0; 5];
    client.read_exact(&mut bytes).expect("downstream relay");
    assert_eq!(&bytes, b"hello");
    client.write_all(b"reply").expect("client bytes");
    upstream.read_exact(&mut bytes).expect("upstream relay");
    assert_eq!(&bytes, b"reply");
}
