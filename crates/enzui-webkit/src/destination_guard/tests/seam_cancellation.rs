use super::*;

fn wait_until(condition: impl Fn() -> bool) {
    let started = std::time::Instant::now();
    while !condition() {
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "condition did not become true"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn connect_client(guard: &DestinationGuard) -> TcpStream {
    let mut client = TcpStream::connect(guard.addr()).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    client
        .write_all(&authorized_request(
            guard,
            b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
        ))
        .unwrap();
    client
}

fn guard_with_budget(
    policy: DestinationPolicy,
    resolver: Arc<dyn Resolver>,
    connector: Arc<dyn Connector>,
    budget: Arc<seam_budget::Budget>,
) -> DestinationGuard {
    DestinationGuard::start_with_runtime_seams(
        policy,
        resolver,
        connector,
        Arc::new(SystemTimeouts),
        Arc::new(TcpListenerWake),
        SeamDeadlines::production(),
        budget,
    )
    .unwrap()
}

struct HeldResolver {
    entered: SyncSender<()>,
    release: Mutex<Receiver<()>>,
}

impl Resolver for HeldResolver {
    fn resolve(&self, _: &str, _: u16) -> std::io::Result<Vec<SocketAddr>> {
        let _ = self.entered.send(());
        let _ = self.release.lock().unwrap().recv();
        Ok(vec![public_addr(443)])
    }
}

#[test]
fn dropping_guard_cancels_a_pending_resolver_wait_before_its_deadline() {
    let (entered_send, entered_receive) = sync_channel(1);
    let (release_send, release_receive) = sync_channel(1);
    let fixture = Fixture::start(OK_RESPONSE);
    let connector = RecordingConnector::new(fixture.addr);
    let guard = DestinationGuard::start_with(
        DestinationPolicy::default(),
        Arc::new(HeldResolver {
            entered: entered_send,
            release: Mutex::new(release_receive),
        }),
        connector.clone(),
    )
    .unwrap();
    assert!(Arc::ptr_eq(
        &guard.shared.helper_budget,
        &seam_budget::global()
    ));
    let mut client = connect_client(&guard);
    entered_receive
        .recv_timeout(Duration::from_secs(2))
        .unwrap();
    wait_until(|| guard.shared.seam_parked.load(Ordering::SeqCst) > 0);
    let shared = guard.shared.clone();
    let (done_send, done_receive) = sync_channel(1);
    let dropper = std::thread::spawn(move || {
        drop(guard);
        let _ = done_send.send(());
    });
    let prompt = done_receive.recv_timeout(Duration::from_millis(500));
    let _ = release_send.send(());
    dropper.join().unwrap();
    let mut response = Vec::new();
    let _ = client.read_to_end(&mut response);
    assert!(
        prompt.is_ok(),
        "guard shutdown waited for the resolver deadline"
    );
    assert!(
        response.is_empty(),
        "shutdown published success: {response:?}"
    );
    assert!(
        connector.seen().is_empty(),
        "canceled DNS connected upstream"
    );
    let control = shared.seam.lock().unwrap();
    assert_eq!(control.live, 0);
    assert!(control.poison.is_none(), "shutdown poisoned a healthy seam");
}

#[test]
fn completed_resolver_wakes_a_parked_worker_without_waiting_for_deadline() {
    let (entered_send, entered_receive) = sync_channel(1);
    let (release_send, release_receive) = sync_channel(1);
    let fixture = Fixture::start(OK_RESPONSE);
    let guard = DestinationGuard::start_with(
        DestinationPolicy::default(),
        Arc::new(HeldResolver {
            entered: entered_send,
            release: Mutex::new(release_receive),
        }),
        RecordingConnector::new(fixture.addr),
    )
    .unwrap();
    let mut client = connect_client(&guard);
    let (response_send, response_receive) = sync_channel(1);
    let reader = std::thread::spawn(move || {
        let mut response = Vec::new();
        let mut byte = [0_u8; 1];
        while client.read(&mut byte).unwrap_or(0) == 1 {
            response.push(byte[0]);
            if response.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let _ = response_send.send(response);
    });
    entered_receive
        .recv_timeout(Duration::from_secs(2))
        .unwrap();
    wait_until(|| guard.shared.seam_parked.load(Ordering::SeqCst) > 0);
    release_send.send(()).unwrap();
    let response = response_receive.recv_timeout(Duration::from_millis(500));
    drop(guard);
    reader.join().unwrap();
    assert!(
        response
            .expect("completed resolver left its worker asleep")
            .starts_with(b"HTTP/1.1 200 Connection established")
    );
}

#[test]
fn canceled_resolvers_hold_a_shared_budget_until_callbacks_return() {
    let budget = Arc::new(seam_budget::Budget::new(1));
    let (entered_send, entered_receive) = sync_channel(1);
    let (release_send, release_receive) = sync_channel(1);
    let fixture = Fixture::start(OK_RESPONSE);
    let connector = RecordingConnector::new(fixture.addr);
    let guard = guard_with_budget(
        DestinationPolicy::default(),
        Arc::new(HeldResolver {
            entered: entered_send,
            release: Mutex::new(release_receive),
        }),
        connector.clone(),
        budget.clone(),
    );
    let client = connect_client(&guard);
    entered_receive
        .recv_timeout(Duration::from_secs(2))
        .unwrap();
    wait_until(|| guard.shared.seam_parked.load(Ordering::SeqCst) > 0);
    let (done_send, done_receive) = sync_channel(1);
    let dropper = std::thread::spawn(move || {
        drop(guard);
        let _ = done_send.send(());
    });
    let prompt = done_receive.recv_timeout(Duration::from_millis(500));
    let active_after_drop = budget.active();
    let next_connector = RecordingConnector::new(fixture.addr);
    let next = guard_with_budget(
        DestinationPolicy::default(),
        ScriptedResolver::new(vec![vec![public_addr(443)]]),
        next_connector.clone(),
        budget.clone(),
    );
    let refused = proxy(
        &next,
        "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
    );
    drop(next);
    release_send.send(()).unwrap();
    dropper.join().unwrap();
    drop(client);
    wait_until(|| budget.active() == 0);
    let available = guard_with_budget(
        DestinationPolicy::default().allowing_cleartext(),
        ScriptedResolver::new(vec![vec![public_addr(80)]]),
        next_connector.clone(),
        budget.clone(),
    );
    let recovered = proxy(
        &available,
        "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
    );
    assert!(prompt.is_ok(), "canceling one guard waited on its resolver");
    assert_eq!(
        active_after_drop, 1,
        "cancellation released an active callback's permit"
    );
    assert!(
        refused.starts_with("HTTP/1.1 403"),
        "shared budget was bypassed: {refused}"
    );
    assert!(refused.contains("X-Enzui-Destination: seam-unavailable"));
    assert!(connector.seen().is_empty(), "canceled DNS reached connect");
    assert_eq!(next_connector.seen(), vec![public_addr(80)]);
    assert!(
        recovered.ends_with("FIXTURE"),
        "released budget did not recover: {recovered}"
    );
}

#[test]
fn a_connect_result_returned_after_shutdown_closes_without_relaying() {
    struct HeldConnector {
        addr: SocketAddr,
        entered: SyncSender<()>,
        release: Mutex<Receiver<()>>,
    }
    impl Connector for HeldConnector {
        fn connect(&self, addr: SocketAddr, timeout: Duration) -> std::io::Result<TcpStream> {
            assert_eq!(addr, public_addr(443));
            let socket = TcpStream::connect_timeout(&self.addr, timeout)?;
            let _ = self.entered.send(());
            let _ = self.release.lock().unwrap().recv();
            Ok(socket)
        }
    }
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let (observed_send, observed_receive) = sync_channel(1);
    let addr = listener.local_addr().unwrap();
    let endpoint = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut byte = [0_u8; 1];
        let result = stream.read(&mut byte);
        let _ = observed_send.send(result);
    });
    let (entered_send, entered_receive) = sync_channel(1);
    let (release_send, release_receive) = sync_channel(1);
    let budget = Arc::new(seam_budget::Budget::new(1));
    let guard = guard_with_budget(
        DestinationPolicy::default(),
        ScriptedResolver::new(vec![vec![public_addr(443)]]),
        Arc::new(HeldConnector {
            addr,
            entered: entered_send,
            release: Mutex::new(release_receive),
        }),
        budget.clone(),
    );
    let client = connect_client(&guard);
    entered_receive
        .recv_timeout(Duration::from_secs(2))
        .unwrap();
    wait_until(|| guard.shared.seam_parked.load(Ordering::SeqCst) > 0);
    let (done_send, done_receive) = sync_channel(1);
    let dropper = std::thread::spawn(move || {
        drop(guard);
        let _ = done_send.send(());
    });
    let prompt = done_receive.recv_timeout(Duration::from_millis(500));
    let active_after_drop = budget.active();
    release_send.send(()).unwrap();
    dropper.join().unwrap();
    drop(client);
    let observed = observed_receive
        .recv_timeout(Duration::from_secs(3))
        .unwrap();
    endpoint.join().unwrap();
    wait_until(|| budget.active() == 0);
    assert!(prompt.is_ok(), "shutdown waited for the connector callback");
    assert_eq!(active_after_drop, 1);
    assert!(
        matches!(observed, Ok(0)),
        "late connector socket was leaked or forwarded bytes: {observed:?}"
    );
}

#[test]
fn repeated_worker_wakes_do_not_restart_the_resolver_deadline() {
    let (entered_send, entered_receive) = sync_channel(1);
    let (release_send, release_receive) = sync_channel(1);
    let fixture = Fixture::start(OK_RESPONSE);
    let connector = RecordingConnector::new(fixture.addr);
    let budget = Arc::new(seam_budget::Budget::new(1));
    let guard = DestinationGuard::start_with_runtime_seams(
        DestinationPolicy::default(),
        Arc::new(HeldResolver {
            entered: entered_send,
            release: Mutex::new(release_receive),
        }),
        connector.clone(),
        Arc::new(SystemTimeouts),
        Arc::new(TcpListenerWake),
        SeamDeadlines {
            resolve: Duration::from_millis(50),
            connect: SEAM_CALL_TIMEOUT,
        },
        budget.clone(),
    )
    .unwrap();
    let mut client = connect_client(&guard);
    let (response_send, response_receive) = sync_channel(1);
    let reader = std::thread::spawn(move || {
        let mut response = Vec::new();
        let _ = client.read_to_end(&mut response);
        let _ = response_send.send(response);
    });
    entered_receive
        .recv_timeout(Duration::from_secs(2))
        .unwrap();
    wait_until(|| guard.shared.seam_parked.load(Ordering::SeqCst) > 0);
    let mut response = None;
    for _ in 0..100 {
        for worker in &guard.workers {
            worker.thread().unpark();
        }
        if let Ok(reply) = response_receive.try_recv() {
            response = Some(reply);
            break;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    let poison = guard.shared.seam.lock().unwrap().poison;
    let active = budget.active();
    drop(guard);
    release_send.send(()).unwrap();
    reader.join().unwrap();
    wait_until(|| budget.active() == 0);
    assert!(
        response
            .expect("resolver wait outlived repeated wakes")
            .starts_with(b"HTTP/1.1 403"),
        "resolver wait outlived repeated wakes"
    );
    assert_eq!(poison, Some(SeamFailure::Unavailable));
    assert_eq!(active, 1, "timeout released a running callback's permit");
    assert!(connector.seen().is_empty());
}
