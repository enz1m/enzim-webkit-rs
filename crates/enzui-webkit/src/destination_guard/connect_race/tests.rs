use super::*;

#[test]
fn interleaves_families_deduplicates_and_bounds_attempts() {
    let first: SocketAddr = "[2001:4860:4860::8888]:443".parse().unwrap();
    let second: SocketAddr = "[2606:4700:4700::1111]:443".parse().unwrap();
    let third: SocketAddr = "1.1.1.1:443".parse().unwrap();
    assert_eq!(
        candidates(&[first, second, first, third]),
        [first, third, second]
    );
    assert!(candidates(&[]).is_empty());
    let many: Vec<_> = (1..=40)
        .map(|last| SocketAddr::from(([93, 184, 216, last], 443)))
        .collect();
    assert_eq!(candidates(&many), many[..16]);
}

#[test]
fn pinned_connections_fallback_and_respect_the_total_deadline() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let good = listener.local_addr().unwrap();
    let refused = SocketAddr::new(std::net::Ipv6Addr::LOCALHOST.into(), good.port());
    let reserved = socket_with(
        AddressFamily::INET6,
        SocketType::STREAM,
        SocketFlags::CLOEXEC,
        Some(rustix::net::ipproto::TCP),
    )
    .unwrap();
    rustix::net::bind(&reserved, &refused).unwrap();
    let mut attempts = 0;
    let (mut stream, address) = connect(&[refused, good], Duration::from_secs(2), &mut || {
        attempts += 1
    })
    .unwrap();
    let (mut accepted, _) = listener.accept().unwrap();
    stream.write_all(b"approved fallback").unwrap();
    let mut bytes = [0; 17];
    accepted.read_exact(&mut bytes).unwrap();
    assert_eq!(&bytes, b"approved fallback");
    assert_eq!(address, good);
    assert_eq!(attempts, 2);

    {
        let stalled = TcpListener::bind("127.0.0.2:0").unwrap();
        rustix::net::listen(&stalled, 0).unwrap();
        let first = stalled.local_addr().unwrap();
        let queued = TcpStream::connect_timeout(&first, Duration::from_secs(1)).unwrap();
        let listener = TcpListener::bind(("127.0.0.1", first.port())).unwrap();
        let good = listener.local_addr().unwrap();
        let probe = TcpStream::connect_timeout(&first, Duration::from_millis(60));
        assert!(
            matches!(probe, Err(error) if error.kind() == std::io::ErrorKind::TimedOut),
            "fixture did not establish an unresponsive first address"
        );
        let started = Instant::now();
        let mut attempts = 0;
        let (stream, address) = connect(&[first, good], Duration::from_millis(1500), &mut || {
            attempts += 1
        })
        .unwrap();
        let elapsed = started.elapsed();
        assert_eq!(address, good);
        assert_eq!(attempts, 2);
        assert!(
            elapsed >= FALLBACK_DELAY,
            "fallback skipped its pacing interval"
        );
        assert!(
            elapsed < Duration::from_secs(1),
            "fallback waited for the first address: {elapsed:?}"
        );
        listener.accept().unwrap();
        drop((stream, queued));
    }

    {
        let stalled = TcpListener::bind("127.0.0.2:0").unwrap();
        rustix::net::listen(&stalled, 0).unwrap();
        let first = stalled.local_addr().unwrap();
        let queued = TcpStream::connect_timeout(&first, Duration::from_secs(1)).unwrap();
        let listener = TcpListener::bind(("127.0.0.1", first.port())).unwrap();
        let good = listener.local_addr().unwrap();
        let mut attempts = 0;
        let result = connect(&[first, good], Duration::from_millis(80), &mut || {
            attempts += 1
        });
        assert!(matches!(result, Err(error) if error.kind() == std::io::ErrorKind::TimedOut));
        assert_eq!(attempts, 1, "a later candidate escaped the total deadline");
        drop(queued);
    }
}
