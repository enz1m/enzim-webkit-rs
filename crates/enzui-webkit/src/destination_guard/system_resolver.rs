//! System name resolution that does not wait for a slow address family.
//!
//! `getaddrinfo` for both families returns only when the A and the AAAA
//! lookups have both finished. One lost or slow answer, common behind VPN and
//! tunnel resolvers, then holds every connection to that host for the
//! resolver's whole retry interval, typically four or five seconds, although
//! the other family answered in milliseconds. Each family is therefore looked
//! up on its own. Once one of them has a usable answer the other gets the
//! resolution delay of RFC 8305 to arrive, and is otherwise left out.
//!
//! A family that has not answered after [`REPEAT_AFTER`] is asked a second
//! time. The system resolver repeats a query only after seconds, and resolvers
//! that forward to a flaky upstream answer the first query late but the next
//! one at once.
//!
//! A lookup that outlasts [`LOOKUP_DEADLINE`] fails as an ordinary resolution
//! error before the guard's seam deadline refuses the request.

use crate::name_lookup::{Family, family_lookup};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::time::{Duration, Instant};

/// RFC 8305 section 3: how long a usable answer waits for the other family.
const RESOLUTION_DELAY: Duration = Duration::from_millis(50);
/// Far above an ordinary lookup and far below the resolver's own retry.
const REPEAT_AFTER: Duration = Duration::from_millis(400);
/// Below the guard's `RESOLVE_TIMEOUT`, so slow DNS is a failed lookup and
/// never an overrun of the seam deadline.
const LOOKUP_DEADLINE: Duration = Duration::from_secs(8);
/// Lookups left running after their answer stopped mattering are bounded;
/// past this many a new name is refused rather than resolved without a deadline.
const MAX_LOOKUP_THREADS: usize = 64;

type Lookup = std::io::Result<Vec<SocketAddr>>;

pub(super) fn resolve(host: &str, port: u16) -> Lookup {
    if let Ok(address) = host.trim_matches(['[', ']']).parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(address, port)]);
    }
    static RUNNING: AtomicUsize = AtomicUsize::new(0);
    struct Running;
    impl Drop for Running {
        fn drop(&mut self) {
            RUNNING.fetch_sub(1, Ordering::SeqCst);
        }
    }
    let (send, receive) = channel();
    let mut lookup = |family: Family| {
        if RUNNING.fetch_add(1, Ordering::SeqCst) >= MAX_LOOKUP_THREADS {
            RUNNING.fetch_sub(1, Ordering::SeqCst);
            return false;
        }
        let running = Running;
        let send = send.clone();
        let name = host.to_owned();
        std::thread::Builder::new()
            .name("enzui-destination-dns".into())
            .spawn(move || {
                let _running = running;
                // The receiver is gone when the answer came too late to matter.
                let _ = send.send((family, family_lookup(&name, port, family)));
            })
            .is_ok()
    };
    // A family that could not start is a silent family: repeated once, bounded by the deadline.
    let started = [lookup(Family::V4), lookup(Family::V6)];
    if started == [false, false] {
        return Err(std::io::Error::new(
            std::io::ErrorKind::ResourceBusy,
            "too many name lookups in progress",
        ));
    }
    let waits = Waits {
        delay: RESOLUTION_DELAY,
        repeat_after: REPEAT_AFTER,
        deadline: LOOKUP_DEADLINE,
    };
    race(&receive, &waits, reachable, &mut lookup)
}

pub(super) struct Waits {
    /// How long a usable answer waits for the other family.
    pub delay: Duration,
    /// How long a family may stay silent before it is asked again, once.
    pub repeat_after: Duration,
    /// When the lookup fails with whatever it has.
    pub deadline: Duration,
}

/// Join the two family answers as they arrive.
///
/// The first answer with a reachable address starts the resolution delay; an
/// empty, failed or unreachable one waits for the other family until the
/// deadline. Addresses keep their order within a family, and the family that
/// the system would try first comes first.
///
/// `repeat` starts one more lookup of a family and reports whether it did. Of
/// a family's attempts the first with addresses is its answer; a failed or
/// empty attempt counts only when no other attempt is still out.
pub(super) fn race(
    receive: &Receiver<(Family, Lookup)>,
    waits: &Waits,
    reachable: fn(&SocketAddr) -> Option<IpAddr>,
    repeat: &mut dyn FnMut(Family) -> bool,
) -> Lookup {
    let started = Instant::now();
    let limit = started + waits.deadline;
    let mut answers: [Option<Lookup>; 2] = [None, None];
    let mut spare: [Option<Lookup>; 2] = [None, None];
    let mut pending = [1usize, 1];
    let mut settle_by: Option<Instant> = None;
    let mut repeat_at = Some(started + waits.repeat_after);
    loop {
        let now = Instant::now();
        let mut wait_until = settle_by.map_or(limit, |settle| settle.min(limit));
        // A usable answer is about to settle the lookup; nothing is repeated then.
        if let Some(at) = repeat_at.filter(|_| settle_by.is_none()) {
            if now >= at && now < limit {
                repeat_at = None;
                for (index, family) in [Family::V4, Family::V6].into_iter().enumerate() {
                    if answers[index].is_none() && repeat(family) {
                        pending[index] += 1;
                    }
                }
                continue;
            }
            wait_until = wait_until.min(at);
        }
        if now >= wait_until {
            break;
        }
        match receive.recv_timeout(wait_until - now) {
            Ok((family, answer)) => {
                let index = usize::from(family == Family::V6);
                pending[index] = pending[index].saturating_sub(1);
                if answers[index].is_some() {
                    continue;
                }
                let found = answer.as_ref().is_ok_and(|addresses| !addresses.is_empty());
                if !found && pending[index] > 0 {
                    spare[index].get_or_insert(answer);
                    continue;
                }
                let usable = answer
                    .as_ref()
                    .is_ok_and(|addresses| addresses.iter().any(|a| reachable(a).is_some()));
                answers[index] = Some(answer);
                if answers.iter().all(Option::is_some) {
                    break;
                }
                if usable {
                    settle_by.get_or_insert(Instant::now() + waits.delay);
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
    for (answer, spare) in answers.iter_mut().zip(spare) {
        if answer.is_none() {
            *answer = spare;
        }
    }
    let [v4, v6] = answers;
    let mut failure = None;
    let mut take = |answer: Option<Lookup>| match answer {
        Some(Ok(addresses)) => addresses,
        Some(Err(error)) => {
            failure.get_or_insert(error);
            Vec::new()
        }
        None => Vec::new(),
    };
    let (v4, v6) = (take(v4), take(v6));
    if v4.is_empty() && v6.is_empty() {
        return Err(failure.unwrap_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "name resolution did not finish in time",
            )
        }));
    }
    let v6_first = v6
        .iter()
        .any(|address| reachable(address).is_some_and(|source| preferred_over_v4(address, source)));
    Ok(if v6_first {
        v6.into_iter().chain(v4).collect()
    } else {
        v4.into_iter().chain(v6).collect()
    })
}

/// The local address the system would use to reach `address`, if it has a
/// route. Connecting a datagram socket selects the route and sends nothing.
fn reachable(address: &SocketAddr) -> Option<IpAddr> {
    let any: SocketAddr = match address {
        SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        SocketAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let socket = UdpSocket::bind(any).ok()?;
    socket.connect(address).ok()?;
    socket.local_addr().ok().map(|local| local.ip())
}

/// The part of RFC 6724 destination ordering that decides between families:
/// an IPv6 destination goes first when its source has the same label and the
/// destination outranks IPv4. A unique-local source for a global destination,
/// the usual sign of IPv6 without a way out, therefore keeps IPv4 first.
fn preferred_over_v4(destination: &SocketAddr, source: IpAddr) -> bool {
    let (SocketAddr::V6(destination), IpAddr::V6(source)) = (destination, source) else {
        return false;
    };
    let class = |address: &Ipv6Addr| -> (u8, u8) {
        let first = address.segments()[0];
        if address.is_loopback() {
            (50, 0)
        } else if first & 0xfe00 == 0xfc00 {
            (3, 13)
        } else if first & 0xffc0 == 0xfe80 {
            (1, 11)
        } else if first == 0x2002 {
            (30, 2)
        } else if first == 0x2001 && address.segments()[1] == 0 {
            (5, 5)
        } else {
            (40, 1)
        }
    };
    const IPV4_PRECEDENCE: u8 = 35;
    let (precedence, label) = class(destination.ip());
    precedence > IPV4_PRECEDENCE && label == class(&source).1
}

#[cfg(test)]
mod tests {
    use super::*;

    const V4: &str = "192.0.2.7:443";
    const V6: &str = "[2001:db8::7]:443";

    fn everything_reachable(address: &SocketAddr) -> Option<IpAddr> {
        Some(match address {
            SocketAddr::V4(_) => Ipv4Addr::new(192, 0, 2, 1).into(),
            SocketAddr::V6(_) => "2001:db8::1".parse::<Ipv6Addr>().expect("address").into(),
        })
    }

    fn only_v4_reachable(address: &SocketAddr) -> Option<IpAddr> {
        address
            .is_ipv4()
            .then(|| Ipv4Addr::new(192, 0, 2, 1).into())
    }

    fn answers(plan: Vec<(u64, Family, Lookup)>) -> Receiver<(Family, Lookup)> {
        let (send, receive) = channel();
        for (after_ms, family, answer) in plan {
            let send = send.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(after_ms));
                let _ = send.send((family, answer));
            });
        }
        receive
    }

    fn one(text: &str) -> Lookup {
        Ok(vec![text.parse().expect("socket address")])
    }

    /// The race without repeated lookups.
    fn race(
        receive: &Receiver<(Family, Lookup)>,
        delay: Duration,
        deadline: Duration,
        reachable: fn(&SocketAddr) -> Option<IpAddr>,
    ) -> Lookup {
        let waits = Waits {
            delay,
            repeat_after: deadline,
            deadline,
        };
        super::race(receive, &waits, reachable, &mut |_| false)
    }

    /// The race with a 100 ms repeat whose answers come from `repeats`: the
    /// delay and answer of each family's second attempt.
    fn race_repeating(
        plan: Vec<(u64, Family, Lookup)>,
        mut repeats: Vec<(Family, u64, Lookup)>,
    ) -> (Lookup, Vec<Family>, Duration) {
        let started = Instant::now();
        let (send, receive) = channel();
        for (after_ms, family, answer) in plan {
            let send = send.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(after_ms));
                let _ = send.send((family, answer));
            });
        }
        let mut repeated = Vec::new();
        let waits = Waits {
            delay: Duration::from_millis(50),
            repeat_after: Duration::from_millis(100),
            deadline: Duration::from_secs(8),
        };
        let result = super::race(&receive, &waits, only_v4_reachable, &mut |family| {
            repeated.push(family);
            let Some(position) = repeats.iter().position(|(f, _, _)| *f == family) else {
                return false;
            };
            let (_, after_ms, answer) = repeats.remove(position);
            let send = send.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(after_ms));
                let _ = send.send((family, answer));
            });
            true
        });
        (result, repeated, started.elapsed())
    }

    #[test]
    fn a_silent_family_is_asked_again_and_the_repeat_answers() {
        let (result, repeated, elapsed) = race_repeating(
            vec![
                (5, Family::V6, Ok(Vec::new())),
                (4_000, Family::V4, one(V4)),
            ],
            vec![(Family::V4, 10, one(V4))],
        );
        assert_eq!(
            result.expect("the repeat answers"),
            vec![V4.parse().expect("address")]
        );
        assert_eq!(
            repeated,
            vec![Family::V4],
            "only the silent family is repeated"
        );
        assert!(
            elapsed < Duration::from_secs(1),
            "waited for the first attempt: {elapsed:?}"
        );
    }

    #[test]
    fn prompt_or_settling_lookups_are_not_repeated() {
        let (result, repeated, _) = race_repeating(
            vec![(5, Family::V4, one(V4)), (20, Family::V6, Ok(Vec::new()))],
            Vec::new(),
        );
        assert!(result.is_ok());
        assert!(
            repeated.is_empty(),
            "both families answered before the repeat"
        );
        // IPv4 answers at 80 ms and settles at 130 ms; the repeat falls due at 100 ms.
        let (result, repeated, elapsed) = race_repeating(
            vec![(80, Family::V4, one(V4)), (4_000, Family::V6, one(V6))],
            Vec::new(),
        );
        assert_eq!(
            result.expect("usable family"),
            vec![V4.parse().expect("address")]
        );
        assert!(
            repeated.is_empty(),
            "a settling lookup repeated the other family"
        );
        assert!(elapsed < Duration::from_secs(1));
    }

    #[test]
    fn a_failed_repeat_does_not_displace_the_first_attempt() {
        for failed in [Err(std::io::Error::other("try again")), Ok(Vec::new())] {
            let (result, repeated, _) = race_repeating(
                vec![(5, Family::V6, Ok(Vec::new())), (300, Family::V4, one(V4))],
                vec![(Family::V4, 5, failed)],
            );
            assert_eq!(repeated, vec![Family::V4]);
            assert_eq!(
                result.expect("the first attempt still answers"),
                vec![V4.parse().expect("address")]
            );
        }
        // With no attempt left, the failure is the family's answer.
        let (result, _, elapsed) = race_repeating(
            vec![
                (5, Family::V6, Ok(Vec::new())),
                (200, Family::V4, Err(std::io::Error::other("first failure"))),
            ],
            vec![(
                Family::V4,
                250,
                Err(std::io::Error::other("second failure")),
            )],
        );
        assert!(
            result
                .expect_err("both attempts failed")
                .to_string()
                .contains("failure")
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "waited past the last attempt: {elapsed:?}"
        );
    }

    #[test]
    fn a_slow_family_does_not_hold_a_usable_answer() {
        let started = Instant::now();
        let receive = answers(vec![(5, Family::V4, one(V4)), (2_000, Family::V6, one(V6))]);
        let addresses = race(
            &receive,
            Duration::from_millis(50),
            Duration::from_secs(8),
            everything_reachable,
        )
        .expect("the prompt family answers");
        assert_eq!(addresses, vec![V4.parse().expect("address")]);
        assert!(
            started.elapsed() < Duration::from_millis(600),
            "waited for the slow family: {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn an_unusable_first_answer_waits_for_the_other_family() {
        for first in [
            Ok(Vec::new()),
            Err(std::io::Error::other("temporary failure")),
            one(V6),
        ] {
            let receive = answers(vec![(5, Family::V6, first), (300, Family::V4, one(V4))]);
            let addresses = race(
                &receive,
                Duration::from_millis(50),
                Duration::from_secs(8),
                only_v4_reachable,
            )
            .expect("the later family answers");
            assert!(
                addresses.contains(&V4.parse().expect("address")),
                "returned without the only usable family: {addresses:?}"
            );
        }
    }

    #[test]
    fn no_answer_is_a_failed_lookup_within_the_deadline() {
        let started = Instant::now();
        let receive = answers(vec![
            (5, Family::V4, Ok(Vec::new())),
            (5_000, Family::V6, one(V6)),
        ]);
        let error = race(
            &receive,
            Duration::from_millis(50),
            Duration::from_millis(300),
            everything_reachable,
        )
        .expect_err("nothing usable arrived in time");
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(2));

        let receive = answers(vec![
            (5, Family::V4, Err(std::io::Error::other("server failure"))),
            (10, Family::V6, Ok(Vec::new())),
        ]);
        let error = race(
            &receive,
            Duration::from_millis(50),
            Duration::from_secs(8),
            everything_reachable,
        )
        .expect_err("both families failed");
        assert!(error.to_string().contains("server failure"));
    }
}
