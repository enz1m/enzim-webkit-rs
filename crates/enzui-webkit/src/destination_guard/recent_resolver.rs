use super::{HashMap, Mutex, Resolver, SocketAddr};
use std::sync::{Arc, Condvar};
use std::time::{Duration, Instant};

// getaddrinfo exposes no TTL; Chromium's host cache uses one minute in that case.
const LIFETIME: Duration = Duration::from_secs(60);
const MAX_ENTRIES: usize = 256;
const MAX_ADDRESSES: usize = 32;

struct Entry {
    started: Instant,
    addresses: Vec<SocketAddr>,
}

type LookupKey = (String, u16);
type Resolution = std::io::Result<Vec<SocketAddr>>;

#[derive(Clone)]
enum Outcome {
    Addresses(Vec<SocketAddr>),
    Failed(std::io::ErrorKind, String),
    Unshared,
}

struct Flight {
    outcome: Mutex<Option<Outcome>>,
    ready: Condvar,
}

impl Flight {
    fn wait(&self) -> Option<Resolution> {
        let state = self.outcome.lock().unwrap_or_else(|e| e.into_inner());
        let (state, _) = self
            .ready
            .wait_timeout_while(state, super::RESOLVE_TIMEOUT, |s| s.is_none())
            .unwrap_or_else(|e| e.into_inner());
        match state.as_ref() {
            Some(Outcome::Addresses(addresses)) => Some(Ok(addresses.clone())),
            Some(Outcome::Failed(kind, message)) => {
                Some(Err(std::io::Error::new(*kind, message.clone())))
            }
            Some(Outcome::Unshared) => None,
            None => Some(Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "shared DNS lookup timed out",
            ))),
        }
    }
}

type Flights = Mutex<HashMap<LookupKey, Arc<Flight>>>;

struct Publication<'a> {
    flight: Arc<Flight>,
    flights: &'a Flights,
    key: LookupKey,
}

impl Publication<'_> {
    fn publish(&self, result: &Resolution) {
        let value = match result {
            Ok(addresses) if addresses.len() <= MAX_ADDRESSES => {
                Outcome::Addresses(addresses.clone())
            }
            Ok(_) => Outcome::Unshared,
            Err(error) => {
                Outcome::Failed(error.kind(), error.to_string().chars().take(512).collect())
            }
        };
        *self
            .flight
            .outcome
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(value);
    }
}

impl Drop for Publication<'_> {
    fn drop(&mut self) {
        self.flights
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.key);
        let mut state = self
            .flight
            .outcome
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if state.is_none() {
            *state = Some(Outcome::Failed(
                std::io::ErrorKind::Interrupted,
                "DNS lookup abandoned".into(),
            ));
        }
        drop(state);
        self.flight.ready.notify_all();
    }
}

pub(super) struct RecentResolver<R> {
    inner: R,
    entries: Mutex<HashMap<(String, u16), Entry>>,
    flights: Flights,
    coalescing: bool,
}

impl<R: Resolver> RecentResolver<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            entries: Mutex::default(),
            flights: Mutex::default(),
            coalescing: true,
        }
    }

    pub fn with_coalescing(mut self, enabled: bool) -> Self {
        self.coalescing = enabled;
        self
    }

    fn flight(&self, key: &LookupKey) -> Option<(Arc<Flight>, bool)> {
        if !self.coalescing {
            return None;
        }
        let mut flights = self.flights.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(flight) = flights.get(key) {
            return Some((flight.clone(), false));
        }
        if flights.len() >= MAX_ENTRIES {
            return None;
        }
        let flight = Arc::new(Flight {
            outcome: Mutex::new(None),
            ready: Condvar::new(),
        });
        flights.insert(key.clone(), flight.clone());
        Some((flight, true))
    }

    fn resolve_at(&self, host: &str, port: u16, now: impl Fn() -> Instant) -> Resolution {
        if host.len() > 253 {
            return self.inner.resolve(host, port);
        }
        let key = (host.to_owned(), port);
        if let Some(addresses) = self.cached(&key, now()) {
            return Ok(addresses);
        }
        let Some((flight, leader)) = self.flight(&key) else {
            return self.resolve_cached_at(host, port, now);
        };
        if !leader {
            return flight
                .wait()
                .unwrap_or_else(|| self.resolve_cached_at(host, port, now));
        }
        let publication = Publication {
            flight,
            flights: &self.flights,
            key,
        };
        let result = self.resolve_cached_at(host, port, now);
        publication.publish(&result);
        result
    }

    fn cached(&self, key: &LookupKey, started: Instant) -> Option<Vec<SocketAddr>> {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries.retain(|_, entry| started.saturating_duration_since(entry.started) < LIFETIME);
        entries.get(key).map(|entry| entry.addresses.clone())
    }

    fn resolve_cached_at(
        &self,
        host: &str,
        port: u16,
        now: impl Fn() -> Instant,
    ) -> std::io::Result<Vec<SocketAddr>> {
        if host.len() > 253 {
            return self.inner.resolve(host, port);
        }
        let key = (host.to_owned(), port);
        let started = now();
        if let Some(addresses) = self.cached(&key, started) {
            return Ok(addresses);
        }
        // Every reuse is still judged by the destination policy before connecting.
        let addresses = self.inner.resolve(host, port)?;
        if !addresses.is_empty()
            && addresses.len() <= MAX_ADDRESSES
            && addresses.iter().all(|addr| addr.port() == port)
            && now().saturating_duration_since(started) < LIFETIME
        {
            let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
            if entries
                .get(&key)
                .is_some_and(|entry| entry.started > started)
            {
                return Ok(addresses);
            }
            if entries.len() >= MAX_ENTRIES
                && !entries.contains_key(&key)
                && let Some(oldest) = entries
                    .iter()
                    .min_by_key(|(_, entry)| entry.started)
                    .map(|(key, _)| key.clone())
            {
                entries.remove(&oldest);
            }
            entries.insert(
                key,
                Entry {
                    started,
                    addresses: addresses.clone(),
                },
            );
        }
        Ok(addresses)
    }
}

impl<R: Resolver> Resolver for RecentResolver<R> {
    fn resolve(&self, host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
        self.resolve_at(host, port, Instant::now)
    }
}

#[cfg(test)]
mod concurrent_tests {
    use super::*;
    use std::sync::Barrier;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Blocked {
        calls: AtomicUsize,
        release: Mutex<bool>,
        ready: Condvar,
        fail: bool,
    }
    impl Blocked {
        fn unblock(&self) {
            *self.release.lock().unwrap() = true;
            self.ready.notify_all();
        }
    }
    impl Resolver for Blocked {
        fn resolve(&self, _: &str, port: u16) -> Resolution {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let released = self.release.lock().unwrap();
            drop(
                self.ready
                    .wait_while(released, |released| !*released)
                    .unwrap(),
            );
            if self.fail {
                Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "controlled DNS refusal",
                ))
            } else {
                Ok(vec![SocketAddr::from(([93, 184, 215, 14], port))])
            }
        }
    }
    fn resolver(fail: bool) -> RecentResolver<Blocked> {
        RecentResolver::new(Blocked {
            calls: AtomicUsize::new(0),
            release: Mutex::new(false),
            ready: Condvar::new(),
            fail,
        })
    }
    fn wait_until(mut predicate: impl FnMut() -> bool) -> bool {
        let deadline = Instant::now() + Duration::from_secs(2);
        while !predicate() {
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::yield_now();
        }
        true
    }

    #[test]
    fn concurrent_dns_shares_pending_success_and_error_without_retaining_failures() {
        for fail in [false, true] {
            let resolver = resolver(fail);
            let start = Barrier::new(7);
            std::thread::scope(|scope| {
                let workers: Vec<_> = (0..6)
                    .map(|_| {
                        scope.spawn(|| {
                            start.wait();
                            resolver.resolve("same.example", 443)
                        })
                    })
                    .collect();
                start.wait();
                let attached = wait_until(|| {
                    resolver
                        .flights
                        .lock()
                        .unwrap()
                        .values()
                        .any(|flight| Arc::strong_count(flight) == 7)
                        || resolver.inner.calls.load(Ordering::SeqCst) == 6
                });
                resolver.inner.unblock();
                let results: Vec<_> = workers
                    .into_iter()
                    .map(|thread| thread.join().unwrap())
                    .collect();
                assert!(attached, "workers did not attach before release");
                assert_eq!(
                    resolver.inner.calls.load(Ordering::SeqCst),
                    1,
                    "duplicate pending DNS work"
                );
                for result in results {
                    if fail {
                        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::NotFound);
                    } else {
                        assert_eq!(
                            result.unwrap(),
                            vec![SocketAddr::from(([93, 184, 215, 14], 443))]
                        );
                    }
                }
            });
            assert!(resolver.flights.lock().unwrap().is_empty());
            if fail {
                assert!(resolver.entries.lock().unwrap().is_empty());
                assert!(resolver.resolve("same.example", 443).is_err());
                assert_eq!(
                    resolver.inner.calls.load(Ordering::SeqCst),
                    2,
                    "failure was cached"
                );
            }
        }
    }

    #[test]
    fn concurrent_dns_keeps_other_hosts_ports_and_guards_independent() {
        let first = resolver(false);
        let other = resolver(false);
        std::thread::scope(|scope| {
            let one = scope.spawn(|| first.resolve("a.example", 443));
            let two = scope.spawn(|| first.resolve("b.example", 443));
            let three = scope.spawn(|| first.resolve("a.example", 8443));
            let four = scope.spawn(|| other.resolve("a.example", 443));
            let concurrent = wait_until(|| {
                first.inner.calls.load(Ordering::SeqCst) == 3
                    && other.inner.calls.load(Ordering::SeqCst) == 1
            });
            first.inner.unblock();
            other.inner.unblock();
            let results = [
                one.join().unwrap(),
                two.join().unwrap(),
                three.join().unwrap(),
                four.join().unwrap(),
            ];
            assert!(concurrent, "unrelated DNS lookups serialized");
            assert_eq!(results[2].as_ref().unwrap()[0].port(), 8443);
            assert!(results.iter().all(Result::is_ok));
        });
    }

    #[test]
    fn concurrent_dns_retirement_wakes_followers_after_leader_unwind() {
        let resolver = resolver(false);
        let key = ("abandoned.example".into(), 443);
        let (flight, leader) = resolver.flight(&key).unwrap();
        assert!(leader);
        let follower = flight.clone();
        let result = std::thread::scope(|scope| {
            let waiter = scope.spawn(move || follower.wait().unwrap());
            let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _publication = Publication {
                    flight,
                    flights: &resolver.flights,
                    key,
                };
                panic!("controlled resolver unwind");
            }));
            assert!(caught.is_err());
            waiter.join().unwrap()
        });
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::Interrupted);
        assert!(resolver.flights.lock().unwrap().is_empty());
        resolver.inner.unblock();
        assert!(resolver.resolve("abandoned.example", 443).is_ok());
    }
}
