//! The authenticated loopback proxy that enforces [`DestinationPolicy`] on every
//! connection a WebView makes.
//!
//! Each destination is resolved, screened and pinned before connecting, so a
//! name that resolves to a forbidden address is refused at connect time.
//!

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TryRecvError, TrySendError, sync_channel};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::web::destination::{DestinationDenial, DestinationPolicy};
use crate::web::policy::PolicyUrl;
use enzui_security::loopback_proxy::{LoopbackProxyCapability, PROXY_AUTHENTICATE_VALUE};

mod connect_race;
mod datagrams;
mod recent_resolver;
mod seam_budget;
mod system_resolver;
mod tunnels;
mod upstream;
use tunnels::{TunnelRelay, TunnelSender};
pub use upstream::UpstreamProxy;

/// How long the guard waits for a client's request head before giving up.
const REQUEST_HEAD_TIMEOUT: Duration = Duration::from_secs(30);
/// Ceiling on a proxy request head, so a client cannot make the guard buffer
/// without bound before a decision.
const MAX_REQUEST_HEAD: usize = 16 * 1024;
/// Ceiling on the upstream response head inspected for redirect metadata.
/// Oversized heads fail closed rather than letting a hidden `Location` pass.
const MAX_RESPONSE_HEAD: usize = 64 * 1024;
/// Ceiling on interim (1xx) responses relayed before the final response head.
/// A server that streams unbounded `100 Continue`/`103 Early Hints` heads must
/// not make the screen loop or buffer forever before it can judge the final
/// response; past the ceiling the exchange fails closed.
const MAX_INTERIM_RESPONSES: usize = 32;
/// DNS and connect deadlines. Each host seam call runs on its own bounded
/// helper thread, and calls are not serialized, so a callback may drive a
/// second authenticated request through the same guard concurrently rather
/// than deadlocking against the first. A genuine panic or timeout poisons the
/// seam so no later request calls it again (see [`Shared::call_seam_bounded`]).
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(10);
const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const SEAM_CALL_TIMEOUT: Duration = Duration::from_secs(11);
/// Finite idle deadline for both directions of an established tunnel.
const RELAY_IO_TIMEOUT: Duration = Duration::from_secs(30);
/// Fixed worker count and bounded admission queue. A hostile page cannot turn
/// requests into an unbounded number of native threads or open sockets.
const CONNECTION_WORKERS: usize = 8;
const PENDING_CONNECTIONS: usize = 32;
// Polling bounds shutdown when the auxiliary self-connect cannot allocate a socket.
const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// How many guard decisions are retained before the oldest is evicted.
///
/// This is the single bound shared with the native policy observation ring
/// (`ffi::policy::BoundedObservations::DEFAULT_CAPACITY`), which is
/// defined as this constant. One hostile page drives both logs, so two
/// different bounds would only be a way for them to drift apart. It lives here
/// rather than beside the ring because this module compiles with the `wpe`
/// feature off.
pub const EVENT_LOG_CAPACITY: usize = 256;

/// Resolution seam. Production uses [`SystemResolver`]; a gate substitutes an
/// answer it controls so DNS-dependent attacks (a public name resolving
/// private, and rebinding between two lookups) can be exercised without a
/// network.
///
/// The seam is deliberately *only* the lookup. Classification and pinning stay
/// in [`DestinationPolicy`], so a test cannot accidentally replace the rule it
/// is testing.
pub trait Resolver: Send + Sync {
    /// Resolve `host`/`port` to candidate addresses.
    ///
    /// # Errors
    ///
    /// Whatever the resolver reports; the guard treats any error as a refusal.
    fn resolve(&self, host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>>;
}

/// The real resolver: the platform's DNS/`getaddrinfo`.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemResolver;

impl Resolver for SystemResolver {
    fn resolve(&self, host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
        system_resolver::resolve(host, port)
    }
}

/// Connection seam, so a gate can observe the exact address the guard decided
/// to connect to without the test needing a public host to be reachable.
pub trait Connector: Send + Sync {
    /// Connect to `addr` within `timeout`.
    ///
    /// # Errors
    ///
    /// The underlying connect error.
    fn connect(&self, addr: SocketAddr, timeout: Duration) -> std::io::Result<TcpStream>;

    /// Open a connected UDP socket to an already approved address.
    ///
    /// The default refuses UDP. Custom connectors must explicitly provide it.
    ///
    /// # Errors
    /// Returns a socket error or `Unsupported` when UDP is unavailable.
    fn connect_datagram(&self, _addr: SocketAddr) -> std::io::Result<std::net::UdpSocket> {
        Err(std::io::ErrorKind::Unsupported.into())
    }

    /// Connect only to the already validated candidates within one total deadline.
    /// The default retries sequentially; the system connector races candidates.
    /// Call `attempt` immediately before each connection attempt for accounting.
    /// Returns the successful stream and its candidate address.
    ///
    /// # Errors
    /// Returns the final connection error or a deadline error.
    fn connect_candidates(
        &self,
        candidates: &[SocketAddr],
        timeout: Duration,
        attempt: &mut dyn FnMut(),
    ) -> std::io::Result<(TcpStream, SocketAddr)> {
        let started = std::time::Instant::now();
        let mut error = std::io::Error::from(std::io::ErrorKind::NotFound);
        for &address in candidates {
            let remaining = timeout.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                return Err(std::io::ErrorKind::TimedOut.into());
            }
            attempt();
            match self.connect(address, remaining) {
                Ok(stream) => return Ok((stream, address)),
                Err(failure) => error = failure,
            }
        }
        Err(error)
    }
}

/// System TCP connections with deadlines and connected UDP sockets.
#[derive(Debug, Clone, Copy, Default)]
pub struct TcpConnector;

impl Connector for TcpConnector {
    fn connect_datagram(&self, addr: SocketAddr) -> std::io::Result<std::net::UdpSocket> {
        datagrams::connect(addr)
    }
    fn connect(&self, addr: SocketAddr, timeout: Duration) -> std::io::Result<TcpStream> {
        TcpStream::connect_timeout(&addr, timeout)
    }

    fn connect_candidates(
        &self,
        candidates: &[SocketAddr],
        timeout: Duration,
        attempt: &mut dyn FnMut(),
    ) -> std::io::Result<(TcpStream, SocketAddr)> {
        connect_race::connect(candidates, timeout, attempt)
    }
}

trait ListenerWake: Send + Sync {
    fn wake(&self, addr: SocketAddr, timeout: Duration) -> std::io::Result<()>;
}

#[derive(Debug, Clone, Copy, Default)]
struct TcpListenerWake;

impl ListenerWake for TcpListenerWake {
    fn wake(&self, addr: SocketAddr, timeout: Duration) -> std::io::Result<()> {
        let stream = TcpStream::connect_timeout(&addr, timeout)?;
        drop(stream);
        Ok(())
    }
}

/// Which socket a read/write deadline is being configured on.
///
/// The relay bounds both sides so neither a blocking `read` nor a blocking
/// `write` can wedge a worker forever. A gate that injects a configuration
/// failure names the endpoint it broke, and the typed failure carries it, so a
/// test can prove *each* side fails closed independently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeoutEndpoint {
    /// The client (WebKit-facing) socket.
    Client,
    /// The upstream (origin-facing) socket.
    Upstream,
}

/// Seam for the socket read/write deadlines that make the relay's cancellation
/// bounded. Production uses [`SystemTimeouts`]; a gate substitutes a
/// configurator that fails a chosen endpoint to prove the guard refuses to
/// relay over a socket it could not bound, rather than ignoring the error and
/// blocking a relay thread forever.
pub trait TimeoutConfigurator: Send + Sync {
    /// Set the read deadline on `socket`.
    ///
    /// # Errors
    ///
    /// Whatever the platform reports; the guard treats any error as a hard
    /// refusal to relay over that socket.
    fn set_read_timeout(
        &self,
        endpoint: TimeoutEndpoint,
        socket: &TcpStream,
        timeout: Duration,
    ) -> std::io::Result<()>;

    /// Set the write deadline on `socket`.
    ///
    /// # Errors
    ///
    /// Whatever the platform reports; treated as a hard refusal to relay.
    fn set_write_timeout(
        &self,
        endpoint: TimeoutEndpoint,
        socket: &TcpStream,
        timeout: Duration,
    ) -> std::io::Result<()>;
}

/// The real configurator: the platform's `set_read_timeout`/`set_write_timeout`.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemTimeouts;

impl TimeoutConfigurator for SystemTimeouts {
    fn set_read_timeout(
        &self,
        _endpoint: TimeoutEndpoint,
        socket: &TcpStream,
        timeout: Duration,
    ) -> std::io::Result<()> {
        socket.set_read_timeout(Some(timeout))
    }

    fn set_write_timeout(
        &self,
        _endpoint: TimeoutEndpoint,
        socket: &TcpStream,
        timeout: Duration,
    ) -> std::io::Result<()> {
        socket.set_write_timeout(Some(timeout))
    }
}

/// One decision the guard made at the network boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardEvent {
    /// The request was screened, resolved, pinned, and permitted.
    Allowed {
        /// The requested target as the client spelled it. A [`PolicyUrl`], so
        /// its `Debug`/`Display` are redacted: a proxied request line
        /// is exactly where a signed-URL token or a `user:pass@` credential
        /// appears, and this event is what a diagnostic prints.
        target: PolicyUrl,
        /// The single address the guard pinned and connected to.
        addr: SocketAddr,
        /// Time in authenticated policy setup, including DNS and pinned connect.
        setup: SetupTiming,
    },
    /// A request was refused before its upstream socket existed, or a wire
    /// redirect was refused before its target request existed.
    Denied {
        /// The refused target, redacted for display - see [`PolicyUrl`].
        target: PolicyUrl,
        /// Which rule refused it. Classification only; carries no URL.
        cause: DestinationDenial,
    },
    /// The client did not speak proxy HTTP; refused without interpretation.
    Malformed {
        /// The first line, redacted - an unparsed request line may still
        /// contain a credential.
        head: PolicyUrl,
    },
    /// A host-supplied resolver or connector panicked. The panic was
    /// caught, the request denied without any upstream socket, and the seam
    /// poisoned: every later request is denied without calling it again.
    /// No panic payload is retained (it may contain secrets), matching the
    /// policy responder's panic boundary.
    SeamPanicked {
        /// The target that was being judged, redacted.
        target: PolicyUrl,
    },
    /// A resolver/connector exceeded its finite deadline or disconnected. The
    /// seam is poisoned and later requests fail closed without invoking it.
    SeamUnavailable {
        /// The target that was being judged, redacted.
        target: PolicyUrl,
    },
    /// A read/write deadline could not be configured on one of the relay's
    /// sockets, so the relay could block without bounded cancellation. The
    /// guard fails closed: no [`GuardEvent::Allowed`] is published, both
    /// endpoints are closed, and no byte is relayed.
    RelayUnbounded {
        /// The target being set up when the deadline could not be set,
        /// redacted. Empty when the failure happened before the request line
        /// was parsed.
        target: PolicyUrl,
        /// Which socket's deadline could not be configured.
        endpoint: TimeoutEndpoint,
    },
}

/// Wall-clock costs of an allowed destination's authenticated connection setup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetupTiming {
    /// Time from TCP accept until a bounded connection worker starts the request.
    pub queue: Duration,
    /// Worker time through socket deadlines, header input, authentication and parsing.
    pub header: Duration,
    /// Resolver wall time, including bounded invocation overhead.
    pub dns: Duration,
    /// Pinned socket setup wall time, including bounded invocation overhead.
    pub connect: Duration,
    /// From authenticated-head parsing through endpoint configuration.
    /// Excludes reading/authenticating that head and any tunneled TLS handshake.
    pub total: Duration,
}

impl GuardEvent {
    /// The redacted target, for a gate that wants to find its request.
    ///
    /// Deliberately returns the redacted rendering rather than the raw
    /// URL: a caller that needs the raw string has the request itself.
    #[must_use]
    pub fn target(&self) -> String {
        match self {
            GuardEvent::Allowed { target, .. }
            | GuardEvent::Denied { target, .. }
            | GuardEvent::SeamPanicked { target }
            | GuardEvent::SeamUnavailable { target }
            | GuardEvent::RelayUnbounded { target, .. }
            | GuardEvent::Malformed { head: target } => target.redacted(),
        }
    }

    /// Whether this event permitted the request.
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        matches!(self, GuardEvent::Allowed { .. })
    }
}

#[derive(Debug, Default)]
struct EventLog {
    ring: std::collections::VecDeque<GuardEvent>,
    dropped: u64,
}

impl EventLog {
    const CAPACITY: usize = EVENT_LOG_CAPACITY;

    fn push(&mut self, event: GuardEvent) {
        if self.ring.len() == Self::CAPACITY {
            self.ring.pop_front();
            self.dropped += 1;
        }
        self.ring.push_back(event);
    }
}

#[derive(Debug, Clone, Copy)]
struct SeamDeadlines {
    resolve: Duration,
    connect: Duration,
}

impl SeamDeadlines {
    fn production() -> Self {
        Self {
            resolve: RESOLVE_TIMEOUT,
            connect: SEAM_CALL_TIMEOUT,
        }
    }
}

#[derive(Debug, Default)]
struct SeamControl {
    // A timed-out callback can outlive its waiter; this is not a running-thread count.
    live: usize,
    peak: usize,
    poison: Option<SeamFailure>,
}

struct Shared {
    capability: LoopbackProxyCapability,
    policy: DestinationPolicy,
    local_origins: crate::local_origins::LocalOriginAllowlist,
    resolver: Arc<dyn Resolver>,
    connector: Arc<dyn Connector>,
    timeouts: Arc<dyn TimeoutConfigurator>,
    events: Mutex<EventLog>,
    upstream_connects: AtomicU64,
    stop: AtomicBool,
    // Admission and completion share this lock; a success after poison is discarded.
    seam: Mutex<SeamControl>,
    helper_budget: Arc<seam_budget::Budget>,
    resolve_timeout: Duration,
    seam_call_timeout: Duration,
    next_connection: AtomicU64,
    active_sockets: Mutex<HashMap<u64, Vec<TcpStream>>>,
    #[cfg(test)]
    accept_started: AtomicBool,
    #[cfg(test)]
    accept_idle_waiting: AtomicBool,
    #[cfg(test)]
    accept_readiness: AtomicU64,
    #[cfg(test)]
    accepted_connections: AtomicU64,
    #[cfg(test)]
    header_reads: AtomicU64,
    #[cfg(test)]
    relay_wakes: AtomicU64,
    #[cfg(test)]
    seam_parked: std::sync::atomic::AtomicUsize,
}

impl Shared {
    fn record(&self, event: GuardEvent) {
        // Recovering this plain-data log must preserve recording after an unrelated panic.
        let mut events = self.events.lock().unwrap_or_else(|e| e.into_inner());
        events.push(event);
    }

    // Host callbacks run lock-free on bounded helpers, allowing nested authenticated requests.
    // The first panic, timeout or spawn failure poisons admission and completion; even
    // a successful connection is discarded if another call installed poison first.
    fn call_seam_bounded<T: Send + 'static>(
        &self,
        timeout: Duration,
        call: impl FnOnce() -> T + Send + 'static,
    ) -> Result<T, SeamFailure> {
        {
            let mut control = self.seam.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(cause) = control.poison {
                return Err(cause);
            }
            if self.stop.load(Ordering::SeqCst) {
                return Err(SeamFailure::Unavailable);
            }
            control.live += 1;
            control.peak = control.peak.max(control.live);
        }
        let Some(permit) = self.helper_budget.acquire() else {
            return Err(self.finish_seam_failure(SeamFailure::Unavailable));
        };
        let (send, receive) = sync_channel(1);
        let wake = std::thread::current();
        if std::thread::Builder::new()
            .name("enzui-destination-seam".into())
            .spawn(move || {
                // The permit covers the callback even after its receiver is canceled.
                let result = crate::panic_boundary::catch_silent(call);
                drop(permit);
                let _ = send.send(result);
                wake.unpark();
            })
            .is_err()
        {
            return Err(self.finish_seam_failure(SeamFailure::Unavailable));
        }
        let started = std::time::Instant::now();
        loop {
            if self.stop.load(Ordering::SeqCst) {
                let mut control = self.seam.lock().unwrap_or_else(|e| e.into_inner());
                control.live -= 1;
                return Err(control.poison.unwrap_or(SeamFailure::Unavailable));
            }
            let remaining = timeout.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                return Err(self.finish_seam_failure(SeamFailure::Unavailable));
            }
            match receive.try_recv() {
                Ok(Ok(value)) => return self.finish_seam_success(value),
                Ok(Err(_payload)) => {
                    return Err(self.finish_seam_failure(SeamFailure::Panicked));
                }
                Err(TryRecvError::Disconnected) => {
                    return Err(self.finish_seam_failure(SeamFailure::Unavailable));
                }
                Err(TryRecvError::Empty) => {}
            }
            #[cfg(test)]
            self.seam_parked.fetch_add(1, Ordering::SeqCst);
            // unpark retains a token when completion or shutdown races this park.
            std::thread::park_timeout(remaining);
            #[cfg(test)]
            self.seam_parked.fetch_sub(1, Ordering::SeqCst);
        }
    }

    /// Complete a call whose callback returned a value: account it out and
    /// accept the value only if no poison linearized before this completion.
    fn finish_seam_success<T>(&self, value: T) -> Result<T, SeamFailure> {
        let mut control = self.seam.lock().unwrap_or_else(|e| e.into_inner());
        control.live -= 1;
        match control.poison {
            Some(cause) => Err(cause),
            None => Ok(value),
        }
    }

    /// Complete a call whose callback panicked, timed out, or never spawned:
    /// account it out and install `own` as the poison cause unless a truthful
    /// cause is already present, then return whichever cause now stands.
    fn finish_seam_failure(&self, own: SeamFailure) -> SeamFailure {
        let mut control = self.seam.lock().unwrap_or_else(|e| e.into_inner());
        control.live -= 1;
        *control.poison.get_or_insert(own)
    }

    fn register_connection(self: &Arc<Self>, socket: &TcpStream) -> Option<ConnectionLease> {
        let id = self.next_connection.fetch_add(1, Ordering::Relaxed);
        let socket = socket.try_clone().ok()?;
        self.active_sockets
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id, vec![socket]);
        Some(ConnectionLease {
            id,
            shared: self.clone(),
        })
    }

    fn register_upstream(&self, id: u64, socket: &TcpStream) {
        if let Ok(clone) = socket.try_clone()
            && let Some(sockets) = self
                .active_sockets
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get_mut(&id)
        {
            sockets.push(clone);
        }
    }

    fn shutdown_connections(&self) {
        let sockets = self
            .active_sockets
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        for socket in sockets.values().flatten() {
            let _ = socket.shutdown(Shutdown::Both);
        }
    }
}

// Panics, admission failures and deadlines poison the seam; shutdown only cancels its wait.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum SeamFailure {
    Panicked,
    Unavailable,
}

struct ConnectionLease {
    id: u64,
    shared: Arc<Shared>,
}

impl Drop for ConnectionLease {
    fn drop(&mut self) {
        self.shared
            .active_sockets
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.id);
    }
}

/// A running loopback proxy that enforces a [`DestinationPolicy`].
///
/// Constructed with a policy and started immediately: there is no "install it
/// later" step a caller can skip, and dropping it stops the listener.
pub struct DestinationGuard {
    addr: SocketAddr,
    shared: Arc<Shared>,
    listener_wake: Arc<dyn ListenerWake>,
    accept_thread: Option<std::thread::JoinHandle<()>>,
    workers: Vec<std::thread::JoinHandle<()>>,
    tunnels: TunnelRelay,
}

impl std::fmt::Debug for DestinationGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DestinationGuard")
            .field("addr", &self.addr)
            .field("policy", &self.shared.policy)
            .finish_non_exhaustive()
    }
}

impl DestinationGuard {
    /// Start a guard for `policy` on an ephemeral loopback port.
    /// Successful system-DNS answers may be reused for one second within this
    /// guard, with at most 64 host/port entries of up to 32 addresses each.
    /// Every request still screens and pins the full answer before connecting.
    /// Concurrent misses share the lookup for the same host/port within this guard.
    /// `ENZUI_WEBKIT_DNS_CACHE=0` disables reuse; `ENZUI_WEBKIT_DNS_COALESCE=0`
    /// disables concurrent sharing while retaining the cache, for diagnostics.
    ///
    /// # Errors
    ///
    /// Capability creation, listener setup, and thread startup failures are
    /// returned. A caller must then refuse to create the WebView rather than
    /// run unguarded.
    pub fn start(policy: DestinationPolicy) -> std::io::Result<DestinationGuard> {
        Self::start_routed(policy, None)
    }

    /// [`DestinationGuard::start`], opening every approved stream through
    /// `upstream` when one is given. Screening, resolution and pinning are
    /// unchanged; the upstream proxy receives only the pinned numeric address.
    /// There is no direct fallback, and UDP associations are refused.
    ///
    /// # Errors
    ///
    /// As [`DestinationGuard::start`].
    pub fn start_routed(
        policy: DestinationPolicy,
        upstream: Option<UpstreamProxy>,
    ) -> std::io::Result<DestinationGuard> {
        let resolver: Arc<dyn Resolver> =
            if std::env::var_os("ENZUI_WEBKIT_DNS_CACHE").is_some_and(|value| value == "0") {
                Arc::new(SystemResolver)
            } else {
                Arc::new(
                    recent_resolver::RecentResolver::new(SystemResolver).with_coalescing(
                        !std::env::var_os("ENZUI_WEBKIT_DNS_COALESCE")
                            .is_some_and(|value| value == "0"),
                    ),
                )
            };
        let connector: Arc<dyn Connector> = match upstream {
            Some(proxy) => Arc::new(upstream::UpstreamConnector { proxy }),
            None => Arc::new(TcpConnector),
        };
        Self::start_with(policy, resolver, connector)
    }

    /// [`DestinationGuard::start`] with uncached, caller-owned resolution/connection seams.
    ///
    /// # Errors
    ///
    /// Capability creation, listener setup, and thread startup failures are
    /// returned.
    pub fn start_with(
        policy: DestinationPolicy,
        resolver: Arc<dyn Resolver>,
        connector: Arc<dyn Connector>,
    ) -> std::io::Result<DestinationGuard> {
        Self::start_with_seams(policy, resolver, connector, Arc::new(SystemTimeouts))
    }

    fn start_with_seams(
        policy: DestinationPolicy,
        resolver: Arc<dyn Resolver>,
        connector: Arc<dyn Connector>,
        timeouts: Arc<dyn TimeoutConfigurator>,
    ) -> std::io::Result<DestinationGuard> {
        Self::start_with_runtime_seams(
            policy,
            resolver,
            connector,
            timeouts,
            Arc::new(TcpListenerWake),
            SeamDeadlines::production(),
            seam_budget::global(),
        )
    }

    fn start_with_runtime_seams(
        policy: DestinationPolicy,
        resolver: Arc<dyn Resolver>,
        connector: Arc<dyn Connector>,
        timeouts: Arc<dyn TimeoutConfigurator>,
        listener_wake: Arc<dyn ListenerWake>,
        deadlines: SeamDeadlines,
        helper_budget: Arc<seam_budget::Budget>,
    ) -> std::io::Result<DestinationGuard> {
        // Mint before binding: a listener must never exist without the
        // capability that protects it. Entropy failure is a hard startup
        // refusal, never a weaker unauthenticated mode.
        let capability = LoopbackProxyCapability::mint().map_err(|error| {
            std::io::Error::other(format!("could not mint loopback proxy capability: {error}"))
        })?;
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let addr = listener.local_addr()?;
        listener.set_nonblocking(true)?;
        let shared = Arc::new(Shared {
            capability,
            policy,
            local_origins: crate::local_origins::LocalOriginAllowlist::default(),
            resolver,
            connector,
            timeouts,
            events: Mutex::new(EventLog::default()),
            upstream_connects: AtomicU64::new(0),
            stop: AtomicBool::new(false),
            seam: Mutex::new(SeamControl::default()),
            helper_budget,
            resolve_timeout: deadlines.resolve,
            seam_call_timeout: deadlines.connect,
            next_connection: AtomicU64::new(1),
            active_sockets: Mutex::new(HashMap::new()),
            #[cfg(test)]
            accept_started: AtomicBool::new(false),
            #[cfg(test)]
            accept_idle_waiting: AtomicBool::new(false),
            #[cfg(test)]
            accept_readiness: AtomicU64::new(0),
            #[cfg(test)]
            accepted_connections: AtomicU64::new(0),
            #[cfg(test)]
            header_reads: AtomicU64::new(0),
            #[cfg(test)]
            relay_wakes: AtomicU64::new(0),
            #[cfg(test)]
            seam_parked: std::sync::atomic::AtomicUsize::new(0),
        });
        let (sender, receiver) = sync_channel::<AcceptedConnection>(PENDING_CONNECTIONS);
        let receiver = Arc::new(Mutex::new(receiver));
        let mut tunnels = TunnelRelay::start(shared.clone())?;
        let mut workers = Vec::with_capacity(CONNECTION_WORKERS);
        for index in 0..CONNECTION_WORKERS {
            let worker = shared.clone();
            let queue = receiver.clone();
            let relay = tunnels.sender.clone();
            match std::thread::Builder::new()
                .name(format!("enzui-destination-worker-{index}"))
                .spawn(move || worker_loop(&queue, &worker, &relay))
            {
                Ok(handle) => workers.push(handle),
                Err(error) => {
                    shared.stop.store(true, Ordering::SeqCst);
                    drop(sender);
                    for handle in workers {
                        let _ = handle.join();
                    }
                    tunnels.join();
                    return Err(error);
                }
            }
        }
        let accept_shared = shared.clone();
        let accept_thread = match std::thread::Builder::new()
            .name("enzui-destination-guard".into())
            .spawn(move || {
                accept_loop(&listener, &accept_shared, sender);
            }) {
            Ok(handle) => handle,
            Err(error) => {
                shared.stop.store(true, Ordering::SeqCst);
                for handle in workers {
                    let _ = handle.join();
                }
                tunnels.join();
                return Err(error);
            }
        };
        Ok(DestinationGuard {
            addr,
            shared,
            listener_wake,
            accept_thread: Some(accept_thread),
            workers,
            tunnels,
        })
    }

    /// The loopback address WebKit must be pointed at.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The proxy URI for WebKit's `WebKitNetworkProxySettings`.
    #[must_use]
    pub fn proxy_uri(&self) -> String {
        self.shared.capability.display_uri(self.addr)
    }

    /// Borrow the capability only for WebKit's exact proxy-auth challenge.
    #[cfg(feature = "wpe")]
    pub(crate) fn proxy_credentials(&self) -> (&'static str, &str) {
        (
            self.shared.capability.username(),
            self.shared.capability.password(),
        )
    }

    /// The policy this guard enforces.
    #[must_use]
    pub fn policy(&self) -> DestinationPolicy {
        self.shared.policy
    }

    /// Shared authorization for exact local destination origins in this network session.
    ///
    /// The table is empty by default. Grants affect future connection setup;
    /// established tunnels remain connected. This is a destination capability,
    /// not an initiator-origin permission: CONNECT carries no initiator identity.
    #[must_use]
    pub fn local_origins(&self) -> crate::local_origins::LocalOriginAllowlist {
        self.shared.local_origins.clone()
    }

    /// Every retained decision, oldest first.
    ///
    /// The log is bounded at [`EVENT_LOG_CAPACITY`]; ask
    /// [`DestinationGuard::dropped_events`] how many older entries were
    /// evicted rather than assuming this is the whole history (the same bounded-log rule
    /// for the observation ring, applied to the guard's own log).
    #[must_use]
    pub fn events(&self) -> Vec<GuardEvent> {
        let events = self
            .shared
            .events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        events.ring.iter().cloned().collect()
    }

    /// How many decisions the bounded log evicted since the guard started.
    #[must_use]
    pub fn dropped_events(&self) -> u64 {
        self.shared
            .events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .dropped
    }

    /// Whether a host-supplied resolver/connector panicked and is poisoned.
    /// Once true every request is denied without calling the seam again.
    #[must_use]
    pub fn seam_poisoned(&self) -> bool {
        self.shared
            .seam
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .poison
            .is_some()
    }

    /// How many upstream connections the guard has *attempted*.
    ///
    /// This is the "no network side effect before a request-target denial"
    /// observable: it is incremented immediately before the connect call and
    /// nowhere else, so a refusal that leaked a socket would move it. A
    /// wire-redirect denial includes the already-approved redirector connect,
    /// but no connect to the refused target.
    #[must_use]
    pub fn upstream_connects(&self) -> u64 {
        self.shared.upstream_connects.load(Ordering::SeqCst)
    }
}

impl Drop for DestinationGuard {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        let _ = self
            .listener_wake
            .wake(self.addr, Duration::from_millis(500));
        if let Some(handle) = self.accept_thread.take() {
            handle.thread().unpark();
            let _ = handle.join();
        }
        self.shared.shutdown_connections();
        for handle in &self.workers {
            handle.thread().unpark();
        }
        for handle in self.workers.drain(..) {
            let _ = handle.join();
        }
        self.tunnels.join();
    }
}

struct AcceptedConnection {
    stream: TcpStream,
    accepted: std::time::Instant,
}

fn accept_loop(
    listener: &TcpListener,
    shared: &Arc<Shared>,
    sender: SyncSender<AcceptedConnection>,
) {
    #[cfg(test)]
    shared.accept_started.store(true, Ordering::SeqCst);
    while !shared.stop.load(Ordering::SeqCst) {
        #[cfg(test)]
        shared.accept_idle_waiting.store(true, Ordering::SeqCst);
        match listener.accept() {
            Ok((stream, _peer)) => {
                let accepted = std::time::Instant::now();
                #[cfg(test)]
                shared.accept_idle_waiting.store(false, Ordering::SeqCst);
                if shared.stop.load(Ordering::SeqCst) {
                    break;
                }
                match sender.try_send(AcceptedConnection { stream, accepted }) {
                    Ok(()) => {
                        #[cfg(test)]
                        shared.accepted_connections.fetch_add(1, Ordering::SeqCst);
                    }
                    Err(
                        TrySendError::Full(mut rejected) | TrySendError::Disconnected(mut rejected),
                    ) => {
                        respond(&mut rejected.stream, 503, "guard-capacity");
                    }
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                use rustix::event::{PollFd, PollFlags, Timespec, poll};
                let mut descriptors = [PollFd::new(listener, PollFlags::IN)];
                let timeout =
                    Timespec::try_from(ACCEPT_POLL_INTERVAL).expect("bounded accept interval");
                match poll(&mut descriptors, Some(&timeout)) {
                    Ok(_) =>
                    {
                        #[cfg(test)]
                        if descriptors[0].revents().contains(PollFlags::IN) {
                            shared.accept_readiness.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                    Err(rustix::io::Errno::INTR) => {}
                    Err(_) => std::thread::park_timeout(ACCEPT_POLL_INTERVAL),
                }
            }
            Err(_) => std::thread::park_timeout(ACCEPT_POLL_INTERVAL),
        }
    }
}

fn worker_loop(
    receiver: &Mutex<Receiver<AcceptedConnection>>,
    shared: &Arc<Shared>,
    tunnels: &TunnelSender,
) {
    loop {
        let stream = receiver.lock().unwrap_or_else(|e| e.into_inner()).recv();
        let Ok(AcceptedConnection { stream, accepted }) = stream else {
            return;
        };
        if shared.stop.load(Ordering::SeqCst) {
            let _ = stream.shutdown(Shutdown::Both);
            continue;
        }
        serve_connection(stream, accepted, shared, tunnels);
    }
}

fn serve_connection(
    mut client: TcpStream,
    accepted: std::time::Instant,
    shared: &Arc<Shared>,
    tunnels: &TunnelSender,
) {
    let worker_started = std::time::Instant::now();
    let queue = worker_started.saturating_duration_since(accepted);
    let Some(lease) = shared.register_connection(&client) else {
        respond(&mut client, 503, "guard-capacity");
        return;
    };
    // Bound the client socket before the first blocking read. If either
    // deadline cannot be set the head read (and any later write) could block
    // forever, so fail closed: no upstream, no success, both bytes untouched.
    // No guard event is published yet: credentials must be validated before
    // any policy observation, including failure diagnostics.
    if shared
        .timeouts
        .set_read_timeout(TimeoutEndpoint::Client, &client, REQUEST_HEAD_TIMEOUT)
        .is_err()
        || shared
            .timeouts
            .set_write_timeout(TimeoutEndpoint::Client, &client, RELAY_IO_TIMEOUT)
            .is_err()
    {
        let _ = client.shutdown(Shutdown::Both);
        return;
    }
    #[cfg(test)]
    shared.header_reads.fetch_add(1, Ordering::SeqCst);
    let Some((head, buffered)) = read_head(&mut client) else {
        respond_proxy_auth_required(&mut client);
        return;
    };
    let authenticated = match shared.capability.authenticate_and_strip(&head) {
        Ok(authenticated) => authenticated,
        Err(_) => {
            respond_proxy_auth_required(&mut client);
            return;
        }
    };
    let Ok(head) = std::str::from_utf8(authenticated.as_bytes()) else {
        respond(&mut client, 400, "malformed-proxy-request");
        return;
    };
    let Some(request) = ProxyRequest::parse(head) else {
        shared.record(GuardEvent::Malformed {
            head: PolicyUrl::new(head.lines().next().unwrap_or_default()),
        });
        respond(&mut client, 400, "malformed-proxy-request");
        return;
    };
    let setup_started = std::time::Instant::now();
    let header = setup_started.saturating_duration_since(worker_started);
    if !request.tunnel && !request.datagram && buffered.len() as u64 > request.content_length {
        shared.record(GuardEvent::Malformed {
            head: PolicyUrl::new(request.url.clone()),
        });
        respond(&mut client, 400, "body-length-mismatch");
        return;
    }

    // Select once so the URL and whole DNS answer use the same origin capability.
    let policy = shared
        .local_origins
        .policy_for_url(shared.policy, &request.url);
    // Stage 1: pre-DNS screen, including an IP-literal host.
    let safe = match policy.screen_request(&request.url) {
        Ok(safe) => safe,
        Err(cause) => {
            shared.record(GuardEvent::Denied {
                target: PolicyUrl::new(request.url.clone()),
                cause,
            });
            respond(&mut client, 403, cause.reason());
            return;
        }
    };
    let port = match policy.effective_port(&safe) {
        Ok(port) => port,
        Err(cause) => {
            shared.record(GuardEvent::Denied {
                target: PolicyUrl::new(request.url.clone()),
                cause,
            });
            respond(&mut client, 403, cause.reason());
            return;
        }
    };
    let authority = request.authority_key();
    let host_header = request
        .host_header
        .as_deref()
        .and_then(|host| authority_key(host, request.default_port));
    if authority.is_none() || host_header.is_none() || authority != host_header {
        shared.record(GuardEvent::Malformed {
            head: PolicyUrl::new(request.url.clone()),
        });
        respond(&mut client, 400, "host-mismatch");
        return;
    }
    if request.datagram {
        let Some((host, port)) = host_header else {
            return;
        };
        let Ok(local) = client.local_addr() else {
            return;
        };
        if port != local.port() || !matches!(host.as_str(), "127.0.0.1" | "localhost") {
            respond(&mut client, 400, "host-mismatch");
            return;
        }
    }

    // Stage 2: resolve ONCE, judge the whole answer, keep the pinned address.
    let resolver = shared.resolver.clone();
    let host = safe.host().to_owned();
    let dns_started = std::time::Instant::now();
    let resolution = match shared.call_seam_bounded(shared.resolve_timeout, move || {
        resolver.resolve(&host, port)
    }) {
        Ok(resolution) => resolution,
        Err(failure) => {
            record_seam_failure(shared, &request.url, failure);
            respond(&mut client, 403, failure.reason());
            return;
        }
    };
    let resolved = match resolution {
        Ok(addrs) => addrs,
        Err(_) => {
            shared.record(GuardEvent::Denied {
                target: PolicyUrl::new(request.url.clone()),
                cause: DestinationDenial::Unresolvable,
            });
            respond(&mut client, 403, DestinationDenial::Unresolvable.reason());
            return;
        }
    };
    let dns = dns_started.elapsed();
    if shared.stop.load(Ordering::SeqCst) {
        return;
    }
    match policy.pin_destination_for_port(&resolved, port) {
        Ok(_) => (),
        Err(cause) => {
            shared.record(GuardEvent::Denied {
                target: PolicyUrl::new(request.url.clone()),
                cause,
            });
            respond(&mut client, 403, cause.reason());
            return;
        }
    };

    // Stage 3: connect to the address that was judged. Nothing re-resolves.
    let candidates = connect_race::candidates(&resolved);
    if request.datagram {
        datagrams::serve(
            client,
            shared,
            tunnels,
            lease,
            datagrams::Setup {
                request: &request,
                buffered: &buffered,
                candidates,
                queue,
                header,
                dns,
                started: setup_started,
            },
        );
        return;
    }
    let checked_candidates = candidates.clone();
    let accounting = Arc::clone(shared);
    let connector = shared.connector.clone();
    let connect_started = std::time::Instant::now();
    let connection = match shared.call_seam_bounded(shared.seam_call_timeout, move || {
        connector.connect_candidates(&candidates, UPSTREAM_CONNECT_TIMEOUT, &mut || {
            accounting.upstream_connects.fetch_add(1, Ordering::SeqCst);
        })
    }) {
        Ok(connection) => connection,
        Err(failure) => {
            record_seam_failure(shared, &request.url, failure);
            respond(&mut client, 403, failure.reason());
            return;
        }
    };
    let Ok((mut upstream, pinned)) = connection else {
        respond(&mut client, 502, "upstream-unreachable");
        return;
    };
    if !checked_candidates.contains(&pinned) {
        respond(&mut client, 502, "unapproved-connect-result");
        return;
    }
    let connect = connect_started.elapsed();
    shared.register_upstream(lease.id, &upstream);
    if shared.stop.load(Ordering::SeqCst) {
        let _ = upstream.shutdown(Shutdown::Both);
        return;
    }
    if client.set_nodelay(true).is_err() || upstream.set_nodelay(true).is_err() {
        return;
    }
    // Cleartext response I/O remains blocking. Refuse unbounded endpoints
    // before publishing success; tunnels additionally enforce an idle deadline.
    if let Err(endpoint) = configure_relay_timeouts(shared, &client, &upstream) {
        shared.record(GuardEvent::RelayUnbounded {
            target: PolicyUrl::new(request.url.clone()),
            endpoint,
        });
        let _ = client.shutdown(Shutdown::Both);
        let _ = upstream.shutdown(Shutdown::Both);
        return;
    }
    shared.record(GuardEvent::Allowed {
        target: PolicyUrl::new(request.url.clone()),
        addr: pinned,
        setup: SetupTiming {
            queue,
            header,
            dns,
            connect,
            total: setup_started.elapsed(),
        },
    });

    if request.tunnel {
        let Some(permit) = tunnels.reserve() else {
            respond(&mut client, 503, "guard-capacity");
            return;
        };
        if client
            .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
            .is_err()
            || upstream.write_all(&buffered).is_err()
        {
            return;
        }
        tunnels.relay(client, upstream, lease, permit);
    } else {
        // Forward exactly one request body, never pipelined bytes. Then relay
        // only the response; a second request must open a fresh proxy
        // connection and pass policy again.
        let requested_upgrades = request.requested_upgrades();
        let forwarded = request.origin_form(requested_upgrades.is_some());
        if upstream.write_all(forwarded.as_bytes()).is_err()
            || upstream.write_all(&buffered).is_err()
        {
            return;
        }
        let remaining = request.content_length - buffered.len() as u64;
        if remaining > 0 {
            let mut body = (&mut client).take(remaining);
            if std::io::copy(&mut body, &mut upstream).ok() != Some(remaining) {
                return;
            }
        }
        // A write-side EOF can cancel the server's request context before its response.
        // Framing limits client bytes; Connection: close and relay deadlines bound the response.
        relay_screened_response(
            upstream,
            client,
            shared,
            &request.url,
            requested_upgrades.as_deref(),
            tunnels,
            lease,
        );
    }
}

/// Configure the read/write deadlines that bound the relay on both sockets.
///
/// Client before upstream, and read before write on each: the ordering is
/// deliberate so a gate can name a single failing endpoint, and so the
/// already-open client socket is bounded before the freshly-connected upstream
/// Returns the endpoint whose deadline could not be set.
fn configure_relay_timeouts(
    shared: &Shared,
    client: &TcpStream,
    upstream: &TcpStream,
) -> Result<(), TimeoutEndpoint> {
    shared
        .timeouts
        .set_read_timeout(TimeoutEndpoint::Client, client, RELAY_IO_TIMEOUT)
        .map_err(|_| TimeoutEndpoint::Client)?;
    shared
        .timeouts
        .set_read_timeout(TimeoutEndpoint::Upstream, upstream, RELAY_IO_TIMEOUT)
        .map_err(|_| TimeoutEndpoint::Upstream)?;
    shared
        .timeouts
        .set_write_timeout(TimeoutEndpoint::Upstream, upstream, RELAY_IO_TIMEOUT)
        .map_err(|_| TimeoutEndpoint::Upstream)?;
    Ok(())
}

/// Read bytes until the end of the request head. Returns the head and whatever
/// body bytes arrived with it.
fn read_head(client: &mut impl Read) -> Option<(Vec<u8>, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut search = HeadEndSearch::default();
    let mut chunk = [0u8; 1024];
    loop {
        let read = client.read(&mut chunk).ok()?;
        if read == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..read]);
        if buf.len() > MAX_REQUEST_HEAD {
            return None;
        }
        if let Some(end) = search.find(&buf) {
            return Some((buf[..end].to_vec(), buf[end..].to_vec()));
        }
    }
}

// A search belongs to one append-only header; discard it before draining an interim response.
#[derive(Default)]
struct HeadEndSearch {
    searched_to: usize,
}

#[cfg(test)]
std::thread_local! {
    static HEADER_SCAN_BYTES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

impl HeadEndSearch {
    fn find(&mut self, buf: &[u8]) -> Option<usize> {
        // Three prior bytes retain every possible split of the four-byte delimiter.
        let start = self.searched_to.saturating_sub(3);
        self.searched_to = buf.len();
        #[cfg(test)]
        HEADER_SCAN_BYTES.set(HEADER_SCAN_BYTES.get() + buf.len() - start);
        memchr::memmem::find(&buf[start..], b"\r\n\r\n").map(|offset| start + offset + 4)
    }
}

/// Relay one cleartext upstream response, refusing a credential-bearing
/// redirect before WebKit receives the response and normalises its Location.
///
/// The screen runs only on cleartext exchanges. A `Location` delivered by an
/// HTTPS origin travels inside the CONNECT tunnel and cannot be read here
/// without terminating TLS; that separate unsupported class is not protected
/// by this hook.
///
/// Interim `1xx` heads are relayed and skipped until the final response so a
/// `103 Early Hints`/`100 Continue` prelude cannot hide the real redirect. A
/// bare-LF (non-CRLF) head is unframable and fails closed. Only a request with
/// both Upgrade headers followed by a `101 Switching Protocols` selecting an
/// offered protocol is spliced bidirectionally.
fn relay_screened_response(
    mut upstream: TcpStream,
    mut client: TcpStream,
    shared: &Shared,
    source_url: &str,
    requested_upgrades: Option<&[String]>,
    tunnels: &TunnelSender,
    lease: ConnectionLease,
) {
    let mut buffered = Vec::new();
    let mut interim = 0usize;
    loop {
        let mut search = HeadEndSearch::default();
        let head_end = loop {
            if let Some(end) = search.find(&buffered) {
                break end;
            }
            let mut chunk = [0_u8; 2048];
            match upstream.read(&mut chunk) {
                Ok(0) => {
                    // An incomplete head is ambiguous framing. Never forward
                    // bytes that may contain an unscreened partial Location.
                    respond(&mut client, 502, "incomplete-response-head");
                    return;
                }
                Ok(read) => {
                    if buffered.len().saturating_add(read) > MAX_RESPONSE_HEAD {
                        respond(&mut client, 502, "response-head-too-large");
                        return;
                    }
                    buffered.extend_from_slice(&chunk[..read]);
                }
                Err(_) => return,
            }
        };

        let Some(status) = response_status(&buffered[..head_end]) else {
            // One CRLF contract: a bare-LF or otherwise unframable head is
            // refused rather than passed on, so smuggled framing cannot hide a
            // redirect from the screen.
            respond(&mut client, 502, "malformed-response-head");
            return;
        };

        // Informational 1xx (except the 101 protocol switch) are relayed and
        // then followed by the real response. Bound the count so an endless
        // interim stream cannot wedge the screen.
        if (100..200).contains(&status) && status != 101 {
            interim += 1;
            if interim > MAX_INTERIM_RESPONSES {
                respond(&mut client, 502, "too-many-interim-responses");
                return;
            }
            if client.write_all(&buffered[..head_end]).is_err() {
                return;
            }
            buffered.drain(..head_end);
            continue;
        }

        if (300..400).contains(&status)
            && let Some(redacted) = credential_redirect_location(&buffered[..head_end], source_url)
        {
            shared.record(GuardEvent::Denied {
                target: PolicyUrl::new(redacted),
                cause: DestinationDenial::Url(
                    enzui_security::url_policy::UrlVerdict::CredentialsInUrl,
                ),
            });
            respond(&mut client, 403, "credentials-in-url");
            return;
        }

        if status == 101 {
            let Some(protocols) = requested_upgrades else {
                respond(&mut client, 502, "unexpected-upgrade");
                return;
            };
            if !response_accepts_upgrade(&buffered[..head_end], protocols) {
                respond(&mut client, 502, "mismatched-upgrade");
                return;
            }
            let Some(permit) = tunnels.reserve() else {
                respond(&mut client, 503, "guard-capacity");
                return;
            };
            if client.write_all(&buffered).is_err() {
                return;
            }
            tunnels.relay(client, upstream, lease, permit);
        } else {
            // A requested upgrade that received an ordinary response is an
            // ordinary one-response exchange. End the request side now so it
            // cannot become an unscreened raw tunnel.
            if requested_upgrades.is_some() {
                let _ = upstream.shutdown(Shutdown::Write);
            }
            if client.write_all(&buffered).is_err() {
                return;
            }
            let _ = std::io::copy(&mut upstream, &mut client);
            let _ = client.shutdown(Shutdown::Write);
        }
        return;
    }
}

/// Parse the status code from a response head under one explicit CRLF contract.
///
/// Every `\n` in the head must be preceded by `\r`; a bare LF returns `None`
/// (fail closed). The status line must begin `HTTP/` and carry a numeric code.
/// The same contract governs the status line and every header, so a smuggled
/// bare-LF cannot make one part tolerant and another strict.
fn response_status(head: &[u8]) -> Option<u16> {
    let mut prev = 0_u8;
    for &byte in head {
        if byte == b'\n' && prev != b'\r' {
            return None;
        }
        prev = byte;
    }
    let eol = head.windows(2).position(|window| window == b"\r\n")?;
    let status_line = std::str::from_utf8(&head[..eol]).ok()?;
    let mut tokens = status_line.split_ascii_whitespace();
    let version = tokens.next()?;
    if !version.starts_with("HTTP/") {
        return None;
    }
    tokens.next()?.parse::<u16>().ok()
}

/// Iterate a CRLF-validated head's lines (the status line and each header),
/// with the trailing `\r` removed. Only call after [`response_status`] has
/// confirmed every LF is CR-preceded, so `strip_suffix(b"\r")` always applies.
fn crlf_lines(head: &[u8]) -> impl Iterator<Item = &[u8]> {
    head.split(|byte| *byte == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
}

/// Require both halves of the server's Upgrade handshake and a non-empty
/// selected protocol list in which *every* token matches a protocol offered by
/// the client, compared ASCII-case-insensitively. The response head has already
/// passed the CRLF contract.
///
/// RFC 7230 §6.7 supplies the comma-separated token/list structure and forbids
/// switching to a protocol the client did not offer, so one unoffered layer
/// denies the whole switch even when another layer was offered. RFC 6455
/// §4.1/§4.2 makes the WebSocket keyword itself case-insensitive, which is why
/// a legal `WebSocket` or `WEBSOCKET` response must be accepted against an
/// offered `websocket`.
fn response_accepts_upgrade(head: &[u8], requested: &[String]) -> bool {
    let mut connection_upgrade = false;
    let mut accepted = Vec::new();
    for line in crlf_lines(head).skip(1) {
        let Some(colon) = line.iter().position(|byte| *byte == b':') else {
            continue;
        };
        let Ok(name) = std::str::from_utf8(&line[..colon]) else {
            continue;
        };
        let Ok(value) = std::str::from_utf8(line[colon + 1..].trim_ascii()) else {
            continue;
        };
        if name.eq_ignore_ascii_case("connection") {
            connection_upgrade |= value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("upgrade"));
        } else if name.eq_ignore_ascii_case("upgrade") {
            accepted.extend(
                value
                    .split(',')
                    .map(str::trim)
                    .filter(|protocol| !protocol.is_empty()),
            );
        }
    }
    connection_upgrade
        && !accepted.is_empty()
        && accepted.iter().all(|accepted| {
            requested
                .iter()
                .any(|offered| accepted.eq_ignore_ascii_case(offered))
        })
}

/// When a redirect head carries a credential-bearing `Location`, return a
/// redacted, userinfo-free display of it; otherwise `None`.
///
/// The scan continues past a non-credential or non-UTF8 `Location` so a benign
/// first value cannot mask a credential in a later duplicate header. The
/// returned string never contains the userinfo bytes.
fn credential_redirect_location(head: &[u8], source_url: &str) -> Option<String> {
    for line in crlf_lines(head).skip(1) {
        if line.is_empty() {
            continue;
        }
        let Some(colon) = line.iter().position(|byte| *byte == b':') else {
            continue;
        };
        if !line[..colon].eq_ignore_ascii_case(b"location") {
            continue;
        }
        let value = line[colon + 1..].trim_ascii_start().trim_ascii_end();
        if let Some(redacted) = credential_location_redacted(value, source_url) {
            return Some(redacted);
        }
    }
    None
}

/// Conservatively detect a `userinfo@` credential in a redirect `Location`
/// using the WHATWG special-URL authority rules WebKit applies.
///
/// For a special scheme different from the HTTP(S) base, WHATWG enters the
/// authority state even with no slash (`https:user:pass@host` from an HTTP
/// page). For the same special scheme, zero or one slash is a relative path,
/// while two or more mixed `/`/`\\` separators introduce an authority. A
/// scheme-less network-path reference follows that same two-or-more rule. All
/// leading authority separators are skipped, not merely the first two.
///
/// This is byte-oriented so a non-UTF8 value neither aborts the caller nor
/// hides an ASCII credential. The returned display excludes the entire
/// userinfo and all path/query bytes.
fn credential_location_redacted(raw: &[u8], source_url: &str) -> Option<String> {
    // WHATWG strips tab/newline code points and treats backslash as slash while
    // parsing special URLs. Doing that before locating an authority is a
    // conservative pre-parse: it can expose a special authority, never hide
    // one.
    let mut cleaned: Vec<u8> = raw
        .iter()
        .copied()
        .filter(|byte| !matches!(byte, b'\t' | b'\n' | b'\r'))
        .map(|byte| if byte == b'\\' { b'/' } else { byte })
        .collect();
    let start = cleaned.iter().position(|byte| *byte > 0x20)?;
    let end = cleaned
        .iter()
        .rposition(|byte| *byte > 0x20)
        .map_or(start, |index| index + 1);
    cleaned.truncate(end);
    let stripped = &cleaned[start..];
    let base_scheme = ascii_scheme(source_url.as_bytes());

    let (display_scheme, authority) = if let Some(colon) = scheme_prefix(stripped) {
        let scheme = std::str::from_utf8(&stripped[..colon])
            .ok()?
            .to_ascii_lowercase();
        if !is_special_scheme(&scheme) {
            return None;
        }
        let after_scheme = &stripped[colon + 1..];
        let separators = after_scheme
            .iter()
            .take_while(|byte| **byte == b'/')
            .count();
        let same_scheme = base_scheme
            .as_deref()
            .is_some_and(|base| base.eq_ignore_ascii_case(&scheme));
        if same_scheme && separators < 2 {
            // `http:user@host` and `http:/user@host` from an HTTP base are
            // same-origin relative paths in WHATWG, not authorities.
            return None;
        }
        (Some(scheme), &after_scheme[separators..])
    } else {
        let separators = stripped.iter().take_while(|byte| **byte == b'/').count();
        if separators < 2 || !base_scheme.as_deref().is_some_and(is_special_scheme) {
            return None;
        }
        (None, &stripped[separators..])
    };

    let auth_end = authority
        .iter()
        .position(|byte| matches!(byte, b'/' | b'?' | b'#'))
        .unwrap_or(authority.len());
    let authority = &authority[..auth_end];
    let at = authority.iter().rposition(|byte| *byte == b'@')?;
    let hostport = String::from_utf8_lossy(&authority[at + 1..]);
    Some(match display_scheme {
        Some(scheme) => format!("{scheme}://{hostport}/<redacted-credential-redirect>"),
        None => format!("//{hostport}/<redacted-credential-redirect>"),
    })
}

fn ascii_scheme(url: &[u8]) -> Option<String> {
    let colon = scheme_prefix(url)?;
    std::str::from_utf8(&url[..colon])
        .ok()
        .map(str::to_ascii_lowercase)
}

fn is_special_scheme(scheme: &str) -> bool {
    matches!(scheme, "ftp" | "file" | "http" | "https" | "ws" | "wss")
}

/// Return the index of the `:` ending a valid URL scheme prefix
/// (`ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ) ":"`), or `None`.
fn scheme_prefix(bytes: &[u8]) -> Option<usize> {
    if bytes.first().is_none_or(|byte| !byte.is_ascii_alphabetic()) {
        return None;
    }
    for (index, &byte) in bytes.iter().enumerate() {
        if byte == b':' {
            return (index > 0).then_some(index);
        }
        if index > 0 && !(byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.')) {
            return None;
        }
    }
    None
}

/// A parsed proxy request: what the client wants to reach, and how.
struct ProxyRequest {
    /// An absolute URL the destination policy can judge.
    url: String,
    /// `CONNECT` (a TLS tunnel) rather than a forwarded cleartext request.
    tunnel: bool,
    datagram: bool,
    method: String,
    path: String,
    version: String,
    headers: Vec<(String, String)>,
    connection_tokens: Vec<String>,
    authority: String,
    host_header: Option<String>,
    default_port: u16,
    content_length: u64,
}

impl ProxyRequest {
    fn parse(head: &str) -> Option<ProxyRequest> {
        let mut lines = head.strip_suffix("\r\n\r\n")?.split("\r\n");
        let line = lines.next()?;
        let parts: Vec<&str> = line.split(' ').collect();
        if parts.len() != 3 || parts.iter().any(|part| part.is_empty()) {
            return None;
        }
        let method = parts[0].to_owned();
        let target = parts[1];
        let version = parts[2].to_owned();
        if target.contains('#')
            || method.is_empty()
            || !method.bytes().all(is_token_byte)
            || !matches!(version.as_str(), "HTTP/1.0" | "HTTP/1.1")
        {
            return None;
        }
        let mut headers = Vec::new();
        let mut connection_tokens = Vec::new();
        let mut host_header = None;
        let mut content_length = None;
        for line in lines {
            if line.is_empty() {
                continue;
            }
            if line.starts_with(' ') || line.starts_with('\t') {
                return None;
            }
            let (name, value) = line.split_once(':')?;
            if name.is_empty()
                || !name.bytes().all(is_token_byte)
                || value
                    .bytes()
                    .any(|byte| (byte < 0x20 && byte != b'\t') || byte == 0x7f)
            {
                return None;
            }
            if name.eq_ignore_ascii_case("host") {
                if host_header.is_some() || value.trim().is_empty() {
                    return None;
                }
                host_header = Some(value.trim().to_owned());
            }
            if name.eq_ignore_ascii_case("content-length") {
                let value = value.trim();
                if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                    return None;
                }
                let parsed = value.parse::<u64>().ok()?;
                if content_length.replace(parsed).is_some() {
                    return None;
                }
            }
            if name.eq_ignore_ascii_case("transfer-encoding") {
                // This minimal proxy does not decode chunked bodies. Refuse
                // ambiguous framing before resolution/connection.
                return None;
            }
            if name.eq_ignore_ascii_case("connection")
                || name.eq_ignore_ascii_case("proxy-connection")
            {
                connection_tokens.extend(
                    value
                        .split(',')
                        .map(|token| token.trim().to_ascii_lowercase())
                        .filter(|token| !token.is_empty()),
                );
            }
            headers.push((name.to_owned(), value.trim().to_owned()));
        }
        if version == "HTTP/1.1" && host_header.is_none() {
            return None;
        }
        if connection_tokens
            .iter()
            .any(|name| matches!(name.as_str(), "host" | "content-length"))
        {
            return None;
        }
        let udp_upgrade = headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("upgrade")
                && value
                    .split(',')
                    .any(|value| value.trim().eq_ignore_ascii_case("connect-udp"))
        });
        if udp_upgrade {
            return Self::parse_datagram(
                &method,
                target,
                &version,
                headers,
                connection_tokens,
                host_header,
                content_length.unwrap_or(0),
            );
        }
        if method.eq_ignore_ascii_case("CONNECT") {
            let (host, port) = target.rsplit_once(':')?;
            port.parse::<u16>().ok()?;
            return Some(ProxyRequest {
                url: format!("https://{host}:{port}/"),
                tunnel: true,
                datagram: false,
                method,
                path: String::new(),
                version,
                headers,
                connection_tokens,
                authority: target.to_owned(),
                host_header,
                default_port: 443,
                content_length: 0,
            });
        }
        let (scheme, after_scheme) = target.split_once("://")?;
        let default_port = if scheme.eq_ignore_ascii_case("http") {
            80
        } else if scheme.eq_ignore_ascii_case("https") {
            443
        } else {
            0 // rejected by DestinationPolicy before authority comparison
        };
        let path_start = after_scheme.find(['/', '?']).unwrap_or(after_scheme.len());
        let path = if path_start == after_scheme.len() {
            "/".to_owned()
        } else if after_scheme.as_bytes()[path_start] == b'?' {
            format!("/{}", &after_scheme[path_start..])
        } else {
            after_scheme[path_start..].to_owned()
        };
        Some(ProxyRequest {
            url: target.to_owned(),
            tunnel: false,
            datagram: false,
            method,
            path,
            version,
            headers,
            connection_tokens,
            authority: after_scheme[..path_start].to_owned(),
            host_header,
            default_port,
            content_length: content_length.unwrap_or(0),
        })
    }

    fn parse_datagram(
        method: &str,
        target: &str,
        version: &str,
        headers: Vec<(String, String)>,
        connection_tokens: Vec<String>,
        host_header: Option<String>,
        content_length: u64,
    ) -> Option<Self> {
        if method != "GET"
            || version != "HTTP/1.1"
            || content_length != 0
            || !headers.iter().any(|(name, value)| {
                name.eq_ignore_ascii_case("connection")
                    && value
                        .split(',')
                        .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
            })
        {
            return None;
        }
        for (field, expected) in [("upgrade", "connect-udp"), ("capsule-protocol", "?1")] {
            let values: Vec<_> = headers
                .iter()
                .filter(|(name, _)| name.eq_ignore_ascii_case(field))
                .collect();
            if values.len() != 1 || !values[0].1.eq_ignore_ascii_case(expected) {
                return None;
            }
        }
        let (authority, path) = if target.starts_with('/') {
            (host_header.clone()?, target)
        } else {
            let (scheme, rest) = target.split_once("://")?;
            if !scheme.eq_ignore_ascii_case("http") {
                return None;
            }
            let slash = rest.find('/')?;
            (rest[..slash].to_owned(), &rest[slash..])
        };
        let tail = path
            .strip_prefix("/.well-known/masque/udp/")?
            .strip_suffix('/')?;
        let (host, port) = tail.split_once('/')?;
        if host.is_empty() || port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        let port = port.parse::<u16>().ok().filter(|port| *port != 0)?;
        let mut decoded = Vec::with_capacity(host.len());
        let mut bytes = host.as_bytes().iter().copied();
        while let Some(byte) = bytes.next() {
            decoded.push(if byte == b'%' {
                let high = char::from(bytes.next()?).to_digit(16)?;
                let low = char::from(bytes.next()?).to_digit(16)?;
                (high * 16 + low) as u8
            } else {
                byte
            });
        }
        let host = std::str::from_utf8(&decoded).ok()?;
        let host = if host.contains(':') {
            format!("[{}]", host.parse::<std::net::Ipv6Addr>().ok()?)
        } else {
            if host.is_empty()
                || host
                    .chars()
                    .any(|c| c.is_control() || c.is_whitespace() || "/@?#\\[]%".contains(c))
            {
                return None;
            }
            host.to_owned()
        };
        Some(Self {
            url: format!("https://{host}:{port}/"),
            tunnel: false,
            datagram: true,
            method: method.to_owned(),
            path: path.to_owned(),
            version: version.to_owned(),
            headers,
            connection_tokens,
            authority,
            host_header,
            default_port: 80,
            content_length: 0,
        })
    }

    fn authority_key(&self) -> Option<(String, u16)> {
        authority_key(&self.authority, self.default_port)
    }

    /// Protocols from a syntactically complete Upgrade request. Both
    /// `Connection: upgrade` and at least one non-empty `Upgrade` value are
    /// required; either header by itself remains ordinary hop-by-hop metadata.
    fn requested_upgrades(&self) -> Option<Vec<String>> {
        let connection_upgrade = self
            .headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("connection"))
            .flat_map(|(_, value)| value.split(','))
            .any(|token| token.trim().eq_ignore_ascii_case("upgrade"));
        if !connection_upgrade {
            return None;
        }
        let protocols: Vec<String> = self
            .headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("upgrade"))
            .flat_map(|(_, value)| value.split(','))
            .map(str::trim)
            .filter(|protocol| !protocol.is_empty())
            .map(str::to_owned)
            .collect();
        (!protocols.is_empty()).then_some(protocols)
    }

    /// Rebuild the head with an origin-form target for the upstream server.
    fn origin_form(&self, upgrade: bool) -> String {
        let mut out = format!("{} {} {}\r\n", self.method, self.path, self.version);
        for (name, value) in &self.headers {
            let lower = name.to_ascii_lowercase();
            if lower == "upgrade" {
                if upgrade {
                    out.push_str(name);
                    out.push_str(": ");
                    out.push_str(value);
                    out.push_str("\r\n");
                }
                continue;
            }
            if is_static_hop_header(&lower) || self.connection_tokens.iter().any(|n| n == &lower) {
                continue;
            }
            out.push_str(name);
            out.push_str(": ");
            out.push_str(value);
            out.push_str("\r\n");
        }
        if upgrade {
            out.push_str("Connection: Upgrade\r\n\r\n");
        } else {
            out.push_str("Connection: close\r\n\r\n");
        }
        out
    }
}

fn authority_key(authority: &str, default_port: u16) -> Option<(String, u16)> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, suffix) = rest.split_once(']')?;
        let port = if suffix.is_empty() {
            default_port
        } else {
            suffix.strip_prefix(':')?.parse().ok()?
        };
        return Some((host.to_ascii_lowercase(), port));
    }
    if authority.contains('@') || authority.matches(':').count() > 1 {
        return None;
    }
    match authority.rsplit_once(':') {
        Some((host, port)) => Some((host.to_ascii_lowercase(), port.parse().ok()?)),
        None => Some((authority.to_ascii_lowercase(), default_port)),
    }
}

fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

fn is_static_hop_header(name: &str) -> bool {
    matches!(
        name,
        "connection"
            | "proxy-connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

/// Answer the client without ever touching the network.
impl SeamFailure {
    fn reason(self) -> &'static str {
        match self {
            SeamFailure::Panicked => "seam-poisoned",
            SeamFailure::Unavailable => "seam-unavailable",
        }
    }
}

fn record_seam_failure(shared: &Shared, target: &str, failure: SeamFailure) {
    let target = PolicyUrl::new(target);
    let event = match failure {
        SeamFailure::Panicked => GuardEvent::SeamPanicked { target },
        SeamFailure::Unavailable => GuardEvent::SeamUnavailable { target },
    };
    shared.record(event);
}

fn respond_proxy_auth_required(client: &mut TcpStream) {
    let response = format!(
        "HTTP/1.1 407 Proxy Authentication Required\r\n\
         Proxy-Authenticate: {PROXY_AUTHENTICATE_VALUE}\r\n\
         Content-Length: 0\r\nConnection: close\r\n\r\n"
    );
    let _ = client.write_all(response.as_bytes());
    let _ = client.flush();
    let _ = client.shutdown(Shutdown::Both);
}

fn respond(client: &mut TcpStream, status: u16, reason: &str) {
    let text = match status {
        400 => "Bad Request",
        403 => "Forbidden",
        503 => "Service Unavailable",
        _ => "Bad Gateway",
    };
    let unavailable = status == 502 && reason == "upstream-unreachable";
    let body = if unavailable {
        include_str!("destination_guard/unreachable.html").to_owned()
    } else {
        format!("enzUI destination policy: {reason}\n")
    };
    let content_type = if unavailable {
        "text/html; charset=utf-8"
    } else {
        "text/plain"
    };
    let response = format!(
        "HTTP/1.1 {status} {text}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\
         X-Enzui-Destination: {reason}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = client.write_all(response.as_bytes());
    let _ = client.flush();
    let _ = client.shutdown(Shutdown::Both);
}

#[cfg(test)]
mod tests;
