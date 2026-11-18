//! The bounded records a policy binding keeps: the TLS-certificate ledger and
//! the ring of policy observations.

use super::*;

/// Bounded diagnostics for the native TLS-certificate path.
///
/// The observation ring answers "what did policy decide?". This answers the
/// question a *missing* certificate observation raises: was the callback ever
/// registered, did WebKit ever fire it, and did the safe layer apply exactly
/// one terminal native action? Every list is bounded with a truthful dropped
/// count, so a hostile page cannot grow memory through it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateLedger {
    /// The real GObject handler id of `load-failed-with-tls-errors`. Zero
    /// means the callback was never installed on this WebView, which is a
    /// different defect from a callback that never fired.
    pub(super) tls_handler_id: u64,
    pub(super) callbacks: u64,
    pub(super) events: VecDeque<CertificateEvent>,
    pub(super) load_failures: VecDeque<LoadFailure>,
    pub(super) main_responses: VecDeque<MainResponse>,
    pub(super) dropped_events: u64,
    pub(super) dropped_load_failures: u64,
    pub(super) dropped_main_responses: u64,
    /// Continuations already spent, per host, for this view's lifetime. The
    /// deterministic attempt control behind [`CertificateLedger::admit_continuation`].
    ///
    /// No new redaction surface: the same host already appears in every
    /// [`CertificateEvent`], and nothing else about the URI is retained here.
    pub(super) retry_hosts: Vec<(String, u32)>,
    pub(super) retry_refusals: u64,
    /// Host-initiated pre-trust installations and refusals, oldest first.
    pub(super) pre_trusts: VecDeque<PreTrustEvent>,
    pub(super) dropped_pre_trusts: u64,
}

impl CertificateLedger {
    /// Bound for each event list. A page can fail a handshake repeatedly; the
    /// newest entries are the ones a diagnosis needs.
    pub const CAPACITY: usize = 16;
    /// Bound on a recorded error-domain name or MIME type.
    pub(super) const DETAIL_MAX: usize = 64;
    /// Bound on a redacted URL retained by this diagnostic ledger.
    pub(super) const URL_MAX: usize = 512;

    /// How many times one host's failed certificate may be continued
    /// (exception installed and failing URI reloaded) within one view.
    ///
    /// One. A continuation is only ever justified by "the exception now makes
    /// this handshake succeed"; a second failure for the same host is proof
    /// that it did not, so a second continuation is a retry with a known
    /// answer. Because the reload is issued from inside the failure callback
    /// with no delay, an unbounded budget is a network-driven hot loop: fail →
    /// pin → reload → fail, one full page load per turn, for as long as the
    /// origin keeps presenting a new bad certificate.
    pub const MAX_CONTINUATIONS_PER_HOST: u32 = 1;

    /// How many distinct hosts one view tracks continuation budgets for.
    ///
    /// This is also the total continuation ceiling for a view, which is
    /// what bounds the multi-host variant of the same storm (a page embedding
    /// subresources across many hosts, each raising its own TLS failure).
    ///
    /// The table is bounded in bytes as well as entries: keys come from
    /// `certificate_host`, which refuses identities over
    /// [`MAX_CERTIFICATE_HOST_BYTES`] before allocation.
    pub const RETRY_HOSTS_MAX: usize = 32;

    pub(super) fn new() -> Self {
        Self {
            tls_handler_id: 0,
            callbacks: 0,
            events: VecDeque::with_capacity(Self::CAPACITY),
            load_failures: VecDeque::with_capacity(Self::CAPACITY),
            main_responses: VecDeque::with_capacity(Self::CAPACITY),
            dropped_events: 0,
            dropped_load_failures: 0,
            dropped_main_responses: 0,
            retry_hosts: Vec::new(),
            retry_refusals: 0,
            pre_trusts: VecDeque::with_capacity(Self::CAPACITY),
            dropped_pre_trusts: 0,
        }
    }

    /// Append one host-initiated pre-trust result.
    ///
    /// Bounded like every other list here, with a truthful dropped count: the
    /// host may call the installer in a loop.
    pub(super) fn record_pre_trust(&mut self, mut event: PreTrustEvent) {
        debug_assert!(event.host.len() <= MAX_CERTIFICATE_HOST_BYTES);
        event.host = compact_string(&event.host);
        event.key = compact_string(&event.key);
        if self.pre_trusts.len() == Self::CAPACITY {
            self.pre_trusts.pop_front();
            self.dropped_pre_trusts += 1;
        }
        self.pre_trusts.push_back(event);
    }

    /// Host-initiated pre-trust results, oldest first.
    #[must_use]
    pub fn pre_trusts(&self) -> Vec<PreTrustEvent> {
        self.pre_trusts.iter().cloned().collect()
    }

    /// How many pre-trust records the bounded list evicted.
    #[must_use]
    pub fn pre_trusts_dropped(&self) -> u64 {
        self.dropped_pre_trusts
    }

    /// Whether one more TLS continuation may be performed for `host`, spending
    /// the budget when it may.
    ///
    /// Deterministic and attempt-based on purpose: a *delay* is not available
    /// here. The decision runs inside a WebKit signal handler on the main
    /// loop, where sleeping would stall every view in the process, and a timer
    /// that re-issues the load later is the same unbounded retry with a longer
    /// period. Counting attempts per host bounds the cycle exactly.
    ///
    /// Refusal is fail closed in both saturated cases:
    ///
    /// * a full host table refuses an untracked host instead of evicting one.
    ///   Eviction would reset an exhausted host's budget, so a page cycling
    ///   through `RETRY_HOSTS_MAX + 1` hosts could reopen the very loop the
    ///   budget just closed - an LRU here is a bypass, not a bound;
    /// * a host that already spent its budget never regains it.
    ///
    /// Every refusal is counted ([`Self::retries_refused`]), so "the budget
    /// stopped a retry" is observable and cannot be confused with "no
    /// certificate ever failed".
    ///
    /// A hostless failure never reaches here: the callback answers that with
    /// [`CertificateAction::HostUnknown`] first, because an unscoped exception
    /// is a different (worse) defect than an unbounded retry.
    pub(super) fn admit_continuation(&mut self, host: &str) -> bool {
        if let Some(entry) = self.retry_hosts.iter_mut().find(|(h, _)| h == host) {
            if entry.1 >= Self::MAX_CONTINUATIONS_PER_HOST {
                self.retry_refusals = self.retry_refusals.saturating_add(1);
                return false;
            }
            // Saturating: the counter is only ever compared against a small
            // ceiling, and a wrapped counter would restore the budget.
            entry.1 = entry.1.saturating_add(1);
            return true;
        }
        if self.retry_hosts.len() >= Self::RETRY_HOSTS_MAX {
            self.retry_refusals = self.retry_refusals.saturating_add(1);
            return false;
        }
        self.retry_hosts.push((compact_string(host), 1));
        true
    }

    /// How many certificate continuations the budget refused.
    #[must_use]
    pub fn retries_refused(&self) -> u64 {
        self.retry_refusals
    }

    /// How many distinct hosts hold a continuation budget in this view.
    #[must_use]
    pub fn continuation_hosts(&self) -> usize {
        self.retry_hosts.len()
    }

    pub(super) fn record_main_response(&mut self, mut response: MainResponse) {
        truncate_utf8(&mut response.mime, Self::DETAIL_MAX);
        response.mime = compact_string(&response.mime);
        if self.main_responses.len() == Self::CAPACITY {
            self.main_responses.pop_front();
            self.dropped_main_responses += 1;
        }
        self.main_responses.push_back(response);
    }

    pub(super) fn record_event(&mut self, mut event: CertificateEvent) {
        // Certificate hosts are routing identities, validated before this
        // point. Re-box defensively so every retained event has no spare
        // request-controlled allocation capacity.
        event.host = compact_string(&event.host);
        event.key = compact_string(&event.key);
        debug_assert!(event.host.capacity() <= MAX_CERTIFICATE_HOST_BYTES);
        debug_assert!(event.key.capacity() <= MAX_CERTIFICATE_HOST_BYTES);
        if self.events.len() == Self::CAPACITY {
            self.events.pop_front();
            self.dropped_events += 1;
        }
        self.events.push_back(event);
    }

    pub(super) fn record_load_failure(&mut self, mut failure: LoadFailure) {
        truncate_utf8(&mut failure.domain, Self::DETAIL_MAX);
        failure.domain = compact_string(&failure.domain);
        if self.load_failures.len() == Self::CAPACITY {
            self.load_failures.pop_front();
            self.dropped_load_failures += 1;
        }
        self.load_failures.push_back(failure);
    }

    /// Whether WebKit accepted the `load-failed-with-tls-errors` connection.
    #[must_use]
    pub fn tls_callback_registered(&self) -> bool {
        self.tls_handler_id != 0
    }

    /// How many times the real TLS-certificate callback fired.
    #[must_use]
    pub fn callbacks(&self) -> u64 {
        self.callbacks
    }

    /// The terminal native actions taken, oldest first.
    #[must_use]
    pub fn events(&self) -> Vec<CertificateEvent> {
        self.events.iter().cloned().collect()
    }

    /// `load-failed` fallbacks WebKit reported, oldest first. A TLS-domain
    /// entry here with no [`Self::callbacks`] means WebKit saw the certificate
    /// failure but this binding did not claim it.
    #[must_use]
    pub fn load_failures(&self) -> Vec<LoadFailure> {
        self.load_failures.iter().cloned().collect()
    }

    /// Terminal actions evicted from the bounded list.
    #[must_use]
    pub fn dropped_events(&self) -> u64 {
        self.dropped_events
    }

    /// Load failures evicted from the bounded list.
    #[must_use]
    pub fn dropped_load_failures(&self) -> u64 {
        self.dropped_load_failures
    }

    /// Main-frame main-resource responses WebKit delivered, oldest first. An
    /// entry for an HTTPS URL means the handshake succeeded, so no certificate
    /// callback was due.
    #[must_use]
    pub fn main_responses(&self) -> Vec<MainResponse> {
        self.main_responses.iter().cloned().collect()
    }

    /// Main-resource responses evicted from the bounded list.
    #[must_use]
    pub fn dropped_main_responses(&self) -> u64 {
        self.dropped_main_responses
    }
}

pub(super) type Responder = dyn FnMut(&NativePolicyRequest) -> Option<ViewRequestId>;

/// A bounded observation ring with a truthful dropped count.
///
/// When either the entry or request-string allocation-capacity budget is full,
/// the oldest observation is evicted. Both limits matter: page-controlled
/// URLs can make one observation much larger than another. The total number of evicted or
/// unretainable entries is tracked so a consumer can tell how much history it
/// missed.
#[derive(Debug)]
pub struct BoundedObservations {
    pub(super) ring: VecDeque<NativePolicyObservation>,
    pub(super) request_capacities: VecDeque<usize>,
    pub(super) capacity: usize,
    pub(super) byte_budget: usize,
    pub(super) retained_request_capacity: usize,
    pub(super) dropped: u64,
}

impl Clone for BoundedObservations {
    fn clone(&self) -> Self {
        let mut clone = Self::with_limits(self.capacity, self.byte_budget);
        for observation in &self.ring {
            clone.push(observation.clone());
        }
        // Cloning retained entries is not an eviction. Preserve the source's
        // lifetime count after rebuilding and remeasuring every allocation.
        clone.dropped = self.dropped;
        clone
    }
}

impl BoundedObservations {
    /// The default observation entry bound.
    ///
    /// Deliberately defined as [`crate::destination_guard::EVENT_LOG_CAPACITY`]
    /// so this ring and the destination guard's event log share one count
    /// bound. The separate [`Self::DEFAULT_BYTE_BUDGET`] is authoritative for
    /// page-controlled request strings.
    pub const DEFAULT_CAPACITY: usize = crate::destination_guard::EVENT_LOG_CAPACITY;

    /// Maximum cumulative allocation capacity of request-controlled strings
    /// retained by the default ring. This includes URLs from navigation,
    /// popup, resource and download decisions, plus certificate host names.
    pub const DEFAULT_BYTE_BUDGET: usize = 256 * 1024;

    /// Create a ring with the given entry capacity and the default byte budget.
    /// Panics if `capacity` is zero.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self::with_limits(capacity, Self::DEFAULT_BYTE_BUDGET)
    }

    /// Create a ring with explicit entry and cumulative request-string limits.
    /// Panics if either limit is zero.
    #[must_use]
    pub(super) fn with_limits(capacity: usize, byte_budget: usize) -> Self {
        assert!(capacity > 0, "observation capacity must be nonzero");
        assert!(byte_budget > 0, "observation byte budget must be nonzero");
        Self {
            ring: VecDeque::with_capacity(capacity),
            request_capacities: VecDeque::with_capacity(capacity),
            capacity,
            byte_budget,
            retained_request_capacity: 0,
            dropped: 0,
        }
    }

    /// Push an observation, first rebuilding each request string without spare
    /// capacity and measuring its actual `String::capacity`, then evicting
    /// oldest entries until both limits hold. An observation larger than the
    /// entire byte budget is counted as dropped and is never
    /// retained.
    pub fn push(&mut self, mut obs: NativePolicyObservation) {
        let request_capacity = compact_observation_request_strings(&mut obs);
        if request_capacity > self.byte_budget {
            self.dropped = self.dropped.saturating_add(1);
            return;
        }
        while self.ring.len() == self.capacity
            || request_capacity > self.byte_budget - self.retained_request_capacity
        {
            let Some(_evicted) = self.ring.pop_front() else {
                break;
            };
            let evicted_capacity = self
                .request_capacities
                .pop_front()
                .expect("observation capacity accounting stays parallel");
            self.retained_request_capacity -= evicted_capacity;
            self.dropped = self.dropped.saturating_add(1);
        }
        self.retained_request_capacity += request_capacity;
        self.request_capacities.push_back(request_capacity);
        self.ring.push_back(obs);
    }

    /// The observations currently in the ring, oldest first.
    ///
    /// Returns two slices because a `VecDeque` wraps around internally.
    /// Callers that need a single contiguous view should use [`Self::iter`].
    #[must_use]
    pub fn as_slices(&self) -> (&[NativePolicyObservation], &[NativePolicyObservation]) {
        self.ring.as_slices()
    }

    /// A convenience that collects the ring into a contiguous `Vec`.
    #[must_use]
    pub fn to_vec(&self) -> Vec<NativePolicyObservation> {
        self.ring.iter().cloned().collect()
    }

    /// Total observations evicted or refused retention since creation.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Number of observations currently retained.
    #[must_use]
    pub fn len(&self) -> usize {
        self.ring.len()
    }

    /// Whether the ring is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ring.is_empty()
    }

    /// The maximum number of observations retained.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    #[cfg(test)]
    pub(super) fn byte_budget(&self) -> usize {
        self.byte_budget
    }

    #[cfg(test)]
    pub(super) fn retained_request_capacity(&self) -> usize {
        self.retained_request_capacity
    }

    /// Iterate over the retained observations, oldest first.
    pub fn iter(&self) -> impl Iterator<Item = &NativePolicyObservation> {
        self.ring.iter()
    }
}

pub(super) fn compact_string(value: &str) -> String {
    // A boxed string slice has no spare capacity. Converting it into `String`
    // preserves that exact allocation, unlike best-effort `shrink_to_fit`.
    Box::<str>::from(value).into_string()
}

fn compact_observation_request_strings(observation: &mut NativePolicyObservation) -> usize {
    pub(super) fn compact_url(url: &mut PolicyUrl) -> usize {
        let compact = compact_string(url.as_str());
        let capacity = compact.capacity();
        *url = PolicyUrl::new(compact);
        capacity
    }

    match &mut observation.request.kind {
        RequestKind::Navigation(context) => compact_url(&mut context.url),
        RequestKind::Permission(_) => 0,
        RequestKind::Certificate(context) => {
            context.host = compact_string(&context.host);
            context.host.capacity()
        }
        RequestKind::Popup(context) => compact_url(&mut context.url),
        RequestKind::Download { url } | RequestKind::Resource { url, .. } => compact_url(url),
    }
}
