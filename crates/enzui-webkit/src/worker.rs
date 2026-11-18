//! A command worker for thread-affine native pages, with teardown that queued
//! commands cannot crowd out.
//!

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

pub use std::sync::mpsc::TrySendError;

/// How long [`CommandWorker::shutdown`] waits for a worker by default.
///
/// Sized for "the command in flight finishes", not for "the backlog drains":
/// the backlog is abandoned, not executed.
pub const DEFAULT_TEARDOWN_BUDGET: Duration = Duration::from_millis(2_000);

/// The out-of-band stop signal shared with a worker body.
///
/// It is deliberately not a queue message: a bounded command queue that is
/// full still delivers this, which is the whole point of the type.
#[derive(Debug, Clone, Default)]
pub struct StopFlag {
    stop: Arc<AtomicBool>,
}

impl StopFlag {
    /// Request that the worker stop at its next opportunity.
    pub fn request_stop(&self) {
        // Release pairs with the Acquire in `should_stop`.
        self.stop.store(true, Ordering::Release);
    }

    /// Whether shutdown has been requested.
    #[must_use]
    pub fn should_stop(&self) -> bool {
        self.stop.load(Ordering::Acquire)
    }
}

/// The worker half of a [`CommandWorker`]: a bounded receiver that also honours
/// the out-of-band stop signal.
///
/// A worker body is a `while let Some(command) = rx.next()` loop. Returning
/// `None` means *stop now*: either the stop flag was raised or the UI handle is
/// gone. Any commands still queued are discarded at that moment.
pub struct CommandReceiver<C> {
    rx: Receiver<C>,
    stop: StopFlag,
    drained: Arc<AtomicUsize>,
    started: Arc<AtomicUsize>,
}

impl<C> CommandReceiver<C> {
    /// The next command to execute, or `None` when the worker must stop.
    ///
    /// The stop flag is checked before blocking and again after a command
    /// arrives, so no command is executed after shutdown was requested even if
    /// it was already sitting in the queue.
    pub fn next(&self) -> Option<C> {
        if self.stop.should_stop() {
            self.discard_pending();
            return None;
        }
        match self.rx.recv() {
            Ok(command) => {
                if self.stop.should_stop() {
                    drop(command);
                    self.discard_pending();
                    return None;
                }
                self.started.fetch_add(1, Ordering::Release);
                Some(command)
            }
            Err(_) => {
                self.discard_pending();
                None
            }
        }
    }

    /// Whether shutdown has been requested, for a body that wants to abandon a
    /// long-running command early.
    #[must_use]
    pub fn should_stop(&self) -> bool {
        self.stop.should_stop()
    }

    /// Drop every queued command now, returning how many were released.
    ///
    /// Called automatically by [`next`](Self::next) on its way out; exposed so a
    /// body doing its own bookkeeping can release payloads earlier.
    pub fn discard_pending(&self) -> usize {
        let mut discarded = 0;
        while let Ok(command) = self.rx.try_recv() {
            drop(command);
            discarded += 1;
        }
        self.drained.fetch_add(discarded, Ordering::Release);
        discarded
    }
}

/// What a teardown attempt did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TeardownOutcome {
    /// The OS thread was joined inside the budget: its stack is gone and every
    /// resource the body owned has been dropped. Includes a worker that had
    /// already exited on its own.
    Joined,
    /// The thread finished but its body panicked; it was still joined.
    Panicked,
    /// The thread did not finish inside the budget, so it was detached rather
    /// than blocking the caller. The stop flag stays raised.
    TimedOut,
    /// A previous teardown already joined (or detached) this worker.
    AlreadyTornDown,
}

impl TeardownOutcome {
    /// Whether the OS thread was actually joined.
    #[must_use]
    pub fn is_joined(self) -> bool {
        matches!(self, TeardownOutcome::Joined | TeardownOutcome::Panicked)
    }
}

/// A UI-side handle to one command worker thread.
///
/// Sending is non-blocking and bounded; teardown is signalled out of band,
/// drains the backlog and joins within a budget.
pub struct CommandWorker<C: Send + 'static> {
    /// `None` once teardown has disconnected the channel. Dropping the sender is
    /// what wakes a worker blocked in `recv()` without needing a queue slot.
    commands: Option<SyncSender<C>>,
    stop: StopFlag,
    drained: Arc<AtomicUsize>,
    started: Arc<AtomicUsize>,
    handle: Option<JoinHandle<()>>,
    budget: Duration,
    outcome: Option<TeardownOutcome>,
}

impl<C: Send + 'static> core::fmt::Debug for CommandWorker<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CommandWorker")
            .field("live", &self.commands.is_some())
            .field("finished", &self.is_finished())
            .field("budget", &self.budget)
            .field("outcome", &self.outcome)
            .finish()
    }
}

impl<C: Send + 'static> CommandWorker<C> {
    /// Spawn `body` on a named thread behind a bounded command queue.
    ///
    /// # Errors
    ///
    /// The OS error if the thread cannot be spawned.
    pub fn spawn<F>(
        name: &str,
        capacity: usize,
        budget: Duration,
        body: F,
    ) -> io::Result<CommandWorker<C>>
    where
        F: FnOnce(CommandReceiver<C>) + Send + 'static,
    {
        let (tx, rx) = mpsc::sync_channel(capacity);
        let stop = StopFlag::default();
        let drained = Arc::new(AtomicUsize::new(0));
        let started = Arc::new(AtomicUsize::new(0));
        let receiver = CommandReceiver {
            rx,
            stop: stop.clone(),
            drained: Arc::clone(&drained),
            started: Arc::clone(&started),
        };
        let handle = thread::Builder::new()
            .name(name.to_owned())
            .spawn(move || body(receiver))?;
        Ok(CommandWorker {
            commands: Some(tx),
            stop,
            drained,
            started,
            handle: Some(handle),
            budget,
            outcome: None,
        })
    }

    /// Queue a command without blocking.
    ///
    /// # Errors
    ///
    /// [`TrySendError::Full`] when the bounded queue is saturated, and
    /// [`TrySendError::Disconnected`] once the worker has exited or teardown has
    /// disconnected the channel.
    pub fn try_send(&self, command: C) -> Result<(), TrySendError<C>> {
        match &self.commands {
            Some(tx) => tx.try_send(command),
            None => Err(TrySendError::Disconnected(command)),
        }
    }

    /// Whether the OS thread is *known* to have finished.
    ///
    /// The positive control for a join assertion: while the worker is busy this
    /// is `false`, so "it was joined" cannot be vacuously true. It only ever
    /// reports `true` on proof, never on absence of information:
    ///
    /// - while this code still holds the handle, the OS answers directly;
    /// - once teardown has joined the thread ([`TeardownOutcome::Joined`] or
    ///   [`TeardownOutcome::Panicked`]) its stack is provably gone, so `true`;
    /// - after a [`TeardownOutcome::TimedOut`] detach the thread is still
    ///   running and its handle was dropped, so it is unobservable; the honest
    ///   answer is `false`, not a claim that it will eventually complete.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        match &self.handle {
            // This code still owns the handle: ask the OS, independent of bookkeeping.
            Some(handle) => handle.is_finished(),
            // No handle. This code only *knows* it finished if this code actually joined it; a
            // timed-out detach leaves a live, unobservable thread, so `false`.
            None => matches!(
                self.outcome,
                Some(TeardownOutcome::Joined | TeardownOutcome::Panicked)
            ),
        }
    }

    /// Whether the out-of-band stop signal has been raised.
    #[must_use]
    pub fn stop_requested(&self) -> bool {
        self.stop.should_stop()
    }

    /// How many queued commands the worker discarded during teardown.
    #[must_use]
    pub fn drained_commands(&self) -> usize {
        self.drained.load(Ordering::Acquire)
    }

    /// How many commands the worker has begun executing.
    ///
    /// Lets a caller wait for a worker to be genuinely busy instead of sleeping
    /// a guessed interval.
    #[must_use]
    pub fn started_commands(&self) -> usize {
        self.started.load(Ordering::Acquire)
    }

    /// Block until the worker has begun at least `n` commands, or `timeout`
    /// elapses. Returns whether the target was reached.
    pub fn wait_for_started(&self, n: usize, timeout: Duration) -> bool {
        // An overflowing deadline means no deadline.
        let deadline = Instant::now().checked_add(timeout);
        loop {
            if self.started_commands() >= n {
                return true;
            }
            let now = Instant::now();
            if deadline.is_some_and(|deadline| now >= deadline) {
                return self.started_commands() >= n;
            }
            let sleep_for = deadline
                .map(|deadline| deadline.duration_since(now))
                .unwrap_or(Duration::from_millis(1));
            thread::sleep(Duration::from_millis(1).min(sleep_for));
        }
    }

    /// The outcome of a completed teardown, if this worker has been torn down.
    #[must_use]
    pub fn teardown_outcome(&self) -> Option<TeardownOutcome> {
        self.outcome
    }

    /// Signal out of band, disconnect, then join within the budget.
    ///
    /// The order is load-bearing:
    ///
    /// 1. raise the stop flag - a full queue cannot crowd this out, and the
    ///    worker abandons its backlog instead of executing it;
    /// 2. drop the sender - a worker parked in `recv()` wakes with no queue slot
    ///    required, which is exactly what an in-band `Shutdown` message cannot
    ///    promise;
    /// 3. wait up to the budget, then `join()`. Joining first would block for as
    ///    long as the backlog takes; waiting forever would wedge the UI.
    pub fn shutdown(&mut self) -> TeardownOutcome {
        if self.outcome.is_some() {
            return TeardownOutcome::AlreadyTornDown;
        }

        // 1. Out-of-band signal: an AtomicBool, never a queue message.
        self.stop.request_stop();
        // 2. Disconnect, so an idle worker wakes without a free queue slot.
        self.commands = None;

        let Some(handle) = self.handle.take() else {
            self.outcome = Some(TeardownOutcome::AlreadyTornDown);
            return TeardownOutcome::AlreadyTornDown;
        };

        // 3. Bounded wait, then join. `join()` after `is_finished()` returns at
        //    once; a worker that overruns is detached, never waited on forever.
        let deadline = Instant::now().checked_add(self.budget);
        while !handle.is_finished() {
            let now = Instant::now();
            if deadline.is_some_and(|d| now >= d) {
                self.outcome = Some(TeardownOutcome::TimedOut);
                drop(handle);
                return TeardownOutcome::TimedOut;
            }
            let sleep_for = deadline
                .map(|d| d.duration_since(now))
                .unwrap_or(Duration::from_millis(1));
            thread::sleep(Duration::from_millis(1).min(sleep_for));
        }
        let outcome = match handle.join() {
            Ok(()) => TeardownOutcome::Joined,
            Err(_) => TeardownOutcome::Panicked,
        };
        self.outcome = Some(outcome);
        outcome
    }
}

/// A forgotten handle still tears its worker down, on the same bounded path.
///
/// It cannot report anything, which is why [`CommandWorker::shutdown`] remains
/// the supported call, but it cannot leak the thread or block the UI either.
impl<C: Send + 'static> Drop for CommandWorker<C> {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Weak;

    /// A stand-in for the native state a real worker owns (session, profile
    /// store, display). The test holds only a `Weak`, so "released" is observed
    /// through the allocation being gone, not through a flag someone set.
    struct NativeResources {
        _payload: Vec<u8>,
    }

    fn resources() -> Arc<NativeResources> {
        Arc::new(NativeResources {
            _payload: vec![0u8; 4096],
        })
    }

    /// Every bound in these tests. A worker that ignores the stop flag must fail
    /// the assertion, not hang the binary.
    const BUDGET: Duration = Duration::from_millis(1_500);
    /// One command takes this long, so a saturated queue costs far more than the
    /// budget to execute - abandoning it is the only way to finish in time.
    const SLOW_COMMAND: Duration = Duration::from_millis(300);

    fn slow_worker(capacity: usize) -> (CommandWorker<Vec<u8>>, Weak<NativeResources>) {
        let owned = resources();
        let weak = Arc::downgrade(&owned);
        let worker = CommandWorker::spawn("teardown-test-slow", capacity, BUDGET, move |rx| {
            let held = owned;
            while let Some(command) = rx.next() {
                // Real work: bounded per command, oblivious to shutdown.
                thread::sleep(SLOW_COMMAND);
                drop(command);
            }
            drop(held);
        })
        .expect("spawn worker");
        (worker, weak)
    }

    /// Fill the bounded queue until it refuses, proving an in-band `Shutdown`
    /// message could not have been delivered on this path.
    fn saturate(worker: &CommandWorker<Vec<u8>>) -> usize {
        let mut sent = 0;
        loop {
            match worker.try_send(vec![7u8; 64]) {
                Ok(()) => sent += 1,
                Err(TrySendError::Full(_)) => return sent,
                Err(TrySendError::Disconnected(_)) => panic!("worker died before the queue filled"),
            }
            assert!(sent < 1_000, "a bounded queue must refuse eventually");
        }
    }

    #[test]
    fn full_queue_worker_tears_down_and_releases_resources_inside_the_budget() {
        let capacity = 8;
        let (mut worker, resources) = slow_worker(capacity);
        worker.try_send(vec![1u8; 8]).expect("first command queued");
        assert!(
            worker.wait_for_started(1, Duration::from_secs(2)),
            "the worker must be genuinely busy before teardown is meaningful"
        );
        let queued = saturate(&worker);
        assert!(queued >= capacity, "queued {queued} commands before Full");
        assert!(
            matches!(worker.try_send(vec![0u8; 1]), Err(TrySendError::Full(_))),
            "the queue must be saturated: an in-band Shutdown could not be sent"
        );
        // Positive control: the thread is alive right up to the teardown call.
        assert!(!worker.is_finished(), "the worker is still running");
        assert!(
            resources.upgrade().is_some(),
            "native resources are still held before teardown"
        );

        let backlog_cost = SLOW_COMMAND * u32::try_from(queued).expect("small");
        assert!(
            backlog_cost > BUDGET,
            "the backlog ({backlog_cost:?}) must exceed the budget ({BUDGET:?}), \
             otherwise draining it would pass this test"
        );

        let started = Instant::now();
        let outcome = worker.shutdown();
        let elapsed = started.elapsed();

        assert_eq!(outcome, TeardownOutcome::Joined, "took {elapsed:?}");
        assert!(
            elapsed < BUDGET,
            "teardown must finish inside its budget, took {elapsed:?}"
        );
        assert!(
            resources.upgrade().is_none(),
            "the joined worker released every native resource it owned"
        );
        assert!(
            worker.drained_commands() + 2 >= queued,
            "teardown drained the backlog: {} of {queued}",
            worker.drained_commands()
        );
        assert!(
            worker.started_commands() <= 3,
            "the {queued}-deep backlog must be abandoned, not executed; started {}",
            worker.started_commands()
        );
    }

    #[test]
    fn a_worker_that_ignores_the_signal_is_detached_rather_than_blocking_the_ui() {
        let budget = Duration::from_millis(150);
        let mut worker: CommandWorker<Vec<u8>> =
            CommandWorker::spawn("teardown-test-stuck", 2, budget, |_rx| {
                thread::sleep(Duration::from_millis(1_200));
            })
            .expect("spawn worker");
        let started = Instant::now();
        let outcome = worker.shutdown();
        let elapsed = started.elapsed();
        assert_eq!(outcome, TeardownOutcome::TimedOut);
        assert!(
            elapsed < Duration::from_millis(900),
            "an unresponsive worker must not wedge the caller, waited {elapsed:?}"
        );
        assert!(worker.stop_requested(), "the stop flag stays raised");
    }

    #[test]
    fn a_panicking_worker_is_still_joined() {
        let mut worker: CommandWorker<Vec<u8>> =
            CommandWorker::spawn("teardown-test-panic", 2, BUDGET, |_rx| {
                panic!("worker body failed");
            })
            .expect("spawn worker");
        let outcome = worker.shutdown();
        assert_eq!(outcome, TeardownOutcome::Panicked);
        assert!(outcome.is_joined());
    }
}
