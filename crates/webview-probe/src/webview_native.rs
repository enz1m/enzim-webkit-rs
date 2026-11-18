//! Real WPE page for the `webview` route: the native producer behind the same
//! view, bridge, and publication - real WebKit callbacks and pixels.
//!
//! Both builds share the API (`wpe` owns display, profile, session, snapshots;
//! otherwise typed refusals): real-vs-absent is a value, never a `cfg` path.

#[derive(Debug, Clone)]
pub(crate) enum BrowserAction {
    #[cfg_attr(
        not(feature = "wpe"),
        allow(
            dead_code,
            reason = "Only the native backend consumes navigation payloads"
        )
    )]
    Navigate(String),
    Back,
    Forward,
    Reload,
}

/// Deterministic page with known-offset fields and DOM focus reports in its title.
#[cfg(feature = "wpe")]
pub const PAGE_HTML: &str = "data:text/html,\
<!DOCTYPE html><html><head><title>init</title><style>\
html,body{margin:0;padding:0;background:rgb(18,22,34);width:100vw;height:100vh;\
font-family:sans-serif;color:rgb(232,232,240);}\
h1{font-size:26px;margin:18px 24px 8px 24px;}\
p{margin:0 24px 14px 24px;font-size:15px;color:rgb(168,176,200);}\
input{position:absolute;left:24px;width:420px;height:44px;font-size:22px;\
box-sizing:border-box;border:2px solid rgb(107,124,255);border-radius:6px;\
padding:4px 8px;}\
</style></head><body>\
<h1>Real WPE page (enzUI 1812)</h1>\
<p>text + password inputs; the box below requests cursor:progress</p>\
<input id='t' type='text' style='top:120px' placeholder='text field'>\
<input id='p' type='password' style='top:200px' placeholder='password field'>\
<div id='hover' style='position:absolute;left:24px;top:280px;width:420px;\
height:52px;background:rgb(34,51,51);border:2px dashed rgb(138,148,184);\
border-radius:6px;cursor:progress;line-height:52px;text-align:center;\
font-size:15px'>cursor: progress region</div>\
<script>\
var log='',tabIssued=0,tabAck=0,tabPrevented=0;\
function report(tag){\
  log=log+tag+',';\
  var a=document.activeElement;\
  var id=(a&&a.id)?a.id:'none';\
  var v=(a&&a.value!==undefined)?a.value:'';\
  var s=(a&&a.selectionStart!==undefined&&a.selectionStart!==null)?a.selectionStart:-1;\
  document.title='tf:'+tabAck+':'+tabPrevented+':'+id+'|'+tag+'|'+id+'|'+v+'|'+s;\
}\
document.addEventListener('keydown',function(ev){\
  if(ev.key!=='Tab')return;\
  var serial=++tabIssued;\
  var was=document.activeElement;\
  setTimeout(function(){\
    if(was&&was.tagName==='INPUT'&&document.activeElement===document.body){\
      was.focus();\
    }\
    tabAck=serial;tabPrevented=ev.defaultPrevented?1:0;report('taback');\
  },0);\
},true);\
var els=[document.getElementById('t'),document.getElementById('p')];\
for(var i=0;i<els.length;i++){\
  var e=els[i];\
  e.addEventListener('focus',function(){report('focus');});\
  e.addEventListener('blur',function(){report('blur');});\
  e.addEventListener('input',function(){report('input');});\
  e.addEventListener('compositionstart',function(){report('compstart');});\
  e.addEventListener('compositionupdate',function(ev){\
    report('compupdate:'+ev.data);\
    setTimeout(function(){report('settled');},0);});\
  e.addEventListener('compositionend',function(ev){report('compend:'+ev.data);});\
}\
report('load');\
</script></body></html>";

/// CSS top offsets for aimed clicks (text, password, progress region); height
/// aims at field middles.
pub const TEXT_TOP: f32 = 120.0;
pub const PASSWORD_TOP: f32 = 200.0;
pub const HOVER_TOP: f32 = 280.0;
pub const FIELD_HEIGHT: f32 = 44.0;

/// A typed refusal to dispatch a native page bootstrap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeOpenError {
    /// Process-long execution lane unstartable or dead.
    #[cfg(feature = "wpe")]
    DispatchUnavailable(String),
    /// Preceding page overran its close budget and still owns the lane.
    #[cfg(feature = "wpe")]
    PreviousPageStillReleasing,
    /// No native WPE backend in this build.
    #[cfg(not(feature = "wpe"))]
    BackendUnavailable,
}

impl core::fmt::Display for NativeOpenError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            #[cfg(feature = "wpe")]
            Self::DispatchUnavailable(detail) => {
                write!(f, "native WPE dispatch unavailable: {detail}")
            }
            #[cfg(feature = "wpe")]
            Self::PreviousPageStillReleasing => write!(
                f,
                "native WPE dispatch refused within its bounded handoff: the previous page is still releasing"
            ),
            #[cfg(not(feature = "wpe"))]
            Self::BackendUnavailable => write!(
                f,
                "no native backend: this probe was built without `--features wpe`; no mock was substituted"
            ),
        }
    }
}

impl std::error::Error for NativeOpenError {}

/// Typed worker failure: structure retained so callers distinguish bootstrap,
/// title refusal, and command failures. Feature-off carries `Command` alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeWorkerError {
    /// Display/session/profile bootstrap never completed.
    #[cfg(feature = "wpe")]
    Bootstrap { stage: &'static str, detail: String },
    /// Page-controlled title over the native byte ceiling.
    #[cfg(feature = "wpe")]
    PageTitle {
        /// Pre-NUL bytes observed by the bounded reader.
        observed_bytes: usize,
        /// Accepted native-byte ceiling.
        max_bytes: usize,
    },
    /// Already-open page's work failed.
    Command {
        operation: &'static str,
        detail: String,
    },
}

impl core::fmt::Display for NativeWorkerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            #[cfg(feature = "wpe")]
            Self::Bootstrap { stage, detail } => write!(f, "native bootstrap {stage}: {detail}"),
            #[cfg(feature = "wpe")]
            Self::PageTitle {
                observed_bytes,
                max_bytes,
            } => write!(
                f,
                "native page title exceeds {max_bytes} bytes; observed at least {observed_bytes}"
            ),
            Self::Command { operation, detail } => {
                write!(f, "native command {operation}: {detail}")
            }
        }
    }
}

#[cfg(feature = "wpe")]
impl From<enzui_webkit::ffi::runtime::PageTitleError> for NativeWorkerError {
    fn from(error: enzui_webkit::ffi::runtime::PageTitleError) -> Self {
        match error {
            enzui_webkit::ffi::runtime::PageTitleError::TooLong {
                observed_bytes,
                max_bytes,
            } => Self::PageTitle {
                observed_bytes,
                max_bytes,
            },
        }
    }
}

// First error wins (title sampled before commands finish): outside `mod real`
// so precedence stays testable feature-off.
#[cfg_attr(not(feature = "wpe"), allow(dead_code))]
pub(crate) fn add_command_error(
    update: &mut NativeUpdate,
    operation: &'static str,
    detail: String,
) {
    if update.error.is_none() {
        update.error = Some(NativeWorkerError::Command { operation, detail });
    }
}

/// Complete frame-independent state; absent fields explicitly clear their value.
#[derive(Debug, Default)]
pub struct NativeMetadata {
    pub cursor: Option<String>,
    pub dom_report: Option<String>,
    pub location: Option<String>,
}

/// Coalesced worker notification. No GLib/WebKit work happens while iced holds
/// this value.
#[derive(Debug)]
pub struct NativeUpdate {
    pub view: enzui_webkit::web::ViewId,
    pub report: Option<enzui_webkit::ime_bridge::NativeImeReport>,
    pub metadata: Option<std::sync::Arc<NativeMetadata>>,
    pub frame: Option<Result<enzui_core::media::Rgba8Frame, String>>,
    pub gpu_frame: Option<enzui_webview::gpu::GpuFrame>,
    pub tab_reply: Option<(
        enzui_webkit::web::Generation,
        enzui_webkit::web::focus::TabReply,
    )>,
    /// Session clipboard result, typed never bare: `Copied`/`Pasted`/`Refused`
    /// are different answers a host surfaces differently.
    pub clipboard: Option<enzui_webkit::ClipboardOutcome>,
    /// Native WPE focus sampled after this update's work.
    pub view_focused: Option<bool>,
    pub error: Option<NativeWorkerError>,
}

/// Queued-notification bound: key/motion floods cannot grow memory.
#[cfg_attr(not(feature = "wpe"), allow(dead_code))]
pub(crate) const UPDATE_CAP: usize = 8;

/// Terminal-fallback bound: deduplicating, oldest-first evicted - pathological
/// floods cannot grow memory.
#[cfg_attr(not(feature = "wpe"), allow(dead_code))]
pub(crate) const PENDING_TERMINAL_CAP: usize = 16;

/// Terminal input accepted post-saturation with its monotone `seq`: ordered
/// against all other admissions, so both queues interleave without inversion.
#[cfg_attr(not(feature = "wpe"), allow(dead_code))]
#[derive(Debug, Clone)]
pub(crate) struct PendingTerminal {
    pub(crate) seq: u64,
    pub(crate) event: enzui_webkit::input::InputEvent,
}

/// Serialized admission for every worker command: bounded channel plus terminal-only
/// fallback (lost terminals grab WebKit) - one mutex, one total order by `seq`.
#[cfg_attr(not(feature = "wpe"), allow(dead_code))]
#[derive(Debug, Default)]
pub(crate) struct Admission {
    next_seq: u64,
    pending: std::collections::VecDeque<PendingTerminal>,
}

#[cfg_attr(not(feature = "wpe"), allow(dead_code))]
impl Admission {
    /// Next monotone admission sequence; call under the lock that will `try_send`
    /// or push, so both queues share one total order.
    pub(crate) fn assign_seq(&mut self) -> u64 {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        seq
    }

    /// Push a terminal fallback entry: dedupes in-flight, evicts oldest. The bool
    /// keeps sibling counters consistent with single-`FocusLost` bookkeeping.
    pub(crate) fn push_pending(
        &mut self,
        seq: u64,
        event: enzui_webkit::input::InputEvent,
    ) -> bool {
        if self.pending.iter().any(|p| p.event == event) {
            return false;
        }
        if self.pending.len() == PENDING_TERMINAL_CAP {
            self.pending.pop_front();
        }
        self.pending.push_back(PendingTerminal { seq, event });
        true
    }

    /// Take pending terminals with `seq` below `exclusive_seq`, ascending: they
    /// entered admission first, so they run before that ordinary.
    pub(crate) fn drain_before(&mut self, exclusive_seq: u64) -> Vec<PendingTerminal> {
        // Same-lock atomic seq plus same-section push: the fallback stays
        // seq-monotone, so a front prefix suffices.
        let mut out = Vec::new();
        while let Some(front) = self.pending.front() {
            if front.seq >= exclusive_seq {
                break;
            }
            out.push(self.pending.pop_front().expect("front just observed"));
        }
        out
    }

    /// Take all remaining pending terminals, ascending: only safe when no
    /// smaller-seq ordinary can still be in flight.
    pub(crate) fn drain_all(&mut self) -> Vec<PendingTerminal> {
        self.pending.drain(..).collect()
    }

    #[cfg(test)]
    pub(crate) fn pending_len(&self) -> usize {
        self.pending.len()
    }
}

/// Worker payload tagged with its admission `seq`. Generic so production
/// `Command` and test `InputEvent` drive the same arbitrator.
#[cfg_attr(not(feature = "wpe"), allow(dead_code))]
#[derive(Debug)]
pub(crate) struct SeqCmd<T> {
    pub(crate) seq: u64,
    pub(crate) cmd: T,
}

/// One nonblocking arbitrator turn: ready work covered, `Idle` hands blocking
/// to the caller - no path holds the admission lock across a blocking call.
#[cfg_attr(not(feature = "wpe"), allow(dead_code))]
#[derive(Debug)]
pub(crate) enum ArbitrationStep<T> {
    /// Ordinary hot path: terminals in order, then `cmd` (`terminals` may be empty).
    Execute {
        terminals: Vec<PendingTerminal>,
        cmd: SeqCmd<T>,
    },
    /// No ordinary pending and terminals have no unrun causal predecessor.
    Drain { terminals: Vec<PendingTerminal> },
    /// Nothing ready: block, then feed through `drain_before_cmd` so
    /// blocked-while terminals still run first.
    Idle,
    /// Disconnected: the caller must exit.
    Disconnected,
}

/// One arbitration turn: no cross-queue inversion, no empty-race inversion
/// (re-poll under the lock), nonblocking throughout.
#[cfg_attr(not(feature = "wpe"), allow(dead_code))]
pub(crate) fn arbitrate_step<T>(
    rx: &std::sync::mpsc::Receiver<SeqCmd<T>>,
    admission: &std::sync::Mutex<Admission>,
) -> ArbitrationStep<T> {
    // Fast path: peek without the mutex - the common ready case saves one
    // acquisition per turn.
    match rx.try_recv() {
        Ok(sc) => {
            let terminals = admission
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .drain_before(sc.seq);
            ArbitrationStep::Execute { terminals, cmd: sc }
        }
        Err(std::sync::mpsc::TryRecvError::Disconnected) => ArbitrationStep::Disconnected,
        Err(std::sync::mpsc::TryRecvError::Empty) => arbitrate_empty_branch(rx, admission),
    }
}

/// Empty-branch half, test-callable: re-polls under the lock; `drain_all` only
/// when empty under it. Nonblocking (`try_recv` only).
#[cfg_attr(not(feature = "wpe"), allow(dead_code))]
pub(crate) fn arbitrate_empty_branch<T>(
    rx: &std::sync::mpsc::Receiver<SeqCmd<T>>,
    admission: &std::sync::Mutex<Admission>,
) -> ArbitrationStep<T> {
    let mut adm = admission.lock().unwrap_or_else(|p| p.into_inner());
    match rx.try_recv() {
        Ok(sc) => {
            // In-between submit: its `seq` is authoritative - drain only earlier
            // terminals.
            let terminals = adm.drain_before(sc.seq);
            ArbitrationStep::Execute { terminals, cmd: sc }
        }
        Err(std::sync::mpsc::TryRecvError::Disconnected) => {
            let terminals = adm.drain_all();
            if terminals.is_empty() {
                ArbitrationStep::Disconnected
            } else {
                ArbitrationStep::Drain { terminals }
            }
        }
        Err(std::sync::mpsc::TryRecvError::Empty) => {
            // Truly empty under the lock: no lower-seq ordinary can exist, so
            // `drain_all` cannot invert.
            let terminals = adm.drain_all();
            if terminals.is_empty() {
                ArbitrationStep::Idle
            } else {
                ArbitrationStep::Drain { terminals }
            }
        }
    }
}

/// Drain terminals admitted before `cmd.seq`: blocked-while pushes with lower
/// `seq` still run first.
#[cfg_attr(not(feature = "wpe"), allow(dead_code))]
pub(crate) fn drain_before_cmd<T>(
    cmd: &SeqCmd<T>,
    admission: &std::sync::Mutex<Admission>,
) -> Vec<PendingTerminal> {
    admission
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .drain_before(cmd.seq)
}

/// What the shared admission helper did. Positive variants keep sibling
/// bookkeeping (`blur_requests`) from desyncing with admission state.
#[cfg_attr(not(feature = "wpe"), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TerminalFallbackOutcome {
    /// Ordinary channel took it; no fallback push.
    ChannelAccepted,
    /// Channel full; fallback captured a fresh terminal.
    FallbackAdded,
    /// Channel full and an identical terminal already queued (repeated `FocusLost`:
    /// historical single-event bookkeeping).
    FallbackDuplicate,
    /// The channel is disconnected. The caller must exit or drop.
    Disconnected,
}

/// Shared admission seam for distinct channel/fallback payloads under one `seq`:
/// tests and production share every step - defects redden both. Nonblocking.
#[cfg_attr(not(feature = "wpe"), allow(dead_code))]
pub(crate) fn admit_with_terminal_fallback<T>(
    admission: &std::sync::Mutex<Admission>,
    make_channel_cmd: impl FnOnce(u64) -> T,
    fallback_event: enzui_webkit::input::InputEvent,
    try_send: impl FnOnce(SeqCmd<T>) -> Result<(), std::sync::mpsc::TrySendError<SeqCmd<T>>>,
) -> TerminalFallbackOutcome {
    let mut adm = admission.lock().unwrap_or_else(|p| p.into_inner());
    let seq = adm.assign_seq();
    let cmd = make_channel_cmd(seq);
    match try_send(SeqCmd { seq, cmd }) {
        Ok(()) => TerminalFallbackOutcome::ChannelAccepted,
        Err(std::sync::mpsc::TrySendError::Full(_)) => {
            if adm.push_pending(seq, fallback_event) {
                TerminalFallbackOutcome::FallbackAdded
            } else {
                TerminalFallbackOutcome::FallbackDuplicate
            }
        }
        Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {
            TerminalFallbackOutcome::Disconnected
        }
    }
}

impl NativeUpdate {
    /// Command answer, never ordinary traffic: single-query replies and clipboard
    /// outcomes (refusals included) never regenerate.
    #[cfg_attr(not(feature = "wpe"), allow(dead_code))]
    pub(crate) fn is_command_answer(&self) -> bool {
        self.tab_reply.is_some() || self.clipboard.is_some()
    }
}

/// Bounded push: evict the oldest non-answer; only an all-answers queue loses its
/// oldest answer. Pure and unconditional - pressure-testable feature-off.
#[cfg_attr(not(feature = "wpe"), allow(dead_code))]
pub(crate) fn push_bounded(
    queue: &mut std::collections::VecDeque<NativeUpdate>,
    update: NativeUpdate,
) {
    if queue.len() >= UPDATE_CAP {
        let remove = queue
            .iter()
            .position(|u| !u.is_command_answer())
            .unwrap_or(0);
        queue.remove(remove);
    }
    queue.push_back(update);
}

// A nonzero state completes teardown; zero waits until the bounded deadline.
#[cfg(feature = "wpe")]
fn wait_for_page_completion(
    completed: &std::sync::atomic::AtomicU8,
    budget: std::time::Duration,
) -> u8 {
    use std::sync::atomic::Ordering;
    use std::time::{Duration, Instant};

    use enzui_core::monotonic_ms::{Policy, checked_instant_deadline};

    let deadline = checked_instant_deadline(Instant::now(), budget, Policy::Clamp);
    loop {
        let state = completed.load(Ordering::Acquire);
        if state != 0 {
            return state;
        }
        let now = Instant::now();
        if deadline.is_some_and(|d| now >= d) {
            return 0;
        }
        let sleep_for = deadline
            .map(|d| d.duration_since(now))
            .unwrap_or(Duration::from_millis(1));
        std::thread::sleep(Duration::from_millis(1).min(sleep_for));
    }
}

#[cfg(feature = "wpe")]
type NativeWakeTx = iced::futures::channel::mpsc::Sender<()>;
#[cfg(feature = "wpe")]
type NativeWakeRx = iced::futures::channel::mpsc::Receiver<()>;
#[cfg(feature = "wpe")]
static NATIVE_WAKE_TX: std::sync::OnceLock<std::sync::Mutex<NativeWakeTx>> =
    std::sync::OnceLock::new();
#[cfg(feature = "wpe")]
static NATIVE_WAKE_RX: std::sync::Mutex<Option<NativeWakeRx>> = std::sync::Mutex::new(None);

#[cfg(feature = "wpe")]
fn init_native_wake() {
    NATIVE_WAKE_TX.get_or_init(|| {
        // Capacity-one coalescing: one pending wake carries no more than the drain
        // already will.
        let (tx, rx) = iced::futures::channel::mpsc::channel(1);
        *NATIVE_WAKE_RX.lock().expect("native wake receiver") = Some(rx);
        std::sync::Mutex::new(tx)
    });
}

#[cfg(feature = "wpe")]
thread_local! {
    static OWNER_DISPATCH: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(feature = "wpe")]
fn wake_native_worker() {
    if OWNER_DISPATCH.with(std::cell::Cell::get) {
        return;
    }
    init_native_wake();
    if let Some(tx) = NATIVE_WAKE_TX.get() {
        let _ = tx.lock().unwrap_or_else(|p| p.into_inner()).try_send(());
    }
}

/// A quiet, bounded subscription woken by the dedicated WPE thread. It polls
/// neither frames nor GLib; one wake drains all coalesced worker notifications.
#[cfg(feature = "wpe")]
pub fn notification_subscription() -> iced::Subscription<()> {
    init_native_wake();
    iced::Subscription::run(|| {
        use iced::futures::StreamExt;
        let rx = NATIVE_WAKE_RX.lock().ok().and_then(|mut slot| slot.take());
        match rx {
            Some(rx) => rx.boxed(),
            None => iced::futures::stream::pending().boxed(),
        }
    })
}

/// Feature-off has no native worker and therefore no wake source.
#[cfg(not(feature = "wpe"))]
pub fn notification_subscription() -> iced::Subscription<()> {
    iced::Subscription::none()
}

#[cfg(feature = "wpe")]
mod real {
    use std::collections::VecDeque;
    use std::path::PathBuf;
    #[cfg(test)]
    use std::sync::atomic::AtomicBool;
    use std::sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool as StopBool, AtomicU8, AtomicUsize, Ordering},
        mpsc,
    };
    use std::time::Duration;

    use enzui_core::media::{Generation as MediaGeneration, Rgba8Frame};
    use enzui_webkit::clipboard_route::{ClipboardOutcome, HostGesture};
    use enzui_webkit::ffi::profile::ProfileStore;
    use enzui_webkit::ffi::runtime::{HeadlessDisplay, PendingPageCopy, WebSession};
    use enzui_webkit::ime_bridge::ImeEffect;
    use enzui_webkit::input::{self, InputEvent, PointerButton, ViewportMapping};
    use enzui_webkit::web::Traversal;
    use enzui_webkit::web::focus::TabReply;
    use enzui_webkit::web::frame::FrameSeq;
    use enzui_webkit::web::{Generation as FocusGeneration, ViewId, ViewRouter, WebProfile};

    use crate::webview_scratch::SecureScratch;

    const COMMAND_CAP: usize = 32;
    const INPUT_FRAME_INTERVAL: Duration = Duration::from_millis(50);
    /// Page-drop join budget. Every worker command is itself bounded, so a live
    /// worker exits well inside; overruns report, never block the UI thread.
    const TEARDOWN_BUDGET: Duration = Duration::from_millis(2_500);

    use super::{
        Admission, ArbitrationStep, NativeOpenError, NativeUpdate, NativeWorkerError, SeqCmd,
        TerminalFallbackOutcome, UPDATE_CAP, admit_with_terminal_fallback, arbitrate_step,
        drain_before_cmd, push_bounded,
    };

    /// `SeqCmd<Command>`: the production instantiation of the unconditional seam.
    type PageSeqCmd = SeqCmd<Command>;

    enum Command {
        Browse {
            view: ViewId,
            action: super::BrowserAction,
        },
        Input {
            event: InputEvent,
            tab_query: Option<(FocusGeneration, Traversal)>,
        },
        Resize {
            view: ViewId,
            size: enzui_webkit::ViewportSize,
        },
        Click {
            view: ViewId,
            x: f32,
            y: f32,
        },
        Hover {
            view: ViewId,
            x: f32,
            y: f32,
        },
        Apply {
            view: ViewId,
            effect: ImeEffect,
        },
        /// Copy the page's selection out to the host clipboard.
        CopyToHost {
            view: ViewId,
            gesture: HostGesture,
        },
        /// Publish host text and paste it into the focused DOM field.
        PasteFromHost {
            view: ViewId,
            gesture: HostGesture,
            text: String,
        },
        Recreate {
            router: ViewRouter,
            view: ViewId,
            size: Option<enzui_webkit::ViewportSize>,
        },
        FocusOut {
            view: ViewId,
        },
        Visibility {
            view: ViewId,
            visible: bool,
        },
    }

    // No in-band `Shutdown` (a full queue discards exactly that): teardown uses
    // the out-of-band stop flag.

    /// Process-long owner-free lane for thread-affine GLib: dispatch binds to the
    /// first thread, so the lane survives pages while jobs still die on close.
    struct WpeLane {
        jobs: mpsc::SyncSender<Box<dyn FnOnce() + Send>>,
        busy: Arc<StopBool>,
        on_main: bool,
    }

    type MainJob = Box<dyn FnOnce() + Send>;
    static MAIN_JOBS: OnceLock<Mutex<mpsc::Receiver<MainJob>>> = OnceLock::new();
    std::thread_local! {
        static MAIN_TASK: std::cell::RefCell<Option<MainTask>> = const { std::cell::RefCell::new(None) };
    }

    struct MainTask {
        task: Option<WorkerLoop>,
        completed: Arc<AtomicU8>,
        busy: Arc<StopBool>,
        panicked: bool,
    }
    impl Drop for MainTask {
        fn drop(&mut self) {
            self.task = None;
            self.busy.store(false, Ordering::Release);
            self.completed
                .store(if self.panicked { 2 } else { 1 }, Ordering::Release);
        }
    }

    pub(super) fn main_dispatch_needed() -> bool {
        WPE_LANE
            .get()
            .and_then(|lane| lane.as_ref().ok())
            .is_some_and(|lane| lane.on_main && lane.busy.load(Ordering::Acquire))
            || enzui_webkit::ffi::presentation::pending_gpu_frame_completions() != 0
                && enzui_webkit::ffi::native_requires_process_main_thread()
    }

    static MAIN_WATCHER: OnceLock<Option<enzui_core::native_loop::NativeLoop>> = OnceLock::new();
    static WATCHER_FAILED: StopBool = StopBool::new(false);

    fn main_interest() -> Option<enzui_core::native_loop::Interest> {
        let native = enzui_webkit::ffi::native_event_interest().ok()?;
        let (input_due, import_due) = MAIN_TASK.with(|slot| {
            let task = slot.borrow();
            task.as_ref()
                .and_then(|task| task.task.as_ref())
                .map(|task| {
                    let now = std::time::Instant::now();
                    let input_due = crate::native_interest::publication_deadline(
                        task.input_frame_due,
                        task.worker.publication_pending(),
                        now,
                    );
                    let import_due = crate::native_interest::gpu_import_deadline(
                        task.worker.gpu_last.as_ref().map(|frame| frame.status()),
                        task.worker.gpu_negotiating_until,
                        task.worker.visible,
                        now,
                    );
                    let copy_due = task
                        .worker
                        .pending_copy
                        .as_ref()
                        .and_then(PendingPageCopy::deadline);
                    let input_due = match (input_due, copy_due) {
                        (Some(input), Some(copy)) => Some(input.min(copy)),
                        (input, copy) => input.or(copy),
                    };
                    (input_due, import_due)
                })
                .unwrap_or((None, None))
        });
        Some(crate::native_interest::compose(
            native,
            input_due,
            import_due,
            std::time::Instant::now(),
        ))
    }

    fn arm_main_watcher() -> bool {
        let Some(Some(watcher)) = MAIN_WATCHER.get() else {
            return false;
        };
        let Some(interest) = main_interest() else {
            return false;
        };
        watcher.arm(interest);
        true
    }

    pub(super) fn native_subscription() -> Option<iced::Subscription<()>> {
        static ENABLED: OnceLock<bool> = OnceLock::new();
        if !*ENABLED.get_or_init(|| {
            std::env::var_os("ENZUI_PROBE_NATIVE_READINESS").is_none_or(|v| v != "0")
        }) || WATCHER_FAILED.load(Ordering::Acquire)
        {
            return None;
        }
        MAIN_WATCHER.get_or_init(|| enzui_core::native_loop::NativeLoop::new().ok());
        if !arm_main_watcher() {
            return None;
        }
        Some(MAIN_WATCHER.get()?.as_ref()?.subscription(|ready| {
            if ready == enzui_core::native_loop::NativeReady::Unavailable {
                WATCHER_FAILED.store(true, Ordering::Release);
            }
        }))
    }

    pub(super) fn dispatcher_available() -> bool {
        static ENABLED: OnceLock<bool> = OnceLock::new();
        *ENABLED.get_or_init(|| {
            std::env::var_os("ENZUI_PROBE_NATIVE_DISPATCH").is_none_or(|value| value != "0")
        }) && !WATCHER_FAILED.load(Ordering::Acquire)
            && MAIN_WATCHER.get().is_some_and(Option::is_some)
    }

    pub(super) fn dispatcher<'a, Message: 'a>(
        dispatch: impl Fn(bool) -> Option<Message> + 'a,
    ) -> Option<iced::Element<'a, Message>> {
        if !dispatcher_available() {
            return None;
        }
        let watcher = MAIN_WATCHER.get()?.as_ref()?;
        Some(
            watcher
                .dispatcher(move |ready| {
                    let unavailable = ready == enzui_core::native_loop::NativeReady::Unavailable;
                    if unavailable {
                        WATCHER_FAILED.store(true, Ordering::Release);
                    }
                    struct Reset(bool);
                    impl Drop for Reset {
                        fn drop(&mut self) {
                            super::OWNER_DISPATCH.with(|active| active.set(self.0));
                        }
                    }
                    let _reset = Reset(super::OWNER_DISPATCH.with(|active| active.replace(true)));
                    dispatch(unavailable)
                })
                .into(),
        )
    }

    pub(super) fn main_dispatch_interval() -> Duration {
        MAIN_TASK.with(|slot| {
            if slot
                .borrow()
                .as_ref()
                .and_then(|task| task.task.as_ref())
                .is_some_and(|task| {
                    task.worker.last_activity.elapsed() >= Duration::from_millis(100)
                })
            {
                Duration::from_millis(50)
            } else {
                Duration::from_millis(8)
            }
        })
    }

    pub(super) fn pump_main_thread() {
        if !main_dispatch_needed() {
            return;
        }
        if enzui_webkit::ffi::dispatch_pending_native_events().is_err() {
            return;
        }
        if let Some(jobs) = MAIN_JOBS.get() {
            let job = jobs.lock().ok().and_then(|jobs| jobs.try_recv().ok());
            if let Some(job) = job {
                job();
            }
        }
        MAIN_TASK.with(|slot| {
            let mut task = slot.borrow_mut().take();
            if let Some(active) = task.as_mut() {
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    active
                        .task
                        .as_mut()
                        .is_some_and(|worker| worker.step(false))
                })) {
                    Ok(true) => *slot.borrow_mut() = task,
                    Ok(false) => {}
                    Err(_) => active.panicked = true,
                }
            }
        });
        let _ = enzui_webkit::ffi::dispatch_pending_native_events();
        arm_main_watcher();
    }

    static WPE_LANE: OnceLock<Result<WpeLane, NativeOpenError>> = OnceLock::new();

    fn wpe_lane() -> Result<&'static WpeLane, NativeOpenError> {
        WPE_LANE
            .get_or_init(|| {
                let (jobs, rx) = mpsc::sync_channel::<Box<dyn FnOnce() + Send>>(1);
                let busy = Arc::new(StopBool::new(false));
                if enzui_webkit::ffi::native_requires_process_main_thread() {
                    let _ = MAIN_JOBS.set(Mutex::new(rx));
                    return Ok(WpeLane {
                        jobs,
                        busy,
                        on_main: true,
                    });
                }
                std::thread::Builder::new()
                    .name("enzui-wpe-lane".to_owned())
                    .spawn(move || {
                        loop {
                            let job =
                                if enzui_webkit::ffi::presentation::pending_gpu_frame_completions()
                                    == 0
                                {
                                    match rx.recv() {
                                        Ok(job) => Some(job),
                                        Err(_) => break,
                                    }
                                } else {
                                    match rx.recv_timeout(Duration::from_millis(8)) {
                                        Ok(job) => Some(job),
                                        Err(mpsc::RecvTimeoutError::Timeout) => None,
                                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                                    }
                                };
                            if let Some(job) = job {
                                job();
                            }
                            let _ = enzui_webkit::ffi::dispatch_pending_native_events();
                        }
                    })
                    .map_err(|error| {
                        NativeOpenError::DispatchUnavailable(format!(
                            "spawn persistent WPE dispatch lane: {error}"
                        ))
                    })?;
                Ok(WpeLane {
                    jobs,
                    busy,
                    on_main: false,
                })
            })
            .as_ref()
            .map_err(Clone::clone)
    }

    /// Ordinary channel receiver plus shared stop flag: stop-flag policy lives
    /// here, not in the arbitrator - blocking `recv` still exits on shutdown.
    struct PageReceiver {
        commands: mpsc::Receiver<PageSeqCmd>,
        stop: Arc<StopBool>,
    }

    impl PageReceiver {
        /// Stop-flag check before the crank: shutdown short-circuits pre-mutex.
        fn stop_raised(&self) -> bool {
            self.stop.load(Ordering::Acquire)
        }

        /// Post-shutdown backlog discard on every exit: saturated pre-stop queues
        /// abandon, never execute after teardown.
        fn drain_after_stop(&self) {
            while self.commands.try_recv().is_ok() {}
        }

        /// Idle-only blocking wait: `None` on stop or disconnect.
        fn wait(&self) -> Option<PageSeqCmd> {
            if self.stop_raised() {
                self.drain_after_stop();
                return None;
            }
            match self.commands.recv() {
                Ok(command) if !self.stop_raised() => Some(command),
                Ok(_) | Err(_) => {
                    self.drain_after_stop();
                    None
                }
            }
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum PageTeardownOutcome {
        Completed,
        Panicked,
        TimedOut,
        AlreadyTornDown,
    }

    impl PageTeardownOutcome {
        fn completed(self) -> bool {
            matches!(self, Self::Completed | Self::Panicked)
        }
    }

    /// Per-page endpoint torn down on close; body runs on the lane, so later pages
    /// bootstrap on the same OS thread.
    struct PageWorker {
        commands: Option<mpsc::SyncSender<PageSeqCmd>>,
        stop: Arc<StopBool>,
        /// 0 running/queued, 1 completed, 2 panicked - stored only after native
        /// state and scratch lease drop.
        completed: Arc<AtomicU8>,
        budget: Duration,
        outcome: Option<PageTeardownOutcome>,
        on_main: bool,
    }

    impl PageWorker {
        fn dispatch(
            budget: Duration,
            body: impl FnOnce(PageReceiver) + Send + 'static,
        ) -> Result<Self, NativeOpenError> {
            Self::dispatch_job(budget, move |receiver, completed, busy| {
                let result =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| body(receiver)));
                busy.store(false, Ordering::Release);
                completed.store(if result.is_ok() { 1 } else { 2 }, Ordering::Release);
            })
        }

        fn dispatch_main(
            budget: Duration,
            factory: impl FnOnce(PageReceiver) -> Option<WorkerLoop> + Send + 'static,
        ) -> Result<Self, NativeOpenError> {
            Self::dispatch_job(budget, move |receiver, completed, busy| {
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| factory(receiver))) {
                    Ok(Some(task)) => MAIN_TASK.with(|slot| {
                        *slot.borrow_mut() = Some(MainTask {
                            task: Some(task),
                            completed,
                            busy,
                            panicked: false,
                        })
                    }),
                    result => {
                        busy.store(false, Ordering::Release);
                        completed.store(if result.is_ok() { 1 } else { 2 }, Ordering::Release);
                    }
                }
            })
        }

        fn dispatch_job(
            budget: Duration,
            body: impl FnOnce(PageReceiver, Arc<AtomicU8>, Arc<StopBool>) + Send + 'static,
        ) -> Result<Self, NativeOpenError> {
            let lane = wpe_lane()?;
            lane.busy
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .map_err(|_| NativeOpenError::PreviousPageStillReleasing)?;
            let lane_busy = Arc::clone(&lane.busy);
            let (commands, rx) = mpsc::sync_channel(COMMAND_CAP);
            let stop = Arc::new(StopBool::new(false));
            let worker_stop = Arc::clone(&stop);
            let completed = Arc::new(AtomicU8::new(0));
            let worker_completed = Arc::clone(&completed);
            let job = Box::new(move || {
                body(
                    PageReceiver {
                        commands: rx,
                        stop: worker_stop,
                    },
                    worker_completed,
                    lane_busy,
                );
            });
            if let Err(error) = lane.jobs.try_send(job) {
                lane.busy.store(false, Ordering::Release);
                return Err(match error {
                    mpsc::TrySendError::Full(_) => NativeOpenError::PreviousPageStillReleasing,
                    mpsc::TrySendError::Disconnected(_) => NativeOpenError::DispatchUnavailable(
                        "persistent WPE dispatch lane terminated".to_owned(),
                    ),
                });
            }
            if lane.on_main {
                super::wake_native_worker();
                enzui_webkit::ffi::wake_native_event_loop();
            }
            Ok(Self {
                commands: Some(commands),
                stop,
                completed,
                budget,
                outcome: None,
                on_main: lane.on_main,
            })
        }

        fn try_send(&self, command: PageSeqCmd) -> Result<(), mpsc::TrySendError<PageSeqCmd>> {
            let result = match &self.commands {
                Some(commands) => commands.try_send(command),
                None => Err(mpsc::TrySendError::Disconnected(command)),
            };
            if self.on_main {
                super::wake_native_worker();
                enzui_webkit::ffi::wake_native_event_loop();
            }
            result
        }

        fn shutdown(&mut self) -> PageTeardownOutcome {
            if self.outcome.is_some() {
                return PageTeardownOutcome::AlreadyTornDown;
            }
            self.stop.store(true, Ordering::Release);
            self.commands = None;
            if self.on_main {
                pump_main_thread();
                super::wake_native_worker();
            }
            let completed = super::wait_for_page_completion(&self.completed, self.budget);
            let outcome = match completed {
                1 => {
                    // Frame-completion sources can outlive the session and finish on this same lane.
                    PageTeardownOutcome::Completed
                }
                2 => PageTeardownOutcome::Panicked,
                _ => PageTeardownOutcome::TimedOut,
            };
            self.outcome = Some(outcome);
            outcome
        }
    }

    /// UI-side handle: thread-affine objects live only in the page job.
    pub struct NativePage {
        /// Queue-and-stop owner: drop signals, drains, and bounded-waits native
        /// release; timed-out detached jobs keep their scratch lease, the lane stays.
        worker: PageWorker,
        updates: Arc<Mutex<VecDeque<NativeUpdate>>>,
        /// Per-page admission and fallback: one lock assigns `seq` and pushes;
        /// the worker interleaves off it - releases never precede presses.
        admission: Arc<Mutex<Admission>>,
        /// Accepted UI blur requests: test-visible, so stale replies provably cause
        /// no focus side effect.
        blur_requests: Arc<AtomicUsize>,
        /// Timeout-gate witness: set by `drop` on overrun-detach; production pages
        /// stay `None` and report via `eprintln!`.
        #[cfg(test)]
        teardown_timed_out: Option<Arc<AtomicBool>>,
    }

    impl core::fmt::Debug for NativePage {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str("NativePage(bounded WPE worker)")
        }
    }

    impl NativePage {
        pub fn open(
            router: &ViewRouter,
            view: ViewId,
            scratch: Arc<SecureScratch>,
            initial_size: Option<enzui_webkit::ViewportSize>,
            initial_generation: MediaGeneration,
        ) -> Result<Self, NativeOpenError> {
            Self::open_with_teardown_budget(
                router,
                view,
                scratch,
                initial_size,
                initial_generation,
                TEARDOWN_BUDGET,
            )
        }

        /// The one constructor: production passes the real budget, the close gate a
        /// tiny one driving real detach - one implementation, never two pages.
        fn open_with_teardown_budget(
            router: &ViewRouter,
            view: ViewId,
            scratch: Arc<SecureScratch>,
            initial_size: Option<enzui_webkit::ViewportSize>,
            initial_generation: MediaGeneration,
            teardown_budget: Duration,
        ) -> Result<Self, NativeOpenError> {
            let updates = Arc::new(Mutex::new(VecDeque::with_capacity(UPDATE_CAP)));
            let worker_updates = Arc::clone(&updates);
            let admission = Arc::new(Mutex::new(Admission::default()));
            let worker_admission = Arc::clone(&admission);
            let router = router.clone();
            let scratch_path = scratch.path().to_owned();
            let create = move |rx| {
                WorkerLoop::new(
                    rx,
                    worker_updates,
                    worker_admission,
                    OpenPage {
                        router,
                        view,
                        scratch: scratch_path,
                        initial_size,
                        initial_generation,
                    },
                    Some(scratch),
                )
            };
            let worker = if enzui_webkit::ffi::native_requires_process_main_thread() {
                PageWorker::dispatch_main(teardown_budget, create)?
            } else {
                PageWorker::dispatch(teardown_budget, move |rx| {
                    if let Some(mut task) = create(rx) {
                        while task.step(true) {}
                    }
                })?
            };

            Ok(Self {
                worker,
                updates,
                admission,
                blur_requests: Arc::new(AtomicUsize::new(0)),
                #[cfg(test)]
                teardown_timed_out: None,
            })
        }

        /// Every submission goes through here: seq assignment plus channel push in
        /// one section keeps the cross-queue total order authoritative.
        pub fn set_visibility(&self, router: &ViewRouter, view: ViewId, visible: bool) {
            if router.accepts(view) {
                let _ = self.admit_cmd(Command::Visibility { view, visible });
            }
        }

        fn admit_cmd(&self, cmd: Command) -> Result<(), mpsc::TrySendError<PageSeqCmd>> {
            let mut admission = self.admission.lock().unwrap_or_else(|p| p.into_inner());
            let seq = admission.assign_seq();
            self.worker.try_send(SeqCmd { seq, cmd })
        }

        pub fn recreate(
            self,
            router: &ViewRouter,
            view: ViewId,
            size: Option<enzui_webkit::ViewportSize>,
        ) -> Result<Self, String> {
            self.admit_cmd(Command::Recreate {
                router: router.clone(),
                view,
                size,
            })
            .map_err(|e| format!("queue recreate: {e}"))?;
            Ok(self)
        }

        /// Queue a generation-tagged integer logical viewport for WPE.
        pub fn resize(
            &self,
            router: &ViewRouter,
            view: ViewId,
            size: enzui_webkit::ViewportSize,
        ) -> Result<(), String> {
            if !router.accepts(view) {
                return Err("view generation is no longer live".to_owned());
            }
            self.admit_cmd(Command::Resize { view, size })
                .map_err(|e| format!("queue viewport resize: {e}"))
        }

        pub(crate) fn browse(
            &self,
            router: &ViewRouter,
            view: ViewId,
            action: super::BrowserAction,
        ) -> Result<(), String> {
            if !router.accepts(view) {
                return Err("view generation is no longer live".into());
            }
            self.admit_cmd(Command::Browse { view, action })
                .map_err(|error| format!("queue navigation: {error}"))
        }

        pub fn click(&self, _router: &ViewRouter, view: ViewId, x: f32, y: f32) {
            let _ = self.admit_cmd(Command::Click { view, x, y });
        }

        pub fn hover(&self, view: ViewId, x: f32, y: f32) {
            let _ = self.admit_cmd(Command::Hover { view, x, y });
        }

        pub fn forward_input(
            &self,
            router: &ViewRouter,
            event: &InputEvent,
            tab_query: Option<(FocusGeneration, Traversal)>,
        ) -> bool {
            if !router.accepts(event.view()) {
                return false;
            }
            let is_terminal = event.is_terminal();
            let cmd = Command::Input {
                event: event.clone(),
                tab_query,
            };
            // Whole seq+send+fallback under one hold: monotone front, and
            // full-channel terminals precede later ordinaries.
            let mut admission = self.admission.lock().unwrap_or_else(|p| p.into_inner());
            let seq = admission.assign_seq();
            match self.worker.try_send(SeqCmd { seq, cmd }) {
                Ok(()) => true,
                Err(mpsc::TrySendError::Full(seq_cmd)) if is_terminal => {
                    if let Command::Input { event, .. } = seq_cmd.cmd {
                        admission.push_pending(seq_cmd.seq, event);
                    }
                    true
                }
                Err(_) => false,
            }
        }

        pub fn focus_out(&self, view: ViewId) {
            // Shared seam: defects redden tests where they'd break the worker.
            // Channel takes `Command`, fallback the distinct event - one `seq`.
            let outcome = admit_with_terminal_fallback(
                &self.admission,
                |_seq| Command::FocusOut { view },
                InputEvent::FocusLost {
                    view,
                    modifiers: input::Modifiers::NONE,
                },
                |sc| self.worker.try_send(sc),
            );
            match outcome {
                TerminalFallbackOutcome::ChannelAccepted
                | TerminalFallbackOutcome::FallbackAdded => {
                    self.blur_requests.fetch_add(1, Ordering::Relaxed);
                }
                TerminalFallbackOutcome::FallbackDuplicate
                | TerminalFallbackOutcome::Disconnected => {}
            }
        }

        pub fn apply(
            &self,
            router: &ViewRouter,
            view: ViewId,
            effect: &ImeEffect,
        ) -> Result<(), String> {
            if !router.accepts(view) {
                return Err("view generation is no longer live".to_owned());
            }
            self.admit_cmd(Command::Apply {
                view,
                effect: effect.clone(),
            })
            .map_err(|e| format!("queue IME effect: {e}"))
        }

        /// Page-copy to host clipboard, queued like every page command: worker-thread
        /// work, coalesced-`NativeUpdate` answer - no polling on the update path.
        pub fn copy_to_host(
            &self,
            router: &ViewRouter,
            view: ViewId,
            gesture: HostGesture,
        ) -> Result<(), String> {
            if !router.accepts(view) {
                return Err("view generation is no longer live".to_owned());
            }
            self.admit_cmd(Command::CopyToHost { view, gesture })
                .map_err(|e| format!("queue clipboard copy: {e}"))
        }

        /// Publish `text` on the host clipboard and paste it into the
        /// page's focused editable field.
        pub fn paste_from_host(
            &self,
            router: &ViewRouter,
            view: ViewId,
            gesture: HostGesture,
            text: &str,
        ) -> Result<(), String> {
            if !router.accepts(view) {
                return Err("view generation is no longer live".to_owned());
            }
            self.admit_cmd(Command::PasteFromHost {
                view,
                gesture,
                text: text.to_owned(),
            })
            .map_err(|e| format!("queue clipboard paste: {e}"))
        }

        /// Bounded-notification drain: ordinary coalesces, Tab replies preserved.
        pub fn take_updates(&self) -> Vec<NativeUpdate> {
            self.updates
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .drain(..)
                .collect()
        }
    }

    impl Drop for NativePage {
        fn drop(&mut self) {
            // Signal, disconnect, drain, wait - all inside budget. The lane survives;
            // session, profiles, display release before `Completed`.
            let outcome = self.worker.shutdown();
            #[cfg(test)]
            if let Some(timed_out) = &self.teardown_timed_out {
                timed_out.store(outcome == PageTeardownOutcome::TimedOut, Ordering::Release);
            }
            if !outcome.completed() {
                // Overrun reports, never waits longer: stop flag stays raised, the
                // detached job still exits alone.
                debug_assert_eq!(outcome, PageTeardownOutcome::TimedOut);
                eprintln!(
                    "enzui probe: WPE page job did not release within its teardown budget; \
                     detached under the stop flag ({outcome:?})"
                );
            }
        }
    }

    /// Native session, profile and display owners, followed by transferable frame holds.
    struct Worker {
        session: WebSession,
        profiles: ProfileStore,
        display: HeadlessDisplay,
        router: ViewRouter,
        view: ViewId,
        seq: u64,
        generation: MediaGeneration,
        gpu_enabled: bool,
        gpu_last: Option<enzui_webview::gpu::GpuFrame>,
        gpu_formats_set: bool,
        gpu_negotiating_until: Option<std::time::Instant>,
        visible: bool,
        last_activity: std::time::Instant,
        metadata_cache: Option<CachedMetadata>,
        cache_metadata: bool,
        metadata_builds: u64,
        pending_copy: Option<PendingPageCopy>,
    }

    struct CachedMetadata {
        revision: enzui_webkit::ffi::runtime::PageMetadataRevision,
        value: Arc<super::NativeMetadata>,
        title_error: Option<enzui_webkit::ffi::runtime::PageTitleError>,
    }

    impl Worker {
        fn metadata_pending(&self) -> bool {
            self.metadata_cache
                .as_ref()
                .is_none_or(|cached| cached.revision != self.session.page_metadata_revision())
        }

        fn publication_pending(&self) -> bool {
            self.gpu_pending() || self.metadata_pending()
        }

        fn metadata_snapshot(&mut self) -> (Arc<super::NativeMetadata>, Option<NativeWorkerError>) {
            let revision = self.session.page_metadata_revision();
            if self.cache_metadata
                && let Some(cached) = self.metadata_cache.as_ref()
                && cached.revision == revision
            {
                return (
                    Arc::clone(&cached.value),
                    cached.title_error.map(Into::into),
                );
            }
            let (dom_report, title_error) = match self.session.page_title() {
                Ok(title) => (title, None),
                Err(error) => (None, Some(error)),
            };
            let value = Arc::new(super::NativeMetadata {
                dom_report,
                location: self.session.current_uri().ok().flatten(),
                cursor: self.session.requested_cursor(),
            });
            self.metadata_builds += 1;
            self.metadata_cache = Some(CachedMetadata {
                revision,
                value: Arc::clone(&value),
                title_error,
            });
            (value, title_error.map(Into::into))
        }

        fn new_session(
            display: &HeadlessDisplay,
            profiles: &mut ProfileStore,
        ) -> Result<WebSession, String> {
            #[cfg(feature = "diagnostics")]
            if std::env::var_os("ENZUI_PROBE_TRUSTED_LOCAL").is_some() {
                return WebSession::new_profiled_trusted_local(
                    display,
                    profiles,
                    &WebProfile::ephemeral(),
                )
                .map_err(|error| format!("trusted local diagnostic session: {error}"));
            }
            WebSession::new_profiled(display, profiles, &WebProfile::ephemeral())
                .map_err(|error| format!("new_profiled: {error}"))
        }
        fn settle(&self, millis: u64) {
            if enzui_webkit::ffi::native_requires_process_main_thread() {
                let _ = enzui_webkit::ffi::dispatch_pending_native_events();
            } else {
                self.session.pump(millis);
            }
        }

        fn discard_gpu_frame(&mut self) {
            if let Some(frame) = self.gpu_last.take() {
                frame.discard();
            }
        }

        fn gpu_pending(&self) -> bool {
            self.gpu_enabled
                && self.visible
                && (self.gpu_negotiation_expired()
                    || self.session.gpu_frame_pending()
                    || self.gpu_last.as_ref().is_some_and(|frame| {
                        matches!(frame.status(), enzui_webview::gpu::GpuStatus::Refused(_))
                    }))
        }

        fn gpu_negotiation_expired(&self) -> bool {
            self.gpu_negotiating_until
                .is_some_and(|deadline| std::time::Instant::now() >= deadline)
                && !self
                    .gpu_last
                    .as_ref()
                    .is_some_and(|frame| crate::native_interest::import_pending(&frame.status()))
        }

        fn compositor_frame(&mut self) -> Option<enzui_webview::gpu::GpuFrame> {
            if !self.gpu_enabled || !self.visible {
                return None;
            }
            if self
                .gpu_last
                .as_ref()
                .is_some_and(|frame| frame.status() == enzui_webview::gpu::GpuStatus::Imported)
            {
                self.gpu_negotiating_until = None;
            }
            let refused = self.gpu_last.as_ref().is_some_and(|frame| {
                matches!(frame.status(), enzui_webview::gpu::GpuStatus::Refused(_))
            });
            if refused
                && !self.gpu_formats_set
                && let Some(Some(support)) = enzui_webview::gpu::renderer_support()
                && !support.formats.is_empty()
                && self
                    .session
                    .set_gpu_buffer_formats(&self.router, self.view, &support.formats)
            {
                self.gpu_formats_set = true;
                self.gpu_negotiating_until =
                    Some(std::time::Instant::now() + Duration::from_secs(2));
                self.discard_gpu_frame();
                return None;
            }
            // Buffers allocated before the preference notification may still arrive.
            if refused
                && self
                    .gpu_negotiating_until
                    .is_some_and(|deadline| std::time::Instant::now() < deadline)
            {
                self.discard_gpu_frame();
                return None;
            }
            let expired = self.gpu_negotiation_expired();
            if !refused && !expired {
                match self.session.take_shared_gpu_frame(&self.router, self.view) {
                    Ok(Some(frame)) => {
                        self.last_activity = std::time::Instant::now();
                        let allocation = frame.buffer_id();
                        let frame =
                            enzui_webview::gpu::GpuFrame::from_shared_native(frame, allocation);
                        if let Some(previous) = self.gpu_last.replace(frame.clone()) {
                            previous.discard();
                        }
                        return Some(frame);
                    }
                    Ok(None) => return None,
                    Err(error) => {
                        if cfg!(feature = "diagnostics") {
                            eprintln!("GPU_FRAME_REJECTED {error:?}");
                        }
                    }
                }
            }
            if cfg!(feature = "diagnostics") {
                eprintln!(
                    "GPU_FALLBACK refused={refused} expired={expired} formats={} pending={} held={:?}",
                    self.gpu_formats_set,
                    self.session.gpu_frame_pending(),
                    self.gpu_last.as_ref().map(|frame| frame.status()),
                );
            }
            self.gpu_enabled = false;
            self.gpu_negotiating_until = None;
            self.discard_gpu_frame();
            self.session.disable_gpu_presentation();
            None
        }
        fn open(
            router: ViewRouter,
            view: ViewId,
            scratch: PathBuf,
            initial_size: Option<enzui_webkit::ViewportSize>,
            initial_generation: MediaGeneration,
        ) -> Result<Self, String> {
            let display = HeadlessDisplay::new().map_err(|e| format!("headless display: {e}"))?;
            let mut profiles = ProfileStore::new(&scratch);
            let mut session = Self::new_session(&display, &mut profiles)?;
            session
                .bind_view(&router, view)
                .map_err(|e| format!("bind_view: {e}"))?;
            if let Some(size) = initial_size {
                session
                    .resize_viewport(&router, view, size)
                    .map_err(|e| format!("initial viewport resize: {e}"))?;
            }
            session
                .enable_input_method()
                .map_err(|e| format!("enable_input_method: {e}"))?;
            session.enable_gpu_presentation();
            let gpu_formats_set = enzui_webview::gpu::renderer_support()
                .flatten()
                .filter(|support| !support.formats.is_empty())
                .is_some_and(|support| {
                    session.set_gpu_buffer_formats(&router, view, &support.formats)
                });
            // FocusGained owns focus: never focus here.
            session
                .load(
                    &std::env::var("ENZUI_PROBE_URL").unwrap_or_else(|_| super::PAGE_HTML.into()),
                    20_000,
                )
                .map_err(|e| format!("load: {e}"))?;
            Ok(Self {
                display,
                profiles,
                session,
                router,
                view,
                seq: 0,
                generation: initial_generation,
                gpu_enabled: true,
                gpu_last: None,
                gpu_formats_set,
                gpu_negotiating_until: gpu_formats_set
                    .then(|| std::time::Instant::now() + Duration::from_secs(2)),
                visible: true,
                last_activity: std::time::Instant::now(),
                metadata_cache: None,
                cache_metadata: std::env::var_os("ENZUI_PROBE_METADATA_CACHE")
                    .is_none_or(|value| value != "0"),
                metadata_builds: 0,
                pending_copy: None,
            })
        }

        fn recreate(
            &mut self,
            router: ViewRouter,
            view: ViewId,
            size: Option<enzui_webkit::ViewportSize>,
        ) -> Result<(), String> {
            self.pending_copy.take();
            self.session.blur_view();
            self.session.pump(10);
            let mut replacement = Self::new_session(&self.display, &mut self.profiles)?;
            replacement
                .bind_view(&router, view)
                .map_err(|e| format!("recreate bind_view: {e}"))?;
            if let Some(size) = size {
                replacement
                    .resize_viewport(&router, view, size)
                    .map_err(|e| format!("recreate viewport resize: {e}"))?;
            }
            replacement
                .enable_input_method()
                .map_err(|e| format!("recreate enable_input_method: {e}"))?;
            replacement.enable_gpu_presentation();
            replacement.set_view_visibility(&router, view, self.visible);
            let gpu_formats_set = enzui_webview::gpu::renderer_support()
                .flatten()
                .filter(|support| !support.formats.is_empty())
                .is_some_and(|support| {
                    replacement.set_gpu_buffer_formats(&router, view, &support.formats)
                });
            replacement
                .load(
                    &std::env::var("ENZUI_PROBE_URL").unwrap_or_else(|_| super::PAGE_HTML.into()),
                    20_000,
                )
                .map_err(|e| format!("recreate load: {e}"))?;
            self.discard_gpu_frame();
            self.gpu_enabled = true;
            self.gpu_formats_set = gpu_formats_set;
            self.gpu_negotiating_until =
                gpu_formats_set.then(|| std::time::Instant::now() + Duration::from_secs(2));
            self.session = replacement;
            self.metadata_cache = None;
            self.router = router;
            self.view = view;
            self.seq = 0;
            self.generation = self.generation.next();
            Ok(())
        }

        fn snapshot(&mut self) -> Result<Rgba8Frame, String> {
            self.seq += 1;
            self.session
                .snapshot(
                    enzui_webview::convert::engine_generation(self.generation),
                    FrameSeq(self.seq),
                    1_200,
                )
                .map(enzui_webview::convert::media_frame)
                .map_err(|e| format!("snapshot: {e}"))
        }

        fn resize(&mut self, view: ViewId, size: enzui_webkit::ViewportSize) -> NativeUpdate {
            let outcome = self.session.resize_viewport(&self.router, view, size);
            let changed = matches!(
                outcome,
                Ok(enzui_webkit::ffi::runtime::ViewportResize::Requested)
            );
            if changed {
                self.settle(300);
            }
            let mut update = self.update(None, changed);
            if let Err(error) = outcome {
                super::add_command_error(&mut update, "resize viewport", error.to_string());
            }
            update
        }

        fn update(
            &mut self,
            tab_reply: Option<(FocusGeneration, TabReply)>,
            with_frame: bool,
        ) -> NativeUpdate {
            let copy_was_pending = self.pending_copy.is_some();
            let clipboard = self.poll_copy();
            let (metadata, mut error) = self.metadata_snapshot();
            for event in self.session.take_page_events() {
                if let enzui_webkit::page::PageEvent::LoadFailed {
                    message,
                    cancelled: false,
                    ..
                } = event
                {
                    error.get_or_insert(NativeWorkerError::Command {
                        operation: "load page",
                        detail: message,
                    });
                }
            }
            let gpu_frame = self.compositor_frame();
            NativeUpdate {
                view: self.view,
                report: self.session.native_ime_report(),
                metadata: Some(metadata),
                frame: (with_frame && !self.gpu_enabled && self.visible && !copy_was_pending)
                    .then(|| self.snapshot()),
                gpu_frame,
                tab_reply,
                view_focused: Some(self.session.view_has_focus()),
                error,
                clipboard,
            }
        }

        fn poll_copy(&mut self) -> Option<ClipboardOutcome> {
            if !self.visible {
                self.pending_copy.take();
                return None;
            }
            let pending = self.pending_copy.as_mut()?;
            let result = pending.poll(&self.session, &self.display, &self.router)?;
            self.pending_copy.take();
            Some(match result {
                Ok(selection) => match enzui_webkit::ffi::Clipboard::for_display(&self.display) {
                    Ok(clipboard) => {
                        let before = clipboard.change_count();
                        match clipboard.set_text(&selection.text) {
                            Ok(()) => ClipboardOutcome::Copied(enzui_webkit::PageCopy {
                                text: selection.text,
                                change_count_before: before,
                                change_count_after: clipboard.change_count(),
                            }),
                            Err(error) => ClipboardOutcome::Refused(
                                enzui_webkit::ClipboardRouteError::Native(error.to_string()),
                            ),
                        }
                    }
                    Err(error) => ClipboardOutcome::Refused(
                        enzui_webkit::ClipboardRouteError::Native(error.to_string()),
                    ),
                },
                Err(error) => ClipboardOutcome::Refused(error),
            })
        }

        /// One session clipboard command against the real page, typed outcome.
        fn clipboard(
            &mut self,
            view: ViewId,
            gesture: HostGesture,
            text: Option<&str>,
        ) -> NativeUpdate {
            self.pending_copy.take();
            let Some(text) = text else {
                let outcome =
                    self.session
                        .begin_page_copy(&self.display, &self.router, view, gesture);
                match outcome {
                    Ok(pending) => {
                        self.pending_copy = Some(pending);
                        return self.update(None, false);
                    }
                    Err(error) => {
                        let mut update = self.update(None, false);
                        update.clipboard = Some(ClipboardOutcome::Refused(error));
                        return update;
                    }
                }
            };
            let outcome = self
                .session
                .paste_host_text_into_page(&self.display, &self.router, view, gesture, text)
                .map(ClipboardOutcome::Pasted);
            // Pastes reach the DOM pre-snapshot, like any forwarded input.
            if outcome.is_ok() {
                self.settle(300);
            }
            let mut update = self.update(None, outcome.is_ok());
            update.clipboard = Some(outcome.unwrap_or_else(ClipboardOutcome::Refused));
            update
        }
    }

    #[cfg(feature = "diagnostics")]
    pub(super) fn run_native_clipboard_gate(scratch: PathBuf) -> Result<(), String> {
        let mut router = ViewRouter::new();
        let view = router.create(29021);
        let mut worker = Worker::open(router, view, scratch, None, MediaGeneration::FIRST)?;
        worker.session.disable_gpu_presentation();
        worker.gpu_enabled = false;
        worker.discard_gpu_frame();
        worker.session.load_html("<p>Production copy fixture</p><script>document.addEventListener('copy',e=>{e.preventDefault();e.clipboardData.setData('text/plain','Production custom copy')})</script>", "https://example.org/", 10000).map_err(|error|error.to_string())?;
        worker.session.focus_view();
        metadata_eval(
            &worker,
            "getSelection().selectAllChildren(document.body);true",
        )?;
        worker
            .session
            .evaluate_script(
                "const until=performance.now()+1000;while(performance.now()<until){};true",
                &enzui_webkit::page::ScriptWorld::Page,
            )
            .map_err(|error| error.to_string())?;
        let started = std::time::Instant::now();
        let immediate = worker.clipboard(view, HostGesture::Present, None);
        println!(
            "Production copy dispatch microseconds: {}",
            started.elapsed().as_micros()
        );
        assert!(
            started.elapsed() < Duration::from_millis(50),
            "Production copy blocked the UI for {:?}",
            started.elapsed()
        );
        assert!(
            immediate.clipboard.is_none(),
            "busy copy completed synchronously"
        );
        assert!(
            worker.pending_copy.is_some(),
            "production copy did not retain its asynchronous request"
        );
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            worker.session.pump(1);
            let update_started = std::time::Instant::now();
            let update = worker.update(None, true);
            assert!(
                update_started.elapsed() < Duration::from_millis(50),
                "Pending-copy software update blocked UI for {:?}",
                update_started.elapsed()
            );
            assert!(
                update.frame.is_none(),
                "pending-copy update requested a software snapshot"
            );
            if let Some(outcome) = update.clipboard {
                let ClipboardOutcome::Copied(copy) = outcome else {
                    panic!("production copy refused: {outcome:?}")
                };
                assert_eq!(copy.text, "Production custom copy");
                assert!(copy.change_count_after > copy.change_count_before);
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "production copy did not publish completion"
            );
        }
        assert!(
            started.elapsed() >= Duration::from_millis(800),
            "production page was not busy"
        );
        assert!(
            worker
                .update(None, true)
                .frame
                .is_some_and(|frame| frame.is_ok()),
            "software snapshot did not resume after completed copy"
        );
        metadata_eval(
            &worker,
            "document.addEventListener('copy',()=>{const until=performance.now()+200;while(performance.now()<until){}});true",
        )?;
        let immediate = worker.clipboard(view, HostGesture::Present, None);
        assert!(immediate.clipboard.is_none());
        worker.session.blur_view();
        let blur_deadline = std::time::Instant::now() + Duration::from_secs(3);
        loop {
            worker.session.pump(1);
            if let Some(outcome) = worker.update(None, false).clipboard {
                assert!(
                    matches!(outcome, ClipboardOutcome::Copied(_)),
                    "accepted copy lost on ordinary native defocus: {outcome:?}"
                );
                break;
            }
            assert!(
                std::time::Instant::now() < blur_deadline,
                "accepted copy stalled after native defocus"
            );
        }
        worker.session.focus_view();
        worker.clipboard(view, HostGesture::Present, None);
        worker.visible = false;
        worker.session.pump(300);
        assert!(
            worker.update(None, false).clipboard.is_none(),
            "hidden view published copy completion"
        );
        assert!(
            worker.pending_copy.is_none(),
            "hidden view retained its copy action"
        );
        worker.visible = true;
        worker.session.focus_view();
        metadata_eval(
            &worker,
            "document.addEventListener('copy',()=>{const until=performance.now()+4500;while(performance.now()<until){}});true",
        )?;
        let timeout_started = std::time::Instant::now();
        let immediate = worker.clipboard(view, HostGesture::Present, None);
        assert!(immediate.clipboard.is_none());
        loop {
            worker.session.pump(1);
            let update_started = std::time::Instant::now();
            let update = worker.update(None, true);
            assert!(
                update_started.elapsed() < Duration::from_millis(50),
                "Timeout-copy software update blocked UI for {:?}",
                update_started.elapsed()
            );
            assert!(
                update.frame.is_none(),
                "timeout copy update requested a software snapshot"
            );
            if let Some(outcome) = update.clipboard {
                assert!(
                    matches!(
                        outcome,
                        ClipboardOutcome::Refused(
                            enzui_webkit::ClipboardRouteError::PageDidNotCopy
                        )
                    ),
                    "long-busy copy did not time out: {outcome:?}"
                );
                break;
            }
            assert!(
                timeout_started.elapsed() < Duration::from_millis(3500),
                "long-busy copy timeout stalled UI"
            );
        }
        assert!(
            timeout_started.elapsed() >= Duration::from_millis(1800),
            "long-busy timeout control did not wait"
        );
        metadata_eval(&worker, "true")?;
        assert!(
            worker
                .update(None, true)
                .frame
                .is_some_and(|frame| frame.is_ok()),
            "software snapshot did not resume after timed-out copy became idle"
        );
        println!(
            "Clipboard gate completed: production nonblocking dispatch, real copy handler, deferred completion, blur acceptance, hidden cancellation, pending and timeout software capture suppression, resumed software capture"
        );
        Ok(())
    }

    #[cfg(feature = "diagnostics")]
    pub(super) fn run_native_title_mapping_gate(scratch: PathBuf) -> Result<(), String> {
        let mut router = ViewRouter::new();
        let view = router.create(2875);
        let mut worker = Worker::open(router, view, scratch, None, MediaGeneration::FIRST)?;
        worker.session.disable_gpu_presentation();
        worker.gpu_enabled = false;
        worker.visible = false;
        for (markup, expected) in [
            (
                "Cr&egrave;me &#x2615; &#x2014; &#x6771;&#x4EAC;".to_owned(),
                "Crème ☕ — 東京".to_owned(),
            ),
            ("x".repeat(16385), "x".repeat(1000)),
        ] {
            worker
                .session
                .load_html(
                    &format!("<!doctype html><meta charset=utf-8><title>{markup}</title>"),
                    "about:blank",
                    10000,
                )
                .map_err(|e| e.to_string())?;
            assert_eq!(
                worker.session.page_title().unwrap().as_deref(),
                Some(expected.as_str()),
                "native title follows upstream truncation"
            );
            let update = worker.update(None, false);
            assert_eq!(
                update
                    .metadata
                    .as_ref()
                    .and_then(|value| value.dom_report.as_deref()),
                Some(expected.as_str())
            );
            assert!(update.error.is_none());
        }
        let error = enzui_webkit::ffi::runtime::PageTitleError::TooLong {
            observed_bytes: 16385,
            max_bytes: 16384,
        };
        worker.metadata_cache = Some(CachedMetadata {
            revision: worker.session.page_metadata_revision(),
            value: Arc::new(super::NativeMetadata::default()),
            title_error: Some(error),
        });
        let update = worker.update(None, false);
        assert_eq!(
            update.error,
            Some(error.into()),
            "cached typed title refusal survives reuse"
        );
        Ok(())
    }

    #[cfg(feature = "diagnostics")]
    fn metadata_worker(scratch: PathBuf) -> Result<Worker, String> {
        let mut router = ViewRouter::new();
        let view = router.create(904);
        let mut worker = Worker::open(router, view, scratch, None, MediaGeneration::FIRST)?;
        worker.session.disable_gpu_presentation();
        worker.gpu_enabled = false;
        worker.discard_gpu_frame();
        worker.visible = false;
        Ok(worker)
    }

    #[cfg(feature = "diagnostics")]
    fn metadata_eval(worker: &Worker, script: &str) -> Result<(), String> {
        let id = worker
            .session
            .evaluate_script(script, &enzui_webkit::page::ScriptWorld::Page)
            .map_err(|e| format!("{e:?}"))?;
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        loop {
            worker.session.pump(2);
            for event in worker.session.take_page_events() {
                if let enzui_webkit::page::PageEvent::ScriptResult { id: found, result } = event
                    && found == id
                {
                    result.map_err(|e| format!("{e:?}"))?;
                    return Ok(());
                }
            }
            if std::time::Instant::now() >= deadline {
                return Err("metadata script did not finish".into());
            }
        }
    }

    #[cfg(feature = "diagnostics")]
    pub(super) fn run_metadata_gate(scratch: PathBuf) -> Result<(), String> {
        let mut worker = metadata_worker(scratch.clone())?;
        worker.session.load_html("<title>initial</title><style>html,body{margin:0;width:100vw;height:100vh}</style><input id=p type=password value='PASSWORD_PRIVATE_CANARY'>","about:blank",5000).map_err(|e|e.to_string())?;
        let initial = worker
            .update(None, false)
            .metadata
            .expect("initial complete metadata");
        let stable = worker
            .update(None, false)
            .metadata
            .expect("unchanged updates carry complete metadata");
        assert!(
            Arc::ptr_eq(&initial, &stable),
            "stable metadata shares its snapshot identity"
        );
        let (commands, rx) = mpsc::sync_channel(COMMAND_CAP);
        let queue = Arc::new(Mutex::new(VecDeque::new()));
        let mut task = WorkerLoop {
            worker,
            rx: PageReceiver {
                commands: rx,
                stop: Arc::new(StopBool::new(false)),
            },
            updates: Arc::clone(&queue),
            admission: Arc::new(Mutex::new(Admission::default())),
            input_frame_due: None,
            _scratch: None,
        };
        metadata_eval(&task.worker, "document.title='metadata only';true")?;
        assert!(!task.worker.gpu_pending());
        assert!(task.step(false));
        let changed = queue
            .lock()
            .unwrap()
            .pop_back()
            .expect("metadata-only change publishes without GPU output");
        assert!(changed.frame.is_none() && changed.gpu_frame.is_none());
        let changed = changed.metadata.expect("metadata-only full snapshot");
        assert_eq!(changed.dom_report.as_deref(), Some("metadata only"));
        assert!(!Arc::ptr_eq(&initial, &changed));
        metadata_eval(
            &task.worker,
            "history.pushState({},'',location.href.split('#')[0]+'#metadata-uri');true",
        )?;
        task.step(false);
        let uri = queue
            .lock()
            .unwrap()
            .pop_back()
            .expect("URI-only change publishes")
            .metadata
            .unwrap();
        assert!(
            uri.location
                .as_deref()
                .is_some_and(|uri| uri.ends_with("#metadata-uri")),
            "current URI follows history without a frame"
        );
        metadata_eval(&task.worker, "document.body.style.cursor='crosshair';true")?;
        let mapping = ViewportMapping::new(0.0, 0.0, 1024.0, 768.0, 1.0).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        loop {
            let moved = input::pointer_moved_with_modifiers(
                task.worker.view,
                &mapping,
                400.0,
                300.0,
                input::Modifiers::NONE,
            )
            .unwrap();
            assert!(task.worker.session.forward_input(&moved));
            task.worker.session.pump(10);
            if task.worker.session.requested_cursor().as_deref() == Some("crosshair") {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "cursor callback arrives"
            );
        }
        task.step(false);
        let cursor = queue
            .lock()
            .unwrap()
            .pop_back()
            .expect("cursor-only change publishes")
            .metadata
            .unwrap();
        assert_eq!(cursor.cursor.as_deref(), Some("crosshair"));
        metadata_eval(&task.worker, "document.title='';true")?;
        task.step(false);
        let empty = queue
            .lock()
            .unwrap()
            .pop_back()
            .expect("cleared title publishes")
            .metadata
            .unwrap();
        assert_eq!(empty.dom_report.as_deref(), Some(""));
        assert!(task.worker.session.forward_input(&InputEvent::FocusGained {
            view: task.worker.view,
            modifiers: input::Modifiers::NONE
        }));
        metadata_eval(&task.worker, "document.getElementById('p').focus();true")?;
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        loop {
            let update = task.worker.update(None, false);
            if update.report.is_some_and(|report| {
                report.focused
                    && report.purpose == enzui_webkit::web::ime::WEBKIT_INPUT_PURPOSE_PASSWORD
            }) {
                assert!(!format!("{:?}", update.metadata).contains("PASSWORD_PRIVATE_CANARY"));
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "password purpose remains live"
            );
            task.worker.session.pump(10);
        }
        for _ in 0..UPDATE_CAP * 3 {
            push_update(&queue, task.worker.update(None, false));
        }
        let queued = queue.lock().unwrap();
        assert_eq!(queued.len(), UPDATE_CAP);
        assert!(
            queued.iter().all(|update| update.metadata.is_some()),
            "coalesced updates retain the complete current state"
        );
        drop(queued);
        drop(task);
        drop(commands);
        run_native_title_mapping_gate(scratch)?;
        println!(
            "Metadata gate completed: shared snapshots, metadata-only idle publication, title clearing, history URI, cursor-only changes, password purpose, bounded queue, native title clipping, cached typed refusal"
        );
        Ok(())
    }

    fn wait_for_focus_token(
        session: &WebSession,
    ) -> Result<Option<enzui_webkit::NativeFocusToken>, NativeWorkerError> {
        let started = std::time::Instant::now();
        let cap = std::time::Duration::from_millis(1_000);
        loop {
            let title = session.page_title()?;
            if let Some(token) = title
                .as_deref()
                .and_then(enzui_webkit::parse_native_focus_token)
            {
                return Ok(Some(token));
            }
            if started.elapsed() >= cap {
                return Ok(None);
            }
            session.pump(5);
        }
    }

    fn wait_for_tab_ack(
        session: &WebSession,
        before: &enzui_webkit::NativeFocusToken,
    ) -> Result<Option<enzui_webkit::NativeFocusToken>, NativeWorkerError> {
        let started = std::time::Instant::now();
        let cap = std::time::Duration::from_millis(1_000);
        let Some(expected_marker) = before.marker.checked_add(1) else {
            return Ok(None);
        };
        loop {
            let title = session.page_title()?;
            let token = title
                .as_deref()
                .and_then(enzui_webkit::parse_native_focus_token);
            if token
                .as_ref()
                .is_some_and(|after| after.marker >= expected_marker)
            {
                return Ok(token);
            }
            if started.elapsed() >= cap {
                return Ok(token);
            }
            session.pump(5);
        }
    }

    fn push_update(queue: &Arc<Mutex<VecDeque<NativeUpdate>>>, update: NativeUpdate) {
        let mut q = queue.lock().unwrap_or_else(|p| p.into_inner());
        // Policy lives in `super::push_bounded` (pressure-testable feature-off);
        // this half only locks and wakes.
        push_bounded(&mut q, update);
        super::wake_native_worker();
    }

    struct OpenPage {
        router: ViewRouter,
        view: ViewId,
        scratch: PathBuf,
        initial_size: Option<enzui_webkit::ViewportSize>,
        initial_generation: MediaGeneration,
    }

    struct WorkerLoop {
        worker: Worker,
        rx: PageReceiver,
        updates: Arc<Mutex<VecDeque<NativeUpdate>>>,
        admission: Arc<Mutex<Admission>>,
        input_frame_due: Option<std::time::Instant>,
        _scratch: Option<Arc<SecureScratch>>,
    }

    impl WorkerLoop {
        fn new(
            rx: PageReceiver,
            updates: Arc<Mutex<VecDeque<NativeUpdate>>>,
            admission: Arc<Mutex<Admission>>,
            page: OpenPage,
            scratch_lease: Option<Arc<SecureScratch>>,
        ) -> Option<Self> {
            if rx.stop_raised() {
                return None;
            }
            let OpenPage {
                router,
                view,
                scratch,
                initial_size,
                initial_generation,
            } = page;
            let mut worker =
                match Worker::open(router, view, scratch, initial_size, initial_generation) {
                    Ok(worker) => worker,
                    Err(error) => {
                        push_update(
                            &updates,
                            NativeUpdate {
                                view,
                                report: None,
                                metadata: None,
                                frame: None,
                                gpu_frame: None,
                                tab_reply: None,
                                view_focused: None,
                                error: Some(NativeWorkerError::Bootstrap {
                                    stage: "display/session/load",
                                    detail: error,
                                }),
                                clipboard: None,
                            },
                        );
                        return None;
                    }
                };
            push_update(&updates, worker.update(None, true));

            Some(Self {
                worker,
                rx,
                updates,
                admission,
                input_frame_due: None,
                _scratch: scratch_lease,
            })
        }
        fn step(&mut self, blocking: bool) -> bool {
            let Self {
                worker,
                rx,
                updates,
                admission,
                input_frame_due,
                ..
            } = self;
            if rx.stop_raised() {
                rx.drain_after_stop();
                return false;
            }
            if input_frame_due.is_some_and(|due| std::time::Instant::now() >= due) {
                *input_frame_due = None;
                worker.settle(5);
                push_update(updates, worker.update(None, true));
                push_update(updates, worker.update(None, false));
            }
            let command = match arbitrate_step::<Command>(&rx.commands, admission) {
                ArbitrationStep::Execute { terminals, cmd } => {
                    for pt in terminals {
                        let accepted = worker.session.forward_input(&pt.event);
                        if accepted {
                            worker.settle(10);
                        }
                        push_update(updates, worker.update(None, false));
                    }
                    cmd
                }
                ArbitrationStep::Drain { terminals } => {
                    for pt in terminals {
                        let accepted = worker.session.forward_input(&pt.event);
                        if accepted {
                            worker.settle(10);
                        }
                        push_update(updates, worker.update(None, false));
                    }
                    return true;
                }
                ArbitrationStep::Idle if input_frame_due.is_some() => {
                    worker.settle(5);
                    return true;
                }
                ArbitrationStep::Idle
                    if !blocking
                        || worker.pending_copy.is_some()
                        || (worker.gpu_enabled && worker.visible)
                        || enzui_webkit::ffi::presentation::pending_gpu_frame_completions()
                            != 0 =>
                {
                    if blocking {
                        worker.settle(5);
                    }
                    if worker.publication_pending() || worker.pending_copy.is_some() {
                        push_update(updates, worker.update(None, true));
                    }
                    return true;
                }
                ArbitrationStep::Idle => match rx.wait() {
                    Some(cmd) => {
                        // Blocked-while pushes with lower `seq` still run first.
                        for pt in drain_before_cmd(&cmd, admission) {
                            let accepted = worker.session.forward_input(&pt.event);
                            if accepted {
                                worker.settle(10);
                            }
                            push_update(updates, worker.update(None, false));
                        }
                        cmd
                    }
                    None => return false,
                },
                ArbitrationStep::Disconnected => return false,
            };
            let SeqCmd { seq: _, cmd } = command;
            worker.last_activity = std::time::Instant::now();
            if !blocking {
                input_frame_due
                    .get_or_insert_with(|| std::time::Instant::now() + INPUT_FRAME_INTERVAL);
            }
            let result = match cmd {
                Command::Browse { view, action } => {
                    let result = if view != worker.view || !worker.router.accepts(view) {
                        Err("view generation is no longer live".to_owned())
                    } else {
                        worker.pending_copy.take();
                        match action {
                            super::BrowserAction::Navigate(url) => {
                                worker.session.begin_load_uri(&url)
                            }
                            super::BrowserAction::Back => worker.session.go_back(),
                            super::BrowserAction::Forward => worker.session.go_forward(),
                            super::BrowserAction::Reload => worker.session.reload(false),
                        }
                        .map_err(|error| error.to_string())
                    };
                    let mut update = worker.update(None, false);
                    if let Err(error) = result {
                        super::add_command_error(&mut update, "navigation", error);
                    }
                    update
                }
                Command::Resize { view, size } => worker.resize(view, size),
                Command::Recreate { router, view, size } => {
                    match worker.recreate(router, view, size) {
                        Ok(()) => worker.update(None, true),
                        Err(error) => NativeUpdate {
                            view,
                            report: None,
                            metadata: None,
                            frame: None,
                            gpu_frame: None,
                            tab_reply: None,
                            view_focused: None,
                            error: Some(NativeWorkerError::Command {
                                operation: "recreate",
                                detail: error,
                            }),
                            clipboard: None,
                        },
                    }
                }
                Command::Input { event, tab_query } => {
                    if tab_query.is_none() {
                        if worker.session.forward_input(&event) {
                            if matches!(event, InputEvent::FocusGained { .. }) {
                                // Settle native focus before a subsequent DOM click can request IME ownership.
                                worker.settle(300);
                                push_update(updates, worker.update(None, true));
                            } else if event.is_terminal() {
                                worker.settle(10);
                                push_update(updates, worker.update(None, false));
                            } else {
                                input_frame_due.get_or_insert_with(|| {
                                    std::time::Instant::now() + INPUT_FRAME_INTERVAL
                                });
                                // Native callbacks must progress while input defers frame publication.
                                worker.settle(1);
                            }
                        }
                        return true;
                    }
                    let is_tab_query = tab_query.is_some();
                    let before = match tab_query.as_ref() {
                        Some(_) => match wait_for_focus_token(&worker.session) {
                            Ok(token) => token,
                            Err(error) => {
                                let mut update = worker.update(None, false);
                                update.error.get_or_insert(error);
                                push_update(updates, update);
                                return true;
                            }
                        },
                        None => None,
                    };
                    // No baseline marker, no correlation: fail closed pre-WPE.
                    let accepted =
                        (!is_tab_query || before.is_some()) && worker.session.forward_input(&event);
                    let after = if accepted {
                        match before.as_ref() {
                            Some(before) => match wait_for_tab_ack(&worker.session, before) {
                                Ok(token) => token,
                                Err(error) => {
                                    let mut update = worker.update(None, false);
                                    update.error.get_or_insert(error);
                                    push_update(updates, update);
                                    return true;
                                }
                            },
                            None => None,
                        }
                    } else {
                        None
                    };
                    let reply = tab_query.and_then(|(query, _direction)| {
                        let signal = enzui_webkit::observe_native_tab(
                            accepted,
                            before.as_ref(),
                            after.as_ref(),
                        );
                        signal.reply().map(|reply| (query, reply))
                    });
                    // Never blur here: staleness rejects first; only accepted
                    // LeavesWidget enqueues FocusOut.
                    worker.update(reply, accepted && !event.is_terminal())
                }
                Command::Click { view, x, y } => {
                    if let Some(mapping) = ViewportMapping::new(0.0, 0.0, 1024.0, 768.0, 1.0) {
                        if let Some(down) = input::pointer_pressed_with_modifiers(
                            view,
                            &mapping,
                            x,
                            y,
                            PointerButton::Primary,
                            input::Modifiers::BUTTON1,
                        ) {
                            let _ = worker.session.forward_input(&down);
                        }
                        if let Some(up) = input::pointer_released_with_modifiers(
                            view,
                            &mapping,
                            x,
                            y,
                            PointerButton::Primary,
                            input::Modifiers::NONE,
                        ) {
                            let _ = worker.session.forward_input(&up);
                        }
                        worker.settle(300);
                    }
                    worker.update(None, true)
                }
                Command::Hover { view, x, y } => {
                    if let Some(mapping) = ViewportMapping::new(0.0, 0.0, 1024.0, 768.0, 1.0)
                        && let Some(mv) = input::pointer_moved_with_modifiers(
                            view,
                            &mapping,
                            x,
                            y,
                            input::Modifiers::NONE,
                        )
                    {
                        let _ = worker.session.forward_input(&mv);
                        worker.settle(300);
                    }
                    worker.update(None, false)
                }
                Command::Apply { view, effect } => {
                    let error = worker
                        .session
                        .apply_ime_effect(&worker.router, view, &effect)
                        .err()
                        .map(|e| e.to_string());
                    if error.is_none() {
                        worker.settle(300);
                    }
                    let mut update = worker.update(None, error.is_none());
                    if let Some(detail) = error {
                        super::add_command_error(&mut update, "apply IME effect", detail);
                    }
                    update
                }
                Command::CopyToHost { view, gesture } => worker.clipboard(view, gesture, None),
                Command::PasteFromHost {
                    view,
                    gesture,
                    text,
                } => worker.clipboard(view, gesture, Some(&text)),
                Command::Visibility { view, visible } => {
                    if worker
                        .session
                        .set_view_visibility(&worker.router, view, visible)
                    {
                        worker.visible = visible;
                        if visible && worker.gpu_negotiating_until.is_some() {
                            worker.gpu_negotiating_until =
                                Some(std::time::Instant::now() + Duration::from_secs(2));
                        }
                    }
                    let mut update = worker.update(None, visible);
                    if visible && update.gpu_frame.is_none() {
                        // An unchanged page may not repaint when mapped again.
                        update.gpu_frame = worker.gpu_last.clone();
                    }
                    update
                }
                Command::FocusOut { view } => {
                    let event = InputEvent::FocusLost {
                        view,
                        modifiers: input::Modifiers::NONE,
                    };
                    let _ = worker.session.forward_input(&event);
                    worker.settle(10);
                    worker.update(None, false)
                }
            };
            push_update(updates, result);
            true
        }
    }
}

#[cfg(not(feature = "wpe"))]
mod real {
    // Feature-off stub, signature-identical (snapshot included): the default
    // `--no-features` check guards it; wpe runs never see a break here.
    use super::{NativeOpenError, NativeUpdate};
    use enzui_core::media::Generation as MediaGeneration;
    use enzui_webkit::clipboard_route::HostGesture;
    use enzui_webkit::ime_bridge::ImeEffect;
    use enzui_webkit::web::Traversal;
    use enzui_webkit::web::{Generation as FocusGeneration, ViewId, ViewRouter};
    #[cfg(test)]
    use enzui_webkit::worker::{CommandWorker, TeardownOutcome};

    use crate::webview_scratch::SecureScratch;

    /// Every constructor's feature-off refusal.
    const NO_FEATURE: &str = "no native backend: this probe was built without \
                              `--features wpe`, so `mode::resolve(Native)` is \
                              Err(NativeUnavailable) and there is no real page";

    /// Same-API feature-off placeholder, uninhabited in production. Tests build a
    /// drop witness so the close edge stays observable without a mock browser.
    pub struct NativePage {
        #[cfg(not(test))]
        _never: core::convert::Infallible,
        #[cfg(test)]
        worker: CommandWorker<()>,
        #[cfg(test)]
        teardown_joined: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
        #[cfg(test)]
        teardown_timed_out: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    }

    impl core::fmt::Debug for NativePage {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str("NativePage(<no wpe feature>)")
        }
    }

    impl NativePage {
        pub(crate) fn browse(
            &self,
            _router: &ViewRouter,
            _view: ViewId,
            _action: super::BrowserAction,
        ) -> Result<(), String> {
            Err(NO_FEATURE.into())
        }

        pub fn set_visibility(&self, _router: &ViewRouter, _view: ViewId, _visible: bool) {}

        /// Feature-off close-gate witness: dispatcher ordering only, no page. Real
        /// release claims belong to the wpe gates on real objects.
        #[cfg(test)]
        pub(crate) fn teardown_probe(
            scratch: std::sync::Arc<SecureScratch>,
        ) -> (
            Self,
            std::sync::Arc<std::sync::atomic::AtomicBool>,
            std::sync::Arc<std::sync::atomic::AtomicBool>,
        ) {
            use std::sync::Arc;
            use std::sync::atomic::{AtomicBool, Ordering};
            use std::time::Duration;

            let joined = Arc::new(AtomicBool::new(false));
            let saw_scratch = Arc::new(AtomicBool::new(false));
            let saw_scratch_in_worker = Arc::clone(&saw_scratch);
            let worker = CommandWorker::spawn(
                "enzui-no-wpe-close-probe",
                1,
                Duration::from_millis(500),
                move |rx| {
                    while rx.next().is_some() {}
                    saw_scratch_in_worker.store(scratch.path().exists(), Ordering::Release);
                },
            )
            .expect("spawn feature-off close probe");
            (
                Self {
                    worker,
                    teardown_joined: Some(Arc::clone(&joined)),
                    teardown_timed_out: None,
                },
                joined,
                saw_scratch,
            )
        }

        /// Feature-off twin of the worker timeout witness: same ownership/detach
        /// contract, no engine. Feature-on uses a 1 ms real page instead.
        #[cfg(test)]
        pub(crate) fn teardown_timeout_probe(
            scratch: std::sync::Arc<SecureScratch>,
        ) -> (
            Self,
            std::sync::mpsc::Sender<()>,
            std::sync::Arc<std::sync::atomic::AtomicBool>,
            std::sync::Arc<std::sync::atomic::AtomicBool>,
        ) {
            use std::sync::Arc;
            use std::sync::atomic::{AtomicBool, Ordering};
            use std::sync::mpsc;
            use std::time::Duration;

            let (release_tx, release_rx) = mpsc::channel();
            let (ready_tx, ready_rx) = mpsc::channel();
            let finished = Arc::new(AtomicBool::new(false));
            let timed_out = Arc::new(AtomicBool::new(false));
            let finished_in_worker = Arc::clone(&finished);
            let worker = CommandWorker::spawn(
                "enzui-no-wpe-close-timeout-probe",
                1,
                Duration::from_millis(5),
                move |_rx| {
                    let _ = ready_tx.send(());
                    let _ = release_rx.recv();
                    debug_assert!(scratch.path().exists());
                    finished_in_worker.store(true, Ordering::Release);
                },
            )
            .expect("spawn feature-off close timeout probe");
            ready_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("feature-off close timeout probe started");
            (
                Self {
                    worker,
                    teardown_joined: None,
                    teardown_timed_out: Some(Arc::clone(&timed_out)),
                },
                release_tx,
                finished,
                timed_out,
            )
        }

        /// Always refuses, naming the missing feature.
        pub fn open(
            _router: &ViewRouter,
            _view: ViewId,
            _scratch: std::sync::Arc<SecureScratch>,
            _initial_size: Option<enzui_webkit::ViewportSize>,
            _initial_generation: MediaGeneration,
        ) -> Result<Self, NativeOpenError> {
            let _ = NO_FEATURE;
            Err(NativeOpenError::BackendUnavailable)
        }

        pub fn recreate(
            self,
            _router: &ViewRouter,
            _view: ViewId,
            _size: Option<enzui_webkit::ViewportSize>,
        ) -> Result<Self, String> {
            Err(NO_FEATURE.to_owned())
        }

        /// Typed native-unavailable refusal preserved: no viewport accepted for a
        /// mock page.
        pub fn resize(
            &self,
            _router: &ViewRouter,
            _view: ViewId,
            _size: enzui_webkit::ViewportSize,
        ) -> Result<(), String> {
            Err(NO_FEATURE.to_owned())
        }

        pub fn take_updates(&self) -> Vec<NativeUpdate> {
            Vec::new()
        }

        // No stub counter: real-page-only, sole caller wpe-gated - a stub would be
        // dead code.

        pub fn click(&self, _router: &ViewRouter, _view: ViewId, _x: f32, _y: f32) {}

        pub fn hover(&self, _view: ViewId, _x: f32, _y: f32) {}

        /// Always refuses.
        pub fn forward_input(
            &self,
            _router: &ViewRouter,
            _event: &enzui_webkit::input::InputEvent,
            _tab_query: Option<(FocusGeneration, Traversal)>,
        ) -> bool {
            false
        }

        pub fn focus_out(&self, _view: ViewId) {}

        /// Always refuses: no page to copy from.
        pub fn copy_to_host(
            &self,
            _router: &ViewRouter,
            _view: ViewId,
            _gesture: HostGesture,
        ) -> Result<(), String> {
            Err(NO_FEATURE.to_owned())
        }

        /// Always refuses: no page to paste into.
        pub fn paste_from_host(
            &self,
            _router: &ViewRouter,
            _view: ViewId,
            _gesture: HostGesture,
            _text: &str,
        ) -> Result<(), String> {
            Err(NO_FEATURE.to_owned())
        }

        pub fn apply(
            &self,
            _router: &ViewRouter,
            _view: ViewId,
            _effect: &ImeEffect,
        ) -> Result<(), String> {
            Err(NO_FEATURE.to_owned())
        }
    }

    #[cfg(test)]
    impl Drop for NativePage {
        fn drop(&mut self) {
            use std::sync::atomic::Ordering;

            let outcome = self.worker.shutdown();
            if let Some(joined) = &self.teardown_joined {
                joined.store(outcome.is_joined(), Ordering::Release);
            }
            if let Some(timed_out) = &self.teardown_timed_out {
                timed_out.store(outcome == TeardownOutcome::TimedOut, Ordering::Release);
            }
            if !outcome.is_joined() {
                debug_assert_eq!(outcome, TeardownOutcome::TimedOut);
            }
        }
    }
}

pub use real::NativePage;

pub fn main_thread_subscription() -> iced::Subscription<()> {
    #[cfg(feature = "wpe")]
    if real::main_dispatch_needed() {
        if let Some(subscription) = real::native_subscription() {
            return subscription;
        }
        return iced::time::every(real::main_dispatch_interval()).map(|_| ());
    }
    iced::Subscription::none()
}

pub fn pump_main_thread() {
    #[cfg(feature = "wpe")]
    real::pump_main_thread();
}

#[cfg(feature = "diagnostics")]
pub fn run_metadata_gate(scratch: std::path::PathBuf) -> Result<(), String> {
    real::run_metadata_gate(scratch)
}

pub(crate) fn main_thread_dispatcher<'a, Message: 'a>(
    dispatch: impl Fn(bool) -> Option<Message> + 'a,
) -> Option<iced::Element<'a, Message>> {
    #[cfg(feature = "wpe")]
    return real::dispatcher(dispatch);
    #[cfg(not(feature = "wpe"))]
    {
        let _ = dispatch;
        None
    }
}

pub(crate) fn live_gpu_source_enabled() -> bool {
    match std::env::var_os("ENZUI_PROBE_LIVE_GPU") {
        Some(value) => value == "1",
        None => {
            #[cfg(feature = "wpe")]
            return real::dispatcher_available();
            #[cfg(not(feature = "wpe"))]
            false
        }
    }
}

#[cfg(feature = "diagnostics")]
pub fn run_clipboard_gate(scratch: std::path::PathBuf) -> Result<(), String> {
    real::run_native_clipboard_gate(scratch)
}
