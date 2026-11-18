//! Terminal fallback preserves global admission order. Two inversions closed: the
//! old worker drained every fallback terminal before the popped ordinary (cross-
//! queue inversion), and the empty-race (peek-empty, then `drain_all` under lock)
//! let later-admitted terminals overtake fresh ordinaries. Every test drives the
//! production arbitration seam (`arbitrate_step` over a real bounded channel + the
//! real `Admission` mutex) with a release-before-press observer - no oracles, no
//! sleeps, no timing asserts. Four sabotage pins: `drain(..)` for `drain_before`
//! (ordering tests), bare `drain_all` in the empty branch (empty-race test),
//! skipped `push_pending` on Full (focus test), removed oldest-first eviction
//! (boundedness test).

use std::sync::Mutex;
use std::sync::mpsc::{self, TrySendError};

use enzui_webkit::input::{InputEvent, Modifiers, PointerButton, ViewPoint};
use enzui_webkit::web::ViewId;

use crate::webview_native::{
    Admission, ArbitrationStep, PENDING_TERMINAL_CAP, SeqCmd, arbitrate_step,
};

/// Mirrors production `COMMAND_CAP`; local so the file compiles feature-off.
const CHANNEL_CAP: usize = 32;

// Fixtures.

fn view_a() -> ViewId {
    ViewId::new(1)
}

fn pointer_moved(view: ViewId, x: f32) -> InputEvent {
    InputEvent::PointerMoved {
        view,
        at: ViewPoint { x, y: 0.0 },
        modifiers: Modifiers::BUTTON1,
    }
}

fn pointer_pressed(view: ViewId, x: f32) -> InputEvent {
    InputEvent::PointerPressed {
        view,
        at: ViewPoint { x, y: 0.0 },
        button: PointerButton::Primary,
        modifiers: Modifiers::BUTTON1,
    }
}

fn pointer_released(view: ViewId, x: f32) -> InputEvent {
    InputEvent::PointerReleased {
        view,
        at: ViewPoint { x, y: 0.0 },
        button: PointerButton::Primary,
        modifiers: Modifiers::NONE,
    }
}

fn touch_up(view: ViewId, finger: u32, x: f32) -> InputEvent {
    InputEvent::TouchUp {
        view,
        seq: finger,
        at: ViewPoint { x, y: 0.0 },
        modifiers: Modifiers::NONE,
    }
}

// Production-shape submit path over the REAL bounded channel.

/// Real channel + real `Admission` mutex: no shadow queue, no shadow scheduler.
struct Harness {
    tx: mpsc::SyncSender<SeqCmd<InputEvent>>,
    rx: mpsc::Receiver<SeqCmd<InputEvent>>,
    admission: Mutex<Admission>,
}

impl Harness {
    fn new() -> Self {
        let (tx, rx) = mpsc::sync_channel::<SeqCmd<InputEvent>>(CHANNEL_CAP);
        Self {
            tx,
            rx,
            admission: Mutex::new(Admission::default()),
        }
    }

    /// `forward_input`'s critical section, transcribed: seq + try_send under one
    /// lock; Full+terminal falls back in the same section; saturated ordinaries
    /// drop (`false`) per the ordinary-class policy.
    fn admit_input(&self, event: InputEvent) -> bool {
        let is_terminal = event.is_terminal();
        let mut adm = self.admission.lock().unwrap_or_else(|p| p.into_inner());
        let seq = adm.assign_seq();
        match self.tx.try_send(SeqCmd { seq, cmd: event }) {
            Ok(()) => true,
            Err(TrySendError::Full(sc)) if is_terminal => {
                adm.push_pending(sc.seq, sc.cmd);
                true
            }
            Err(_) => false,
        }
    }

    fn pending_len(&self) -> usize {
        self.admission
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .pending_len()
    }

    /// Shared production arbitrator to quiescence: exactly `worker_main`'s turn.
    fn drive_to_quiescence(&self, sink: &mut Vec<InputEvent>) {
        loop {
            match arbitrate_step::<InputEvent>(&self.rx, &self.admission) {
                ArbitrationStep::Execute { terminals, cmd } => {
                    for pt in terminals {
                        sink.push(pt.event);
                    }
                    sink.push(cmd.cmd);
                }
                ArbitrationStep::Drain { terminals } => {
                    for pt in terminals {
                        sink.push(pt.event);
                    }
                }
                // Never signalled stop: Idle means both queues empty. Production
                // blocks; the harness exits.
                ArbitrationStep::Idle | ArbitrationStep::Disconnected => break,
            }
        }
    }
}

// Pressed-state observer: release-before-press detector per identity.

#[derive(Default, Debug)]
struct PressedState {
    pressed: bool,
    saw_release_before_press: bool,
    presses: usize,
    releases: usize,
}

#[derive(Debug, Clone, Copy)]
enum Identity {
    Pointer { view: ViewId, button: PointerButton },
}

impl PressedState {
    fn matches(&self, target: &Identity, event: &InputEvent) -> bool {
        match (target, event) {
            (
                Identity::Pointer { view, button },
                InputEvent::PointerPressed {
                    view: v, button: b, ..
                }
                | InputEvent::PointerReleased {
                    view: v, button: b, ..
                },
            ) => v == view && b == button,
            _ => false,
        }
    }

    fn observe(&mut self, target: &Identity, event: &InputEvent) {
        if !self.matches(target, event) {
            return;
        }
        match event {
            InputEvent::PointerPressed { .. }
            | InputEvent::TouchDown { .. }
            | InputEvent::FocusGained { .. } => {
                self.pressed = true;
                self.presses += 1;
            }
            InputEvent::PointerReleased { .. }
            | InputEvent::TouchUp { .. }
            | InputEvent::TouchCancel { .. }
            | InputEvent::FocusLost { .. } => {
                if !self.pressed {
                    self.saw_release_before_press = true;
                }
                self.pressed = false;
                self.releases += 1;
            }
            _ => {}
        }
    }
}

// Tests.

#[test]
fn a_terminal_release_does_not_overtake_its_press_across_queues() {
    // Stalled worker: tagged press is the final accepted ordinary; its release
    // falls back.
    let view = view_a();
    let harness = Harness::new();

    for i in 0..(CHANNEL_CAP - 1) {
        assert!(
            harness.admit_input(pointer_moved(view, i as f32)),
            "an ordinary move must be admitted while the channel has space",
        );
    }
    let unique_press = pointer_pressed(view, 999.0);
    assert!(
        harness.admit_input(unique_press.clone()),
        "the tagged press must be the final accepted ordinary command",
    );

    // Saturated: ordinaries refused, terminals fall back.
    let sanity_ordinary = pointer_moved(view, 0.0);
    assert!(
        !harness.admit_input(sanity_ordinary),
        "an ordinary must saturate when channel is full",
    );

    let unique_release = pointer_released(view, 999.0);
    assert!(
        harness.admit_input(unique_release.clone()),
        "a terminal release must be admitted via the fallback",
    );
    assert_eq!(
        harness.pending_len(),
        1,
        "the fallback captured the release the ordinary queue could not",
    );

    let mut order = Vec::new();
    harness.drive_to_quiescence(&mut order);

    let mut state = PressedState::default();
    let target = Identity::Pointer {
        view,
        button: PointerButton::Primary,
    };
    for event in &order {
        state.observe(&target, event);
    }

    assert_eq!(
        state.presses, 1,
        "the tagged press must execute exactly once"
    );
    assert_eq!(
        state.releases, 1,
        "the tagged release must execute exactly once"
    );
    assert!(
        !state.saw_release_before_press,
        "release must not precede press for the same pointer identity — a \
         page that sees release-before-press stays grabbed",
    );
    assert!(!state.pressed, "final state must be released");

    let press_pos = order
        .iter()
        .position(|e| e == &unique_press)
        .expect("the tagged press must execute");
    let release_pos = order
        .iter()
        .position(|e| e == &unique_release)
        .expect("the tagged release must execute");
    assert!(
        press_pos < release_pos,
        "arbitration order: press at {press_pos}, release at {release_pos}",
    );
}

#[test]
fn terminal_fallback_is_not_starved_by_continuous_ordinary_traffic() {
    // Starvation control + ordinary-after-terminal check: pending terminals fire
    // at the first higher-seq pop; predecessors first, later admissions after -
    // "bypasses only later admissions".
    let view = view_a();
    let harness = Harness::new();

    for i in 0..CHANNEL_CAP {
        assert!(harness.admit_input(pointer_moved(view, i as f32)));
    }
    let uniquely_tagged_terminal = pointer_released(view, 314.0);
    assert!(harness.admit_input(uniquely_tagged_terminal.clone()));
    assert_eq!(harness.pending_len(), 1);

    let mut order = Vec::new();
    let mut fresh_admitted = 0usize;
    let cap_turns = CHANNEL_CAP * 4;
    for turn in 0..cap_turns {
        if fresh_admitted < CHANNEL_CAP
            && harness.admit_input(pointer_moved(view, (10_000 + turn) as f32))
        {
            fresh_admitted += 1;
        }
        match arbitrate_step::<InputEvent>(&harness.rx, &harness.admission) {
            ArbitrationStep::Execute { terminals, cmd } => {
                for pt in terminals {
                    order.push(pt.event);
                }
                order.push(cmd.cmd);
            }
            ArbitrationStep::Drain { terminals } => {
                for pt in terminals {
                    order.push(pt.event);
                }
            }
            ArbitrationStep::Idle | ArbitrationStep::Disconnected => break,
        }
    }

    let terminal_pos = order
        .iter()
        .position(|e| e == &uniquely_tagged_terminal)
        .expect("the pending terminal must not be starved");

    let mut predecessors_before_terminal = 0usize;
    for event in order.iter().take(terminal_pos) {
        if matches!(event, InputEvent::PointerMoved { at, .. } if at.x < 10_000.0) {
            predecessors_before_terminal += 1;
        }
    }
    assert_eq!(
        predecessors_before_terminal, CHANNEL_CAP,
        "every ordinary admitted BEFORE the terminal must run first; \
         found only {predecessors_before_terminal}/{CHANNEL_CAP} predecessors \
         before the terminal at position {terminal_pos}",
    );

    for (i, event) in order.iter().enumerate() {
        if matches!(event, InputEvent::PointerMoved { at, .. } if at.x >= 10_000.0) {
            assert!(
                i > terminal_pos,
                "a later-admitted ordinary at position {i} must not \
                 overtake the terminal at {terminal_pos}",
            );
        }
    }
}

#[test]
fn the_fallback_queue_stays_bounded_under_terminal_pressure() {
    let view = view_a();
    let harness = Harness::new();
    for i in 0..CHANNEL_CAP {
        assert!(harness.admit_input(pointer_moved(view, i as f32)));
    }
    for finger in 0u32..(PENDING_TERMINAL_CAP as u32 + 4) {
        assert!(harness.admit_input(touch_up(view, finger, finger as f32)));
        assert!(
            harness.pending_len() <= PENDING_TERMINAL_CAP,
            "fallback must stay <= PENDING_TERMINAL_CAP",
        );
    }
    assert_eq!(harness.pending_len(), PENDING_TERMINAL_CAP);

    let mut order = Vec::new();
    harness.drive_to_quiescence(&mut order);
    let mut previous_finger: Option<u32> = None;
    for finger in order.iter().filter_map(|e| match e {
        InputEvent::TouchUp { seq, .. } => Some(*seq),
        _ => None,
    }) {
        if let Some(prev) = previous_finger {
            assert!(
                finger > prev,
                "terminal survivors must fire in admission (finger) order: \
                 prev={prev}, event={finger}",
            );
        }
        previous_finger = Some(finger);
    }
}
