//! Poll native readiness without delaying work that is already complete.

use std::time::{Duration, Instant};

pub(super) fn wait_until_ready(
    timeout: Duration,
    mut ready: impl FnMut() -> bool,
    mut pump: impl FnMut(),
) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if ready() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        pump();
    }
}
