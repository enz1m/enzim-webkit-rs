#![cfg(feature = "wpe")]

use enzui_core::native_loop::Interest;
use enzui_webkit::ffi::NativeInterest;
use std::time::{Duration, Instant};

use enzui_webview::gpu::GpuStatus;

pub(crate) fn import_pending(status: &GpuStatus) -> bool {
    matches!(status, GpuStatus::Pending | GpuStatus::Writing)
}

pub(crate) fn publication_deadline(
    deferred: Option<Instant>,
    pending: bool,
    now: Instant,
) -> Option<Instant> {
    deferred.or_else(|| pending.then_some(now))
}

pub(crate) fn gpu_import_deadline(
    status: Option<GpuStatus>,
    negotiating_until: Option<Instant>,
    visible: bool,
    now: Instant,
) -> Option<Instant> {
    if !visible {
        None
    } else if status.as_ref().is_some_and(import_pending) {
        Some(negotiating_until.unwrap_or(now + Duration::from_millis(50)))
    } else if status == Some(GpuStatus::Imported) {
        None
    } else {
        negotiating_until
    }
}

pub(crate) fn compose(
    native: NativeInterest,
    input_due: Option<Instant>,
    import_due: Option<Instant>,
    now: Instant,
) -> Interest {
    let mut interest = Interest::new();
    for (fd, events) in native.descriptors {
        interest = interest.descriptor(fd, events);
    }
    if let Some(timeout) = native.timeout {
        interest = interest.deadline(now + timeout);
    }
    if let Some(due) = input_due {
        interest = interest.deadline(due);
    }
    if let Some(due) = import_due {
        // Renderer import status can change without a native descriptor event.
        let poll_due = now + Duration::from_millis(50);
        let due = if due <= now {
            poll_due
        } else {
            due.min(poll_due)
        };
        interest = interest.deadline(due);
    }
    interest
}

#[cfg(test)]
mod tests {
    use super::*;
    use enzui_core::native_loop::{NativeLoop, NativeReady};
    use iced::futures::StreamExt;
    use std::task::{Context, Poll, Waker};

    fn wait(interest: Interest) -> Duration {
        let watcher = NativeLoop::new().unwrap();
        watcher.arm(interest);
        let mut recipes = iced::advanced::subscription::into_recipes(
            watcher.subscription(std::convert::identity),
        );
        let mut stream = recipes
            .pop()
            .unwrap()
            .stream(Box::pin(iced::futures::stream::pending()));
        let started = Instant::now();
        let mut context = Context::from_waker(Waker::noop());
        while started.elapsed() < Duration::from_millis(300) {
            if let Poll::Ready(ready) = stream.poll_next_unpin(&mut context) {
                assert_eq!(ready, Some(NativeReady::Deadline));
                return started.elapsed();
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        panic!("host deadline did not wake the native owner");
    }

    #[test]
    fn native_readiness_deadlines_include_host_work_and_avoid_expired_import_spins() {
        for source in [
            "input",
            "native",
            "import",
            "expired-import",
            "pending-import",
            "ready-frame",
        ] {
            let now = Instant::now();
            let soon = now + Duration::from_millis(20);
            let later = now + Duration::from_secs(1);
            let native = NativeInterest {
                descriptors: Vec::new(),
                timeout: (source == "native").then_some(Duration::from_millis(20)),
            };
            let input = Some(match source {
                "input" => soon,
                "ready-frame" => now,
                _ => later,
            });
            let import = match source {
                "import" => Some(soon),
                "expired-import" => Some(now - Duration::from_secs(1)),
                "pending-import" => Some(later),
                _ => None,
            };
            eprintln!("native_readiness_case={source}");
            let elapsed = wait(compose(native, input, import, now));
            assert!(
                elapsed < Duration::from_millis(250),
                "{source}: {elapsed:?}"
            );
            if matches!(source, "expired-import" | "pending-import") {
                assert!(
                    now.elapsed() >= Duration::from_millis(30),
                    "expired import armed an immediate wake storm"
                );
            }
        }
    }
}
