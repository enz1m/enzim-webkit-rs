//! Panic containment for host-provided synchronous callbacks.
//!
//! `catch_unwind` alone still runs the process panic hook before returning the
//! payload. A callback panic may contain a URL token or credential, so a single
//! process-wide forwarding hook suppresses output only while the current thread
//! is inside a protected call. Other threads continue to use the hook that was
//! installed when this boundary was first used.
//!
//! Protected calls may nest, because a host callback can pump work that enters
//! another one. Each scope restores the suppression state of its caller, so
//! only the outermost scope re-enables hook output on the thread.

use std::any::Any;
use std::cell::Cell;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Once;

thread_local! {
    static SUPPRESS_CURRENT_PANIC: Cell<bool> = const { Cell::new(false) };
}

static INSTALL_REDACTING_HOOK: Once = Once::new();
#[cfg(test)]
static SUPPRESSED_PANICS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[cfg(test)]
thread_local! {
    // The hook runs on the panicking thread, so a thread-local record of its
    // decision is unaffected by panics on the other test threads.
    static HOOK_DECISION: Cell<Option<bool>> = const { Cell::new(None) };
}

fn install_hook() {
    INSTALL_REDACTING_HOOK.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let suppressed = SUPPRESS_CURRENT_PANIC.with(Cell::get);
            #[cfg(test)]
            HOOK_DECISION.with(|decision| decision.set(Some(suppressed)));
            if suppressed {
                #[cfg(test)]
                SUPPRESSED_PANICS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            } else {
                previous(info);
            }
        }));
    });
}

pub(crate) fn catch_silent<F, T>(call: F) -> Result<T, Box<dyn Any + Send>>
where
    F: FnOnce() -> T,
{
    install_hook();

    // An enclosing protected call may still be running, so the guard restores
    // its suppression value instead of clearing the flag.
    struct Restore(bool);
    impl Drop for Restore {
        fn drop(&mut self) {
            SUPPRESS_CURRENT_PANIC.with(|flag| flag.set(self.0));
        }
    }

    let restore = Restore(SUPPRESS_CURRENT_PANIC.with(|flag| flag.replace(true)));
    let result = catch_unwind(AssertUnwindSafe(call));
    drop(restore);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn last_hook_decision() -> Option<bool> {
        HOOK_DECISION.with(Cell::get)
    }

    fn forget_hook_decision() {
        HOOK_DECISION.with(|decision| decision.set(None));
    }

    #[test]
    fn caught_secret_payload_does_not_escape_and_flag_is_restored() {
        let before = SUPPRESSED_PANICS.load(std::sync::atomic::Ordering::Relaxed);
        let result = catch_silent(|| panic!("secret=DO-NOT-LOG"));
        assert!(result.is_err());
        assert!(
            SUPPRESSED_PANICS.load(std::sync::atomic::Ordering::Relaxed) > before,
            "the redacting hook did not consume the protected panic"
        );
        assert!(!SUPPRESS_CURRENT_PANIC.with(Cell::get));
    }

    #[test]
    fn outer_panic_after_inner_protected_call_unwinds_stays_suppressed() {
        forget_hook_decision();
        let inner_payload_caught = Cell::new(false);
        let result = catch_silent(|| {
            inner_payload_caught.set(catch_silent(|| panic!("inner=DO-NOT-LOG")).is_err());
            panic!("outer=DO-NOT-LOG");
        });

        assert!(
            inner_payload_caught.get(),
            "the inner panic did not become a typed error outcome"
        );
        assert_eq!(
            last_hook_decision(),
            Some(true),
            "the outer payload reached the real process hook after the inner scope unwound"
        );
        assert!(result.is_err());
        assert!(!SUPPRESS_CURRENT_PANIC.with(Cell::get));
    }

    #[test]
    fn suppression_is_disabled_after_the_outermost_scope() {
        let nested = catch_silent(|| catch_silent(|| 1u32));
        assert!(matches!(nested, Ok(Ok(1))));
        assert!(!SUPPRESS_CURRENT_PANIC.with(Cell::get));

        forget_hook_decision();
        // The forwarded message on stderr is this control's expected output.
        let unprotected = catch_unwind(AssertUnwindSafe(|| {
            panic!("positive control: unprotected panic reaches the real hook")
        }));

        assert!(unprotected.is_err());
        assert_eq!(
            last_hook_decision(),
            Some(false),
            "suppression outlived the outermost protected scope"
        );
    }
}
