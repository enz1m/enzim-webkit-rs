use super::ProcessIdentity;
#[cfg(target_os = "linux")]
use super::parse_stat;

pub(crate) struct ProcessLiveness {
    identity: ProcessIdentity,
    #[cfg(target_os = "linux")]
    descriptor: std::fs::File,
}

impl ProcessLiveness {
    pub(crate) fn new(identity: ProcessIdentity) -> Option<Self> {
        #[cfg(target_os = "linux")]
        {
            let descriptor = std::fs::File::open(format!("/proc/{}/stat", identity.pid)).ok()?;
            let witness = Self {
                identity,
                descriptor,
            };
            (witness.is_gone() == Some(false)).then_some(witness)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = identity;
            None
        }
    }

    pub(crate) fn identity(&self) -> ProcessIdentity {
        self.identity
    }

    pub(crate) fn is_gone(&self) -> Option<bool> {
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::FileExt;
            // An open proc stat file stays bound to its original process across PID reuse.
            let mut bytes = [0; 1024];
            let entry = self
                .descriptor
                .read_at(&mut bytes, 0)
                .ok()
                .and_then(|length| std::str::from_utf8(&bytes[..length]).ok())
                .and_then(parse_stat);
            Some(entry.is_none_or(|entry| {
                entry.has_exited() || entry.start_ticks != self.identity.start_ticks
            }))
        }
        #[cfg(not(target_os = "linux"))]
        {
            None
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests;
