use super::super::read_identity;
use super::*;
use std::io::{BufRead, Write};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Reaped(Child);
impl Drop for Reaped {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn live_child() -> Reaped {
    Reaped(
        Command::new("/bin/cat")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()
            .expect("owned child"),
    )
}

#[test]
fn stat_liveness_binds_exact_identity_and_observes_exit() {
    let mut child = live_child();
    let identity = read_identity(child.0.id()).expect("live child identity");
    let witness = ProcessLiveness::new(identity);
    assert!(
        witness.is_some(),
        "live process did not acquire a stat descriptor"
    );
    let stale = ProcessIdentity {
        start_ticks: identity.start_ticks + 1,
        ..identity
    };
    assert!(
        ProcessLiveness::new(stale).is_none(),
        "stale identity acquired a witness"
    );
    if let Some(witness) = &witness {
        assert_eq!(witness.identity(), identity);
        assert_eq!(witness.is_gone(), Some(false));
    }
    child.0.kill().expect("terminate owned child");
    child.0.wait().expect("reap owned child");
    assert!(super::super::process_is_gone(identity));
    if let Some(witness) = witness {
        assert_eq!(witness.is_gone(), Some(true));
    }
}

#[test]
fn stat_liveness_detects_leader_exit_while_another_thread_survives() {
    let mut child = Reaped(
        Command::new("python3")
            .args(["-c", "import ctypes,threading,sys; threading.Thread(target=lambda:threading.Event().wait(20)).start(); print('ready',flush=True); sys.stdin.readline(); ctypes.CDLL(None).pthread_exit(None)"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("owned threaded child"),
    );
    let stdout = child.0.stdout.take().expect("child readiness pipe");
    let (send, receive) = std::sync::mpsc::sync_channel(1);
    let reader = std::thread::spawn(move || {
        let mut ready = String::new();
        std::io::BufReader::new(stdout)
            .read_line(&mut ready)
            .expect("child readiness");
        let _ = send.send(ready);
    });
    let ready = receive
        .recv_timeout(Duration::from_secs(2))
        .expect("child readiness deadline");
    reader.join().expect("readiness reader");
    assert_eq!(ready.trim(), "ready");
    let identity = read_identity(child.0.id()).expect("thread-group leader");
    let witness = ProcessLiveness::new(identity);
    assert!(
        witness.is_some(),
        "live process did not acquire a stat descriptor"
    );
    child
        .0
        .stdin
        .take()
        .expect("leader command")
        .write_all(b"exit\n")
        .expect("release leader");
    let deadline = Instant::now() + Duration::from_secs(2);
    while !super::super::process_is_gone(identity) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(
        super::super::process_is_gone(identity),
        "leader did not exit"
    );
    assert!(
        child.0.try_wait().expect("thread-group status").is_none(),
        "worker thread did not survive"
    );
    if let Some(witness) = witness {
        while witness.is_gone() == Some(false) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(
            witness.is_gone(),
            Some(true),
            "leader exit was hidden by a surviving worker"
        );
    }
}
