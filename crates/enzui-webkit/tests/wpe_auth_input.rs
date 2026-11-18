//! Malformed credentials preserve an authentication challenge for correction.
//!
//! ```text
//! cargo test --offline --locked --workspace --features enzui-webkit/wpe --test wpe_auth_input credentials_cross -- --ignored --nocapture
//! ```

mod wpe_native_support;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use enzui_security::secret::SecretText;
use enzui_webkit::ffi::page::AnswerError;
use enzui_webkit::ffi::runtime::{HeadlessDisplay, WebSession};
use enzui_webkit::page::{AuthAnswer, PageEvent, PagePrompts};

struct Origin {
    url: String,
    authorized: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl Origin {
    fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("origin listener");
        let url = format!("http://{}/", listener.local_addr().expect("address"));
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        let authorized = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let received = Arc::clone(&authorized);
        let finished = Arc::clone(&stop);
        let worker = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(30);
            while !finished.load(Ordering::Relaxed) && Instant::now() < deadline {
                let Ok((mut stream, _)) = listener.accept() else {
                    thread::sleep(Duration::from_millis(5));
                    continue;
                };
                stream
                    .set_read_timeout(Some(Duration::from_millis(500)))
                    .expect("read timeout");
                stream
                    .set_write_timeout(Some(Duration::from_millis(500)))
                    .expect("write timeout");
                let mut request = Vec::new();
                let mut buffer = [0; 1024];
                while request.len() < 16 * 1024 && !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.read(&mut buffer) {
                        Ok(0) | Err(_) => break,
                        Ok(count) => request.extend_from_slice(&buffer[..count]),
                    }
                }
                let request = String::from_utf8_lossy(&request);
                let accepted = request.lines().any(|line| {
                    line.split_once(':').is_some_and(|(name, value)| {
                        name.eq_ignore_ascii_case("Authorization")
                            && value.trim() == "Basic dXNlcjpwYXNz"
                    })
                });
                let (status, headers, title) = if accepted {
                    received.fetch_add(1, Ordering::Relaxed);
                    ("200 OK", "", "authed")
                } else {
                    (
                        "401 Unauthorized",
                        "WWW-Authenticate: Basic realm=\"fixture\"\r\n",
                        "needs credentials",
                    )
                };
                let body = format!("<title>{title}</title>");
                let response = format!(
                    "HTTP/1.1 {status}\r\n{headers}Content-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        Self {
            url,
            authorized,
            stop,
            worker: Some(worker),
        }
    }
}

impl Drop for Origin {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn credentials(user: &str, password: &str) -> AuthAnswer {
    AuthAnswer::Credentials {
        user: user.into(),
        password: SecretText::new(password.into()),
    }
}

#[test]
#[ignore = "requires the confined WPE source runtime and a loopback authentication origin"]
fn credentials_cross_the_native_boundary_without_rewriting_or_consuming_invalid_answers() {
    wpe_native_support::run(
        "credentials_cross_the_native_boundary_without_rewriting_or_consuming_invalid_answers",
        run_gates,
    );
}

fn run_gates() {
    let display = HeadlessDisplay::new().expect("headless display");
    let origin = Origin::new();
    let session = WebSession::new_trusted_local(&display).expect("session");
    session.set_page_prompts(PagePrompts {
        authentication: true,
        ..PagePrompts::default()
    });
    session
        .begin_load_uri(&origin.url)
        .expect("begin protected page");
    let deadline = Instant::now() + Duration::from_secs(5);
    let request = loop {
        assert!(Instant::now() < deadline, "no authentication challenge");
        session.pump(10);
        if let Some(request) = session.take_page_events().into_iter().find_map(|event| {
            if let PageEvent::Authentication(request) = event {
                Some(request)
            } else {
                None
            }
        }) {
            break request;
        }
    };
    for answer in [credentials("us\0er", "pass"), credentials("user", "pa\0ss")] {
        assert_eq!(
            session.answer_authentication(request.id, &answer),
            Err(AnswerError::InvalidCredentials)
        );
    }
    session.pump(100);
    assert_eq!(
        origin.authorized.load(Ordering::Relaxed),
        0,
        "malformed credentials never authorize a request"
    );
    let valid = credentials("user", "pass");
    session
        .answer_authentication(request.id, &valid)
        .expect("correct the same challenge");
    let deadline = Instant::now() + Duration::from_secs(5);
    while session.page_title().expect("title").as_deref() != Some("authed") {
        assert!(
            Instant::now() < deadline,
            "the corrected credentials never reached the origin"
        );
        session.pump(10);
    }
    assert!(origin.authorized.load(Ordering::Relaxed) > 0);
    assert_eq!(
        session.answer_authentication(request.id, &valid),
        Err(AnswerError::Unknown)
    );
}
