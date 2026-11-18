//! Shared loopback HTTPS origin for native policy and installation gates.
//!
//! Self-signed certificate, request counters and the Python TLS server stay
//! in test storage. Redirect routes preserve raw Location userinfo; the
//! installed-page route supplies a visible native snapshot fixture.

// Each including test binary uses a subset of the fixture surface.
#![allow(dead_code)]

/// A self-signed loopback HTTPS origin that records every request path.
///
/// Redirect routes count source and target requests separately; ordinary
/// routes return text, and `/installed-page` returns a styled HTML fixture.
pub struct TlsRedirectOrigin {
    port: u16,
    child: std::process::Child,
    dir: std::path::PathBuf,
    requests: std::path::PathBuf,
    /// PEM-encoded self-signed certificate, read once during `start()` so
    /// callers can pre-trust it via
    /// `WebSession::allow_tls_certificate_for_host` before navigating.
    cert_pem: Vec<u8>,
}

impl TlsRedirectOrigin {
    pub fn start() -> Result<Self, String> {
        Self::start_in("enzui-credential-tls", None)
    }

    /// A second origin on another port with this origin's certificate, so one
    /// pre-trusted certificate covers both.
    pub fn start_another(&self) -> Result<Self, String> {
        Self::start_in("enzui-credential-tls-second", Some(&self.dir))
    }

    fn start_in(name: &str, certificate_of: Option<&std::path::Path>) -> Result<Self, String> {
        let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let cert = dir.join("cert.pem");
        let key = dir.join("key.pem");
        if let Some(other) = certificate_of {
            std::fs::copy(other.join("cert.pem"), &cert).map_err(|e| e.to_string())?;
            std::fs::copy(other.join("key.pem"), &key).map_err(|e| e.to_string())?;
        } else {
            Self::generate_certificate(&cert, &key)?;
        }
        Self::serve(dir, cert, key)
    }

    fn generate_certificate(cert: &std::path::Path, key: &std::path::Path) -> Result<(), String> {
        let status = std::process::Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-subj",
                "/CN=localhost",
                "-days",
                "1",
                "-keyout",
            ])
            .arg(key)
            .arg("-out")
            .arg(cert)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map_err(|e| format!("spawn openssl req: {e}"))?;
        if !status.success() {
            return Err(format!("openssl req failed: {status}"));
        }
        Ok(())
    }

    fn serve(
        dir: std::path::PathBuf,
        cert: std::path::PathBuf,
        key: std::path::PathBuf,
    ) -> Result<Self, String> {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
        let port = probe.local_addr().map_err(|e| e.to_string())?.port();
        drop(probe);
        let requests = dir.join("requests");
        std::fs::write(&requests, "").map_err(|e| e.to_string())?;
        let script = dir.join("server.py");
        std::fs::write(
            &script,
            r#"import socket, ssl, sys, threading
port = int(sys.argv[1])
cert, key, log = sys.argv[2:5]
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(cert, key)
# Dual-stack: `localhost` resolves to ::1 before 127.0.0.1 on this host,
# and a v4-only fixture is then simply unreachable at the identity
# (`localhost`) whose certificate these gates pre-trust.
sock = socket.socket(socket.AF_INET6)
sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('::', port))
sock.listen(16)
def serve(raw):
    # Per-connection timeout AND a dedicated thread: WebKit opens speculative
    # connections and abandons handshakes it rejects, and a single-threaded
    # blocking accept loop would then wedge on one idle socket and answer
    # nothing for the rest of the run.
    raw.settimeout(5)
    try:
        with ctx.wrap_socket(raw, server_side=True) as conn:
            data = b''
            while b'\r\n\r\n' not in data and len(data) < 16384:
                part = conn.recv(4096)
                if not part: break
                data += part
            fields = data.split(b' ', 2)
            if len(fields) < 2: return
            path = fields[1].decode('ascii', 'replace')
            with open(log, 'a', encoding='ascii') as out:
                out.write(path + '\n')
                out.flush()
            if path == '/slow-page':
                import time
                time.sleep(1)
            if path == '/credential-start':
                location = f'https://redirect-user:TOP-SECRET@localhost:{port}/credential-target'
                response = f'HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n'
            elif path == '/safe-start':
                location = f'https://localhost:{port}/safe-target'
                response = f'HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n'
            elif path == '/installed-page':
                body = '<html><body style="margin:0;background:#12aa44;color:white;font:28px sans-serif"><h1 style="margin:48px">Installed WPE consumer</h1><p style="margin:48px">HTTPS rendered with the build tree unavailable.</p></body></html>'
                response = f'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n{body}'
            elif path.startswith('/html/'):
                from urllib.parse import unquote
                body = unquote(path[len('/html/'):])
                response = f'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nCache-Control: no-store\r\nContent-Length: {len(body.encode())}\r\nConnection: close\r\n\r\n{body}'
            elif path == '/auth-challenge':
                response = 'HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm="ordinary"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n'
            else:
                body = 'ok'
                response = f'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n{body}'
            conn.sendall(response.encode('ascii'))
    except (ssl.SSLError, ConnectionError, socket.timeout, OSError):
        pass

while True:
    raw, _ = sock.accept()
    threading.Thread(target=serve, args=(raw,), daemon=True).start()
"#,
        )
        .map_err(|e| e.to_string())?;
        let child = std::process::Command::new("python3")
            .arg(&script)
            .arg(port.to_string())
            .arg(&cert)
            .arg(&key)
            .arg(&requests)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|e| format!("spawn TLS fixture: {e}"))?;
        let cert_pem = std::fs::read(&cert).map_err(|e| format!("read cert PEM: {e}"))?;
        std::thread::sleep(std::time::Duration::from_millis(150));
        Ok(Self {
            port,
            child,
            dir,
            requests,
            cert_pem,
        })
    }

    /// The loopback port this origin listens on. A gate needs it to build the
    /// `host:port` spelling that is not a certificate-authorization identity.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The PEM-encoded certificate for pre-trust before navigation.
    pub fn cert_pem(&self) -> &[u8] {
        &self.cert_pem
    }

    /// A URL whose response is `html`, served as a document.
    pub fn html_url(&self, html: &str) -> String {
        let encoded: String = html
            .bytes()
            .map(|byte| {
                if byte.is_ascii_alphanumeric() {
                    (byte as char).to_string()
                } else {
                    format!("%{byte:02X}")
                }
            })
            .collect();
        self.url(&format!("/html/{encoded}"))
    }

    pub fn url(&self, path: &str) -> String {
        format!("https://localhost:{}{path}", self.port)
    }

    /// Every request path this origin logged, oldest first. Diagnostics for a
    /// gate whose count assertion failed: "the server was never reached" and
    /// "the server was reached on another path" are different failures.
    pub fn paths(&self) -> Vec<String> {
        std::fs::read_to_string(&self.requests)
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    pub fn count(&self, path: &str) -> usize {
        std::fs::read_to_string(&self.requests)
            .unwrap_or_default()
            .lines()
            .filter(|seen| *seen == path)
            .count()
    }
}

impl Drop for TlsRedirectOrigin {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
