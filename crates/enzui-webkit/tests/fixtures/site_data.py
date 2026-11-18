"""TLS cookie flags and storage for the owner-thread site-data probe."""
import http.server
import pathlib
import ssl
import subprocess
import sys

root = pathlib.Path(sys.argv[1])
cert, key = root / "cert.pem", root / "key.pem"
subprocess.run(
    ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
     "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1",
     "-out", str(cert), "-keyout", str(key)],
    check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
)


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'<!doctype html><title>Site data</title><script>localStorage.setItem("site-data", "present")</script><p>Owned inventory fixture</p>'
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if self.path == "/":
            self.send_header("Set-Cookie", "native_flags=present; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(cert, key)
server.socket = context.wrap_socket(server.socket, server_side=True)
print(f"https://127.0.0.1:{server.server_port}", flush=True)
server.serve_forever()
