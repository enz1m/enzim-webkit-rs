"""Two explicit TLS origins for requesting-frame permission identity checks."""
import http.server
import json
import pathlib
import ssl
import subprocess
import sys
import threading
root = pathlib.Path(sys.argv[1])
cert, key = root/'cert.pem', root/'key.pem'
subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=localhost','-addext','subjectAltName=IP:127.0.0.1','-out',str(cert),'-keyout',str(key)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
servers=[]
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        child = f'https://127.0.0.1:{servers[1].server_port}'

        if self.path=='/notify':
            body='<!doctype html><style>html,body,button{margin:0;width:100%;height:100%}</style><button onclick="Notification.requestPermission().then(p=>{document.title=\'asked:\'+p;if(p===\'granted\')new Notification(\'legacy-positive\',{body:\'positive-body\',tag:\'positive-tag\'})})">Allow notification</button>'
        elif self.path=='/child':
            body='''<!doctype html><script>navigator.geolocation.getCurrentPosition(p=>parent.postMessage('child-ok','*'),e=>parent.postMessage('child-error-'+e.code,'*'),{timeout:500});</script><p>Child origin</p>'''
        elif self.path=='/frame':
            body=f'''<!doctype html><script>addEventListener('message',e=>{{if(e.origin==='{child}')document.body.dataset.child=e.data}})</script><iframe allow="geolocation *" src="{child}/child"></iframe>'''
        else:
            body='<!doctype html><title>Permissions fixture</title><p>Permission authority</p>'
        data=body.encode();self.send_response(200)
        self.send_header('Content-Type','text/html');self.send_header('Content-Length',str(len(data)))
        self.send_header('Permissions-Policy',f'geolocation=(self "{child}")')
        self.end_headers();self.wfile.write(data)
    def log_message(self,*args):pass
for _ in range(2):
    server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(cert,key)
    server.socket=context.wrap_socket(server.socket,server_side=True);servers.append(server)
servers.append(http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler))
for server in servers:threading.Thread(target=server.serve_forever,daemon=True).start()
print(json.dumps([f'{"http" if i==2 else "https"}://127.0.0.1:{s.server_port}' for i,s in enumerate(servers)]),flush=True)
threading.Event().wait()
