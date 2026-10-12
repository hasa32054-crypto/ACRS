"""One machine of the mini hospital (runs inside a container; Python standard library only).

  clinical port  : the service staff use (HTTP 200 "ok <role>")
  2222           : stand-in for an admin protocol (what lateral movement would use); accepts and closes
  7000 (control) : GET /reach?ip=<lab ip>&port=<allowed port> -> {"open": true|false}
                   lets the agent ask "can this machine still reach that one?" after HASSAN's rules.
                   Only lab IPs and allowed ports are accepted, so it cannot be used to scan anything else.
Nothing here runs commands, writes files, or contains attack code.
"""
import ipaddress
import json
import os
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

ROLE = os.environ.get("ROLE", "node")[:60]
CLINICAL = int(os.environ.get("CLINICAL_PORT", "0"))
LAB_IPS = {str(ipaddress.ip_address(x)) for x in os.environ.get("LAB_IPS", "").split(",") if x}
ALLOWED_PORTS = {int(p) for p in os.environ.get("ALLOWED_PORTS", "").split(",") if p}
ADMIN, CONTROL = 2222, 7000


class Clinical(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        b = f"ok {ROLE}\n".encode()
        self.send_response(200); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)


class Control(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _json(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)

    def do_GET(self):
        u = urlparse(self.path)
        if u.path != "/reach":
            return self._json(404, {"error": "not found"})
        q = parse_qs(u.query)
        ip, port = (q.get("ip") or [""])[0], (q.get("port") or ["0"])[0]
        if ip not in LAB_IPS or not port.isdigit() or int(port) not in ALLOWED_PORTS:
            return self._json(400, {"error": "lab ip and allowed port only"})
        try:
            with socket.create_connection((ip, int(port)), timeout=0.8):
                ok = True
        except OSError:
            ok = False
        self._json(200, {"open": ok})


def admin_listener():
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", ADMIN)); s.listen(16)
    while True:
        c, _ = s.accept(); c.close()


def raw_listener(port):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port)); s.listen(16)
    while True:
        c, _ = s.accept(); c.close()


if __name__ == "__main__":
    threading.Thread(target=admin_listener, daemon=True).start()
    if CLINICAL and CLINICAL != 8080:
        threading.Thread(target=raw_listener, args=(CLINICAL,), daemon=True).start()
    elif CLINICAL == 8080:
        threading.Thread(target=ThreadingHTTPServer(("0.0.0.0", 8080), Clinical).serve_forever, daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", CONTROL), Control).serve_forever()
