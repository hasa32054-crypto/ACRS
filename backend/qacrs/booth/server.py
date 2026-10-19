"""SAIF booth server: offline UI + hardened API on top of the real HASSAN v9 engine. Standard library only.

    cd backend
    python -m qacrs.booth.server                       # http://127.0.0.1:8800  (opens nothing on the network)
    python -m qacrs.booth.server --agent 192.168.1.50:8900   # also drive the Linux mini hospital (signed plans)

Security (see docs/qacrs/THREAT_MODEL_STRIDE.md, booth section):
  * binds to 127.0.0.1 only; the Host header must name this server (DNS-rebinding defence);
  * every POST needs the per-install token (from ~/.hassan/booth_token), JSON content type, same Origin;
  * the token is handed only to a loopback client of this server; secrets never live in the repo;
  * strict validation (known machine names, bounded sizes), per-client rate limit, body limit 16 KB;
  * static files come from a fixed list built at start-up (no path from the request touches the disk);
  * CSP without inline script, nosniff, no-referrer, frame-ancestors none;
  * plans to the mini-hospital agent are HMAC envelopes with timestamp + one-time nonce.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import mimetypes
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from qacrs import hassan as H
from qacrs.booth import evidence, qr, secure
from qacrs.booth.core import Booth
from qacrs.booth.incidents import Incidents
from qacrs.booth.memory import AttackMemory

WEB = Path(__file__).resolve().parent / "web"
MAX_BODY = 16 * 1024
EVALUATED_SOLVER_BUDGET_S = H.SOLVER_TIMEOUT_S          # the budget used in every reported evaluation
STABLE_SOLVER_BUDGET_S = 3.0      # booth setting: the optimiser always finishes, so the same attack gives the same decision
CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; "
       "connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
TYPES = {".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8",
         ".js": "text/javascript; charset=utf-8", ".woff2": "font/woff2", ".svg": "image/svg+xml",
         ".png": "image/png", ".json": "application/json; charset=utf-8", ".txt": "text/plain; charset=utf-8"}


def static_table(root: Path = WEB) -> dict:
    table = {}
    for p in sorted(root.rglob("*")):
        if p.is_file() and p.suffix in TYPES:
            table["/" + p.relative_to(root).as_posix()] = (p, TYPES[p.suffix])
    table["/"] = table.get("/index.html")
    return {k: v for k, v in table.items() if v}


def self_test(booth, incidents, ev) -> dict:
    """Start-up self test shown by the boot sequence. Every value is computed here, never typed."""
    root = Path(__file__).resolve().parents[1]
    lock = json.loads((root / "blind_v9" / "LOCK_blind_v9.json").read_text(encoding="utf-8"))
    files = lock["sha256"]
    ok = sum(hashlib.sha256((root / Path(k).name).read_bytes()).hexdigest() == v
             for k, v in files.items() if isinstance(v, str) and (root / Path(k).name).exists())
    pk = getattr(booth.engine, "pk", None)
    return {"locked_ok": ok, "locked_n": sum(isinstance(v, str) for v in files.values()),
            "pq_alg": "ML-DSA-65" if pk else None, "pq_pk_bytes": len(pk) if pk else 0,
            "engine": booth.engine_name, "hosts": len(booth.net.machines), "links": len(booth.net.links),
            "services": len(booth.net.services), "incidents": len(incidents.items),
            "incidents_real": sum(i["origin"] == "real" for i in incidents.items.values()),
            "evidence_files": len(ev["files"]), "started_at": time.time()}


def receipt_text(d: dict) -> str:
    """What the 'verify yourself' QR carries: status, SHA-256 of the certificate, signature prefix, repo."""
    sha = hashlib.sha256(secure.canonical(d["certificate"])).hexdigest()
    return f"ACRS {d.get('engine', 'v9')}|{d['status']}|cert-sha256:{sha}|hmac:{d['signature'][:16]}|{evidence.REPO}"


class Agent:
    """Client for the Linux mini-hospital agent (agent.py). Sends sealed plans; never raw commands."""

    def __init__(self, addr: str, key: bytes):
        host, _, port = addr.rpartition(":")
        import ipaddress
        ip = ipaddress.ip_address(host)
        if not (ip.is_private or ip.is_loopback):
            raise SystemExit("agent address must be on the private LAN or loopback")
        self.base, self.key = f"http://{host}:{int(port)}", key

    def _post(self, path, obj, timeout=8.0):
        req = urllib.request.Request(self.base + path, data=json.dumps(obj).encode(), method="POST",
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:            # noqa: S310 (fixed private address)
            return json.loads(r.read(65536))

    def apply(self, d: dict) -> dict:
        plan = {"isolate": d["hassan"]["isolate"], "segment": d["hassan"]["segment"],
                "restrict": d["hassan"]["restrict"] + d["hassan"]["held"], "ttl_s": int(d["expires_in_s"]),
                "decision_sig": d["signature"][:64]}
        return self._post("/apply", secure.seal(plan, self.key))

    def health(self) -> dict:
        return self._post("/health", secure.seal({"ask": "health"}, self.key))

    def reset(self) -> dict:
        return self._post("/apply", secure.seal({"isolate": [], "segment": [], "restrict": [], "ttl_s": 1,
                                                 "decision_sig": "reset"}, self.key))


class App:
    def __init__(self, token: str, key: bytes, memory: AttackMemory | None = None, agent: Agent | None = None,
                 solver_budget_s: float = EVALUATED_SOLVER_BUDGET_S, engine: str = "v12"):
        H.SOLVER_TIMEOUT_S = solver_budget_s                    # process-local; default = evaluated value
        self.token, self.booth, self.memory, self.agent = token, Booth(key, engine=engine), memory or AttackMemory(), agent
        self.static = static_table()
        self.limiter = secure.ClientLimiter(limit=40, window=10.0)
        self.lock = threading.Lock()
        ev = evidence.collect()
        self.model = self.booth.model() | {
            "evidence": ev,
            "config": {"solver_budget_s": solver_budget_s, "evaluated_solver_budget_s": EVALUATED_SOLVER_BUDGET_S,
                       "agent": bool(agent), "engine": engine},
            "repo_qr": qr.svg(ev["repo"], scale=5),
            "reproduce": "git clone " + ev["repo"] + " && cd ACRS && make hassan-test",
        }
        self.quantum = evidence.quantum_shots()
        self.incidents = Incidents()
        self.incident_catalog = self.incidents.catalog()
        self.model["selftest"] = self_test(self.booth, self.incidents, ev)

    # every API handler: (validated body) -> (code, object)
    def decide(self, b):
        hacked, forged = secure.attack(b, self.booth.names, extra={"live"})
        with self.lock:
            d = self.booth.decide(hacked, forged)
        d["receipt"] = receipt_text(d)
        d["receipt_qr"] = qr.svg(d["receipt"], scale=4)
        if self.agent and b.get("live") is True:
            try:
                d["lab"] = self.agent.apply(d)
            except Exception as e:                              # the lab is optional; the decision stands
                d["lab"] = {"ok": False, "error": type(e).__name__}
        return 200, d

    def judge(self, b):
        hacked, forged = secure.attack({k: b[k] for k in ("hacked", "forged") if k in b}, self.booth.names)
        secure._keys(b, {"hacked", "forged", "isolate", "segment", "seconds"}, {"hacked", "isolate", "segment"})
        iso = secure.machines_list(b["isolate"], self.booth.names, "isolate", 60)
        seg = secure.machines_list(b["segment"], self.booth.names, "segment", 60)
        sec = b.get("seconds", 0)
        if isinstance(sec, bool) or not isinstance(sec, (int, float)) or not 0 <= sec <= 600:
            raise secure.Invalid("seconds: 0-600")
        with self.lock:
            j = self.booth.judge(hacked, forged, iso, seg)
            m = self.booth.decide(hacked, forged)
        return 200, {"judge": j | {"seconds": sec}, "hassan": m}

    def spread(self, b):
        secure._keys(b, {"start", "policy"}, {"start", "policy"})
        start = secure.machines_list(b["start"], self.booth.names, "start", 3)
        if not start or b["policy"] not in ("none", "full", "hassan"):
            raise secure.Invalid("start: 1-3 machines; policy: none | full | hassan")
        with self.lock:
            return 200, self.booth.spread_timeline(start, b["policy"])

    def verify(self, b):
        secure._keys(b, {"hacked", "certificate", "signature", "pq_signature"}, {"hacked", "certificate", "signature"})
        pq = b.get("pq_signature")
        if pq is not None and (not isinstance(pq, str) or len(pq) > 8000):
            raise secure.Invalid("pq_signature: hex text")
        hacked, _ = secure.attack({"hacked": b["hacked"]}, self.booth.names)
        if not isinstance(b["certificate"], dict) or len(secure.canonical(b["certificate"])) > 8192:
            raise secure.Invalid("certificate: object up to 8 KB")
        if not isinstance(b["signature"], str) or len(b["signature"]) > 128:
            raise secure.Invalid("signature: text")
        with self.lock:
            return 200, self.booth.verify(hacked, b["certificate"], b["signature"], pq)

    def save_attack(self, b):
        secure._keys(b, {"name", "hacked", "forged", "consent"}, {"name", "hacked", "consent"})
        if b["consent"] is not True:
            raise secure.Invalid("consent is required to save an attack")
        name = secure.label(b["name"])
        hacked, forged = secure.attack({k: b[k] for k in ("hacked", "forged") if k in b}, self.booth.names)
        with self.lock:
            return 200, self.memory.save(self.booth, name, hacked, forged)

    def delete_attack(self, b):
        secure._keys(b, {"id"}, {"id"})
        if not isinstance(b["id"], str) or len(b["id"]) != 16:
            raise secure.Invalid("id")
        return 200, {"deleted": self.memory.delete(b["id"])}

    def regress(self, b):
        secure._keys(b, set())
        with self.lock:
            return 200, self.memory.regress(self.booth)

    def lab(self, b):
        secure._keys(b, {"reset"})
        if not self.agent:
            return 200, {"connected": False}
        try:
            out = self.agent.reset() if b.get("reset") is True else self.agent.health()
            return 200, {"connected": True} | out
        except Exception as e:
            return 200, {"connected": False, "error": type(e).__name__}

    def incident(self, b):
        secure._keys(b, {"id", "mode"}, {"id", "mode"})
        if not isinstance(b["id"], str) or b["id"] not in self.incidents.items:
            raise secure.Invalid("id: unknown incident")
        if b["mode"] not in ("normal", "fault"):
            raise secure.Invalid("mode: normal | fault")
        with self.lock:
            return 200, self.incidents.run(b["id"], b["mode"])

    POST = {"/api/incident": incident, "/api/decide": decide, "/api/judge": judge, "/api/spread": spread, "/api/verify": verify,
            "/api/attacks/save": save_attack, "/api/attacks/delete": delete_attack, "/api/attacks/regress": regress,
            "/api/lab": lab}


def make_handler(app: App, port_ref: list):
    class Handler(BaseHTTPRequestHandler):
        server_version = "ACRS-booth"
        sys_version = ""

        def log_message(self, *a):
            pass

        # ---------------------------------------------------------------- helpers
        def _headers(self, code, ctype, n, cache=False):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(n))
            self.send_header("Content-Security-Policy", CSP)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Cross-Origin-Opener-Policy", "same-origin")
            self.send_header("Cross-Origin-Resource-Policy", "same-origin")
            self.send_header("Cache-Control", "public, max-age=3600" if cache else "no-store")
            self.end_headers()

        def _json(self, code, obj):
            body = json.dumps(obj, ensure_ascii=False).encode()
            self._headers(code, "application/json; charset=utf-8", len(body))
            self.wfile.write(body)

        def _host_ok(self) -> bool:
            return self.headers.get("Host") in {f"127.0.0.1:{port_ref[0]}", f"localhost:{port_ref[0]}"}

        def _origin_ok(self) -> bool:
            o = self.headers.get("Origin")
            return o is None or o in {f"http://127.0.0.1:{port_ref[0]}", f"http://localhost:{port_ref[0]}"}

        def _loopback(self) -> bool:
            return self.client_address[0] in ("127.0.0.1", "::1")

        # ---------------------------------------------------------------- GET
        def do_GET(self):
            if not self._host_ok():
                return self._json(421, {"error": "wrong host"})
            if not app.limiter.allow(self.client_address[0]):
                return self._json(429, {"error": "slow down"})
            path = self.path.split("?", 1)[0]
            if path == "/api/session":
                site = self.headers.get("Sec-Fetch-Site")
                if not self._loopback() or site not in (None, "same-origin", "none"):
                    return self._json(403, {"error": "forbidden"})
                return self._json(200, {"token": app.token})
            if path == "/api/model":
                return self._json(200, app.model)
            if path == "/api/quantum":
                return self._json(200, app.quantum)
            if path == "/api/incidents":
                return self._json(200, app.incident_catalog)
            if path == "/api/attacks":
                return self._json(200, {"attacks": app.memory.public()})
            hit = app.static.get(path)
            if not hit:
                return self._json(404, {"error": "not found"})
            body = hit[0].read_bytes()
            self._headers(200, hit[1], len(body), cache=hit[1].startswith("font/"))
            self.wfile.write(body)

        # ---------------------------------------------------------------- POST
        def do_POST(self):
            if not self._host_ok() or not self._origin_ok():
                return self._json(403, {"error": "forbidden"})
            if not secure.token_ok(self.headers.get("X-HASSAN-Token"), app.token):
                return self._json(401, {"error": "token required"})
            if not app.limiter.allow(self.client_address[0]):
                return self._json(429, {"error": "slow down"})
            if (self.headers.get("Content-Type") or "").split(";")[0].strip() != "application/json":
                return self._json(415, {"error": "application/json only"})
            fn = App.POST.get(self.path)
            if fn is None:
                return self._json(404, {"error": "not found"})
            try:
                n = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                n = -1
            if not 0 < n <= MAX_BODY:
                return self._json(413, {"error": "body size"})
            try:
                body = json.loads(self.rfile.read(n).decode("utf-8"))
                code, out = fn(app, body)
            except (ValueError, UnicodeDecodeError) as e:       # secure.Invalid is a ValueError
                return self._json(400, {"error": str(e)[:120] if isinstance(e, secure.Invalid) else "bad json"})
            except Exception as e:
                return self._json(500, {"error": type(e).__name__})
            self._json(code, out)

    return Handler


def make_server(port: int = 8800, token: str | None = None, key: bytes | None = None, **kw) -> ThreadingHTTPServer:
    token = token or secure.load_secret("booth_token").hex()
    key = key or secure.load_secret("plan_key")
    port_ref = [port]
    app = App(token, key, **kw)
    srv = ThreadingHTTPServer(("127.0.0.1", port), make_handler(app, port_ref))
    port_ref[0] = srv.server_address[1]
    srv.app = app
    return srv


def selfcheck(app: App) -> dict:
    """Start-up check: how often the solver budget forces the fail-safe on typical critical attacks."""
    tests = [{"pc_admin1": 9, "dc1": 9}, {"pc_admin1": 9, "dc1": 9, "ehr_db": 9, "backup": 8},
             {"pc_doc1": 8, "pacs1": 8, "pacs_store": 9}, {"pc_nurse2": 7, "ehr_app2": 8, "ehr_db": 9},
             {"pc_recep1": 8, "web1": 8, "ehr_app1": 8},
             {m: 9 for m in sorted(app.booth.names)}]                 # the whole hospital at once (heaviest case)
    fb = sum(bool(app.booth.decide(t, [])["fallback"]) for t in tests)
    return {"attacks": len(tests), "fail_safe": fb}


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python -m qacrs.booth.server")
    ap.add_argument("--port", type=int, default=8800)
    ap.add_argument("--agent", help="LAN address of the Linux mini-hospital agent, e.g. 192.168.1.50:8900")
    ap.add_argument("--engine", choices=("v12", "v9"), default="v12", help="decision engine (default v12)")
    ap.add_argument("--auto-budget", action="store_true",
                    help=f"booth setting: solver budget {STABLE_SOLVER_BUDGET_S} s so the optimiser always finishes and "
                         "the same attack always gives the same decision on a slow laptop; shown on screen as a deviation")
    ap.add_argument("--solver-budget", type=float, default=EVALUATED_SOLVER_BUDGET_S,
                    help=f"solver time budget in s (default {EVALUATED_SOLVER_BUDGET_S} = the evaluated setting; "
                         "a different value is shown on screen as a deviation)")
    a = ap.parse_args(argv)
    if a.auto_budget:
        a.solver_budget = max(a.solver_budget, STABLE_SOLVER_BUDGET_S)
    if not 0.05 <= a.solver_budget <= 5.0:
        raise SystemExit("--solver-budget must be between 0.05 and 5.0 s")
    key = secure.load_secret("plan_key")
    agent = Agent(a.agent, key) if a.agent else None
    srv = make_server(a.port, key=key, agent=agent, solver_budget_s=a.solver_budget, engine=a.engine)
    sc = selfcheck(srv.app)
    srv.app.model["selftest"]["reference_attacks"] = sc["attacks"]
    srv.app.model["selftest"]["fail_safe"] = sc["fail_safe"]
    print(f"ACRS booth: http://127.0.0.1:{srv.server_address[1]}/   (loopback only; secrets in {secure.secret_dir()})")
    print(f"self-check: {sc['fail_safe']}/{sc['attacks']} reference attacks hit the solver budget "
          f"({a.solver_budget:.2f} s) and fell back to the safe path."
          + ("  Decisions may differ between runs on this machine; start with --auto-budget." if sc["fail_safe"] else ""))
    if agent:
        print(f"mini hospital agent: {agent.base} (signed plans, 30 s window, one-time nonces)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
