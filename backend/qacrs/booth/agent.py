"""Mini-hospital agent for the Linux Mint laptop (idea 10). Standard library only.

It accepts ONLY sealed plans (HMAC-SHA256 + timestamp + one-time nonce, see secure.py) from the booth server and
turns them into firewall rules for the small Docker hospital. It never runs a command it was sent:

  * the only thing a plan can say is which known machine to isolate / segment / restrict;
  * machine -> container IP comes from the agent's own config (allowlist), never from the plan;
  * rules are built from fixed templates, live in the agent's own chain HASSAN (jumped to from DOCKER-USER),
    and are installed atomically with `iptables-restore --noflush` (fixed argv, rules on stdin, no shell);
  * after installing, the chain is read back (`iptables -S HASSAN`) and compared with the plan (structural twin);
    if it differs, the chain is emptied (fail closed to "no HASSAN rules", never to unknown rules);
  * every plan has a TTL; when it expires the chain is emptied (containment must be re-confirmed);
  * dry-run is the default: without --apply it prints the rules and touches nothing.

    sudo python3 -m qacrs.booth.agent --bind 192.168.1.50 --apply      # on the Mint laptop
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import shutil
import subprocess
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from qacrs.booth import secure

CHAIN = "HASSAN"
HERE = Path(__file__).resolve().parent
DEFAULT_CONFIG = HERE / "minihospital" / "lab.json"
MAX_BODY = 8 * 1024
EMPTY = [f"-A {CHAIN} -j RETURN"]


def load_config(path: Path = DEFAULT_CONFIG) -> dict:
    cfg = json.loads(path.read_text(encoding="utf-8"))
    nodes = {}
    for name, n in cfg["nodes"].items():
        ip = ipaddress.ip_address(n["ip"])
        if not ip.is_private:
            raise ValueError(f"{name}: lab IPs must be private")
        nodes[name] = {"ip": str(ip), "clinical_port": int(n["clinical_port"]), "role": str(n.get("role", ""))}
    return {"nodes": nodes, "c2": str(ipaddress.ip_address(cfg["c2"]["ip"])), "c2_port": int(cfg["c2"]["port"]),
            "admin_port": int(cfg["admin_port"]), "client": str(ipaddress.ip_address(cfg["client"]["ip"])),
            "control_port": int(cfg["control_port"])}


# ------------------------------------------------------------------ rules from fixed templates -----------------------
def rules(cfg: dict, plan: dict) -> tuple[list[str], list[str]]:
    """Plan -> iptables rule lines for chain HASSAN (exactly as `iptables -S` prints them).
    Returns (rules, machine names that are not in the lab and were ignored)."""
    nodes, admin = cfg["nodes"], cfg["admin_port"]
    out = [f"-A {CHAIN} -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN"]
    ignored = []
    for kind in ("isolate", "segment", "restrict"):
        for m in plan.get(kind, []):
            if m not in nodes:
                ignored.append(m)
                continue
            ip, port = nodes[m]["ip"], nodes[m]["clinical_port"]
            if kind == "isolate":
                out += [f"-A {CHAIN} -s {ip}/32 -j DROP", f"-A {CHAIN} -d {ip}/32 -j DROP"]
            elif kind == "segment":     # keep the clinical service; cut lateral movement in and out + attacker channel
                out += [f"-A {CHAIN} -d {ip}/32 -p tcp -m tcp --dport {port} -j RETURN",
                        f"-A {CHAIN} -d {ip}/32 -j DROP",
                        f"-A {CHAIN} -s {ip}/32 -p tcp -m tcp --dport {admin} -j REJECT --reject-with tcp-reset",
                        f"-A {CHAIN} -s {ip}/32 -d {cfg['c2']}/32 -p tcp -j REJECT --reject-with tcp-reset"]
            else:                       # restrict: cut the attacker's channel only
                out += [f"-A {CHAIN} -s {ip}/32 -d {cfg['c2']}/32 -p tcp -j REJECT --reject-with tcp-reset"]
    out += EMPTY
    return out, sorted(set(ignored))


def restore_text(lines: list[str]) -> str:
    return "*filter\n:" + CHAIN + " - [0:0]\n" + "".join(l + "\n" for l in lines) + "COMMIT\n"


def validate_plan(plan: dict) -> dict:
    secure._keys(plan, {"isolate", "segment", "restrict", "ttl_s", "decision_sig"},
                 {"isolate", "segment", "restrict", "ttl_s"})
    out = {}
    for k in ("isolate", "segment", "restrict"):
        v = plan[k]
        if not isinstance(v, list) or len(v) > 60 or not all(isinstance(x, str) and len(x) <= 32 for x in v):
            raise secure.Invalid(k)
        out[k] = v
    if isinstance(plan["ttl_s"], bool) or not isinstance(plan["ttl_s"], int) or not 1 <= plan["ttl_s"] <= 3600:
        raise secure.Invalid("ttl_s")
    out["ttl_s"] = plan["ttl_s"]
    return out


# ------------------------------------------------------------------ firewall backend --------------------------------
class Firewall:
    def __init__(self, apply: bool):
        self.apply = apply
        if apply:
            if os.name != "posix" or os.geteuid() != 0:
                raise SystemExit("--apply needs root on Linux (sudo)")
            self.restore, self.iptables = shutil.which("iptables-restore"), shutil.which("iptables")
            if not (self.restore and self.iptables):
                raise SystemExit("iptables not found")
            self._ensure_jump()

    def _run(self, argv, stdin=None):
        return subprocess.run(argv, input=stdin, capture_output=True, text=True, timeout=5, check=False)

    def _ensure_jump(self):
        self._run([self.restore, "--noflush"], restore_text(EMPTY))
        if self._run([self.iptables, "-C", "DOCKER-USER", "-j", CHAIN]).returncode != 0:
            if self._run([self.iptables, "-I", "DOCKER-USER", "1", "-j", CHAIN]).returncode != 0:
                raise SystemExit("DOCKER-USER chain missing: start the lab first (docker compose up -d)")

    def install(self, lines: list[str]) -> dict:
        if not self.apply:
            return {"applied": False, "dry_run": True, "rules": lines, "ms": 0.0, "twin_ok": None}
        t = time.perf_counter()
        r = self._run([self.restore, "--noflush"], restore_text(lines))
        ms = round(1000 * (time.perf_counter() - t), 1)
        if r.returncode != 0:
            return {"applied": False, "error": "iptables-restore failed", "ms": ms, "twin_ok": None}
        got = [l for l in self._run([self.iptables, "-S", CHAIN]).stdout.splitlines() if l.startswith("-A ")]
        twin_ok = got == lines
        if not twin_ok:
            self._run([self.restore, "--noflush"], restore_text(EMPTY))
        return {"applied": twin_ok, "rules": lines, "ms": ms, "twin_ok": twin_ok}


# ------------------------------------------------------------------ health from inside the lab ---------------------
def probe(cfg: dict, compromised: list[str]) -> dict:
    """Ask lab nodes (control port: host -> container, not filtered by DOCKER-USER) to try container-to-container
    connections. Nodes connect only to lab IPs and ports on their own allowlist (node.py)."""
    nodes = cfg["nodes"]

    def ask(src_ip, dst_ip, port):
        url = f"http://{src_ip}:{cfg['control_port']}/reach?ip={dst_ip}&port={port}"
        try:
            with urllib.request.urlopen(url, timeout=1.5) as r:            # noqa: S310 (lab-only private IPs)
                return bool(json.loads(r.read(256)).get("open"))
        except Exception:
            return None                                                    # unknown: node down or lab off

    jobs = {("clinical", m, None): (cfg["client"], n["ip"], n["clinical_port"]) for m, n in nodes.items()}
    for m in compromised:
        if m in nodes:
            src = nodes[m]["ip"]
            jobs[("c2", m, None)] = (src, cfg["c2"], cfg["c2_port"])
            for o in [o for o in nodes if o != m][:2]:
                jobs[("lateral", m, o)] = (src, nodes[o]["ip"], cfg["admin_port"])
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=16) as pool:                         # probes in parallel: ~1 s in total
        res = dict(zip(jobs, pool.map(lambda a: ask(*a), jobs.values())))
    out = {"clinical_from_client": {}, "lateral_from_compromised": {}, "c2_from_compromised": {}}
    for (kind, m, o), v in res.items():
        if kind == "clinical":
            out["clinical_from_client"][m] = v
        elif kind == "c2":
            out["c2_from_compromised"][m] = v
        else:
            out["lateral_from_compromised"].setdefault(m, {})[o] = v
    return out


# ------------------------------------------------------------------ server -----------------------------------------
class Agent:
    def __init__(self, cfg, key, fw: Firewall, probe_fn=probe):
        self.cfg, self.key, self.fw, self.probe = cfg, key, fw, probe_fn
        self.nonces, self.lock = secure.NonceCache(), threading.Lock()
        self.limiter = secure.ClientLimiter(limit=20, window=10.0)
        self.expiry, self.compromised = None, []
        threading.Thread(target=self._ttl_loop, daemon=True).start()

    def _ttl_loop(self):
        while True:
            time.sleep(1)
            with self.lock:
                if self.expiry and time.time() > self.expiry:
                    self.fw.install(EMPTY)
                    self.expiry, self.compromised = None, []

    def handle(self, path, env):
        msg, why = secure.open_envelope(env, self.key, self.nonces)
        if msg is None:
            return 403, {"ok": False, "error": why}
        if path == "/health":
            return 200, {"ok": True, "nodes": list(self.cfg["nodes"]), "probe": self.probe(self.cfg, self.compromised),
                         "expires_in_s": max(0, int(self.expiry - time.time())) if self.expiry else 0,
                         "mode": "apply" if self.fw.apply else "dry-run"}
        plan = validate_plan(msg)
        lines, ignored = rules(self.cfg, plan)
        with self.lock:
            res = self.fw.install(lines)
            self.expiry = time.time() + plan["ttl_s"] if res.get("applied") else None
            self.compromised = [m for m in plan["isolate"] + plan["segment"] + plan["restrict"] if m in self.cfg["nodes"]]
        return 200, {"ok": True, "ignored_not_in_lab": ignored, "mode": "apply" if self.fw.apply else "dry-run",
                     **res, "probe": self.probe(self.cfg, self.compromised)}


def make_server(bind: str, port: int, agent: Agent) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _json(self, code, obj):
            b = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def do_GET(self):
            self._json(405, {"error": "POST a sealed envelope"})

        def do_POST(self):
            if not agent.limiter.allow(self.client_address[0]):
                return self._json(429, {"error": "slow down"})
            if self.path not in ("/apply", "/health"):
                return self._json(404, {"error": "not found"})
            try:
                n = int(self.headers.get("Content-Length") or 0)
                if not 0 < n <= MAX_BODY:
                    return self._json(413, {"error": "body size"})
                code, out = agent.handle(self.path, json.loads(self.rfile.read(n)))
            except (ValueError, UnicodeDecodeError) as e:
                return self._json(400, {"error": str(e)[:80] if isinstance(e, secure.Invalid) else "bad request"})
            self._json(code, out)

    ip = ipaddress.ip_address(bind)
    if not (ip.is_private or ip.is_loopback):
        raise SystemExit("bind to a private LAN address only")
    return ThreadingHTTPServer((bind, port), Handler)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python -m qacrs.booth.agent")
    ap.add_argument("--bind", default="127.0.0.1", help="this laptop's private LAN IP")
    ap.add_argument("--port", type=int, default=8900)
    ap.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    ap.add_argument("--apply", action="store_true", help="really install rules (root). Default: dry-run")
    ap.add_argument("--print-rules", nargs="*", metavar="MACHINE", help="print rules for isolating these and exit")
    a = ap.parse_args(argv)
    cfg = load_config(a.config)
    if a.print_rules is not None:
        print(restore_text(rules(cfg, {"isolate": a.print_rules, "segment": [], "restrict": []})[0]))
        return
    agent = Agent(cfg, secure.load_secret("plan_key"), Firewall(a.apply))
    srv = make_server(a.bind, a.port, agent)
    print(f"HASSAN lab agent on {a.bind}:{a.port} ({'APPLY' if a.apply else 'dry-run'}); sealed plans only")
    srv.serve_forever()


if __name__ == "__main__":
    main()
