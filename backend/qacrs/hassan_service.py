"""v8 G: HASSAN integration — HTTP API (44), ACRS timers adapter (45), incident replay CLI (46).

    python -m qacrs.hassan_service serve [--port 8765]              # POST /hassan/decide, GET /hassan/health
    python -m qacrs.hassan_service replay <scenario_id>             # print the decision card of any stored scenario
    python -m qacrs.hassan_service replay <scenario_id> --json

Standard library only. Binds to 127.0.0.1. The API decides; it never touches a network (no executor is wired in).
Request:  {"network": "net12" | "net22" | "hospital60", "hacked": {"web1": 8, ...}, "id": "optional",
           "ndr_lateral": [["web1", "app1"], ...]  (optional: independent network-sensor lateral flows -> guard v2)}
Response: the HassanDecision as JSON (+ "acrs" block from the timers adapter).
"""
from __future__ import annotations

import argparse
import json
import sys
import threading
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from qacrs import hassan as H
from qacrs import realism_v8 as RV
from qacrs.network import Scenario, build as build_net

MAX_BODY = 64 * 1024


def networks() -> dict:
    return {n.name: n for n in (build_net(1), build_net(2), RV.hospital60())}


# ------------------------------------------------------------------ 45. ACRS timers adapter --------------------------
# ACRS (backend/app/engines/policy.py) gives restrictive containment a tier deadline: tier 0 = 7 s, 1 = 15 s, 2 = 90 s.
ACRS_TIER_DEADLINE_S = {0: 7.0, 1: 15.0, 2: 90.0}


def to_acrs(net, d: H.HassanDecision, tier: int = 0, sc=None) -> dict:
    """Map a HASSAN decision onto ACRS actions. Since v11 every automatic action goes through gate_v11.enforce:
    only what the gate allows is marked auto; anything else proposed (and every escalation) is queued for approvals,
    exactly as ACRS does for full containment (2 approvals at tier 0). Without the scenario the gate cannot check
    what was reported, so nothing is marked automatic (safe default)."""
    from qacrs import gate_v11 as GV
    if sc is not None:
        g = GV.enforce(net, sc, d)
    else:
        g = {"auto_isolate": [], "auto_segment": [], "blocked_all": True, "reason": "scenario not given to to_acrs",
             "held": [{"target": m, "action": "ISOLATE", "reason": "scenario not given"} for m in d.isolate]
             + [{"target": m, "action": "SEGMENT", "reason": "scenario not given"} for m in d.segment]}
    actions = ([{"level": "ISOLATE", "target": m, "auto": True} for m in g["auto_isolate"]]
               + [{"level": "SEGMENT", "target": m, "auto": True} for m in g["auto_segment"]]
               + [{"level": "RESTRICT", "target": m, "auto": True} for m in d.restrict]
               + [{"level": h["action"], "target": h["target"], "auto": False, "approvals": 2,
                   "reason": f"gate: {h['reason']}"} for h in g["held"]]
               + [{"level": "APPROVAL", "target": e["target"], "auto": False, "approvals": e.get("approvals", 2),
                   "reason": e.get("rule")} for e in d.escalations])
    deadline = ACRS_TIER_DEADLINE_S[tier]
    return {"tier": tier, "deadline_s": deadline, "decision_s": d.ms / 1000,
            "within_deadline": d.ms / 1000 < deadline, "actions": actions,
            "gate": {"blocked_all": g["blocked_all"], "reason": g["reason"], "held": len(g["held"])}}


# ------------------------------------------------------------------ 44. HTTP API ------------------------------------
class _Handler(BaseHTTPRequestHandler):
    engines: dict = {}
    lock = threading.Lock()

    def log_message(self, *a):                       # quiet
        pass

    def _send(self, code: int, obj: dict):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/hassan/health":
            return self._send(200, {"ok": True, "networks": sorted(self.engines)})
        self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/hassan/decide":
            return self._send(404, {"error": "not found"})
        n = int(self.headers.get("Content-Length") or 0)
        if n <= 0 or n > MAX_BODY:
            return self._send(413 if n > MAX_BODY else 400, {"error": "body size"})
        try:
            req = json.loads(self.rfile.read(n))
            eng = self.engines[req["network"]]
            hacked = {str(k): int(v) for k, v in dict(req["hacked"]).items()}
            lateral = {(str(a), str(b)) for a, b in req["ndr_lateral"]} if "ndr_lateral" in req else None
        except (ValueError, KeyError, TypeError) as e:
            return self._send(400, {"error": f"bad request: {type(e).__name__}"})
        sc = Scenario(str(req.get("id", "api")), req["network"], hacked, "api")
        with self.lock:                               # engine state (rate limiter) is shared
            d = eng.decide(sc, lateral)
        out = asdict(d)
        out["acrs"] = to_acrs(eng.net, d, int(req.get("tier", 0)) if str(req.get("tier", 0)) in "012" else 0, sc=sc)
        self._send(200, out)


def make_server(port: int = 0, key: bytes = b"demo-key-not-secret", limiter_factory=None) -> ThreadingHTTPServer:
    from qacrs.hassan_v9 import EngineV9
    _Handler.engines = {name: EngineV9(net, key=key, limiter=(limiter_factory or H.RateLimiter)())
                        for name, net in networks().items()}
    return ThreadingHTTPServer(("127.0.0.1", port), _Handler)


# ------------------------------------------------------------------ 46. incident replay -----------------------------
def find_scenario(sid: str):
    from qacrs.phase11_executor import all_pairs
    for net, sc in all_pairs():
        if sc.id == sid:
            return net, sc
    from qacrs.phase8_ood import chain_scenarios
    h60 = RV.hospital60()
    for sc in chain_scenarios(h60, 200, 7101):                      # the Hospital-60 evaluation set
        if sc.id == sid:
            return h60, sc
    return None, None


def replay(sid: str) -> dict | None:
    net, sc = find_scenario(sid)
    if net is None:
        return None
    d = H.Engine(net, limiter=H.RateLimiter(limit=10 ** 9)).decide(sc)
    return {"scenario": {"id": sc.id, "network": sc.network, "hacked": sc.hacked, "description": sc.description},
            "decision": asdict(d), "acrs": to_acrs(net, d, sc=sc)}


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python -m qacrs.hassan_service")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve"); s.add_argument("--port", type=int, default=8765)
    r = sub.add_parser("replay"); r.add_argument("scenario_id"); r.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    if a.cmd == "serve":
        srv = make_server(a.port)
        print(f"HASSAN API on http://127.0.0.1:{srv.server_address[1]}/hassan/decide (decides only; executes nothing)")
        srv.serve_forever()
    out = replay(a.scenario_id)
    if out is None:
        sys.exit(f"unknown scenario id: {a.scenario_id}")
    if a.json:
        print(json.dumps(out, indent=1, ensure_ascii=False, default=str))
    else:
        c = out["decision"]["card"]
        print(f"[{out['scenario']['id']}] {out['scenario']['description']}\n  status: {out['decision']['status']}\n"
              f"  EN: {c['en']}\n  AR: {c['ar']}\n  services saved vs full isolation: {c['services_saved_vs_full_isolation']}")


if __name__ == "__main__":
    main()
