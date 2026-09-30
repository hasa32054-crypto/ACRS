"""Hospital in a box: a real website, a real app server and a real device service, each on a "hacked" machine.

    sudo python3 -m research.hospital_box          # Linux, root (needs iptables)

What happens, for each box and for both policies (full isolation vs ACRS):
  1. The box runs a real HTTP service: the appointments website, the records API a nurse app calls, or the
     MRI console status service.
  2. A real client keeps using it (a patient loading the website, the nurse app calling the API, the
     radiology workstation polling the MRI), every 20 ms, and checks the answer is correct.
  3. The box is "hacked": it keeps opening connections to the attacker's server. This is harmless TCP
     traffic that stands in for malware; nothing malicious runs.
  4. The alert reaches ACRS; the real decision engine decides; the real planner turns it into commands; a
     real Linux firewall rule enforces them.
  5. We measure: was the attacker cut off, how fast, and did the website/app/device keep answering.

Each box uses a real incident from the experiment (same host, same evidence), so the decision is the one the
engine really makes for that machine. Everything runs on one Linux machine; rules are removed afterwards.
"""
from __future__ import annotations

import http.client
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from app.engines.decision import decide as acrs_decide
from app.engines.response import plan
from research import experiment as E
from research.experiment import incidents, uniform_decide
from research.real_lab import C2, Flow, ipt, listener, rules_for

OUT = Path(__file__).parent / "results"

BOXES = [
    {"key": "website", "title": "Appointments website", "scenario": "erp_web_exploit_cw",
     "box": ("127.40.0.10", 47610), "client": "127.50.0.10", "path": "/",
     "body": b"<!doctype html><title>Hospital appointments</title><h1>Book an appointment</h1>", "expect": b"Book an appointment"},
    {"key": "app", "title": "Nurse app (records API)", "scenario": "erp_db_exfil",
     "box": ("127.40.0.20", 47611), "client": "127.50.0.20", "path": "/api/patients/1042",
     "body": json.dumps({"patient": 1042, "ward": "ICU-2", "allergies": ["penicillin"]}).encode(), "expect": b"ICU-2"},
    {"key": "device", "title": "MRI console", "scenario": "mri_non_isolatable",
     "box": ("127.40.0.30", 47612), "client": "127.50.0.30", "path": "/status",
     "body": json.dumps({"device": "MRI-CTRL-02", "scan": "running"}).encode(), "expect": b"running"},
]
PERIOD, TIMEOUT = 0.02, 0.15


def serve(box: dict) -> ThreadingHTTPServer:
    body = box["body"]
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers()
            self.wfile.write(body)
        def log_message(self, *a):
            pass
    srv = ThreadingHTTPServer(box["box"], H); srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


class User(threading.Thread):
    """A real client using the service: HTTP GET every 20 ms, success only if the right answer comes back."""
    def __init__(self, box: dict):
        super().__init__(daemon=True); self.box = box; self.log: list[tuple[float, bool]] = []; self.stop = False
    def run(self):
        host, port = self.box["box"]
        while not self.stop:
            t = time.monotonic(); ok = False
            try:
                c = http.client.HTTPConnection(host, port, timeout=TIMEOUT, source_address=(self.box["client"], 0))
                c.request("GET", self.box["path"]); r = c.getresponse()
                ok = r.status == 200 and self.box["expect"] in r.read(); c.close()
            except OSError:
                pass
            self.log.append((t, ok))
            time.sleep(PERIOD)


def find(scenario: str) -> dict:
    return next(i for i in incidents() if i["scenario"] == scenario and i["attr"].asset)


def run(box: dict, policy, name: str) -> dict:
    inc = find(box["scenario"]); asset = inc["attr"].asset
    srv = serve(box); user = User(box); beacon = Flow(box["box"][0], C2)
    user.start(); beacon.start(); time.sleep(0.3)                      # service in use, attacker connected
    t_alert = time.monotonic()
    d = policy(inc["attr"], inc["ra"], inc["dets"], 0, inc["segment_hits"])
    cmds = plan(d.level, asset, inc["dets"], segment_restrict=d.segment_restrict) if d.auto_execute else []
    rules = rules_for(box["box"][0], cmds)
    for r in rules: ipt("-I", "OUTPUT", *r)
    t_enf = time.monotonic()
    time.sleep(1.0)
    user.stop = beacon.stop = True; user.join(); beacon.join()
    for r in rules: ipt("-D", "OUTPUT", *r)
    srv.shutdown(); srv.server_close()

    after = [ok for t, ok in user.log if t > t_enf + 0.1]
    before = [ok for t, ok in user.log if t < t_alert]
    c2_alive = any(t > t_enf + 0.1 for t in beacon.ok)
    last = max(beacon.ok, default=t_alert)
    return {
        "box": box["key"], "title": box["title"], "host": asset.hostname, "policy": name,
        "decision": d.level.value, "firewall_rules": len(rules),
        "attacker_cut": not c2_alive,
        "alert_to_attacker_cut_ms": None if c2_alive else round(max(0.0, last - t_alert) * 1000, 1),
        "service_ok_before_pct": round(100 * sum(before) / max(1, len(before))),
        "service_ok_after_pct": round(100 * sum(after) / max(1, len(after))),
        "requests_after": len(after),
    }


def main() -> None:
    c2 = listener(C2)
    rows = []
    try:
        for box in BOXES:
            for name, pol in (("full_isolation", uniform_decide), ("acrs", acrs_decide)):
                rows.append(run(box, pol, name))
    finally:
        c2.close()
    OUT.mkdir(exist_ok=True)
    (OUT / "hospital_box.json").write_text(json.dumps({
        "note": "Real HTTP services and clients, real ACRS decisions, real Linux firewall (iptables), one machine. "
                "The 'attacker' is harmless TCP traffic to a local address.", "rows": rows}, indent=1))
    print(f"\n{'SERVICE':26}{'POLICY':16}{'DECISION':20}{'ATTACKER':12}{'CUT IN':>9}{'SERVICE AFTER':>16}")
    for r in rows:
        cut = "cut" if r["attacker_cut"] else "NOT cut"
        v = r["alert_to_attacker_cut_ms"]
        ms = "-" if v is None else ("<1 ms" if v < 1 else f"{v} ms")
        svc = f"{r['service_ok_after_pct']}% up" if r["service_ok_after_pct"] else "DOWN"
        print(f"{r['title']:26}{r['policy']:16}{r['decision']:20}{cut:12}{ms:>9}{svc:>16}")
    print("\nSaved: research/results/hospital_box.json")


if __name__ == "__main__":
    main()
