"""Real-enforcement lab: the same 42 incidents, but containment is done by the real Linux firewall (iptables).

    sudo python -m research.real_lab            # Linux, root (needs iptables)

What is real here:
  * Every incident gets its own "machine": a real network address (127.10.x.y) that keeps opening real TCP
    connections to three places: the attacker's server (C2), a critical internal server (spread path), and
    the business service it must keep reaching.
  * The real ACRS decision engine (and the uniform baseline) decide; the real command planner turns the
    decision into commands; each command is enforced with a real iptables rule in the kernel.
  * We time, with a monotonic clock, from the moment the alert reaches ACRS until the attacker's connections
    actually stop getting through, and we check which flows are still alive afterwards.

What is still NOT real: one Linux machine (loopback addresses, not a hospital network), no EDR/NAC product,
and detection is not timed (the alert is handed to ACRS directly). Rules are removed after each incident.
"""
from __future__ import annotations

import json
import socket
import statistics
import subprocess
import threading
import time
from pathlib import Path

from app.engines.decision import decide as acrs_decide
from app.engines.response import plan
from research import experiment as E
from research.experiment import incidents, uniform_decide, EGRESS_CMDS

OUT = Path(__file__).parent / "results"
C2 = ("127.66.0.1", 4444)          # attacker's server
CRIT = ("127.30.0.1", 4445)        # critical internal server (spread target)
SVC = ("127.20.0.1", 8080)         # business service the machine must keep reaching
PERIOD, TIMEOUT = 0.002, 0.03


def ipt(*args: str) -> None:
    subprocess.run(["iptables", *args], check=True, capture_output=True)


def listener(addr):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(addr); s.listen(512)
    def loop():
        while True:
            try:
                c, _ = s.accept(); c.close()
            except OSError:
                return
    threading.Thread(target=loop, daemon=True).start()
    return s


class Flow(threading.Thread):
    """A machine's real TCP flow: connects again and again, remembers when each attempt succeeded."""
    def __init__(self, src: str, dst):
        super().__init__(daemon=True); self.src, self.dst = src, dst
        self.ok: list[float] = []; self.fail: list[float] = []; self.stop = False
    def run(self):
        while not self.stop:
            s = socket.socket(); s.settimeout(TIMEOUT)
            try:
                s.bind((self.src, 0)); s.connect(self.dst); self.ok.append(time.monotonic())
            except OSError:
                self.fail.append(time.monotonic())
            finally:
                s.close()
            time.sleep(PERIOD)


def rules_for(src: str, cmds) -> list[list[str]]:
    names = {c.name for c in cmds}
    quarantine = any(c.name == "APPLY_MICROSEGMENTATION" and c.params.get("mode") in ("quarantine", "nac_quarantine_vlan")
                     for c in cmds)
    spread = quarantine or "ISOLATE_ASSET" in names or any(
        c.name == "RESTRICT_NETWORK" and c.params.get("new_flows_to_tiers") for c in cmds)
    rules = []
    if "ISOLATE_ASSET" in names or quarantine:
        rules.append(["-s", src, "-j", "DROP"])                       # machine cut off from everything
    else:
        if names & EGRESS_CMDS:
            rules.append(["-s", src, "-d", C2[0], "-j", "DROP"])      # attacker channel only
        if spread:
            rules.append(["-s", src, "-d", CRIT[0], "-j", "DROP"])    # new flows to critical servers
    return rules


def run_one(inc: dict, policy, src: str) -> dict:
    flows = {k: Flow(src, a) for k, a in (("c2", C2), ("crit", CRIT), ("svc", SVC))}
    for f in flows.values(): f.start()
    time.sleep(0.15)                                                   # traffic is flowing before the alert
    t_alert = time.monotonic()
    d = policy(inc["attr"], inc["ra"], inc["dets"], 0, inc["segment_hits"])
    t_decided = time.monotonic()
    asset = inc["attr"].asset or E.Asset(id=0, hostname=inc["ip"], ip=inc["ip"], tier=2, role="unknown",
                                         segment="unknown", owner="", isolatable=True)   # same fallback as experiment
    cmds = plan(d.level, asset, inc["dets"], segment_restrict=d.segment_restrict) if d.auto_execute else []
    rules = rules_for(src, cmds)
    for r in rules: ipt("-I", "OUTPUT", *r)
    t_enforced = time.monotonic()
    time.sleep(0.4)
    for f in flows.values(): f.stop = True
    for f in flows.values(): f.join()
    for r in rules: ipt("-D", "OUTPUT", *r)

    def alive_after(f: Flow) -> bool:                                 # still getting through 100 ms after enforcement?
        return any(t > t_enforced + 0.1 for t in f.ok)
    c2 = flows["c2"]
    c2_alive = alive_after(c2)
    last_ok = max([t for t in c2.ok], default=t_alert)
    return {
        "scenario": inc["scenario"], "host": inc["attr"].asset.hostname if inc["attr"].asset else inc["ip"],
        "benign": inc["benign"], "level": d.level.value, "auto": d.auto_execute, "rules": len(rules),
        "decide_ms": round((t_decided - t_alert) * 1000, 3),
        "alert_to_enforced_ms": round((t_enforced - t_alert) * 1000, 2),
        "alert_to_c2_stopped_ms": None if c2_alive else round(max(0.0, last_ok - t_alert) * 1000, 2),
        "c2_cut": not c2_alive, "spread_cut": not alive_after(flows["crit"]),
        "service_still_reachable": alive_after(flows["svc"]),
    }


def arm(incs, policy, base: int) -> list[dict]:
    rows = []
    for i, inc in enumerate(incs):
        rows.append(run_one(inc, policy, f"127.10.{base}.{i + 1}"))
    return rows


def summary(rows):
    mal = [r for r in rows if not r["benign"]]
    stop = [r["alert_to_c2_stopped_ms"] for r in mal if r["c2_cut"]]
    enf = [r["alert_to_enforced_ms"] for r in mal if r["c2_cut"]]
    return {
        "malicious": len(mal), "c2_cut": sum(r["c2_cut"] for r in mal), "spread_cut": sum(r["spread_cut"] for r in mal),
        "service_lost": sum((not r["service_still_reachable"]) for r in rows),
        "benign_service_lost": sum((not r["service_still_reachable"]) for r in rows if r["benign"]),
        "alert_to_c2_stopped_ms": {"median": round(statistics.median(stop), 1), "max": round(max(stop), 1),
                                   "min": round(min(stop), 1)} if stop else None,
        "alert_to_enforced_ms": {"median": round(statistics.median(enf), 1), "max": round(max(enf), 1)} if enf else None,
    }


def main() -> None:
    socks = [listener(C2), listener(CRIT), listener(SVC)]
    incs = incidents()
    try:
        base = arm(incs, uniform_decide, 1)
        acrs = arm(incs, acrs_decide, 2)
    finally:
        for s in socks: s.close()
    out = {"note": "Real Linux firewall (iptables) enforcement of the real ACRS decisions, real TCP flows on one "
                   "machine (loopback addresses). Detection is not timed; no EDR/NAC product.",
           "baseline": {"summary": summary(base), "rows": base}, "acrs": {"summary": summary(acrs), "rows": acrs}}
    OUT.mkdir(exist_ok=True)
    (OUT / "real_lab.json").write_text(json.dumps(out, indent=1))
    print(json.dumps({"baseline": out["baseline"]["summary"], "acrs": out["acrs"]["summary"]}, indent=1))


if __name__ == "__main__":
    main()
