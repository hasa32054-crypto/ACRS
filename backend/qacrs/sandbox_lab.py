"""Phase 6 / E10: do Q-ACRS decisions do what the model says when a REAL Linux firewall enforces them?

    sudo python -m qacrs.sandbox_lab        (Linux, root, iptables; run inside an isolated container/VM)
    -> results/v4/sandbox_lab.json

Rules: docs/qacrs/PREREGISTRATION_v4.md (E10).
What is real: Linux kernel iptables rules and real TCP connections between loopback addresses, one per machine.
What is NOT real: a hospital network, routing between hosts, detection. Loopback only (127.0.0.0/8); every rule
lives in the chain QACRS_SANDBOX, flushed after every scenario and removed at the end (also on error).

Mapping (same as policy_executor plan): ISOLATE m -> drop everything from/to m; RESTRICT h -> drop h -> C2 only.
Policies waiting for two-person approval are not applied (as in production).
"""
from __future__ import annotations

import ipaddress
import json
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

from qacrs import safety_checks as S
from qacrs.independent_test import check_lock
from qacrs.meta import meta
from qacrs.network import build as build_net, scenarios
from qacrs.phase3_compare import q_acrs
from qacrs.phase3b_containment import full_isolation_safe
from qacrs.phase6_heldout import heldout_pairs
from qacrs.policy_executor import ISOLATE, RESTRICT, PolicyAuditLog, PolicyExecutor
from qacrs.qubo_builder import services_down

OUT = Path(__file__).parent / "results" / "v4"
CHAIN, PORT = "QACRS_SANDBOX", 47600
C2, CLIENT = "127.66.0.1", "127.50.0.1"
TIMEOUT, ATTEMPTS = 0.05, 3
HELDOUT_PER_NET = 50
METHODS = {"q_acrs": lambda net, sc: q_acrs(net, sc)[0], "full_isolation_safe": full_isolation_safe}


def ipt(*args, check=True):
    return subprocess.run(["iptables", *args], check=check, capture_output=True, text=True)


def loopback(addr: str) -> str:
    if not ipaddress.ip_address(addr).is_loopback:
        raise ValueError(f"refusing non-loopback address {addr}")
    return addr


class SandboxIptablesAdapter:
    """Real iptables, loopback addresses only, own chain. Not a production firewall adapter."""
    is_real = True
    sandbox_only = True

    def __init__(self, addr: dict[str, str]):
        self.addr = {k: loopback(v) for k, v in addr.items()}
        self.rules: dict[str, str] = {}
        self.calls = 0

    def _specs(self, target, action):
        a = self.addr[target]
        return [["-s", a, "-j", "DROP"], ["-d", a, "-j", "DROP"]] if action == ISOLATE else [["-s", a, "-d", C2, "-j", "DROP"]]

    def apply(self, target, action):
        self.calls += 1
        for spec in self._specs(target, action):
            ipt("-A", CHAIN, *spec)
        self.rules[target] = action

    def remove(self, target):
        action = self.rules.pop(target, None)
        if action:
            for spec in self._specs(target, action):
                ipt("-D", CHAIN, *spec, check=False)


def setup():
    ipt("-N", CHAIN, check=False); ipt("-F", CHAIN)
    if ipt("-C", "OUTPUT", "-j", CHAIN, check=False).returncode != 0:
        ipt("-I", "OUTPUT", "-j", CHAIN)


def teardown():
    ipt("-D", "OUTPUT", "-j", CHAIN, check=False); ipt("-F", CHAIN, check=False); ipt("-X", CHAIN, check=False)


def listeners(addrs):
    socks = []
    for a in addrs:
        s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind((a, PORT)); s.listen(4096)
        socks.append(s)
        def loop(s=s):
            while True:
                try:
                    c, _ = s.accept(); c.close()
                except OSError:
                    return
        threading.Thread(target=loop, daemon=True).start()
    return socks


def can_connect(src, dst) -> bool:
    for _ in range(ATTEMPTS):
        c = socket.socket(); c.settimeout(TIMEOUT)
        try:
            c.bind((src, 0)); c.connect((dst, PORT)); return True
        except OSError:
            pass
        finally:
            c.close()
    return False


def address_book(net, tag):
    return {m.name: f"127.40.{tag}.{i + 1}" for i, m in enumerate(net.machines)}


def run_one(net, sc, method, addr):
    ipt("-F", CHAIN)
    adapter = SandboxIptablesAdapter(addr)
    ex = PolicyExecutor(net, adapter, PolicyAuditLog(), max_retries=0, dry_run=False)
    iso = set(METHODS[method](net, sc))
    t0 = time.perf_counter()
    res = ex.execute(sc, iso)
    t_exec = time.perf_counter() - t0
    applied_iso = {t for t, a in adapter.rules.items() if a == ISOLATE}
    applied_any = set(adapter.rules)
    crit = {m.name for m in net.machines if m.critical}
    checks, mism, notes = 0, [], []

    def compare(kind, what, expected, measured):
        nonlocal checks
        checks += 1
        if expected != measured:
            mism.append({"check": kind, "what": what, "expected": expected, "measured": measured})

    for h in sorted(sc.hacked):                                                         # 1. attacker channel
        compare("c2_blocked", h, h in applied_any, not can_connect(addr[h], C2))
    model_down = set(services_down(net, applied_iso))                                   # 2. services
    for s in net.services:
        up = any(can_connect(CLIENT, addr[r]) and all(can_connect(addr[r], addr[d]) for d in s.depends_on)
                 for r in s.replicas)
        compare("service_up", s.name, s.name not in model_down, up)
    model_open = set(S.open_paths(net, sc, applied_iso))                                 # 3. lateral paths
    for a, b in net.links:
        if a in sc.hacked and a not in applied_iso and b in crit:
            measured = can_connect(addr[a], addr[b])
            if b in sc.hacked:
                notes.append({"link": f"{a}->{b}", "open": measured,
                              "note": "target critical server is itself hacked; C1 does not count it by definition"})
                continue
            compare("lateral_open", f"{a}->{b}", (a, b) in model_open, measured)
    for m in net.machines:                                                              # 4. healthy machines
        if m.name not in sc.hacked:
            compare("healthy_reachable", m.name, m.name not in applied_iso, can_connect(CLIENT, addr[m.name]))
    ipt("-F", CHAIN)
    return {"scenario": sc.id, "method": method, "executor_status": res.status,
            "applied": sorted(adapter.rules.items()), "execute_ms": round(1000 * t_exec, 2),
            "checks": checks, "mismatches": mism, "notes": notes}


def main():
    if subprocess.run(["id", "-u"], capture_output=True, text=True).stdout.strip() != "0":
        sys.exit("needs root (iptables)")
    drift = check_lock()
    if drift:
        sys.exit("REFUSED: locked code changed:\n  " + "\n  ".join(drift))
    dev = [(net, sc, "dev") for net in (build_net(1), build_net(2)) for sc in scenarios(net)]
    ho, _ = heldout_pairs()
    ho = [(net, sc, "heldout") for name in ("net12", "net22") for net, sc in [p for p in ho if p[0].name == name][:HELDOUT_PER_NET]]
    rows = []
    setup()
    try:
        socks = []
        books = {}
        for tag, net in enumerate((build_net(1), build_net(2)), start=1):
            books[net.name] = address_book(net, tag)
            socks += listeners(books[net.name].values())
        socks += listeners([C2, CLIENT])
        sanity = can_connect(CLIENT, C2)
        for net, sc, split in dev + ho:
            for method in METHODS:
                r = run_one(net, sc, method, books[net.name]) | {"split": split}
                rows.append(r)
                if r["mismatches"]:
                    print("MISMATCH", r["scenario"], method, r["mismatches"], flush=True)
            print(f"{sc.id:12} done", flush=True)
    finally:
        teardown()
    total = sum(r["checks"] for r in rows); bad = sum(len(r["mismatches"]) for r in rows)
    by = {}
    for r in rows:
        for m in r["mismatches"]:
            by[m["check"]] = by.get(m["check"], 0) + 1
    summary = {"runs": len(rows), "scenarios": len(dev) + len(ho), "checks": total, "mismatches": bad,
               "agreement": (total - bad) / total if total else None, "mismatches_by_check": by,
               "H5_supported": bad == 0, "baseline_connectivity_ok": sanity,
               "executor_status_counts": {s: sum(r["executor_status"] == s for r in rows) for s in {r["executor_status"] for r in rows}},
               "execute_ms_median": sorted(r["execute_ms"] for r in rows)[len(rows) // 2],
               "notes_hacked_critical_target_links": sum(len(r["notes"]) for r in rows)}
    res = {"meta": meta("sandbox_lab", ("sandbox_lab.py", "policy_executor.py"), chain=CHAIN, timeout_s=TIMEOUT,
                        attempts=ATTEMPTS, heldout_per_net=HELDOUT_PER_NET,
                        scope="real iptables + real TCP on loopback addresses in an isolated container; not a hospital network"),
           "summary": summary, "rows": rows}
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "sandbox_lab.json").write_text(json.dumps(res, indent=1))
    print(json.dumps(summary, indent=1))


if __name__ == "__main__":
    main()
