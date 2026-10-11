"""v7 real-kernel validation: ISOLATE / SEGMENT / RESTRICT enforced by Linux iptables on real TCP (loopback only).

    sudo python -m qacrs.sandbox_v7      -> results/v7/sandbox_v7.json

Rules: PREREGISTRATION_v7 (H5-v7) + PREREGISTRATION_v8 (features 24 segment validation, 25 rollback, 26 time-to-contain).
Same environment and scope as sandbox_lab.py (v4): one Linux kernel, loopback addresses, own chain, removed at the end.
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

from qacrs import qubo_v7 as V7
from qacrs.meta import meta
from qacrs.phase9_v7 import fresh_sets
from qacrs.network import build as build_net, scenarios
from qacrs.sandbox_lab import C2, CHAIN, CLIENT, address_book, can_connect, ipt, listeners, loopback, setup, teardown

OUT = Path(__file__).parent / "results" / "v7"
PER_SET_PER_NET = 25
METHODS = ("q_acrs_v7", "rule_segment")


class SandboxAdapterV7:
    is_real, sandbox_only = True, True

    def __init__(self, addr):
        self.addr = {k: loopback(v) for k, v in addr.items()}
        self.rules: dict[str, list[list[str]]] = {}

    def apply(self, target, action, hacked_active=()):
        a = self.addr[target]
        if action == "ISOLATE":
            specs = [["-s", a, "-j", "DROP"], ["-d", a, "-j", "DROP"]]
        elif action == "RESTRICT":
            specs = [["-s", a, "-d", C2, "-j", "DROP"]]
        elif action == "SEGMENT":
            specs = [["-s", a, "-d", C2, "-j", "DROP"]] + [["-s", self.addr[h], "-d", a, "-j", "DROP"] for h in sorted(hacked_active)]
        else:
            raise ValueError(action)
        for sp in specs:
            ipt("-A", CHAIN, *sp)
        self.rules[f"{action}:{target}"] = specs

    def rollback(self):
        for specs in self.rules.values():
            for sp in specs:
                ipt("-D", CHAIN, *sp, check=False)
        self.rules.clear()


def run_one(net, sc, method, addr):
    ipt("-F", CHAIN)
    t0 = time.perf_counter()
    iso, seg = V7.METHODS_V7[method](net, sc)
    machines = {m.name: m for m in net.machines}
    needs_two = {m for m in iso if machines[m].critical}               # waits for approval: not applied
    iso_applied = iso - needs_two
    hacked = set(sc.hacked)
    active = hacked - iso_applied
    ad = SandboxAdapterV7(addr)
    for m in sorted(iso_applied):
        ad.apply(m, "ISOLATE")
    for m in sorted(seg):
        ad.apply(m, "SEGMENT", active)
    for h in sorted(active - seg):
        ad.apply(h, "RESTRICT")
    t_rules = time.perf_counter()
    first_block = not can_connect(addr[sorted(hacked)[0]], C2)          # first attacker attempt after enforcement
    t_contain_ms = 1000 * (time.perf_counter() - t0)
    seg_applied = set(seg)
    checks, mism = 0, []

    def cmp(kind, what, expected, measured):
        nonlocal checks
        checks += 1
        if expected != measured:
            mism.append({"check": kind, "what": what, "expected": expected, "measured": measured})

    for h in sorted(hacked):
        cmp("c2_blocked", h, True, not can_connect(addr[h], C2))
    model_down = set(V7.services_down_v7(net, iso_applied, seg_applied, hacked))
    for s in net.services:
        up = any(can_connect(CLIENT, addr[r]) and all(can_connect(addr[r], addr[d]) for d in s.depends_on) for r in s.replicas)
        cmp("service_up", s.name, s.name not in model_down, up)
    crit = {m.name for m in net.machines if m.critical}
    for a, b in net.links:
        if a in active and b in crit:
            cmp("lateral_open", f"{a}->{b}", not (b in iso_applied or b in seg_applied), can_connect(addr[a], addr[b]))
    for m in net.machines:
        if m.name not in hacked:
            cmp("healthy_reachable", m.name, m.name not in iso_applied, can_connect(CLIENT, addr[m.name]))
    for m in sorted(seg_applied):
        for h in sorted(active):
            cmp("segment_blocks_hacked", f"{h}->{m}", False, can_connect(addr[h], addr[m]))
    ad.rollback()                                                        # feature 25: rollback restores everything
    rb_checks, rb_fail = 0, []
    for h in sorted(hacked):
        rb_checks += 1
        if not can_connect(addr[h], C2):
            rb_fail.append(f"{h}->C2 still blocked")
    for m in net.machines:
        rb_checks += 1
        if not can_connect(CLIENT, addr[m.name]):
            rb_fail.append(f"client->{m.name} still blocked")
    return {"scenario": sc.id, "method": method, "isolate": sorted(iso_applied), "segment": sorted(seg_applied),
            "awaiting_two_person": sorted(needs_two), "checks": checks, "mismatches": mism,
            "rollback_checks": rb_checks, "rollback_failures": rb_fail,
            "rules_ms": round(1000 * (t_rules - t0), 3), "decision_to_first_blocked_attempt_ms": round(t_contain_ms, 3),
            "first_attempt_blocked": first_block}


def main():
    if subprocess.run(["id", "-u"], capture_output=True, text=True).stdout.strip() != "0":
        sys.exit("needs root (iptables)")
    sets, _ = fresh_sets()
    picked = []
    for name, pairs in sets.items():
        for net_name in ("net12", "net22"):
            picked += [(n, s, name) for n, s in pairs if n.name == net_name][:PER_SET_PER_NET]
    picked = [(n, s, "development") for n in (build_net(1), build_net(2)) for s in scenarios(n)] + picked
    rows = []
    setup()
    try:
        books = {}
        for tag, net in enumerate((build_net(1), build_net(2)), start=1):
            books[net.name] = address_book(net, tag)
            listeners(books[net.name].values())
        listeners([C2, CLIENT])
        for net, sc, split in picked:
            for m in METHODS:
                r = run_one(net, sc, m, books[net.name]) | {"split": split}
                rows.append(r)
                if r["mismatches"] or r["rollback_failures"]:
                    print("PROBLEM", r["scenario"], m, r["mismatches"], r["rollback_failures"], flush=True)
    finally:
        teardown()
    ms = sorted(r["decision_to_first_blocked_attempt_ms"] for r in rows)
    by = {}
    for r in rows:
        for x in r["mismatches"]:
            by[x["check"]] = by.get(x["check"], 0) + 1
    summ = {"runs": len(rows), "scenarios": len(picked), "checks": sum(r["checks"] for r in rows),
            "mismatches": sum(len(r["mismatches"]) for r in rows), "mismatches_by_check": by,
            "segment_checks": sum(1 for r in rows for _ in r["segment"]),
            "rollback_checks": sum(r["rollback_checks"] for r in rows),
            "rollback_failures": sum(len(r["rollback_failures"]) for r in rows),
            "first_attempt_blocked": sum(r["first_attempt_blocked"] for r in rows),
            "decision_to_block_ms": {"median": ms[len(ms) // 2], "p95": ms[int(0.95 * (len(ms) - 1))], "max": ms[-1]}}
    summ["H5_v7_supported"] = summ["mismatches"] == 0
    summ["agreement"] = 1 - summ["mismatches"] / summ["checks"]
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "sandbox_v7.json").write_text(json.dumps({"meta": meta("sandbox_v7", ("sandbox_v7.py", "qubo_v7.py"),
        scope="real iptables + real TCP on loopback in an isolated container; not a hospital network"),
        "summary": summ, "rows": rows}, indent=1))
    print(json.dumps(summ, indent=1))


if __name__ == "__main__":
    main()
