"""v8 C in the real-kernel sandbox: digital-twin pre-check (S6) and self-drills (S9). Loopback only, own chains.

    sudo python -m qacrs.sandbox_v8      -> results/v8/sandbox_v8.json

S6: every policy is first applied in a shadow chain and measured (attacker channels, segment blocks, services);
    it is committed only if measured == predicted. 200 trials, half with an injected faulty adapter that silently
    skips one rule; target: faulty -> 100% aborted, healthy -> 100% committed, pre-check p95 < 100 ms.
S9: 100 drills, 25 per injected fault (missing jump to the chain, rule silently not applied, rule on the wrong
    address, adapter raising); a drill inserts a canary block and checks it bites; target: 100% detected.
"""
from __future__ import annotations

import json
import random
import socket
import subprocess
import sys
import time
from pathlib import Path

from qacrs import qubo_v7 as V7
from qacrs.meta import meta
from qacrs.network import build as build_net
from qacrs.phase9_v7 import fresh_sets
from qacrs.sandbox_lab import C2, CLIENT, address_book, ipt, listeners, PORT

OUT = Path(__file__).parent / "results" / "v8"
TWIN, LIVE = "QACRS_TWIN", "QACRS_LIVE"
FAST_TIMEOUT = 0.005


def fast(src, dst) -> bool:
    c = socket.socket(); c.settimeout(FAST_TIMEOUT)
    try:
        c.bind((src, 0)); c.connect((dst, PORT)); return True
    except OSError:
        return False
    finally:
        c.close()


def chain_on(name):
    ipt("-N", name, check=False); ipt("-F", name)
    if ipt("-C", "OUTPUT", "-j", name, check=False).returncode != 0:
        ipt("-I", "OUTPUT", "-j", name)


def chain_off(name):
    ipt("-D", "OUTPUT", "-j", name, check=False); ipt("-F", name, check=False); ipt("-X", name, check=False)


def specs_for(net, sc, iso, seg, addr):
    hacked = set(sc.hacked); active = hacked - iso
    out = []
    for m in sorted(iso):
        out += [["-s", addr[m], "-j", "DROP"], ["-d", addr[m], "-j", "DROP"]]
    for m in sorted(seg):
        out += [["-s", addr[m], "-d", C2, "-j", "DROP"]] + [["-s", addr[h], "-d", addr[m], "-j", "DROP"] for h in sorted(active)]
    for h in sorted(active - seg):
        out += [["-s", addr[h], "-d", C2, "-j", "DROP"]]
    return out


def measured_matches(net, sc, iso, seg, addr) -> bool:
    hacked = set(sc.hacked); active = hacked - iso
    if any(fast(addr[h], C2) for h in hacked):
        return False
    for m in iso:                                          # isolated: nothing in, nothing out
        if fast(CLIENT, addr[m]) or fast(addr[m], CLIENT):
            return False
    for m in seg:
        if any(fast(addr[h], addr[m]) for h in active):
            return False
    down = set(V7.services_down_v7(net, iso, seg, hacked))
    for s in net.services:
        up = any(fast(CLIENT, addr[r]) and all(fast(addr[r], addr[d]) for d in s.depends_on) for r in s.replicas)
        if up != (s.name not in down):
            return False
    return True


def twin_trials(pairs, books, n=200, seed=8020):
    rng = random.Random(seed)
    res = {"healthy": [0, 0], "faulty": [0, 0]}
    times = []
    for i in range(n):
        net, sc = pairs[i % len(pairs)]
        addr = books[net.name]
        iso, seg = V7.METHODS_V7["q_acrs_v7"](net, sc)
        iso = {m for m in iso if not net.machine(m).critical}
        specs = specs_for(net, sc, iso, seg, addr)
        faulty = i % 2 == 1 and len(specs) > 0
        skip = rng.randrange(len(specs)) if faulty else -1
        applied = [s for j, s in enumerate(specs) if j != skip]
        ipt("-F", TWIN)
        t = time.perf_counter()
        for sp in applied:
            ipt("-A", TWIN, *sp)
        ok = measured_matches(net, sc, iso, seg, addr)
        times.append(1000 * (time.perf_counter() - t))
        ipt("-F", TWIN)
        if ok:                                            # commit to the live chain only after the twin agrees
            for sp in applied:
                ipt("-A", LIVE, *sp)
            ipt("-F", LIVE)
        kind = "faulty" if faulty else "healthy"
        res[kind][1] += 1
        res[kind][0] += (not ok) if faulty else ok
    times.sort()
    return {"healthy_committed": res["healthy"][0], "healthy_trials": res["healthy"][1],
            "faulty_aborted": res["faulty"][0], "faulty_trials": res["faulty"][1],
            "precheck_ms": {"median": times[len(times) // 2], "p95": times[int(0.95 * (len(times) - 1))], "max": times[-1]},
            "target_met": res["faulty"][0] == res["faulty"][1] and res["healthy"][0] == res["healthy"][1]
                          and times[int(0.95 * (len(times) - 1))] < 100}


CANARY_SRC, CANARY_DST = "127.77.0.1", "127.77.0.2"


def drill(fault: str | None) -> bool:
    """True = drill reports 'enforcement healthy'. A fault must make it report False."""
    try:
        if fault == "missing_jump":
            ipt("-D", "OUTPUT", "-j", LIVE, check=False)
        if fault == "adapter_raises":
            raise RuntimeError("adapter down")
        if fault != "rule_not_applied":
            dst = "127.77.0.9" if fault == "wrong_address" else CANARY_DST
            ipt("-A", LIVE, "-s", CANARY_SRC, "-d", dst, "-j", "DROP")
        bites = not fast(CANARY_SRC, CANARY_DST)
        ipt("-F", LIVE)
        healthy_after = fast(CANARY_SRC, CANARY_DST)
        return bites and healthy_after
    except Exception:
        return False
    finally:
        ipt("-F", LIVE)
        if ipt("-C", "OUTPUT", "-j", LIVE, check=False).returncode != 0:
            ipt("-I", "OUTPUT", "-j", LIVE)


def drills():
    faults = ["missing_jump", "rule_not_applied", "wrong_address", "adapter_raises"]
    det = {f: 0 for f in faults}
    for i in range(100):
        f = faults[i % 4]
        det[f] += not drill(f)
    healthy_ok = sum(drill(None) for _ in range(20))
    return {"faults_injected": 100, "detected": det, "detected_total": sum(det.values()),
            "healthy_drills_passed": healthy_ok, "healthy_drills": 20,
            "target_met": sum(det.values()) == 100 and healthy_ok == 20}


def main():
    if subprocess.run(["id", "-u"], capture_output=True, text=True).stdout.strip() != "0":
        sys.exit("needs root (iptables)")
    sets, _ = fresh_sets()
    pairs = sets["chains_7008"][:100]
    books = {}
    for tag, net in enumerate((build_net(1), build_net(2)), start=1):
        books[net.name] = address_book(net, tag)
        listeners(books[net.name].values())
    listeners([C2, CLIENT, CANARY_DST])
    chain_on(TWIN); chain_on(LIVE)
    try:
        res = {"meta": meta("sandbox_v8", ("sandbox_v8.py",), fast_probe_timeout_s=FAST_TIMEOUT),
               "digital_twin_precheck": twin_trials(pairs, books), "self_drills": drills()}
    finally:
        chain_off(TWIN); chain_off(LIVE)
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "sandbox_v8.json").write_text(json.dumps(res, indent=1))
    print(json.dumps({k: v for k, v in res.items() if k != "meta"}, indent=1))


if __name__ == "__main__":
    main()
