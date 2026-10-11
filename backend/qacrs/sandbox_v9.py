"""v9 in the real kernel (loopback only, own chains): 26-v9 time to contain, S6-v9 twin, SHIELD port checks.

    sudo python -m qacrs.sandbox_v9      -> results/v9/sandbox_v9.json

Fixes (PREREGISTRATION_v9.md): one atomic `iptables-restore --noflush` per decision; attacker TCP egress is REJECTed
with a TCP reset (fails at once) while inbound to isolated machines stays DROP; the twin compares installed rules
(`iptables -S`) with the plan AND measured behaviour; probes run in parallel.
"""
from __future__ import annotations

import concurrent.futures as cf
import json
import random
import socket
import subprocess
import sys
import threading
import time
from collections import Counter
from pathlib import Path

from qacrs import hassan as H
from qacrs import hassan_v9 as V9
from qacrs import qubo_v7 as V7
from qacrs import realism_v8 as RV
from qacrs.meta import meta
from qacrs.network import Scenario, build as build_net
from qacrs.sandbox_lab import C2, CLIENT, PORT, address_book, ipt, loopback

OUT = Path(__file__).parent / "results" / "v9"
LIVE, TWIN = "QACRS_LIVE9", "QACRS_TWIN9"
LATERAL = 47645                  # stands in for an admin protocol (SMB/RDP-style); PORT stands in for clinical traffic
PROBE_TIMEOUT = 0.005
POOL = cf.ThreadPoolExecutor(max_workers=48)


# ------------------------------------------------------------------ plan -> rules ---------------------------------
def rej(src, dst=None):
    r = ["-s", src] + (["-d", dst] if dst else []) + ["-p", "tcp", "-j", "REJECT", "--reject-with", "tcp-reset"]
    return r


def specs_v9(net, sc, iso, seg, shield, addr):
    hacked = set(sc.hacked); active = hacked - iso
    out = []
    for m in sorted(iso):
        out += [rej(addr[m]), ["-s", addr[m], "-j", "DROP"], ["-d", addr[m], "-j", "DROP"]]
    for m in sorted(seg):
        out += [rej(addr[m], C2)] + [["-s", addr[h], "-d", addr[m], "-j", "DROP"] for h in sorted(active)]
    for h in sorted(active - seg):
        out += [rej(addr[h], C2)]
    for a, b in sorted(shield):
        out += [["-s", addr[a], "-d", addr[b], "-p", "tcp", "--dport", str(LATERAL), "-j", "DROP"]]
    return out


def restore(chain, specs):
    text = "*filter\n" + f":{chain} - [0:0]\n" + "".join(f"-A {chain} {' '.join(s)}\n" for s in specs) + "COMMIT\n"
    subprocess.run(["iptables-restore", "--noflush"], input=text, text=True, check=True, capture_output=True)


def canon(tokens):
    toks = [t[:-3] if t.endswith("/32") else t for t in tokens]
    pairs, i = [], 0
    while i < len(toks):
        if toks[i] == "-m" and i + 1 < len(toks) and toks[i + 1] == "tcp":
            i += 2; continue
        pairs.append((toks[i], toks[i + 1] if i + 1 < len(toks) else "")); i += 2
    return frozenset(pairs)


def installed(chain):
    lines = ipt("-S", chain).stdout.splitlines()
    return Counter(canon(l.split()[2:]) for l in lines if l.startswith(f"-A {chain} "))


def structure_matches(chain, specs) -> bool:
    return installed(chain) == Counter(canon(s) for s in specs)


# ------------------------------------------------------------------ probes ----------------------------------------
def probe(src, dst, port=PORT) -> bool:
    c = socket.socket(); c.settimeout(PROBE_TIMEOUT)
    try:
        c.bind((src, 0)); c.connect((dst, port)); return True
    except OSError:
        return False
    finally:
        c.close()


def expected_probes(net, sc, iso, seg, addr):
    """(src, dst, port, expected_open) implied by the plan's semantics."""
    hacked = set(sc.hacked); active = hacked - iso
    P = [(addr[h], C2, PORT, False) for h in sorted(hacked)]
    for m in sorted(iso):
        P += [(CLIENT, addr[m], PORT, False), (addr[m], CLIENT, PORT, False)]
    for m in sorted(seg):
        P += [(addr[h], addr[m], PORT, False) for h in sorted(active)]
    for s in net.services:
        for r in s.replicas:
            P.append((CLIENT, addr[r], PORT, r not in iso))
            for d in s.depends_on:
                P.append((addr[r], addr[d], PORT, r not in iso and d not in iso and not (d in seg and r in active)))
    return P


def run_probes(P):
    return list(POOL.map(lambda p: probe(p[0], p[1], p[2]), P))


def behaviour_matches(net, sc, iso, seg, addr) -> tuple[bool, int]:
    P = expected_probes(net, sc, iso, seg, addr)
    got = run_probes(P)
    ok = all(g == p[3] for g, p in zip(got, P))
    # service-level: measured up/down must equal the V7 model
    meas = {(p[0], p[1]): g for p, g in zip(P, got)}
    down = set(V7.services_down_v7(net, iso, seg, set(sc.hacked)))
    for s in net.services:
        up = any(meas[(CLIENT, addr[r])] and all(meas[(addr[r], addr[d])] for d in s.depends_on) for r in s.replicas)
        ok &= up == (s.name not in down)
    return ok, len(P)


# ------------------------------------------------------------------ 26-v9 -----------------------------------------
def time_to_contain(pairs, books):
    lat, agree, checks = [], 0, 0
    for net, sc in pairs:
        addr = books[net.name]
        t0 = time.perf_counter()
        iso, seg, _ = H.solve(net, sc)
        iso = {m for m in iso if not net.machine(m).critical}
        restore(LIVE, specs_v9(net, sc, iso, seg, set(), addr))
        first = sorted(sc.hacked)[0]
        blocked = not probe(addr[first], C2)
        lat.append(1000 * (time.perf_counter() - t0))
        ok, n = behaviour_matches(net, sc, iso, seg, addr)
        agree += ok and blocked; checks += n
        restore(LIVE, [])
    return {"decisions": len(pairs), "decision_to_first_failed_attempt_ms": {"median": V9_pct(lat, .5), "p95": V9_pct(lat, .95),
            "max": max(lat)}, "decisions_model_equals_measured": agree, "probe_checks": checks,
            "target_met": V9_pct(lat, .95) < 50 and agree == len(pairs)}


def V9_pct(v, q):
    v = sorted(v); return v[min(len(v) - 1, int(round(q * (len(v) - 1))))]


# ------------------------------------------------------------------ S6-v9 -----------------------------------------
def twin(pairs, books, n=200):
    rng = random.Random(V9.TWIN_SEED)
    res = {"healthy": [0, 0], "faulty": [0, 0]}; times = []; caught_by = Counter()
    for i in range(n):
        net, sc = pairs[i % len(pairs)]
        addr = books[net.name]
        iso, seg, _ = H.solve(net, sc)
        iso = {m for m in iso if not net.machine(m).critical}
        specs = specs_v9(net, sc, iso, seg, set(), addr)
        faulty = i % 2 == 1
        skip = rng.randrange(len(specs)) if faulty else -1
        applied = [s for j, s in enumerate(specs) if j != skip]
        t = time.perf_counter()
        restore(TWIN, applied)
        s_ok = structure_matches(TWIN, specs)
        b_ok = behaviour_matches(net, sc, iso, seg, addr)[0] if s_ok else False
        times.append(1000 * (time.perf_counter() - t))
        restore(TWIN, [])
        ok = s_ok and b_ok
        if ok:
            restore(LIVE, applied); restore(LIVE, [])
        elif faulty:
            caught_by["structure" if not s_ok else "behaviour"] += 1
        kind = "faulty" if faulty else "healthy"
        res[kind][1] += 1; res[kind][0] += (not ok) if faulty else ok
    return {"healthy_committed": res["healthy"][0], "healthy_trials": res["healthy"][1],
            "faulty_aborted": res["faulty"][0], "faulty_trials": res["faulty"][1], "faulty_caught_by": dict(caught_by),
            "precheck_ms": {"median": V9_pct(times, .5), "p95": V9_pct(times, .95), "max": max(times)},
            "target_met": res["faulty"][0] == res["faulty"][1] and res["healthy"][0] == res["healthy"][1]
                          and V9_pct(times, .95) < 100}


# ------------------------------------------------------------------ SHIELD in the kernel --------------------------
def shield_checks(books, nets):
    total = ok = 0
    for net in nets:
        addr = books[net.name]; rng = random.Random(V9.RW_SEED); names = [m.name for m in net.machines]
        for _ in range(50):
            init = {rng.choice(names)}
            infected = set(init)                                   # state at decision time (tick 2)
            for _ in range(1):
                infected |= {b for a, b in net.links if a in infected}
            sc = Scenario("rw", net.name, {m: 8 for m in sorted(infected)}, "ransomware")
            iso, seg, _ = H.solve(net, sc)
            iso = {m for m in iso if not net.machine(m).critical}
            sh = V9.shield_links(net, infected, iso)
            restore(LIVE, specs_v9(net, sc, iso, seg, sh, addr))
            P = []
            for a, b in sorted(sh):
                if b in iso:
                    continue                                       # isolated target: everything blocked anyway
                clinical_open = not (b in seg and a in set(sc.hacked) - iso)
                P += [(addr[a], addr[b], LATERAL, False), (addr[a], addr[b], PORT, clinical_open)]
            got = list(POOL.map(lambda p: probe(p[0], p[1], p[2]), P))
            total += len(P); ok += sum(g == p[3] for g, p in zip(got, P))
            restore(LIVE, [])
    return {"checks": total, "agree": ok, "target_met": total > 0 and ok == total,
            "meaning": "lateral (admin) port blocked and clinical port open on every shielded link"}


# ------------------------------------------------------------------ setup -----------------------------------------
def listen(addrs, ports):
    for a in addrs:
        for p in ports:
            s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind((a, p)); s.listen(4096)
            def loop(s=s):
                while True:
                    try:
                        c, _ = s.accept(); c.close()
                    except OSError:
                        return
            threading.Thread(target=loop, daemon=True).start()


def hook(chain):
    if ipt("-C", "OUTPUT", "-j", chain, check=False).returncode != 0:
        ipt("-N", chain, check=False); ipt("-I", "OUTPUT", "-j", chain)


def unhook(chain):
    ipt("-D", "OUTPUT", "-j", chain, check=False); ipt("-F", chain, check=False); ipt("-X", chain, check=False)


def main():
    if subprocess.run(["id", "-u"], capture_output=True, text=True).stdout.strip() != "0":
        sys.exit("needs root (iptables)")
    sets, _ = V9.fresh_sets_v9()
    nets = (build_net(1), build_net(2), RV.hospital60())
    books = {}
    for tag, net in enumerate(nets, start=11):
        books[net.name] = {k: loopback(v) for k, v in address_book(net, tag).items()}
        listen(books[net.name].values(), (PORT, LATERAL))
    listen([C2, CLIENT], (PORT,))
    h60, h60s = V9.hospital60_v9()
    pairs = sets["chains_7009"][:150] + [(h60, s) for s in h60s[:50]]
    for c in (LIVE, TWIN):
        hook(c)
    try:
        res = {"meta": meta("sandbox_v9", ("sandbox_v9.py", "hassan_v9.py"), probe_timeout_s=PROBE_TIMEOUT,
                            scope="real iptables + real TCP on loopback addresses in an isolated container"),
               "time_to_contain_26_v9": time_to_contain(pairs, books),
               "digital_twin_S6_v9": twin(pairs, books),
               "shield_kernel": shield_checks(books, (nets[0], nets[2]))}
    finally:
        for c in (LIVE, TWIN):
            unhook(c)
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "sandbox_v9.json").write_text(json.dumps(res, indent=1))
    print(json.dumps({k: v for k, v in res.items() if k != "meta"}, indent=1))


if __name__ == "__main__":
    main()
