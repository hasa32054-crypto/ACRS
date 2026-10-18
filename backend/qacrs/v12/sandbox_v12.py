"""D8 (v12): the real incidents and 50 realistic-generator scenarios executed in the real Linux kernel.

    sudo python -m qacrs.v12.sandbox_v12      -> qacrs/results/v12/sandbox_v12.json   (T10-kernel)

Same mechanics as sandbox_v9.py (imported, unchanged): loopback addresses only, own iptables chains, one atomic
iptables-restore per decision, REJECT-with-reset for attacker egress, DROP for isolated hosts, SHIELD on lateral port,
twin that compares installed rules with the plan and measured behaviour before committing to the live chain.
What is new: the decisions are v12's (safety floor + locked solver, automatic part only; two-person isolations of
critical servers are NOT executed automatically, exactly as in production), and the scenarios are real incidents.
Nothing here is malware: the "attacker" is a TCP connect() from a loopback address.
"""
from __future__ import annotations

import json
import random
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path

from qacrs import hassan_v9 as V9
from qacrs import phase16_v11 as P16
from qacrs import qubo_v7 as V7
from qacrs.sandbox_lab import C2, CLIENT, PORT, address_book, loopback
from qacrs.sandbox_v9 import (LATERAL, LIVE, POOL, PROBE_TIMEOUT, TWIN, V9_pct, behaviour_matches, hook, listen,
                              probe, restore, specs_v9, structure_matches, unhook)
from qacrs.v12 import qubo_v12 as Q
from qacrs.v12 import realism_v12 as R

OUT = Path(__file__).parent.parent / "results" / "v12"


def specs_v12(net, sc, iso, seg, shield, addr):
    """v9 rule set with ONE change: segmentation blocks NEW connections from a hacked host to the segmented server
    (`-m conntrack --ctstate NEW`), so replies to connections the server itself opened still flow. v9 used a stateless
    DROP, which was equivalent while only hacked hosts were segmented; Amendment 1(d) also segments healthy critical
    neighbours, and a stateless DROP of hacked->healthy silently killed the healthy server's own connections to the
    hacked host (found in the first kernel run: 23/66 model/measured mismatches, all with healthy segmented servers)."""
    hacked = set(sc.hacked); active = hacked - iso
    out = []
    for m in sorted(iso):
        out += [["-s", addr[m], "-p", "tcp", "-j", "REJECT", "--reject-with", "tcp-reset"],
                ["-s", addr[m], "-j", "DROP"], ["-d", addr[m], "-j", "DROP"]]
    for m in sorted(seg):
        out += [["-s", addr[m], "-d", C2, "-p", "tcp", "-j", "REJECT", "--reject-with", "tcp-reset"]]
        out += [["-s", addr[h], "-d", addr[m], "-m", "conntrack", "--ctstate", "NEW", "-j", "DROP"] for h in sorted(active)]
    for h in sorted(active - seg):
        out += [["-s", addr[h], "-d", C2, "-p", "tcp", "-j", "REJECT", "--reject-with", "tcp-reset"]]
    for a, b in sorted(shield):
        out += [["-s", addr[a], "-d", addr[b], "-p", "tcp", "--dport", str(LATERAL), "-j", "DROP"]]
    return out


def plan_v12(net, sc):
    d = Q.decide_v12(net, sc)
    iso = {m for m in d.isolate if not net.machine(m).critical}        # critical isolations wait for two people
    seg = set(d.segment)
    shield = V9.shield_links(net, set(sc.hacked), iso)
    return iso, seg, shield, d.status


def time_to_contain(pairs, books):
    lat, agree, checks, leaks, rows = [], 0, 0, 0, []
    for net, sc in pairs:
        addr = books[net.name]
        t0 = time.perf_counter()
        iso, seg, sh, status = plan_v12(net, sc)
        restore(LIVE, specs_v12(net, sc, iso, seg, sh, addr))
        first = sorted(sc.hacked, key=lambda m: -sc.hacked[m])[0]
        blocked = not probe(addr[first], C2)
        ms = 1000 * (time.perf_counter() - t0)
        ok, n = behaviour_matches(net, sc, iso, seg, addr)
        # leak test: every isolated host must be unreachable from the client and unable to reach C2
        leak = sum(probe(CLIENT, addr[m]) or probe(addr[m], C2) for m in iso)
        # shield test: lateral port closed on every shielded link whose target is not isolated
        P = [(addr[a], addr[b], LATERAL, False) for a, b in sorted(sh) if b not in iso]
        got = list(POOL.map(lambda p: probe(p[0], p[1], p[2]), P)) if P else []
        sh_ok = sum(g == p[3] for g, p in zip(got, P))
        restore(LIVE, [])
        lat.append(ms); agree += ok and blocked; checks += n + len(P); leaks += leak
        rows.append({"scenario": sc.id, "status": status, "isolated": len(iso), "segmented": len(seg), "shields": len(sh),
                     "ms_decision_to_first_blocked_attempt": round(ms, 2), "model_equals_measured": ok and blocked,
                     "leaks": leak, "shield_checks": [sh_ok, len(P)]})
    return {"decisions": len(pairs), "ms": {"median": V9_pct(lat, .5), "p95": V9_pct(lat, .95), "max": max(lat)},
            "model_equals_measured": agree, "probe_checks": checks, "isolated_host_leaks": leaks,
            "target_met": agree == len(pairs) and leaks == 0, "rows": rows}


def twin(pairs, books, n=100):
    rng = random.Random(V9.TWIN_SEED)
    res = {"healthy": [0, 0], "faulty": [0, 0]}; times = []; caught = Counter()
    for i in range(n):
        net, sc = pairs[i % len(pairs)]; addr = books[net.name]
        iso, seg, sh, _ = plan_v12(net, sc)
        specs = specs_v12(net, sc, iso, seg, sh, addr)
        faulty = i % 2 == 1
        skip = rng.randrange(len(specs)) if faulty and specs else -1
        applied = [s for j, s in enumerate(specs) if j != skip]
        t = time.perf_counter()
        restore(TWIN, applied)
        s_ok = structure_matches(TWIN, specs)
        b_ok = behaviour_matches(net, sc, iso, seg, addr)[0] if s_ok else False
        times.append(1000 * (time.perf_counter() - t))
        restore(TWIN, [])
        ok = s_ok and b_ok
        if not ok and faulty:
            caught["structure" if not s_ok else "behaviour"] += 1
        kind = "faulty" if faulty else "healthy"
        res[kind][1] += 1; res[kind][0] += (not ok) if faulty else ok
    return {"healthy_committed": res["healthy"][0], "healthy_trials": res["healthy"][1],
            "faulty_aborted": res["faulty"][0], "faulty_trials": res["faulty"][1], "faulty_caught_by": dict(caught),
            "precheck_ms": {"median": V9_pct(times, .5), "p95": V9_pct(times, .95), "max": max(times)},
            "target_met": res["faulty"][0] == res["faulty"][1] and res["healthy"][0] == res["healthy"][1]}


def main():
    if subprocess.run(["id", "-u"], capture_output=True, text=True).stdout.strip() != "0":
        sys.exit("needs root (iptables)")
    real = []
    for p in sorted(P16.INC.glob("*.json")):
        d, net, scs = P16.load(p)
        if net is not None:
            real += [(net, sc) for sc in scs]
    nets, scen = R.generate()
    byname = {n.name: n for n in nets}
    synth = [(byname[name], scs[-1]) for name, scs in scen[:50]]      # the detonation moment of 50 chains
    pairs = real + synth
    books = {}
    for tag, net in enumerate({n.name: n for n, _ in pairs}.values(), start=21):
        books[net.name] = {k: loopback(v) for k, v in address_book(net, tag).items()}
        listen(books[net.name].values(), (PORT, LATERAL))
    listen([C2, CLIENT], (PORT,))
    for c in (LIVE, TWIN):
        hook(c)
    try:
        t0 = time.time()
        res = {"meta": {"experiment": "sandbox_v12", "scope": "real iptables + real TCP on loopback in an isolated container",
                        "real_scenarios": len(real), "synthetic_scenarios": len(synth), "probe_timeout_s": PROBE_TIMEOUT},
               "time_to_contain": time_to_contain(pairs, books),
               "digital_twin": twin(pairs, books)}
        res["meta"]["seconds"] = round(time.time() - t0, 1)
    finally:
        for c in (LIVE, TWIN):
            unhook(c)
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "sandbox_v12.json").write_text(json.dumps(res, indent=1), encoding="utf-8")
    print(json.dumps({k: ({kk: vv for kk, vv in v.items() if kk != "rows"} if isinstance(v, dict) else v)
                      for k, v in res.items()}, indent=1))


if __name__ == "__main__":
    main()
