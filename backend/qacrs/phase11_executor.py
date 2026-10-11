"""Phase 11 (v8 C, no network): audit chain (17), HMAC (16), proof-carrying certificates (S5), TTL (8), decay (S7).

    cd backend && python -m qacrs.phase11_executor      -> results/v8/executor.json
"""
from __future__ import annotations

import copy
import json
import random
import statistics
import time
from pathlib import Path

from qacrs import executor_v8 as X
from qacrs import hassan as H
from qacrs.meta import meta
from qacrs.network import build as build_net, scenarios
from qacrs.phase6_heldout import heldout_pairs
from qacrs.phase7_v5 import fresh_pairs
from qacrs.phase8_ood import ood_pairs
from qacrs.phase9_v7 import fresh_sets

OUT = Path(__file__).parent / "results" / "v8"
R = Path(__file__).parent / "results"


def all_pairs():
    fs, _ = fresh_sets()
    return ([(n, s) for n in (build_net(1), build_net(2)) for s in scenarios(n)] + heldout_pairs()[0] + fresh_pairs()[0]
            + ood_pairs()[0] + fs["chains_7008"] + fs["random_9003"])


def audit_chain(n=1000, seed=8030):
    rng = random.Random(seed)
    log = X.ChainLog()
    for i in range(200):
        log.append(event="decision", i=i, target=f"m{i % 12}")
    assert X.ChainLog.verify(log.entries)
    det = {"edit": 0, "delete": 0, "reorder": 0}
    for t in range(n):
        e = copy.deepcopy(log.entries)
        kind = ("edit", "delete", "reorder")[t % 3]
        k = rng.randrange(len(e) - 1)
        if kind == "edit":
            e[k]["body"]["target"] = "tampered"
        elif kind == "delete":
            del e[k]
        else:
            e[k], e[k + 1] = e[k + 1], e[k]
        det[kind] += not X.ChainLog.verify(e)
    return {"entries": 200, "tamper_attempts": n, "detected": det, "target_met": sum(det.values()) == n}


def certificates(pairs, n_tamper=1000, seed=8031):
    rng = random.Random(seed)
    engines = {}
    times, accepted, sig_ok, total = [], 0, 0, 0
    certs = []
    for net, sc in pairs:
        eng = engines.setdefault(net.name, H.Engine(net, limiter=H.RateLimiter(limit=10 ** 9)))
        d = eng.decide(sc)
        if d.status == "REJECTED":
            continue
        t = time.perf_counter(); ok = H.verify_certificate(net, sc, d.certificate); times.append(1000 * (time.perf_counter() - t))
        accepted += ok; total += 1
        sig_ok += H.verify_signature(d.certificate, d.signature, eng.key)
        certs.append((net, sc, d, eng.key))
    cert_rej = sig_rej = 0
    names_cache = {}
    for i in range(n_tamper):
        net, sc, d, key = certs[rng.randrange(len(certs))]
        names = names_cache.setdefault(net.name, [m.name for m in net.machines])
        c = copy.deepcopy(d.certificate)
        choice = i % 4
        if choice == 0:
            extra = [m for m in names if m not in c["isolate"]]
            c["isolate"] = sorted(c["isolate"] + [rng.choice(extra)])
        elif choice == 1:
            c["segment"] = c["segment"] + [rng.choice(names)]
        elif choice == 2:
            c["status"] = "CONTAINED" if c["status"] != "CONTAINED" else "ESCALATED"
        else:
            c["claims"]["services_down"] = c["claims"]["services_down"] + ["fake_service"]
        cert_rej += not H.verify_certificate(net, sc, c)
        sig_rej += not H.verify_signature(c, d.signature, key)
    times.sort()
    return {"decisions": total, "genuine_accepted": accepted, "signatures_valid": sig_ok,
            "checker_ms": {"median": times[len(times) // 2], "p95": times[int(0.95 * (len(times) - 1))]},
            "tampered": n_tamper, "tampered_rejected_by_checker": cert_rej, "tampered_rejected_by_hmac": sig_rej,
            "S5_target_met": accepted == total and cert_rej == n_tamper and times[len(times) // 2] < 1,
            "F16_target_met": sig_rej == n_tamper}


def ttl(n=1000, seed=8032):
    rng = random.Random(seed)
    store = X.RuleStore(); confirmed = set()
    for i in range(n):
        store.add(f"r{i}", "ISOLATE", f"m{i}", now=rng.uniform(0, 600))
        if i % 5 == 0:
            store.confirm(f"r{i}", now=1200); confirmed.add(f"r{i}")
    with_expiry = sum("expires" in r for r in store.rules.values())
    store.expire(now=600 + X.DEFAULT_TTL_S)               # every unconfirmed rule is past its expiry
    left = set(store.rules)
    return {"rules": n, "with_expiry": with_expiry, "unconfirmed_expired": n - len(confirmed) - len(left - confirmed),
            "unconfirmed": n - len(confirmed), "confirmed_kept": len(left & confirmed),
            "target_met": with_expiry == n and left == confirmed}


def main():
    pairs = all_pairs()
    v7 = json.loads((R / "v7" / "v7.json").read_text())
    res = {"meta": meta("phase11_executor", ("executor_v8.py", "hassan.py", "phase11_executor.py")),
           "audit_chain": audit_chain(), "certificates_and_hmac": certificates(pairs), "ttl": ttl(),
           "decaying_containment": {k: X.decay_simulation(v7[k]["rows"]) for k in ("chains_7008", "random_9003")}}
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "executor.json").write_text(json.dumps(res, indent=1))
    print(json.dumps({k: v for k, v in res.items() if k != "meta"}, indent=1))


if __name__ == "__main__":
    main()
