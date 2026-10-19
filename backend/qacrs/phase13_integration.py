"""Phase 13 (v8 G): integration targets — API latency (44), ACRS timers (45), incident replay (46).

    cd backend && python -m qacrs.phase13_integration        -> results/v8/integration.json
    cd backend && python -m qacrs.phase13_integration --v9   -> results/v9/integration_v9.json (API on EngineV9)

Rules: docs/qacrs/PREREGISTRATION_v8.md, section G.
  44: 1,000 POST /hassan/decide over local HTTP (one keep-alive-free request each), p95 < 50 ms.
  45: every stored scenario (all sets + Hospital-60) decided and mapped to ACRS: 100% within the 7 s tier-0 timer.
  46: 100 scenario ids drawn at random (seed 8130) all replay to a decision card.
"""
from __future__ import annotations

import json
import random
import threading
import time
import urllib.request
from pathlib import Path

from qacrs import hassan as H
from qacrs import hassan_service as SV
from qacrs import realism_v8 as RV
from qacrs.meta import meta
from qacrs.phase11_executor import all_pairs
from qacrs.phase8_ood import chain_scenarios

OUT = Path(__file__).parent / "results" / "v8"


def pct(v, q):
    v = sorted(v); return v[min(len(v) - 1, int(round(q * (len(v) - 1))))]


def api_latency(pairs, n=1000):
    srv = SV.make_server(0, limiter_factory=lambda: H.RateLimiter(limit=10 ** 9))
    th = threading.Thread(target=srv.serve_forever, daemon=True); th.start()
    url = f"http://127.0.0.1:{srv.server_address[1]}/hassan/decide"
    lat, codes, server_ms = [], {}, []
    try:
        for i in range(n):
            net, sc = pairs[i % len(pairs)]
            body = json.dumps({"network": net.name, "hacked": sc.hacked, "id": sc.id}).encode()
            req = urllib.request.Request(url, body, {"Content-Type": "application/json"})
            t = time.perf_counter()
            with urllib.request.urlopen(req) as r:
                out = json.loads(r.read()); codes[r.status] = codes.get(r.status, 0) + 1
            lat.append(1000 * (time.perf_counter() - t)); server_ms.append(out["ms"])
        bad = []
        for payload in (b"{", b'{"network":"nope","hacked":{}}', b'{"network":"net12"}'):
            try:
                urllib.request.urlopen(urllib.request.Request(url, payload, {"Content-Type": "application/json"}))
                bad.append(200)
            except urllib.error.HTTPError as e:
                bad.append(e.code)
    finally:
        srv.shutdown()
    return {"requests": n, "status_codes": codes, "round_trip_ms": {"median": pct(lat, .5), "p95": pct(lat, .95), "max": max(lat)},
            "engine_ms": {"median": pct(server_ms, .5), "p95": pct(server_ms, .95)},
            "malformed_requests_status": bad, "target_met": pct(lat, .95) < 50 and codes == {200: n} and bad == [400, 400, 400]}


def acrs_timers(pairs):
    engines, within, n, worst = {}, 0, 0, 0.0
    for net, sc in pairs:
        eng = engines.setdefault(net.name, H.Engine(net, limiter=H.RateLimiter(limit=10 ** 9)))
        a = SV.to_acrs(net, eng.decide(sc), tier=0, sc=sc)
        within += a["within_deadline"]; n += 1; worst = max(worst, a["decision_s"])
    return {"decisions": n, "within_7s": within, "worst_decision_s": worst, "target_met": within == n,
            "note": "decision time only; ACRS executor/controller latency is measured separately in research/e2e_timing.py"}


def replay_check(pairs, k=100, seed=8130):
    ids = [sc.id for _, sc in random.Random(seed).sample(pairs, k)]
    ok = sum(bool((r := SV.replay(i)) and r["decision"]["card"]["en"]) for i in ids)
    return {"sampled": k, "replayed_with_card": ok, "target_met": ok == k}


def main():
    import sys
    out_dir, out_name = (OUT.parent / "v9", "integration_v9.json") if "--v9" in sys.argv else (OUT, "integration.json")
    t = time.perf_counter()
    h60 = RV.hospital60()
    pairs = all_pairs() + [(h60, s) for s in chain_scenarios(h60, 200, 7101)]
    res = {"meta": meta("phase13_integration", ("hassan.py", "hassan_service.py", "phase13_integration.py"))}
    for name, fn in (("api_44", lambda: api_latency(pairs)), ("acrs_timers_45", lambda: acrs_timers(pairs)),
                     ("replay_46", lambda: replay_check(pairs))):
        t0 = time.perf_counter(); res[name] = fn()
        print(f"== {name} ({time.perf_counter() - t0:.1f}s): {json.dumps(res[name])}", flush=True)
    res["meta"]["seconds"] = round(time.perf_counter() - t, 1)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / out_name).write_text(json.dumps(res, indent=1))


if __name__ == "__main__":
    main()
