"""HASSAN engine: one hardened entry point around the v7 decision.

    from qacrs.hassan import Engine
    eng = Engine(net); d = eng.decide(scenario)      # -> HassanDecision (actions, status, card, certificate, signature)

Features (docs/qacrs/PREREGISTRATION_v8.md): 13 fail-safe, 14 rate limit, 36 solver portfolio, S10 alert-consistency
guard, S1 harm certificate, S5 proof-carrying certificate, 16 HMAC signature, 8 time-boxed rules, 18/19/47 decision card.
Nothing here touches a network: it only returns decisions. Execution goes through an adapter (mock or sandbox).
"""
from __future__ import annotations

import concurrent.futures as cf
import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field

from qacrs import escalation as E
from qacrs import qubo_v7 as V7
from qacrs import safety_checks as S
from qacrs.network import Network, Scenario
from qacrs.phase3_compare import annealing

EXACT_MAX_VARS = 20
SOLVER_TIMEOUT_S = 0.100
RATE_LIMIT, RATE_WINDOW_S = 3, 60.0
DEFAULT_TTL_S = 30 * 60
GUARD_BURST_SIZE, GUARD_BURST_RISK = 3, 9


# ------------------------------------------------------------------ solver portfolio (36) -------------------------
def solve(net: Network, sc: Scenario, seed: int = 0) -> tuple[set, set, str]:
    q = V7.build_v7(net, sc)
    if q.n <= EXACT_MAX_VARS:
        vals = q.all_values(); k = int(vals.argmin()); method = "exact"
    else:
        best = None
        for r in range(3):                                 # simulated annealing, keep best bit-vector
            import random
            rng = random.Random(seed * 100 + r)
            x = [0] * q.n; e = q.value(x)
            bx, be = x[:], e
            steps = 6000
            for t in range(steps):
                T = 10 * (1 - t / steps) + 1e-3
                i = rng.randrange(q.n); x[i] ^= 1; e2 = q.value(x)
                if e2 <= e or rng.random() < pow(2.718281828, (e - e2) / T):
                    e = e2
                    if e < be:
                        bx, be = x[:], e
                else:
                    x[i] ^= 1
            if best is None or be < best[1]:
                best = (bx, be)
        k = sum(b << i for i, b in enumerate(best[0])); method = "annealing"
    iso, seg = V7.split(q, k)
    return iso, seg, method


# ------------------------------------------------------------------ alert-consistency guard (S10) -----------------
def entry_points(net: Network) -> set[str]:
    return {m.name for m in net.machines if m.name.startswith(("web", "pc_"))}


def consistency_flags(net: Network, sc: Scenario) -> list[str]:
    """Implausible alert sets: a hacked non-entry machine with no hacked in-neighbour, or a burst of very high risks."""
    entries = entry_points(net)
    preds: dict[str, set[str]] = {}
    for a, b in net.links:
        preds.setdefault(b, set()).add(a)
    flags = [f"'{m}' reported hacked with no compromised path into it" for m in sorted(sc.hacked)
             if m not in entries and not (preds.get(m, set()) & set(sc.hacked))]
    if len(sc.hacked) >= GUARD_BURST_SIZE and all(r >= GUARD_BURST_RISK for r in sc.hacked.values()):
        flags.append(f"burst of {len(sc.hacked)} simultaneous alerts all at risk >= {GUARD_BURST_RISK}")
    return flags


# ------------------------------------------------------------------ rate limiter (14) -----------------------------
class RateLimiter:
    def __init__(self, limit=RATE_LIMIT, window=RATE_WINDOW_S, clock=time.monotonic):
        self.limit, self.window, self.clock, self.events = limit, window, clock, []

    def allow(self, n: int) -> int:
        now = self.clock()
        self.events = [t for t in self.events if now - t < self.window]
        ok = max(0, min(n, self.limit - len(self.events)))
        self.events += [now] * ok
        return ok


# ------------------------------------------------------------------ certificates, signing ------------------------
def certificate(net: Network, sc: Scenario, iso, seg, status) -> dict:
    hacked = set(sc.hacked)
    machines = {m.name: m for m in net.machines}
    return {"scenario_hash": hashlib.sha256(json.dumps(sorted(sc.hacked.items())).encode()).hexdigest()[:16],
            "isolate": sorted(iso), "segment": sorted(seg), "status": status,
            "claims": {"isolated_subset_of_reported_hacked": set(iso) <= hacked,
                       "no_never_isolate_device_isolated": all(machines[m].isolatable for m in iso),
                       "segment_only_on_critical": all(machines[m].critical for m in seg),
                       "no_critical_isolated_automatically": not any(machines[m].critical for m in iso),
                       "services_down": V7.services_down_v7(net, iso, seg, hacked),
                       "open_paths_after": [list(p) for p in V7.open_paths_v7(net, sc, iso, seg)]}}


def verify_certificate(net: Network, sc: Scenario, cert: dict) -> bool:
    """Independent checker (S5): recomputes every claim from the network and the scenario only."""
    try:
        fresh = certificate(net, sc, set(cert["isolate"]), set(cert["segment"]), cert["status"])
    except Exception:
        return False
    c = fresh["claims"]
    return (fresh == cert and c["no_never_isolate_device_isolated"] and c["segment_only_on_critical"]
            and c["no_critical_isolated_automatically"] and c["isolated_subset_of_reported_hacked"])


def sign(payload: dict, key: bytes) -> str:
    return hmac.new(key, json.dumps(payload, sort_keys=True).encode(), hashlib.sha256).hexdigest()


def verify_signature(payload: dict, sig: str, key: bytes) -> bool:
    return hmac.compare_digest(sign(payload, key), sig)


# ------------------------------------------------------------------ decision card (18, 19, 47) -------------------
def card(net, sc, iso, seg, status, escalations, flags) -> dict:
    hacked = set(sc.hacked)
    down = V7.services_down_v7(net, iso, seg, hacked)
    full = V7.m_full_isolation_safe(net, sc)[0]
    full_down = V7.services_down_v7(net, full, set(), hacked)
    restricted = sorted(hacked - set(iso) - set(seg))
    en = (f"Isolate {', '.join(sorted(iso)) or 'nothing'}; segment {', '.join(sorted(seg)) or 'nothing'}; "
          f"restrict {', '.join(restricted) or 'nothing'}. Services down: {', '.join(down) or 'none'} "
          f"(full isolation would take down {len(full_down)}: {', '.join(full_down) or 'none'}). Status: {status}.")
    ar = (f"عزل: {'، '.join(sorted(iso)) or 'لا شيء'}؛ تجزئة: {'، '.join(sorted(seg)) or 'لا شيء'}؛ "
          f"تقييد: {'، '.join(restricted) or 'لا شيء'}. الخدمات المتوقفة: {'، '.join(down) or 'لا شيء'} "
          f"(العزل الكامل كان سيوقف {len(full_down)}). الحالة: {status}.")
    return {"en": en, "ar": ar, "services_down": down, "services_saved_vs_full_isolation": len(full_down) - len(down),
            "escalations": [e["action"] for e in escalations], "guard_flags": flags}


# ------------------------------------------------------------------ engine ---------------------------------------
@dataclass
class HassanDecision:
    isolate: list[str]
    segment: list[str]
    restrict: list[str]
    status: str
    escalations: list[dict]
    held_for_humans: list[str]
    solver: str
    fallback: str | None
    guard_flags: list[str]
    expires_in_s: int
    card: dict
    certificate: dict
    signature: str
    ms: float = 0.0
    extra: dict = field(default_factory=dict)


class Engine:
    def __init__(self, net: Network, key: bytes = b"demo-key-not-secret", limiter: RateLimiter | None = None,
                 solver=solve, ttl_s: int = DEFAULT_TTL_S):
        self.net, self.key, self.limiter, self.solver, self.ttl = net, key, limiter or RateLimiter(), solver, ttl_s
        self._pool = cf.ThreadPoolExecutor(max_workers=1)

    def _safe_solve(self, sc):
        try:
            fut = self._pool.submit(self.solver, self.net, sc)
            iso, seg, method = fut.result(timeout=SOLVER_TIMEOUT_S)
        except cf.TimeoutError:
            self._pool = cf.ThreadPoolExecutor(max_workers=1)        # abandon the stuck worker
            return set(), set(), "fallback", "solver timeout"
        except Exception as e:
            return set(), set(), "fallback", f"solver error: {type(e).__name__}"
        names = {m.name for m in self.net.machines}
        if not (isinstance(iso, set) and isinstance(seg, set)) or (iso | seg) - names or iso & seg:
            return set(), set(), "fallback", "malformed solver output"
        return iso, seg, method, None

    def decide(self, sc: Scenario) -> HassanDecision:
        t = time.perf_counter()
        errors = S.validate_scenario(self.net, sc)
        if errors:
            payload = {"status": S.REJECTED, "errors": errors}
            return HassanDecision([], [], [], S.REJECTED, [], [], "none", "invalid input", [], 0,
                                  {"en": "; ".join(errors), "ar": "مدخلات غير صالحة"}, payload,
                                  sign(payload, self.key), 1000 * (time.perf_counter() - t))
        iso, seg, method, fallback = self._safe_solve(sc)
        flags = consistency_flags(self.net, sc)
        held = []
        if flags and iso:                                       # suspected forgery: no automatic isolation
            held += sorted(iso); iso = set()
        allowed = self.limiter.allow(len(iso))                  # rate limit automatic isolations
        if allowed < len(iso):
            keep = sorted(iso, key=lambda m: -sc.hacked.get(m, 0))[:allowed]
            held += sorted(set(iso) - set(keep)); iso = set(keep)
        d = V7.decide_v7(self.net, sc, iso, seg)
        status, esc = d.status, list(d.escalations)
        if fallback or held or flags:
            if status in (S.CONTAINED, S.PENDING, S.NOT_CONTAINED):
                status = E.ESCALATED
            if fallback:
                esc.append({"rule": "FAILSAFE", "target": "*", "approvals": 2,
                            "action": f"restricted all reported machines only ({fallback}); human decision required"})
            if held:
                esc.append({"rule": "HELD", "target": ",".join(held), "approvals": 2,
                            "action": f"isolation of {', '.join(held)} held for humans (rate limit or alert-consistency guard)"})
        restrict = sorted(set(sc.hacked) - iso - seg)
        cert = certificate(self.net, sc, iso, seg, status)
        return HassanDecision(sorted(iso), sorted(seg), restrict, status, esc, held, method, fallback, flags,
                              self.ttl, card(self.net, sc, iso, seg, status, esc, flags), cert, sign(cert, self.key),
                              1000 * (time.perf_counter() - t))
