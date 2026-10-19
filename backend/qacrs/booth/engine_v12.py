"""Booth engine on v12: safety floor + the locked optimiser + closure (PREREGISTRATION_v12 D1 + Amendment 1),
wrapped by the unchanged v8/v9 machinery (input validation, solver time budget with fail-safe, alert-consistency guard
with the network sensor, rate limit, locked gate `decide_v7`, HMAC) and signed with ML-DSA-65 (D9).

Nothing locked is modified: the v12 composition is passed to the locked `hassan.Engine` through its public
`solver=` parameter, exactly as `qubo_v12.decide_v12` composes it in the reported evaluation.

Certificate v12 = the v9 certificate fields (same claims, same status rule) + the floor reasons. The v9 checker's
optimality test does not apply (v12 deliberately adds floor actions on top of the optimum), so the v12 checker
re-derives the decision independently from the scenario and requires an exact match, plus every safety claim.
"""
from __future__ import annotations

import sys
from pathlib import Path

from qacrs import hassan as H
from qacrs import qubo_v7 as V7
from qacrs.hassan_v9 import certificate_v9, guard_v2
from qacrs.network import Network, Scenario
from qacrs.v12 import risk_map as RM
from qacrs.v12.qubo_v12 import closure, safety_floor

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "third_party"))
from dilithium_py.ml_dsa import ML_DSA_65  # noqa: E402

ALG = "ML-DSA-65"


def v12_plan(net: Network, sc: Scenario) -> tuple[set, set, str, dict]:
    """floor ∪ locked solver, then closure (d)(e). Deterministic; same composition as qubo_v12.decide_v12."""
    fl = safety_floor(net, sc)
    s_iso, s_seg, how = H.solve(net, sc)
    iso = set(s_iso) | fl.isolate
    seg = (set(s_seg) | fl.segment) - iso
    iso, seg = closure(net, sc, iso, seg, fl.reasons)
    seg -= iso
    return iso, seg, f"v12 floor + {how}", dict(fl.reasons)


def v12_solver(net: Network, sc: Scenario):
    iso, seg, how, _ = v12_plan(net, sc)
    return iso, seg, how


def certificate_v12(net, sc, iso, seg, held=(), flags=(), fallback=None, reasons=None) -> dict:
    c = certificate_v9(net, sc, iso, seg, held, flags, fallback)
    c.pop("objective_with_held", None)              # v12 is not "the optimum"; the checker re-derives instead
    c["engine"] = "v12"
    c["risk_table_hash"] = RM.table_hash()
    c["floor_reasons"] = dict(sorted((reasons or {}).items()))
    return c


def verify_certificate_v12(net, sc, cert: dict) -> bool:
    try:
        iso, seg, held = set(cert["isolate"]), set(cert["segment"]), set(cert["held"])
        if iso & held or iso & seg or cert.get("engine") != "v12" or cert.get("risk_table_hash") != RM.table_hash():
            return False
        fresh = certificate_v12(net, sc, iso, seg, held, cert["guard_flags"], cert["fallback"], cert["floor_reasons"])
    except Exception:
        return False
    if fresh != cert:
        return False
    c = fresh["claims"]
    if not (c["no_never_isolate_device_isolated"] and c["segment_only_on_critical"]
            and c["no_critical_isolated_automatically"] and c["isolated_subset_of_reported_hacked"]):
        return False
    if cert["fallback"]:
        return not iso and not seg and not held
    e_iso, e_seg, _, e_reasons = v12_plan(net, sc)          # independent re-derivation
    return (iso | held) == e_iso and seg == e_seg and e_reasons == cert["floor_reasons"]


class EngineV12:
    def __init__(self, net, key: bytes, limiter=None, pq: bool = True):
        self.net, self.key = net, key
        self.base = H.Engine(net, key=key, limiter=limiter, solver=v12_solver)
        self.pk, self._sk = ML_DSA_65.keygen() if pq else (None, None)

    def decide(self, sc: Scenario, lateral: set | None = None):
        d = self.base.decide(sc, flags=guard_v2(self.net, sc, lateral) if lateral is not None else None)
        if d.status == "REJECTED":
            return d
        reasons = {} if d.fallback else v12_plan(self.net, sc)[3]
        d.certificate = certificate_v12(self.net, sc, d.isolate, d.segment, d.held_for_humans, d.guard_flags,
                                        d.fallback, reasons)
        d.signature = H.sign(d.certificate, self.key)
        d.pq_signature = ML_DSA_65.sign(self._sk, H_canonical(d.certificate)).hex() if self._sk else None
        return d

    def verify_pq(self, cert: dict, sig_hex: str) -> bool:
        try:
            return bool(self.pk) and ML_DSA_65.verify(self.pk, H_canonical(cert), bytes.fromhex(sig_hex))
        except Exception:
            return False


def H_canonical(cert: dict) -> bytes:
    import json
    return json.dumps(cert, sort_keys=True, separators=(",", ":")).encode()


def services_after_approval(net, sc, iso, seg, escalations) -> list[str]:
    from qacrs.v12.qubo_v12 import approve_all
    ia, sa = approve_all(net, sc, iso, seg, [e for e in escalations if e["rule"] in ("G1", "G2", "G3")])
    return V7.services_down_v7(net, ia, sa, set(sc.hacked))
