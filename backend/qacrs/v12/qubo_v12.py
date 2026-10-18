"""D1: safety floor, then the locked optimiser, then the locked gate.

    floor  = deterministic actions that follow from the alert alone (no cost model involved)
    solver = qacrs.hassan.solve (locked v9 portfolio) on the same scenario, unchanged
    answer = union of the two; judged by qacrs.qubo_v7.decide_v7 (locked)

Nothing in the locked files is modified or monkey-patched. The floor only ADDS actions.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from qacrs import escalation as E
from qacrs import hassan as H
from qacrs import qubo_v7 as V7
from qacrs import safety_checks as S
from qacrs.network import Network, Scenario
from qacrs.v12 import risk_map as RM


@dataclass
class FloorResult:
    isolate: set[str] = field(default_factory=set)
    segment: set[str] = field(default_factory=set)
    owner_review: list[str] = field(default_factory=list)
    reasons: dict[str, str] = field(default_factory=dict)


def safety_floor(net: Network, sc: Scenario, immunity=None) -> FloorResult:
    machines = {m.name: m for m in net.machines}
    f = FloorResult()
    for h, r in sorted(sc.hacked.items()):
        m = machines.get(h)
        if m is None:
            continue
        if not m.isolatable:
            if r >= S.HIGH_RISK:
                f.owner_review.append(h); f.reasons[h] = "never-isolatable at high risk -> owner review"
            continue
        if m.critical:
            if r >= RM.RISK_FLOOR_SEGMENT:
                f.segment.add(h); f.reasons[h] = f"critical hacked at risk {r} >= {RM.RISK_FLOOR_SEGMENT} -> segment"
        elif r >= RM.RISK_FLOOR_ISOLATE:
            f.isolate.add(h); f.reasons[h] = f"destructive payload (risk {r}) -> isolate, no restrict option"
    if immunity is not None:
        for h, why in immunity.first_hop_actions(net, sc).items():
            if machines[h].isolatable and not machines[h].critical and h not in f.isolate:
                f.isolate.add(h); f.reasons[h] = why
    return f


def closure(net: Network, sc: Scenario, iso: set[str], seg: set[str], reasons: dict) -> tuple[set[str], set[str]]:
    """Amendment 1 (D1 d, e): close the two structural gaps found in the first v12 run.

    (d) a hacked critical server that is segmented (not isolated) still has an OPEN outgoing path to every healthy
        critical neighbour (segmentation protects the target, not the source) -> segment those neighbours too.
    (e) a hacked, isolatable, non-critical host at risk >= threshold that is only restricted, whose isolation takes
        NO additional service down (the service is already down or has a live twin) -> isolate it; it is free.
    Repeated until nothing changes. Only ADDS actions; the locked gate still judges the result.
    """
    machines = {m.name: m for m in net.machines}
    hacked = set(sc.hacked)
    changed = True
    while changed:
        changed = False
        for a, b in V7.open_paths_v7(net, sc, iso, seg):
            if machines[a].critical and a in seg and machines[b].critical and b not in seg and b not in iso:
                seg.add(b); reasons[b] = f"healthy critical neighbour of segmented '{a}' -> segment (closes C1)"; changed = True
        before = set(V7.services_down_v7(net, iso, seg, hacked))
        for h, r in sorted(sc.hacked.items()):
            m = machines[h]
            if r >= S.HIGH_RISK and m.isolatable and not m.critical and h not in iso and h not in seg:
                after = set(V7.services_down_v7(net, iso | {h}, seg, hacked))
                if after <= before:
                    iso.add(h); reasons[h] = f"risk {r} >= {S.HIGH_RISK} and isolation costs no service -> isolate"; changed = True
                    before = after
    return iso, seg


@dataclass
class DecisionV12:
    status: str
    isolate: list[str]
    segment: list[str]
    floor: dict
    solver: dict
    gate: dict
    decision_ms: float
    if_approved: dict

    def as_dict(self) -> dict:
        return self.__dict__


def approve_all(net, sc, iso, seg, escalations):
    iso, seg = set(iso), set(seg)
    for e in escalations:
        if e["rule"] in ("G1", "G3"):
            iso.add(e["target"]); seg.discard(e["target"])
        elif e["rule"] == "G2":
            seg.add(e["target"])
    return iso, seg


def decide_v12(net: Network, sc: Scenario, immunity=None, solver=H.solve) -> DecisionV12:
    t = time.perf_counter()
    fl = safety_floor(net, sc, immunity)
    s_iso, s_seg, how = solver(net, sc)
    iso = set(s_iso) | fl.isolate
    seg = (set(s_seg) | fl.segment) - iso
    iso, seg = closure(net, sc, iso, seg, fl.reasons)
    seg -= iso
    d = V7.decide_v7(net, sc, iso, seg)
    ms = 1000 * (time.perf_counter() - t)
    hacked = set(sc.hacked)
    ia, sa = approve_all(net, sc, iso, seg, d.escalations)
    return DecisionV12(
        status=d.status, isolate=sorted(iso), segment=sorted(seg),
        floor={"isolate": sorted(fl.isolate), "segment": sorted(fl.segment), "owner_review": fl.owner_review,
               "reasons": fl.reasons, "table_hash": RM.table_hash()},
        solver={"isolate": sorted(s_iso), "segment": sorted(s_seg), "method": how,
                "added_by_floor": sorted((fl.isolate - set(s_iso)) | (fl.segment - set(s_seg) - set(s_iso)))},
        gate=d.as_dict() | {"services_down": V7.services_down_v7(net, iso, seg, hacked),
                            "healthy_isolated": sorted(iso - hacked)},
        decision_ms=round(ms, 3),
        if_approved={"status": V7.decide_v7(net, sc, ia, sa).status, "isolate": sorted(ia), "segment": sorted(sa),
                     "services_down": V7.services_down_v7(net, ia, sa, hacked)},
    )


# ------------------------------------------------------------------ the five policies (D5) ------------------------
def policy_v9(net, sc):
    iso, seg, _ = H.solve(net, sc); return iso, seg


def policy_rule_segment(net, sc):
    return V7.m_rule_segment(net, sc)


def policy_wazuh_style(net, sc):
    """Active-response style: isolate every alerted host, no safety rule, no segmentation. Modelled, not the software."""
    return set(sc.hacked), set()


def policy_full_isolation(net, sc):
    return V7.m_full_isolation_safe(net, sc)


def policy_v12(net, sc, immunity=None):
    d = decide_v12(net, sc, immunity); return set(d.isolate), set(d.segment)


POLICIES = {"v12": policy_v12, "v9": policy_v9, "rule_segment": policy_rule_segment,
            "wazuh_style": policy_wazuh_style, "full_isolation": policy_full_isolation}


def evaluate_policy(net, sc, name: str, immunity=None) -> dict:
    t = time.perf_counter()
    iso, seg = POLICIES[name](net, sc, immunity) if name == "v12" else POLICIES[name](net, sc)
    ms = 1000 * (time.perf_counter() - t)
    d = V7.decide_v7(net, sc, iso, seg)
    hacked = set(sc.hacked)
    ia, sa = approve_all(net, sc, iso, seg, d.escalations)
    return {"status": d.status, "isolate": sorted(iso), "segment": sorted(seg),
            "services_down_auto": V7.services_down_v7(net, iso, seg, hacked),
            "services_down_after_approval": V7.services_down_v7(net, ia, sa, hacked),
            "healthy_isolated": sorted(iso - hacked), "escalations": len(d.escalations),
            "unsafe": d.status == S.REJECTED, "silent": d.status == S.NOT_CONTAINED,
            "auto_contained": d.status in (S.CONTAINED, S.PENDING), "decision_ms": round(ms, 3)}
