"""Controlled simulation experiment: uniform full isolation vs. ACRS risk-adaptive containment.

Run from the backend folder:
    python -m research.experiment

Design
------
* Same input for both arms: the 40 attack-lab scenarios (success mode), the same detection rules and the same
  risk / confidence scoring. Only the response policy differs, so any difference is caused by the policy.
* BASELINE (uniform): an incident is actionable when risk >= 60 or the ransomware fast path fires (the same
  trigger floor ACRS uses). Every actionable incident gets FULL_ISOLATION, automatically, on every asset type.
* ACRS: the unmodified decision engine (app.engines.decision.decide).
* Each decision is turned into the concrete command list by the unmodified response planner
  (app.engines.response.plan). All outcome metrics are read from that command list and the asset model,
  using the measurement model defined in `measure()` below. Nothing is sampled at random, so the run is
  fully reproducible: same code, same numbers.

All data are simulated. The results describe the behaviour of the decision model on synthetic incidents,
not performance in a real network.
"""
from __future__ import annotations

import json
import time
from collections import Counter, defaultdict
from dataclasses import replace
from pathlib import Path

from app.engines.decision import decide as acrs_decide
from app.engines.detection import detect
from app.engines.policy import MEDIUM_FLOOR
from app.engines.response import plan
from app.engines.risk import assess, attribute
from app.engines.types import Asset, Attribution, Decision, Level, RiskAssessment
from app.services import simulators
from app.services.seed_data import asset_rows

OUT = Path(__file__).parent / "results"
ASSETS = {r["ip"]: Asset(**r) for r in asset_rows()}
BENIGN = {"erp_change_window_fp"}          # ground truth: the only scenario that is legitimate activity

OFFLINE_LEVELS = {Level.FULL_ISOLATION, Level.SURGICAL, Level.EMERGENCY_RESTRICT}
EGRESS_CMDS = {"BLOCK_C2", "RESTRICT_NETWORK", "ISOLATE_ASSET", "APPLY_MICROSEGMENTATION", "CLOUD_SG_UPDATE"}


# ---------------------------------------------------------------------------------------------- policies
def uniform_decide(attribution: Attribution, ra: RiskAssessment, detections, recent_auto: int = 0,
                   segment_hits: int = 0, threshold: int = MEDIUM_FLOOR) -> Decision:
    """Baseline: one rule for every asset. Actionable -> full isolation, no tiers, no human."""
    fast_path = any(d.fast_path for d in detections)
    if ra.risk >= threshold or fast_path:
        return Decision(Level.FULL_ISOLATION, True, 15.0, 0,
                        [f"Uniform policy: risk {ra.risk} >= {threshold} (or ransomware) -> full isolation"])
    return Decision(Level.MONITOR, False, 15.0, 0, [f"Uniform policy: risk {ra.risk} < {threshold}"])


# ---------------------------------------------------------------------------------------------- incidents
def incidents() -> list[dict]:
    """Every incident the 40 scenarios produce, analysed once and shared by both arms."""
    out = []
    for sid, sc in simulators.SCENARIOS.items():
        events, _ = simulators.build(sid, "success")
        seg_hits: Counter = Counter()
        for ip in sorted({e.src_ip for e in events}):
            evs = sorted([e for e in events if e.src_ip == ip], key=lambda e: e.ts)
            dets = detect(evs)
            if not dets:
                continue
            attr = attribute(ip, evs, ASSETS)
            ra = assess(dets, attr.asset, evs, attr.conflict)
            seg = attr.asset.segment if attr.asset else ip
            out.append({"scenario": sid, "category": sc["category"], "ip": ip, "attr": attr, "ra": ra,
                        "dets": dets, "segment_hits": seg_hits[seg], "benign": sid in BENIGN})
            if any(d.fast_path for d in dets):
                seg_hits[seg] += 1
    return out


# ---------------------------------------------------------------------------------------------- measurement
def measure(inc: dict, d: Decision) -> dict:
    """Measurement model (stated on the poster):
    * An action only happens automatically when the policy auto-executes it; otherwise it waits for a human.
    * Host offline      = FULL_ISOLATION, SURGICAL or EMERGENCY_RESTRICT executed on the host.
    * Critical outage   = a Tier-0/Tier-1 host with no redundant peer taken offline, or a non-isolatable
                          (safety-critical) device taken offline. Its business function stops.
    * C2 cut            = the automatic command list blocks the attacker's external channel.
    * Spread paths cut  = the automatic command list stops new connections from the host to critical systems.
    """
    attr: Attribution = inc["attr"]
    asset: Asset = attr.asset or Asset(id=0, hostname=inc["ip"], ip=inc["ip"], tier=2, role="unknown",
                                       segment="unknown", owner="", isolatable=True)
    auto = d.auto_execute
    cmds = plan(d.level, asset, inc["dets"], segment_restrict=d.segment_restrict) if auto else []
    names = {c.name for c in cmds}
    offline = auto and d.level in OFFLINE_LEVELS
    redundant = (asset.pool_size or 1) >= 2
    critical_outage = offline and ((asset.tier in (0, 1) and not redundant and attr.ok) or not asset.isolatable)
    spread_cut = bool(names & {"ISOLATE_ASSET"}) or any(
        c.name == "APPLY_MICROSEGMENTATION" and c.params.get("mode") in ("quarantine", "nac_quarantine_vlan")
        for c in cmds) or any(c.name == "RESTRICT_NETWORK" and c.params.get("new_flows_to_tiers") for c in cmds)
    # Human involvement, split by what the human is asked to do (optional escalations are counted separately).
    human_to_contain = (not auto) and d.level != Level.MONITOR          # nothing happens until a person approves
    human_before_recovery = auto and bool(d.hold_after_verify)          # contained automatically, person confirms
    tier0_two_person = auto and d.level == Level.EMERGENCY_RESTRICT     # optional full isolation needs 2 people
    return {
        "level": d.level.value, "auto": auto, "commands": sorted(names), "n_commands": len(cmds),
        "offline": offline, "critical_outage": bool(critical_outage),
        "safety_device_offline": offline and not asset.isolatable,
        "tier0_irreversible_without_human": auto and d.level == Level.FULL_ISOLATION and asset.tier == 0 and attr.ok,
        "c2_cut": bool(names & EGRESS_CMDS), "spread_cut": bool(spread_cut),
        "human_to_contain": human_to_contain, "human_before_recovery": human_before_recovery,
        "tier0_two_person_pending": tier0_two_person,
        "fully_autonomous": auto and not d.hold_after_verify and not tier0_two_person,
        "reasons": d.reasons,
    }


def run_arm(incs: list[dict], policy) -> list[dict]:
    rows = []
    for inc in incs:
        d = policy(inc["attr"], inc["ra"], inc["dets"], 0, inc["segment_hits"])
        a = inc["attr"].asset
        rows.append({"scenario": inc["scenario"], "category": inc["category"], "ip": inc["ip"],
                     "host": a.hostname if a else inc["ip"], "tier": a.tier if a else None,
                     "role": a.role if a else "unknown", "isolatable": a.isolatable if a else True,
                     "redundant": (a.pool_size or 1) >= 2 if a else False, "benign": inc["benign"],
                     "risk": inc["ra"].risk, "confidence": inc["ra"].confidence,
                     "sources": inc["ra"].distinct_sources, **measure(inc, d)})
    return rows


def summarise(rows: list[dict]) -> dict:
    mal = [r for r in rows if not r["benign"]]
    ben = [r for r in rows if r["benign"]]
    return {
        "incidents": len(rows), "malicious": len(mal), "benign": len(ben),
        "hosts_offline": sum(r["offline"] for r in rows),
        "critical_outages": sum(r["critical_outage"] for r in rows),
        "critical_outage_hosts": sorted({r["host"] for r in rows if r["critical_outage"]}),
        "safety_devices_offline": sum(r["safety_device_offline"] for r in rows),
        "tier0_irreversible_without_human": sum(r["tier0_irreversible_without_human"] for r in rows),
        "benign_hosts_offline": sum(r["offline"] for r in ben),
        "c2_cut_auto": sum(r["c2_cut"] for r in mal),
        "spread_cut_auto": sum(r["spread_cut"] for r in mal),
        "human_to_contain": sum(r["human_to_contain"] for r in rows),
        "human_before_recovery": sum(r["human_before_recovery"] for r in rows),
        "tier0_two_person_pending": sum(r["tier0_two_person_pending"] for r in rows),
        "fully_autonomous": sum(r["fully_autonomous"] for r in rows),
        "no_action": sum(r["level"] == "MONITOR" for r in rows),
        "levels": dict(Counter(r["level"] for r in rows)),
    }


# ---------------------------------------------------------------------------------------------- criticality
def criticality_sweep() -> list[dict]:
    """Same attack evidence (the HR C2 scenario, 3 sensors + threat intel) replayed on every asset."""
    events, _ = simulators.build("tier1_c2_hr", "success")
    src = sorted({e.src_ip for e in events})[0]
    rows = []
    for ip, asset in ASSETS.items():
        evs = sorted([replace(e, src_ip=ip, hostname=asset.hostname if e.hostname else None)
                      for e in events if e.src_ip == src], key=lambda e: e.ts)
        dets = detect(evs)
        attr = attribute(ip, evs, ASSETS)
        ra = assess(dets, attr.asset, evs, attr.conflict)
        a = acrs_decide(attr, ra, dets)
        b = uniform_decide(attr, ra, dets)
        rows.append({"host": asset.hostname, "tier": asset.tier, "role": asset.role, "isolatable": asset.isolatable,
                     "redundant": asset.pool_size >= 2, "in_change_window": asset.in_change_window,
                     "risk": ra.risk, "confidence": ra.confidence,
                     "acrs": a.level.value, "acrs_auto": a.auto_execute, "acrs_approvals": a.approvals_required,
                     "baseline": b.level.value})
    return rows


# ---------------------------------------------------------------------------------------------- decision matrix
def decision_matrix() -> dict:
    """The deterministic policy surface: risk (rows) x asset class (columns), confidence fixed at 90 %."""
    classes = {
        "Tier-2 user device": next(a for a in ASSETS.values() if a.hostname == "WS-FIN-023"),
        "Tier-1 server (redundant)": next(a for a in ASSETS.values() if a.hostname == "HR-APP-01"),
        "Tier-0 identity": next(a for a in ASSETS.values() if a.hostname == "DC-01"),
        "Safety-critical device": next(a for a in ASSETS.values() if a.hostname == "MRI-CTRL-02"),
    }
    risks = [40, 50, 60, 70, 80, 85, 90, 95, 100]
    grid = {}
    for name, asset in classes.items():
        attr = Attribution(asset=asset, ok=True, conflict=False)
        row = {}
        for r in risks:
            ra = RiskAssessment(risk=r, confidence=90, risk_factors=[], confidence_factors=[], adjustments={},
                                distinct_sources=3, blast_radius={"containment_impact": "low"})
            d = acrs_decide(attr, ra, [])
            row[str(r)] = {"level": d.level.value, "auto": d.auto_execute, "approvals": d.approvals_required}
        grid[name] = row
    low_conf = {}
    for name, asset in classes.items():
        attr = Attribution(asset=asset, ok=True, conflict=False)
        ra = RiskAssessment(risk=95, confidence=55, risk_factors=[], confidence_factors=[], adjustments={},
                            distinct_sources=1, blast_radius={"containment_impact": "low"})
        d = acrs_decide(attr, ra, [])
        low_conf[name] = {"level": d.level.value, "auto": d.auto_execute}
    return {"risks": risks, "classes": list(classes), "grid": grid, "single_source_risk95": low_conf}


# ---------------------------------------------------------------------------------------------- threshold sweep
def threshold_sweep(incs: list[dict]) -> list[dict]:
    """Can any single uniform threshold match ACRS? Outages vs. C2 channels cut, for thresholds 50..100."""
    out = []
    for t in range(50, 101, 5):
        rows = run_arm(incs, lambda at, ra, de, ra2=0, sh=0, t=t: uniform_decide(at, ra, de, ra2, sh, threshold=t))
        s = summarise(rows)
        out.append({"threshold": t, "critical_outages": s["critical_outages"], "c2_cut_auto": s["c2_cut_auto"],
                    "hosts_offline": s["hosts_offline"], "malicious": s["malicious"]})
    return out


def decision_latency(incs: list[dict], repeats: int = 2000) -> dict:
    res = {}
    for name, fn in (("acrs", acrs_decide), ("baseline", uniform_decide)):
        t0 = time.perf_counter()
        for _ in range(repeats):
            for inc in incs:
                fn(inc["attr"], inc["ra"], inc["dets"], 0, inc["segment_hits"])
        res[name + "_us_per_decision"] = round((time.perf_counter() - t0) / (repeats * len(incs)) * 1e6, 2)
    return res


def main() -> None:
    OUT.mkdir(exist_ok=True)
    incs = incidents()
    base_rows, acrs_rows = run_arm(incs, uniform_decide), run_arm(incs, acrs_decide)
    result = {
        "note": "Simulated evaluation: 40 synthetic attack scenarios, deterministic, reproducible.",
        "scenarios": len(simulators.SCENARIOS), "incidents": len(incs),
        "baseline": summarise(base_rows), "acrs": summarise(acrs_rows),
        "per_incident": {"baseline": base_rows, "acrs": acrs_rows},
        "criticality_sweep": criticality_sweep(),
        "decision_matrix": decision_matrix(),
        "threshold_sweep": threshold_sweep(incs),
        "decision_latency": decision_latency(incs),
    }
    (OUT / "experiment.json").write_text(json.dumps(result, indent=1, default=str))
    b, a = result["baseline"], result["acrs"]
    print(f"{len(simulators.SCENARIOS)} scenarios -> {len(incs)} incidents ({b['malicious']} malicious, {b['benign']} benign)")
    for k in ("hosts_offline", "critical_outages", "safety_devices_offline", "tier0_irreversible_without_human",
              "benign_hosts_offline", "c2_cut_auto", "spread_cut_auto", "human_to_contain", "human_before_recovery",
              "tier0_two_person_pending", "fully_autonomous", "no_action"):
        print(f"  {k:36} baseline={b[k]:>3}   acrs={a[k]:>3}")
    print("  levels baseline", b["levels"]); print("  levels acrs    ", a["levels"])
    print("  outage hosts baseline", b["critical_outage_hosts"]); print("  outage hosts acrs    ", a["critical_outage_hosts"])
    print("  latency", result["decision_latency"])


if __name__ == "__main__":
    main()
