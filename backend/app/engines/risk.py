"""Risk Engine: Asset Attribution, Risk Score (0-100), Confidence (0-100 %), Blast Radius.

Every number is returned with its explanation matrix, so an analyst can see
exactly why the engine reached a score. No ML black box, no LLM.
"""
from __future__ import annotations

from datetime import timedelta

from .detection import is_public
from .policy import (ADJUSTMENTS, CONFIDENCE_WEIGHTS, CRITICALITY_BLAST, RISK_WEIGHTS, ROLE_EGRESS_PROFILE,
                     SINGLE_SOURCE_CONFIDENCE_CAP, TIER_SENSITIVITY)
from .types import Asset, Attribution, Detection, Event, Factor, RiskAssessment

# TI and UEBA enrich the same telemetry, so they are not independent sensors.
INDEPENDENT_SOURCES = {"edr", "ndr", "firewall", "dns", "identity", "cloud", "app"}


def attribute(src_ip: str, events: list[Event], assets_by_ip: dict[str, Asset]) -> Attribution:
    """IP -> asset via CMDB, cross-checked with the hostname the EDR reports."""
    asset = assets_by_ip.get(src_ip)
    if asset is None:
        return Attribution(None, False, False, [f"{src_ip} is not in the CMDB / asset inventory"])
    edr_hosts = {e.hostname.lower() for e in events if e.source == "edr" and e.hostname}
    if edr_hosts and asset.hostname.lower() not in edr_hosts:
        return Attribution(asset, True, True,
                           [f"EDR reports {sorted(edr_hosts)} but CMDB says {asset.hostname}"])
    return Attribution(asset, True, False,
                       [f"{src_ip} -> {asset.hostname} (Tier-{asset.tier}, {asset.role}, owner {asset.owner})"])


def noisy_or(values: list[float]) -> float:
    p = 1.0
    for v in values:
        p *= (1.0 - max(0.0, min(1.0, v)))
    return 1.0 - p


def role_mismatch(asset: Asset | None, events: list[Event]) -> float:
    if asset is None:
        return 0.0
    allowed = ROLE_EGRESS_PROFILE.get(asset.role, {443})
    for e in events:
        if e.event_type == "net_conn" and is_public(e.data.get("dest_ip", "")) and e.data.get("dest_port") not in allowed:
            return 1.0
    return 0.0


def blast_radius(asset: Asset | None, events: list[Event]) -> dict:
    if events:
        latest = max(e.ts for e in events)
        recent = [e for e in events if e.ts >= latest - timedelta(hours=24)]
    else:
        recent = []
    peers = sorted({e.data["dest_ip"] for e in recent if e.event_type == "net_conn"
                    and "dest_ip" in e.data and not is_public(e.data["dest_ip"])})
    dependents = list(asset.dependents) if asset else []
    crit = CRITICALITY_BLAST.get(asset.criticality, 0.3) if asset else 0.3
    value = max(min(1.0, (len(peers) + len(dependents)) / 5), crit)
    if asset is None:
        impact = "unknown"
    else:
        impact = "high" if asset.tier == 0 or (asset.pool_size < 2 and dependents) else "low"
    return {"value": round(value, 3), "peers": peers[:50], "threat_radius": len(peers),
            "dependents": dependents, "containment_impact": impact}


def _factor(name: str, weights: dict[str, float], value: float, explanation: str) -> Factor:
    w = weights[name]
    return Factor(name, w, round(value, 3), round(w * value * 100, 2), explanation)


def assess(detections: list[Detection], asset: Asset | None, events: list[Event],
           attribution_conflict: bool) -> RiskAssessment:
    sources = sorted({d.source for d in detections if d.source in INDEPENDENT_SOURCES})
    n = len(sources)
    strengths = [d.strength for d in detections]
    severity = noisy_or(strengths)
    corroboration = 1.0 if n >= 3 else 0.7 if n == 2 else 0.3 if n == 1 else 0.0
    ti = max((d.evidence.get("confidence", d.strength * 100) / 100 for d in detections
              if d.category == "threat_intel"), default=0.0)
    ueba = max((d.strength for d in detections if d.category == "ueba"), default=0.0)
    mismatch = role_mismatch(asset, events)
    behavior = max(ueba, mismatch)
    sensitivity = TIER_SENSITIVITY.get(asset.tier, 0.5) if asset else 0.5
    blast = blast_radius(asset, events)

    rw = RISK_WEIGHTS
    risk_factors = [
        _factor("signal_severity", rw, severity, f"{len(detections)} detections combined (noisy-OR)"),
        _factor("source_correlation", rw, corroboration, f"{n} independent sources: {', '.join(sources) or 'none'}"),
        _factor("threat_intel", rw, ti, f"IoC reputation {int(ti * 100)}" if ti else "no threat-intel match"),
        _factor("behavior_anomaly", rw, behavior,
                "egress outside role profile" if mismatch else (f"UEBA deviation {ueba:.2f}" if ueba else "no anomaly")),
        _factor("asset_sensitivity", rw, sensitivity, f"Tier-{asset.tier}" if asset else "unknown asset"),
        _factor("blast_radius", rw, blast["value"],
                f"{blast['threat_radius']} peers, {len(blast['dependents'])} dependents, criticality "
                f"{asset.criticality if asset else 'unknown'}"),
    ]
    adjustments: dict[str, int] = {}
    if asset and asset.in_change_window:
        adjustments["change_window"] = ADJUSTMENTS["change_window"]
    if attribution_conflict:
        adjustments["attribution_conflict"] = ADJUSTMENTS["attribution_conflict"]
    risk = int(round(max(0.0, min(100.0, sum(f.contribution for f in risk_factors) + sum(adjustments.values())))))

    cw = CONFIDENCE_WEIGHTS
    source_agreement = 1.0 if n >= 3 else 0.7 if n == 2 else 0.35 if n == 1 else 0.0
    conf_factors = [
        _factor("independent_sources", cw, source_agreement, f"{n} independent sensors agree"),
        _factor("ioc_reputation", cw, ti, "threat-intel confidence" if ti else "no IoC reputation"),
        _factor("evidence_strength", cw, severity, "combined detection strength"),
    ]
    confidence = sum(f.contribution for f in conf_factors)
    if n < 2:
        confidence = min(confidence, SINGLE_SOURCE_CONFIDENCE_CAP)
    return RiskAssessment(risk=risk, confidence=int(round(confidence)), risk_factors=risk_factors,
                          confidence_factors=conf_factors, adjustments=adjustments,
                          distinct_sources=n, blast_radius=blast)
