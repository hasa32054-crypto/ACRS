"""Decision Engine: explicit, prioritised rules. No ML, no LLM.

Principle: "Autonomous by Default, Human as Last Resort" – with two deliberate
exceptions agreed in design review: full isolation of a Tier-0 asset needs two
people, and medium-confidence or change-window cases pause for confirmation.
"""
from __future__ import annotations

from .policy import (CIRCUIT_BREAKER_MAX, MEDIUM_FLOOR, MIN_AUTO_CONFIDENCE, SEGMENT_RESTRICT_MIN_ASSETS,
                     TIER_POLICY)
from .types import Attribution, Decision, Detection, Level, RiskAssessment


def _deadline(tier: int) -> float:
    return float(TIER_POLICY.get(tier, TIER_POLICY[2])["deadline_s"])


def decide(attribution: Attribution, ra: RiskAssessment, detections: list[Detection],
           recent_auto: int = 0, segment_hits: int = 0) -> Decision:
    reasons: list[str] = []
    fast_path = any(d.fast_path for d in detections)
    ueba_confirms = any(d.category == "ueba" for d in detections)

    # 1. Unknown asset: restrict by IP at the network edge, a human registers it.
    if not attribution.ok or attribution.asset is None:
        return Decision(Level.RESTRICT, True, _deadline(2), 1,
                        ["Asset not in CMDB: restrict the source IP at the edge only"],
                        escalation_level=Level.SURGICAL,
                        hold_after_verify="Unknown asset: register it in the CMDB or escalate")

    asset = attribution.asset
    tier = asset.tier
    policy = TIER_POLICY.get(tier, TIER_POLICY[2])
    deadline = _deadline(tier)
    high_impact = ra.blast_radius.get("containment_impact") == "high"

    # 2. Non-isolatable (legacy medical / OT): compensating controls only.
    if not asset.isolatable:
        if ra.risk < MEDIUM_FLOOR:
            return Decision(Level.MONITOR, False, deadline, 0, [f"Risk {ra.risk} < {MEDIUM_FLOOR}: monitor"])
        return Decision(Level.COMPENSATING, True, deadline, 0,
                        ["Asset cannot be isolated (safety-critical / no agent): compensating controls only",
                         "Essential flows stay allowlisted; C2 and DNS are blocked at the network"],
                        hold_after_verify="Non-isolatable asset: remediation needs the device owner / vendor")

    # 3. Ransomware fast path: containment before confidence.
    if fast_path:
        seg = segment_hits + 1 >= SEGMENT_RESTRICT_MIN_ASSETS
        reasons.append("Ransomware fast path (T1486/T1490): contain before confidence gating")
        if seg:
            reasons.append(f"{segment_hits + 1} assets hit in {asset.segment}: restrict SMB/RDP inside this segment only")
        if tier == 0:
            return Decision(Level.EMERGENCY_RESTRICT, True, deadline, 2,
                            reasons + ["Tier-0: restrictive actions only; full isolation needs two approvers"],
                            escalation_level=Level.FULL_ISOLATION, segment_restrict=seg, degraded_mode=True)
        if tier == 1:
            return Decision(Level.SURGICAL, True, deadline, 1, reasons, escalation_level=Level.FULL_ISOLATION,
                            segment_restrict=seg, degraded_mode=high_impact)
        return Decision(Level.FULL_ISOLATION, True, deadline, 0, reasons, segment_restrict=seg)

    # 4. Confidence gate (includes the single-source cap).
    if ra.confidence < MIN_AUTO_CONFIDENCE:
        reasons.append(f"Confidence {ra.confidence}% < {MIN_AUTO_CONFIDENCE}% "
                       f"({ra.distinct_sources} independent source): no automatic containment")
        if ra.risk >= MEDIUM_FLOOR:
            return Decision(Level.RESTRICT, False, deadline, 1, reasons)
        return Decision(Level.MONITOR, False, deadline, 0, reasons)

    # 5. Low risk.
    if ra.risk < MEDIUM_FLOOR:
        return Decision(Level.MONITOR, False, deadline, 0, [f"Risk {ra.risk} < {MEDIUM_FLOOR}: monitor and enrich"])

    # 6. Change window: lower the odds of isolation, ask UEBA for context.
    if asset.in_change_window:
        reasons.append("Asset is inside an approved change window (risk -15)")
        if not ueba_confirms:
            return Decision(Level.RESTRICT, False, deadline, 1,
                            reasons + ["UEBA shows no deviation beyond the change baseline: analyst confirmation required"])
        reasons.append("UEBA confirms abnormal behaviour despite the change window")
        return Decision(Level.RESTRICT, True, deadline, 1, reasons, escalation_level=Level.SURGICAL,
                        hold_after_verify="Change window: confirm before remediation")

    threshold = policy["auto_threshold"]
    reasons.append(f"Risk {ra.risk} / confidence {ra.confidence}% on Tier-{tier} (auto threshold {threshold})")

    # 7. Tier thresholds.
    if ra.risk >= threshold:
        if tier == 0:
            d = Decision(Level.EMERGENCY_RESTRICT, True, deadline, 2,
                         reasons + ["Tier-0 emergency containment: restrictive actions only, "
                                    "authentication keeps running on the other controllers",
                                    "Full isolation needs two approvers"],
                         escalation_level=Level.FULL_ISOLATION, degraded_mode=True)
        elif tier == 1:
            d = Decision(Level.SURGICAL, True, deadline, 1,
                         reasons + ["Tier-1: surgical isolation, service continues on redundant nodes"
                                    if not high_impact else "Tier-1 without redundancy: surgical isolation + degraded mode"],
                         escalation_level=Level.FULL_ISOLATION, degraded_mode=high_impact)
        else:
            d = Decision(Level.FULL_ISOLATION, True, deadline, 0, reasons + ["Tier-2: full isolation, no human needed"])
    else:
        # 8. Medium band: restrict now, stronger action needs a human.
        reasons.append(f"Medium band ({MEDIUM_FLOOR} <= risk < {threshold})")
        if tier == 0:
            d = Decision(Level.MONITOR, False, deadline, 2,
                         reasons + ["Tier-0: enhanced monitoring, emergency containment needs two approvers"],
                         escalation_level=Level.EMERGENCY_RESTRICT)
        else:
            d = Decision(Level.RESTRICT, True, deadline, 1,
                         reasons + ["Restrict automatically; surgical isolation needs approval"],
                         escalation_level=Level.SURGICAL,
                         hold_after_verify="Medium confidence: confirm or escalate before remediation")

    # 9. Circuit breaker: containment-as-DoS protection.
    if d.auto_execute and recent_auto >= CIRCUIT_BREAKER_MAX:
        d.auto_execute = False
        d.approvals_required = max(1, d.approvals_required)
        d.escalation_level = None
        d.circuit_breaker = True
        d.reasons.append(f"Circuit breaker: {recent_auto} automatic containments in 10 min, human approval required")
    return d
