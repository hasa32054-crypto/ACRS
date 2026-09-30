"""Response Memory: reuse responses that an engineer has already validated.

Rules agreed in design review:
  * a pattern is reused only at >= 96 % similarity;
  * only APPROVED patterns (approved by an engineer) are reused, new ones start PENDING_VALIDATION;
  * memory never exceeds tier policy: it cannot raise the containment level, cannot turn a
    human-approval decision into an automatic one, and never touches Tier-0.
What it can do: skip the post-containment confirmation pause for a response that is already proven.
"""
from __future__ import annotations

from .types import LEVEL_RANK, Level

SIMILARITY_THRESHOLD = 0.96
FEATURE_WEIGHTS = {
    "attack_type": 0.20, "rules": 0.20, "mitre": 0.15, "entry_vector": 0.10,
    "asset_role": 0.15, "tier": 0.10, "environment": 0.05, "level": 0.05,
}
SET_FEATURES = {"rules", "mitre"}


def fingerprint(inc: dict, asset_role: str, environment: str) -> dict:
    dets = inc.get("detections") or []
    return {
        "attack_type": inc.get("attack_type") or "unknown",
        "rules": sorted({d["rule_id"] for d in dets}),
        "mitre": sorted({t for d in dets for t in d.get("mitre", [])}),
        "entry_vector": (inc.get("entry") or {}).get("vector", "unknown"),
        "asset_role": asset_role,
        "tier": inc.get("tier") if inc.get("tier") is not None else -1,
        "environment": environment,
        "level": inc.get("level") or "MONITOR",
    }


def _jaccard(a, b) -> float:
    a, b = set(a or []), set(b or [])
    if not a and not b:
        return 1.0
    return len(a & b) / len(a | b)


def similarity(a: dict, b: dict) -> float:
    score = 0.0
    for k, w in FEATURE_WEIGHTS.items():
        score += w * (_jaccard(a.get(k), b.get(k)) if k in SET_FEATURES else float(a.get(k) == b.get(k)))
    return round(score, 4)


def best_match(fp: dict, patterns: list[dict], approved_only: bool = True) -> tuple[dict | None, float]:
    best, best_score = None, 0.0
    for p in patterns:
        if approved_only and p["status"] != "APPROVED":
            continue
        s = similarity(fp, p["fingerprint"])
        if s > best_score:
            best, best_score = p, s
    if best is not None and best_score >= SIMILARITY_THRESHOLD:
        return best, best_score
    return None, best_score


def may_apply(pattern: dict, decision: dict, tier: int | None) -> tuple[bool, str]:
    """Tier-policy guard. Returns (allowed, reason)."""
    if tier == 0:
        return False, "Tier-0 is never automated from memory"
    if not decision.get("auto_execute"):
        return False, "decision requires human approval; memory cannot override it"
    if LEVEL_RANK[Level(pattern["level"])] > LEVEL_RANK[Level(decision["level"])]:
        return False, "pattern level is stronger than the tier policy allows"
    return True, "approved pattern within tier policy"
