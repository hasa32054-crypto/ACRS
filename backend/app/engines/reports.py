"""Hourly SOC report: KPIs computed from incidents in a time window (pure function)."""
from __future__ import annotations

from collections import Counter
from datetime import datetime

MTTC_TARGET_MS = 60_000


def _pct(n: int, d: int) -> float:
    return round(100.0 * n / d, 1) if d else 0.0


def _percentile(values: list[int], p: float) -> int | None:
    if not values:
        return None
    v = sorted(values)
    k = min(len(v) - 1, max(0, int(round((p / 100) * (len(v) - 1)))))
    return v[k]


def build(incidents: list[dict], start: datetime, end: datetime, total_assets: int) -> dict:
    n = len(incidents)
    mttc = [i["mttc_ms"] for i in incidents if i.get("mttc_ms") is not None]
    mttd = [int((i["detected_at"] - i["started_at"]).total_seconds() * 1000)
            for i in incidents if i.get("started_at") and i.get("detected_at")]
    auto = sum(1 for i in incidents if i.get("auto_executed"))
    fps = sum(1 for i in incidents if i.get("false_positive"))
    esc = sum(1 for i in incidents if i.get("escalation_reason") or i.get("state") == "ESCALATED")
    breaches = sum(1 for i in incidents if i.get("sla_breached"))
    memory_hits = sum(1 for i in incidents if (i.get("memory") or {}).get("applied"))
    contained_assets = {i.get("asset_id") for i in incidents if i.get("contained_at") and i.get("asset_id")}
    kpis = {
        "incidents": n,
        "auto_contained": auto, "auto_rate_pct": _pct(auto, n),
        "mttd_ms_avg": int(sum(mttd) / len(mttd)) if mttd else None,
        "mttc_ms_avg": int(sum(mttc) / len(mttc)) if mttc else None,
        "mttc_ms_p50": _percentile(mttc, 50), "mttc_ms_p95": _percentile(mttc, 95),
        "mttc_within_target_pct": _pct(sum(1 for m in mttc if m <= MTTC_TARGET_MS), len(mttc)),
        "false_positives": fps, "false_positive_rate_pct": _pct(fps, n),
        "escalations": esc, "sla_breaches": breaches, "memory_hits": memory_hits,
        "assets_contained": len(contained_assets), "assets_total": total_assets,
        "business_continuity_pct": _pct(total_assets - len(contained_assets), total_assets),
    }
    recs: list[dict] = []
    if kpis["false_positive_rate_pct"] > 10:
        recs.append({"en": "False-positive rate above 10 %: review the rules listed on rolled-back incidents.",
                     "ar": "معدل الإيجابيات الكاذبة أعلى من 10%: راجع القواعد في الحوادث التي أُلغيت."})
    if esc:
        recs.append({"en": f"{esc} incident(s) reached the Emergency Queue: check controller health and gate failures.",
                     "ar": f"{esc} حادثة وصلت إلى طابور الطوارئ: افحص جاهزية أدوات العزل وأسباب فشل البوابة."})
    if kpis["mttc_ms_p95"] and kpis["mttc_ms_p95"] > MTTC_TARGET_MS:
        recs.append({"en": "p95 time-to-contain is above the 60 s target.",
                     "ar": "زمن الاحتواء (p95) أعلى من هدف 60 ثانية."})
    if not recs:
        recs.append({"en": "All KPIs within target for this hour.", "ar": "كل المؤشرات ضمن الهدف في هذه الساعة."})
    return {
        "window_start": start.isoformat(), "window_end": end.isoformat(), "kpis": kpis,
        "by_state": dict(Counter(i["state"] for i in incidents)),
        "by_tier": {str(k): v for k, v in Counter(i.get("tier") for i in incidents).items()},
        "by_attack_type": dict(Counter(i.get("attack_type") or "unknown" for i in incidents).most_common(8)),
        "by_level": dict(Counter(i.get("level") or "none" for i in incidents)),
        "recommendations": recs,
    }
