"""v8 C: executor hardening that needs no network — hash-chained audit log (17), time-boxed rules (8),
decaying containment simulation (S7).

Rules: docs/qacrs/PREREGISTRATION_v8.md, section C. Design assumptions: default rule lifetime 30 min,
evidence half-life 15 min, isolation kept while decayed risk >= 7, fixed-policy human review after 60 min.
"""
from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass, field

GENESIS = "0" * 64


# ------------------------------------------------------------------ 17. hash-chained audit log -------------------
@dataclass
class ChainLog:
    entries: list[dict] = field(default_factory=list)

    @staticmethod
    def _h(prev: str, body: dict) -> str:
        return hashlib.sha256((prev + json.dumps(body, sort_keys=True, ensure_ascii=False)).encode()).hexdigest()

    def append(self, **body) -> dict:
        prev = self.entries[-1]["hash"] if self.entries else GENESIS
        e = {"seq": len(self.entries), "prev": prev, "body": body, "hash": self._h(prev, body | {"seq": len(self.entries)})}
        self.entries.append(e)
        return e

    @classmethod
    def verify(cls, entries: list[dict]) -> bool:
        prev = GENESIS
        for i, e in enumerate(entries):
            if e.get("seq") != i or e.get("prev") != prev or e.get("hash") != cls._h(prev, e["body"] | {"seq": i}):
                return False
            prev = e["hash"]
        return True


# ------------------------------------------------------------------ 8. time-boxed rules ---------------------------
DEFAULT_TTL_S = 30 * 60


@dataclass
class RuleStore:
    rules: dict[str, dict] = field(default_factory=dict)

    def add(self, rid: str, action: str, target: str, now: float, ttl: float = DEFAULT_TTL_S) -> None:
        self.rules[rid] = {"action": action, "target": target, "expires": now + ttl, "confirmed": False}

    def confirm(self, rid: str, now: float, ttl: float = DEFAULT_TTL_S) -> None:
        if rid in self.rules:
            self.rules[rid] |= {"confirmed": True, "expires": now + ttl}

    def expire(self, now: float) -> list[str]:
        gone = [rid for rid, r in self.rules.items() if now >= r["expires"]]
        for rid in gone:
            del self.rules[rid]
        return gone


# ------------------------------------------------------------------ S7. decaying containment ----------------------
HALF_LIFE_MIN, KEEP_ISOLATION_AT, FIXED_REVIEW_MIN = 15.0, 7, 60.0


def isolation_minutes_decaying(risk: float) -> float:
    """Isolation is relaxed (to restrict) once risk * 0.5^(t/half-life) falls below the keep-threshold."""
    if risk < KEEP_ISOLATION_AT:
        return 0.0
    return HALF_LIFE_MIN * math.log2(risk / KEEP_ISOLATION_AT) + (1e-9)


def decay_simulation(rows: list[dict], method: str = "q_acrs_v7") -> dict:
    """rows: scenario rows with 'hacked' and method['isolate_now']. Returns isolation-minutes fixed vs decaying."""
    fixed = dec = 0.0
    n_iso = 0
    for r in rows:
        for m in r[method]["isolate_now"]:
            risk = r["hacked"].get(m, 0)
            fixed += FIXED_REVIEW_MIN
            dec += max(isolation_minutes_decaying(risk), 0.0)
            n_iso += 1
    return {"isolations": n_iso, "isolation_minutes_fixed": round(fixed, 1), "isolation_minutes_decaying": round(dec, 1),
            "reduction": round(1 - dec / fixed, 4) if fixed else None,
            "assumptions": {"half_life_min": HALF_LIFE_MIN, "keep_isolation_at_risk": KEEP_ISOLATION_AT,
                            "fixed_review_min": FIXED_REVIEW_MIN},
            "note": "model arithmetic under stated assumptions; no re-infection modelled"}
