"""Attack memory (idea 14): every attack a visitor builds on the map can be saved, with consent, as a button.
Saved attacks are re-run as regression tests: HASSAN must pass every one of them, every time.

Honest wording: HASSAN does not "learn" by itself. The memory keeps the attack; if one ever breaks a rule, the fix is
made in code and the attack stays as a permanent test, so the same attack cannot pass unnoticed twice.

Stored outside the repo (visitor content): $HASSAN_DATA_DIR or ~/.hassan/booth_data/attack_memory.json.
Only machine names, risks and a display label are stored; no personal data is requested.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from pathlib import Path

from qacrs import qubo_v7 as V7
from qacrs.booth import secure

MAX_ENTRIES = 500


def data_dir() -> Path:
    return Path(os.environ.get("HASSAN_DATA_DIR") or Path.home() / ".hassan" / "booth_data")


def attack_id(hacked: dict, forged: list[str]) -> str:
    return hashlib.sha256(secure.canonical({"hacked": hacked, "forged": sorted(forged)})).hexdigest()[:16]


def invariants(booth, hacked: dict, r: dict) -> list[str]:
    """Rules every decision must keep. Returns the broken ones (empty = pass)."""
    m = booth.machine
    iso, seg = set(r["hassan"]["isolate"]), set(r["hassan"]["segment"])
    broken = []
    if any(not m[x].isolatable for x in iso):
        broken.append("medical device isolated")
    if any(m[x].critical for x in iso):
        broken.append("critical server isolated automatically")
    if iso - set(hacked):
        broken.append("isolated a machine that was not reported")
    if any(not m[x].critical for x in seg):
        broken.append("segmented a non-critical machine")
    if len(r["hassan"]["services_down"]) > len(r["full_isolation"]["services_down"]):
        broken.append("more services down than full isolation")
    if r["status"] not in ("CONTAINED", "ESCALATED", "CONTAINED_PENDING_APPROVAL"):
        broken.append(f"status {r['status']}")
    v = booth.verify(hacked, r["certificate"], r["signature"])
    if not v["accepted"]:
        broken.append("certificate or signature did not verify")
    return broken


class AttackMemory:
    def __init__(self, path: Path | None = None):
        self.path = path or data_dir() / "attack_memory.json"
        self._lock = threading.Lock()

    def load(self) -> list[dict]:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            return data["attacks"] if isinstance(data, dict) and isinstance(data.get("attacks"), list) else []
        except (OSError, ValueError):
            return []

    def _write(self, attacks: list[dict]):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"version": 1, "attacks": attacks}, ensure_ascii=False, indent=1), encoding="utf-8")
        os.replace(tmp, self.path)                                  # atomic: never a half-written memory

    def save(self, booth, name: str, hacked: dict, forged: list[str]) -> dict:
        r = booth.decide(hacked, forged, sid="memory")
        entry = {"id": attack_id(hacked, forged), "name": name, "hacked": hacked, "forged": sorted(forged),
                 "saved_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                 "first": {"status": r["status"], "isolate": r["hassan"]["isolate"], "segment": r["hassan"]["segment"],
                           "services_down": r["hassan"]["services_down"]},
                 "broke_rules_when_saved": invariants(booth, hacked, r)}
        with self._lock:
            attacks = [a for a in self.load() if a.get("id") != entry["id"]]
            if len(attacks) >= MAX_ENTRIES:
                raise secure.Invalid(f"memory full ({MAX_ENTRIES} attacks)")
            attacks.append(entry)
            self._write(attacks)
        return entry

    def delete(self, aid: str) -> bool:
        with self._lock:
            attacks = self.load()
            keep = [a for a in attacks if a.get("id") != aid]
            if len(keep) == len(attacks):
                return False
            self._write(keep)
            return True

    def regress(self, booth) -> dict:
        """Re-run every saved attack. pass = no rule broken. `changed` = decision differs from the first run
        (reported, not a failure: a later engine may legitimately choose differently)."""
        rows = []
        t = time.perf_counter()
        for a in self.load():
            try:
                hacked, forged = secure.attack({"hacked": a["hacked"], "forged": a.get("forged", [])}, booth.names)
            except (secure.Invalid, KeyError, TypeError):
                rows.append({"id": a.get("id"), "name": a.get("name"), "pass": False, "broken": ["entry unreadable"]})
                continue
            r = booth.decide(hacked, forged, sid="regress")
            broken = invariants(booth, hacked, r)
            first = a.get("first", {})
            changed = (first.get("isolate") != r["hassan"]["isolate"] or first.get("segment") != r["hassan"]["segment"])
            rows.append({"id": a["id"], "name": a["name"], "pass": not broken, "broken": broken, "status": r["status"],
                         "changed_since_saved": changed, "services_down": r["hassan"]["services_down"],
                         "full_isolation_services_down": r["full_isolation"]["services_down"]})
        return {"total": len(rows), "passed": sum(r["pass"] for r in rows), "rows": rows,
                "seconds": round(time.perf_counter() - t, 3)}

    def public(self) -> list[dict]:
        return [{k: a.get(k) for k in ("id", "name", "hacked", "forged", "saved_utc", "first", "broke_rules_when_saved")}
                for a in self.load()]
