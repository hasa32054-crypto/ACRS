"""Stage 1-b: validate the open-source corpus against the D2 tables and freeze it.

    cd backend && python -m qacrs.v12.corpus_check          -> prints a report, writes qacrs/v12/corpus/MANIFEST.json

Rules enforced (D2): when a detection moment lists ATT&CK techniques per host, the host's risk is **recomputed from
`risk_map.TECHNIQUE_RISK`** and the file is rewritten with that number (the table decides, not the converter); service
values must come from `IMPACT_VALUE`; disruption from `ROLE_DISRUPTION`. Structural checks are those of
`phase16_v11.load` (every link / replica / depends_on / hacked host must exist; 1-2 replicas; risks 1-10).
The manifest records every file's sha256 after normalisation, so the corpus is frozen before `phase17_v12.py` runs.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from qacrs import phase16_v11 as P16
from qacrs.v12 import risk_map as RM

CORPUS = Path(__file__).parent / "corpus"
VALUES = set(RM.IMPACT_VALUE.values())
DISR = set(RM.ROLE_DISRUPTION.values()) | {4}        # "core 3-4"


def normalise(p: Path) -> dict:
    d = json.loads(p.read_text(encoding="utf-8"))
    rep = {"file": p.name, "dropped": bool(d.get("dropped")), "risk_recomputed": 0, "risk_changed": [], "warnings": []}
    if d.get("dropped"):
        return rep
    for m in d.get("detection_moments", []):
        tech = m.get("techniques") or {}
        for h, ts in tech.items():
            if h in m.get("hacked", {}):
                r = RM.risk_of(list(ts))
                if r != m["hacked"][h]:
                    rep["risk_changed"].append([m.get("id"), h, m["hacked"][h], r])
                m["hacked"][h] = r; rep["risk_recomputed"] += 1
    for s in d.get("services", []):
        if int(s.get("value", 0)) not in VALUES:
            rep["warnings"].append(f"service '{s['name']}' value {s.get('value')} not in {sorted(VALUES)}")
    for mach in d.get("machines", []):
        if int(mach.get("disruption", 1)) not in DISR:
            rep["warnings"].append(f"machine '{mach['name']}' disruption {mach.get('disruption')} not in {sorted(DISR)}")
    p.write_text(json.dumps(d, indent=1, ensure_ascii=False), encoding="utf-8")
    try:
        P16.load(p)
    except Exception as e:  # noqa: BLE001
        rep["warnings"].append(f"STRUCTURE: {e}")
    return rep


def main() -> None:
    reports = [normalise(p) for p in sorted(CORPUS.glob("*.json"))]
    man = {"files": [], "n_files": len(reports), "n_dropped": sum(r["dropped"] for r in reports),
           "risk_table_hash": RM.table_hash()}
    for r in reports:
        p = CORPUS / r["file"]
        man["files"].append({"file": r["file"], "sha256": hashlib.sha256(p.read_bytes()).hexdigest(),
                             "dropped": r["dropped"], "risk_recomputed": r["risk_recomputed"],
                             "risk_changed": r["risk_changed"], "warnings": r["warnings"]})
    (CORPUS / "MANIFEST.json").write_text(json.dumps(man, indent=1, ensure_ascii=False), encoding="utf-8")
    for f in man["files"]:
        flag = "DROPPED" if f["dropped"] else ("WARN" if f["warnings"] else "ok")
        print(f"{flag:7} {f['file']:48} risks recomputed {f['risk_recomputed']:3} changed {len(f['risk_changed'])}")
        for w in f["warnings"]:
            print("        ", w)
    print(f"{man['n_files']} files, {man['n_dropped']} dropped, table {man['risk_table_hash']}")


if __name__ == "__main__":
    main()
