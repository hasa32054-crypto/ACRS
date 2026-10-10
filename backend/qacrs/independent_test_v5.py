"""Blind scenarios through the v5 gate (run AFTER `python -m qacrs.independent_test FILE`, which uses the v3 gate).

    cd backend && python -m qacrs.independent_test_v5 --write-lock     # once, before any blind scenario exists
    cd backend && python -m qacrs.independent_test_v5 FILE.json        # runs once -> results/v5/independent/

Same validation and run-once rule as independent_test.py; code locked in qacrs/independent/LOCK_v5.json.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from qacrs import escalation as E
from qacrs import independent_test as IT
from qacrs import safety_checks as S
from qacrs.meta import meta, sha
from qacrs.network import build as build_net
from qacrs.phase7_v5 import evaluate

HERE = Path(__file__).parent
LOCK5 = IT.KIT / "LOCK_v5.json"
OUT = HERE / "results" / "v5" / "independent"
FILES = IT.LOCKED_FILES + ("escalation_v5.py", "phase7_v5.py", "independent_test_v5.py")


def check_lock5():
    if not LOCK5.exists():
        return ["LOCK_v5.json missing"]
    lock = json.loads(LOCK5.read_text())["code_sha256_prefix"]
    return [f"{f}: locked {h}, now {sha(HERE / f)}" for f, h in lock.items() if sha(HERE / f) != h]


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("file", nargs="?"); ap.add_argument("--write-lock", action="store_true")
    a = ap.parse_args(argv)
    if a.write_lock:
        if LOCK5.exists():
            sys.exit("REFUSED: LOCK_v5.json already exists")
        LOCK5.write_text(json.dumps(meta("independent_lock_v5") | {"code_sha256_prefix": {f: sha(HERE / f) for f in FILES},
                                     "note": "Written before any blind scenario existed. Do not edit."}, indent=1))
        return print(f"Saved: {LOCK5}")
    if not a.file:
        return ap.print_help()
    drift = check_lock5()
    if drift:
        sys.exit("REFUSED: code changed since LOCK_v5:\n  " + "\n  ".join(drift))
    path = Path(a.file)
    doc, errors = IT.load(path)
    if errors:
        sys.exit("REFUSED: invalid file:\n  " + "\n  ".join(errors))
    out = OUT / f"{path.stem}.json"
    if out.exists():
        sys.exit(f"REFUSED: already run ({out})")
    nets = {n.name: n for n in (build_net(1), build_net(2))}
    pairs, invalid = [], []
    for item in doc["scenarios"]:
        sc, errs = IT.scenario_errors(item)
        (invalid.append({"id": item.get("id") if isinstance(item, dict) else None, "errors": errs}) if errs
         else pairs.append((nets[sc.network], sc)))
    rows = evaluate(pairs)
    q = [r["q_acrs"] for r in rows]
    summary = {"valid": len(rows), "invalid": len(invalid),
               "q_acrs_v5": {s: sum(x["status"] == s for x in q) for s in (S.CONTAINED, S.PENDING, E.ESCALATED, S.NOT_CONTAINED, S.REJECTED)},
               "q_acrs_v3_gate": {s: sum(x["status_v3_gate"] == s for x in q) for s in (S.CONTAINED, S.PENDING, E.ESCALATED, S.NOT_CONTAINED, S.REJECTED)},
               "services_down": {m: sum(len(r[m]["services_down"]) for r in rows) for m in rows[0] if isinstance(rows[0][m], dict) and "status" in rows[0][m]} if rows else {}}
    OUT.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"meta": meta("independent_test_v5", file=path.name, file_sha256=sha(path)),
                               "summary": summary, "invalid": invalid, "rows": rows}, indent=1, ensure_ascii=False))
    print(json.dumps(summary, indent=1)); print(f"Saved: {out}")


if __name__ == "__main__":
    main()
