"""Turn the experiment output into files a judge can open and count by hand.

    python -m research.export_evidence

Reads results/experiment.json (written by `python -m research.experiment`) and writes:
  results/per_incident.csv   one row per incident, both policies side by side
  results/summary.csv        every headline number on the poster, with how it is counted
"""
from __future__ import annotations

import csv
import json
from pathlib import Path

RES = Path(__file__).parent / "results"


def main() -> None:
    exp = json.loads((RES / "experiment.json").read_text())
    base, acrs = exp["per_incident"]["baseline"], exp["per_incident"]["acrs"]
    assert len(base) == len(acrs)

    cols = ["n", "scenario", "category", "host", "tier", "benign", "risk", "confidence", "sensors",
            "uniform_action", "uniform_auto", "uniform_offline", "uniform_critical_outage", "uniform_attacker_cut",
            "acrs_action", "acrs_auto", "acrs_offline", "acrs_critical_outage", "acrs_attacker_cut", "acrs_reason"]
    with open(RES / "per_incident.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(cols)
        for i, (b, a) in enumerate(zip(base, acrs), 1):
            assert (b["scenario"], b["host"]) == (a["scenario"], a["host"])
            w.writerow([i, a["scenario"], a["category"], a["host"], a["tier"], a["benign"], a["risk"],
                        a["confidence"], a["sources"],
                        b["level"], b["auto"], b["offline"], b["critical_outage"], b["c2_cut"],
                        a["level"], a["auto"], a["offline"], a["critical_outage"], a["c2_cut"],
                        " | ".join(a.get("reasons") or [])])

    B, A = exp["baseline"], exp["acrs"]
    rows = [
        ("Machines taken offline", "hosts_offline", "count rows where *_offline is True"),
        ("Critical-service outages", "critical_outages", "count rows where *_critical_outage is True"),
        ("Attacks cut off (of 41 malicious)", "c2_cut_auto", "count malicious rows where *_attacker_cut is True"),
        ("Paths to Tier-0/1 cut", "spread_cut_auto", "from the commands each policy issued"),
        ("Safety devices taken offline", "safety_devices_offline", "medical device rows taken offline"),
        ("Tier-0 isolated with no person", "tier0_irreversible_without_human", "Tier-0 rows isolated automatically"),
        ("Harmless activity cut off", "benign_hosts_offline", "the one benign row taken offline"),
    ]
    with open(RES / "summary.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["metric", "uniform", "acrs", "how it is counted"])
        for label, key, how in rows:
            w.writerow([label, B[key], A[key], how])
    print(f"wrote per_incident.csv ({len(acrs)} rows) and summary.csv ({len(rows)} rows)")


if __name__ == "__main__":
    main()
