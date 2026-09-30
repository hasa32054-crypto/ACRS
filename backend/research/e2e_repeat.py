"""Repeat the end-to-end timing run several times, because real timers jitter from run to run.

    python -m research.e2e_repeat            # 5 runs
    python -m research.e2e_repeat 10         # 10 runs

Writes results/e2e_repeats.json with the median decide-to-contain time of every run, per policy,
so the poster can report a range instead of a single lucky number.
"""
from __future__ import annotations

import asyncio
import json
import statistics
import sys

from app.engines.decision import decide as acrs_decide

from research.e2e_timing import OUT, arm, stats
from research.experiment import uniform_decide


async def main(n: int) -> None:
    runs = {"baseline": [], "acrs": []}
    for i in range(n):
        for name, policy in (("baseline", uniform_decide), ("acrs", acrs_decide)):
            s = stats(await arm(policy))
            runs[name].append(s)
            print(f"run {i + 1}/{n}  {name:8}  median {s['median_ms']} ms  "
                  f"within deadline {s['within_deadline']}/{s['contained']}")
    out = {"runs": n, "note": "Median decide-to-contain time per run; simulated controllers, real 7/15/90 s timers."}
    for name, rs in runs.items():
        med = [r["median_ms"] for r in rs]
        out[name] = {"median_of_runs_ms": statistics.median(med), "min_ms": min(med), "max_ms": max(med),
                     "missed_deadline_total": sum(r["contained"] - r["within_deadline"] for r in rs), "per_run": rs}
    OUT.mkdir(exist_ok=True)
    (OUT / "e2e_repeats.json").write_text(json.dumps(out, indent=1, default=str))
    for name in runs:
        o = out[name]
        print(f"{name:8}  median of runs {o['median_of_runs_ms']} ms  range {o['min_ms']}-{o['max_ms']} ms  "
              f"missed deadlines {o['missed_deadline_total']}")


if __name__ == "__main__":
    asyncio.run(main(int(sys.argv[1]) if len(sys.argv) > 1 else 5))
