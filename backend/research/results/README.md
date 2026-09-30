# Results — what each file proves

| File | Made by | What a judge can check |
|---|---|---|
| `experiment.json` | `python -m research.experiment` | Every number in the Results panel. Re-running gives identical values. |
| `per_incident.csv` | `python -m research.export_evidence` | All 42 incidents, both policies side by side. Count `uniform_offline` = True (37) and `acrs_offline` = True (20) by hand. |
| `summary.csv` | `python -m research.export_evidence` | The poster's headline numbers and how each is counted. |
| `e2e_repeats.json` | `python -m research.e2e_repeat 5` | Time to contain across 5 runs: 0.29–0.34 s for both policies, 0 missed deadlines out of 365. |
| `e2e_timing.json` | `python -m research.e2e_timing` | One full timed run with the real orchestrator. |

All data is simulated. Rules version: sha256(app/engines/decision.py) starts with `87893ca0`.
