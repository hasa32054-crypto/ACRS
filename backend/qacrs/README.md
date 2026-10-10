# Q-ACRS: Quantum-Assisted Adaptive Cyber Response System

**A Hybrid Quantum-Classical Adaptive Cyber Response System for Optimizing Threat Containment and Service Availability**

ACRS picks the *smallest action that stops the attacker* for each machine. Q-ACRS does this for the
**whole network at once**: it treats the choice as a QUBO (Quadratic Unconstrained Binary Optimization). A quantum
algorithm (QAOA) proposes a decision, and a classical safety layer checks it before anything is executed.

> The quantum part proposes. The classical part verifies. Safety rules are never broken.

All numbers below come from runs on the author's own machine and on IBM Quantum hardware.
They are research results at small scale, not a claim of quantum speed-up.

---

## 1. First run on a real quantum computer

The 3-machine decision from Lesson 1 (two web-server twins + one office PC). The QAOA depth is p = 2, with 4000 shots.

| | Chance that one measurement is a best decision |
|---|---|
| Random guessing | 25.0% |
| Ideal simulator | 98.1% |
| **Real IBM QPU: `ibm_marrakesh` (156-qubit Heron r2)** | **96.5%** |

- IBM job id: `db0mcf6egvvc73bghe70` (date: 2026-10-03)
- The circuit on the chip had 16 layers and 2 two-qubit gates. Because it is short, the noise cost only 1.6 points.
- The worst decision isolates both twins, which takes the website down. It appeared in only 0.5% of measurements, and the safety layer rejects it anyway.
- Expected cost on the real QPU was 5.16. The best possible is 5.
- Script: `lesson3_ibm.py`. Result: `results/lesson3_ibm.json`

## 2. Network and scenarios (`network.py`)

- **net12** has 12 machines and 3 services:
  - website twins
  - nurse-app twins
  - a patient-records database
  - a domain controller
  - devices that must **never** be isolated (MRI, lab analyzer)
  - staff PCs
- **net22** has 22 machines (two departments). It is used for the scale study.
- There are **40 attack scenarios**. 10 are written by hand (exfiltration, ransomware, stolen credentials, jump box, ...). 30 are random with a fixed seed (2027), so anyone gets the same set.
- The weights (service value, disruption, risk) are **design assumptions**, not measured data.

## 3. Q-ACRS vs two other methods, on 40 scenarios (`phase3_compare.py`)

| Method | Services taken down | Unsafe decisions | Risk left |
|---|---|---|---|
| Full isolation (isolate every hacked machine) | 23 | 12 | 0 |
| Per-machine rule (each machine decided alone) | 1 | 0 | 269 |
| **Q-ACRS** | **0** | **0** | **155** |

- Q-ACRS optimizes this cost function, so of course it has the lowest cost. The evidence that matters is in the
  columns it does **not** optimize directly: zero services down, zero unsafe decisions, and less risk left than the
  per-machine rule.
- The per-machine rule is a *simplified* rule in the spirit of ACRS. It is not the full ACRS engine.
- **Problem reduction:** on average there are 15.8 machines but only **6.3 qubits** (12 at most). Only the machines that matter become variables.
- Simulated annealing found the exact optimum in 40/40 scenarios. It is the classical baseline for QAOA.

## 4. QAOA on 38 scenarios (noiseless simulation) (`phase4_qaoa_sim.py`)

Machines that must never be isolated are fixed to 0 and removed. 2 scenarios then need no quantum step.

| Qubits | Scenarios | p_best (p=3) | Random |
|---|---|---|---|
| 2 | 1 | 93.7% | 25.0% |
| 4 | 8 | 53.7% | 7.0% |
| 5 | 10 | 29.4% | 3.1% |
| 6 | 2 | 25.9% | 1.6% |
| 7 | 9 | 12.2% | 0.8% |
| 8 | 2 | 15.6% | 0.4% |
| 9 | 1 | 1.9% | 0.2% |
| 10 | 3 | 2.3% | 0.1% |
| 11 | 1 | 0.7% | 0.1% |
| 12 | 1 | 2.1% | ~0.02% |

- On average, QAOA gets the best decision 26.9% of the time, against 3.3% for random guessing.
- **Hybrid use:** take 100 measurements, check each one classically, and keep the cheapest safe one. This finds the optimum (with more than 99% chance) in **31/38** scenarios.
- **Limitation found:** from 9 qubits up, shallow QAOA (p ≤ 3) drops to about 2%, and adding depth does not help.

## 5. Making QAOA stronger with CVaR (`phase4b_cvar.py`)

The angles are tuned to improve the best 10% of measurements, not the average. This is run on the 17 hard scenarios (7 qubits or more).

| | Before (mean) | After (CVaR) |
|---|---|---|
| Optimum found within 100 shots | 10/17 | **15/17** |

| Qubits | Mean p_best | CVaR p_best | Gain |
|---|---|---|---|
| 7 | 12.2% | 10.2% | 0.8x |
| 8 | 15.5% | 10.0% | 0.6x |
| 9 | 1.9% | 2.7% | 1.4x |
| 10 | 2.3% | 10.4% | **4.5x** |
| 11 | 0.7% | 5.4% | **7.9x** |
| 12 | 2.1% | 10.2% | **5.0x** |

- **All 38 scenarios: from 31/38 to 36/38.**
- CVaR helps on large problems (10–12 qubits). It does not help on 7–8 qubits.
- The results vary slightly between machines (optimizer sensitivity). The author's PC gave 15/17 and a second machine gave 16/17. The improvement holds on both.

## Honest limits

- The networks are modeled, not a real hospital. The weights are assumptions; a sensitivity analysis is planned.
- QAOA is **not faster** than classical solvers at this size. The contribution is the formulation, the hybrid safety design, and running on real quantum hardware.
- Only the 3-machine decision has run on real hardware so far.

## Run it

```bash
source ~/qenv/bin/activate
cd ~/ACRS/backend
python -m qacrs.lesson1_qubo        # QUBO by hand, 3 machines
python -m qacrs.lesson2_qaoa        # QAOA on a simulator
python -m qacrs.lesson3_ibm --job db0mcf6egvvc73bghe70   # re-grade the real IBM run (no new QPU time)
python -m qacrs.network             # networks + 40 scenarios
python -m qacrs.phase3_compare      # 3-way comparison
python -m qacrs.phase4_qaoa_sim     # QAOA on 38 scenarios (~4 min)
python -m qacrs.phase4b_cvar        # CVaR vs mean (~3.5 min)

# v2 verification (numpy only, no Qiskit needed)
python -m qacrs.phase3b_containment # pre-registered containment check -> results/v2/containment.json
python -m qacrs.report_v2           # rebuilds docs/qacrs/VERIFICATION_v2.md from the result files
python -m unittest tests.test_qacrs -v   # 27 tests: QUBO, penalty, reduction, safety layer, result files
```

> v2 status: see [`docs/qacrs/VERIFICATION_v2.md`](../../docs/qacrs/VERIFICATION_v2.md) and the criteria
> fixed in advance in [`docs/qacrs/PREREGISTRATION.md`](../../docs/qacrs/PREREGISTRATION.md).

### v3 (criteria fixed in advance: [`docs/qacrs/PREREGISTRATION_v3.md`](../../docs/qacrs/PREREGISTRATION_v3.md))

```bash
cd backend
python -m qacrs.phase5_escalation          # E1 escalation gate          -> results/v3/escalation.json
python -m qacrs.phase5_sensitivity         # E2 weights ±50% + λ curve    -> results/v3/sensitivity.json/.csv
python -m qacrs.phase5_scaling             # E3 12-52 machines            -> results/v3/scaling.json/.csv
python -m qacrs.phase4c_seeds 0 1 2 3 4    # E4 QAOA/CVaR, 5 seeds (~25 min per seed)
python -m qacrs.phase4c_seeds --aggregate  #    -> results/v3/qaoa_seeds_summary.json
python -m qacrs.figures_v3                 # docs/qacrs/figures/*.png from the result files
python -m qacrs.report_v3                  # docs/qacrs/RESULTS_v3.md from the result files
python -m unittest tests.test_qacrs tests.test_qacrs_v3 -v

# E5 blind scenarios (someone else writes them; code is locked in qacrs/independent/LOCK.json)
python -m qacrs.independent_test --validate their_file.json
python -m qacrs.independent_test their_file.json        # runs once, keeps every result

# E7 IBM hardware (your machine, saved IBM account; never put a key in the repo)
python -m qacrs.lesson4_ibm_scaled --check     # no job
python -m qacrs.lesson4_ibm_scaled --dry-run   # no job
python -m qacrs.lesson4_ibm_scaled --run       # one job, asks for 'yes'
```

`qacrs/policy_executor.py` (E6) is a **mock** firewall adapter: no real network or firewall is ever touched.

**Use of AI tools (disclosure):** Claude (Anthropic) was used to write and review parts of the v2/v3 code and tests,
re-run experiments, search for and check sources, and generate figures and reports from the result files.

## References used so far

- Farhi, Goldstone, Gutmann (2014). *A Quantum Approximate Optimization Algorithm*. arXiv:1411.4028
- Lucas (2014). *Ising formulations of many NP problems*. Frontiers in Physics 2:5
- Glover, Kochenberger, Du (2019). *Quantum Bridge Analytics I: a tutorial on formulating and using QUBO models*. 4OR 17
- Shameli-Sendi et al. (2016). Classical multi-objective response selection. IEEE TDSC
- *(To verify before citing: Barkoutsos et al. 2020, CVaR for variational quantum optimization.)*
