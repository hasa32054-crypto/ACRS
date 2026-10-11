# E9 — a whole 4-hospital incident decision computed on one IBM quantum chip

Rules fixed before the job: `PREREGISTRATION_E9.md` (+ amendments 1–2, both before any hardware data). Design (angles)
committed before the job: `e9_design.json`. Run by the project owner on 2026-10-11. Raw counts:
`backend/qacrs/results/v3/ibm/e9_run.json` and `e9_run_rep.json`.

## The problem
- Network `cluster4`: 4 hospitals × 60 machines = **240 machines**, joined by inter-site links.
- Incident: **80 compromised machines** (seed 9090, never used before).
- Decision: 146 variables → **132** after the penalty-tight reduction (exact MILP: same optimum, 165.8).
- 57 variables are independent single choices (decided classically by the sign of their coefficient — stated plainly).
- The other **75 variables form 11 coupled sub-problems (2–16 qubits) that were all run at the same time, in one circuit,
  in one job** on `ibm_kingston` (156-qubit Heron r2): depth ≈ 233, ≈ 524 two-qubit gates, 10,000 shots, dynamical
  decoupling + twirling.

## Results (job `db5u2d2mb58s738b1020`; repeat job `db5u2u2mb58s738b10n0` on the same QPU)

| Sub-problem | Real chance of the optimum per shot (run / repeat) | Ideal | Random | × random (run) | QPU found the optimum |
|---|---|---|---|---|---|
| 16 qubits | 0.03% / 0.06% | 0.31% | 0.0015% | 20× | ✅ / ✅ |
| 10 qubits | 2.27% / 2.42% | 5.03% | 0.098% | 23× | ✅ / ✅ |
| 10 qubits | 2.10% / 2.33% | 5.03% | 0.098% | 22× | ✅ / ✅ |
| 10 qubits | 1.38% / 1.08% | 5.00% | 0.098% | 14× | ✅ / ✅ |
| 6 qubits | 20.8% / 20.6% | 42.7% | 1.56% | 13× | ✅ / ✅ |
| 5 qubits | 28.5% / 20.8% | 43.3% | 3.13% | 9× | ✅ / ✅ |
| 4 qubits (×4) | 21.6–52.1% / 19.0–41.8% | 31–83% | 6.25% | 3–8× | ✅ / ✅ |
| 2 qubits | 76.6% / 83.8% | 100% | 25% | 3× | ✅ / ✅ |

- **H-E9a** (every sub-problem beats random, Holm-corrected): ✅ supported in both runs (largest p = 5 × 10⁻⁴ for the
  16-qubit part in the first run, 1.5 × 10⁻⁸ in the repeat).
- **H-E9b** (QPU best sample optimal on ≥ 75% of sub-problems): ✅ **11/11 in both runs** (all 75 qubits).
- **The assembled decision equals the exact optimum** (165.8 = MILP 165.8) in both runs; the v9 optimality certificate
  verified it; **0 unsafe**.
- Safety gate: **ESCALATED** — correctly. The optimal plan contains two decisions that HASSAN never takes alone: isolating
  the compromised EHR database of site 0 (G1, two-person approval) and a twin dilemma on the HL7 engines of site 1 (G3).
  Everything else is contained automatically.
- A single shot that is optimal on *all* 11 parts at once: 0% (expected: product of the per-part rates ≈ 10⁻¹⁰). The
  decision is assembled per part, which is why the parts are independent by construction.

## Replication on a second quantum computer (`ibm_fez`, job `db5u7084qg6s73c40er0`)
Same design, same circuit, different machine (depth 259, 544 two-qubit gates): the QPU again found the **optimum of 11/11
sub-problems**; the assembled decision **equals the exact optimum**; certificate verified; 0 unsafe. Every sub-problem beat
random after Holm correction (largest p = 0.011, the 16-qubit part). The per-shot rates were lower than on `ibm_kingston`
(e.g. 10 qubits: 0.35–0.94% vs 1.1–2.4%; 16 qubits: 0.02%), consistent with a noisier device at this depth, but enough
for 10,000 shots to contain every optimum. Raw counts: `e9_run_fez.json`.

## What we claim and what we do not
- Claim: to our knowledge (search on 2026-10-11), the largest safety-gated cyber-containment decision computed on real
  quantum hardware: a 240-machine, 80-compromise incident, with the quantum part (75 qubits, 11 parts) finding the exact
  optimum of every part, verified by an exact solver and an independent certificate. The closest published security work
  we found (Cogburn, DeCusatis, Spillane 2026, arXiv:2606.09469) ran 110-qubit QAOA for traffic partitioning and reached
  ~70% of the optimum, with no safety gating.
- Not claimed: quantum advantage (the exact solver takes milliseconds); that the QPU decided the 57 single choices; that
  one shot gives the whole decision. Three runs in total: two on `ibm_kingston`, one on `ibm_fez`.
- Key enabler found here: the **penalty-tight QUBO** — the standard "big" safety penalty hides the real cost differences
  from the quantum circuit; the smallest provably-safe penalty keeps the same optimum and makes QAOA work.

### ملخص عربي
شغّلنا قرار حادث كامل — 80 جهازًا مخترقًا في شبكة 4 مستشفيات (240 جهازًا) — على شريحة IBM واحدة في مهمة واحدة:
75 كيوبت في 11 مسألة مستقلة. الحاسوب الكمّي وجد **القرار الأمثل في 11 من 11** مسألة، في ثلاثة تشغيلات على جهازين مختلفين (ibm_kingston وibm_fez)، وكل مسألة أفضل من
العشوائي بفارق إحصائي (حتى 23 ضعفًا). القرار المجمّع **طابق الحل الدقيق تمامًا**، وتحققت منه الشهادة المستقلة، وصفر قرارات
غير آمنة، وبوابة السلامة أحالت قرارين حرجين فقط للبشر. لا ندّعي تفوقًا كمّيًا.
