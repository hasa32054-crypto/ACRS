# E8 — IBM hardware run with corrected angle tuning: 82.7% on a 5-qubit hospital decision

Rules fixed before the job: `PREREGISTRATION_E8.md` (+ amendment 1, primary p = 2, decided before any hardware data).
E7 stays published unchanged (`RESULTS_IBM_E7.md`). Run by the project owner on his IBM account on 2026-10-11; raw counts in
`backend/qacrs/results/v3/ibm/e8_run.json`.

| Item | p = 2 (**primary**) | p = 3 |
|---|---|---|
| Quantum computer | `ibm_fez` (156 qubits), job `db5srdclf4us73c4gkc0`, one job, 4,000 shots per circuit | same job |
| Circuit on the chip | depth 16, 4 two-qubit gates | depth 20, 6 two-qubit gates |
| Error suppression | dynamical decoupling (XpXm) + gate and measurement twirling; no post-processing | same |
| Chance one shot is optimal — **real** | **82.7%** (Wilson 95%: 81.5–83.9%) | 67.9% (66.4–69.3%) |
| — ideal simulator | 88.2% | 74.1% |
| — random | 3.1% | 3.1% |
| Real / ideal | **93.8%** | 91.6% |
| Real / random | **26.5×** | 21.7× |
| Best of 100 real shots optimal | ✅ | ✅ |
| Most frequent real decision | the optimal one → safety gate: ESCALATED (database needs two-person approval) | same |

## Hypotheses
- **H-E8a** (p = 2 real > E7 real 11.9%): z = 63.4, one-sided p < 10⁻³⁰⁰ — ✅ supported.
- **H-E8b** (p = 2 real > random 3.1%): exact binomial p < 10⁻³⁰⁰ — ✅ supported.

## What changed from E7 (11.9%) to E8 (82.7%)
1. **Root cause fixed:** the angle γ was searched in [0, π] while the cost gap between the best decision and the next
   (8 vs 9) is ~1/89 of the scale; widening the range lets QAOA separate them (ideal 13.5% → 88.2%). Same circuit size.
2. **Error suppression** on the chip (dynamical decoupling, twirling): the hardware kept 93.8% of the ideal rate (E7: 88.6%).
   These two effects are not separated by this experiment (both changed at once); the first is by far the larger.

## Honest notes
- p = 3 tuned to 74.1% ideal on the owner's machine vs 67.9% when the amendment was written here (different Python/SciPy
  builds give a different COBYLA path). The primary (p = 2) was not affected.
- The console prints "p=2" in both result headers (a label bug in the shared report function); the saved JSON has the
  correct `p` for each circuit.
- Even the optimal decision is escalated here: in this v3 problem the database is a critical server whose isolation needs
  two people. (v7 would instead SEGMENT it automatically.) The gate is the final word, not the quantum answer.
- No quantum advantage is claimed: the exact classical solver finds the optimum instantly. The point is that the decision
  can run on real quantum hardware, close to its ideal, with a classical safety gate on top.

### ملخص عربي
بعد إصلاح سبب الضعف (مدى البحث عن الزوايا) وتشغيل تقنيات IBM لتقليل الضوضاء، صار احتمال أن تعطي القراءة الواحدة على
الحاسوب الكمّي الحقيقي `ibm_fez` القرار الأمثل **82.7%** بدل 11.9%، أي **26 ضعف التخمين العشوائي**، و**93.8% من أداء
المحاكي المثالي**. النتيجة السابقة (E7) بقيت منشورة كما هي، والقرار الأمثل نفسه مرّ على بوابة السلامة قبل أي تنفيذ.
