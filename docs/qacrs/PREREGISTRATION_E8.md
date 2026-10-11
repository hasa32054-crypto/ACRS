# E8 — second IBM hardware run with corrected angle tuning and error suppression

**Written:** 2026-10-11, after E7 (`RESULTS_IBM_E7.md`) and **before any E8 code or job**; committed alone.
E7 stays published unchanged (real 11.9%, ideal 13.5%, random 3.1%).

## Root cause of the low E7 ideal rate (found on the simulator, no QPU time)
The cost is scaled by the sum of |coefficients| (89 for `net12_h04`), so the optimum (8) and the next decisions (9, 10)
differ by about 1/89 of the scale. Angles γ were searched only in [0, π], too narrow to separate them. On the noiseless
simulator, widening the γ range to [0, 40] (same objective: mean cost, same circuit family) gives ideal p_best
0.549 at p = 2 and 0.744 at p = 3 (was 0.135 at p = 2). This check used the noiseless simulator only.

## Design (fixed here)
- Scenario: `net12_h04` (same 5 qubits as E7) — so E7 and E8 are directly comparable.
- Tuning: mean-cost objective, γ ∈ [0, 40], β ∈ [0, π], 30 COBYLA restarts, seed 0; p = 2 and p = 3.
- Error suppression on the QPU: dynamical decoupling and Pauli twirling of gates and measurements (IBM runtime options).
  No post-processing of counts.
- ONE job with two circuits (p = 2 and p = 3), 4,000 shots each, on the least busy QPU (or the one named by the owner).
- Self-check before any job: the Qiskit circuit must equal the numpy simulator (max probability difference < 1e-9).
- **Primary:** p = 3. Both circuits are reported whatever the result; no re-runs to pick a better number.
  If a job fails on the hardware, that is reported and a second job may be sent once.

## Hypotheses (α = 0.05)
- **H-E8a:** real p_best (p = 3) > E7 real p_best (477/4000), one-sided two-proportion z-test.
- **H-E8b:** real p_best (p = 3) > random (1/32), exact binomial.
- Reported, no threshold: real/ideal ratio for p = 2 and p = 3, expected cost, best-of-100 contains the optimum, safety
  gate verdict on the most frequent decision.

### ملخص عربي
سبب انخفاض نتيجة E7 أن مدى البحث عن الزوايا كان ضيقًا. نثبت هنا قبل كتابة الكود: نفس المسألة، مدى زوايا صحيح، عمق 2 و3
في مهمة واحدة، مع تقنيات تقليل الضوضاء من IBM. ننشر النتيجتين أيًا كانتا، ولا نعيد التشغيل لاختيار رقم أفضل.
