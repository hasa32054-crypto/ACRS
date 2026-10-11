# E9 — a whole 4-hospital incident decision on one IBM quantum chip

**Written:** 2026-10-11, after E8 and **before any E9 code or job**; committed alone. E7 and E8 stay unchanged.

## Why (found on the simulator, no QPU time)
1. Scaling E8 to a 240-machine network fails for a precise reason: the v7 safety penalty (≈ 2×10⁵) is ~50,000× the
   real cost gaps (≈ 4), so QAOA cannot resolve them (ideal chance of the optimum ≈ 0.2% on a 10-qubit part).
2. **Penalty-tight QUBO (the fix):** (a) machines that may never be isolated are fixed to 0 and removed; (b) each
   "isolate AND segment the same server" penalty is set to 1 + Σ|coefficients touching the segment variable| instead
   of 2·big. Proof: if both are 1, switching the segment variable off lowers the cost by more than any term it touches
   can raise it, so no optimum has both — the optimal decisions are unchanged. Checked by an exact MILP solver.
3. The decision splits into **independent sub-problems** (no coupling between them). Each one is a small QAOA circuit;
   all of them are placed side by side on one chip and run in **one job**.

## Design (fixed here)
- Network `cluster4`: 4 copies of Hospital-60 (240 machines) joined by inter-site VPN / HL7 / admin links.
- Incident: 80 compromised machines, risks 3–9, `random.Random(9090)` (never used before).
- QUBO: v7 → penalty-tight. Variables decided alone (no coupling) are set by the sign of their coefficient (classical,
  reported as such). Every coupled component goes on the QPU.
- Angles: per component, standard QAOA, depth p ∈ {1, 2, 3} chosen by the **lowest expected cost** on the noiseless
  simulator (deployable criterion; the optimum is not used to choose). γ ∈ [0, 40], β ∈ [0, π]. Components above
  16 qubits: p = 1 on a grid. Angles are computed once here and committed (`e9_design.json`) before the job.
- Hardware: one job, all components in one circuit, 10,000 shots, dynamical decoupling + twirling, least busy QPU.
  Optional: the same job once on a second QPU for replication. Both are reported.
- Decision: for each component the lowest-cost measured sample; assembled with the classical singletons; checked by
  the v7 safety rules, the v9 optimality certificate and an exact MILP. Components where the QPU did not find the
  optimum are solved classically and **counted as QPU misses**.

## Hypotheses and reported quantities (α = 0.05)
- **H-E9a:** for every coupled component, real chance of the optimum per shot > random (1 optimum count / 2ⁿ),
  exact binomial, Holm-corrected across components.
- **H-E9b:** the QPU's best sample is optimal on ≥ 75% of coupled components.
- Reported: per-component real vs ideal vs random, best-of-shots, the share of variables decided by the QPU, whether the
  assembled decision equals the MILP optimum, safety-gate status, certificate verdict, and the chance that a single
  shot is optimal on *all* components at once.
- Not claimed: quantum advantage (MILP solves this instantly), or that the QPU decided the singletons.

### ملخص عربي
نثبت قبل كتابة الكود: قرار حادث لـ 80 جهازًا مخترقًا في شبكة 4 مستشفيات (240 جهازًا) يُقسَّم إلى مسائل مستقلة تعمل
كلها في مهمة واحدة على شريحة IBM. نستخدم «أصغر عقوبة آمنة» المثبتة رياضيًا. ما يفشل فيه الكمّي يُحل كلاسيكيًا ويُحسب
فشلًا للكمّي وينشر.
