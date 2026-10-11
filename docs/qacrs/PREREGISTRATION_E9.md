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

## Amendment 1 (2026-10-11, before any E9 job; simulator only)
The first design (mean-cost objective) gave ideal chances of the optimum of 0.05–4% on the 10-qubit parts — one *below*
random. Tuning with the CVaR objective (mean of the best 5% of outcomes; Barkoutsos et al. 2020, Quantum 4:256) raised
them to 3–5% on a simulator test. **Change:** angles and depth are chosen by the lowest CVaR(α = 0.05) instead of the
lowest expected cost (still deployable: the optimum is not used). Everything else unchanged. The mean-cost design is kept
in git history. Decided before any hardware data exist.

## Amendment 2 (2026-10-11, before any E9 job; simulator only)
With CVaR(5%) the large parts improved (16 qubits: 0.02% → 0.3% ideal; 10 qubits: 5%), but on small parts the CVaR is
already at its minimum once the optimum has ≥ 5% probability, so the optimizer stops early (2-qubit part: 6.6%, below
random). **Change:** each part is tuned with both objectives (CVaR 5% and mean cost) for every depth; the candidate with the
lowest CVaR is chosen and **ties are broken by the lowest expected cost**. Still deployable (optimum not used).
Decided before any hardware data exist; earlier designs are in git history.
