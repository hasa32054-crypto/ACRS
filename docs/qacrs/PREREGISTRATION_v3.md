# Q-ACRS — Pre-registration v3

**Written:** 2026-10-10, before any v3 code or result. Committed alone so its git timestamp precedes them.
**Builds on:** `PREREGISTRATION.md` (v2) and the v2 results in `VERIFICATION_v2.md`.

**Frozen inputs (no change in v3):** `network.py` sha256 `71c872b912d4`, `qubo_builder.py` sha256
`aa5cc3110408`, `SPREAD = 0.5`, all service values, disruptions and scenario risks, scenario seed 2027.
**No QUBO weight is changed in v3.** Every v3 change is a rule applied *after* the solver.

---

## E1 — Escalation gate (fix for the weakness found in v2)

v2 found that Q-ACRS left 4 hacked critical servers (risk ≥ 7) only restricted, and that 4 more scenarios had an
open path from a never-isolatable device to a critical server. In v2 these were **silent** failures.

v3 adds a gate after the solver (and after the S1–S3 safety checks). It never changes what is isolated
automatically; it only stops a silent failure:

- **G1** — a hacked critical server with `r ≥ 7` that the decision leaves restricted → `ESCALATED`, with the
  recommended action "isolate `<server>` after two-person approval".
- **G2** — a C1 open path whose source is a hacked never-isolatable device → `ESCALATED`, with the
  recommended action "two-person decision: isolate `<critical server>` or accept the documented risk; device owner
  applies compensating controls".

v3 statuses (exactly one): `REJECTED`, `NOT_CONTAINED` (= silent failure), `ESCALATED`,
`CONTAINED_PENDING_APPROVAL`, `CONTAINED`. A decision is `ESCALATED` only if **every** C1/C2 failure is covered
by G1 or G2; any uncovered failure keeps it `NOT_CONTAINED`.

`ESCALATED` is **not** counted as contained. It is counted as "handed to humans with a concrete action".

Metrics: silent failures, automatically contained, escalations (= human workload), services down.
The gate is applied to **every** method, not only Q-ACRS.

**Disclosure:** G1 and G2 were designed after seeing the v2 failures on these same 40 scenarios. Their result
on the 40 development scenarios therefore shows only that the gate does what it was built to do; it is **not**
evidence that it generalises. Evidence of generalisation can only come from E5 (blind scenarios).

## H1 (wording fixed)

v2's H1 sentence and rejection rule disagreed. v3 uses one rule:
**H1-v3:** Q-ACRS contains (CONTAINED + CONTAINED_PENDING_APPROVAL) at least 80% as many scenarios as
`full_isolation_safe`, **and** takes down strictly fewer services. Healthy machines isolated is reported, not
tested. H1-v3 is evaluated on the blind set (primary, when available) and the development set (secondary,
already known from v2, so not a new test).

## E2 — Weight sensitivity and trade-off curve

Purpose: show how decisions depend on the design weights. **No weight will be chosen from these results.**

- One-at-a-time factors applied to the network: `f_service` (all service values), `f_disruption` (all machine
  disruptions), `f_spread` (SPREAD) ∈ {0.5, 0.7, 0.8, 0.9, 1.0, 1.1, 1.2, 1.3, 1.5}
  (= −50%…+50%; ±10/20/30% as requested, ±50% as the original plan in `network.py`).
- Joint availability weight λ (multiplies service values **and** disruptions) ∈
  {0.05, 0.1, 0.2, 0.3, 0.5, 0.7, 1, 1.5, 2, 3, 5, 10} → trade-off (Pareto) curve of containment vs services down,
  with `full_isolation_safe` and `per_machine` as fixed reference points.
- Per configuration, on all 40 scenarios with the exact solver: contained (v2 rules, threshold 7), escalated
  (v3), silent failures, services down, healthy machines isolated, leftover risk, rejected, number of scenarios
  whose decision differs from the baseline (factor 1.0), solve time.
- A factor is called **robust** if, for every level within ±30%, at most 10% of scenarios (≤ 4/40) change
  decision. Otherwise it is **sensitive**, and the level where decisions start to change is reported.
- Solution quality is always optimal here (exact solver), so it is not a sensitivity metric.

## E3 — Scaling study

Networks with 1–5 departments (12, 22, 32, 42, 52 machines), 15 random scenarios each (seed 2027). Per scenario:
machines, decision variables after reduction, never-isolate variables removed, qubits, QUBO linear/quadratic
terms, build time, exact brute-force time (only if qubits ≤ 20), simulated-annealing time and whether SA
matches the exact optimum, and QAOA logical circuit size per layer (`n` RX + `|quad|` ZZ terms; two-qubit
gates before routing = 2·|quad|·p). Hardware depth after routing is **not** estimated here.

## E4 — QAOA / CVaR: fair comparison over seeds

- Seeds 0–4 for the angle optimiser, p = 1, 2, 3, `RESTARTS = 6`, COBYLA, noiseless state vector (unchanged
  v1 code paths `run_qaoa` and `tune`). CVaR α = 0.10 on the hard scenarios (≥ 7 qubits), as in v1.
- **Sampled** budget: 100 real samples drawn from the final distribution (sampling seed fixed per scenario);
  success = the best **safe** sample is optimal.
- Baselines with the same budget of 100 cost evaluations: uniform random (100 samples), simulated annealing
  with 100 steps (1 restart). Reference: full SA (5 × 4000) and exact brute force.
- Report median and min–max over seeds. The classical cost of tuning QAOA angles is **not** inside the 100-sample
  budget; this favours QAOA and is stated with the result.

## E5 — Blind (independent) scenarios

- A person other than the developer writes scenarios in `qacrs/independent/TEMPLATE.json` format without seeing
  any Q-ACRS decision. File records author role (no personal data beyond what they agree to), date, and
  consent to publish. The developer's adult sponsor confirms whether ISEF human-participant review is needed
  **before** collection.
- Runner refuses to run if `network.py` / `qubo_builder.py` / `safety_checks.py` hashes differ from this file
  (or from the v3 code hash recorded at the first blind run).
- All results are published, including failures. No weight or rule changes after seeing them; any change → v4.
- Success criteria are the v2/v3 statuses above and H1-v3.

## E6 — Mock firewall adapter

`PolicyExecutor` → `MockFirewallAdapter` (in-memory, **no network access, no real firewall**) → `PolicyAuditLog`.
Real execution mode does not exist in code; a `dry_run=True` default is enforced. Tested cases: valid policy;
never-isolate device; critical server without two different approvers; same approver twice; unknown device;
adapter failure; retry then success; retry exhausted; same policy twice (idempotent); rollback.

## E7 — IBM hardware (run by the owner, not in this environment)

Pre-specified scenario: `net12_h04` (database exfiltration, 5 qubits after removing never-isolate devices).
Fallback if the budget is insufficient: `net12_h01` (4 qubits). Steps: `--check` (account and backends, no job),
`--dry-run` (transpile, report depth and two-qubit gates, no job), then one job after explicit confirmation.
Same metric definitions as Lesson 3 (`p_best` = chance one shot is optimal, expected cost, random baseline),
raw counts saved. Not run = reported as "not run".

---

### ملخص عربي

v3 لا يغيّر أي وزن. يضيف «بوابة تصعيد» بعد الحل: إذا بقي خادم حرج مخترق مقيدًا، أو بقي مسار مفتوح من جهاز طبي لا
يُعزل إلى خادم حرج، يتحول الفشل الصامت إلى تصعيد لموافقة شخصين مع إجراء محدد. صممنا البوابة بعد رؤية فشل v2،
لذلك نتيجتها على نفس السيناريوهات لا تثبت التعميم، والسيناريوهات العمياء هي الاختبار الحقيقي. وفيه أيضًا: تحليل
حساسية للأوزان بدون اختيار أوزان جديدة، ودراسة توسع، ومقارنة QAOA عادلة بخمس بذور وميزانية 100 عينة، ومحوّل
جدار ناري محاكى، وتجربة IBM محددة مسبقًا على السيناريو `net12_h04`.
