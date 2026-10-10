# Q-ACRS — Pre-registration v4 (generalisation, statistics, real-kernel validation)

**Written:** 2026-10-10, before any v4 code or result; committed alone.
**Frozen:** everything locked in `backend/qacrs/independent/LOCK.json` (network, QUBO, safety layer, escalation
gate, methods). **No weight, threshold or rule is changed in v4.** If any of them changes, that is v5.

Why v4: the v3 escalation gate was designed after seeing the 40 development scenarios. v4 asks whether the
whole system (QUBO + safety layer + gate) still behaves on scenarios it was never designed on, with proper
statistics, and whether its decisions do what the model says when enforced by a real Linux firewall.

---

## E8 — Held-out scenarios (out-of-sample, same generator)

- 250 scenarios per network (net12, net22) from `random_scenarios(net, 250, seed=9001)`. Seed 9001 has never
  been used in this project.
- Exclusion rule (fixed now): drop a held-out scenario if its hacked set (machines and risks) is identical to
  any development scenario, or to an earlier held-out scenario. The number dropped is reported.
- Honest scope: same random generator as the 30 random development scenarios → this tests **out-of-sample**
  generalisation, not out-of-distribution. Human-written scenarios (E5, blind) remain the stronger test.
- Methods: the same four (full isolation, safe full isolation, per-machine rule, Q-ACRS), all with the v3 gate.

## E9 — Statistics (confirmatory on the held-out set; development set reported as secondary)

All tests two-sided unless stated, α = 0.05, no correction beyond what is listed (four primary tests).

| ID | Hypothesis | Test | Supported if |
|---|---|---|---|
| H1-v3 | Q-ACRS contains ≥ 80% as many as safe full isolation AND takes down fewer services | counts | both parts hold |
| H2 | the gate generalises: Q-ACRS silent failures are rare | Wilson 95% CI of the silent-failure rate | upper bound ≤ 2% |
| H3 | Q-ACRS takes down fewer services per scenario than safe full isolation | Wilcoxon signed-rank, one-sided (paired) | p < 0.05 |
| H4 | containment differs between Q-ACRS and safe full isolation | exact McNemar (binomial on discordant pairs) | reported either way, with direction |

Also reported: Wilson 95% CIs for every rate; bootstrap 95% CI (10,000 resamples, seed 0) for the difference in
containment rate and in mean services down; per-network breakdown.

## E10 — Real-kernel validation of the model (Linux iptables, isolated sandbox)

Purpose: check that what the **model predicts** for a decision is what a **real firewall** produces.

- Environment: this project's own Linux container (root, own network stack), loopback addresses only
  (`127.0.0.0/8`). Every machine of net12/net22 gets an address and a real TCP listener; an "attacker C2" and a
  "client" get their own addresses. All rules live in a dedicated iptables chain `QACRS_SANDBOX`, flushed after
  every scenario. No external network, no real hospital, no production firewall.
- Enforcement: ISOLATE m → drop all packets from/to m; RESTRICT h → drop h → C2 only (the attacker's channel).
  Decisions waiting for two-person approval are **not** applied (as in production). Applied through
  `PolicyExecutor` with a new sandbox adapter that refuses any non-loopback address.
- Measured with real TCP connections (3 attempts, 50 ms timeout each, success = any attempt connects):
  1. every hacked machine → C2 (expected: blocked),
  2. every service: client → some non-isolated replica, and that replica → each dependency (expected: model's
     `services_down`),
  3. every network link from a hacked, non-isolated machine to a critical server (expected: open iff the model
     says the C1 path is open),
  4. every healthy machine stays reachable from the client (expected: reachable unless isolated).
- Scenarios: all 40 development + the first 50 held-out per network (100), for Q-ACRS and safe full isolation.
- **H5:** model prediction and measurement agree on 100% of checks. Every disagreement is listed and explained;
  none is hidden or "fixed" after the fact.
- Also timed: from `execute()` call to the first failed C2 connection attempt (monotonic clock).

Honest scope: one Linux kernel and loopback addresses, not a hospital network; this validates the decision →
firewall → traffic mapping, not detection.

---

### ملخص عربي

v4 لا يغيّر شيئًا في النموذج؛ يختبره. (E8) 500 سيناريو جديد لم يُصمَّم عليها شيء (بذرة 9001)، مع استبعاد المكرر.
(E9) اختبارات إحصائية مثبتة مسبقًا: McNemar وWilcoxon وفترات ثقة. (E10) تنفيذ قرارات Q-ACRS بجدار حماية Linux
حقيقي على اتصالات TCP حقيقية داخل بيئة معزولة، ومقارنة ما يتوقعه النموذج بما يحدث فعلًا.
