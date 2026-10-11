# Q-ACRS — Pre-registration v5 (the "twin dilemma" gate, tested on a fresh held-out set)

**Written:** 2026-10-10, after the v4 held-out results and before any v5 code or result; committed alone.

## What v4 found

On 482 held-out scenarios (seed 9001) Q-ACRS had **14 silent failures** (2.9%, Wilson 95% CI 1.7–4.8%), so H2
was **not supported**. All 14 have the same shape: **both twins of a service were hacked**. Q-ACRS isolates one
twin to keep the service up and leaves the other restricted, so a path to the database stays open (13) or a
high-risk twin stays restricted (4 reasons; some scenarios have both). The v3 gate (G1 critical server, G2
never-isolatable device) does not cover this case. This is a real trade-off — closing the gap takes the service
down — so it is a decision for humans, not for the optimiser.

## The v5 change (one rule, after the solver; QUBO weights still untouched)

- **G3 — twin dilemma:** a containment failure (C1 source or C2 machine) on an isolatable, non-critical machine
  `h`, where isolating `h` as well would take down at least one more service → `ESCALATED` with the action
  "two-person decision: isolate `h` (service(s) X go down) or keep X up and accept the documented risk".
- G1, G2 and everything else unchanged. A decision is `ESCALATED` only if **every** failure is covered by
  G1/G2/G3. Implemented in a new module (`escalation_v5.py`) that wraps the v3 gate, so v3/v4 code and results
  stay reproducible and the v4 lock stays valid.

## How it is tested

- **Fresh held-out set:** `random_scenarios(net, 250, seed=9002)` per network, same exclusion rule as v4
  (drop exact duplicates of development, of the 9001 set, and of earlier 9002 scenarios). Seed 9002 has never
  been run. **This is the confirmatory test.** The 9001 set is reported as secondary (G3 was designed on it).
- **H2-v5:** Q-ACRS + v5 gate silent-failure rate on the 9002 set has Wilson 95% upper bound ≤ 2%.
- **Cost of G3 (reported, no threshold):** escalation rate with Wilson CI on 9002, compared with the v3 gate on the
  same scenarios — more escalations means more human work, and that is stated.
- H1-v3, H3, H4 are recomputed on 9002 for completeness (the gate does not change containment or services).
- A new lock `LOCK_v5.json` is written before any blind scenario exists; blind scenarios are then reported with
  both the v3 and v5 gates.
- If H2-v5 fails, the failures are published and analysed; no further rule is added and tested on the same set.

### ملخص عربي

اختبار v4 كشف 14 فشلًا صامتًا كلها من نوع واحد: اختراق التوأمين معًا، فيعزل النموذج واحدًا ليبقي الخدمة ويترك الآخر.
v5 يضيف قاعدة تصعيد واحدة (G3) لهذا «المأزق»، دون تغيير الأوزان، ويُختبر على 500 سيناريو **جديدة تمامًا** (بذرة 9002)
لم نرها. إذا فشل، ننشر الفشل ولا نضيف قاعدة أخرى على نفس البيانات.
