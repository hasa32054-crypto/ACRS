# Q-ACRS — Pre-registration v6 (out-of-distribution attack chains, decision latency)

**Written:** 2026-10-11, before any v6 code or result; committed alone.
**Frozen:** everything in `backend/qacrs/independent/LOCK_v5.json` (QUBO, safety layer, v3 + v5 gates, methods).
**Nothing in the model changes in v6.** v6 only tests.

## E11 — Out-of-distribution scenarios: attack chains that follow the network

Every scenario so far (except 10 hand-made ones) came from one generator that picks hacked machines uniformly at
random. Real intrusions instead **enter** through an exposed machine and **move along network links**. v6 tests the
frozen system on scenarios from a different generator, specified here before it is written:

- Entry points: the website twins and the staff PCs of each department (exposed to the internet or to phishing).
- 1 intrusion chain with probability 0.7, 2 independent chains with probability 0.3.
- Each chain starts at a uniformly chosen entry point; while the chain has fewer than 4 machines, with
  probability 0.6 it moves to a uniformly chosen machine reachable by one outgoing link (if none, it stops).
- Risk (1–10 scale): each machine on a chain gets an integer uniform in 3–9; the database and domain controller,
  if reached, get an integer uniform in 6–9 (crown-jewel targets). If two chains hit the same machine, the higher
  risk is kept.
- Seed 7007 (never used), 200 scenarios per network (net12, net22). Drop a scenario if its hacked set equals any
  development, 9001, 9002 or earlier 7007 scenario; the number dropped is reported.
- Methods and gates: the same four methods; Q-ACRS with the **v5 gate** (primary) and the v3 gate (reported).

Hypotheses on this set (same tests as v4/v5, α = 0.05):
- **H2-v5-OOD:** Q-ACRS + v5 gate silent failures, Wilson 95% upper bound ≤ 2%.
- **H1-v3:** containment ≥ 80% of safe full isolation AND fewer services down.
- **H3:** fewer services down per scenario than safe full isolation (one-sided Wilcoxon).
- **H4:** containment difference (exact McNemar), reported with direction.
- Escalation rate (human workload) with Wilson CI, reported without threshold.
If H2-v5-OOD fails, the failures are published and analysed; no rule is added and re-tested on this set.

## E12 — Decision latency

Time from "scenario received" to "policy ready" for Q-ACRS: build the reduced QUBO + exact solve + safety layer +
v5 gate + executor plan (dry run, no firewall). Measured with a monotonic clock, 3 repetitions per scenario (median
kept), on: development (40), 9001, 9002, the E11 set, and the 52-machine networks of the scaling study (15).
Reported: median, 95th percentile and maximum per set, plus the hardware this ran on.
**Target (fixed now):** 95th percentile < 1 s and maximum < 7 s (ACRS's restrictive-containment timer for its most
critical tier is 7 s). Missing the target is reported as-is.

### ملخص عربي

v6 لا يغيّر شيئًا في النموذج. (E11) مولّد جديد مختلف تمامًا: الهجوم يدخل من جهاز مكشوف ثم يتنقل عبر روابط الشبكة
(سلسلة هجوم)، 400 سيناريو ببذرة جديدة 7007 — اختبار «خارج التوزيع». (E12) قياس زمن القرار من استلام الحادثة حتى جاهزية
السياسة، والهدف المثبت مسبقًا: 95% من القرارات أقل من ثانية، وأبطأ قرار أقل من 7 ثوانٍ.
