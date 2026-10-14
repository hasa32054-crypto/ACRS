# ACRS — Pre-registration v11: attack the defender

**Written:** 2026-10-14, **before any v11 result was computed**. Drafted with Claude (Anthropic) at the student's
request; the targets below are proposed for the student's approval and are not changed after the first run. The v9
engine is used **unchanged**: no weight, threshold, rule or solver setting is modified, and the files locked for the
blind test (`LOCK_blind_v9.json`) are not touched. Everything new lives in new files.

## Why

v8–v9 showed that forged alert sets *alone* never made ACRS take a service down. That test had two limits:

1. the forged alerts were drawn from fixed generators (exhaustive 1–3 machines at risk 10, random sets), not chosen
   by an attacker who **knows the engine** and searches for the input that hurts most;
2. it only asked about **weaponization** (forged alerts make the defender cut healthy systems). It did not ask about
   **hiding**: an attacker who already controls a machine lowers or deletes its alert so the engine reports
   "contained" while the real attack still has an open path. Nobody is told.

v11 asks: **how many alert sources must an attacker control to make ACRS do harm, and does fusing several
independent sources raise that number?** It also asks for **machine-checked proofs** of the safety rules, so the
claim "ACRS never isolates a never-isolate device" does not rest on tests alone.

## Threat model (fixed here)

- **Truth `T`:** a genuine attack (true hacked machines and true risks), from the existing chain generator
  `phase8_ood.chain_scenarios` (unchanged).
- **Alert sources:** every machine has **3 independent host alert sources** (for example EDR, antivirus, log/SIEM rule).
  Honest readings: a truly hacked machine reports `true risk + e`, `e` uniform in {−1, 0, +1}, clipped to 1–10; a healthy
  machine reports 0 (no alert), except a false positive with probability 0.02 per source, value uniform 1–5.
- **Network evidence:** the NDR lateral-flow log of guard v2 (`hassan_v9.ndr_lateral_flows`, unchanged settings
  p_spurious 0.02, p_miss 0.05) is generated from the genuine hops. **Assumption:** the attacker cannot forge it.
  This assumption is stated wherever D4 results are quoted.
- **Attacker:** white-box (knows the network, the code, the honest readings and the fusion rule). Controls up to
  **Γ source readings** in total and may set each to any value 0–10 (0 = delete the alert).
- **Attacker goals:**
  - **A1 weaponize:** extra automatic harm compared with the honest readings: services down caused by automatic
    actions, plus healthy machines isolated automatically.
  - **A2 hide (silent miss):** the engine returns `CONTAINED` (no human is asked) while the same automatic actions,
    judged against the truth `T` with the unchanged v7 check (`qubo_v7.check_v7`), are `NOT_CONTAINED`; and this was not
    already the case with the honest readings.
  - **A3 flood (descriptive):** extra human escalations caused (workload), no target.

## Defenders (fusion rule → unchanged v9 engine)

The fused risk of each machine becomes the reported scenario (a machine is reported if its fused risk is ≥ 1).

| ID | Fusion | Engine |
|---|---|---|
| D0 | one source only (the model used in v1–v10) | `EngineV9`, v8 consistency guard |
| D1 | maximum of the 3 sources | same |
| D2 | mean of the 3, rounded half up | same |
| D3 | **median** of the 3 | same |
| D4 | median of the 3 | `EngineV9` with guard v2 (NDR flows) |
| B  | median of the 3 | safe full isolation (`qubo_v7.m_full_isolation_safe`) — baseline for A1 only |

## Experiment E1 — adaptive attacker and certified radius (primary)

**Data (fresh seeds, never used before):** 120 attack chains on `net12` (seed **7501**) and 120 on `net22`
(seed **7502**); honest-reading noise seed **7511**, false positives **7531**, NDR flows **7521** (one random stream per
network: seed + 1 for `net12`, seed + 2 for `net22`, consumed in scenario order). Exact duplicates are dropped and
counted.

**Search:**
- Γ = 1: exhaustive over every source and every value 0–10 (exact).
- Γ = 2: exhaustive over every pair of sources and every value 0–10 on `net12` (exact); on `net22` over the value set
  {0, 1, 6, 7, 10} (exact within that set, labelled as such).
- Γ = 3: beam search (width 20, built from the best Γ = 2 attacks) — a **lower bound** on what an attacker can do,
  never used for a certificate.

**Certified radius** of a scenario for goal A1 or A2 under a defender: the smallest Γ at which the exact search finds
an attack that succeeds; reported as "≥ 3" if none is found at Γ ≤ 2.

**Targets (on the 240 chains together):**

| ID | Target |
|---|---|
| H1 | A2 (hide) at Γ = 1: success rate of D3 is **lower than D0** (exact McNemar, p < 0.05) and **≤ 5%** |
| H2 | A1 (weaponize) at Γ ≤ 2: D4 causes **0** extra services down in every scenario |
| H3 | Certified radius for A2 under D4 is **≥ 2** in at least **80%** of scenarios |

Also reported, no target: per-defender success rates for A1, A2, A3 at Γ = 1, 2, 3; the damage-vs-Γ curve; the radius
distribution; D0–D4 decisions with honest readings only (Γ = 0), so the cost of fusion with no attacker is visible; and
every scenario where an attack succeeds against D4, with the attack written out.

**Known in advance and reported, not hidden:** with honest noise ±1, a machine whose true risk is 7 can have honest
readings on both sides of the threshold, so a single forged source can still move a median across it. H1 allows for
this (≤ 5%, not 0).

## Experiment E2 — formal proofs of the safety rules (Z3)

The automatic decision path **after the solver** is written as a logical model for each network (`net12`, `net22`, the
three v10 sector networks). The solver is treated as **untrusted** (a noisy QAOA bit-string, a buggy annealer): its
output can be anything. Two automatic paths are modelled separately, because both exist in the code:

- **Path X (firewall executor):** `hassan.Engine.decide` → `policy_executor.PolicyExecutor.execute` with no approvals.
- **Path S (ACRS service adapter):** `hassan.Engine.decide` → `hassan_service.to_acrs` (actions marked `auto: True`).

Symbolic inputs: **any** reported scenario (any non-empty subset of machines; risks only matter to the rate limiter,
which is modelled as keeping **any** subset of the proposed isolations), **any** solver output (any isolate/segment
sets), any guard result (flag or no flag). The Z3 SMT solver must show that no input violates:

| ID | Property |
|---|---|
| P1 | a machine that must never be isolated is never isolated automatically |
| P2 | a critical server is never isolated automatically (it always waits for two people) |
| P3 | every automatic isolation is a machine that was reported hacked |
| P4 | only critical servers are ever segmented |
| P5 | if the guard raises a flag, nothing is isolated automatically |
| P6 | with 3 sources and at most 1 forged, the median lies between the two honest readings |

P1–P5 are checked on both paths; P6 is a property of the fusion rule alone.

**Pass rule:** each property is "proved" only if Z3 returns `unsat` for its negation. **Second, independent prover:**
the same properties are also encoded as 0/1 integer programs and solved exactly with HiGHS (scipy `milp`); a property
holds only if the maximum number of violations is 0. This one runs without Z3. **Model fidelity:** the model is checked
against the real Python code (engine + executor + adapter, with an injected solver that returns the random output)
on 100,000 random inputs per network (seed **7541**); any mismatch fails E2. **Mutation check:** three planted bugs
(gate skips the never-isolate check; guard ignored; segment allowed on a non-critical machine), each in a copy of the
model only, must each produce a concrete counterexample.

**Disclosed before any run (from reading the code and one manual probe with a hand-made wrong solver output, no data
set involved):** the engine itself does not filter what the solver proposes; it labels it. On **Path X** the executor
rejects a never-isolate device and blocks a critical server until two people approve, but it **would isolate a
healthy machine that was never reported** (P3). On **Path S**, `to_acrs` marks every proposed isolation `auto: True`
whatever the engine status, so a wrong solver output can reach ACRS as an automatic isolation of a never-isolate
device or a critical server (P1, P2), even though the engine status says `REJECTED` / approval needed and the
certificate check fails. With the engine's own classical solver this has not happened in any earlier run (the QUBO
penalty keeps the optimum away from it), but the project's claim is that safety must **not** depend on the solver.

**Plan if a property fails (fixed now):** the counterexample is published as found. A single enforcement layer is
added in a new file, `qacrs/gate_v11.py`, that turns any engine decision into the automatic action set: nothing
automatic if the status is `REJECTED` or the certificate does not verify; never-isolate devices dropped; critical
servers and machines that were not reported moved to "held for humans"; segments only on critical servers.
`hassan_service.to_acrs` (not a locked file) is switched to use it; the locked engine files stay unchanged. The fixed
paths are then proved again with both provers. Both the failing and the fixed results are published.

**Limit stated with the result:** Z3 proves properties of the *model* of the decision path; the fidelity check is the
evidence that the model matches the code. It is not a proof about the operating system, the firewall or the sensors.

E2 needs `z3-solver` (`pip install z3-solver`); it is run on the student's machine and its output file is committed.

## Files

`qacrs/sensors_v11.py` (sources, fusion, attack search), `qacrs/phase16_v11.py` (E1 → `results/v11/attack.json`),
`qacrs/formal_v11.py` (E2 → `results/v11/formal.json`; Z3 part `--z3`), `qacrs/gate_v11.py` (only if a property
fails), `qacrs/report_v11.py` (→ `docs/qacrs/RESULTS_v11.md`), `tests/test_v11.py`.

### ملخص عربي

قبل أي نتيجة: نهاجم ACRS بمهاجم يعرف الكود كاملاً ويبحث عن أسوأ مدخل، بدل التنبيهات المزوّرة الثابتة في v8. نختبر هدفين:
**التسليح** (يخلي النظام يقطع أنظمة سليمة) و**الإخفاء** (يخفض أو يحذف تنبيه جهاز مخترق فعلاً، فيقول النظام «تم الاحتواء» والهجوم
ما زال مفتوحاً بدون ما يُبلَّغ أحد). لكل جهاز 3 مصادر تنبيه مستقلة، ونقارن خمس طرق دمج (مصدر واحد، أعلى قيمة، المتوسط،
الوسيط، الوسيط مع حارس الشبكة). لكل سيناريو نحسب **نصف القطر المضمون**: أقل عدد مصادر يحتاج المهاجم يزوّرها عشان يضر. والأهداف
مثبتة مسبقاً: الوسيط أقل من المصدر الواحد في الإخفاء (≤ 5%)، و0 خدمات متوقفة إضافية بالتسليح مع مصدرين مزوّرين، ونصف قطر ≥ 2
في 80% من السيناريوهات. وفي التجربة الثانية نثبت بأداة **Z3** رياضياً (لكل المدخلات الممكنة، مو بعينات) إن النظام ما يعزل
جهازاً ممنوعاً، ولا خادماً حرجاً بدون شخصين، ولا جهازاً غير مبلَّغ عنه، مع افتراض إن الحلّال (الكمومي أو الكلاسيكي) ممكن
يطلّع أي شي. **أعلنّا قبل التشغيل:** قراءة الكود أظهرت إن طبقة الخدمة `to_acrs` تعلّم كل عزل يقترحه الحلّال «تلقائي» حتى لو
المحرّك رفضه، وإن منفّذ الجدار الناري ممكن يعزل جهازاً سليماً ما أحد بلّغ عنه. لو تأكد هذا رسمياً، ننشر المثال المضاد، ونضيف
طبقة إنفاذ واحدة (`gate_v11.py`) بدون لمس ملفات المحرّك المقفلة، ونثبت الإصلاح من جديد بأداتين مستقلتين (Z3 وHiGHS).
كل فشل يُنشر كما هو.
