# ACRS — Pre-registration v10: does the same engine generalise beyond hospitals?

**Written:** 2026-10-14, **before any v10 result was computed**; committed together with the three network
definitions (`backend/qacrs/sectors_v10.py`) and nothing else. Drafted with Claude (Anthropic) at the student's request;
the student approved the targets before the run. The v9 engine is used **unchanged**: no weight, threshold, rule or
solver setting is modified. The files locked for the blind test (`LOCK_blind_v9.json`) are not touched.

## Why

Every result so far is on hospital-inspired networks. Calling ACRS a containment system for critical *systems* in
general is only honest if the same engine, with the same weights, works on networks from other sectors. If it fails in a
sector, that failure is published as a limit and the claim is narrowed to the sectors that pass.

## Experiment A — cross-sector generalisation (primary)

**Networks (fixed in `sectors_v10.py`):** `factory48` (manufacturing plant with an OT zone: 6 PLCs, 4 HMIs and a safety
system that can never be isolated; SCADA twins; historian bridging IT and OT), `bank42` (core banking twins, payments
and ATM-switch twins, an HSM that can never be isolated, SWIFT gateway, online and mobile banking), `univ45` (LMS twins,
student records, exams, research cluster with a critical data store, two research instruments that can never be
isolated, 12 student lab PCs). Weights are design assumptions on the same 1-10 scale as all earlier networks.

**Fresh data (seeds never used before):** attack chains (existing generator `phase8_ood.chain_scenarios`, unchanged)
seeds **7401 / 7402 / 7403**, 200 per network; random alert sets (`network.random_scenarios`, unchanged) seeds
**9401 / 9402 / 9403**, 200 per network. Exact duplicates inside a set are dropped and the count is reported.

**Engine and baselines:** ACRS v9 portfolio (`hassan.solve` + `qubo_v7.decide_v7`), exactly as in `phase14_v9.py`;
baseline = safe full isolation (`qubo_v7.m_full_isolation_safe`).

**Metrics (identical to v9):** containment ratio vs safe full isolation, services down (ACRS and baseline), unsafe
decisions (status REJECTED), silent failures (NOT_CONTAINED), Wilson 95% upper bound on silent failures.

**Targets, per network, on the attack chains:**

| ID | Target |
|---|---|
| G1 (= Ibdaa H1) | containment ratio ≥ **0.80**, **0** unsafe decisions, and services down ACRS < safe full isolation (one-sided Wilcoxon p < 0.05 on per-scenario counts; if the baseline also takes 0 services down the test is reported as not applicable) |
| G2 (= v9 strict) | containment ratio ≥ **0.90**, **0** services down, **0** silent failures, **0** unsafe |

Random sets: same metrics reported, no target (they include implausible alert sets by design).

**Decision rule for the wording:** the form and website may say "systems" (not only hospitals) only for the sectors
where **G1 passes**. Every miss is published with its cause.

## Experiment B — classical solver comparison (descriptive, no target)

**Question:** how do simple classical solvers compare with the exact optimum on the same decision problems, and where
does the quantum path stand? This experiment is **not** designed to show, and will not claim, any quantum advantage.

**Problems:** every attack chain of Experiment A (600) plus the v9 fresh chains (seed 7009) and Hospital-60 chains
(seed 7102), and one large incident: the E9 four-hospital 240-machine network (`quantum_scale.cluster/incident`).

**Solvers:** exact enumeration (ground truth, ≤ 20 variables), exact MILP (HiGHS, any size), the engine portfolio,
greedy descent (start from "restrict everything", flip the single best bit until no improvement), simulated annealing
(one run, 6,000 steps, seed 0), best of 1,000 uniform random bit-strings (a sampling baseline of the same order as a
few thousand quantum shots).

**Reported:** share of problems solved to the optimum (gap ≤ 1e-6), mean relative gap, median and p95 time per problem.
The IBM results (E7–E9) are quoted from their own files, not re-run.

## Experiment C — MITRE ATT&CK coverage (descriptive)

Every attack chain of A and B gets technique tags from the existing rule set (`realism_v8.mitre_tags`, unchanged) plus
ICS tags for the factory OT zone (rules fixed here): a chain hop **into** a SCADA server, HMI, PLC or the safety system
→ ATT&CK for ICS **T0886 Remote Services** (Lateral Movement); a hop into a PLC → also **T0843 Program Download**;
an internet-facing entry into the plant over the VPN → **T0822 External Remote Services** (Initial Access). Reported:
technique and tactic counts per network. This shows which real-world behaviours the synthetic chains represent; it is
not a claim that they cover all of ATT&CK.

### ملخص عربي

قبل أي نتيجة: نختبر نفس محرّك ACRS v9 بدون تغيير أي وزن على ثلاث شبكات من قطاعات غير المستشفيات (مصنع فيه أنظمة
تحكم صناعي، وبنك، وجامعة)، ببذور جديدة لم تُستخدم. الهدف الأساسي لكل قطاع هو نفس فرضية إبداع: احتواء ≥ 0.80 أمام العزل
الكامل الآمن، و0 قرارات غير آمنة، وخدمات متوقفة أقل. لا نكتب «الأنظمة» بدل «المستشفيات» إلا للقطاعات التي تنجح، وكل فشل
يُنشر. ونقارن الحلّالات الكلاسيكية بالحل الأمثل وصفيًا بدون ادّعاء تفوق كمّي، ونربط سلاسل الهجوم بتقنيات MITRE ATT&CK.
