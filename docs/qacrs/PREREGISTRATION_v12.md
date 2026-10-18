# ACRS — Pre-registration v12: safety-first engine, real-world data, recovery, resilience and immunity

**Written:** 2026-10-18, after the v11-pilot (`RESULTS_v11_pilot.md`, PR #25) and **before any v12 code, data or
result exists.** Committed alone. Drafted with Claude (Anthropic) at the student's request; the student approved it.

## What v11-pilot found and what v12 answers

| v11-pilot finding | v12 change |
|---|---|
| #1 The optimiser left hacked critical servers restrict-only and escalated; a one-line rule matched or beat it (21 vs 24 services down) | **D1** safety floor before the optimiser |
| #3 "Restrict" is meaningless for a host where the destructive payload already ran (risk 9) | **D1** risk 9 = isolate, no restrict option |
| #7 S10 burst guard flagged 4 real detonations | **D3** connectivity-aware guard |
| #2 Synthetic data (one hospital, risk 4–8, never-isolate always present) does not resemble real incidents | **D4** new realistic generator |
| #4 "Services down" measured deferral, not quality; no comparison with the simple rule | **D5** primary metric = services down **after approvals**, four-way comparison |
| #6 / #10 Weights are design assumptions; the alert→risk mapping lives outside the system | **D2** published mapping tables, recorded in the certificate |
| #8 One-shot decisions; real incidents have several detection moments | **D6** monotone sequential decisions |
| #9 Real estates have 30,000 hosts; exact solver ≤ 20 variables | **D7** scale test |
| #5 Containment presupposes an alert | **D10** wording: "given an alert" everywhere |
| New: what happens after a failure? | **D11** recovery terminal, **D12** survival tests, **D13** immunity |
| From the security books: HMAC gives no non-repudiation | **D9** ML-DSA signature over the certificate |

## What does NOT change
- The 11 files locked for the blind test (`LOCK_blind_v9.json`): untouched. Every v12 module is a **new file** that
  calls the locked engine.
- Engine constants: threshold **7**, ρ **0.3**, d_seg **1.0**, SPREAD **0.5**. The 1–10 risk and weight scales.
- The pre-registered H1 threshold 0.80 from v3.
- Results are published whatever they are.

## Design changes (fixed here)

**D1 — Safety floor, then optimiser (`qubo_v12.py`).** Before the QUBO, deterministic actions from the alert set:
(a) hacked, isolatable, non-critical, risk ≥ 9 → **isolate** (risk 9 is defined in D2 as "destructive payload
executed on this host"; there is nothing left to keep running); (b) hacked, critical, risk ≥ 7 → **segment**
(automatic; isolation of a critical server stays a two-person decision); (c) hacked, never-isolatable → owner review
(unchanged). The locked solver then runs unchanged and its answer is **unioned** with the floor
(`iso = solver ∪ floor_iso`, `seg = (solver_seg ∪ floor_seg) − iso`). The locked gate `decide_v7` judges the result
unchanged. Hosts at risk 7–8 that are the only replica of a service remain the human's call (G3), by design.

**D2 — Published mapping tables (`risk_map.py`).** Shipped with the system and hashed into the certificate:
ATT&CK → risk (T1486/T1485 = 9; T1003/T1558 = 8; T1071/T1219 = 7; T1021/PsExec/AnyDesk = 6; T1190/T1566/T1133 = 5);
documented impact → service value (life-critical or emergency care = 30; national/regional service or > 10,000 affected
appointments/customers = 25; core business = 20; support = 10); role → disruption d (life-critical 5, core 3–4,
support 2, workstation 1). The 8 v11 conversion files are re-expressed with this table **before** any v12 run.

**D3 — Connectivity-aware guard (`guard_v12.py`).** The burst flag fires only when ≥ 3 simultaneous alerts at risk ≥ 9
are **not connected** to each other through the network's links (undirected). A real detonation spreads along links;
an injected burst picks hosts at random. The "no compromised path into a non-entry host" flag is kept.

**D4 — Realistic generator (`realism_v12.py`).** Sectors (health / finance / industry), flat or two-tier networks of
20–60 machines, an explicit share of never-isolatable devices drawn from {0, 10, 30}%, attack chains with 1–4
documented detection moments whose last moment is a detonation burst (all chain hosts at 9). Seed **12012**, 1,000
scenarios, generated once, hashed, never regenerated.

**D5 — Metrics.** Primary: **services down after all escalations are approved as written**. Secondary: automatic
containment (CONTAINED/PENDING), unsafe, silent, healthy isolated, escalations, decision time. Every table compares
**five** policies on identical scenarios: v12, locked v9, `rule_segment`, "Wazuh-style active response" (isolate every
alerted host, no safety rule — modelled, not the Wazuh software), full isolation (safe).

**D6 — Sequential monotonicity.** For incidents with moments m1…mk, the v12 action set at m(i+1) must contain the
action set at m(i) (an isolated host is never released by a later decision while still hacked).

**D7 — Scale.** Generator networks of 100 / 300 / 1,000 machines (D4 rules), 50 scenarios each.

**D9 — ML-DSA.** The v9 certificate is additionally signed with ML-DSA-65 (FIPS 204) in a new module; the HMAC stays.
A tampered certificate (1,000 random tamperings, v9 kinds) must fail verification.

**D10 — Wording.** Every v12 table and the form say "containment *given an alert*".

**D11 — Recovery terminal (`acrs_recover.py`).** A command line for the engineer after an incident:
`status`, `readmit <host>`, `restore <host>`, `rotate-creds`, `shield <a> <b>`, `close-incident`. Every command is
validated by the locked safety checks before execution (`readmit` of a host still at risk ≥ 7 is refused; any command
touching a critical server needs two approvals; never-isolatable rules apply) and appended to a signed audit log.

**D12 — Survival.** Three fault injections: (a) solver killed/timeout mid-decision → fallback to the safety floor within
a fixed budget; (b) process crash and restart → persisted state restored, no isolated host released; (c) alert flood
(v8 kind) during recovery. Measured: unsafe decisions, state loss, decision time.

**D13 — Immunity.** On `close-incident`, the system extracts an *attack-path fingerprint* (ordered ATT&CK technique
chain + the links the attacker crossed) and installs: (1) permanent shields on those links (v9 SHIELD mechanism);
(2) a first-hop rule: an alert whose technique and link match the fingerprint's first hop is contained at that hop by
the safety floor. Weights and threshold are **not** modified. Tested by replaying each real incident three ways after
immunisation: the same attack, a *similar* attack (same technique chain, different hosts of the same roles, generated
by a fixed rule), and a *dissimilar* attack (different technique chain) as a counter-test for over-blocking.

## Data

- Real incidents: the 8 v11 conversions (16 moments), re-expressed with D2.
- **Open-source incident corpus (stage 1-b):** cases converted with the v11 rules from MITRE CTID Attack Flow examples,
  CTID adversary emulation plans, The DFIR Report write-ups (2020–2026), CISA #StopRansomware advisories with a
  described victim path, and VCDB records that name an attack path. A case with no documented entry point and hop is
  dropped with the reason. The corpus is frozen (hash) before any run. Target size ≥ 50 cases; the actual size is
  published.
- Synthetic: D4 (1,000), plus the v9 fresh sets for regression.

## Targets (all reported with Wilson 95% intervals; no p-values on the real sets)

| ID | Target |
|---|---|
| T1 | 0 REJECTED and 0 NOT_CONTAINED for v12 on every set |
| T2 | Automatic containment (CONTAINED or PENDING) ≥ 80% on the real 16 moments (v9: 31%) and on the open corpus |
| T3 | Services down after approvals: v12 ≤ `rule_segment` in total on the real 16 and on the corpus; v12 < full isolation in ≥ 70% of scenarios where full isolation takes ≥ 1 down |
| T4 | Guard: 0 burst flags on the 4 real detonations; ≥ 90% of phase-10 *naive* injections still flagged |
| T5 | Regression: on the v9 fresh sets, v12 containment ratio ≥ v9 and services down after approvals ≤ v9 |
| T6 | Monotonicity holds in 100% of multi-moment incidents |
| T7 | Scale: median decision ≤ 2 s at 1,000 machines, 0 unsafe |
| T8 | Survival: 0 unsafe decisions and 0 released hosts under (a)(b)(c) |
| T9 | Immunity: same attack contained with ≤ services down than before in 8/8; similar attack ≤ before in ≥ 6/8; dissimilar attack: identical decision to the un-immunised engine in 8/8 (no over-blocking) |
| T10 | ML-DSA: 1,000/1,000 tamperings rejected; sign + verify median ≤ 50 ms |
| T11 | Sensitivity ±50% on the real 16: published, no target |

Every miss is published with the scenario and the reason.

## Honesty controls
1. This file is committed alone; its hash is recorded in `results/v12/v12.json`.
2. The open corpus is converted by Claude (not an independent human) — stated in every table; conversion files carry
   sources and ambiguities so a human can redo them blind.
3. "Outperforms" is claimed only against the five modelled policies above, never against commercial EDR.
4. If D1 turns out to be all the improvement and the optimiser adds nothing over `rule_segment`, that is published and
   the project is described as "safety rule + gate + escalation + verification".

### ملخص عربي
قبل أي كود: v12 تضيف **أرضية أمان قبل المُحسِّن** (خطر 9 = عزل مباشر، خادم حرج مصاب = تقسيم مباشر)، جداول تحويل
منشورة (تقنية→خطر، أثر→قيمة)، حارسًا يفرّق الانفجار الحقيقي عن الحقن، مولّدًا واقعيًا جديدًا، مقياسًا صادقًا (الخدمات
المتوقفة **بعد** الموافقات) ومقارنة خماسية تشمل نمط Wazuh، واتساقًا زمنيًا، واختبار حجم 1,000 جهاز، وطرفية إنعاش
تمر أوامرها على بوابة الأمان، واختبارات «النظام ما يموت»، و**مناعة** بعد الحادثة تُختبر على الهجوم نفسه ومشابه
وغير مشابه، وتوقيع ML-DSA. الملفات المقفولة وثوابت المحرك لا تتغيّر. الأهداف الرقمية مثبتة أعلاه، والنتائج تُنشر
كما تطلع — وإن طلع أن القاعدة البسيطة تكفي، نقولها.
