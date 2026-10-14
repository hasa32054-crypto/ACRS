# ACRS — Results v10: cross-sector generalisation, solver comparison, MITRE ATT&CK

Rules: `PREREGISTRATION_v10.md` (commit `144da4e`, before any result). Code: `backend/qacrs/phase15_v10.py`.
Raw numbers: `backend/qacrs/results/v10/v10.json`. Reproduce: `cd backend && python -m qacrs.phase15_v10` (~100 s).
The v9 engine is unchanged; the 11 files locked for the blind test still match `LOCK_blind_v9.json`.

## A. Same engine, three non-hospital sectors (attack chains, fresh seeds)

| Network | Chains | Contained / full isolation | Ratio | Services down ACRS vs full isolation | Unsafe | Silent | G1 (≥ 0.80) | G2 (≥ 0.90, 0 down) |
|---|---|---|---|---|---|---|---|---|
| factory48 (OT plant) | 192 | 152 / 192 | **0.792** | 0 vs 161 | 0 | 0 | **missed** | missed |
| bank42 | 193 | 174 / 193 | **0.902** | 1 vs 388 | 0 | 0 | **passed** | missed (1 service) |
| univ45 | 192 | 161 / 192 | **0.839** | 13 vs 218 | 0 | 0 | **passed** | missed (13 services) |

Services down are lower than safe full isolation in every sector (one-sided Wilcoxon p < 10⁻¹⁴ in all three). Decision
time median 0.1–0.3 ms (timings vary slightly between runs). Random alert sets (no target): ratios 0.90 / 0.84 / 0.90, 0 unsafe, 1 silent failure in
factory48 (Wilson 95% upper bound 2.8%).

**The factory miss (0.792 < 0.80), published as is.** None of the 40 non-contained factory chains is unsafe or silent:
all are **escalations to humans**. 25 involve a critical server (two-person approval by design) and 14 hit the ERP
application, which has **a single replica**: isolating it would take ERP down, so the engine hands the decision to
people instead of stopping a service. Industrial networks with single-copy business systems on the attack path
therefore get more human hand-offs. This is a real limit for OT environments, not hidden by changing any weight.

**Why G2 is missed in bank42 and univ45:** a few services go down where both replicas or a single-replica service sit on
the attack path and leaving them up would break a containment rule (1 service in the bank, 13 in the university, versus
388 and 218 under full isolation).

**Decision rule applied:** the claim may say "systems" for **hospitals, banking and university networks** (G1 passed);
for **industrial (OT) networks** the result is a near miss that is published as a limit.

## B. Classical solvers on the same problems (descriptive)

1,017 decision problems (600 sector chains + 230 v9 chains seed 7009 + 187 Hospital-60 chains), up to 24 variables
(median 8). Ground truth = exact MILP (HiGHS) and exhaustive enumeration.

| Solver | Optimal | Mean relative gap | Median time | p95 time |
|---|---|---|---|---|
| Exact MILP (HiGHS) | 1017 / 1017 | 0 | 9.2 ms | 13.8 ms |
| ACRS engine (exact ≤ 20 vars, else annealing) | 1017 / 1017 | 0 | 0.17 ms | 94 ms |
| Greedy descent | 1017 / 1017 | 0 | 0.07 ms | 0.3 ms |
| Simulated annealing (one run) | 1017 / 1017 | 0 | 16 ms | 29 ms |
| Best of 1,000 random bit-strings | 661 / 1017 (65%) | 0.21 | 2.6 ms | 5.2 ms |

Large incident (E9 network, 240 machines, 80 hacked, 146 variables): exact MILP 165.8 in 14 ms; greedy 165.8 (gap 0)
in 142 ms; annealing (60,000 steps) 165.8 in 1.0 s; random sampling far from optimal.

**What this means, stated plainly:** today's ACRS decision problems are easy for classical methods, including a simple
greedy search. The contribution is the formulation, the safety gate and the evaluation, not speed. The IBM results
(E7 11.9% → E8 82.7% single-shot optimal, E9 11/11 components optimal) show the same decision can be produced on
real quantum hardware once the penalty is scaled ("smallest safe penalty"); they are not a speed or quality advantage.
Random sampling (65% optimal) is the fair "no structure" baseline that the hardware results beat.

## C. MITRE ATT&CK coverage (descriptive)

Every one of the 1,017 chains carries at least one technique tag. Counts per network (scenarios containing the technique):

| Technique | factory48 | bank42 | univ45 | Hospital-60 |
|---|---|---|---|---|
| T1071 Application Layer Protocol (C2) | 192 | 193 | 192 | 187 |
| T1566 Phishing (Initial Access) | 178 | 180 | 174 | 176 |
| T1021 Remote Services (Lateral Movement) | 128 | 140 | 142 | 127 |
| T1190 Exploit Public-Facing Application | 21 | 23 | 26 | 25 |
| T1003 OS Credential Dumping / T1078 Valid Accounts | 43 | 42 | 33 | 37 |
| T1005 Data from Local System / T1041 Exfiltration Over C2 | 43 | 52 | 61 | 44 |
| T1486 Data Encrypted for Impact | 48 | 55 | 27 | 44 |
| ICS T0886 Remote Services (OT lateral movement) | 13 | – | – | – |
| ICS T0843 Program Download (into a PLC) | 7 | – | – | – |

Nine tactics are represented (Initial Access, Lateral Movement, Command and Control, Credential Access, Defense
Evasion/Persistence, Collection, Exfiltration, Impact, ICS Lateral Movement). This shows which real behaviours the
synthetic chains stand for; it does not mean every ATT&CK technique is covered.

**Correction made before publishing:** the first run applied the ICS rule by name prefix and wrongly tagged the
university's student information system (`sis_*`) as an industrial safety system. The pre-registration limits ICS tags
to the factory OT zone, so the rule was scoped to the factory and the script re-run. Experiments A and B are unaffected.

### ملخص عربي

- **التعميم:** نفس المحرّك بدون تغيير أي وزن نجح في فرضية إبداع (≥ 0.80) في **البنك (0.902)** و**الجامعة (0.839)**، وفشل
  بفارق بسيط في **المصنع الصناعي (0.792)**. في كل القطاعات: 0 قرارات غير آمنة، و0 فشل صامت، وخدمات متوقفة أقل بكثير من
  العزل الكامل (1 مقابل 388 في البنك). سبب فشل المصنع: كل الحالات غير المحتواة إحالات للبشر، أغلبها لخوادم حرجة أو لنظام
  ERP بنسخة واحدة؛ ننشره كحد صادق لبيئات التحكم الصناعي.
- **الحلّالات الكلاسيكية:** الحل الدقيق والجشع والتلدين وجدت الأمثل في 1,017 من 1,017 مسألة، والعيّنات العشوائية 65% فقط.
  المسائل الحالية سهلة كلاسيكيًا، ومساهمة المشروع في الصياغة وبوابة السلامة والتقييم، لا في السرعة، ولا ندّعي تفوقًا كمّيًا.
- **MITRE ATT&CK:** كل السلاسل مربوطة بتقنيات حقيقية في تسعة تكتيكات، منها تقنيتان لأنظمة التحكم الصناعي في المصنع.
