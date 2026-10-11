# HASSAN (Q-ACRS) — Pre-registration v7: graded containment for critical servers

**Written:** 2026-10-11, before any v7 code or result; committed alone.
**Motivation (from v6, kept as-is):** on attack chains H1 was not supported (0.56) because 59% of chains reach a
critical server, and the only options were *restrict* (attacker keeps a foothold) or *isolate* (services go down and
two people must approve), so Q-ACRS escalated 43.6% of incidents.

**v7 is a model change.** Earlier versions stay frozen and reproducible (`LOCK_v5.json`); v7 lives in new modules.
No existing weight changes. New parameters are design assumptions, listed below, and their sensitivity is reported.

---

## 1. New action: SEGMENT (critical servers only — database and domain controller)

Enforced as firewall rules (same mapping in the mock adapter and the real-kernel sandbox):
- drop `m → C2` (the attacker's channel, as RESTRICT);
- drop every packet **from a hacked, non-isolated machine to `m`** (no lateral access into the server);
- healthy machines keep reaching `m`, so services served through healthy replicas stay up.

Approval policy (design decision, fixed now): SEGMENT is **automatic** (it removes no healthy traffic and is fully
reversible) and is logged with an owner notification. ISOLATE of a critical server still needs **two different
approvers**.

## 2. Exact semantics used for scoring (not the QUBO approximation)

- **Service down** if any dependency is isolated, **or** every replica is either isolated or (hacked, not isolated,
  and a dependency of the service is segmented — it can no longer reach the dependency).
- **C1-v7 open path** `a → b`: `a` hacked and not isolated, `b` critical, not hacked, not isolated **and not segmented**.
- **C2-v7:** a hacked isolatable machine with risk ≥ 7 is contained if isolated, **or** if it is critical and segmented.
- Containment, statuses, H-tests otherwise as in v2–v6. **Both** the old (v2) and new (v7) containment rules are
  reported for every method, so the effect of the redefinition is visible, not hidden.

## 3. QUBO (new builder `qubo_v7.py`; extra variable `s_m` for each critical server in the variable set)

- leftover risk of a hacked machine: `r(1 − x)`, minus `(1 − ρ)·r·s` if it is a segmented critical server
  (segmented keeps a residual fraction **ρ = 0.3** of its risk: the attacker may still act locally on it);
- spread `a → b` (b critical, not hacked): `w(1 − x_a)(1 − x_b − s_b)`, `w = SPREAD·r_a` (quadratic under one-hot);
- disruption: `d·x + d_seg·s`, **d_seg = 1**;
- service down from isolation: unchanged; from segmentation (replica loses its dependency): for replicas `R` of a
  service depending on `m`, `V·(x₁ + h₁s)(x₂ + h₂s) − V·x₁x₂` (two replicas) or `V·h₁·s` (one replica) — an
  over-estimate of damage, never an under-estimate (same convention as v1);
- one-hot `P·x_m·s_m` and never-isolate `BIG·x` penalties with `P = BIG` (same BIG as v1).
Exact brute force is the solver (as in every evaluation so far).

## 4. Methods compared (same scenarios, same scoring)

| Method | Rule |
|---|---|
| `full_isolation_safe` | isolate every isolatable hacked machine (unchanged baseline) |
| `rule_segment` (**new, strong baseline**) | isolate every isolatable non-critical hacked machine; segment every hacked critical server and every critical server a hacked machine links to |
| `q_acrs_v5` | v1 QUBO + v5 gate (the system as of v6) |
| `q_acrs_v7` | v7 QUBO + v7 gate (G1/G2/G3 trigger only on failures that remain after segmentation) |

`rule_segment` exists so that any gain cannot be credited to the new action alone: Q-ACRS v7 must beat a simple rule
that has the same action available.

## 5. Data (fresh, never used)

- **Primary:** attack chains, generator exactly as v6, **seed 7008**, 200 per network.
- **Secondary:** uniform random, **seed 9003**, 250 per network.
- Drop exact duplicates of any earlier set (development, 9001, 9002, 7007) and within the set; counts reported.

## 6. Hypotheses (α = 0.05; primary set unless stated)

| ID | Hypothesis | Test / rule |
|---|---|---|
| H1-v7 | Q-ACRS v7 contains (v7 rules) ≥ 80% as many scenarios as safe full isolation AND takes down fewer services | counts |
| H6 | Q-ACRS v7 contains more scenarios **fully automatically** (no approval, no escalation) than Q-ACRS v5 | exact one-sided binomial on discordant pairs (McNemar) |
| H7 | Q-ACRS v7 takes down fewer services than `rule_segment` | one-sided paired Wilcoxon |
| H8 | Q-ACRS v7 contains (v7 rules) at least 90% as many as `rule_segment` | counts |
| H2-v7 | silent failures of Q-ACRS v7: Wilson 95% upper ≤ 2% | Wilson |
| H5-v7 | real-kernel sandbox: model and measured traffic agree on 100% of checks, including SEGMENT | count |

Also reported, no threshold: escalation rate, two-person approval rate, segment usage, leftover risk, the v2-rule
containment of every method, and a sensitivity sweep of ρ ∈ {0.1, 0.2, 0.3, 0.5, 0.7} × d_seg ∈ {0.5, 1, 2}
(exploratory; no parameter is chosen from it). Any failed hypothesis is reported as-is.

### ملخص عربي

v7 يضيف إجراءً ثالثًا للخوادم الحرجة اسمه «التجزئة»: يقطع قناة المهاجم ويمنع الأجهزة المخترقة من الوصول للخادم،
ويترك الأجهزة السليمة تخدم. يُطبّق تلقائيًا لأنه لا يقطع خدمة سليمة، أما العزل الكامل فيبقى بموافقة شخصين. يُختبر على
بيانات جديدة تمامًا، ونقارنه بقاعدة بسيطة تملك الإجراء نفسه حتى لا يُنسب التحسن للإجراء وحده، ونعرض نتائج الاحتواء
بالتعريف القديم والجديد معًا.
