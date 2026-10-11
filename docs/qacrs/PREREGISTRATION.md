# Q-ACRS — Pre-registered evaluation criteria (v2)

**Written:** 2026-10-10, **before** any v2 run. This file is committed on its own, before the code that
applies it and before any result it produces, so its git timestamp is the proof that the criteria were not
chosen after seeing the outcomes.

**Frozen inputs** (must not change during v2 — any change means a new version, v3):

| Input | Value |
|---|---|
| `qacrs/network.py` | sha256 prefix `71c872b912d4` |
| `qacrs/qubo_builder.py` | sha256 prefix `aa5cc3110408` |
| QUBO weights | `SPREAD = 0.5`; disruption, service values, risks exactly as in `network.py` |
| Scenarios | `scenarios(net)` with `n_random = 15`, `seed = 2027`, for net12 and net22 (40 in total) |

**Disclosure:** the aggregate Phase-3 summary from v1 (services down / unsafe / risk left per method) was
already known when these criteria were written. Per-scenario containment under the rules below had never
been computed.

---

## 1. Definitions

For one scenario: `H` = hacked machines with leftover risk `r(h)` (1–10 scale), `D` = machines a method
decides to **isolate**. Every hacked machine that is not in `D` is **restricted** (the attacker's channel is
cut; the machine keeps working).

### 1.1 Safety (checked first, independent of the solver)

A decision is **REJECTED** if any of these hold:

- S1: it isolates a machine marked `isolatable = False` (MRI, lab analyzer);
- S2: it names a machine that does not exist in the network;
- S3: the scenario itself is invalid (unknown machine, risk outside 1–10, empty, wrong network).

A decision that isolates a machine marked `critical = True` (database, domain controller) is not rejected,
but its status is **APPROVAL_REQUIRED**: it may only be executed after two different people approve.

### 1.2 Containment (the main success criterion)

A safe decision **contains** the threat when both rules hold:

- **C1 — no open path to a critical server.** There is no link `(a → b)` where `a ∈ H`, `a ∉ D`, `b` is
  critical, `b ∉ H` and `b ∉ D`. (A restricted hacked machine that can still open connections to an
  untouched critical server is an open lateral-movement path.)
- **C2 — no high-risk machine left only restricted.** Every `h ∈ H` with `r(h) ≥ 7` and
  `isolatable = True` is in `D`.

Threshold 7 is chosen because the "High" band of the CVSS v3 qualitative scale starts at 7.0 (FIRST, CVSS
v3.1 Specification, §5). It is a design choice, so 6 and 8 are reported as a **secondary** analysis; the
**primary** result uses 7 only.

Hacked machines that are **not isolatable** and have `r ≥ 7` cannot satisfy C2 by any method. They are
excluded from C2 and counted separately as **OWNER_REVIEW** (compensating controls + device owner), never
as a success of the algorithm.

### 1.3 Outcome of a scenario (exactly one)

| Status | Meaning |
|---|---|
| `REJECTED` | failed a safety rule (S1–S3) |
| `NOT_CONTAINED` | safe, but C1 or C2 fails |
| `CONTAINED_PENDING_APPROVAL` | safe, C1 and C2 hold, but needs the two-person rule |
| `CONTAINED` | safe, C1 and C2 hold, fully automatic |

`OWNER_REVIEW` is an extra flag that can be attached to any of the last three.

A failed or rejected scenario is **never** counted as a success.

---

## 2. Methods compared (same 40 scenarios, same scoring)

| Method | Rule |
|---|---|
| `full_isolation` | isolate every hacked machine (v1 baseline; can break S1) |
| `full_isolation_safe` | isolate every hacked machine that is isolatable (**new, fairer** baseline) |
| `per_machine` | isolate if `r ≥ 6`, isolatable and not critical (v1 baseline, unchanged) |
| `q_acrs` | exact QUBO optimum (brute force), unchanged from v1 |

## 3. Metrics reported for every method

1. count of each status in §1.3 (primary: `CONTAINED` + `CONTAINED_PENDING_APPROVAL`);
2. services down; 3. healthy machines isolated (isolated but not hacked);
4. leftover risk (sum of `r` over restricted hacked machines); 5. QUBO cost (v1 definition, no BIG term);
6. decisions needing two-person approval; 7. `OWNER_REVIEW` count.

No single number is called "the" result. Lower leftover risk alone is **not** evidence of a better method.

## 4. Hypothesis tested here

**H1:** compared with `full_isolation_safe`, `q_acrs` takes down fewer services and isolates fewer healthy
machines, while containing (per §1.2) at least 80% as many scenarios.

H1 is **rejected** if `q_acrs` contains fewer than 80% of the scenarios `full_isolation_safe` contains, or
if it does not reduce services down. Either outcome is reported as-is.

## 5. What is out of scope for v2

No weight is tuned in v2. Weight sensitivity, independent scenarios, scaling and the QAOA/CVaR comparison
are separate, later experiments with their own pre-registration.

---

### ملخص عربي

هذا الملف كُتب **قبل** تشغيل أي تجربة في الإصدار v2، ويُرفع وحده في commit مستقل حتى يثبت تاريخه أن معايير
النجاح لم تُختر بعد رؤية النتائج. يعرّف متى يُرفض القرار (يعزل جهازًا لا يجوز عزله أو جهازًا غير موجود)، ومتى
يُعد التهديد «محتوى»: لا يبقى مسار مفتوح من جهاز مخترق إلى خادم حرج سليم (C1)، ولا يبقى جهاز خطورته 7 أو أكثر
مقيّدًا فقط دون عزل (C2). الأوزان مجمّدة، وأضفنا خط أساس أعدل هو «العزل الكامل الآمن». الفرضية H1 قد تُقبل أو
تُرفض، وتُنشر النتيجة كما هي.
