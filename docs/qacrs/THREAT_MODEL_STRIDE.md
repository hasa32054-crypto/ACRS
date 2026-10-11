# HASSAN threat model (STRIDE) — feature 50

Scope: the HASSAN decision engine (`qacrs/hassan.py`), its API (`hassan_service.py`), the executor pieces
(`executor_v8.py`, `policy_executor.py`, `sandbox_*.py`). Out of scope: the alert sources (EDR/NDR) and the real
firewall, which HASSAN has never been connected to.

Assets to protect: **availability of clinical services**, integrity of containment decisions, the audit trail.

| # | STRIDE | Threat | Control in HASSAN | Test / evidence | Residual risk |
|---|---|---|---|---|---|
| 1 | **S**poofing | attacker forges alerts so HASSAN isolates healthy service replicas | harm bound: only reported machines are touched; critical servers never isolated automatically; rate limit 3 isolations/min | `phase10_adversarial` exhaustive 1–3-machine forgeries: worst forced outage 0 (safe full isolation: 1); `test_hassan_engine` | a forger can still *trigger escalations* (human workload) |
| 2 | Spoofing | forged alerts that look like a plausible attack path | alert-consistency guard (flags machines with no hacked predecessor / entry point) → holds isolation for humans | guard detection 46.7% overall (naive 81%, path-aware 12%) — **target 80% missed**, published | path-aware forgeries mostly pass the guard; harm bound (row 1) still holds |
| 3 | Spoofing | someone calls the API pretending to be the SOC pipeline | API binds to 127.0.0.1 only; decisions are signed (HMAC-SHA256) | `test_hassan_service`, `phase11_executor` HMAC 1000/1000 | **no authentication on the API**; must sit behind an authenticated gateway before any real use |
| 4 | **T**ampering | decision changed between engine and executor | HMAC signature over the certificate; executor verifies before acting | 1000/1000 tampered decisions rejected (`executor.json`) | demo key in code (`demo-key-not-secret`); a real key must come from a secret store |
| 5 | Tampering | solver bug or manipulated solver returns an unsafe plan | penalty dominance (proof + unit test); independent checker after any solver; proof-carrying certificate | 20,000 random forged sets, 0 certificate violations; S5 independent checker caught 726/1000 tampered certificates — **target missed**, published | a certificate tampered in ways the checker does not model can pass (27%) — HMAC is the main control |
| 6 | Tampering | audit log edited to hide an action | SHA-256 hash chain | edit/delete/reorder detected 1000/1000; `test_executor_v8` | whole-log replacement needs an external anchor (not built) |
| 7 | **R**epudiation | "HASSAN never told us to isolate that server" | signed decision + bilingual card + hash-chained log | explainability 1956/1956 cards | none beyond row 6 |
| 8 | **I**nformation disclosure | decision cards reveal network layout to whoever reads them | API local only; cards contain machine names only | — | not tested; cards should be treated as internal documents |
| 9 | **D**enial of service | alert flood slows decisions or exhausts isolations | rate limiter; solver portfolio; 100 ms solver timeout with fail-safe (restrict only + escalate); 64 KB body limit | flood 1000 alerts/min: p99 2.3 ms, isolations ≤ 3; fail-safe 1000/1000 | escalation queue can be flooded (human DoS) |
| 10 | Denial of service | firewall rules silently not applied | digital-twin pre-check; self-drills with canary rule | drills 100/100; twin pre-check caught all 22 *observable* faults but only 22/100 injected faults were observable — **S6 target missed**, published | a skipped rule with no observable effect is not detected by the twin |
| 11 | DoS (self-inflicted) | containment outlives the threat | rules expire after 30 min unless confirmed; decay simulation | TTL test; decay −98% isolation-minutes (assumption-driven) | decay is a model, not measured in a hospital |
| 12 | **E**levation of privilege | the engine executes real firewall changes outside the sandbox | `policy_executor` only accepts mock adapters or adapters marked `sandbox_only=True`; sandbox uses own iptables chains on 127.x | sandbox runs: 6002/6002 checks, rollback 5412/5412 | running as root is needed for the sandbox; never run on a production host |
| 13 | Elevation | quantum backend (IBM) output executed directly | QAOA output never executed; disagreement with exact solver → human decision | hybrid cross-check: 2/38 disagreements, 0 executed | — |

## Missed controls (stated plainly)
- No API authentication (row 3) and a demo HMAC key (row 4): acceptable for a research prototype, not for deployment.
- Path-aware forgery guard (row 2) and twin pre-check coverage (row 10) are below their pre-registered targets.

### ملخص عربي
لكل تهديد في نموذج STRIDE ربطنا ضابطًا في HASSAN واختبارًا يقيسه. أهم ما ينقص: الواجهة بلا مصادقة، والمفتاح تجريبي،
وكاشف التنبيهات المزيفة الذكية ضعيف (12%)، والتوأم الرقمي لا يكشف الخطأ الذي لا أثر له. كلها منشورة كما هي.
