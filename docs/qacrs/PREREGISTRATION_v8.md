# HASSAN — Pre-registration v8: the 50 + 10 feature programme

**Written:** 2026-10-11, after v7 results and **before any code for the features below**; committed alone.
**Rule:** each feature has an acceptance target fixed here. Results are published as they come, including misses.
"Report" means measured and published with no pass/fail threshold. Everything is simulation or the isolated
loopback sandbox unless stated; nothing touches a real network. Design assumptions are labelled as such.

Already done before v8 (not re-tested here): 1, 2, 3, 5, 6, 7, 12, 15, 20, 21, 22, 23, 27, 30, 31, 32, 35, 37, 39, and
4 (v7). Needs the owner: 28 (blind scenarios), 33 (IBM hardware).

## A. Validation of v7 in the real kernel

| ID | Target |
|---|---|
| 24 SEGMENT in the sandbox | model vs measured traffic agree on 100% of checks (incl. "hacked → segmented server blocked") |
| 25 Rollback | after rollback, 100% of attacker-channel and client checks reconnect |
| 26 Time to contain | decision start → first blocked attacker attempt: p95 < 50 ms |

## B. Anti-weaponization (phase 3)

| ID | Target |
|---|---|
| S1 Harm certificate | for every decision, a computed upper bound on what an attacker can make the system do **automatically** by forging alerts (healthy machines isolated, critical servers isolated without approval, services taken down). Validity: 0 violations in 10,000 random forged-alert sets per network. **H9:** worst case of HASSAN v7 < worst case of safe full isolation (services down), found by exhaustive search over forged sets of up to 3 machines at risk 10 |
| 9 Bounded blast radius | under forged alerts: 0 healthy machines isolated, 0 critical servers isolated without two approvers |
| 10 Alert flood | 1,000 alerts within one simulated minute: per-decision p99 < 10 ms; 0 healthy isolated |
| 11 Risk inflation | every risk forced to 10 on all scenario sets: 0 critical isolated without approval; services down reported |
| 13 Fail-safe | 1,000 injected solver faults (exception, timeout > 100 ms, malformed output): 100% fall back to restrict-all + escalate; 0 crashes; 0 silent |
| 14 Rate limit | ≤ 3 automatic isolations per rolling 60 s; excess goes to humans; 100% enforcement in tests |
| S10 Alert-consistency guard | flags alert sets that are implausible on the network graph (a hacked machine not reachable from an exposed entry point or another hacked machine) and routes them to humans. On 1,000 synthetic manipulated sets: detection ≥ 80%; on the realistic attack-chain sets (7007, 7008): false-flag rate ≤ 10% |

## C. Executor hardening (phase 4)

| ID | Target |
|---|---|
| 8 Time-boxed containment | 100% of rules carry an expiry (default 30 min, design assumption); unreviewed rules expire in simulation 100% |
| 16 Signed decisions (HMAC-SHA256) | 1,000 tamper attempts detected 100% |
| 17 Hash-chained audit log | 1,000 random edits / deletions / reorders detected 100% |
| S5 Proof-carrying decision | each decision ships a certificate (safety rules, containment rules, cost); an independent checker verifies it: median < 1 ms, 100% of genuine decisions accepted, 100% of tampered ones rejected |
| S6 Digital-twin pre-check | policy applied first in a shadow sandbox chain; commit only if measured = predicted; pre-check p95 < 100 ms; with an injected faulty adapter, 100% of mismatching commits aborted |
| S7 Decaying containment | rules relax as evidence decays (design: half-life 15 min). Simulation vs fixed isolation: service downtime reported; no hypothesis |
| S9 Self-drills | 100 injected enforcement faults (missing chain, rule not applied, adapter down): 100% detected by the drill |

## D. Explainability (phase 5)

| ID | Target |
|---|---|
| 18 Decision card | 100% of decisions have action, reasons, safety status |
| 19 Counterfactual | 100% state services saved vs safe full isolation |
| 47 Arabic + English | 100% of cards in both languages |

## E. Hospital realism

| ID | Target |
|---|---|
| 38 + S3 Clinical tiers and patient-minutes | services get patients-per-hour (design assumption: logins 120, nurse app 60, appointments 30) and an outage time of 60 min; patient-minutes saved vs safe full isolation reported per set |
| 40 Hospital-60 network | ~60 machines incl. EHR, PACS, HL7 engine, pharmacy, ER; 200 attack chains (seed 7101): 0 unsafe, silent Wilson upper ≤ 2%, decision p95 < 1 s |
| 41 MITRE ATT&CK tags | 100% of generated scenarios tagged with technique IDs by rule (role/step → technique) |
| 42 Ransomware spread | discrete-time spread along links (1 hop per tick); containment applied at tick 2; machines encrypted reported for HASSAN v7, safe full isolation, no action |
| S2 Anticipatory containment | on attack chains, hide the last machine of each chain; report the share of hidden next hops already blocked by the decision on the visible part (v7 vs v5 vs rule_segment) |

## F. Scale and solvers

| ID | Target |
|---|---|
| 29 200 machines | v7 with portfolio solver on 20 chain scenarios: decision p95 < 1 s |
| 36 Solver portfolio | exact ≤ 20 variables, simulated annealing above; where both run, agreement 100% |
| S4 Hybrid cross-check | QAOA (noiseless, 100 samples) vs exact on the v1 QUBOs: disagreement rate reported; 0 disagreements executed (they go to humans) |
| 34 Noise sweep | simulated p_best of the Lesson-3 circuit vs gate error; the error rate matching the recorded 96.5% is reported (inference, not a claim about the device) |
| S8 Regret-bounded escalation | escalate only if the automatic decision is worse than the best human-approved option by more than τ (design: τ = 5 cost units); escalation reduction and silent failures reported |

## G. Integration (phases 1 and 6)

| ID | Target |
|---|---|
| P1 Comparison document | SOAR, Defender XDR, CrowdStrike, Darktrace, Illumio, academic IRS — with sources |
| 44 API `/hassan/decide` | standard-library HTTP server: p95 < 50 ms over 1,000 local requests |
| 45 ACRS timers | 100% of decisions inside the 7 s restrictive-containment timer |
| 46 Incident replay | any scenario id replays to its decision card |
| 48 One-command reproduction | `make hassan-repro` regenerates core results (excluding 25-min QAOA seeds) in < 10 min |
| 49 Continuous integration | GitHub Actions runs every Q-ACRS/HASSAN test on each push and pull request |
| 50 Threat model (STRIDE) | every threat mapped to a control and, where possible, to a test |

### ملخص عربي

هذا التعريف يثبت الهدف الرقمي لكل ميزة متبقية قبل بناء أي منها. ما يتحقق يُعلن، وما يفشل يُعلن أيضًا. الميزتان 28
(السيناريوهات العمياء) و33 (عتاد IBM) تحتاجان صاحب المشروع.
