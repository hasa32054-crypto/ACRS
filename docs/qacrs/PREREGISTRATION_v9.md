# HASSAN — Pre-registration v9: fixing the v8 misses at their root cause

**Written:** 2026-10-11, after the v8 results and **before any v9 code**; committed alone.
**Rule:** the v8 misses stay published unchanged in `RESULTS_v7_v8.md`. v9 is a new version tested on **fresh data
that has never been used** (new seeds below). Targets are the same as v8 or stricter. Misses will be published.

## Root causes found in v8 (from the code, not guessed)

| v8 miss | Root cause |
|---|---|
| 26 time to contain (p95 174 ms) | rules applied by one `iptables` process per rule; and the attacker probe used 3 attempts × 50 ms timeout, so a *blocked* attempt could only be observed after 150 ms |
| S5 certificate checker (726/1000) | the checker recomputed the claims from the plan in the certificate but **copied the status** and never checked that the plan is the optimum for the scenario |
| S6 digital twin (22/100) | the twin compared behaviour only; a skipped rule with no observable effect (redundant half of ISOLATE) is invisible to behaviour |
| S10 guard (46.7%) | the guard used graph shape only; a path-aware forger draws a plausible path |
| ransomware: HASSAN = full isolation | no action could do better than isolating every infected machine; non-isolatable infected devices kept spreading under both |
| regret rule adds a silent failure | the rule accepted *any* cheaper alternative, including ones that break a containment rule |

## Fixes (design fixed here)

1. **Atomic enforcement + fast-fail egress.** All rules of a decision are loaded in **one** `iptables-restore --noflush`
   call. Attacker → C2 egress is blocked with `REJECT --reject-with tcp-reset` (the attacker's next attempt fails at once
   instead of hanging); isolation stays `DROP`. Time to contain = decision start → first attacker attempt observed failing.
2. **Optimality certificate.** The certificate carries the plan's objective value and the held list. The independent
   checker recomputes **every** field (claims, status via the decision rules, objective) and re-solves the scenario with
   its own exact solver (≤ 20 variables after reduction; annealing bound above) to confirm the plan is optimal.
3. **Twin = structure + behaviour.** The twin reads back the installed rules (`iptables -S`) and requires them to equal
   the plan exactly, *and* measures behaviour. Commit only if both agree.
4. **Corroborated alerts (guard v2).** Threat model A: the forger controls the endpoint-alert channel but not the
   independent network sensor (NDR flow log). Every scenario carries an NDR flow log. A genuine attack hop produces a
   lateral-movement flow (admin protocol) on that link; benign traffic produces only clinical/service flows, plus
   spurious lateral flows on 2% of links (design assumption); the sensor misses a genuine hop with probability 5%
   (design assumption). Guard v2 flags a non-entry hacked machine with no lateral flow from a hacked in-neighbour.
   Threat model B (forger also controls NDR) is reported with no target; there the harm bound is the protection.
5. **SHIELD action (port-scoped micro-segmentation).** On every outgoing link of an infected machine that is *not*
   isolated (non-isolatable devices, critical servers awaiting approval, restricted machines), block lateral-movement
   protocols only; clinical/service traffic stays open, so no service is lost. Design assumption: ransomware spreads
   over admin protocols (SMB/RDP-style), as WannaCry did over SMB.
6. **Safety-constrained regret rule.** An escalation may be resolved automatically only if the alternative
   (a) passes every safety rule, (b) satisfies containment rules C1 and C2, (c) takes **0** services down, and
   (d) costs at most τ = 5 more than the optimum. Otherwise the escalation stays.

## Fresh data (never used before)

attack chains seed **7009** (primary, ~260), random seed **9004** (~430), Hospital-60 chains seed **7102** (200),
ransomware seed **7203** (100 per network), manipulated-alert sets seed **8109** (1,000), tamper seed **8131**,
twin trials seed **8121**.

## Targets

| ID | Target |
|---|---|
| 26-v9 | real kernel, ≥ 200 decisions: decision → first attacker attempt observed failing, **p95 < 50 ms**; model vs measured checks 100% agree |
| S5-v9 | 1,000 tampered certificates incl. **smart tampering** (plan changed and every claim recomputed to look self-consistent): **100% rejected** by the checker; 100% genuine accepted; checker median < 5 ms (v8: < 1 ms without re-solving — stated as relaxed) |
| S6-v9 | 200 twin trials, half with a faulty adapter that skips one rule: **100% faulty aborted, 100% healthy committed, p95 < 100 ms** |
| S10-v9 | threat model A: detection **≥ 80%** on 1,000 manipulated sets (half naive, half path-aware); false-flag rate **≤ 10%** on genuine chains (seed 7009); harm bound under model B: worst services down 0 |
| R-v9 ransomware | mean machines encrypted HASSAN v9 **< safe full isolation** (one-sided Wilcoxon p < 0.05, both networks); services unavailable HASSAN v9 ≤ safe full isolation; SHIELD verified in the real kernel: lateral port blocked and clinical port open on 100% of checks |
| G-v9 regret | 0 silent failures introduced; escalations resolved reported (no minimum) |
| v7 claims on fresh data | chains 7009: containment ratio vs safe full isolation ≥ 0.9, 0 services down, 0 silent, 0 unsafe; Hospital-60 seed 7102 same |

### ملخص عربي
لن نغيّر نتائج v8 الفاشلة؛ تبقى منشورة. v9 تعالج السبب الجذري لكل إخفاق وتُختبر على بيانات جديدة لم تُستخدم، بأهداف
مثبتة هنا قبل كتابة أي كود. أي هدف يفشل هنا يُنشر أيضًا.
