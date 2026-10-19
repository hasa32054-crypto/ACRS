# ACRS — Results v14: attack the defender

Rules: `PREREGISTRATION_v14.md` (committed before any v14 result; targets H1–H3 approved by the student before E1 ran). Raw numbers: `backend/qacrs/results/v14/`. Rebuild this page: `cd backend && python -m qacrs.report_v14`. The locked v9 engine files are unchanged (`LOCK_blind_v9.json`).

## E2 — formal proofs of the safety rules

The solver is treated as **untrusted**: any output is allowed. Prover: HiGHS exact 0/1 programme (the Z3 run is `formal_z3.json`, from the student's machine, when present). ✅ = proved for every input, ❌ = a counterexample exists.

| Network | Path | P1 never-isolate | P2 critical | P3 only reported | P4 segment only critical | P5 guard |
|---|---|---|---|---|---|---|
| net12 | X firewall executor (before fix) | ✅ | ✅ | ❌ | ✅ | ✅ |
| net12 | S service adapter (pre-v14) (before fix) | ❌ | ❌ | ❌ | ❌ | ✅ |
| net22 | X firewall executor (before fix) | ✅ | ✅ | ❌ | ✅ | ✅ |
| net22 | S service adapter (pre-v14) (before fix) | ❌ | ❌ | ❌ | ❌ | ✅ |
| factory48 | X firewall executor (before fix) | ✅ | ✅ | ❌ | ✅ | ✅ |
| factory48 | S service adapter (pre-v14) (before fix) | ❌ | ❌ | ❌ | ❌ | ✅ |
| bank42 | X firewall executor (before fix) | ✅ | ✅ | ❌ | ✅ | ✅ |
| bank42 | S service adapter (pre-v14) (before fix) | ❌ | ❌ | ❌ | ❌ | ✅ |
| univ45 | X firewall executor (before fix) | ✅ | ✅ | ❌ | ✅ | ✅ |
| univ45 | S service adapter (pre-v14) (before fix) | ❌ | ❌ | ❌ | ❌ | ✅ |
| net12 | G service + gate_v14 (after fix) | ✅ | ✅ | ✅ | ✅ | ✅ |
| net12 | XG executor fed by gate_v14 (after fix) | ✅ | ✅ | ✅ | ✅ | ✅ |
| net22 | G service + gate_v14 (after fix) | ✅ | ✅ | ✅ | ✅ | ✅ |
| net22 | XG executor fed by gate_v14 (after fix) | ✅ | ✅ | ✅ | ✅ | ✅ |
| factory48 | G service + gate_v14 (after fix) | ✅ | ✅ | ✅ | ✅ | ✅ |
| factory48 | XG executor fed by gate_v14 (after fix) | ✅ | ✅ | ✅ | ✅ | ✅ |
| bank42 | G service + gate_v14 (after fix) | ✅ | ✅ | ✅ | ✅ | ✅ |
| bank42 | XG executor fed by gate_v14 (after fix) | ✅ | ✅ | ✅ | ✅ | ✅ |
| univ45 | G service + gate_v14 (after fix) | ✅ | ✅ | ✅ | ✅ | ✅ |
| univ45 | XG executor fed by gate_v14 (after fix) | ✅ | ✅ | ✅ | ✅ | ✅ |

**Executor path closed (post-hoc extension, disclosed):** the pre-registered fix covered the service adapter (G). The same gap on the firewall executor (path X, P3: an unreported machine could be isolated) is closed by feeding the executor only `gate_v14.enforce(...)['auto_isolate']` (`gate_v14.execute`, path XG). XG proves P1–P5 on every network; path X is kept in the table unchanged as the documented 'before'.

- **Model fidelity:** 2,000,000 random inputs compared with the real code (engine + executor + adapter + gate, injected solver output): **0 mismatches**.
- **Mutation check:** 15 / 15 planted bugs produced a counterexample.
- **Defence in depth (descriptive):** removing only the gate's own filter for one rule left the path safe in 10 / 10 cases, because the engine's rejection still covers it.
- **P6 (median of 3, one forged):** 1331 cases, 0 violations.

**Example counterexample before the fix (net12, path S, P1):** the solver proposes isolating mri, lab; the engine marks the decision REJECTED, but the pre-v14 adapter still sent these isolations to ACRS as automatic.

## E1 — a white-box attacker against five fusion defenders

_Not run yet._

### ملخص عربي

- **الإثبات الرياضي (E2):** قبل الإصلاح، طبقة الخدمة كانت تمرّر أي عزل يقترحه الحلّال كأنه تلقائي، حتى لو المحرّك رفضه (جهاز رنين مغناطيسي، خادم حرج)، ومنفّذ الجدار الناري ممكن يعزل جهازاً ما أحد بلّغ عنه. بعد إضافة طبقة الإنفاذ `gate_v14` صارت كل الخصائص الخمس مثبتة لكل المدخلات الممكنة على الشبكات الخمس، وتطابق النموذج مع الكود الحقيقي في 2,000,000 مدخل عشوائي بدون أي اختلاف، والأداة كشفت كل الأخطاء المزروعة عمداً.
