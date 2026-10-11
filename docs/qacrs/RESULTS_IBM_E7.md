# E7 — a real hospital decision on IBM quantum hardware (5 qubits)

Pre-registered in `PREREGISTRATION_v3.md` (E7): scenario `net12_h04` (database exfiltration), one job, same metrics as
Lesson 3. Run by the project owner on his own machine and IBM account on 2026-10-11. No key is stored in this repository.
Raw counts: `backend/qacrs/results/v3/ibm/net12_h04_run.json`.

| Item | Value |
|---|---|
| Quantum computer | `ibm_kingston` (156 qubits), job `db5sjrkvf2bc73d0bvkg`, 4,000 shots |
| Problem | 5 qubits (web1, web2, app1, app2, db), QAOA p = 2, angles tuned on the noiseless simulator |
| Circuit on the chip | depth 16, 4 two-qubit gates; Qiskit circuit = numpy simulator to 2.2 × 10⁻¹⁶ |
| Chance one shot is optimal | **real 11.9%** (Wilson 95%: 11.0–13.0%) · ideal 13.5% · random 3.1% |
| vs random | 3.8× random; exact binomial one-sided p ≈ 5 × 10⁻¹³⁴ |
| vs ideal | the hardware kept 88.6% of the ideal simulator's success rate |
| Expected cost | real 9.62 · ideal 9.42 · best 8.00 · worst 97 |
| Best of 100 real shots | contains an optimal decision ✅ |
| Most frequent single shot | isolate `web2` (cost 9, not optimal) → **safety gate: ESCALATED** (database needs two-person approval) |

## Reading it honestly
- The hardware works on a real 5-qubit decision: far above random and close to the ideal simulator.
- The ideal rate itself is low (13.5%) because QAOA with p = 2 spreads probability over several near-optimal decisions;
  so a single shot is not used as a decision. HASSAN takes the best of many shots, then the independent safety gate checks it.
- The most frequent shot was not optimal, and the gate did not execute it silently: it escalated. This is the design
  working as intended — a quantum answer is never executed without the classical safety check.
- No quantum advantage is claimed: the exact classical solver finds the optimum instantly.

### ملخص عربي
شغّلنا قرار مستشفى حقيقي بـ 5 كيوبت على حاسوب IBM الكمّي `ibm_kingston`. احتمال أن تعطي القراءة الواحدة القرار الأمثل
11.9%، أي 3.8 أضعاف التخمين العشوائي (3.1%)، و88.6% من أداء المحاكي المثالي (13.5%). أفضل 100 قراءة احتوت القرار الأمثل.
والقراءة الأكثر تكرارًا لم تكن مثالية، فأوقفتها بوابة السلامة وأحالتها للبشر بدل تنفيذها، وهذا بالضبط هدف التصميم.
لا ندّعي تفوقًا كمّيًا.
