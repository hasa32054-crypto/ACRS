# ACRS v11-pilot — real incidents 2016–2026 replayed on the unchanged v9 engine

**Run:** 2026-10-18 · `backend/qacrs/phase16_v11.py` → `backend/qacrs/results/v11/v11.json` ·
pre-registration `PREREGISTRATION_v11.md` (sha256 `c462728…bf7ca2`, merged in PR #24 **before** any conversion) ·
script sha256 `033aaa8…bc619` · engine v9 unchanged (threshold 7, ρ 0.3, d_seg 1.0) · 128 unit tests pass.

> **This is a pilot, not the registered v11.** The pre-registration requires a converter who is not the student
> and who has not seen the engine's earlier results. The converter for this run was **Claude (Anthropic)**, which
> wrote the pre-registration and had seen v7–v10 results in the same session. Every conversion file lists its sources
> and ambiguities (`backend/qacrs/v11/incidents/*.json`), so a human converter can redo them blind. Until that
> happens, nothing below is a confirmatory result.

## 1. What was converted

| # | Incident | Public sources used | Result |
|---|---|---|---|
| 1 | Bangladesh Bank / SWIFT, Feb 2016 | BAE Systems; SWIFT statement; Reuters (Daily Star); Bloomberg printer account; DOJ complaint (via PYMNTS) | converted, 2 moments |
| 2 | WannaCry / NHS England, 12 May 2017 | NAO HC 414 (full PDF); DHSC cost; CISA TA17-181A | converted as **one representative trust** (NAO names no hosts), 2 moments |
| 3 | NotPetya / Maersk, 27 Jun 2017 | CISA TA17-181A; Microsoft analysis; Wired; Maersk Q2 2017 | converted, 2 moments |
| 4 | Norsk Hydro / LockerGoga, 19 Mar 2019 | Microsoft DART case study; NorCERT; Hydro Q1 2019 | converted, 2 moments |
| 5 | Düsseldorf University Hospital, 10 Sep 2020 | BSI; NRW Justice Ministry (dpa); Cologne prosecutor | converted, 1 moment |
| 6 | Colonial Pipeline, 7 May 2021 | Blount Senate testimony; CISA AA21-131A; Mandiant (Bloomberg) | converted, 1 moment |
| 7 | Irish HSE / Conti, 14 May 2021 | PwC independent review (pp. 2–33); HHS HC3; Krebs | converted, **5 moments** (31 Mar → 14 May) |
| 8 | Change Healthcare, 21 Feb 2024 | Witty Senate Finance testimony; UHG 8-K; Cybersecurity Dive | converted, 1 moment |
| 9 | Synnovis / NHS London, 3 Jun 2024 | NHS England updates; Parliament statement; HSJ | **dropped** — no public entry point or hop |
| 10 | Interlock AA25-203A (2025) / Kettering Health | CISA advisory; BleepingComputer | **dropped** — technique chain, no victim network, no detection moment |
| 11 | AZ Monica, Belgium, 13 Jan 2026 | VRT; The Record; The Register | **dropped** — only detection time and impact are public |

8 incidents, **16 scenarios** (one per documented detection moment). Network sizes 8–24 machines, 1–26 links.
Service values (life-critical 30, core 20–25, support 10) were **not** fixed in the pre-registration — the brief added
them; this is a gap to close before the registered run.

## 2. Pre-registered targets

| Target | Result | Met? |
|---|---|---|
| R1: 0 unsafe decisions, 0 silent failures | 0 REJECTED, 0 NOT_CONTAINED in 16/16 | **yes** |
| R2: fewer services down than full isolation where full isolation takes ≥1 down | 14/14 (Wilson 95% 0.78–1.00) — **but see §3.1** | yes *as written*, misleading |
| R3: CONTAINED or PENDING in ≥ 80% | **5/16 = 31%** (Wilson 95% 0.14–0.56); 11 ESCALATED to two-person review | **no** |

Status counts: CONTAINED 5 · PENDING 0 · ESCALATED 11 · NOT_CONTAINED 0 · REJECTED 0. Decision time median 20 ms,
max 271 ms (WannaCry m2, 14 machines, annealing). Healthy machines isolated: 0.

## 3. What was not expected (exploratory — not pre-registered)

### 3.1 The "0 services down" is an artefact of deferral
ACRS took 0 services down in all 16 scenarios, against 42 for full isolation. But in 11 scenarios it did so by
**leaving the infected service hosts running** and escalating them (G1/G3) to two people. If those two people approve
every escalation as written, ACRS takes **24** services down (full isolation 42) and beats full isolation in only
**9/14** scenarios (Wilson 0.39–0.84), tying it in WannaCry m1/m2, NotPetya m2, Hydro m2 and Düsseldorf. The registered
R2 therefore measures the gate's refusal to act, not the optimiser's quality. The registered v11 must count services
down **after** approvals.

### 3.2 A one-line rule matched or beat the optimiser on real incidents
`rule_segment` (isolate every hacked non-critical host, segment every hacked critical one) was CONTAINED
**automatically in 16/16** and took **21** services down in total — fewer than ACRS-with-approvals (24). In Hydro m2 the
difference is stark: the DC was hacked at risk 8; the rule segmented it (1 service down), ACRS left it restrict-only,
escalated "isolate dc", and isolating the DC takes all 5 production services down. On these real graphs the QUBO's
extra machinery bought nothing over the rule. This is the most important negative finding of the pilot.

### 3.3 The S10 alert-consistency guard flags real ransomware as "implausible"
The guard's burst rule (≥ 3 simultaneous alerts all at risk ≥ 9) fired on **4 real detonations**: WannaCry m1 and m2,
NotPetya m2, HSE m5. In a real wiper/ransomware detonation, many hosts at risk 9 at once is the *normal* pattern, not an
injection. The guard was tuned on synthetic data where such bursts only came from the adversarial injector (phase 10).
It is advisory only (it did not change any decision), but as a signal it has a 100% false-positive rate on this class.

### 3.4 Decisions are not stable under halving the weights
Scaling all service values and disruptions by ×0.5 changed the ACRS action set in **8/16** scenarios; ×1.5 changed it
in 2/16. The v5 sensitivity study (synthetic hospital) reported much higher stability. Status never changed to unsafe,
but "which hosts get isolated" moved. Weights are design assumptions; on real networks they matter more than the
synthetic study suggested.

### 3.5 Cost of a missed alert (the one finding in the project's favour)
Where the public record gives an early, ignored alert and a late detonation, the same engine at the two moments:

| Incident | First documented alert | ACRS at first alert | Last moment | ACRS at last moment (if approved) | Full isolation at last moment |
|---|---|---|---|---|---|
| HSE / Conti | 31 Mar 2021, AV in monitor mode flags Cobalt Strike + Mimikatz on one PC | CONTAINED, isolate **1** PC, 0 services down | 14 May 04:36, 19 hosts encrypted | 13 isolations, **3** services down | **9** services down |
| Norsk Hydro | Dec 2018, AV flags Trojan on one PC | CONTAINED, isolate **1** PC, 0 down | 19 Mar 2019 04:00, DC pushing LockerGoga | 5 isolations, 5 down | 5 down |
| NotPetya | first black screens in Copenhagen (6 hosts) | ESCALATED, 1 down if approved | 2 h later, 13 hosts | 3 down | 3 down |
| Bangladesh Bank | 5 Feb printer empty | CONTAINED: isolate the phished PC, **segment** the SWIFT server, 0 down | 6 Feb terminal error | same | 2 down |

The engine's value, on this evidence, is not a cleverer action set at detonation time (§3.2) — it is that **at the
first alert it acts on one machine, automatically, in under a millisecond**, where the organisations in the record
had the alert and did nothing (HSE: "antivirus … set to monitor mode so it did not block"; Hydro: "antivirus detected
the Trojan a few days later, but by then the attacker had built an initial foothold"). The precondition is that the
alert reaches ACRS at all; Düsseldorf (9-month backdoor, patched, pentested, never seen) and Colonial (first sign was
the ransom note) show that without a detection signal there is nothing to contain.

### 3.6 No never-isolate machine appeared
Rule 2 (never-isolate only if the report says disconnection endangers life) produced **zero** never-isolate machines
in 8 incidents — even WannaCry's MRI scanners, because the NAO says trusts themselves took devices off the network.
The engine's hardest rule (S1) was therefore never exercised on real data. The synthetic hospital assumed it would be.

## 4. Per-incident before / after

"Before" = what the public record says happened. "ACRS" = the frozen engine at the documented detection moment.

| Incident (moment) | Before (record) | ACRS automatic | Escalated to humans | Services down: ACRS auto / if approved / full isolation |
|---|---|---|---|---|
| Bangladesh m1 (5 Feb printer) | fault treated as routine; staff leave 11:15; $81m gone | isolate pc_phish, **segment** SWIFT Alliance server | — | 0 / 0 / 2 |
| Bangladesh m2 (6 Feb terminal error) | 24 h of manual printing reveals 46 Fed queries | same | — | 0 / 0 / 2 |
| WannaCry m1 (late morning) | trusts report lock-outs; 13:06 EPRR | isolate web_smb_entry, pc_1, pc_3 | G3 pc_2 (A&E PCs) | 0 / 1 / 1 |
| WannaCry m2 (13:06–16:00) | major incident; 34 trusts locked out, 1,220 devices | isolate 6, segment MRI + pathology device | G3 ×2 | 0 / 2 / 2 |
| NotPetya m1 (screens go black) | >2 h to disconnect network | isolate 4, segment dc, dc_ghana, gate, booking | G3 pc_odessa_medoc (M.E.Doc service) | 0 / 1 / 3 |
| NotPetya m2 (+2 h) | 150 DCs, 4,000 servers, 45,000 PCs wiped | isolate 9, segment 3 | G1 dc, G3 pc_odessa_medoc | 0 / 3 / 3 |
| Hydro m1 (Dec 2018 AV alert) | alert seen, foothold kept 3 months | isolate pc_patient_zero | — | 0 / 0 / 0 |
| Hydro m2 (4 a.m. call) | network shut down manually; ~USD 71m | isolate 3 | G1 dc, G3 srv_1 | 0 / 5 / 5 |
| Düsseldorf (10 Sep) | 30 servers encrypted; emergency care deregistered 13 days | isolate 8 | G1 srv_his, G3 srv_1, G3 srv_mail | 0 / 3 / 3 |
| Colonial (ransom note 05:00) | 5,500 miles shut by 06:10 as precaution | isolate 9, segment srv_finance_1 | G3 srv_it_1; two-person on finance_2/3 | 0 / 1 / 2 |
| HSE m1 (31 Mar) | AV monitor mode, no ticket | isolate pc_patient_zero | — | 0 / 0 / 0 |
| HSE m2 (7 May) | six servers flagged, "not actioned" | isolate 7, segment dc + 5 data-centre servers | — | 0 / 0 / 1 |
| HSE m3 (10 May) | Hospital C DC alert rated low risk | isolate 9, segment 6 | G1 dc_hosp_c | 0 / 1 / 2 |
| HSE m4 (12–13 May) | vendor email "16 systems"; servers restarted | isolate 11, segment 6 | G1 dc_hosp_c | 0 / 1 / 3 |
| HSE m5 (14 May 04:36) | 80% encrypted; ≥ €100m; 7,000 appts/day | isolate 9, segment 6 | G1 + G3 ×3 | 0 / 3 / 9 |
| Change Healthcare (21 Feb) | backups encrypted; $872m Q1; 190m people | isolate 4, segment 3 claims platforms | G3 srv_core_1; two-person srv_backup | 0 / 3 / 4 |

## 5. Limitations (all of them)
1. Converter = Claude, not an independent human; not blind to earlier results. **Pilot only.**
2. Networks are partial reconstructions from public reports; generic groups capped at 3–10 hosts; internal pivot
   sequences are mostly not public (logged per incident in `ambiguities`).
3. WannaCry is a representative trust, not a named one.
4. Service values were added by the brief, not the pre-registration.
5. "If approved" assumes reviewers accept every escalation as written; they could choose segmentation instead.
6. n = 16 scenarios from 8 incidents; intervals are wide.

## 6. What changes because of this
- The registered v11 must report services down **after approvals** and compare against `rule_segment`, not only
  against full isolation. If the rule still matches the optimiser, the form must say so.
- The S10 burst rule needs re-deriving on real detonation patterns or being dropped.
- The sensitivity claim in the form should cite the real-network ×0.5 instability (8/16), not only the synthetic study.
- The project's strongest honest claim is §3.5: act on the first alert, on one machine, automatically.

### ملخص عربي
شغّلنا محرك v9 **بدون أي تغيير** على 8 حوادث حقيقية (16 لحظة اكتشاف) من 2016 إلى 2024؛ 3 حوادث (Synnovis، Interlock، AZ Monica)
أُسقطت لأن المصادر العامة ما تذكر نقطة دخول أو قفزة. النتائج كما هي: **R1 تحقق** (0 قرار غير آمن، 0 فشل صامت)،
**R3 لم يتحقق** (31% فقط احتواء آلي، 11/16 صُعّدت للبشر). وأربع مفاجآت غير متوقعة: (1) «0 خدمات متوقفة» وهم — المحرك
يؤجّل القرار على الخوادم المصابة؛ لو وافق البشر تصير 24 مقابل 42 للعزل الكامل. (2) قاعدة بسيطة (`rule_segment`)
احتوت 16/16 آليًا بـ 21 خدمة متوقفة — أفضل من ACRS. (3) حارس التنبيهات S10 اعتبر 4 هجمات حقيقية «غير معقولة».
(4) تنصيف الأوزان غيّر القرار في 8/16. النتيجة الوحيدة لصالح المشروع: عند **أول تنبيه** (HSE 31 مارس، Hydro ديسمبر 2018)
يعزل جهازًا واحدًا آليًا ويحتوي — بينما المؤسسات تجاهلت التنبيه وانتهت بـ 9 خدمات متوقفة. المحوّل هنا Claude وليس
إنسانًا مستقلًا؛ هذه تجربة تجريبية والنسخة المسجّلة تحتاج محوّلًا بشريًا أعمى.
