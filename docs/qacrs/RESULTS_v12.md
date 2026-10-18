# ACRS v12 — results

**Pre-registration:** `PREREGISTRATION_v12.md` (PR #26, sha256 `b066c3f12719…`, + Amendment 1 recorded in the file) ·
**runs:** `phase17_v12.py` (sha `94fde5134e07…`), `phase18_survive_immune.py`, `pqsign.py`, `sandbox_v12.py` ·
**engine constants unchanged** (threshold 7, ρ 0.3, d_seg 1.0, SPREAD 0.5) · **locked files untouched** · 128 unit tests pass.
All containment figures are **given an alert** (D10). The open corpus was converted by Claude, not an independent human.

## 1. Scoreboard against the pre-registered targets

| ID | Target | Result | Met |
|---|---|---|---|
| T1 | 0 REJECTED, 0 NOT_CONTAINED for v12 on every set | 0 / 0 on real16, corpus (207), realistic (894), v9 chains (253), v9 random (412) | **yes** |
| T2 | Automatic containment ≥ 80 % on real16 (v9 was 31 %) and on the corpus | real16 **16/16 = 100 %** (Wilson 0.81–1.00); corpus **188/207 = 91 %** (0.86–0.94) | **yes** |
| T3 | Services down after approvals: v12 ≤ `rule_segment`; v12 < full isolation in ≥ 70 % where full takes ≥ 1 down | real16 **19 vs 21**, 11/14 = 79 %; corpus **70 vs 126**, 129/139 = 93 % | **yes** |
| T4 | Guard: 0 burst flags on the 4 real detonations; ≥ 90 % of phase-10 naive injections still flagged | **0/4** (v9: 4/4); naive 398/500 vs v9 406/500 = 98 % of v9; path-aware 158 vs v9 61 | **yes** |
| T5 | Regression on v9 fresh sets: containment ≥ v9 and services down ≤ v9 | chains 253/253 vs 248, down 6 vs 9; random 392/412 vs 390, down 22 vs 24 | **yes** |
| T6 | Monotonicity in 100 % of multi-moment incidents | 502/502 | **yes** |
| T7 | Scale: median ≤ 2 s at 1,000 machines, 0 unsafe | 1,000 machines: median **2.2 ms**, p95 9.2 ms, max 25.7 ms, 0 unsafe, 50/50 auto | **yes** |
| T8 | Survival: 0 unsafe and 0 released hosts under solver timeout / crash / restart / flood | timeout 354/354 fallback, 0 unsafe, ≤ 307 ms; crash 354/354, 0 unsafe; 200 restarts, 0 released, audit chain intact; 1,000-alert flood 0 unsafe | **yes** |
| T9 | Immunity: same attack ≤ before in 8/8; similar ≥ 6/8; dissimilar identical in 8/8 | same **7/8**, similar 6/8, dissimilar 4/4 (4 incidents had no dissimilar variant) | **no** (same 7/8) |
| T10 | ML-DSA: 1,000/1,000 tamperings rejected; sign + verify median ≤ 50 ms | **1,000/1,000 rejected**; median **97.6 ms** (pure-Python library) | **partial** (timing) |
| T11 | Sensitivity ±50 % on real16: published | ×0.5 unchanged 12/16 (v9: 8/16); ×1.5 14/16 | published |
| D11 | Terminal gate mechanics | 9/9 checks (high-risk readmit refused, two-person on critical, same person twice refused, tamper detected) | **yes** |
| D8 | Kernel: twin agreement 100 %; 0 probe through an isolated host | 66/66 model = measured (16 real + 50 realistic); 0 leaks; twin 50/50 healthy committed, 50/50 faulty aborted; median 10 ms decision→first blocked attempt | **yes** |

Two targets not met, both published: T9 (one incident) and T10's timing clause.

## 2. How it was / how it is — the five policies on identical scenarios

Primary metric: services down **after every escalation is approved as written** (what a human team would actually lose).

| Set (n) | v12 | locked v9 | `rule_segment` | Wazuh-style AR | full isolation |
|---|---|---|---|---|---|
| **Real incidents 2016–2024** (16 moments) — auto contained | **16/16** | 5/16 | 16/16 | 16/16 | 16/16 |
| — services down after approvals | **19** | 24 | 21 | 42 | 42 |
| — fewer than full isolation (pool 14) | **11** | 9 | 10 | 0 | — |
| **Realistic generator** (894 moments, 3 sectors, never-isolate 0–30 %) — auto | **883** (99 %) | 780 (87 %) | 894 | 882 | 894 |
| — services down after approvals | **114** | 165 | 131 | 890 | 890 |
| — unsafe / silent | 0 / 0 | 0 / **6** | 0 / 0 | **12** / 0 | 0 / 0 |
| **v9 chains 7009** (253) — down after approvals | **6** | 9 | 12 | 273 | 273 |
| **v9 random 9004** (412) — down after approvals · unsafe | **22** · 0 | 24 · 0 | 33 · 0 | 288 · **182** | 288 · 0 |
| Decision time, median | 0.2–22 ms | 0.1–17 ms | < 0.02 ms | < 0.01 ms | < 0.01 ms |

What changed and why it matters:
- **The escalation wall is gone.** v9 pushed 11 of 16 real moments to a two-person decision; v12's safety floor (risk 9
  = isolate, hacked critical = segment) decides them itself, and the locked gate still judges every decision (0 unsafe).
- **The optimiser now earns its place.** In v11-pilot the one-line rule beat the optimiser (21 vs 24). With the floor
  underneath it, v12 beats the rule on every set: 19 vs 21 (real), 114 vs 131 (realistic), 6 vs 12, 22 vs 33. The
  honest statement is therefore: *floor + optimiser < rule < full isolation*, not "the optimiser alone".
- **Wazuh-style "isolate whatever alerts"** is unsafe without a safety rule: 182 REJECTED decisions on the v9 random set
  and 12 on the realistic set (it isolates never-isolatable devices), and it takes 20× more services down.
- **The guard stopped fighting reality**: 0/4 false flags on real detonations, same detection of naive injections,
  and 2.6× better detection of path-aware injections (158 vs 61), because a random path rarely stays link-connected.

### Per incident (real16): services down after approvals

| Moment | v12 | v9 | rule | full | v12 action |
|---|---|---|---|---|---|
| Bangladesh m1, m2 | 0 | 0 | 0 | 2 | isolate phished PC, segment SWIFT server |
| WannaCry m1 / m2 | 1 / 2 | 1 / 2 | 1 / 2 | 1 / 2 | isolate 4 / 8 encrypted hosts, segment MRI + pathology device |
| NotPetya m1 / m2 | 1 / 3 | 1 / 3 | 1 / 3 | 3 / 3 | isolate 5 / 10, segment DCs, gate, booking |
| Hydro m1 / m2 | 0 / **1** | 0 / 5 | 0 / 1 | 0 / 5 | m2: segment the DC instead of escalating "isolate dc" |
| Düsseldorf | **2** | 3 | 2 | 3 | isolate 10 encrypted servers, segment HIS |
| Colonial | 1 | 1 | 1 | 2 | isolate 10, segment finance_1 (PENDING two-person on finance_2/3) |
| HSE m1 … m5 | 0 / 0 / 1 / **1** / 3 | 0 / 0 / 1 / 1 / 3 | 0 / 0 / 1 / 2 / 3 | 0 / 1 / 2 / 3 / 9 | m1: one PC; m5: 12 isolations, 7 segmentations |
| Change Healthcare | **3** | 3 | 4 | 4 | isolate 5, segment the three claims platforms (PENDING on backup) |

The HSE row is the project's whole argument in one line: at the 31 March alert the engine isolates **one PC** and loses
nothing; at 04:36 on 14 May even the best decision loses 3 services and full isolation loses 9.

## 3. Open-source corpus (stage 1-b)

Converted by Claude from The DFIR Report, MITRE CTID Attack Flow / adversary emulation plans and CISA advisories with
the v11 rules; risks recomputed from the D2 table (`corpus_check.py`, manifest hashed). Results are appended here by
`phase17_v12.py` once the corpus is frozen — see `results/v12/v12.json["summaries"]["corpus"]`.

**Corpus:** 84 files written, **75 converted, 9 dropped** with reason (Telerik/IIS: advisory states no lateral
movement; JLR, Collins Aerospace, CDK, Ascension, Snowflake: no public path; menuPass, Blind Eagle, ToolShell: single
host). **207 detection moments** spanning 2013–2026: 27 DFIR Report cases (Ryuk, NetWalker, PYSA, Conti ×4, REvil,
Quantum ×3, Hive, BlueSky, Trigona, LockBit ×2, BlackSuit ×2, RansomHub, Lynx, Akira, …), 28 CTID Attack Flow /
emulation cases (Target 2013, JPMorgan 2014, Equifax, NotPetya, Marriott, SolarWinds, FIN13, Uber, Ivanti/UTA0178,
MITRE NERVE, Carbanak, FIN6, APT29, Sandworm, Wizard Spider …), 8 CISA/CERT advisories with a described victim path
(Log4Shell/Horizon ×2, Impacket/DIB, Volt Typhoon water utility, GeoServer FCEB 2025–26, DynoWiper Poland CHP 2026 …),
and 5 documented 2022–2025 incidents (Rackspace, 3CX, MGM, M&S …). Six services that listed > 2 replicas were split
mechanically (logged in `MANIFEST.json`); 70 host risks were re-derived from the D2 table.

| Corpus (207 moments) | v12 | locked v9 | `rule_segment` | Wazuh-style | full isolation |
|---|---|---|---|---|---|
| automatic containment | **188 (91 %, Wilson 0.86–0.94)** | 155 (75 %) | 207 | 206 | 207 |
| services down after approvals | **70** | 90 | 126 | 268 | 268 |
| unsafe / silent | 0 / 0 | 0 / 1 | 0 / 0 | 1 / 0 | 0 / 0 |
| escalations to humans | 19 | 77 | 0 | 0 | 0 |
| fewer services down than full isolation (pool 139) | **129 (93 %)** | 113 | 112 | 0 | — |

T2 (≥ 80 %) and T3 (v12 ≤ rule) **met on the corpus**. The 19 escalations are G3 by design: a host at risk 7–8
that is the only replica of a service (e.g. the Horizon server in AA22-320A, the aeronautical ServiceDesk in
AA23-250A, the Sandworm DC in the emulation) — the engine asks two people whether to lose that service, as
pre-registered. Caveat: DFIR Report anonymises victims (sector unknown), hosts are named by role, and the reports'
timeline markers stand in for defender detection moments.

## 4. Survival, recovery, immunity (phase18)

- **Solver killed or over budget** (354 scenarios): fallback to floor + rule within 200 ms budget → 0 unsafe, 0 silent,
  max 307 ms. **Solver crash**: same, max 1.9 ms.
- **Crash + restart** (200 cycles): state reloaded from the hash-chained log; 0 isolated hosts released; 0 broken chains.
- **1,000-alert flood** during an open recovery session: 0 unsafe; 7 hosts isolated at the end; audit intact;
  no never-isolatable device touched.
- **Recovery terminal** (`acrs-recover`): `readmit` of a host still at risk ≥ 7 refused; `readmit` after `restore`
  accepted; any command on a critical server needs a second approver; the same person approving twice is refused;
  unknown host refused; `close-incident` with open risk refused; audit tamper detected. 9/9.
- **Immunity**: after `close-incident` the path fingerprint installs permanent shields and a first-hop isolation rule.
  Replaying the **same** attack: contained at hop 1 in 8/8 and with ≤ services down in **7/8** — the miss is Change
  Healthcare, where the first hop is the Citrix portal that is itself a service replica, so isolating it at hop 1 costs
  the remote-access service (3 → 4). **Similar** attack (same technique chain, relabelled hosts): 6/8. **Dissimilar**
  attack: decision identical to the un-immunised engine in 4/4 (no over-blocking); 4 incidents had no generable
  dissimilar variant. T9 is **not met** as written; immunity ships **off by default** per the pre-registration, with the
  refinement "do not first-hop-isolate a service replica — segment it" left for a v13 pre-registration.

## 5. Kernel (sandbox_v12)

Real iptables on loopback, own chains, one atomic restore per decision. 16 real + 50 realistic detonations:
**66/66** model = measured, **0** probes through an isolated host, 1,693 probe checks; decision → first blocked
attacker attempt median **10 ms**, p95 118 ms. Twin: 50/50 healthy plans committed, 50/50 sabotaged plans aborted
(all caught at structure check), precheck median 11 ms.
Engineering finding from the first kernel run (23/66 mismatches): segmenting a *healthy* critical neighbour
(Amendment 1d) with a stateless `DROP hacked→server` also drops the replies to connections the healthy server opens
to the hacked host, silently killing its service. v12's executor blocks **NEW** connections only
(`-m conntrack --ctstate NEW`); the model's definition of a link ("can open new connections") is now what the kernel
enforces.

## 6. ML-DSA-65 (FIPS 204) over the certificate

Envelope = v9 certificate + risk-table hash + HMAC (locked) + ML-DSA-65 signature. 1,000 tamperings of seven kinds
(the five v9 kinds + signature bit-flip + re-signing with another key): **1,000/1,000 rejected**. Sign median 55 ms,
verify 14 ms, sign + verify median 97.6 ms (`dilithium-py`, pure Python, vendored under MIT because package registries
were unreachable from the session) — **the ≤ 50 ms clause is missed**; a C implementation (liboqs) is the known fix,
not attempted here. Signature 3,309 bytes, public key 1,952 bytes.

**v9 observation found on the way** (locked, published, not changed): on real incidents the v9 solver can place a
critical server in its *automatic* isolate set (gate: PENDING), and the v9 rate limiter (3 automatic isolations / 60 s)
keeps three of the equal-risk hosts in set-iteration order; when a critical server lands there, v9's own checker
**rejects the engine's own certificate** (Change Healthcare every run, Colonial some runs). Never seen on synthetic data.
v12 decides without the limiter and orders deterministically.

## 7. Limitations
1. Corpus and real-set conversions by Claude; networks partially reconstructed from public reports.
2. Service values from the D2 table applied to documented impact — a mapping, not a measurement.
3. T9 same-attack 7/8 and T10 timing missed (above).
4. "Outperforms" is claimed only against the four modelled policies on identical scenarios; no commercial EDR was run.
5. Immunity's similar/dissimilar variants are generated by a fixed rule, not taken from new incidents.

### ملخص عربي — كيف كان وكيف صار
**كان (v9 على 16 لحظة حقيقية):** 31% احتواء آلي، 11 تصعيد للبشر، 24 خدمة متوقفة بعد الموافقات، القاعدة البسيطة أفضل منه (21)،
الحارس يكذّب 4 هجمات حقيقية، والأوزان تقلب القرار في 8/16.
**صار (v12، نفس الحوادث، نفس البوابة المقفولة، نفس الثوابت):** **100%** احتواء آلي، **19** خدمة متوقفة (أقل من القاعدة 21 ومن
العزل الكامل 42)، 0 غير آمن، 0 صامت، الحارس 0/4 إنذار كاذب مع كشف أفضل 2.6× للحقن الذكي، الاستقرار 12/16، اتساق زمني
502/502، 1,000 جهاز في 2.2 ms، ارتداد آمن عند قتل المُحسِّن 354/354، 200 إعادة تشغيل بلا إطلاق أي جهاز، طرفية إنعاش كل
أمر فيها يمر على البوابة 9/9، المناعة 7/8 (نُشر الفشل، وتُشحن مطفأة افتراضيًا)، ML-DSA يرفض 1,000/1,000 تلاعب لكن أبطأ
من الهدف، والنواة الحقيقية 66/66 بصفر تسريب. وعلى 894 سيناريو واقعي: v12 114 خدمة مقابل القاعدة 131 وv9 165 ونمط Wazuh 890
مع 12 قرارًا غير آمن. الجملة الصادقة: **أرضية أمان + مُحسِّن < قاعدة بسيطة < عزل كامل** — والمُحسِّن وحده بدون الأرضية ما كان
يستحق.
