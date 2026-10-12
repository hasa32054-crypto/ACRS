# Blind test of HASSAN v9 — pre-registration (scenarios written in plain Arabic by an independent author)

**Written:** 2026-10-12, before the converter, the runner or any blind scenario exists; committed alone.

## Why
Every scenario so far came from generators written by the developer. The blind test asks whether the results hold on
attacks written by someone who has never seen a HASSAN decision.

## Who writes
- One or more people other than the developer: a teacher, an IT or security professional, or a colleague.
- They are chosen by the student after the supervisor approves.
- The developer and AI tools never write, edit or suggest scenarios.
- The author never sees a HASSAN decision before the run.
- Recorded in the file: author role (a name is optional), date, `consent_to_publish`, and
  `saw_hassan_decisions_before_writing` = false.

## How scenarios are written
- The author types each attack in plain Arabic, for example «فدية دخلت من جهاز الاستقبال عبر البريد ووصلت لقاعدة
  البيانات».
- A **rule-based converter**, `nl_attack.py`, turns the text into a scenario: compromised machines and a risk from 1 to 10
  for each.
  - The converter is fixed and locked together with the engine **before any scenario exists**.
  - It uses no AI model, and the same text always gives the same scenario.
  - Its rules cover:
    - machine names and roles in Arabic;
    - the attack path along network links, from the entry machine to the target;
    - risk from the attack type, unless the author states a risk explicitly.
- The author sees the converter's reading of each attack: «فهمتُ هجومك هكذا…».
  - The author accepts it, or rewrites the text until the reading matches the intent.
  - The author can also pick machines directly from a numbered list.
  - Only scenarios the author accepted are saved.
- Network: **Hospital-60**, the 60-machine hospital network in `realism_v8.py`. Its Arabic guide lists every machine, role and
  link.
- Target size: 20–40 scenarios. Fewer are allowed and will be reported with wider intervals. Variety is asked for in
  the guide: entry points, targets, attack types, and single or multiple attack paths.

## How it runs
1. `LOCK_blind_v9.json` stores the SHA-256 of the engine, rules, converter and runner. It is written before any scenario
   exists. If any locked file changes, the run refuses.
2. The author's file is committed to GitHub unchanged before the run. The commit time proves it existed first.
3. The run happens **once**. A second run refuses, unless `--allow-rerun` is passed, and that is logged.
4. Every result is kept and published, including invalid scenarios and failures. Nothing is tuned afterwards. Any
   change made after seeing these results becomes a new version and is tested on new data.

## Measures and targets (as in v7/v9)
For each scenario, HASSAN v9 (EngineV9) and safe full isolation are compared on the same scenario.

| Measure | Target |
|---|---|
| Unsafe decisions (a never-isolate machine isolated, or a critical server isolated automatically) | 0 |
| Silent failures | 0; Wilson 95% interval reported |
| Services down: HASSAN vs safe full isolation | HASSAN fewer; one-sided Wilcoxon reported if n ≥ 10 |
| H1 containment ratio vs safe full isolation | ≥ 0.80 |
| Escalation rate | reported, no target |
| Decision time | reported (median and p95) |
| Converter acceptance | share of texts the author accepted on the first reading — reported, measures the converter not HASSAN |

Small samples are reported as they are, with intervals. With 30 scenarios and 0 silent failures, the 95% upper bound is
about 11%. That is stated, not hidden.

### ملخص عربي
شخص غير المطوّر يكتب هجمات بالعربية العادية. محوّل بقواعد ثابتة، مقفل قبل وصول أي سيناريو، يحوّل كل نص إلى سيناريو،
والكاتب يؤكد الفهم بنفسه. يُشغَّل HASSAN v9 مرة واحدة، وتُنشر النتائج كما هي، ولا يُعدَّل شيء بعدها.

## Amendment 1 (2026-10-12, before any blind tool or scenario exists)
The text converter is **dropped**. The author builds each scenario by **picking machines from a numbered list**
(Arabic name and role of every Hospital-60 machine, with its links) and giving each a risk 1–10, plus a short free-text
description that is stored for the record only and never parsed. Everything else is unchanged: independent author,
code locked before any scenario exists, file committed before the run, one run, all results published.
The "converter acceptance" measure is removed.
