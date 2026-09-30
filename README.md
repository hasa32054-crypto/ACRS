# ACRS — Adaptive Cyber Response System


**Live website:** https://hasa32054-crypto.github.io/ACRS/

> © 2026 حسان عبدالله الينبعاوي — جميع الحقوق محفوظة. يُمنع النسخ أو الاستخدام دون إذن كتابي. انظر [LICENSE](LICENSE).

> ⚠️ **Simulation Only — No Real Network Operations.**
> لا يوجد كود هجومي، ولا اتصال بأي شبكة أو أداة أمنية حقيقية. كل «أمر عزل» محاكاة تُسجَّل في سجل التدقيق.

**المبدأ الحاكم:** نعزل الجزء المصاب، لا المؤسسة كلها.

الإصدار الكامل (المراحل A–D):

- **A — الخلفية:** State Machine بـ 14 مرحلة، مؤقتات 7/15/90/60 ثانية، Emergency Queue، JWT + RBAC بأربعة أدوار،
  PostgreSQL + Alembic، Redis + WebSocket.
- **B — الذكاء التشغيلي:** Response Memory (تطابق ≥96%، يعتمده مهندس، لا يتجاوز سياسة المستوى)، تقرير كل ساعة،
  و**40 سيناريو في 8 فئات** بنمطي نجاح وفشل.
- **C — وحدة التحكم:** 8 صفحات، عربي RTL افتراضيًا مع الإنجليزية، داكن/فاتح، تحديث مباشر عبر WebSocket.
- **D — الجودة:** 42 اختبارًا للمحركات ودورة الحياة + 8 اختبارات API + 11 اختبار وحدة للواجهة، Makefile، وهذا الدليل.

---

## التشغيل على Windows (PowerShell)

```powershell
Expand-Archive -Path "$HOME\Downloads\acrs-v2.zip" -DestinationPath "C:\Users\PC\Desktop\ACRS2" -Force
cd C:\Users\PC\Desktop\ACRS2
Copy-Item .env.example .env
notepad .env                      # غيّر كل قيمة تبدأ بـ change-me
powershell -ExecutionPolicy Bypass -File .\acrs.ps1 up
```

ثم افتح **وحدة التحكم**: http://localhost:8080 (أو `acrs.ps1 open`). توثيق الـ API: http://localhost:8000/docs

> أول بناء يستغرق بضع دقائق: صورة الواجهة تنزّل حزم Node وتشغّل اختباراتها، وصورة الخلفية تشغّل اختبارات المحركات.

تجربة سيناريو ومشاهدة مراحله مباشرة في الطرفية:

```powershell
powershell -ExecutionPolicy Bypass -File .\acrs.ps1 demo tier1_c2_hr
powershell -ExecutionPolicy Bypass -File .\acrs.ps1 demo tier1_c2_hr failure
```

الاختبارات الكاملة داخل الحاوية (محركات + دورة الحياة + المرحلة B + API):

```powershell
powershell -ExecutionPolicy Bypass -File .\acrs.ps1 test
```

على Linux/macOS: `cp .env.example .env && make up`، ثم `make test` و`make test-ui`.

> نسخة v1 تبقى في مجلدها وتعمل كما هي. أوقفها أولًا (`docker compose down` داخل مجلد v1) لأن المنفذ 8000 مشترك.

## الحسابات التجريبية

كلها تستخدم كلمة المرور `ACRS_SEED_PASSWORD` من ملف `.env`:

| المستخدم | الدور | يستطيع |
|---|---|---|
| `viewer` | viewer | القراءة فقط |
| `analyst`, `analyst2` | analyst | تشغيل السيناريوهات، الموافقة، التأكيد، Rollback |
| `connector` | analyst | إرسال الأحداث إلى `/events/ingest` |
| `engineer` | engineer | ما سبق + أوامر Engineer Mode + Change Window |
| `admin` | admin | ما سبق + إعادة ضبط العرض |

قاعدة الشخصين لـ Tier-0 تحتاج مستخدمَين مختلفين (مثلًا `analyst` ثم `analyst2`).

في Swagger: نفّذ `POST /api/v1/auth/login`، انسخ `access_token`، ثم اضغط **Authorize** والصقه.

## الـ API (المسار الأساسي `/api/v1`)

| الطريقة | المسار | الدور الأدنى |
|---|---|---|
| POST | `/auth/login` | — |
| POST | `/events/ingest` | analyst (مع Rate Limiting) |
| GET | `/incidents`, `/incidents/{id}`, `/emergency-queue` | viewer |
| POST | `/incidents/{id}/approve` `/confirm` `/rollback` | analyst |
| POST | `/incidents/{id}/commands` | engineer |
| GET | `/assets`, `/assets/{id}` | viewer |
| PATCH | `/assets/{id}/change-window` | engineer |
| GET/POST | `/sim/scenarios`, `/sim/scenarios/{id}/run` | viewer / analyst |
| GET | `/memory/patterns` | viewer |
| POST | `/memory/patterns/{id}/approve` `/reject` | engineer |
| GET | `/reports/kpis?hours=24`, `/reports/hourly` | viewer |
| POST | `/reports/hourly/generate` | analyst |
| GET | `/health`, `/system/policy`, `/audit` | — / viewer / analyst |
| WS | `/ws/incidents?token=…`, `/ws/incidents/{id}?token=…` | أي دور |

## وحدة التحكم (8 صفحات)

| الصفحة | ما تعرضه |
|---|---|
| مركز القيادة | **شريط الاستجابة الذاتية** (رصد ← تحليل ← احتواء ← تحقق ← تحصين ← استعادة ← تعلّم ← تم تحييد التهديد) مع عدّاد المهلة، مؤشرات 24 ساعة، خريطة الأصول حسب المستوى، والأحداث المباشرة |
| الحوادث | كل الحوادث مع تصفية حسب الحالة؛ صفحة الحادثة تعرض المراحل الـ14، المؤقت، تفسير الخطورة والثقة عاملًا بعامل، مصدر الهجوم ومسار الدخول، الإجراءات، فحوص التحقق، سلسلة الأدلة، الموافقات، ووضع المهندس |
| طابور الطوارئ | المكان الوحيد الذي يلزم فيه تدخل بشري |
| الأصول | الأصول العشرون حسب المستوى، مع منحنى الخطورة وتبديل نافذة التغيير (مهندس) |
| مختبر المحاكاة | 40 سيناريو في 8 فئات، زرّا «نجاح» و«فشل» لكل سيناريو |
| ذاكرة الاستجابة | الأنماط المقترحة والمعتمدة، واعتمادها أو رفضها (مهندس فقط) |
| التقارير | مؤشرات آخر 24 ساعة، وتقارير كل ساعة، وزر «إنشاء تقرير الآن» |
| سجل التدقيق | كل إجراء: من، ماذا، على ماذا، لماذا، ومتى |

زر **English/العربية** وزر **الوضع الفاتح/الداكن** في الشريط العلوي يغيّران الواجهة فورًا، وتُحفظ الاختيارات في المتصفح.
اللغة متسقة بالكامل: في العربية تُترجم كل النصوص التي يولّدها الخادم أيضًا (أسباب القرار، أسماء الهجمات، الإجراءات، الفحوص،
سجل التدقيق، رسائل الأخطاء)، وفي الإنجليزية تظهر أسماء مقروءة بدل الرموز التقنية. اختبار `tr.test.ts` يمر على كل النصوص التي
تولّدها المحركات في السيناريوهات الأربعين ويفشل إن بقيت كلمة غير مترجمة.

**خريطة العزل** (في صفحة كل حادثة، وتتحدث لحظيًا): تعرض الجهاز المصاب، والمهاجم، والجدار الناري، والأنظمة التي كان يمكن
أن يصل إليها (الأنظمة المعتمدة عليه والأجهزة الداخلية التي اتصل بها)، والخادم البديل في العزل الجراحي، وجهاز التحقيق. كل مسار
يظهر نشطًا أو مهددًا أو **مقطوعًا ✕**، وفوقها حكم واضح: تم العزل، أو تقييد فقط، أو **لم يتم العزل** (في سيناريوهات الفشل)،
أو عاد للشبكة بعد التنظيف. على الجوال تظهر تحتها قائمة مقروءة بكل مسار وحالته.

## السيناريوهات وحالات الحافة

المختبر يحتوي 40 سيناريو: الشبكة وC2 (6)، الهوية (5)، برامج الفدية (5)، السحابة وKubernetes (5)،
الوصول الأولي (5)، الويب وAPI (5)، البيانات والتهديد الداخلي (4)، حالات الحافة (5).
كل سيناريو يعمل بنمط **نجاح** أو **فشل** (تعطل أداة العزل، أو فشل بوابة التحقق، أو عودة المؤشر).

| السيناريو | ما يحدث | حالة الحافة |
|---|---|---|
| `mri_non_isolatable` | ضوابط تعويضية فقط، ثم توقف لانتظار الجهة المالكة | 1 |
| `erp_change_window_fp` | خصم 15 نقطة، لا عزل تلقائي، طلب تأكيد، ثم Rollback | 2 |
| `tier1_c2_hr` + فشل | أداة العزل معطلة، إعادة محاولة حتى 15s، ثم Emergency Queue | 3 |
| `cloud_workload` + فشل | فشل Verification Gate مرتين، ثم Emergency Queue | 4 |
| `ioc_return_hr` | المؤشر يعود أثناء المراقبة، ثم إصلاح جديد (دورة 2) | 5 |
| `tier2_workstation` + فشل | تجاوز 90 ثانية، ثم Emergency Queue | 6 |
| `tier0_dc_cred_dump` | احتواء تقييدي خلال 7s، العزل الكامل بموافقة شخصين | 7 |
| `tier1_c2_hr` | عزل جراحي، الخادم الشقيق يواصل الخدمة | 8 |
| `tier2_workstation` | عزل كامل وإغلاق بدون أي تدخل بشري | 9 |
| `response_memory_repeat` | انظر الخطوات أدناه | 10 |

**تجربة حالة الحافة 10 (Response Memory):**

1. شغّل `response_memory_repeat` (نجاح). الخطورة متوسطة، فيقيّد النظام الجهاز ويتوقف منتظرًا تأكيدك.
2. اضغط «تأكيد ومتابعة الأتمتة». تُغلق الحادثة ويظهر «حُفظ نمط استجابة للمراجعة».
3. سجّل الدخول كـ `engineer`، وافتح «ذاكرة الاستجابة»، واضغط «اعتماد النمط».
4. شغّل السيناريو نفسه مرة ثانية. يظهر «طُبّق نمط استجابة معتمد» وتكتمل الحادثة **بلا توقف**، لأن الاستجابة نفسها سبق أن تحقق منها مهندس.

الذاكرة لا ترفع مستوى العزل، ولا تحوّل قرارًا بشريًا إلى آلي، ولا تعمل على Tier-0 أبدًا.

**التقرير الساعي:** يُنشأ تلقائيًا كل ساعة (الفترة تتبع `ACRS_TIME_SCALE`) ويحتوي نسبة الاحتواء الآلي،
MTTD، وMTTC (متوسط وp50 وp95 ونسبة ما هو ضمن 60 ثانية)، والإيجابيات الكاذبة، والتصعيدات، واستمرارية الأعمال، مع توصيات بالعربية والإنجليزية.

## البنية

```
backend/app/
  engines/    detection, correlation, risk, decision, response, recovery, evidence, entry,
              threat_intel, state_machine, policy, types   (Python خالص، لا يعتمد على مكتبات)
  workers/    lifecycle.py   (State Machine + المؤقتات + الـ Watchdog)
  services/   sql_store, memory_store, publisher (Redis), ratelimit, simulators, seed_data
  api/        auth, events, incidents, assets, sim, system, ws
  core/       config, security (JWT + RBAC + PBKDF2), logging
  db/         models (SQLAlchemy 2)
  engines/memory.py, engines/reports.py     (المرحلة B: الذاكرة والتقرير الساعي)
backend/alembic/versions/0001_initial.py   (SQL صريح + triggers للـ append-only والـ WORM)
backend/alembic/versions/0002_memory_reports.py
frontend/src/
  lib/        i18n (عربي/إنجليزي)، format، api، types   + اختبارات الوحدة
  app/        context (اللغة، الوضع، المستخدم)، router، hooks (WebSocket + ناقل أحداث داخلي)
  components/ Shell، ResponseBar، Lifecycle، Countdown، FactorTable، ui
  pages/      CommandCenter، Incidents، IncidentDetail، Assets، Lab، Memory، Reports، Audit، Login
frontend/nginx.conf                          (يمرّر /api و/ws إلى الخلفية)
docs/ARCHITECTURE.md                        (المخططات، حدود الثقة، القرارات المتفق عليها)
```

## ما تم التحقق منه وما لم يتم

- **الخلفية:** 42 اختبارًا للمحركات ودورة الحياة والمرحلة B تنجح (منها تشغيل الـ40 سيناريو كاملة بنمطي النجاح والفشل،
  وحالة الحافة 10)، وتُشغَّل تلقائيًا أثناء بناء صورة الخلفية.
- **الواجهة:** 11 اختبار وحدة تنجح (تطابق مفاتيح العربية والإنجليزية، مراحل الشريط، التنسيق، الصلاحيات، التوجيه)،
  وتُشغَّل أثناء بناء صورة الواجهة. الصفحات الثماني عُرضت في متصفح Chromium ببيانات حقيقية من المحركات،
  بالعربية والإنجليزية، داكن وفاتح، وعلى شاشة جوال 390px، بلا أي خطأ JavaScript.
- **PostgreSQL:** اختبارات الـ API (`tests/test_api.py`) تعمل على مخزن داخل الذاكرة. الذي يغطي PostgreSQL الحقيقي هو
  `tests/test_sql_integration.py`: ينشئ قاعدة منفصلة `acrs_test`، ويطبّق الـ Migrations، ويشغّل دورات كاملة عبر كل دوال القاعدة
  دون أن يلمس بياناتك. `acrs.ps1 test` يشغّل كل ذلك معًا.
- **Lighthouse ≥ 90:** الواجهة بُنيت لتحقيقه (HTML دلالي، lang/dir صحيحان، تباين ألوان، تركيز مرئي، احترام تقليل الحركة،
  حزمة صغيرة بلا مكتبات رسوم)، لكن القياس نفسه تجريه أنت: Chrome ← DevTools ← Lighthouse على http://localhost:8080.

## البحث والتجربة (Research)

تجربة مضبوطة تقارن ACRS بسياسة العزل الكامل الموحد على نفس الـ40 سيناريو. التفاصيل كاملة
في [docs/RESEARCH.md](docs/RESEARCH.md).

```bash
cd backend
python -m research.experiment        # الأرقام كلها -> research/results/experiment.json
python -m research.e2e_timing        # زمن الاحتواء بالمؤقتات الحقيقية -> research/results/e2e_timing.json
python -m research.e2e_repeat 5      # نفس القياس 5 مرات (المؤقتات تتذبذب) -> research/results/e2e_repeats.json
python -m research.export_evidence   # ملف لكل حادثة يعدّه أي شخص بيده -> research/results/per_incident.csv + summary.csv
python -m research.learning         # تجربة التعلّم: 8 جولات مع خدع المهاجم -> research/results/learning.json
sudo python -m research.real_lab     # معمل حقيقي: قرارات ACRS تُنفَّذ بجدار حماية Linux (iptables) على اتصالات TCP حقيقية -> research/results/real_lab.json
python -m pytest tests/test_research.py
```

كل البيانات محاكاة، وكل رقم في الموقع والورقة يُقرأ من ملفات النتائج مباشرة.

---

## الحقوق

© 2026 حسان عبدالله الينبعاوي (Hassan Abdullah Alyenbawi). جميع الحقوق محفوظة.
هذا العمل ليس مفتوح المصدر. شروط الاستخدام كاملة في ملف [LICENSE](LICENSE).
