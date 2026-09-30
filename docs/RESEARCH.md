# ACRS: البحث والتجربة

هذا الملف هو المرجع العلمي للمشروع. كل رقم فيه يخرج من الكود، وليس مكتوبًا باليد. لإعادة إنتاج الأرقام:

```bash
cd backend
python -m research.experiment      # يكتب research/results/experiment.json
python -m research.e2e_timing      # يكتب research/results/e2e_timing.json  (حوالي دقيقة)
```

> **كل البيانات محاكاة (Simulated).** لم يتم لمس أي شبكة حقيقية.

---

## 1. Research Title

**Design and Evaluation of a Risk-Adaptive Cyber Containment Model Based on Threat Severity and Asset Criticality**

اسم المشروع: **ACRS: Adaptive Cyber Response System**

## 2. Abstract

أغلب أدوات الاستجابة الآلية تعطي كل جهاز مخترق الجواب نفسه: عزله عن الشبكة. هذا يوقف المهاجم، لكنه يوقف أيضًا خدمات المؤسسة نفسها إذا كان الجهاز قاعدة بيانات أو خادم هوية أو جهازًا طبيًا.

يقترح هذا البحث نموذج قرار حتميًا (Deterministic) ومفسَّرًا اسمه ACRS، يختار **أقل احتواء فعّال (Minimum Effective Containment)** بناءً على:
- شدة التهديد (Risk).
- الثقة في الدليل (Confidence).
- أهمية الأصل (Asset Criticality)، أي الـ Tier، ووجود بديل (Redundancy)، وهل هو جهاز سلامة (Safety-critical).

قارنّا ACRS بسياسة موحدة (Uniform) تعزل أي جهاز كليًا إذا تجاوز الخطر 60. استخدمنا نفس 40 سيناريو هجوم (42 حادثة) ونفس الاكتشاف ونفس حساب الخطر، واختلفت السياسة فقط.

**النتائج:**
- ACRS أخرج **20** جهازًا من الخدمة بدل **37**.
- سبّب **2** انقطاع خدمة حرجة بدل **7**.
- قطع قناة المهاجم في **36 من 41** هجومًا، تمامًا مثل السياسة الموحدة.
- لا توجد أي عتبة موحدة بين 50 و100 تحقق الهدفين معًا.

**الثمن:** جهد بشري موجَّه. شخص يؤكد التعافي في 16 حالة، وعزل Tier-0 الكامل يحتاج شخصين دائمًا.

## 3. Research Question

هل يستطيع قرار احتواء يوازن بين شدة التهديد وأهمية الأصل أن يعطّل أنظمة سليمة أقل من العزل الكامل الموحد، مع إيقاف الهجمات بنفس المعدل؟

> *Can a containment decision that weighs threat severity and asset criticality disrupt fewer healthy systems than uniform full isolation, while stopping attacks just as often?*

## 4. Hypothesis

السياسة المتكيفة ستُخرج أنظمة أقل من الخدمة، وتسبب انقطاعات حرجة أقل، دون أن تقل قدرتها على قطع المهاجم.

- **H0 (الفرضية الصفرية):** لا فرق في التعطيل، أو أن ACRS يقطع المهاجم أقل.
- **النتيجة:** رُفضت H0 في هذه المحاكاة.

## 5. Objectives

1. بناء ACRS كنموذج قرار قائم على قواعد (Rule-based) وقابل للتفسير.
2. اختباره أمام العزل الكامل الموحد على 40 هجومًا محاكى.
3. قياس التعطيل وقطع المهاجم والسرعة والجهد البشري.

## 6. Variables

| النوع | المتغير |
|---|---|
| **مستقل (Independent)** | سياسة الاحتواء: Uniform أو ACRS |
| **تابع (Dependent)** | عدد الأجهزة المعزولة، انقطاعات الخدمة الحرجة، أجهزة السلامة المعزولة، عزل Tier-0 بدون إنسان، عزل نشاط سليم، قطع قناة C2، قطع مسارات الانتشار، زمن الاحتواء، الجهد البشري |
| **ثابت (Controlled)** | نفس السيناريوهات، نفس محرك الاكتشاف، نفس حساب الخطر والثقة، نفس قائمة الأصول، نفس طريقة تحويل القرار إلى أوامر (`plan()`)، نفس قواعد القياس |

## 7. Methodology

1. **Detect:** 12 قاعدة اكتشاف على 8 أنواع من الحساسات.
2. **Analyze:** ربط الأحداث في نافذة 5 دقائق.
3. **Score risk:** 6 عوامل موزونة.
4. **Asset criticality:** Tier، ووجود بديل، وهل الأصل جهاز سلامة.
5. **Decide:** 9 قواعد مرتبة، بدون ذكاء اصطناعي.
6. **Contain:** مهلة 7 أو 15 أو 90 ثانية حسب الـ Tier.
7. **Verify:** بوابة من 9 فحوص.
8. **Recover:** عودة تدريجية للخدمة.

التجربة تغيّر الخطوة 5 فقط.

## 8. Experimental Design

- **النوع:** تجربة مضبوطة من ذراعين (Controlled two-arm experiment). كل حادثة تمر على السياستين بنفس المدخلات بالضبط.
- **القياس:** يُقرأ من قائمة الأوامر الفعلية التي يُنتجها `plan()` لكل قرار، وليس من اسم القرار. مثال: "قطع C2" يعني وجود أمر من نوع `BLOCK_C2` أو `RESTRICT_NETWORK` أو `ISOLATE_ASSET` أو `APPLY_MICROSEGMENTATION` أو `CLOUD_SG_UPDATE`.
- **الحتمية:** النظام Deterministic، لذلك التكرار يعطي نفس الرقم. `tests/test_research.py` يتأكد من ذلك.
- **تجارب إضافية:**
  - **Threshold sweep:** السياسة الموحدة بعتبات من 50 إلى 100، لمعرفة هل توجد عتبة واحدة تساوي ACRS.
  - **Criticality sweep:** نفس دليل الهجوم على 20 أصلًا مختلفًا.
  - **Decision matrix:** الخطر × نوع الأصل.
  - **E2E timing:** تشغيل الـ Orchestrator الحقيقي بمؤقتات حقيقية.

## 9. Baseline Definition

```python
def uniform_decide(...):
    if risk >= 60 or ransomware_fast_path:
        return FULL_ISOLATION, auto=True, approvals=0
    return MONITOR
```

- العتبة 60 هي نفسها `MEDIUM_FLOOR` في ACRS، حتى تكون المقارنة عادلة.
- السياسة الموحدة ترى نفس الخطر ونفس الثقة. الفرق الوحيد أنها لا تنظر إلى الأصل.

## 10. ACRS Model Definition

القواعد التسع بالترتيب (`app/engines/decision.py`):

| # | القاعدة | القرار |
|---|---|---|
| 1 | أصل غير معروف | تقييد عنوان الـ IP عند الحافة فقط |
| 2 | أصل لا يمكن عزله (طبي أو OT) | ضوابط تعويضية فقط (Compensating) |
| 3 | فدية (T1486/T1490) | احتواء قبل الثقة: Tier-0 تقييد طارئ، Tier-1 عزل جراحي، Tier-2 عزل كامل |
| 4 | الثقة أقل من 60% (مصدر واحد يُسقَّف عند 55%) | لا احتواء آلي |
| 5 | الخطر أقل من 60 | مراقبة |
| 6 | نافذة تغيير معتمدة | تقييد وانتظار تأكيد |
| 7 | الخطر فوق عتبة الـ Tier (Tier-0 = 95، Tier-1 = 90، Tier-2 = 85) | Tier-0 تقييد طارئ + شخصان للعزل الكامل، Tier-1 عزل جراحي (البديل يستمر)، Tier-2 عزل كامل |
| 8 | النطاق المتوسط | تقييد آلي، والأقوى يحتاج إنسانًا. Tier-0 مراقبة + شخصان |
| 9 | Circuit breaker | 5 احتواءات آلية أو أكثر في 10 دقائق توقف الآلية |

## 11. Metrics

| المقياس | التعريف |
|---|---|
| Hosts taken offline | أجهزة أُخرجت من الخدمة آليًا (عزل كامل أو جراحي أو تقييد طارئ) |
| Critical-service outages | جهاز Tier-0/1 بدون بديل، أو جهاز سلامة، أُخرج من الخدمة |
| Attacker channel cut | قناة C2 الخارجية حُجبت آليًا |
| Paths to critical systems cut | الجهاز لم يعد يستطيع فتح اتصالات جديدة نحو Tier-0/1 |
| Time to contain | من القرار حتى الاحتواء المُتحقَّق منه، بمؤقتات حقيقية وزمن أدوات محاكى |
| Human effort | ينتظر إنسانًا قبل الاحتواء / يؤكد إنسان بعد الاحتواء / موافقة شخصين لـ Tier-0 / آلي بالكامل |

## 12. Dataset / Simulation Design

- **40 سيناريو** في 8 فئات، تنتج **42 حادثة**:

  | الفئة | عدد الحوادث |
  |---|---|
  | ransomware | 7 |
  | network_c2 | 6 |
  | identity | 5 |
  | initial_access | 5 |
  | edge_cases | 5 |
  | cloud_k8s | 5 |
  | web_api | 5 |
  | data_insider | 4 |

- **الحوادث:** 41 خبيثة وحادثة واحدة سليمة (`erp_change_window_fp`، وهي الحقيقة المرجعية لنشاط مشروع).
- **20 أصلًا:**
  - 4 Tier-0: DC-01، DC-02، K8S-CP-01، PKI-CA-01.
  - 10 Tier-1: منها MRI-CTRL-02 كجهاز طبي لا يُعزل، وخوادم لها توأم مثل HR-APP-01/02.
  - 6 Tier-2: أجهزة مستخدمين وخوادم بناء.
- **الحوادث حسب الـ Tier:** Tier-0 = 5، Tier-1 = 19، Tier-2 = 17، غير معروف = 1.
- **الخطر:** يتراوح بين 40 و99.
- **عدد الحساسات لكل حادثة:** 1 إلى 4.

## 13. Charts (عنوان كل رسم هو النتيجة)

| # | عنوان الرسم | النوع | البيانات |
|---|---|---|---|
| R1 | ACRS takes far fewer systems offline | أعمدة أفقية مجمعة | 20/37، 2/7، 0/4، 0/1، 0/1 |
| R2 | It cuts the attacker off just as often | أعمدة أفقية مجمعة | C2: 36/36، مسارات: 30/36 |
| R3 | No single uniform threshold achieves both | نقاط وخط (Frontier) | العتبات 50–100 مقابل ACRS |
| R4 | Response chosen for each of the 42 incidents | عمود مكدّس | Uniform: 5 مراقبة / 37 عزل كامل. ACRS: 4 / 18 / 13 / 7 |
| R5 | How much a person had to do | عمود مكدّس | Uniform: 5 / 37. ACRS: 4 / 16 / 20 / 2 |
| R6 | 4 بطاقات أرقام | Stat tiles | 0.31 ث، 0.30 ث، 2 µs، صفر مهلة فائتة |
| I1 | Uniform response vs. ACRS | مخطط تدفق | — |
| I2 | The same attack evidence on 20 different machines | شبكة مربعات | نفس الدليل، والخطر من 77 إلى 99 |
| I3 | ACRS decision rules at 90% confidence | مصفوفة Risk × Criticality | 4 أصول × 5 نطاقات خطر |

**Threshold sweep (العتبة ← انقطاعات، C2 مقطوع):**

| العتبة | الانقطاعات | C2 مقطوع |
|---|---|---|
| 50 | 7 | 38 |
| 55 | 7 | 37 |
| 60 | 7 | 36 |
| 65 | 7 | 34 |
| 70 | 7 | 33 |
| 75–80 | 5 | 32 |
| 85 | 5 | 24 |
| 90 | 2 | 18 |
| 95 | 2 | 10 |
| 100 | 1 | 7 |
| **ACRS** | **2** | **36** |

## 14. Chart Captions

- **R1:** Critical-service outage: a Tier-0/1 system with no backup, or a safety device, taken offline. ACRS still caused 2 (ERP-DB-01, PKI-CA-01).
- **R2:** Out of 41 malicious incidents. The 6 fewer paths cut are by design: 4 Tier-0 servers held at restriction until two people approve, 1 medical device, 1 single-sensor alert.
- **R3:** Each labelled point is the uniform policy at that risk threshold. Getting down to 2 outages needs a threshold of 90, which cuts off only 18 attacks. ACRS: 2 outages, 36 attacks cut off.
- **R4:** Targeted isolation: the machine is cut off or restricted while its twin keeps the service running.
- **R5:** 20 = 16 recoveries a person confirms + 4 Tier-0 servers awaiting two approvals. The 2 "person first" cases: the harmless change-window alert and a single-sensor alert.
- **I2:** Risk ranged 77 to 99 for identical evidence. The medical device got network controls only; the ERP server in an approved change window was restricted pending confirmation.
- **I3:** If only one sensor sees the activity, confidence is capped at 55% and no isolation happens until a person approves.

## 15. Innovation Statement

> Automatic isolation already exists in commercial security tools. The contribution of ACRS is a deterministic, explainable model that sets how strongly to contain from threat severity, confidence and asset criticality, and a controlled test of that model against uniform isolation.

**لا ندّعي أننا "اخترعنا العزل".** أدوات EDR وSOAR التجارية فيها عزل جهاز وPlaybooks.

ما يضيفه ACRS:
1. نموذج قرار صريح يمكن فحصه واختباره، بقواعد مرتبة وأسباب مكتوبة لكل قرار.
2. مفهوم Minimum Effective Containment كقاعدة قابلة للقياس.
3. تجربة مضبوطة تقارنه بالبديل الموحد.

**مكونات مبنية أخرى:**
- Surgical isolation مع توأم يعمل.
- قاعدة الشخصين (Two-person rule) لـ Tier-0.
- بوابة من 9 فحوص قبل التعافي.
- Circuit breaker ضد العزل الجماعي.
- ذاكرة استجابة محدودة بالسياسة.
- خريطة احتواء حية.

## 16. Impact Statement

> Hospitals keep clinical devices running during an incident, small security teams get safe automation with clear reasons, and the identity and certificate services everything depends on are not switched off by a single alert.

**في السياق السعودي:** يتوافق مع توجه ضوابط الهيئة الوطنية للأمن السيبراني (ECC) نحو إدارة الحوادث وحماية الأصول الحساسة. لم نختبر الامتثال رسميًا؛ هذه صلة مفاهيمية فقط.

## 17. Limitations

1. بيانات صناعية: 40 سيناريو على 20 أصلًا محاكى.
2. أثر الخدمة مُقدَّر من نموذج الأصول، ولم يُقَس على خدمات حية.
3. أوزان الخطر محددة بالتصميم، ولم تُعايَر على حوادث حقيقية.
4. **نفس الشخص كتب السيناريوهات والقواعد، وهذا قد يميل لصالح ACRS.** (هذا أهم قيد)
5. زمن الاحتواء يعتمد على أدوات محاكاة بزمن واقعي، وليس على أدوات حقيقية.
6. ACRS يقطع مسارات انتشار أقل (30 مقابل 36). هذا مقصود لحماية Tier-0، لكنه تنازل حقيقي.

## 18. Future Work

- **Feasibility:** تجربة قراءة فقط على تنبيهات حقيقية: يقرر ويسجل ولا ينفذ، ثم تُضبط الأوزان.
- **Independent test:** سيناريوهات هجوم يكتبها أشخاص آخرون، وتُشغَّل بدون تعديل القواعد.
- **Sustainability:** نسخة أساسية مجانية، مع موصلات ودعم مدفوع للمستشفيات والشركات الصغيرة. (المشروع ليس مفتوح المصدر؛ انظر LICENSE)
- ربط أداة EDR حقيقية واحدة في بيئة اختبار.

## 19. References

1. NIST SP 800-61 Rev. 3 (2025). *Incident Response Recommendations and Considerations for Cybersecurity Risk Management.*
2. NIST SP 800-207 (2020). *Zero Trust Architecture.*
3. MITRE ATT&CK, Enterprise Matrix. The MITRE Corporation. (T1486 Data Encrypted for Impact, T1490 Inhibit System Recovery)
4. National Cybersecurity Authority (NCA). *Essential Cybersecurity Controls (ECC).*
