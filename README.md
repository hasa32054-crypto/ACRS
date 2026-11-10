<div dir="rtl">

# ACRS

**Automated Compromise Response System**

## أوقفنا الهجوم، وبقيت الخدمة شغّالة

مثل رجل الإطفاء: يُغلق الغرفة التي فيها الحريق، ولا يقطع الكهرباء عن المستشفى كله.

**صفحة النتائج:** https://hasa32054-crypto.github.io/ACRS/  
**البوستر كاملاً:** [ACRS_poster.pdf](ACRS_poster.pdf)

## أهم النتائج

| النتيجة | الرقم |
|---|---|
| خدمات توقفت (بدل 273 مع العزل الكامل، 253 سلسلة هجوم) | **6** |
| نسبة الاحتواء مقارنة بالعزل الكامل (الهدف 80%، 259 سلسلة) | **97.7%** |
| قرارات غير آمنة | **0** |
| خدمات توقفت على 75 حالة من تقارير هجمات منشورة (بدل 268) | **70** |

## المشكلة

- في هجوم WannaCry عام 2017 تأثرت 80 جهة صحية بريطانية، و46 منها لم تكن مصابة أصلاً [1].
- أُلغي أكثر من 19,000 موعد طبي بسبب الهجوم [1].
- هجمات الفدية على المستشفيات تضاعفت بين 2016 و2021 [2].
- الحل المعتاد هو العزل الكامل: يوقف الهجوم، ويوقف الخدمة معه.

**سؤال البحث:** كيف نوقف الهجوم دون أن نوقف الخدمة؟

## الفرضيات (سُجّلت في Git قبل التجارب)

| | الفرضية | النتيجة | |
|---|---|---|---|
| H1 | احتواء ≥ 80% من العزل الكامل | 97.7% (شبكة المصنع 0.792) | ✅ |
| H2 | 0 قرارات غير آمنة | 0، وتحقّق رسمي من 5 خصائص سلامة بـ HiGHS [6]، و6,002 فحص على جدار حماية لينكس | ✅ |
| H3 | قطع المهاجم في أقل من 50 ms | 118 ms على 66 حالة واقعية، و41 ms على التركيبية | ❌ |
| H4 | أفضل من العشوائي على حاسوب IBM الكمّي | 3-23× على 11 مسألة (حتى 16 كيوبت) من شبكة 240 جهازاً [7]، دون ادعاء تفوّق كمّي | ✅ |
| H5 | تنبيه مزيّف لا يوقف أي خدمة | تنبيهات مزيّفة على 1-3 أجهزة لم توقف أي خدمة | ✅ |

## المراجع

<div dir="ltr">

1. National Audit Office. (2017). *Investigation: WannaCry cyber attack and the NHS* (HC 414).
2. Neprash, H. T., et al. (2022). Trends in ransomware attacks on US hospitals, clinics, and other health care delivery organizations, 2016-2021. *JAMA Health Forum, 3*(12), e224873.
3. National Cybersecurity Authority. (2024). *Essential Cybersecurity Controls (ECC-2:2024).*
4. Lucas, A. (2014). Ising formulations of many NP problems. *Frontiers in Physics, 2*, 5.
5. Sha, L. (2001). Using simplicity to control complexity. *IEEE Software, 18*(4), 20-28.
6. Huangfu, Q., & Hall, J. A. J. (2018). Parallelizing the dual revised simplex method. *Mathematical Programming Computation, 10*, 119-142.
7. Javadi-Abhari, A., et al. (2024). Quantum computing with Qiskit. *arXiv:2405.08810.*

</div>

---

الكود المصدري غير منشور. © حقوق محفوظة

</div>
