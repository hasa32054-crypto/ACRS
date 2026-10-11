# Next research question (decided 2026-10-11, after v6)

**Decision by the project owner:** the v6 result stays as it is. H1 is **not supported** on attack chains
(containment ratio 0.56 vs the pre-registered 0.80). No weight is changed and the 0.80 threshold is not lowered
to make the result look successful.

**Next question (v7, to be pre-registered before any work):**
How can Q-ACRS contain more attacks that reach critical servers (database, domain controller) **without**
taking services down and **without** giving up the two-person rule, and how much human workload does that remove?

Starting points, none tested yet:
- Graded actions for critical servers between "restrict" and "isolate" (for example, block only the attacker's
  channels and new outbound connections from the server, keep inbound service traffic).
- Measuring containment and human workload on the same attack-chain generator (seed 7007 is now used; a fresh
  seed must be fixed in the v7 pre-registration).
- The exploratory v6 finding (fully automatic containment 164 vs 119) becomes a pre-registered hypothesis here,
  tested on new data only.

### بالعربي

قررنا إبقاء نتيجة v6 كما هي: H1 لم تتحقق على سلاسل الهجوم (0.56 مقابل 0.80)، ولن نغيّر الأوزان ولن نخفّض الحد.
سؤال البحث التالي: كيف يحتوي Q-ACRS هجمات تصل إلى الخوادم الحرجة دون إيقاف الخدمات ودون التخلي عن قاعدة الشخصين،
وكم يخفّف ذلك من عبء القرار البشري؟ يُثبَّت تعريفه مسبقًا ويُختبر على بيانات جديدة فقط.
