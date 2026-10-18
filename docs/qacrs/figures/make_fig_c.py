# Figure 3: engineering drawing of the system — the "رسم هندسي" the teacher asked for: blocks, interfaces, what is
# measured at each interface, and where the three test benches (groups A/B/C/D) plug in.
exec(open('make.py').read().split('rows1=')[0])   # reuse HEAD + colours
W=1100; H=560
s=f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}"><rect width="{W}" height="{H}" fill="{BG}"/>'
s+=f'<text x="{W-20}" y="34" direction="rtl" text-anchor="start" font-size="21" font-weight="600" fill="{INK}">شكل 3: الرسم الهندسي لـ ACRS — المكوّنات، الواجهات، وما يُقاس عند كل واجهة</text>'
def box(x,y,w,h,title,sub,hl=False):
    global s
    s+=f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="8" fill="{"#EAF1FD" if hl else "#F4F5F5"}" stroke="{BLUE if hl else GRAY}" stroke-width="{2 if hl else 1.2}"/>'
    s+=f'<text x="{x+w/2}" y="{y+24}" direction="rtl" text-anchor="middle" font-size="15" font-weight="600" fill="{INK}">{title}</text>'
    for i,line in enumerate(sub):
        s+=f'<text x="{x+w/2}" y="{y+44+i*17}" direction="rtl" text-anchor="middle" font-size="12.5" fill="{INK2}">{line}</text>'
def arrow(x1,y1,x2,y2,label=""):
    global s
    s+=f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{INK2}" stroke-width="1.6" marker-end="url(#a)"/>'
    if label: s+=f'<text x="{(x1+x2)/2}" y="{(y1+y2)/2-7}" direction="rtl" text-anchor="middle" font-size="12" fill="{INK2}">{label}</text>'
s+=f'<defs><marker id="a" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0,0 L8,4 L0,8 z" fill="{INK2}"/></marker></defs>'
# right-to-left pipeline (Arabic reading order)
bw=170; bh=92; y=70; gap=22; x=W-20-bw
boxes=[("1. التنبيه", ["تقنية ATT&CK + جهاز","من EDR/NDR/SIEM","واجهة: JSON موقّع"]),
       ("2. جدول الخطر (D2)", ["تقنية ← خطر 1–10","أثر ← قيمة الخدمة","تجزيعه في كل شهادة"]),
       ("3. أرضية الأمان (v12)", ["خطر 9 ← عزل","خادم حرج ← تجزئة","حتمية، < 1 مللي ثانية"]),
       ("4. المُحسِّن QUBO", ["دقيق ≤ 20 متغيرًا","تلدين / QAOA فوقها","يقرر ما بقي فقط"]),
       ("5. بوابة السلامة", ["S1–S5، C1–C2","G1–G3 ← شخصان","لا تتغيّر بين الإصدارات"])]
for i,(t,sub) in enumerate(boxes):
    box(x,y,bw,bh,t,sub,hl=(i in (2,4)))
    if i<len(boxes)-1: arrow(x,y+bh/2,x-gap+2,y+bh/2)
    x-=bw+gap
# second row
y2=y+bh+70
x=W-20-bw
boxes2=[("6. المنفّذ", ["iptables / nftables","قاعدة ذرية واحدة","NEW فقط للتجزئة"]),
        ("7. التوأم الرقمي", ["يقارن القواعد المركّبة","بالخطة وبالسلوك","يرفض الخطة المعطوبة"]),
        ("8. الشهادة", ["HMAC + ML-DSA-65","مدقق مستقل يعيد الحساب","عدم إنكار"]),
        ("9. طرفية الإنعاش", ["readmit / restore / shield","كل أمر يمر بالبوابة","سجل مُسلسل موقّع"]),
        ("10. المناعة (v13)", ["بصمة المسار","دروع دائمة + أول قفزة","لا تسقط خدمة شغّالة"])]
for i,(t,sub) in enumerate(boxes2):
    box(x,y2,bw,bh,t,sub,hl=(i in (1,2)))
    if i<len(boxes2)-1: arrow(x,y2+bh/2,x-gap+2,y2+bh/2)
    x-=bw+gap
# connector from 5 to 6 (down-left)
x5=W-20-4*(bw+gap); s+=f'<path d="M{x5+bw/2},{y+bh} L{x5+bw/2},{y2-40} L{W-20-bw/2},{y2-40} L{W-20-bw/2},{y2}" fill="none" stroke="{INK2}" stroke-width="1.6" marker-end="url(#a)"/>'
s+=f'<text x="{(x5+W-20)/2}" y="{y2-46}" direction="rtl" text-anchor="middle" font-size="12" fill="{INK2}">قرار معتمد (CONTAINED / PENDING / ESCALATED)</text>'
# test benches row
y3=y2+bh+58
s+=f'<text x="{W-20}" y="{y3-12}" direction="rtl" text-anchor="start" font-size="15" font-weight="600" fill="{INK}">منصّات الاختبار (المجموعات التجريبية) وما يُقاس في كل واحدة</text>'
bench=[("أ — المحاكاة", "4,000+ سيناريو تركيبي + 894 واقعي؛ يُقاس: الاحتواء، الخدمات المتوقفة بعد الموافقات، الفشل الصامت"),
       ("ب — نواة Linux", "نفس «الدائرة» تُختبر حاسوبيًا: 66/66 تطابق النموذج مع المقاس، 0 تسريب، 10 مللي ثانية للقطع"),
       ("ج — العتاد الكمّي", "IBM 156 كيوبت: هل تجد الدارة الأمثل تحت قيود السلامة؟ 11/11؛ لا تفوق كمّي"),
       ("د — الابتكار على الواقع", "83 حادثة حقيقية 2013–2026: v12 100% و91% احتواء تلقائي، 0 غير آمن؛ الضابطة = بلا حماية")]
bw3=255; x=W-20-bw3
for t,sub in bench:
    s+=f'<rect x="{x}" y="{y3}" width="{bw3}" height="78" rx="8" fill="#fff" stroke="{BLUE}" stroke-width="1.2"/>'
    s+=f'<text x="{x+bw3-10}" y="{y3+22}" direction="rtl" text-anchor="start" font-size="14" font-weight="600" fill="{INK}">{t}</text>'
    # wrap sub into 2-3 lines of ~38 chars
    words=sub.split(); lines=[]; cur=""
    for w_ in words:
        if len(cur)+len(w_)+1>40: lines.append(cur); cur=w_
        else: cur=(cur+" "+w_).strip()
    lines.append(cur)
    for i,l in enumerate(lines[:3]):
        s+=f'<text x="{x+bw3-10}" y="{y3+40+i*15}" direction="rtl" text-anchor="start" font-size="11.5" fill="{INK2}">{l}</text>'
    x-=bw3+13
s+=f'<text x="{W-20}" y="{H-30}" direction="rtl" text-anchor="start" font-size="12.5" fill="{INK2}">المتغير المستقل الرئيسي: سياسة القرار (الضابطة بلا حماية، العزل الكامل، القاعدة البسيطة، عزل كل مُنبَّه عليه، ACRS).</text>'
s+=f'<text x="{W-20}" y="{H-12}" direction="rtl" text-anchor="start" font-size="12.5" fill="{INK2}">التابع: الخدمات المتوقفة بعد الموافقات، الاحتواء، الفشل الصامت، القرارات غير الآمنة، الزمن. المضبوط: الأوزان والعتبة 7 والبذور العشوائية.</text></svg>'
open('fig_c.html','w').write(HEAD+s+"</body></html>")
print('ok')
