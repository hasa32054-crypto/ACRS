"""Arabic names for the Hospital-60 machines and services (display only; no logic)."""
from __future__ import annotations

ROLE_AR = {
    "dc1": "خادم الدخول 1", "dc2": "خادم الدخول 2", "files": "خادم الملفات", "backup": "خادم النسخ الاحتياطي",
    "email": "خادم البريد", "vpn": "بوابة الوصول عن بعد (VPN)", "print": "خادم الطابعات",
    "wifi": "متحكم الشبكة اللاسلكية", "ehr_app1": "تطبيق السجلات الطبية 1", "ehr_app2": "تطبيق السجلات الطبية 2",
    "ehr_db": "قاعدة بيانات السجلات الطبية", "pacs1": "خادم الأشعة 1", "pacs2": "خادم الأشعة 2",
    "pacs_store": "أرشيف صور الأشعة", "hl7_1": "محرك ربط الأنظمة 1", "hl7_2": "محرك ربط الأنظمة 2",
    "pharm": "نظام الصيدلية", "lis": "نظام المختبر", "er1": "لوحة الطوارئ 1", "er2": "لوحة الطوارئ 2",
    "web1": "بوابة المرضى 1", "web2": "بوابة المرضى 2", "lab_a1": "جهاز تحليل 1", "lab_a2": "جهاز تحليل 2",
    "lab_a3": "جهاز تحليل 3", "ct": "الأشعة المقطعية", "mri": "الرنين المغناطيسي", "xray": "الأشعة السينية",
    "pump_gw": "بوابة مضخات المحاليل", "monitor_gw": "بوابة أجهزة المراقبة", "nursecall": "نداء التمريض",
    "badge": "بطاقات الدخول", "hvac": "التحكم بالمبنى",
}
for _i in range(1, 10):
    ROLE_AR[f"pc_nurse{_i}"] = f"جهاز تمريض {_i}"
    ROLE_AR[f"pc_doc{_i}"] = f"جهاز طبيب {_i}"
for _i in range(1, 5):
    ROLE_AR[f"pc_admin{_i}"] = f"جهاز إدارة {_i}"
for _i in range(1, 6):
    ROLE_AR[f"pc_recep{_i}"] = f"جهاز استقبال {_i}"

SERVICE_AR = {"logins": "دخول الموظفين", "ehr": "السجلات الطبية", "imaging": "الأشعة", "hl7": "ربط الأنظمة",
              "er_board": "لوحة الطوارئ", "portal": "بوابة المرضى", "pharmacy": "الصيدلية", "lab_results": "نتائج المختبر"}

GROUP_AR = [  # display groups, in order
    ("الخوادم الحرجة", ["dc1", "dc2", "ehr_db", "pacs_store"]),
    ("خوادم الخدمات", ["ehr_app1", "ehr_app2", "pacs1", "pacs2", "hl7_1", "hl7_2", "er1", "er2", "web1", "web2",
                       "pharm", "lis"]),
    ("البنية التحتية", ["files", "backup", "email", "vpn", "print", "wifi", "badge", "hvac"]),
    ("أجهزة طبية (لا تُعزل أبدًا)", ["lab_a1", "lab_a2", "lab_a3", "ct", "mri", "xray", "pump_gw", "monitor_gw",
                                      "nursecall"]),
    ("أجهزة الموظفين", [f"pc_nurse{i}" for i in range(1, 10)] + [f"pc_doc{i}" for i in range(1, 10)]
                       + [f"pc_admin{i}" for i in range(1, 5)] + [f"pc_recep{i}" for i in range(1, 6)]),
]


def name(m: str) -> str:
    return ROLE_AR.get(m, m)
