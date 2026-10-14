"""Blind test of HASSAN v9 on Hospital-60. Rules: docs/qacrs/PREREGISTRATION_BLIND_v9.md (+ amendment 1).

    cd backend
    python -m qacrs.blind_v9 guide                    # writes qacrs/blind_v9/AUTHOR_GUIDE_AR.md (machines + links)
    python -m qacrs.blind_v9 author OUT.json          # the INDEPENDENT AUTHOR builds scenarios (no decisions shown)
    python -m qacrs.blind_v9 validate FILE.json       # checks a file; runs nothing
    python -m qacrs.blind_v9 write-lock               # once, before any scenario exists
    python -m qacrs.blind_v9 run FILE.json            # runs ONCE -> results/blind_v9/<file sha>.json

The author tool never calls the engine. The run refuses if locked code changed, and refuses a second run of the same file.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import statistics
import sys
import time
from pathlib import Path

from qacrs import hassan as H
from qacrs import hassan_v9 as V9
from qacrs import qubo_v7 as V7
from qacrs import realism_v8 as RV
from qacrs import safety_checks as S
from qacrs import stats
from qacrs.hospital_ar import GROUP_AR, ROLE_AR, SERVICE_AR, name
from qacrs.meta import meta
from qacrs.network import Scenario

HERE = Path(__file__).parent
KIT = HERE / "blind_v9"
LOCK = KIT / "LOCK_blind_v9.json"
OUT = HERE / "results" / "blind_v9"
LOCKED = ("hassan.py", "hassan_v9.py", "qubo_v7.py", "qubo_builder.py", "escalation.py", "safety_checks.py",
          "network.py", "realism_v8.py", "hospital_ar.py", "blind_v9.py", "stats.py")
MAX_SCENARIOS, MAX_TEXT = 60, 600


def sha_file(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def numbered(net):
    order = [m for _, ms in GROUP_AR for m in ms]
    assert sorted(order) == sorted(m.name for m in net.machines)
    return order


# ------------------------------------------------------------------ guide ------------------------------------------
def guide() -> Path:
    net = RV.hospital60()
    order = numbered(net)
    mach = {m.name: m for m in net.machines}
    L = ["# دليل كاتب سيناريوهات الاختبار الأعمى — HASSAN", "",
         "أنت تكتب هجمات **افتراضية** على شبكة مستشفى من 60 جهازًا. لن ترى أي قرار من النظام قبل التشغيل.",
         "لكل هجوم: اختر الأجهزة المخترقة من القائمة بأرقامها، وأعطِ كل جهاز خطورة من 1 إلى 10",
         "(10 = خطر شديد لو تُرك الجهاز يعمل)، واكتب وصفًا قصيرًا للتوثيق فقط.", "",
         "نطلب التنوع: نقاط دخول مختلفة، وأهداف مختلفة، وهجمات تتنقل بين الأجهزة، وهجمات متعددة في وقت واحد.",
         "لا تكتب بيانات شخصية.", "", "## الأجهزة", "", "| رقم | الجهاز | يجوز عزله | خادم حرج |", "|---|---|---|---|"]
    for i, m in enumerate(order, 1):
        L.append(f"| {i} | {name(m)} | {'نعم' if mach[m].isolatable else '**لا أبدًا**'} | {'نعم' if mach[m].critical else ''} |")
    L += ["", "## الخدمات", ""]
    for s in net.services:
        L.append(f"- **{SERVICE_AR.get(s.name, s.name)}**: تعمل على {' أو '.join(name(r) for r in s.replicas)}"
                 + (f"، وتحتاج {'، '.join(name(d) for d in s.depends_on)}" if s.depends_on else ""))
    L += ["", "## من يستطيع الاتصال بمن (طرق انتقال الهجوم)", ""]
    for a, b in net.links:
        L.append(f"- {name(a)} ← يتصل بـ ← {name(b)}")
    KIT.mkdir(parents=True, exist_ok=True)
    p = KIT / "AUTHOR_GUIDE_AR.md"
    p.write_text("\n".join(L) + "\n")
    return p


# ------------------------------------------------------------------ author tool (never calls the engine) -----------
def author(out: Path):
    net = RV.hospital60()
    order = numbered(net)
    print("أداة كاتب الاختبار الأعمى. لن تُعرض أي قرارات من النظام.\n")
    role = input("دورك (مثال: معلم حاسب، مختص أمن): ").strip()[:120]
    scenarios = []
    while len(scenarios) < MAX_SCENARIOS:
        print("\nالأجهزة:")
        for i, m in enumerate(order, 1):
            print(f"  {i:>2}. {name(m)}")
        raw = input("\nأرقام الأجهزة المخترقة مفصولة بفواصل (أو اتركه فارغًا للإنهاء): ").strip()
        if not raw:
            break
        try:
            idx = sorted({int(x) for x in raw.replace("،", ",").split(",") if x.strip()})
            picked = [order[i - 1] for i in idx if 1 <= i <= len(order)]
        except ValueError:
            print("أرقام غير صحيحة، حاول مرة أخرى."); continue
        if not picked:
            continue
        hacked = {}
        for m in picked:
            while True:
                r = input(f"  خطورة «{name(m)}» من 1 إلى 10: ").strip()
                if r.isdigit() and 1 <= int(r) <= 10:
                    hacked[m] = int(r); break
        desc = input("وصف قصير للهجوم (للتوثيق فقط): ").strip()[:MAX_TEXT]
        print("\nالهجوم: " + "، ".join(f"{name(m)} ({r})" for m, r in hacked.items()))
        if input("حفظ هذا الهجوم؟ (نعم/لا): ").strip() in ("نعم", "y", "yes", "ن"):
            scenarios.append({"id": f"blind_{len(scenarios) + 1:02d}", "hacked": hacked, "description": desc})
    consent = input("\nهل توافق على نشر هذه السيناريوهات ونتائجها في المشروع؟ (نعم/لا): ").strip() in ("نعم", "y", "yes", "ن")
    data = {"author_role": role, "created": time.strftime("%Y-%m-%d"), "network": "hospital60",
            "consent_to_publish": consent, "saw_hassan_decisions_before_writing": False, "scenarios": scenarios}
    out.write_text(json.dumps(data, indent=1, ensure_ascii=False))
    print(f"\nحُفظ {len(scenarios)} سيناريو في {out}. أرسل الملف كما هو.")


# ------------------------------------------------------------------ validation -------------------------------------
def validate(data: dict) -> list[str]:
    net = RV.hospital60()
    names = {m.name for m in net.machines}
    err = []
    if data.get("network") != "hospital60":
        err.append("network must be hospital60")
    if data.get("saw_hassan_decisions_before_writing") is not False:
        err.append("saw_hassan_decisions_before_writing must be false")
    sc = data.get("scenarios")
    if not isinstance(sc, list) or not 1 <= len(sc) <= MAX_SCENARIOS:
        return err + [f"scenarios must be a list of 1..{MAX_SCENARIOS}"]
    ids = set()
    for s in sc:
        sid = s.get("id")
        if not isinstance(sid, str) or sid in ids or len(sid) > 40:
            err.append(f"bad or duplicate id {sid!r}")
        ids.add(sid)
        h = s.get("hacked")
        if not isinstance(h, dict) or not h:
            err.append(f"{sid}: hacked must be a non-empty object"); continue
        for m, r in h.items():
            if m not in names:
                err.append(f"{sid}: unknown machine {m!r}")
            if not isinstance(r, int) or isinstance(r, bool) or not 1 <= r <= 10:
                err.append(f"{sid}: risk of {m} must be an integer 1..10")
        if len(str(s.get("description", ""))) > MAX_TEXT:
            err.append(f"{sid}: description too long")
    return err


# ------------------------------------------------------------------ lock and run -----------------------------------
def write_lock():
    if LOCK.exists():
        sys.exit("REFUSED: lock already exists")
    KIT.mkdir(parents=True, exist_ok=True)
    LOCK.write_text(json.dumps(meta("blind_v9_lock") | {"sha256": {f: sha_file(HERE / f) for f in LOCKED}}, indent=1))
    print(f"Saved: {LOCK}")


def drift() -> list[str]:
    if not LOCK.exists():
        return ["lock missing"]
    lock = json.loads(LOCK.read_text())["sha256"]
    return [f for f in LOCKED if sha_file(HERE / f) != lock.get(f)]


def pct(v, q):
    v = sorted(v); return v[min(len(v) - 1, int(round(q * (len(v) - 1))))]


def run(path: Path, allow_rerun=False):
    d = drift()
    if d:
        sys.exit("REFUSED: locked code changed or lock missing: " + ", ".join(d))
    raw = path.read_bytes(); fsha = hashlib.sha256(raw).hexdigest()
    data = json.loads(raw)
    err = validate(data)
    out = OUT / f"{fsha[:16]}.json"
    if out.exists() and not allow_rerun:
        sys.exit(f"REFUSED: this file was already run -> {out}")
    net = RV.hospital60()
    eng = V9.EngineV9(net, limiter=H.RateLimiter(limit=10 ** 9))
    machines = {m.name: m for m in net.machines}
    rows, ms = [], []
    valid = [s for s in data.get("scenarios", []) if not validate({**data, "scenarios": [s]})]
    for s in valid:
        sc = Scenario(s["id"], "hospital60", s["hacked"], s.get("description", ""))
        t = time.perf_counter(); dcs = eng.decide(sc); ms.append(1000 * (time.perf_counter() - t))
        iso, seg = set(dcs.isolate), set(dcs.segment)
        fi, _ = V7.m_full_isolation_safe(net, sc)
        fstat = V7.decide_v7(net, sc, fi, set()).status
        unsafe = (dcs.status == S.REJECTED or any(not machines[m].isolatable for m in iso)
                  or any(machines[m].critical for m in iso))
        rows.append({"id": s["id"], "hacked": s["hacked"], "description": s.get("description", ""),
                     "hassan": {"status": dcs.status, "isolate": sorted(iso), "segment": sorted(seg),
                                "escalations": [e.get("rule") for e in dcs.escalations],
                                "services_down": V7.services_down_v7(net, iso, seg, set(sc.hacked)),
                                "certificate_verified": V9.verify_certificate_v9(net, sc, dcs.certificate),
                                "card_ar": dcs.card.get("ar")},
                     "full_isolation_safe": {"status": fstat, "services_down": V7.services_down_v7(net, fi, set(), set(sc.hacked))},
                     "unsafe": unsafe})
    n = len(rows)
    cont = lambda st: st in (S.CONTAINED, S.PENDING)
    h_cont = sum(cont(r["hassan"]["status"]) for r in rows); f_cont = sum(cont(r["full_isolation_safe"]["status"]) for r in rows)
    silent = sum(r["hassan"]["status"] == S.NOT_CONTAINED for r in rows)
    h_down = [len(r["hassan"]["services_down"]) for r in rows]; f_down = [len(r["full_isolation_safe"]["services_down"]) for r in rows]
    summary = {"scenarios_in_file": len(data.get("scenarios", [])), "valid": n, "invalid_reasons": err,
               "unsafe": sum(r["unsafe"] for r in rows), "silent": silent,
               "silent_wilson95": stats.wilson(silent, n) if n else None,
               "escalated": sum(r["hassan"]["status"] == "ESCALATED" for r in rows),
               "containment_ratio_vs_full_isolation": (h_cont / f_cont) if f_cont else None,
               "H1_met": bool(f_cont) and h_cont >= 0.8 * f_cont and sum(h_down) < sum(f_down),
               "services_down_total": {"hassan": sum(h_down), "full_isolation_safe": sum(f_down)},
               "wilcoxon_services": stats.wilcoxon_less(h_down, f_down) if n >= 10 else "n < 10, not computed",
               "decision_ms": {"median": statistics.median(ms), "p95": pct(ms, .95)} if ms else None}
    res = {"meta": meta("blind_v9_run", LOCKED), "file_sha256": fsha, "author_role": data.get("author_role"),
           "consent_to_publish": data.get("consent_to_publish"), "rerun": out.exists(), "summary": summary, "rows": rows}
    OUT.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(res, indent=1, ensure_ascii=False))
    print(json.dumps(summary, indent=1, ensure_ascii=False)); print(f"Saved: {out}")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python -m qacrs.blind_v9")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("guide"); sub.add_parser("write-lock")
    a1 = sub.add_parser("author"); a1.add_argument("out")
    a2 = sub.add_parser("validate"); a2.add_argument("file")
    a3 = sub.add_parser("run"); a3.add_argument("file"); a3.add_argument("--allow-rerun", action="store_true")
    a = ap.parse_args(argv)
    if a.cmd == "guide":
        print(f"Saved: {guide()}")
    elif a.cmd == "author":
        author(Path(a.out))
    elif a.cmd == "validate":
        e = validate(json.loads(Path(a.file).read_text()))
        print("OK" if not e else "\n".join(e))
    elif a.cmd == "write-lock":
        write_lock()
    else:
        run(Path(a.file), a.allow_rerun)


if __name__ == "__main__":
    main()
