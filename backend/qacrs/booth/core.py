"""Booth logic on top of the real engine (EngineV9 on Hospital-60). Display helpers only; no new decision logic.

A visitor's attack = machines picked on the map:
  genuine picks  -> the independent network sensor (NDR) sees lateral flows between linked genuine picks;
  forged picks   -> alerts with no flow behind them (what an attacker who forges alerts would produce).
HASSAN v9 then decides exactly as in the evaluation (guard v2, fail-safe, rate limit, certificate, HMAC).
"""
from __future__ import annotations

import time
from dataclasses import asdict

from qacrs import hassan as H
from qacrs import hospital_ar as AR
from qacrs import qubo_v7 as V7
from qacrs import realism_v8 as RV
from qacrs import safety_checks as S
from qacrs import escalation as E
from qacrs.hassan_v9 import EngineV9, verify_certificate_v9
from qacrs.network import Scenario

# ------------------------------------------------------------------ map: departments = zones, devices = stations ----
# Display grouping only (the engine never sees it). Every Hospital-60 machine sits in exactly one zone.
ZONES = [
    {"id": "identity", "ar": "الهوية والدخول", "en": "Identity & access", "machines": ["dc1", "dc2", "vpn", "wifi", "badge"]},
    {"id": "records", "ar": "السجلات الطبية", "en": "Medical records", "machines": ["ehr_db", "ehr_app1", "ehr_app2", "hl7_1", "hl7_2"]},
    {"id": "er", "ar": "الطوارئ", "en": "Emergency", "machines": ["er1", "er2", "monitor_gw", "pump_gw", "nursecall"]},
    {"id": "imaging", "ar": "الأشعة", "en": "Radiology", "machines": ["pacs_store", "pacs1", "pacs2", "ct", "mri", "xray"]},
    {"id": "lab", "ar": "المختبر والصيدلية", "en": "Lab & pharmacy", "machines": ["lis", "lab_a1", "lab_a2", "lab_a3", "pharm"]},
    {"id": "infra", "ar": "البنية التحتية", "en": "Infrastructure", "machines": ["files", "backup", "email", "print", "hvac"]},
    {"id": "front", "ar": "الاستقبال وبوابة المرضى", "en": "Front desk & portal",
     "machines": ["web1", "web2"] + [f"pc_recep{i}" for i in range(1, 6)]},
    {"id": "nursing", "ar": "التمريض", "en": "Nursing", "machines": [f"pc_nurse{i}" for i in range(1, 10)]},
    {"id": "doctors", "ar": "الأطباء", "en": "Physicians", "machines": [f"pc_doc{i}" for i in range(1, 10)]},
    {"id": "admin", "ar": "الإدارة", "en": "Administration", "machines": [f"pc_admin{i}" for i in range(1, 5)]},
]

STATUS_AR = {S.CONTAINED: "تم الاحتواء", E.ESCALATED: "أُحيل إلى البشر", S.PENDING: "احتواء بانتظار موافقة شخصين",
             S.NOT_CONTAINED: "لم يكتمل الاحتواء", S.REJECTED: "مرفوض (مدخلات غير صالحة)"}
STATUS_EN = {S.CONTAINED: "Contained", E.ESCALATED: "Escalated to humans", S.PENDING: "Contained, pending two-person approval",
             S.NOT_CONTAINED: "Not contained", S.REJECTED: "Rejected (invalid input)"}
RULE_AR = {"G1": "عزل خادم حرج لا يتم آليًا: يحتاج موافقة شخصين",
           "G2": "قرار يمس خدمة حرجة: يحتاج موافقة شخصين",
           "G3": "العزل سيوقف خدمة سريرية: يحتاج موافقة شخصين",
           "HELD": "حُجز العزل للبشر: تنبيه بلا حركة جانبية يراها مستشعر الشبكة (احتمال تزوير)",
           "FAILSAFE": "تجاوز الحل مهلته: تقييد كل الأجهزة المبلغ عنها فقط، والقرار للبشر"}
RULE_EN = {"G1": "Critical server isolation is never automatic: two-person approval",
           "G2": "Touches a critical service: two-person approval",
           "G3": "Isolation would stop a clinical service: two-person approval",
           "HELD": "Isolation held for humans: alert without a lateral flow seen by the network sensor (possible forgery)",
           "FAILSAFE": "Solver over its time budget: restrict reported machines only; humans decide"}


FLOOR_AR = {"destructive": "حمولة مدمّرة نُفّذت على الجهاز (خطر 9): يُعزل فورًا",
            "critical": "خادم حرج مخترق: يُجزّأ فورًا، وتبقى خدمته السريرية تعمل",
            "neighbour": "خادم حرج سليم بجوار خادم حرج مخترق: يُجزّأ ليُغلق الطريق إليه",
            "free": "عزله لا يوقف أي خدمة إضافية: يُعزل",
            "owner": "جهاز طبي لا يُعزل أبدًا: يُحال لصاحبه"}
FLOOR_EN = {"destructive": "Destructive payload ran on the host (risk 9): isolate at once",
            "critical": "Hacked critical server: segment at once; its clinical service keeps running",
            "neighbour": "Healthy critical neighbour of a hacked critical server: segment to close the path",
            "free": "Isolating it stops no additional service: isolate",
            "owner": "Never-isolate medical device: referred to its owner"}


def floor_kind(reason: str) -> str:
    r = reason.lower()
    if "destructive" in r: return "destructive"
    if "neighbour" in r: return "neighbour"
    if "costs no service" in r: return "free"
    if "owner" in r: return "owner"
    return "critical"


class Booth:
    def __init__(self, key: bytes = b"demo-key-not-secret", engine: str = "v12"):
        self.net = RV.hospital60()
        self.names = {m.name for m in self.net.machines}
        self.machine = {m.name: m for m in self.net.machines}
        self.entries = H.entry_points(self.net)
        # booth-wide rate limit stays the engine's own default (3 automatic isolations / 60 s) would make a queue of
        # visitors look like an attack flood; each visitor attack is independent, so the limiter is per decision.
        self.key = key
        self.engine_name = engine
        if engine == "v12":
            from qacrs.booth.engine_v12 import EngineV12
            self.engine = EngineV12(self.net, key=key, limiter=H.RateLimiter(limit=10 ** 9))
        else:
            self.engine = EngineV9(self.net, key=key, limiter=H.RateLimiter(limit=10 ** 9))
        self._links = set(self.net.links)
        for sc in ({"pc_recep1": 8, "web1": 8}, {"pc_admin1": 9, "dc1": 9, "ehr_db": 9}):   # warm caches
            self.engine.decide(Scenario("warm", "hospital60", sc, "warm-up"), lateral=set())
        assert sorted(m for z in ZONES for m in z["machines"]) == sorted(self.names), "every machine in one zone"

    # -------------------------------------------------------------- static model for the UI --------------------------
    def model(self) -> dict:
        zone_of = {m: z["id"] for z in ZONES for m in z["machines"]}
        return {
            "zones": [{k: z[k] for k in ("id", "ar", "en", "machines")} for z in ZONES],
            "machines": [{"id": m.name, "ar": AR.name(m.name), "en": m.role, "zone": zone_of[m.name],
                          "isolatable": m.isolatable, "critical": m.critical, "entry": m.name in self.entries}
                         for m in self.net.machines],
            "links": [list(l) for l in self.net.links],
            "services": [{"id": s.name, "ar": AR.SERVICE_AR.get(s.name, s.name), "replicas": s.replicas,
                          "depends_on": s.depends_on, "value": s.value} for s in self.net.services],
        }

    # -------------------------------------------------------------- one attack -------------------------------------
    def lateral(self, hacked: dict, forged: list[str]) -> set:
        genuine = set(hacked) - set(forged)
        return {(a, b) for a, b in self._links if a in genuine and b in genuine} | \
               {(b, a) for a, b in self._links if a in genuine and b in genuine}

    def side(self, hacked, iso, seg) -> dict:
        down = V7.services_down_v7(self.net, iso, seg, set(hacked))
        return {"isolate": sorted(iso), "segment": sorted(seg), "services_down": down,
                "patient_minutes": RV.patient_minutes(down)}

    def decide(self, hacked: dict, forged: list[str], sid: str = "booth") -> dict:
        sc = Scenario(sid, "hospital60", dict(hacked), "booth attack: picked on the map")
        t = time.perf_counter()
        d = self.engine.decide(sc, self.lateral(hacked, forged))
        ms = 1000 * (time.perf_counter() - t)
        full_iso, _ = V7.m_full_isolation_safe(self.net, sc)
        hassan = self.side(hacked, d.isolate, d.segment)
        full = self.side(hacked, full_iso, set())
        return {
            "status": d.status, "status_ar": STATUS_AR.get(d.status, d.status), "status_en": STATUS_EN.get(d.status, d.status),
            "hassan": hassan | {"restrict": d.restrict, "held": d.held_for_humans},
            "full_isolation": full,
            "escalations": [{"rule": e["rule"], "target": e["target"], "ar": RULE_AR.get(e["rule"], e["action"]),
                             "en": RULE_EN.get(e["rule"], e["action"]), "approvals": e.get("approvals", 2)}
                            for e in d.escalations],
            "guard_flags": d.guard_flags, "solver": d.solver, "fallback": d.fallback, "ms": round(ms, 1),
            "expires_in_s": d.expires_in_s,
            "services": [{"id": s.name, "ar": AR.SERVICE_AR.get(s.name, s.name),
                          "hassan_up": s.name not in hassan["services_down"],
                          "full_up": s.name not in full["services_down"]} for s in self.net.services],
            "card": self.card_ar(hacked, forged, d, hassan, full),
            "card_en": d.card["en"],
            "certificate": d.certificate, "signature": d.signature,
            "engine": self.engine_name,
            "pq_signature": getattr(d, "pq_signature", None), "pq_alg": "ML-DSA-65" if getattr(d, "pq_signature", None) else None,
            "floor": [{"machine": m, "kind": floor_kind(r), "ar": FLOOR_AR[floor_kind(r)], "en": FLOOR_EN[floor_kind(r)]}
                      for m, r in sorted((d.certificate.get("floor_reasons") or {}).items())]
                     if isinstance(d.certificate, dict) else [],
            "after_approval_down": self._after_approval(sc, d),
            "full_down_n": len(full["services_down"]),
        }

    def _after_approval(self, sc, d) -> list[str]:
        from qacrs.booth.engine_v12 import services_after_approval
        if d.status == "REJECTED":
            return []
        return services_after_approval(self.net, sc, set(d.isolate), set(d.segment), d.escalations)

    def card_ar(self, hacked, forged, d, hassan, full) -> dict:
        n = lambda ms: "، ".join(AR.name(m) for m in ms) or "لا شيء"
        saved = len(full["services_down"]) - len(hassan["services_down"])
        lines = [
            ("عزل كامل", n(d.isolate)),
            ("تجزئة (تبقى الخدمة السريرية وتُقطع الحركة الجانبية)", n(d.segment)),
            ("تقييد (قطع قناة المهاجم فقط)", n(d.restrict)),
        ]
        if d.held_for_humans:
            lines.append(("محجوز لقرار البشر", n(d.held_for_humans)))
        why = []
        if any(not self.machine[m].isolatable for m in hacked):
            why.append("الأجهزة الطبية لا تُعزل أبدًا؛ تُقيَّد فقط حتى لا يتوقف علاج مريض.")
        if any(self.machine[m].critical for m in hacked):
            why.append("الخوادم الحرجة تُجزَّأ بدل عزلها، وعزلها الكامل يحتاج موافقة شخصين.")
        if d.guard_flags:
            why.append("مستشعر الشبكة لم يرَ حركة جانبية تبرر بعض التنبيهات، فلم يُعزل شيء آليًا.")
        if d.fallback:
            why.append("الحل تجاوز مهلته، فطُبّق المسار الآمن: تقييد فقط وإحالة للبشر.")
        return {"status": STATUS_AR.get(d.status, d.status), "actions": lines,
                "services_down": [AR.SERVICE_AR.get(s, s) for s in hassan["services_down"]],
                "full_services_down": [AR.SERVICE_AR.get(s, s) for s in full["services_down"]],
                "saved": saved, "why": why}

    # -------------------------------------------------------------- judge vs machine -------------------------------
    def judge(self, hacked: dict, forged: list[str], iso: list[str], seg: list[str]) -> dict:
        sc = Scenario("judge", "hospital60", dict(hacked), "judge vs machine")
        iso, seg = set(iso), set(seg) - set(iso)
        verdict = V7.check_v7(self.net, sc, iso, seg)
        status = V7.decide_v7(self.net, sc, iso, seg).status if verdict.status != S.REJECTED else S.REJECTED
        mine = self.side(hacked, iso, seg)
        broken = [m for m in iso if not self.machine[m].isolatable]
        return {"status": status, "status_ar": STATUS_AR.get(status, status), "status_en": STATUS_EN.get(status, status),
                "safety_violations": verdict.reasons if verdict.status == S.REJECTED else [],
                "medical_devices_isolated": broken,
                "isolated_not_reported": sorted(iso - set(hacked)),
                "open_paths": [list(p) for p in V7.open_paths_v7(self.net, sc, iso, seg)][:12],
                **mine}

    # -------------------------------------------------------------- ransomware replay (board) -----------------------
    def spread_timeline(self, start: list[str], policy: str, ticks: int = 10, decide_at: int = 2, risk: int = 8) -> dict:
        """Tick-by-tick copy of hassan_v9.spread_v9 (same rules); tests check the final state matches it."""
        from qacrs.hassan_v9 import shield_links
        pol = {"none": None, "full": V7.m_full_isolation_safe,
               "hassan": lambda net, sc: H.solve(net, sc)[:2]}[policy]
        shield = policy == "hassan"
        infected, iso, seg, sh = set(start), set(), set(), set()
        frames = [{"tick": 0, "infected": sorted(infected)}]
        for t in range(1, ticks + 1):
            if t == decide_at and pol is not None:
                sc = Scenario("rw", self.net.name, {m: risk for m in sorted(infected)}, "ransomware")
                iso, seg = pol(self.net, sc)
                iso = {m for m in iso if not self.machine[m].critical}
                if shield:
                    sh = shield_links(self.net, infected, iso)
            new = {b for a, b in self.net.links if a in infected and a not in iso and b not in iso and b not in seg
                   and (a, b) not in sh}
            infected |= new
            frames.append({"tick": t, "infected": sorted(infected), "isolate": sorted(iso), "segment": sorted(seg)})
        down = V7.services_down_v7(self.net, iso, seg, infected)
        enc_down = [s.name for s in self.net.services
                    if all(r in infected or r in iso for r in s.replicas)
                    or any(x in infected or x in iso for x in s.depends_on)]
        return {"policy": policy, "frames": frames, "encrypted": len(infected),
                "services_unavailable": sorted(set(down) | set(enc_down))}

    # -------------------------------------------------------------- verify yourself -------------------------------
    def verify(self, hacked: dict, certificate: dict, signature: str, pq_signature: str | None = None) -> dict:
        sig_ok = H.verify_signature(certificate, signature, self.key) if isinstance(signature, str) else False
        sc = Scenario("v", "hospital60", dict(hacked), "verify")
        try:
            if self.engine_name == "v12":
                from qacrs.booth.engine_v12 import verify_certificate_v12
                cert_ok = verify_certificate_v12(self.net, sc, certificate)
            else:
                cert_ok = verify_certificate_v9(self.net, sc, certificate)
        except Exception:
            cert_ok = False
        out = {"signature_ok": bool(sig_ok), "certificate_ok": bool(cert_ok), "accepted": bool(sig_ok and cert_ok)}
        if pq_signature is not None and hasattr(self.engine, "verify_pq"):
            out["pq_ok"] = bool(self.engine.verify_pq(certificate, pq_signature))
            out["accepted"] = out["accepted"] and out["pq_ok"]
        return out
