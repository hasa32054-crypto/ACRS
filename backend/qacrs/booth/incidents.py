"""Booth: replay a REAL documented incident (the 8 v11 conversions + the 75 open-corpus conversions) on ACRS v12.

Two modes, both executed by the real code, nothing scripted:
  normal   every detection moment goes through the survivable v12 engine (recover.apply_alert: floor + locked solver
           + closure + locked gate, monotone, HMAC-chained audit), compared with "isolate everything" on the same moment;
  fault    the same, but at the second moment the optimiser CRASHES (an injected exception, as in phase18 D12 a):
           the engine falls back to floor + rule and still contains. Then the PROCESS is killed and restarted: the state
           file is reloaded (D12 b) and we check nothing was released and the audit chain is intact. Then the engineer
           uses the recovery terminal (recover.run_command, D11): a premature readmit is REFUSED by the gate,
           credentials are rotated, hosts restored (critical ones need a second person), the incident is closed and
           immunity installed (D13-v13). Finally the same attack is replayed against the immunised engine.

Data: backend/qacrs/v11/incidents (real 8) and backend/qacrs/v12/corpus (open corpus); conversions by Claude from the
cited public reports (stated on screen). Sector labels come from the conversion files.
"""
from __future__ import annotations

import copy
import json
import tempfile
import time
from pathlib import Path

from qacrs import qubo_v7 as V7
from qacrs import safety_checks as S
from qacrs import phase16_v11 as P16
from qacrs.network import Scenario
from qacrs.v12 import recover as RC
from qacrs.v12.qubo_v12 import approve_all

ROOT = Path(__file__).resolve().parents[1]
DIRS = [("real", ROOT / "v11" / "incidents"), ("corpus", ROOT / "v12" / "corpus")]

SECTORS = {   # conversion-file sector -> booth group
    "health": "health", "finance": "finance",
    "manufacturing": "industry", "energy": "industry", "critical-infrastructure": "industry", "water": "industry",
    "transport_logistics": "industry", "aviation": "industry",
    "government": "government", "defense": "government", "ngo": "government",
    "technology": "tech", "research": "tech", "education": "tech",
    "retail": "business", "hospitality": "business",
}
GROUPS = [
    {"id": "health", "ar": "مستشفيات وصحة", "en": "Hospitals & health"},
    {"id": "finance", "ar": "بنوك ومال", "en": "Banks & finance"},
    {"id": "industry", "ar": "مصانع وطاقة ومياه ونقل", "en": "Industry, energy, water, transport"},
    {"id": "government", "ar": "جهات حكومية", "en": "Government"},
    {"id": "tech", "ar": "تقنية وتعليم وبحث", "en": "Technology, education, research"},
    {"id": "business", "ar": "تجزئة وفنادق", "en": "Retail & hospitality"},
    {"id": "other", "ar": "جهات أخرى (القطاع غير مذكور)", "en": "Other (sector not stated)"},
]
STATUS_AR = {"CONTAINED": "تم الاحتواء", "CONTAINED_PENDING_APPROVAL": "احتواء بانتظار موافقة شخصين",
             "ESCALATED": "أُحيل إلى البشر", "NOT_CONTAINED": "لم يكتمل الاحتواء", "REJECTED": "مرفوض"}


def _broken_solver(net, sc):
    raise RuntimeError("optimiser crashed (injected fault)")


class Incidents:
    def __init__(self):
        self.items: dict[str, dict] = {}
        for origin, d in DIRS:
            for p in sorted(d.glob("*.json")):
                if p.name == "MANIFEST.json":
                    continue
                try:
                    raw, net, scs = P16.load(p)
                except Exception:      # noqa: BLE001 - invalid conversions are excluded exactly as in phase17
                    continue
                if net is None or not scs:
                    continue
                src = (raw.get("sources") or [{}])[0]
                path = self._path(raw, net)
                self.items[p.stem] = {
                    "id": p.stem, "origin": origin, "title": raw.get("incident", p.stem), "year": raw.get("year"),
                    "sector": raw.get("sector") or "unknown", "group": SECTORS.get(raw.get("sector") or "", "other"),
                    "source": src.get("title", ""), "url": raw.get("case_url") or src.get("url", ""),
                    "machines": len(net.machines), "moments": len(scs),
                    "_raw": raw, "_net": net, "_scs": scs, "_path": path,
                }

    @staticmethod
    def _path(raw, net) -> list[str]:
        names = {m.name for m in net.machines}
        seq: list[str] = []
        for hop in raw.get("attack_path") or []:
            for h in hop[:2]:
                if h in names and h not in seq:
                    seq.append(h)
        return seq

    def catalog(self) -> dict:
        rows = [{k: v for k, v in it.items() if not k.startswith("_")} for it in self.items.values()]
        rows.sort(key=lambda r: (r["origin"] != "real", -(r["year"] or 0), r["title"]))
        counts = {g["id"]: sum(r["group"] == g["id"] for r in rows) for g in GROUPS}
        return {"groups": [g | {"n": counts[g["id"]]} for g in GROUPS if counts[g["id"]]], "incidents": rows,
                "n": len(rows)}

    # ------------------------------------------------------------------ one run
    def run(self, iid: str, mode: str) -> dict:
        it = self.items[iid]
        net, scs = it["_net"], it["_scs"]
        roles = {m.name: m for m in net.machines}
        model = {"machines": [{"id": m.name, "role": m.role, "critical": m.critical, "isolatable": m.isolatable}
                              for m in net.machines],
                 "links": [list(l) for l in net.links],
                 "services": [{"id": s.name, "replicas": s.replicas, "depends_on": s.depends_on} for s in net.services],
                 "path": it["_path"]}
        td = tempfile.TemporaryDirectory()
        state_path = Path(td.name) / "acrs_state.json"
        st = RC.State(copy.deepcopy(net))
        steps, term = [], []
        totals = {"acrs_down": 0, "full_down": 0, "unsafe": 0, "silent": 0}
        fault_at = 1 if (mode == "fault" and len(scs) > 1) else (0 if mode == "fault" else -1)

        def tline(kind, text, out="", ok=None, audit=True):
            term.append({"kind": kind, "text": text, "out": out, "ok": ok,
                         "audit": st.audit[-1]["hash"][:12] if (audit and st.audit) else ""})

        for i, sc in enumerate(scs):
            t = time.perf_counter()
            if i == fault_at:
                tline("sys", "inject: optimiser.raise(RuntimeError)", "fault injected into the solver process", None, False)
                for h, r in sc.hacked.items():
                    st.risk[h] = max(st.risk.get(h, 0), int(r))
                d = RC.decide_with_budget(st.network, st.scenario, st.immunity, solver=_broken_solver)
                st.isolated |= set(d.isolate); st.segmented |= set(d.segment) - st.isolated
                st.log("decision", hacked=sc.hacked, status=d.status, isolate=d.isolate, segment=d.segment,
                       fallback=d.solver["fallback"])
                st.save(state_path)
            else:
                d = RC.apply_alert(st, dict(sc.hacked), state_path)
            ms = 1000 * (time.perf_counter() - t)
            live = st.scenario
            hacked = set(live.hacked)
            gate = V7.decide_v7(st.network, live, set(st.isolated), set(st.segmented))
            ia, sa = approve_all(st.network, live, st.isolated, st.segmented, gate.escalations)
            acrs_down = V7.services_down_v7(st.network, ia, sa, hacked)
            fi, fs = V7.m_full_isolation_safe(st.network, live)
            fa, fsa = approve_all(st.network, live, fi, fs, V7.decide_v7(st.network, live, fi, fs).escalations)
            full_down = V7.services_down_v7(st.network, fa, fsa, hacked)
            totals["acrs_down"] += len(acrs_down); totals["full_down"] += len(full_down)
            totals["unsafe"] += gate.status == S.REJECTED; totals["silent"] += gate.status == S.NOT_CONTAINED
            steps.append({
                "moment": sc.id.split("/")[-1], "description": sc.description, "alert": dict(sc.hacked),
                "risk": {h: r for h, r in st.risk.items() if r > 0},
                "isolate": sorted(st.isolated), "segment": sorted(st.segmented),
                "status": gate.status, "status_ar": STATUS_AR.get(gate.status, gate.status),
                "escalations": [{"rule": e["rule"], "target": e["target"]} for e in gate.escalations],
                "fallback": d.solver.get("fallback"), "method": d.solver.get("method"),
                "floor": [{"machine": m, "reason": r} for m, r in sorted(d.floor["reasons"].items())],
                "acrs_down": acrs_down, "full_down": full_down, "full_isolate": sorted(fi),
                "ms": round(ms, 1), "audit": st.audit[-1]["hash"][:12],
            })
            if i == fault_at:
                tline("ok" if gate.status != S.REJECTED else "bad",
                      f"fallback → floor + rule ({d.solver['fallback']})",
                      f"{gate.status}: isolate {sorted(st.isolated)} segment {sorted(st.segmented)}", gate.status != S.REJECTED)
                # process crash + restart (D12 b)
                before = set(st.isolated)
                tline("sys", "kill -9 acrs-engine", "process terminated", None, False)
                st = RC.State.load(state_path)
                released = sorted(before - st.isolated)
                tline("ok" if not released and st.audit_ok() else "bad", "systemctl start acrs-engine",
                      f"state reloaded from disk: {len(st.isolated)} isolated, released {len(released)}, "
                      f"audit chain {'intact' if st.audit_ok() else 'BROKEN'}", not released and st.audit_ok())
                steps[-1]["restart"] = {"released": released, "audit_ok": st.audit_ok(), "isolated": sorted(st.isolated)}

        result = {"incident": {k: v for k, v in it.items() if not k.startswith("_")}, "mode": mode, "model": model,
                  "steps": steps, "terminal": term, "totals": totals}
        if mode == "fault":
            result["recovery"] = self._recover(st, it, tline, roles)
        td.cleanup()
        result["terminal"] = term
        result["audit_ok"] = st.audit_ok()
        result["audit_entries"] = len(st.audit)
        return result

    # ------------------------------------------------------------------ recovery terminal session
    def _recover(self, st, it, tline, roles) -> dict:
        def cmd(line, who="eng.hassan"):
            try:
                out = RC.run_command(st, line, who)
                ok = True
            except RC.Refused as e:
                st.log("refused", command=line, reason=str(e), by=who)
                out, ok = f"REFUSED: {e}", False
            if ok and line == "status":
                s = json.loads(out)
                out = (f"isolated {len(s['isolated'])} · segmented {len(s['segmented'])} · pending {len(s['pending'])} · "
                       f"shields {len(s['shields'])} · immunity {s['immunity'] or '[]'} · audit_ok {s['audit_ok']}")
            tline("cmd", f"acrs-recover> {line}", out if len(out) < 400 else out[:400] + "…", ok)
            return ok, out

        cmd("status")
        # 1) a premature readmit must be refused by the gate
        risky = sorted(h for h in st.isolated if st.risk.get(h, 0) >= S.HIGH_RISK)
        refused_ok = None
        if risky:
            ok, _ = cmd(f"readmit {risky[0]}")
            refused_ok = not ok
        # 2) rotate credentials, restore every host on the path still at high risk
        cmd("rotate-creds")
        pending = []
        for h in [h for h in st.risk if st.risk[h] >= S.HIGH_RISK]:
            ok, out = cmd(f"restore {h}")
            if ok and "pending #" in out:
                n = int(out.split("pending #")[1].split(",")[0].split()[0])
                pending.append(n)
        for n in pending:
            cmd(f"approve {n} eng.hassan", "eng.hassan")        # same person: refused (two-person rule)
            cmd(f"approve {n} sec.lead", "eng.hassan")           # a different person: executed
        # 3) close the incident and install immunity
        path = [h for h in it["_path"]]
        closed = False; fp_first = None
        if len(path) >= 2:
            ok, out = cmd(f"close-incident {it['id'][:24]} {'>'.join(path)}")
            closed = ok
            if ok and st.immunity.fingerprints:
                fp_first = list(st.immunity.fingerprints[-1].first_hop)
        cmd("status")
        # 4) the same attack again, against the immunised engine (fresh network state, immunity kept)
        replay = None
        if closed:
            imm = copy.deepcopy(st.immunity); imm.v13 = True
            fresh = RC.State(copy.deepcopy(it["_net"])); fresh.immunity = imm
            before_net = RC.State(copy.deepcopy(it["_net"]))
            down_after = down_before = 0
            for sc in it["_scs"]:
                RC.apply_alert(fresh, dict(sc.hacked)); RC.apply_alert(before_net, dict(sc.hacked))
            for s_ in (fresh, before_net):
                live = s_.scenario
                g = V7.decide_v7(s_.network, live, set(s_.isolated), set(s_.segmented))
                ia, sa = approve_all(s_.network, live, s_.isolated, s_.segmented, g.escalations)
                n = len(V7.services_down_v7(s_.network, ia, sa, set(live.hacked)))
                if s_ is fresh:
                    down_after = n; st_after = g.status
                else:
                    down_before = n
            replay = {"services_down_before": down_before, "services_down_after": down_after, "status": st_after,
                      "first_hop": fp_first}
            tline("ok" if down_after <= down_before else "bad", "replay same attack (immunised)",
                  f"{st_after}: services down {down_after} (before immunity {down_before})", down_after <= down_before)
        return {"refused_premature_readmit": refused_ok, "closed": closed, "replay": replay,
                "pending_two_person": len(pending), "audit_ok": st.audit_ok()}
