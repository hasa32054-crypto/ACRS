"""Phase 18 (v12): D11 terminal gate, D12 survival, D13 immunity. Rules: PREREGISTRATION_v12.md (T8, T9).

    cd backend && python -m qacrs.v12.phase18_survive_immune    -> qacrs/results/v12/survive_immune.json
"""
from __future__ import annotations

import copy
import json
import random
import tempfile
import time
from pathlib import Path

from qacrs import phase16_v11 as P16
from qacrs import safety_checks as S
from qacrs.v12 import immunity as IM
from qacrs.v12 import qubo_v12 as Q
from qacrs.v12 import realism_v12 as R
from qacrs.v12 import recover as RC
from qacrs.network import Scenario

OUT = Path(__file__).parent.parent / "results" / "v12"


# ------------------------------------------------------------------ D12 survival -----------------------------------
def slow_solver(net, sc):
    time.sleep(5); raise AssertionError("never reached")


def broken_solver(net, sc):
    raise RuntimeError("solver crashed")


def survival(items) -> dict:
    out = {}
    for name, solver, budget in (("solver_timeout", slow_solver, 200), ("solver_crash", broken_solver, 500)):
        unsafe = silent = 0; times = []; fb = 0
        for net, sc in items:
            t = time.perf_counter()
            d = RC.decide_with_budget(net, sc, None, budget_ms=budget, solver=solver)
            times.append(1000 * (time.perf_counter() - t))
            unsafe += d.status == S.REJECTED; silent += d.status == S.NOT_CONTAINED; fb += d.solver["fallback"] is not None
        times.sort()
        out[name] = {"n": len(items), "unsafe": unsafe, "silent": silent, "fallback_used": fb,
                     "median_ms": round(times[len(times) // 2], 1), "max_ms": round(times[-1], 1)}
    # (b) crash + restart: decide, persist, reload, check nothing released and audit chain intact
    released = 0; audit_bad = 0; n = 0
    with tempfile.TemporaryDirectory() as td:
        for net, sc in items[:200]:
            p = Path(td) / "s.json"
            st = RC.State(copy.deepcopy(net))
            RC.apply_alert(st, sc.hacked, p)
            before = set(st.isolated)
            st2 = RC.State.load(p)                                        # "restart"
            RC.apply_alert(st2, {h: r for h, r in list(sc.hacked.items())[:1]}, p)     # same alert again after restart
            released += bool(before - st2.isolated); audit_bad += not st2.audit_ok(); n += 1
    out["crash_restart"] = {"n": n, "released_hosts": released, "audit_chain_broken": audit_bad}
    # (c) flood during recovery: 1,000 alerts at full speed on one live state
    net, sc0 = items[0]
    st = RC.State(copy.deepcopy(net))
    rng = random.Random(12014)
    hosts = [m.name for m in net.machines]
    unsafe = 0; t = time.perf_counter(); n_fl = 1000
    for i in range(n_fl):
        h = rng.choice(hosts)
        d = RC.apply_alert(st, {h: rng.randint(1, 10)})
        unsafe += d.status == S.REJECTED
        if i % 100 == 50:
            try:
                RC.run_command(st, "rotate-creds", "eng")
            except RC.Refused:
                pass
    out["flood"] = {"alerts": n_fl, "seconds": round(time.perf_counter() - t, 2), "unsafe": unsafe,
                    "isolated_at_end": len(st.isolated), "audit_ok": st.audit_ok(),
                    "never_isolatable_isolated": sorted(h for h in st.isolated if not net.machine(h).isolatable)}
    out["met"] = all(out[k]["unsafe"] == 0 for k in ("solver_timeout", "solver_crash", "flood")) \
        and out["crash_restart"]["released_hosts"] == 0 and not out["flood"]["never_isolatable_isolated"]
    return out


# ------------------------------------------------------------------ D11 terminal gate ------------------------------
def terminal_gate(net) -> dict:
    st = RC.State(copy.deepcopy(net))
    crit = next(m.name for m in net.machines if m.critical)
    pc = next(m.name for m in net.machines if m.name.startswith("pc_"))
    RC.apply_alert(st, {pc: 9, crit: 8})
    checks = {}

    def refused(cmd, who="eng"):
        try:
            RC.run_command(st, cmd, who); return False
        except RC.Refused:
            return True
    checks["readmit_high_risk_refused"] = refused(f"readmit {pc}")
    RC.run_command(st, f"restore {pc}", "eng")
    checks["readmit_after_restore_ok"] = not refused(f"readmit {pc}")
    RC.run_command(st, "rotate-creds", "eng")
    r = RC.run_command(st, f"restore {crit}", "eng")
    checks["critical_needs_two"] = "pending" in r
    n = next(iter(st.pending))
    checks["same_person_twice_refused"] = refused(f"approve {n} eng")
    checks["second_person_ok"] = not refused(f"approve {n} other")
    checks["unknown_host_refused"] = refused("readmit ghost")
    checks["close_with_risk_refused"] = (RC.apply_alert(st, {pc: 9}) is not None) and refused(f"close-incident t {pc}>{crit}")
    checks["audit_ok"] = st.audit_ok()
    st.audit[0]["event"] = "tampered"
    checks["audit_tamper_detected"] = not st.audit_ok()
    return checks | {"met": all(checks.values())}


# ------------------------------------------------------------------ D13 immunity -----------------------------------
def similar_scenario(net, sc, path, rng) -> tuple[Scenario, list[str]]:
    """Same roles, different hosts of the same role where another exists (fixed rule), same risks."""
    groups: dict[str, list[str]] = {}
    for m in net.machines:
        groups.setdefault(IM.role_key(net, m.name), []).append(m.name)
    ren = {}
    for h in path:
        alt = [x for x in groups[IM.role_key(net, h)] if x != h and x not in ren.values()]
        ren[h] = rng.choice(alt) if alt else h
    hacked = {ren.get(h, h): r for h, r in sc.hacked.items()}
    return Scenario(sc.id + "/similar", net.name, hacked, "similar"), [ren.get(h, h) for h in path]


def dissimilar_scenario(net, sc, path, rng) -> Scenario | None:
    """A different entry role and no host of the original path (fixed rule)."""
    entry_role = IM.role_key(net, path[0])
    cands = [m.name for m in net.machines if m.name.startswith(("web_", "pc_")) and IM.role_key(net, m.name) != entry_role
             and m.name not in path]
    if not cands:
        return None
    succ: dict[str, list[str]] = {}
    for a, b in net.links:
        succ.setdefault(a, []).append(b)
    start = rng.choice(cands); p = [start]; cur = start
    for _ in range(3):
        nxt = [n for n in succ.get(cur, []) if n not in p and n not in path]
        if not nxt:
            break
        cur = rng.choice(nxt); p.append(cur)
    hacked = {h: (5 if i == 0 else 7) for i, h in enumerate(p)}
    return Scenario(sc.id + "/dissimilar", net.name, hacked, "dissimilar")


def path_of(d: dict) -> list[str]:
    ap = d.get("attack_path", [])
    path = []
    for hop in ap:
        for h in hop[:2]:
            if h not in path and any(m["name"] == h for m in d["machines"]):
                path.append(h)
    return path


def immunity(real, v13: bool = False) -> dict:
    rng = random.Random(12015)
    rows = []
    for stem, net, scs, d in real:
        path = path_of(d)
        if len(path) < 2:
            rows.append({"incident": stem, "skipped": "no path with >= 2 modelled hosts"}); continue
        tech = [t for hop in d.get("attack_path", []) for t in hop[2].split() if t.startswith("T1")] if d.get("attack_path") else []
        first, last = scs[0], scs[-1]
        before = {k: Q.evaluate_policy(net, s, "v12") for k, s in (("first", first), ("last", last))}
        im = IM.Immunity(v13=v13); fp = im.learn(net, path, tech, stem)
        after_same = {k: Q.evaluate_policy(net, s, "v12", im) for k, s in (("first", first), ("last", last))}
        sim, spath = similar_scenario(net, last, path, rng)
        sim_before = Q.evaluate_policy(net, sim, "v12"); sim_after = Q.evaluate_policy(net, sim, "v12", im)
        dis = dissimilar_scenario(net, last, path, rng)
        dis_before = Q.evaluate_policy(net, dis, "v12") if dis else None
        dis_after = Q.evaluate_policy(net, dis, "v12", im) if dis else None
        down = lambda e: len(e["services_down_after_approval"])  # noqa: E731
        rows.append({
            "incident": stem, "fingerprint": fp.as_dict(),
            "same_first_hop_isolated_at_m1": path[0] in after_same["first"]["isolate"],
            "same_down_before_after": [down(before["last"]), down(after_same["last"])],
            "same_ok": down(after_same["last"]) <= down(before["last"]) and path[0] in after_same["first"]["isolate"],
            "similar_path": spath, "similar_down_before_after": [down(sim_before), down(sim_after)],
            "similar_first_hop_isolated": spath[0] in sim_after["isolate"],
            "similar_ok": down(sim_after) <= down(sim_before) and spath[0] in sim_after["isolate"],
            "dissimilar": None if dis is None else {
                "hacked": dis.hacked, "identical_decision": (dis_before["isolate"], dis_before["segment"]) == (dis_after["isolate"], dis_after["segment"]),
                "healthy_isolated_after": dis_after["healthy_isolated"]},
        })
    tested = [r for r in rows if "skipped" not in r]
    dis_rows = [r for r in tested if r["dissimilar"]]
    summary = {"n": len(tested), "same_ok": sum(r["same_ok"] for r in tested), "similar_ok": sum(r["similar_ok"] for r in tested),
               "dissimilar_identical": sum(r["dissimilar"]["identical_decision"] for r in dis_rows), "dissimilar_n": len(dis_rows)}
    summary["met"] = (summary["same_ok"] == summary["n"] and summary["similar_ok"] >= 6
                      and summary["dissimilar_identical"] == summary["dissimilar_n"])
    return {"summary": summary, "rows": rows}


# ------------------------------------------------------------------ main ------------------------------------------
def main() -> None:
    t0 = time.time()
    real = []
    for p in sorted(P16.INC.glob("*.json")):
        d, net, scs = P16.load(p)
        if net is not None:
            real.append((p.stem, net, scs, d))
    nets, scen = R.generate()
    byname = {n.name: n for n in nets}
    items = [(net, sc) for _, net, scs, _ in real for sc in scs] + [(byname[n], sc) for n, scs in scen[:150] for sc in scs]
    res = {"T8_survival": survival(items), "D11_terminal_gate": terminal_gate(real[0][1]), "T9_immunity": immunity(real),
           "meta": {"n_items": len(items), "seconds": round(time.time() - t0, 1)}}
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "survive_immune.json").write_text(json.dumps(res, indent=1, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({"T8": res["T8_survival"]["met"], "D11": res["D11_terminal_gate"]["met"],
                      "T9": res["T9_immunity"]["summary"]}, indent=1))
    print(json.dumps({k: v for k, v in res["T8_survival"].items() if k != "met"}, indent=1))
    for r in res["T9_immunity"]["rows"]:
        print(r.get("incident"), r.get("skipped") or (r["same_down_before_after"], r["similar_down_before_after"],
                                                        r["same_first_hop_isolated_at_m1"], r["similar_first_hop_isolated"],
                                                        r["dissimilar"] and r["dissimilar"]["identical_decision"]))


if __name__ == "__main__":
    from qacrs.network import Scenario  # noqa: E402  (used by helpers above)
    main()
