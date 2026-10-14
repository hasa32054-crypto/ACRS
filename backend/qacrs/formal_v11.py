"""v11 E2: machine-checked safety properties of the automatic path, with the solver treated as UNTRUSTED.
Rules: docs/qacrs/PREREGISTRATION_v11.md (E2).

    cd backend && python -m qacrs.formal_v11            # fidelity + HiGHS proofs (no Z3 needed) -> results/v11/formal.json
    cd backend && python -m qacrs.formal_v11 --z3       # also the Z3 proofs (pip install z3-solver)

Paths (all start at hassan.Engine.decide with an arbitrary solver output):
  X  firewall executor   PolicyExecutor.execute(sc, d.isolate), no approvals given
  S  ACRS service        hassan_service.to_acrs as it was before v11 (to_acrs_v10 below), actions marked auto
  G  the fix            hassan_service.to_acrs(net, d, sc=sc) since v11 (every auto action goes through gate_v11)

Model inputs (per machine m): R reported hacked, I solver says isolate, G solver says segment, K rate limiter keeps it;
global: F guard flag, C certificate verifies (path G only). Risks only matter to the rate limiter, which is modelled as
keeping ANY subset of the proposals (an over-approximation: a property proved here also holds for the real limiter).

Properties:  P1 never-isolate device never auto-isolated   P2 critical server never auto-isolated
             P3 auto-isolated => reported                  P4 auto-segmented => critical
             P5 guard flag => nothing auto-isolated        P6 median of 3 with 1 forged lies between the honest two
"""
from __future__ import annotations

import json
import random
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import numpy as np

from qacrs import hassan as H
from qacrs import hassan_service as HS
from qacrs import safety_checks as S
from qacrs.meta import meta
from qacrs.network import Network, Scenario, build as build_net
from qacrs.policy_executor import MockFirewallAdapter, PolicyAuditLog, PolicyExecutor

OUT = Path(__file__).parent / "results" / "v11"
FIDELITY_SEED, FIDELITY_N = 7541, 100_000
PROPS = ("P1", "P2", "P3", "P4", "P5")
MUTATIONS = ("skip_never_isolate", "ignore_guard", "segment_any")


@dataclass(frozen=True)
class Spec:
    name: str
    machines: tuple[str, ...]
    isolatable: tuple[bool, ...]
    critical: tuple[bool, ...]

    @classmethod
    def of(cls, net: Network) -> "Spec":
        return cls(net.name, tuple(m.name for m in net.machines), tuple(m.isolatable for m in net.machines),
                   tuple(m.critical for m in net.machines))

    @property
    def n(self) -> int:
        return len(self.machines)


def networks() -> list[Network]:
    from qacrs import sectors_v10 as SX
    nets = [build_net(1), build_net(2)]
    for name in ("factory48", "bank42", "univ45"):
        nets.append(getattr(SX, name)())
    return nets


# ------------------------------------------------------------------ reference model (plain Python) ----------------
def model(spec: Spec, R, I, G, K, F, C=True, path="S", mutation=None):
    """Automatic (isolate, segment) bit-lists for one input. R, I, G, K are lists of 0/1 per machine."""
    n = spec.n
    valid = any(R)
    mal = any(I[i] and G[i] for i in range(n))
    if not valid or mal:
        return [0] * n, [0] * n
    flag = F and mutation != "ignore_guard"
    iso = [I[i] and not flag and K[i] for i in range(n)]
    seg = list(G)
    if path == "X":
        never = any(iso[i] and not spec.isolatable[i] for i in range(n)) and mutation != "skip_never_isolate"
        crit = any(iso[i] and spec.critical[i] for i in range(n))
        return ([0] * n if (never or crit) else [int(b) for b in iso]), [0] * n
    if path == "S":
        return [int(b) for b in iso], [int(b) for b in seg]
    if path == "G":
        skip = mutation == "skip_never_isolate"           # the rule switched off everywhere in the gate path
        rejected = ((not skip and any(iso[i] and not spec.isolatable[i] for i in range(n)))
                    or (mutation != "segment_any" and any(seg[i] and not spec.critical[i] for i in range(n))))
        if rejected or not C:
            return [0] * n, [0] * n
        a_iso = [int(iso[i] and (spec.isolatable[i] or mutation in ("skip_never_isolate", "skip_never_isolate_filter_only"))
                     and not spec.critical[i] and R[i])
                 for i in range(n)]
        a_seg = [int(seg[i] and (spec.critical[i] or mutation in ("segment_any", "segment_any_filter_only"))) for i in range(n)]
        return a_iso, a_seg
    raise ValueError(path)


def violates(spec: Spec, prop: str, R, F, a_iso, a_seg) -> bool:
    n = spec.n
    if prop == "P1":
        return any(a_iso[i] and not spec.isolatable[i] for i in range(n))
    if prop == "P2":
        return any(a_iso[i] and spec.critical[i] for i in range(n))
    if prop == "P3":
        return any(a_iso[i] and not R[i] for i in range(n))
    if prop == "P4":
        return any(a_seg[i] and not spec.critical[i] for i in range(n))
    if prop == "P5":
        return bool(F) and any(a_iso)
    raise ValueError(prop)


# ------------------------------------------------------------------ the real code, with an injected solver ---------
def to_acrs_v10(net, d) -> dict:
    """hassan_service.to_acrs exactly as it was before v11 (commit 179a20e), kept so path S stays reproducible."""
    return {"actions": [{"level": "ISOLATE", "target": m, "auto": True} for m in d.isolate]
            + [{"level": "SEGMENT", "target": m, "auto": True} for m in d.segment]
            + [{"level": "RESTRICT", "target": m, "auto": True} for m in d.restrict]
            + [{"level": "APPROVAL", "target": e["target"], "auto": False} for e in d.escalations]}


def real(net: Network, R, I, G, F, risks, limit, path: str):
    """Run the real engine (+ executor / adapter / gate) on one input.
    Returns (auto_iso, auto_seg, K-as-used) and, for path G, the certificate result the gate saw."""
    names = [m.name for m in net.machines]
    hacked = {names[i]: risks[i] for i in range(len(names)) if R[i]}
    sc = Scenario("fid", net.name, hacked, "fidelity")
    iso_out = {names[i] for i in range(len(names)) if I[i]}
    seg_out = {names[i] for i in range(len(names)) if G[i]}
    eng = H.Engine(net, solver=lambda n_, s_: (set(iso_out), set(seg_out), "injected"),
                   limiter=H.RateLimiter(limit=limit))
    d = eng.decide(sc, flags=["forced flag"] if F else [])
    keep = set(d.isolate)
    K = [1 if (names[i] in keep or not I[i]) else 0 for i in range(len(names))]
    if path == "X":
        r = PolicyExecutor(net, MockFirewallAdapter(), PolicyAuditLog()).execute(sc, d.isolate)
        auto = set(d.isolate) if r.status == "PLANNED_DRY_RUN" else set()
        return [int(x in auto) for x in names], [0] * len(names), K
    if path in ("S", "G"):
        acts = (to_acrs_v10(net, d) if path == "S" else HS.to_acrs(net, d, sc=sc))["actions"]
        ai = {a["target"] for a in acts if a["auto"] and a["level"] == "ISOLATE"}
        sg = {a["target"] for a in acts if a["auto"] and a["level"] == "SEGMENT"}
        out = [int(x in ai) for x in names], [int(x in sg) for x in names], K
        if path == "G":
            from qacrs import gate_v11 as GV
            out = out + (GV.certificate_ok(net, sc, d),)
        return out
    raise ValueError(path)


def fidelity(net: Network, path: str, n: int, seed: int) -> dict:
    """Compare the reference model with the real code on random inputs. The rate limit is drawn at random and the
    set it actually kept is fed to the model as K, so the model is checked on what the limiter really did."""
    spec = Spec.of(net)
    rng = random.Random(seed)
    mism, first = 0, None
    for _ in range(n):
        R = [int(rng.random() < 0.3) for _ in range(spec.n)]
        if not any(R):
            R[rng.randrange(spec.n)] = 1
        I = [int(rng.random() < 0.25) for _ in range(spec.n)]
        G = [int(rng.random() < 0.15) for _ in range(spec.n)]
        F = int(rng.random() < 0.2)
        risks = [rng.randint(1, 10) for _ in range(spec.n)]
        limit = rng.choice((0, 1, 2, 3, 10 ** 9))
        got = real(net, R, I, G, F, risks, limit, path)
        a_iso, a_seg, K = got[:3]
        C = got[3] if len(got) > 3 else True                  # path G: the certificate result the gate really saw
        m_iso, m_seg = model(spec, R, I, G, K, F, C, path)
        if (a_iso, a_seg) != (list(m_iso), list(m_seg)):
            mism += 1
            first = first or {"R": R, "I": I, "G": G, "F": F, "risks": risks, "limit": limit}
    return {"network": net.name, "path": path, "n": n, "mismatches": mism, "first_mismatch": first}


# ------------------------------------------------------------------ prover 1: HiGHS 0/1 integer programme ----------
def milp_prove(spec: Spec, path: str, prop: str, mutation=None) -> dict:
    """Maximise the number of violated machines (P1-P4) or the flag-and-isolation indicator (P5) over ALL inputs.
    Optimum 0 => property proved for this network and path. Otherwise the optimal input is a counterexample."""
    from scipy.optimize import Bounds, LinearConstraint, milp
    n = spec.n
    names = []

    def var(nm):
        names.append(nm)
        return len(names) - 1

    R = [var(f"R{i}") for i in range(n)]; I = [var(f"I{i}") for i in range(n)]
    G = [var(f"G{i}") for i in range(n)]; K = [var(f"K{i}") for i in range(n)]
    F, C = var("F"), var("C")
    rows, lo, hi = [], [], []

    def cons(coef: dict, lb, ub):
        rows.append(coef); lo.append(lb); hi.append(ub)

    def AND(a, b):                       # z = a AND b
        z = var("and")
        cons({z: 1, a: -1}, -np.inf, 0); cons({z: 1, b: -1}, -np.inf, 0); cons({z: 1, a: -1, b: -1}, -1, np.inf)
        return z

    def NOT(a):
        z = var("not"); cons({z: 1, a: 1}, 1, 1)
        return z

    def OR(lst):                         # z = OR(lst); empty -> constant 0
        z = var("or")
        if not lst:
            cons({z: 1}, 0, 0); return z
        for a in lst:
            cons({z: 1, a: -1}, 0, np.inf)
        cons({z: 1, **{a: -1 for a in lst}}, -np.inf, 0)
        return z

    def CONST(v):
        z = var("const"); cons({z: 1}, v, v)
        return z

    ok = AND(OR(R), NOT(OR([AND(I[i], G[i]) for i in range(n)])))           # valid and not malformed
    flag = CONST(0) if mutation == "ignore_guard" else F
    iso = [AND(AND(AND(I[i], NOT(flag)), K[i]), ok) for i in range(n)]
    seg = [AND(G[i], ok) for i in range(n)]
    if path == "X":
        bad_never = OR([iso[i] for i in range(n) if not spec.isolatable[i]]) if mutation != "skip_never_isolate" else CONST(0)
        bad_crit = OR([iso[i] for i in range(n) if spec.critical[i]])
        admit = NOT(OR([bad_never, bad_crit]))
        a_iso = [AND(iso[i], admit) for i in range(n)]
        a_seg = [CONST(0) for _ in range(n)]
    elif path == "S":
        a_iso, a_seg = iso, seg
    elif path == "G":
        never = [] if mutation == "skip_never_isolate" else [iso[i] for i in range(n) if not spec.isolatable[i]]
        nonc = [] if mutation == "segment_any" else [seg[i] for i in range(n) if not spec.critical[i]]
        rej = OR(never + nonc)
        go = AND(NOT(rej), C)
        a_iso = [AND(AND(iso[i], R[i]), go) if ((spec.isolatable[i] or mutation in ("skip_never_isolate", "skip_never_isolate_filter_only"))
                                                 and not spec.critical[i]) else CONST(0) for i in range(n)]
        a_seg = [AND(seg[i], go) if (spec.critical[i] or mutation in ("segment_any", "segment_any_filter_only"))
                 else CONST(0) for i in range(n)]
    else:
        raise ValueError(path)
    if prop == "P1":
        viol = [a_iso[i] for i in range(n) if not spec.isolatable[i]]
    elif prop == "P2":
        viol = [a_iso[i] for i in range(n) if spec.critical[i]]
    elif prop == "P3":
        viol = [AND(a_iso[i], NOT(R[i])) for i in range(n)]
    elif prop == "P4":
        viol = [a_seg[i] for i in range(n) if not spec.critical[i]]
    elif prop == "P5":
        viol = [AND(F, OR(a_iso))]
    else:
        raise ValueError(prop)
    nv = len(names)
    A = np.zeros((len(rows), nv))
    for r, coef in enumerate(rows):
        for j, a in coef.items():
            A[r, j] += a
    c = np.zeros(nv)
    for v in viol:
        c[v] -= 1                                  # milp minimises
    t = time.perf_counter()
    res = milp(c, constraints=LinearConstraint(A, lo, hi), integrality=np.ones(nv), bounds=Bounds(0, 1))
    if not res.success:
        return {"prover": "highs", "status": "error", "message": res.message}
    x = np.round(res.x).astype(int)
    best = int(round(-res.fun))
    out = {"prover": "highs", "max_violations": best, "proved": best == 0, "ms": round(1000 * (time.perf_counter() - t), 1)}
    if best:
        pick = lambda idx: [spec.machines[i] for i in range(n) if x[idx[i]]]
        cex = {"reported": pick(R), "solver_isolate": pick(I), "solver_segment": pick(G), "limiter_keeps": pick(K),
               "guard_flag": bool(x[F]), "certificate_ok": bool(x[C])}
        Rb, Ib, Gb, Kb = ([int(x[v[i]]) for i in range(n)] for v in (R, I, G, K))
        m_iso, m_seg = model(spec, Rb, Ib, Gb, Kb, int(x[F]), bool(x[C]), path, mutation)
        cex["reference_model_agrees"] = violates(spec, prop, Rb, int(x[F]), m_iso, m_seg)
        out["counterexample"] = cex
    return out


# ------------------------------------------------------------------ prover 2: Z3 ----------------------------------
def z3_prove(spec: Spec, path: str, prop: str, mutation=None) -> dict:
    import z3
    n = spec.n
    R = [z3.Bool(f"R_{m}") for m in spec.machines]; I = [z3.Bool(f"I_{m}") for m in spec.machines]
    G = [z3.Bool(f"G_{m}") for m in spec.machines]; K = [z3.Bool(f"K_{m}") for m in spec.machines]
    F, C = z3.Bool("F"), z3.Bool("C")
    ok = z3.And(z3.Or(*R), z3.Not(z3.Or(*[z3.And(I[i], G[i]) for i in range(n)])))
    flag = z3.BoolVal(False) if mutation == "ignore_guard" else F
    iso = [z3.And(I[i], z3.Not(flag), K[i], ok) for i in range(n)]
    seg = [z3.And(G[i], ok) for i in range(n)]
    false = z3.BoolVal(False)
    if path == "X":
        bad_never = z3.Or(false, *[iso[i] for i in range(n) if not spec.isolatable[i]]) \
            if mutation != "skip_never_isolate" else false
        bad_crit = z3.Or(false, *[iso[i] for i in range(n) if spec.critical[i]])
        a_iso = [z3.And(iso[i], z3.Not(z3.Or(bad_never, bad_crit))) for i in range(n)]
        a_seg = [false] * n
    elif path == "S":
        a_iso, a_seg = iso, seg
    elif path == "G":
        never = [] if mutation == "skip_never_isolate" else [iso[i] for i in range(n) if not spec.isolatable[i]]
        nonc = [] if mutation == "segment_any" else [seg[i] for i in range(n) if not spec.critical[i]]
        rej = z3.Or(false, *never, *nonc)
        go = z3.And(z3.Not(rej), C)
        a_iso = [z3.And(iso[i], R[i], go) if ((spec.isolatable[i] or mutation in ("skip_never_isolate", "skip_never_isolate_filter_only"))
                                              and not spec.critical[i]) else false for i in range(n)]
        a_seg = [z3.And(seg[i], go) if (spec.critical[i] or mutation in ("segment_any", "segment_any_filter_only"))
                 else false for i in range(n)]
    else:
        raise ValueError(path)
    bad = {"P1": z3.Or(false, *[a_iso[i] for i in range(n) if not spec.isolatable[i]]),
           "P2": z3.Or(false, *[a_iso[i] for i in range(n) if spec.critical[i]]),
           "P3": z3.Or(false, *[z3.And(a_iso[i], z3.Not(R[i])) for i in range(n)]),
           "P4": z3.Or(false, *[a_seg[i] for i in range(n) if not spec.critical[i]]),
           "P5": z3.And(F, z3.Or(false, *a_iso))}[prop]
    s = z3.Solver(); s.add(bad)
    t = time.perf_counter()
    r = s.check()
    out = {"prover": "z3", "result": str(r), "proved": r == z3.unsat, "ms": round(1000 * (time.perf_counter() - t), 1)}
    if r == z3.sat:
        mdl = s.model()
        val = lambda b: z3.is_true(mdl.eval(b, model_completion=True))
        pick = lambda v: [spec.machines[i] for i in range(n) if val(v[i])]
        out["counterexample"] = {"reported": pick(R), "solver_isolate": pick(I), "solver_segment": pick(G),
                                 "limiter_keeps": pick(K), "guard_flag": val(F), "certificate_ok": val(C)}
    return out


def z3_median_p6() -> dict:
    """P6 over all integers a, b (honest) and f (forged): min(a,b) <= median(a,b,f) <= max(a,b)."""
    import z3
    a, b, f = z3.Ints("a b f")
    lo, hi = z3.If(a <= b, a, b), z3.If(a <= b, b, a)
    med = z3.If(f <= lo, lo, z3.If(f >= hi, hi, f))           # median of (lo, hi, f)
    s = z3.Solver(); s.add(z3.Not(z3.And(lo <= med, med <= hi)))
    r = s.check()
    return {"prover": "z3", "result": str(r), "proved": r == z3.unsat}


def exhaustive_median_p6() -> dict:
    """P6 on the whole reading range 0-10 (all 11^3 cases), checked with the real fusion code."""
    from qacrs import sensors_v11 as SV
    bad = [(a, b, f) for a in range(11) for b in range(11) for f in range(11) if not SV.median_bounded((a, b), f)]
    return {"prover": "exhaustive 0-10 (real fuse code)", "cases": 11 ** 3, "violations": len(bad), "proved": not bad}


# ------------------------------------------------------------------ run ---------------------------------------------
def gate_available() -> bool:
    return (Path(__file__).parent / "gate_v11.py").exists()


def run(use_z3: bool = False, fidelity_n: int = FIDELITY_N) -> dict:
    paths = ("X", "S", "G") if gate_available() else ("X", "S")
    nets = networks()
    res = {"paths": list(paths), "proofs": {}, "fidelity": [], "mutations": {}, "defence_in_depth": {}, "P6": {}}
    for net in nets:
        spec = Spec.of(net)
        for path in paths:
            for prop in PROPS:
                key = f"{net.name}/{path}/{prop}"
                res["proofs"][key] = {"highs": milp_prove(spec, path, prop)}
                if use_z3:
                    res["proofs"][key]["z3"] = z3_prove(spec, path, prop)
            res["fidelity"].append(fidelity(net, path, fidelity_n, FIDELITY_SEED))
        if "G" in paths:
            for mut, prop in zip(MUTATIONS, ("P1", "P5", "P4")):
                key = f"{net.name}/G/{mut}"
                res["mutations"][key] = {"property": prop, "highs": milp_prove(spec, "G", prop, mut)}
                if use_z3:
                    res["mutations"][key]["z3"] = z3_prove(spec, "G", prop, mut)
            for mut, prop in (("skip_never_isolate_filter_only", "P1"), ("segment_any_filter_only", "P4")):
                key = f"{net.name}/G/{mut}"                                   # descriptive: defence in depth
                res["defence_in_depth"][key] = {"property": prop, "note": "gate filter removed, engine rejection kept",
                                                "highs": milp_prove(spec, "G", prop, mut)}
    res["P6"]["exhaustive"] = exhaustive_median_p6()
    if use_z3:
        res["P6"]["z3"] = z3_median_p6()
    return res


def main():
    use_z3 = "--z3" in sys.argv
    t = time.time()
    res = run(use_z3)
    res["meta"] = meta("v11_formal", extra_files=("hassan.py", "hassan_service.py", "policy_executor.py", "formal_v11.py",
                                                  "sensors_v11.py") + (("gate_v11.py",) if gate_available() else ()),
                       preregistration="docs/qacrs/PREREGISTRATION_v11.md", fidelity_seed=FIDELITY_SEED,
                       fidelity_n=FIDELITY_N, z3=use_z3)
    OUT.mkdir(parents=True, exist_ok=True)
    name = "formal_z3.json" if use_z3 else "formal.json"
    (OUT / name).write_text(json.dumps(res, indent=1))
    for key, v in res["proofs"].items():
        h = v["highs"]
        tag = "PROVED" if h.get("proved") else f"FAILS  e.g. {h.get('counterexample')}"
        z = f" | z3 {v['z3']['result']}" if "z3" in v else ""
        print(f"{key:28s} {tag}{z}")
    bad_fid = [f for f in res["fidelity"] if f["mismatches"]]
    print(f"fidelity: {sum(f['n'] for f in res['fidelity'])} inputs, mismatches {sum(f['mismatches'] for f in res['fidelity'])}")
    for f in bad_fid:
        print("  mismatch", f["network"], f["path"], f["first_mismatch"])
    for key, v in res["mutations"].items():
        print(f"mutation {key:32s} caught: {not v['highs'].get('proved')}")
    for key, v in res["defence_in_depth"].items():
        print(f"one layer removed {key:40s} still safe: {v['highs'].get('proved')}")
    print("P6", res["P6"], f"total {time.time() - t:.0f} s")


if __name__ == "__main__":
    main()
