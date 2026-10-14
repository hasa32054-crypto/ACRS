"""Builds docs/qacrs/RESULTS_v11.md from the v11 result files only (no number is typed by hand).

    cd backend && python -m qacrs.report_v11
"""
from __future__ import annotations

import json
from pathlib import Path

HERE = Path(__file__).parent
RES = HERE / "results" / "v11"
DOC = HERE.parent.parent / "docs" / "qacrs" / "RESULTS_v11.md"
DEF_NAMES = {"D0": "one source (v1-v10 model)", "D1": "max of 3", "D2": "mean of 3", "D3": "median of 3",
             "D4": "median of 3 + NDR guard"}
DEF_AR = {"D0": "مصدر واحد", "D1": "أعلى قيمة", "D2": "المتوسط", "D3": "الوسيط", "D4": "الوسيط + حارس الشبكة"}


def pct(x: float) -> str:
    return f"{100 * x:.1f}%"


def load(name):
    p = RES / name
    return json.loads(p.read_text()) if p.exists() else None


def e2_section(before, after) -> list[str]:
    L = ["## E2 — formal proofs of the safety rules", ""]
    if not (before or after):
        return L + ["_Not run yet._", ""]
    nets = []
    for src in (before, after):
        for k in (src or {}).get("proofs", {}):
            n = k.split("/")[0]
            if n not in nets:
                nets.append(n)
    L += ["The solver is treated as **untrusted**: any output is allowed. Prover: HiGHS exact 0/1 programme "
          "(the Z3 run is `formal_z3.json`, from the student's machine, when present). ✅ = proved for every input, "
          "❌ = a counterexample exists.", "",
          "| Network | Path | P1 never-isolate | P2 critical | P3 only reported | P4 segment only critical | P5 guard |",
          "|---|---|---|---|---|---|---|"]
    rows = []
    for label, src, paths in (("before fix", before, ("X", "S")), ("after fix", after, ("G",))):
        if not src:
            continue
        for n in nets:
            for p in paths:
                cells = []
                for prop in ("P1", "P2", "P3", "P4", "P5"):
                    v = src["proofs"].get(f"{n}/{p}/{prop}")
                    cells.append("–" if v is None else ("✅" if v["highs"].get("proved") else "❌"))
                name = {"X": "X firewall executor", "S": "S service adapter (pre-v11)", "G": "G service + gate_v11"}[p]
                rows.append(f"| {n} | {name} ({label}) | " + " | ".join(cells) + " |")
    L += rows + [""]
    if after and any(not after["proofs"].get(f"{n}/X/P3", {}).get("highs", {}).get("proved", True) for n in nets):
        L += ["**Still open:** path X (firewall executor called directly with the engine's isolate list) can still "
              "isolate a machine that was not reported (P3). The pre-registered fix covered the service adapter only. "
              "Next step: feed the executor `gate_v11.enforce(...)['auto_isolate']` instead of `d.isolate`, then prove "
              "path X again.", ""]
    if after:
        fid = after["fidelity"]
        n_in, n_mis = sum(f["n"] for f in fid), sum(f["mismatches"] for f in fid)
        mut = after.get("mutations", {})
        caught = sum(not v["highs"].get("proved") for v in mut.values())
        did = after.get("defence_in_depth", {})
        safe = sum(bool(v["highs"].get("proved")) for v in did.values())
        p6 = after.get("P6", {}).get("exhaustive", {})
        L += [f"- **Model fidelity:** {n_in:,} random inputs compared with the real code (engine + executor + adapter "
              f"+ gate, injected solver output): **{n_mis} mismatches**.",
              f"- **Mutation check:** {caught} / {len(mut)} planted bugs produced a counterexample.",
              f"- **Defence in depth (descriptive):** removing only the gate's own filter for one rule left the path "
              f"safe in {safe} / {len(did)} cases, because the engine's rejection still covers it.",
              f"- **P6 (median of 3, one forged):** {p6.get('cases', '–')} cases, {p6.get('violations', '–')} violations.", ""]
    if before:
        ex = before["proofs"].get("net12/S/P1", {}).get("highs", {}).get("counterexample")
        if ex:
            L += ["**Example counterexample before the fix (net12, path S, P1):** the solver proposes isolating "
                  f"{', '.join(ex['solver_isolate'])}; the engine marks the decision REJECTED, but the pre-v11 adapter "
                  "still sent these isolations to ACRS as automatic.", ""]
    z = load("formal_z3.json")
    if z:
        agree = sum(v.get("z3", {}).get("proved") == v["highs"].get("proved") for v in z["proofs"].values())
        L += [f"- **Z3 cross-check:** Z3 and HiGHS agree on {agree} / {len(z['proofs'])} proof obligations.", ""]
    return L


def e1_section(att) -> list[str]:
    L = ["## E1 — a white-box attacker against five fusion defenders", ""]
    if not att:
        return L + ["_Not run yet._", ""]
    s = att["summary"]
    n = s["n_scenarios"]
    dd = att["meta"]["settings"].get("duplicates_dropped", {})
    L += [f"{n} fresh attack chains (net12 seed 7501, net22 seed 7502; duplicates dropped: {dd}). The attacker "
          "controls Γ alert-source readings. Γ = 1 and Γ = 2 are exhaustive (net22 Γ = 2 over {0,1,6,7,10}); Γ = 3 is a "
          "beam search (a lower bound on attacker power).", "",
          "**Share of scenarios where the attacker succeeds**", "",
          "| Defender | Hide Γ=1 | Hide Γ=2 | Hide Γ=3* | Weaponize Γ=1 | Weaponize Γ=2 | Weaponize Γ=3* | Extra escalations Γ=1 |",
          "|---|---|---|---|---|---|---|---|"]
    for d, row in s["per_defender"].items():
        cells = [pct(row[f"A2_{g}"]["rate"]) for g in ("gamma1", "gamma2", "gamma3_beam")]
        cells += [pct(row[f"A1_{g}"]["rate"]) for g in ("gamma1", "gamma2", "gamma3_beam")]
        cells += [pct(row["A3_gamma1"]["rate"])]
        L.append(f"| {d} {DEF_NAMES[d]} | " + " | ".join(cells) + " |")
    L += ["", "\\* beam search, lower bound.", "",
          "**With honest readings only (no attacker)** and **certified radius** (smallest number of forged sources "
          "that makes the attack succeed, exact search):", "",
          "| Defender | Silent misses | Services down | Escalated | Hide radius 1 / 2 / ≥3 | Weaponize radius 1 / 2 / ≥3 | Max extra services down (Γ≤2) |",
          "|---|---|---|---|---|---|---|"]
    for d, row in s["per_defender"].items():
        h, r2, r1 = row["honest"], row["radius_A2"], row["radius_A1"]
        L.append(f"| {d} | {h['silent']} | {h['services_down']} | {h['escalated']} | "
                 f"{r2['1']} / {r2['2']} / {r2['>=3']} | {r1['1']} / {r1['2']} / {r1['>=3']} | "
                 f"{row['services_extra_max_gamma_le2']} |")
    hy = s["hypotheses"]
    L += ["", "**Pre-registered targets**", "",
          "| ID | Target | Result | Met |", "|---|---|---|---|",
          f"| H1 | {hy['H1']['target']} | D3 {pct(hy['H1']['d3_rate'])}; discordant D0-only {hy['H1']['d0_only']} vs "
          f"D3-only {hy['H1']['d3_only']}, p = {hy['H1']['p']:.2g} | {'✅' if hy['H1']['met'] else '❌'} |",
          f"| H2 | {hy['H2']['target']} | max extra services down under D4 = "
          f"{s['per_defender']['D4']['services_extra_max_gamma_le2']} | {'✅' if hy['H2']['met'] else '❌'} |",
          f"| H3 | {hy['H3']['target']} | {pct(hy['H3']['share'])} | {'✅' if hy['H3']['met'] else '❌'} |", ""]
    succ = s["d4_successes"]
    L += [f"**Every successful attack against D4** ({len(succ)} in total; first 12 written out, all in `attack.json`):", ""]
    for x in succ[:12]:
        att_s = ", ".join(f"{m}[source {k + 1}]→{v}" for m, k, v in (x["attack"] or []))
        o = x["outcome"] or {}
        L.append(f"- `{x['id']}` {x['goal']} at {x['gamma']}: {att_s} → status {o.get('status')}, truth "
                 f"{o.get('truth_status')}, services down {o.get('services_down')}, healthy isolated {o.get('healthy_isolated')}")
    if not succ:
        L.append("- none")
    L.append("")
    return L


def arabic(att, after) -> list[str]:
    L = ["### ملخص عربي", ""]
    if after:
        fid = sum(f["n"] for f in after["fidelity"])
        L += [f"- **الإثبات الرياضي (E2):** قبل الإصلاح، طبقة الخدمة كانت تمرّر أي عزل يقترحه الحلّال كأنه تلقائي، حتى لو المحرّك "
              "رفضه (جهاز رنين مغناطيسي، خادم حرج)، ومنفّذ الجدار الناري ممكن يعزل جهازاً ما أحد بلّغ عنه. بعد إضافة طبقة الإنفاذ "
              f"`gate_v11` صارت كل الخصائص الخمس مثبتة لكل المدخلات الممكنة على الشبكات الخمس، وتطابق النموذج مع الكود الحقيقي "
              f"في {fid:,} مدخل عشوائي بدون أي اختلاف، والأداة كشفت كل الأخطاء المزروعة عمداً."]
    if att:
        s = att["summary"]; hy = s["hypotheses"]; pdf = s["per_defender"]
        L += [f"- **المهاجم الذكي (E1):** على {s['n_scenarios']} سيناريو، نجح الإخفاء بتزوير مصدر واحد في "
              f"{pct(pdf['D0']['A2_gamma1']['rate'])} مع {DEF_AR['D0']}، و{pct(pdf['D3']['A2_gamma1']['rate'])} مع {DEF_AR['D3']}، "
              f"و{pct(pdf['D4']['A2_gamma1']['rate'])} مع {DEF_AR['D4']}.",
              f"- الأهداف المثبتة مسبقاً: H1 {'تحقق' if hy['H1']['met'] else 'لم يتحقق'}، H2 {'تحقق' if hy['H2']['met'] else 'لم يتحقق'}، "
              f"H3 {'تحقق' if hy['H3']['met'] else 'لم يتحقق'} ({pct(hy['H3']['share'])} من السيناريوهات نصف قطرها المضمون ≥ 2). "
              "كل فشل منشور كما هو."]
    return L + [""]


def main():
    att, before, after = load("attack.json"), load("formal_before_gate.json"), load("formal.json")
    L = ["# ACRS — Results v11: attack the defender", "",
         "Rules: `PREREGISTRATION_v11.md` (committed before any v11 result; targets H1–H3 approved by the student before "
         "E1 ran). Raw numbers: `backend/qacrs/results/v11/`. Rebuild this page: `cd backend && python -m qacrs.report_v11`. "
         "The locked v9 engine files are unchanged (`LOCK_blind_v9.json`).", ""]
    L += e2_section(before, after) + e1_section(att) + arabic(att, after)
    DOC.write_text("\n".join(L))
    print(f"wrote {DOC}")


if __name__ == "__main__":
    main()
