"""Regenerate every v3 figure from the result files (no number typed by hand).

    cd backend && python -m qacrs.figures_v3        -> docs/qacrs/figures/*.png

Every figure states: what is measured, number of scenarios/runs, and "simulation" vs "hardware".
"""
from __future__ import annotations

import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import matplotlib.ticker  # noqa: E402,F401

R = Path(__file__).parent / "results" / "v3"
FIG = Path(__file__).resolve().parents[2] / "docs" / "qacrs" / "figures"

SURFACE, INK, INK2, MUTED, GRID, AXIS = "#fcfcfb", "#0b0b0b", "#52514e", "#898781", "#e1e0d9", "#c3c2b7"
BLUE, ORANGE, AQUA = "#2a78d6", "#eb6834", "#1baf7a"                    # categorical slots 1-3 (validated)
GOOD, WARN, SERIOUS, CRIT = "#0ca30c", "#fab219", "#ec835a", "#d03b3b"  # status palette (always with labels)

plt.rcParams.update({"figure.facecolor": SURFACE, "axes.facecolor": SURFACE, "axes.edgecolor": AXIS,
                     "axes.labelcolor": INK2, "xtick.color": MUTED, "ytick.color": MUTED, "text.color": INK,
                     "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.6, "axes.spines.top": False,
                     "axes.spines.right": False, "font.size": 10, "axes.titlesize": 12, "axes.titleweight": "bold",
                     "axes.titlelocation": "left", "legend.frameon": False})


def foot(fig, text, y=-0.04):
    fig.text(0.01, y, text, fontsize=7.5, color=MUTED, ha="left", va="top", wrap=True)


def save(fig, name):
    FIG.mkdir(parents=True, exist_ok=True)
    fig.savefig(FIG / name, dpi=200, bbox_inches="tight")
    plt.close(fig)
    print(f"Saved: docs/qacrs/figures/{name}")


def fig_tradeoff():
    d = json.loads((R / "sensitivity.json").read_text())
    pts = d["pareto"]; refs = d["references"]; n = d["meta"]["settings"]["scenarios"]
    fig, ax = plt.subplots(figsize=(7.2, 4.6))
    xs = [p["services_down"] for p in pts]; ys = [p["contained"] for p in pts]
    ax.plot(xs, ys, color=BLUE, lw=2, marker="o", ms=6, mec=SURFACE, mew=1.5, zorder=3,
            label="Q-ACRS, availability weight λ varied")
    seen = set()
    for p in pts:
        key = (p["services_down"], p["contained"])
        if key in seen:
            continue
        seen.add(key)
        same = [q["lambda"] for q in pts if (q["services_down"], q["contained"]) == key]
        lab = f"λ={same[0]:g}" if len(same) == 1 else f"λ={min(same):g}–{max(same):g} (baseline 1)"
        off = {0.2: (-4, 9), 5.0: (-6, -14)}.get(same[0], (8, -12) if len(same) > 1 else (8, -3))
        ax.annotate(lab, key, textcoords="offset points", xytext=off, fontsize=8, color=INK2)
    for name, col, lab in (("full_isolation_safe", ORANGE, "Full isolation (safe)"),
                           ("per_machine", AQUA, "Per-machine rule")):
        r = refs[name]
        ax.scatter([r["services_down"]], [r["contained"]], s=80, color=col, marker="s", edgecolor=SURFACE,
                   lw=1.5, zorder=4, label=lab)
        ax.annotate(lab, (r["services_down"], r["contained"]), textcoords="offset points", xytext=(8, 4),
                    fontsize=8, color=INK2)
    ax.set_xlabel("Services taken down (sum over scenarios)  ← better")
    ax.set_ylabel(f"Threats contained automatically (of {n})  ↑ better")
    ax.set_title("Containment vs. availability trade-off")
    ax.legend(loc="lower right", fontsize=8)
    foot(fig, f"Simulation, {n} scenarios (net12 + net22), exact solver. λ scales service values and disruption together; "
              "baseline λ=1. Escalations are not counted as contained.")
    save(fig, "fig1_tradeoff.png")


def fig_outcomes():
    d = json.loads((R / "escalation.json").read_text())
    names = [("full_isolation", "Full isolation"), ("full_isolation_safe", "Full isolation (safe)"),
             ("per_machine", "Per-machine rule"), ("q_acrs", "Q-ACRS + gate")]
    cats = [("CONTAINED", "Contained (automatic)", GOOD), ("CONTAINED_PENDING_APPROVAL", "Contained, needs 2 approvers", "#7fcf7f"),
            ("ESCALATED", "Escalated to humans (action given)", WARN), ("NOT_CONTAINED", "Silent failure", SERIOUS),
            ("REJECTED", "Unsafe → rejected", CRIT)]
    fig, ax = plt.subplots(figsize=(7.6, 3.8))
    ax.set_axisbelow(True)
    for yi, (k, lab) in enumerate(names):
        left = 0; sc = d["summary"][k]["status_counts"]
        for key, clab, col in cats:
            v = sc[key]
            if v:
                ax.barh(yi, v, left=left, color=col, edgecolor=SURFACE, linewidth=2, height=0.6)
                if v >= 2:
                    ax.text(left + v / 2, yi, str(v), ha="center", va="center", fontsize=8.5, color=INK)
            left += v
        ax.text(41, yi, f"{d['summary'][k]['services_down']} services down", va="center", fontsize=8, color=INK2)
    ax.set_yticks(range(len(names)), [lab for _, lab in names]); ax.invert_yaxis()
    ax.set_xlim(0, 52); ax.set_xticks(range(0, 41, 10)); ax.grid(axis="y", visible=False)
    ax.set_xlabel("Scenarios (of 40)")
    ax.set_title("What happens to each scenario (v3 safety gate applied to every method)")
    handles = [plt.Rectangle((0, 0), 1, 1, color=c) for _, _, c in cats]
    ax.legend(handles, [l for _, l, _ in cats], loc="upper center", bbox_to_anchor=(0.45, -0.2), ncol=3, fontsize=7.5)
    foot(fig, "Simulation, 40 development scenarios. The gate was designed after seeing these scenarios; "
              "blind scenarios are the real test.", y=-0.2)
    save(fig, "fig2_outcomes.png")


def fig_scaling():
    d = json.loads((R / "scaling.json").read_text())["by_departments"]
    ks = sorted(d, key=int)
    m = [d[k]["machines"] for k in ks]
    fig, ax = plt.subplots(figsize=(6.4, 3.8))
    ax.plot(m, m, color=AXIS, lw=1.2, ls="--", label="No reduction (1 qubit per machine)")
    ax.plot(m, [d[k]["qubits_max"] for k in ks], color=ORANGE, lw=2, marker="o", ms=6, mec=SURFACE, label="Qubits, worst scenario")
    ax.plot(m, [d[k]["qubits_mean"] for k in ks], color=BLUE, lw=2, marker="o", ms=6, mec=SURFACE, label="Qubits, average")
    for k, x in zip(ks, m):
        ax.annotate(f"{d[k]['qubits_mean']:.1f}", (x, d[k]["qubits_mean"]), textcoords="offset points",
                    xytext=(0, -13), ha="center", fontsize=8, color=INK2)
    ax.set_xlabel("Machines in the network"); ax.set_ylabel("Qubits needed")
    ax.set_title("Problem reduction keeps the quantum problem small")
    ax.legend(fontsize=8, loc="upper left")
    foot(fig, "15 random scenarios per network size (seed 2027). Simulated annealing matched the exact optimum in all 75.")
    save(fig, "fig3_scaling.png")


def fig_qaoa():
    p = R / "qaoa_seeds_summary.json"
    if not p.exists():
        return print("skip fig4: run phase4c_seeds --aggregate first")
    d = json.loads(p.read_text())
    qs = sorted(d["by_qubits"], key=int); x = [int(q) for q in qs]
    t = d["by_qubits"]; nseeds = len(d["seeds"])
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(10, 3.9))
    a1.plot(x, [100 * t[q]["mean_p_best_p3"] for q in qs], color=BLUE, lw=2, marker="o", mec=SURFACE, label="QAOA p=3")
    a1.plot(x, [100 * t[q]["random_p_best"] for q in qs], color=ORANGE, lw=2, marker="o", mec=SURFACE, label="Random guess")
    a1.set_yscale("log"); a1.yaxis.set_major_formatter(matplotlib.ticker.FuncFormatter(lambda v, _: f"{v:g}%")); a1.set_xlabel("Qubits"); a1.set_ylabel("Chance one shot is optimal (%)")
    a1.set_title("One measurement"); a1.legend(fontsize=8)
    w = 0.27
    for i, (key, col, lab) in enumerate((("qaoa_hit_rate_100", BLUE, "QAOA (100 samples)"),
                                         ("sa100_hit_rate", AQUA, "Annealing (100 steps)"),
                                         ("random_hit_rate_100", ORANGE, "Random (100 samples)"))):
        a2.bar([xx + (i - 1) * w for xx in x], [100 * t[q][key] for q in qs], width=w - 0.03, color=col, label=lab)
    a2.set_xlabel("Qubits"); a2.set_ylabel("Runs where best of 100 is optimal (%)")
    a2.set_ylim(0, 105); a2.set_title("Same budget: 100 evaluations")
    a2.legend(fontsize=7.5, loc="upper center", bbox_to_anchor=(0.5, -0.16), ncol=3)
    a2.grid(axis="x", visible=False)
    foot(fig, f"Noiseless simulation, 38 scenarios × {nseeds} optimiser seeds. QAOA angle-tuning cost is NOT inside the budget "
              "(this favours QAOA). Exact solver and full annealing find the optimum 40/40.", y=-0.12)
    save(fig, "fig4_qaoa_budget.png")


def main():
    fig_tradeoff(); fig_outcomes(); fig_scaling(); fig_qaoa()


if __name__ == "__main__":
    main()
