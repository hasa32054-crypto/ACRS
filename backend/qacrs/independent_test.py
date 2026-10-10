"""E5: blind (independent) scenarios written by someone other than the developer.

    cd backend && python -m qacrs.independent_test --guide                 # writes the author guide (machines, links)
    cd backend && python -m qacrs.independent_test --validate FILE.json    # checks a file, runs NOTHING
    cd backend && python -m qacrs.independent_test FILE.json               # runs once, saves everything

Rules (docs/qacrs/PREREGISTRATION_v3.md, E5):
  * the code is LOCKED: the run refuses if the core files differ from qacrs/independent/LOCK.json
    (written before any blind scenario existed);
  * a scenario file can be run only once (a second run refuses unless --allow-rerun, which is logged);
  * every result is kept, including failures and invalid scenarios; nothing is tuned afterwards.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from qacrs import escalation as E
from qacrs import safety_checks as S
from qacrs.meta import meta, sha
from qacrs.network import Scenario, build as build_net
from qacrs.phase3_compare import per_machine, q_acrs, score
from qacrs.phase3b_containment import full_isolation_safe

HERE = Path(__file__).parent
KIT = HERE / "independent"
LOCK = KIT / "LOCK.json"
OUT = HERE / "results" / "v3" / "independent"
NETS = {n.name: n for n in (build_net(1), build_net(2))}
REQUIRED = ("author_role", "consent_to_publish", "created_date", "saw_qacrs_decisions_before_writing", "scenarios")
METHODS = {"q_acrs": lambda net, sc: q_acrs(net, sc)[0], "full_isolation_safe": full_isolation_safe,
           "per_machine": per_machine}


def write_guide() -> Path:
    L = ["# دليل كاتب السيناريوهات المستقلة / Independent scenario author guide", "",
         "اكتب حوادث اختراق **افتراضية** على إحدى الشبكتين أدناه، دون أن ترى أي قرار من Q-ACRS. لكل سيناريو:",
         "الأجهزة المخترقة، وخطورة كل جهاز من 1 إلى 10 (كم خطرًا يبقى لو اكتفينا بتقييده بدل عزله)، ووصف قصير.",
         "Write hypothetical incidents on one of the networks below without seeing any Q-ACRS decision. For each:",
         "hacked machines, a risk 1-10 per machine (risk left if we only restrict it), and a short description.", "",
         "- استخدم أسماء الأجهزة كما هي حرفيًا. / Use machine names exactly as listed.",
         "- لا تكتب بيانات شخصية. / Do not include personal data.",
         "- يمكنك إضافة رأيك كخبير في حقل `expert_view` (لا يدخل في الحساب). / Optional `expert_view` is not scored.",
         "- ابدأ من الملف `TEMPLATE.json`. / Start from `TEMPLATE.json`.", ""]
    for net in NETS.values():
        L += [f"## {net.name} ({len(net.machines)} machines)", "",
              "| machine | role | can be isolated | two-person rule |", "|---|---|---|---|"]
        L += [f"| `{m.name}` | {m.role} | {'yes' if m.isolatable else '**never**'} | {'yes' if m.critical else ''} |"
              for m in net.machines]
        L += ["", "Services: " + "; ".join(f"`{s.name}` runs on {' + '.join(s.replicas)}"
                                         + (f", needs {', '.join(s.depends_on)}" if s.depends_on else "")
                                         for s in net.services),
              "", "Links (who can open connections to whom): " + ", ".join(f"{a}→{b}" for a, b in net.links), ""]
    p = KIT / "AUTHOR_GUIDE.md"
    p.write_text("\n".join(L))
    return p


def load(path: Path) -> tuple[dict, list[str]]:
    errors = []
    try:
        doc = json.loads(path.read_text())
    except Exception as e:
        return {}, [f"not valid JSON: {e}"]
    for k in REQUIRED:
        if k not in doc:
            errors.append(f"missing field '{k}'")
    if doc.get("saw_qacrs_decisions_before_writing") is not False:
        errors.append("file must state saw_qacrs_decisions_before_writing = false (otherwise it is not blind)")
    if doc.get("consent_to_publish") is not True:
        errors.append("consent_to_publish must be true before results can be published")
    if not isinstance(doc.get("scenarios"), list) or not doc.get("scenarios"):
        errors.append("'scenarios' must be a non-empty list")
    return doc, errors


def scenario_errors(item: dict) -> tuple[Scenario | None, list[str]]:
    if not isinstance(item, dict):
        return None, ["scenario is not an object"]
    net = NETS.get(item.get("network"))
    if net is None:
        return None, [f"unknown network {item.get('network')!r} (use one of {sorted(NETS)})"]
    sc = Scenario(str(item.get("id", "?")), net.name, item.get("hacked"), str(item.get("description", "")))
    return sc, S.validate_scenario(net, sc)


def check_lock() -> list[str]:
    if not LOCK.exists():
        return ["LOCK.json missing"]
    lock = json.loads(LOCK.read_text())["code_sha256_prefix"]
    now = {f: sha(HERE / f) if (HERE / f).exists() else None for f in lock}
    return [f"{f}: locked {h}, now {now[f]}" for f, h in lock.items() if now[f] != h]


LOCKED_FILES = ("network.py", "qubo_builder.py", "safety_checks.py", "escalation.py", "phase3_compare.py",
                "phase3b_containment.py", "independent_test.py")


def write_lock() -> Path:
    if LOCK.exists():
        sys.exit("REFUSED: LOCK.json already exists; a lock is written once, before any blind scenario.")
    LOCK.write_text(json.dumps(meta("independent_lock") | {"code_sha256_prefix": {f: sha(HERE / f) for f in LOCKED_FILES},
                                   "note": "Written before any blind scenario existed. Do not edit."}, indent=1))
    return LOCK


def run(path: Path, allow_rerun=False) -> dict:
    drift = check_lock()
    if drift:
        sys.exit("REFUSED: code changed since the lock (this would no longer be a blind test):\n  " + "\n  ".join(drift))
    doc, errors = load(path)
    if errors:
        sys.exit("REFUSED: invalid file:\n  " + "\n  ".join(errors))
    out = OUT / f"{path.stem}.json"
    if out.exists() and not allow_rerun:
        sys.exit(f"REFUSED: {path.name} was already run (results in {out}). A blind set is run once.")
    rows, invalid = [], []
    for item in doc["scenarios"]:
        sc, errs = scenario_errors(item)
        if errs:
            invalid.append({"id": item.get("id") if isinstance(item, dict) else None, "errors": errs}); continue
        net = NETS[sc.network]
        row = {"scenario": sc.id, "network": net.name, "hacked": sc.hacked, "description": sc.description,
               "expert_view": item.get("expert_view")}
        for name, fn in METHODS.items():
            try:
                iso = set(fn(net, sc))
            except Exception as e:                      # solver failure is a recorded outcome, never hidden
                row[name] = {"status": "NO_DECISION", "error": repr(e)}; continue
            d = E.decide(net, sc, iso); base = score(net, sc, iso)
            row[name] = d.as_dict() | {"services_down": base["services_down"], "risk_left": base["risk_left"],
                                       "healthy_isolated": sorted(iso - set(sc.hacked))}
        rows.append(row)
    summary = {}
    for name in METHODS:
        r = [row[name] for row in rows]
        st = [x["status"] for x in r]
        summary[name] = {"valid_scenarios": len(r), "contained": st.count(S.CONTAINED) + st.count(S.PENDING),
                         "escalated": st.count(E.ESCALATED), "silent_failures": st.count(S.NOT_CONTAINED),
                         "rejected_unsafe": st.count(S.REJECTED), "no_decision": st.count("NO_DECISION"),
                         "services_down": sum(len(x.get("services_down", [])) for x in r),
                         "risk_left": sum(x.get("risk_left") or 0 for x in r)}
    q, b = summary["q_acrs"], summary["full_isolation_safe"]
    h1 = {"containment_ok": q["contained"] >= 0.8 * b["contained"], "fewer_services_down": q["services_down"] < b["services_down"]}
    h1["H1_v3_supported"] = h1["containment_ok"] and h1["fewer_services_down"]
    res = {"meta": meta("independent_test", ("independent_test.py",), file=path.name, file_sha256=sha(path),
                        rerun=allow_rerun and out.exists()),
           "source": {k: doc.get(k) for k in ("author_role", "created_date", "consent_to_publish",
                                               "saw_qacrs_decisions_before_writing")},
           "counts": {"submitted": len(doc["scenarios"]), "valid": len(rows), "invalid": len(invalid)},
           "summary": summary, "h1_v3": h1, "invalid": invalid, "rows": rows}
    OUT.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(res, indent=1, ensure_ascii=False))
    print(json.dumps({k: res[k] for k in ("counts", "summary", "h1_v3")}, indent=1))
    print(f"Saved: {out}")
    return res


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("file", nargs="?")
    ap.add_argument("--guide", action="store_true")
    ap.add_argument("--validate", metavar="FILE")
    ap.add_argument("--allow-rerun", action="store_true")
    ap.add_argument("--write-lock", action="store_true")
    a = ap.parse_args(argv)
    if a.write_lock:
        return print(f"Saved: {write_lock()}")
    if a.guide:
        return print(f"Saved: {write_guide()}")
    if a.validate:
        doc, errors = load(Path(a.validate))
        for i, item in enumerate(doc.get("scenarios") or []):
            errors += [f"scenario {i + 1}: {e}" for e in scenario_errors(item)[1]]
        print("VALID" if not errors else "INVALID:\n  " + "\n  ".join(errors))
        return
    if a.file:
        return run(Path(a.file), a.allow_rerun)
    ap.print_help()


if __name__ == "__main__":
    main()
