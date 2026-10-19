"""Every number the booth shows, read from the committed result files at start-up (never typed by hand).
Each entry carries its source file and key path so a judge can open the file and find it.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

RES = Path(__file__).resolve().parent.parent / "results"
REPO = "https://github.com/hasa32054-crypto/ACRS"


def _get(obj, path: str):
    for k in path.split("."):
        obj = obj[int(k)] if isinstance(obj, list) else obj[k]
    return obj


def _load(rel: str):
    return json.loads((RES / rel).read_text(encoding="utf-8"))


# (id, file, key path)
SOURCES = [
    ("v7_h1_ratio", "v7/v7.json", "chains_7008.tests.H1_v7.ratio"),
    ("v7_hassan_services_down", "v7/v7.json", "chains_7008.tests.H1_v7.services_down.0"),
    ("v7_full_services_down", "v7/v7.json", "chains_7008.tests.H1_v7.services_down.1"),
    ("v7_n", "v7/v7.json", "chains_7008.summary.q_acrs_v7.n"),
    ("v7_escalation_rate", "v7/v7.json", "chains_7008.tests.escalation_rate.v7"),
    ("v6_h1_ratio", "v6/ood.json", "ood.tests.H1_v3.ratio"),
    ("v9_chains_ratio", "v9/v9.json", "fresh_claims.chains_7009.containment_ratio_vs_full_isolation"),
    ("v9_h60_ratio", "v9/v9.json", "fresh_claims.hospital60_7102.containment_ratio_vs_full_isolation"),
    ("v9_h60_services_down", "v9/v9.json", "fresh_claims.hospital60_7102.services_down"),
    ("v9_h60_full_services_down", "v9/v9.json", "fresh_claims.hospital60_7102.full_isolation_services_down"),
    ("v9_cert_rejected", "v9/v9.json", "S5_v9_certificates.rejected"),
    ("v9_cert_tampered", "v9/v9.json", "S5_v9_certificates.tampered"),
    ("v9_guard_detection", "v9/v9.json", "S10_v9_guard.model_A.detection_overall"),
    ("v9_guard_false_flags", "v9/v9.json", "S10_v9_guard.model_A.false_flag_rate"),
    ("v9_ttc_p95_ms", "v9/sandbox_v9.json", "time_to_contain_26_v9.decision_to_first_failed_attempt_ms.p95"),
    ("v9_twin_aborted", "v9/sandbox_v9.json", "digital_twin_S6_v9.faulty_aborted"),
    ("v9_twin_trials", "v9/sandbox_v9.json", "digital_twin_S6_v9.faulty_trials"),
    ("v8_forgery_sets_net12", "v8/adversarial.json", "certificate_validity_random.net12.sets"),
    ("v8_forgery_sets_net22", "v8/adversarial.json", "certificate_validity_random.net22.sets"),
    ("v8_forgery_worst_down_net12", "v8/adversarial.json", "certificate_validity_random.net12.worst_services_down"),
    ("v8_forgery_worst_down_net22", "v8/adversarial.json", "certificate_validity_random.net22.worst_services_down"),
    ("v8_failsafe_injected", "v8/adversarial.json", "failsafe.injected"),
    ("v8_failsafe_crashes", "v8/adversarial.json", "failsafe.crashes"),
    ("v8_cards_complete", "v8/realism_scale.json", "explainability.cards_complete_bilingual_with_counterfactual"),
    ("v8_cards_total", "v8/realism_scale.json", "explainability.decisions"),
    ("rw_h60_floor", "v9/v9.json", "R_v9_ransomware.hospital60/entry.hassan_v9_at_floor"),
    ("rw_h60_runs", "v9/v9.json", "R_v9_ransomware.hospital60/entry.runs"),
    ("e7_p_best_real", "v3/ibm/net12_h04_run.json", "p_best_real"),
    ("e7_backend", "v3/ibm/net12_h04_run.json", "backend"),
    ("e8_p_best_real", "v3/ibm/e8_run.json", "results.p2.p_best_real"),
    ("e8_p_best_ideal", "v3/ibm/e8_run.json", "results.p2.p_best_ideal"),
    ("e8_p_best_random", "v3/ibm/e8_run.json", "results.p2.p_best_random"),
    ("e8_backend", "v3/ibm/e8_run.json", "backend"),
    ("e8_job", "v3/ibm/e8_run.json", "job_id"),
    ("e9_optimal", "v3/ibm/e9_run.json", "summary.qpu_components_optimal"),
    ("e9_components", "v3/ibm/e9_run.json", "summary.qpu_components"),
    ("e9_qubits", "v3/ibm/e9_run.json", "summary.qpu_qubits"),
    ("e9_value", "v3/ibm/e9_run.json", "summary.assembled_value"),
    ("e9_milp", "v3/ibm/e9_run.json", "summary.milp_optimum"),
    ("e9_backend", "v3/ibm/e9_run.json", "backend"),
    ("e9_fez_optimal", "v3/ibm/e9_run_fez.json", "summary.qpu_components_optimal"),
    ("e9_fez_backend", "v3/ibm/e9_run_fez.json", "backend"),
    ("e9_single_shot_all_optimal", "v3/ibm/e9_run.json", "summary.single_shot_all_components_optimal"),
    # v12 (the engine the booth runs): open incident corpus, 75 real incidents 2013-2026
    ("v12_corpus_cases", "v12/v12.json", "meta.corpus_converted"),
    ("v12_corpus_moments", "v12/v12.json", "summaries.corpus.n"),
    ("v12_corpus_auto_ratio", "v12/v12.json", "summaries.corpus.policies.v12.auto_ratio"),
    ("v12_corpus_unsafe", "v12/v12.json", "summaries.corpus.policies.v12.unsafe"),
    ("v12_corpus_down", "v12/v12.json", "summaries.corpus.policies.v12.services_down_after_approval"),
    ("v12_corpus_v9_down", "v12/v12.json", "summaries.corpus.policies.v9.services_down_after_approval"),
    ("v12_corpus_rule_down", "v12/v12.json", "summaries.corpus.policies.rule_segment.services_down_after_approval"),
    ("v12_corpus_full_down", "v12/v12.json", "summaries.corpus.policies.full_isolation.services_down_after_approval"),
    ("v12_scale_1000_median_ms", "v12/v12.json", "targets.T7.1000.median_ms"),
    ("v12_pq_tamperings", "v12/pqsign.json", "tamperings"),
]


def file_sha(rel: str) -> str:
    return hashlib.sha256((RES / rel).read_bytes()).hexdigest()


def collect() -> dict:
    cache, out = {}, {}
    for key, rel, path in SOURCES:
        if rel not in cache:
            cache[rel] = _load(rel)
        out[key] = {"value": _get(cache[rel], path), "file": f"backend/qacrs/results/{rel}", "path": path}
    files = sorted({rel for _, rel, _ in SOURCES})
    return {"numbers": out, "files": {f"backend/qacrs/results/{r}": file_sha(r) for r in files}, "repo": REPO}


def quantum_shots() -> dict:
    """E8 raw counts (ibm_fez, 4000 shots, 5 qubits) decoded into decisions and passed through the safety gate."""
    import numpy as np
    from qacrs import escalation as E
    from qacrs.lesson4_ibm_scaled import bits_to_x, decide_names, problem
    run = _load("v3/ibm/e8_run.json")
    r = run["results"]["p2"]
    net, sc, q = problem(r["scenario"])
    rows = []
    vals = {}
    for b, c in r["counts"].items():
        x = bits_to_x(b)
        idx = sum(v << i for i, v in enumerate(x))
        if idx not in vals:
            vals[idx] = float(q.const + sum(q.lin.get(i, 0) * x[i] for i in range(q.n))
                              + sum(w * x[i] * x[j] for (i, j), w in q.quad.items()))
        iso = sorted(decide_names(q, x))
        gate = E.decide(net, sc, set(iso)).as_dict()
        rows.append({"bits": b, "count": c, "isolate": iso, "cost": vals[idx],
                     "optimal": bool(np.isclose(vals[idx], r["best_cost"])),
                     "gate": gate["status"], "isolate_now": gate["isolate_now"],
                     "escalations": [e["rule"] + " " + e["target"] for e in gate["escalations"]]})
    rows.sort(key=lambda x: -x["count"])
    return {"backend": r["backend"], "job_id": r["job_id"], "shots": r["shots"], "qubits": r["qubits"],
            "variables": r["variables"], "hacked": r["hacked"], "best_cost": r["best_cost"],
            "p_best_real": r["p_best_real"], "p_best_ideal": r["p_best_ideal"], "p_best_random": r["p_best_random"],
            "rows": rows, "source": "backend/qacrs/results/v3/ibm/e8_run.json"}
