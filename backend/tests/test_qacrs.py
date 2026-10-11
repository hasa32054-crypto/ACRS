"""Tests for Q-ACRS (network, QUBO, penalty, safety layer, results files).

Pure standard library + numpy, so they run without pytest and without Qiskit:
    cd backend && python -m unittest tests.test_qacrs -v
(pytest also collects them: python -m pytest tests/test_qacrs.py)
"""
from __future__ import annotations

import itertools
import json
import math
import random
import unittest
from pathlib import Path

import numpy as np

from qacrs import safety_checks as S
from qacrs.ising import brute_force, qubo_value, to_ising
from qacrs.network import Network, Scenario, build as build_net, check as check_net, scenarios
from qacrs.phase3_compare import annealing, full_isolation, per_machine, q_acrs
from qacrs.qubo_builder import build, variables

RESULTS = Path(__file__).resolve().parents[1] / "qacrs" / "results"
NETS = (build_net(1), build_net(2))


def all_scenarios():
    for net in NETS:
        for sc in scenarios(net):
            yield net, sc


# ------------------------------------------------------------------ network & scenarios -----------------------
class TestNetwork(unittest.TestCase):
    def test_sizes(self):
        self.assertEqual([len(n.machines) for n in NETS], [12, 22])
        self.assertEqual([len(n.services) for n in NETS], [3, 5])

    def test_structure_is_valid(self):
        for n in NETS:
            check_net(n)

    def test_forty_scenarios_ten_hand_made(self):
        sc = list(all_scenarios())
        self.assertEqual(len(sc), 40)
        self.assertEqual(sum("_h" in s.id for _, s in sc), 10)

    def test_seed_reproducible(self):
        for n in NETS:
            a = [s.hacked for s in scenarios(n, 15, 2027)]
            b = [s.hacked for s in scenarios(n, 15, 2027)]
            c = [s.hacked for s in scenarios(n, 15, 2028)]
            self.assertEqual(a, b)
            self.assertNotEqual(a, c)

    def test_two_person_and_never_isolate_flags(self):
        m = {x.name: x for x in NETS[0].machines}
        self.assertTrue(m["db"].critical and m["dc"].critical)
        self.assertFalse(m["mri"].isolatable or m["lab"].isolatable)


# ------------------------------------------------------------------ QUBO --------------------------------------
class TestQubo(unittest.TestCase):
    def test_vectorised_matches_scalar(self):
        rng = random.Random(0)
        for net, sc in all_scenarios():
            q = build(net, sc)
            vals = q.all_values()
            for _ in range(5):
                k = rng.randrange(2 ** q.n)
                x = [(k >> i) & 1 for i in range(q.n)]
                self.assertAlmostEqual(vals[k], q.value(x), places=9)

    def test_ising_conversion_is_exact(self):
        for net, sc in list(all_scenarios())[:12]:
            q = build(net, sc)
            c, h, J = to_ising(q.const, q.lin, q.quad, q.n)
            for x in itertools.product([0, 1], repeat=min(q.n, 8)):
                x = list(x) + [0] * (q.n - len(x))
                z = [1 - 2 * b for b in x]
                e = c + sum(h[i] * z[i] for i in range(q.n)) + sum(v * z[i] * z[j] for (i, j), v in J.items())
                self.assertAlmostEqual(e, q.value(x), places=9)

    def test_lesson1_best_cost_is_5(self):
        from qacrs.lesson1_qubo import cost
        self.assertEqual(min(cost(x) for x in itertools.product([0, 1], repeat=3)), 5)

    def test_brute_force_helper_agrees(self):
        for net, sc in list(all_scenarios())[:10]:
            q = build(net, sc)
            best, _ = brute_force(q.const, q.lin, q.quad, q.n)
            self.assertAlmostEqual(best, float(q.all_values().min()), places=9)

    def test_hand_example_terms(self):
        """One hacked web twin (risk 7): restrict -> cost 7 + spread 0; isolate -> disruption 1."""
        net = NETS[0]
        sc = Scenario("t", net.name, {"web1": 7}, "test")
        q = build(net, sc)
        x0 = [0] * q.n
        x1 = [1 if n == "web1" else 0 for n in q.names]
        self.assertAlmostEqual(q.value(x0), 7.0)
        self.assertAlmostEqual(q.value(x1), 1.0)

    def test_annealing_finds_exact_optimum_everywhere(self):
        for net, sc in all_scenarios():
            _, q, opt = q_acrs(net, sc)
            self.assertAlmostEqual(annealing(q), opt, places=9, msg=sc.id)


class TestHardPenalty(unittest.TestCase):
    """The BIG penalty must make every never-isolate violation worse than EVERY decision without it."""

    def test_big_dominates_all_soft_costs(self):
        for net, sc in all_scenarios():
            hard, soft = build(net, sc, hard=True), build(net, sc, hard=False)
            never = [i for i, n in enumerate(hard.names) if not net.machine(n).isolatable]
            if not never:
                continue
            hv, sv = hard.all_values(), soft.all_values()
            k = np.arange(len(hv))
            bad = np.zeros(len(hv), dtype=bool)
            for i in never:
                bad |= ((k >> i) & 1).astype(bool)
            self.assertGreater(hv[bad].min(), sv.max(), msg=sc.id)
            self.assertFalse(bad[int(np.argmin(hv))], msg=sc.id)


class TestReduction(unittest.TestCase):
    """Problem reduction must not change the optimum (checked exactly on the 12-machine network)."""

    def test_reduced_optimum_equals_full_optimum(self):
        net = NETS[0]
        for sc in scenarios(net):
            red = build(net, sc).all_values().min()
            full = build(net, sc, full=True).all_values().min()
            self.assertAlmostEqual(red, full, places=9, msg=sc.id)

    def test_variables_include_hacked(self):
        for net, sc in all_scenarios():
            self.assertTrue(set(sc.hacked) <= set(variables(net, sc)))


# ------------------------------------------------------------------ safety layer ------------------------------
class TestSafetyLayer(unittest.TestCase):
    net = NETS[0]

    def sc(self, hacked, network=None):
        return Scenario("t", network or self.net.name, hacked, "test")

    def test_contained_simple(self):
        v = S.check(self.net, self.sc({"web1": 7}), {"web1"})
        self.assertEqual(v.status, S.CONTAINED)

    def test_never_isolate_is_rejected(self):
        v = S.check(self.net, self.sc({"mri": 9}), {"mri"})
        self.assertEqual(v.status, S.REJECTED)
        self.assertTrue(any(r.startswith("S1") for r in v.reasons))

    def test_unknown_machine_in_decision_is_rejected(self):
        v = S.check(self.net, self.sc({"web1": 5}), {"web1", "ghost"})
        self.assertEqual(v.status, S.REJECTED)

    def test_invalid_scenarios_are_rejected(self):
        for bad in ({"ghost": 5}, {"web1": 0}, {"web1": 11}, {"web1": True}, {"web1": 5.5}, {"web1": None}, {}):
            self.assertEqual(S.check(self.net, self.sc(bad), set()).status, S.REJECTED, msg=str(bad))
        self.assertEqual(S.check(self.net, self.sc({"web1": 5}, "net99"), set()).status, S.REJECTED)

    def test_critical_needs_two_person(self):
        v = S.check(self.net, self.sc({"db": 8}), {"db"})
        self.assertEqual(v.status, S.PENDING)
        self.assertEqual(v.needs_two_person, ["db"])

    def test_c2_high_risk_left_restricted(self):
        v = S.check(self.net, self.sc({"web1": 7}), set())
        self.assertEqual(v.status, S.NOT_CONTAINED)
        self.assertEqual(S.check(self.net, self.sc({"web1": 6}), set()).status, S.CONTAINED)
        self.assertEqual(S.check(self.net, self.sc({"web1": 6}), set(), threshold=6).status, S.NOT_CONTAINED)

    def test_c1_open_path_to_critical(self):
        v = S.check(self.net, self.sc({"app1": 3}), set())          # app1 -> db, db untouched
        self.assertEqual(v.status, S.NOT_CONTAINED)
        self.assertTrue(any(r.startswith("C1") for r in v.reasons))
        self.assertEqual(S.check(self.net, self.sc({"app1": 3}), {"app1"}).status, S.CONTAINED)

    def test_non_isolatable_goes_to_owner_review_not_success_of_c2(self):
        v = S.check(self.net, self.sc({"mri": 9}), set())
        self.assertEqual(v.owner_review, ["mri"])
        self.assertEqual(v.status, S.CONTAINED)                     # mri has no link to a critical server

    def test_lab_path_to_db_cannot_be_closed_without_db(self):
        self.assertEqual(S.check(self.net, self.sc({"lab": 3}), set()).status, S.NOT_CONTAINED)
        self.assertEqual(S.check(self.net, self.sc({"lab": 3}), {"db"}).status, S.PENDING)

    def test_method_decisions_never_crash(self):
        for net, sc in all_scenarios():
            for fn in (full_isolation, per_machine, lambda n, s: q_acrs(n, s)[0]):
                self.assertIn(S.check(net, sc, fn(net, sc)).status, S.STATUSES)


# ------------------------------------------------------------------ results files -----------------------------
def _finite(obj):
    if isinstance(obj, float):
        return math.isfinite(obj)
    if isinstance(obj, dict):
        return all(_finite(v) for v in obj.values())
    if isinstance(obj, list):
        return all(_finite(v) for v in obj)
    return True


class TestResultsFiles(unittest.TestCase):
    def test_v1_phase3_reproduces(self):
        stored = json.loads((RESULTS / "phase3_compare.json").read_text())
        by_id = {r["scenario"]: r for r in stored["rows"]}
        self.assertEqual(len(by_id), 40)
        for net, sc in all_scenarios():
            dec, _, _ = q_acrs(net, sc)
            self.assertEqual(sorted(dec), by_id[sc.id]["q_acrs"]["isolated"], msg=sc.id)

    def test_v2_containment_file(self):
        path = RESULTS / "v2" / "containment.json"
        if not path.exists():
            self.skipTest("run python -m qacrs.phase3b_containment first")
        d = json.loads(path.read_text())
        self.assertTrue(_finite(d))
        self.assertEqual(d["meta"]["status"], "complete")
        from qacrs.phase3b_containment import summarise
        self.assertEqual(summarise(d["rows"]), d["summary"])        # report numbers == raw rows
        for row in d["rows"]:
            for m in ("full_isolation", "full_isolation_safe", "per_machine", "q_acrs"):
                v = row[m]["verdict"]
                self.assertIn(v["status"], S.STATUSES)
                if v["status"] in (S.REJECTED, S.NOT_CONTAINED):
                    self.assertTrue(v["reasons"], msg=f"{row['scenario']} {m}: failure without a reason")
        for m, s in d["summary"].items():
            self.assertEqual(sum(s["status_counts"].values()), s["scenarios"])
            self.assertEqual(s["contained"], s["status_counts"][S.CONTAINED] + s["status_counts"][S.PENDING])

    def test_all_result_json_finite(self):
        for p in RESULTS.rglob("*.json"):
            self.assertTrue(_finite(json.loads(p.read_text())), msg=str(p))


if __name__ == "__main__":
    unittest.main()
