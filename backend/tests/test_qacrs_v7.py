"""v7 tests: SEGMENT action, exact semantics, QUBO penalties, gate, baselines.

    cd backend && python -m unittest tests.test_qacrs_v7 -v
"""
from __future__ import annotations

import unittest

import numpy as np

from qacrs import escalation as E
from qacrs import qubo_v7 as V7
from qacrs import safety_checks as S
from qacrs.network import Scenario, build as build_net, scenarios

NET = build_net(1)


def sc(h):
    return Scenario("t", NET.name, h, "test")


class TestSemantics(unittest.TestCase):
    def test_segment_keeps_service_via_healthy_replica(self):
        # app1 hacked, db segmented: app1 cannot reach db, app2 can -> nurse_app stays up
        self.assertNotIn("nurse_app", V7.services_down_v7(NET, set(), {"db"}, {"app1"}))

    def test_segment_downs_service_when_all_replicas_hacked(self):
        self.assertIn("nurse_app", V7.services_down_v7(NET, set(), {"db"}, {"app1", "app2"}))

    def test_isolating_dependency_downs_services(self):
        self.assertIn("appointments", V7.services_down_v7(NET, {"db"}, set(), set()))

    def test_segment_closes_c1(self):
        self.assertEqual(V7.open_paths_v7(NET, sc({"app1": 3}), set(), {"db"}), [])
        self.assertEqual(V7.open_paths_v7(NET, sc({"app1": 3}), set(), set()), [("app1", "db")])

    def test_segmented_critical_satisfies_c2(self):
        self.assertEqual(V7.check_v7(NET, sc({"db": 9}), set(), {"db"}).status, S.CONTAINED)
        self.assertEqual(V7.check_v7(NET, sc({"db": 9}), {"db"}, set()).status, S.PENDING)

    def test_invalid_segments_rejected(self):
        self.assertEqual(V7.check_v7(NET, sc({"web1": 5}), set(), {"web1"}).status, S.REJECTED)   # S4
        self.assertEqual(V7.check_v7(NET, sc({"db": 5}), {"db"}, {"db"}).status, S.REJECTED)     # S5
        self.assertEqual(V7.check_v7(NET, sc({"mri": 5}), {"mri"}, set()).status, S.REJECTED)    # S1


class TestQubo(unittest.TestCase):
    def test_penalties_dominate(self):
        """Any decision violating one-hot or never-isolate costs more than every feasible decision."""
        for net in (build_net(1), build_net(2)):
            for s in scenarios(net):
                q = V7.build_v7(net, s)
                vals = q.all_values()
                k = np.arange(len(vals))
                bad = np.zeros(len(vals), dtype=bool)
                idx = {n: i for i, n in enumerate(q.names)}
                for n, i in idx.items():
                    if n.endswith(V7.SEG):
                        j = idx[n[:-len(V7.SEG)]]
                        bad |= (((k >> i) & 1) & ((k >> j) & 1)).astype(bool)
                    elif not net.machine(n).isolatable:
                        bad |= ((k >> i) & 1).astype(bool)
                if bad.any():
                    self.assertGreater(vals[bad].min(), vals[~bad].max(), msg=s.id)

    def test_optimum_is_valid_everywhere(self):
        for net in (build_net(1), build_net(2)):
            for s in scenarios(net):
                iso, seg, _, _ = V7.q_acrs_v7(net, s)
                self.assertNotEqual(V7.check_v7(net, s, iso, seg).status, S.REJECTED, msg=s.id)

    def test_qubo_matches_exact_cost_direction_on_simple_case(self):
        """Hacked db risk 8: segment (residual 2.4 + d_seg 1) beats isolate (services down) and restrict (8)."""
        iso, seg, _, _ = V7.q_acrs_v7(NET, sc({"db": 8}))
        self.assertEqual((iso, seg), (set(), {"db"}))


class TestGateAndMethods(unittest.TestCase):
    def test_gate_escalates_unsegmented_critical(self):
        self.assertEqual(V7.decide_v7(NET, sc({"db": 9}), set(), set()).status, E.ESCALATED)

    def test_rule_segment(self):
        iso, seg = V7.m_rule_segment(NET, sc({"app1": 5, "db": 8}))
        self.assertEqual(iso, {"app1"}); self.assertEqual(seg, {"db"})

    def test_evaluate_fields(self):
        r = V7.evaluate(NET, sc({"db": 8}), "q_acrs_v7")
        self.assertEqual(r["segment_now"], ["db"])
        self.assertAlmostEqual(r["risk_left"], 8 * V7.RHO)
        self.assertEqual(r["status_v2_rules"], S.NOT_CONTAINED)     # old rules do not count SEGMENT


if __name__ == "__main__":
    unittest.main()
