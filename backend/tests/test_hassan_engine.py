"""HASSAN engine tests (v8 features 8, 13, 14, 16, 18/19/47, 36, S1, S5, S10)."""
from __future__ import annotations

import time
import unittest

from qacrs import hassan as H
from qacrs import qubo_v7 as V7
from qacrs import safety_checks as S
from qacrs.network import Scenario, build as build_net, scenarios

NET = build_net(1)


def sc(h):
    return Scenario("t", NET.name, h, "test")


class TestEngine(unittest.TestCase):
    def eng(self, **kw):
        return H.Engine(NET, limiter=kw.pop("limiter", H.RateLimiter(limit=10 ** 9)), **kw)

    def test_matches_v7_decision(self):
        e = self.eng()
        for s in scenarios(NET):
            d = e.decide(s)
            if not d.guard_flags:
                iso, seg, _, _ = V7.q_acrs_v7(NET, s)
                self.assertEqual((set(d.isolate), set(d.segment)), (iso, seg), msg=s.id)

    def test_invalid_input_rejected(self):
        self.assertEqual(self.eng().decide(sc({"ghost": 5})).status, S.REJECTED)

    def test_failsafe_exception_timeout_malformed(self):
        def boom(*_): raise ValueError()
        def slow(*_): time.sleep(0.2); return set(), set(), "x"
        def bad(*_): return {"db"}, {"db"}, "x"
        for f in (boom, slow, bad):
            d = self.eng(solver=f).decide(sc({"web1": 9}))
            self.assertTrue(d.fallback); self.assertEqual(d.isolate, []); self.assertEqual(d.status, "ESCALATED")
            self.assertEqual(d.restrict, ["web1"])

    def test_rate_limit(self):
        clock = [0.0]
        e = H.Engine(NET, limiter=H.RateLimiter(limit=3, clock=lambda: clock[0]))
        total = 0
        for i, m in enumerate(["web1", "pc_recep", "pc_nurse", "pc_admin", "files"]):
            clock[0] = i
            total += len(e.decide(Scenario(f"s{i}", NET.name, {m: 9}, "t")).isolate)
        self.assertLessEqual(total, 3)
        clock[0] = 120
        self.assertEqual(len(e.decide(Scenario("late", NET.name, {"web1": 9}, "t")).isolate), 1)

    def test_guard_flags_and_holds_isolation(self):
        self.assertTrue(H.consistency_flags(NET, sc({"app1": 9})))           # app1 hacked, no hacked predecessor
        self.assertFalse(H.consistency_flags(NET, sc({"web1": 9, "app1": 8})))
        d = self.eng().decide(sc({"app1": 9}))
        self.assertEqual(d.isolate, []); self.assertIn("app1", d.held_for_humans)

    def test_certificate_and_signature(self):
        e = self.eng()
        d = e.decide(sc({"web1": 9, "app1": 8}))
        self.assertTrue(H.verify_certificate(NET, sc({"web1": 9, "app1": 8}), d.certificate))
        self.assertTrue(H.verify_signature(d.certificate, d.signature, e.key))
        tampered = d.certificate | {"isolate": ["db"]}
        self.assertFalse(H.verify_certificate(NET, sc({"web1": 9, "app1": 8}), tampered))
        self.assertFalse(H.verify_signature(tampered, d.signature, e.key))

    def test_card_bilingual_with_counterfactual(self):
        d = self.eng().decide(sc({"web1": 9, "web2": 9, "pc_recep": 5}))
        self.assertIn("full isolation", d.card["en"]); self.assertIn("العزل الكامل", d.card["ar"])
        self.assertIn("services_saved_vs_full_isolation", d.card)

    def test_ttl_present(self):
        self.assertEqual(self.eng().decide(sc({"web1": 9})).expires_in_s, H.DEFAULT_TTL_S)

    def test_portfolio_uses_annealing_for_large(self):
        big = build_net(8)
        s = Scenario("b", big.name, {"web1_a": 9, "app1_b": 7, "db_c": 8, "pc_admin_d": 6, "web2_e": 7, "app2_f": 7,
                                     "pc_nurse_g": 5, "files": 6}, "t")
        iso, seg, method = H.solve(big, s)
        self.assertIn(method, ("exact", "annealing"))
        self.assertNotEqual(V7.check_v7(big, s, iso, seg).status, S.REJECTED)


if __name__ == "__main__":
    unittest.main()
