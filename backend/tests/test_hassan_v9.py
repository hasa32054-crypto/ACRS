import random
import unittest

from qacrs import hassan as H
from qacrs import hassan_v9 as V9
from qacrs import qubo_v7 as V7
from qacrs import realism_v8 as RV
from qacrs.network import Scenario, build


class TestCertificateV9(unittest.TestCase):
    def setUp(self):
        self.net = build(1)
        self.sc = Scenario("t", "net12", {"web1": 5, "app1": 6, "db": 8}, "attack chain(s): web1 -> app1 -> db")
        self.iso, self.seg, _ = H.solve(self.net, self.sc)

    def test_genuine_accepted(self):
        c = V9.certificate_v9(self.net, self.sc, self.iso, self.seg)
        self.assertTrue(V9.verify_certificate_v9(self.net, self.sc, c))

    def test_smart_forgery_rejected(self):
        m = sorted(self.iso)[0]
        forged = V9.certificate_v9(self.net, self.sc, set(self.iso) - {m}, self.seg)   # self-consistent, not optimal
        self.assertFalse(V9.verify_certificate_v9(self.net, self.sc, forged))

    def test_status_flip_rejected(self):
        c = V9.certificate_v9(self.net, self.sc, self.iso, self.seg)
        c["status"] = "ESCALATED" if c["status"] != "ESCALATED" else "CONTAINED"
        self.assertFalse(V9.verify_certificate_v9(self.net, self.sc, c))


class TestGuardV2(unittest.TestCase):
    def test_flags_uncorroborated_and_passes_corroborated(self):
        net = build(1)
        sc = Scenario("t", "net12", {"web1": 5, "app1": 6, "db": 8}, "attack chain(s): web1 -> app1 -> db")
        self.assertTrue(V9.guard_v2(net, sc, set()))
        self.assertEqual(V9.guard_v2(net, sc, {("web1", "app1"), ("app1", "db")}), [])


class TestShieldSpread(unittest.TestCase):
    def test_v9_reaches_floor_and_no_worse_than_none(self):
        net = RV.hospital60()
        pol = lambda n, s: H.solve(n, s)[:2]
        for start in ("ct", "pc_nurse1", "lab_a1"):
            r = V9.spread_v9(net, {start}, pol, shield=True)
            self.assertEqual(r["encrypted"], r["floor"])
            self.assertLessEqual(r["encrypted"], V9.spread_v9(net, {start}, None)["encrypted"])


class TestRegret(unittest.TestCase):
    def test_never_resolves_into_uncontained(self):
        from qacrs.network import random_scenarios
        net = build(1)
        for sc in random_scenarios(net, 60, 1):
            r = V9.regret_resolve(net, sc)
            if r and r["resolved"]:
                self.assertEqual(r["status_alt"], "CONTAINED")
                self.assertEqual(r["services_down_alt"], 0)


class TestCanon(unittest.TestCase):
    def test_iptables_s_form_equals_spec(self):
        from qacrs.sandbox_v9 import canon
        spec = ["-s", "127.40.1.3", "-d", "127.40.1.4", "-p", "tcp", "--dport", "47645", "-j", "DROP"]
        shown = "-s 127.40.1.3/32 -d 127.40.1.4/32 -p tcp -m tcp --dport 47645 -j DROP".split()
        self.assertEqual(canon(spec), canon(shown))


if __name__ == "__main__":
    unittest.main()
