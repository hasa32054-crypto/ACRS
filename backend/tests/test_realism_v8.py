import unittest

from qacrs import realism_v8 as RV
from qacrs.network import Scenario


class TestHospital60(unittest.TestCase):
    def test_shape(self):
        net = RV.hospital60()
        self.assertEqual(len(net.machines), 60)
        self.assertEqual(len(net.services), 8)
        crit = {m.name for m in net.machines if m.critical}
        self.assertEqual(crit, {"dc1", "dc2", "ehr_db", "pacs_store"})
        names = {m.name for m in net.machines}
        self.assertTrue(all(a in names and b in names for a, b in net.links))


class TestMitre(unittest.TestCase):
    def test_every_hacked_machine_tagged(self):
        net = RV.hospital60()
        sc = Scenario("t", net.name, {"web1": 6, "ehr_app1": 7, "ehr_db": 9, "dc1": 9, "files": 8},
                      "attack chain: web1 -> ehr_app1 | ehr_app1 -> ehr_db")
        tags = RV.mitre_tags(net, sc)
        self.assertEqual(set(tags), set(sc.hacked))
        self.assertIn("T1190", tags["web1"])
        self.assertIn("T1021", tags["ehr_db"])
        self.assertIn("T1003", tags["dc1"])
        self.assertIn("T1486", tags["files"])
        self.assertTrue(all(t.startswith("T") for ts in tags.values() for t in ts))


class TestPatientMinutes(unittest.TestCase):
    def test_formula(self):
        self.assertEqual(RV.patient_minutes([]), 0.0)
        self.assertEqual(RV.patient_minutes(["ehr"]), 120 * 1 * 30)


class TestSpread(unittest.TestCase):
    def test_no_action_spreads_and_isolation_stops(self):
        net = RV.hospital60()
        free = RV.spread(net, {"pc_nurse1"}, None)
        iso_all = RV.spread(net, {"pc_nurse1"}, lambda n, sc: (set(sc.hacked), set()))
        self.assertGreater(free["encrypted"], 1)
        self.assertLessEqual(iso_all["encrypted"], free["encrypted"])


if __name__ == "__main__":
    unittest.main()
