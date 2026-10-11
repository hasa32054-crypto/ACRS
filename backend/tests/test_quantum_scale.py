import random
import unittest

from qacrs import quantum_scale as QS
from qacrs import realism_v8 as RV
from qacrs.network import Scenario, build


class TestTightQubo(unittest.TestCase):
    def test_same_optimum_as_original(self):
        nets = [build(1), build(2), RV.hospital60(), QS.cluster(2)]
        rng = random.Random(1)
        for net in nets:
            names = [m.name for m in net.machines]
            for _ in range(15):
                sc = Scenario("t", net.name, {m: rng.randint(3, 9) for m in rng.sample(names, rng.randint(1, min(30, len(names))))}, "x")
                qt, q = QS.tight_qubo(net, sc)
                self.assertAlmostEqual(QS.exact_milp(q)[0], QS.exact_milp(qt)[0], places=6)

    def test_no_optimum_isolates_and_segments(self):
        net = RV.hospital60()
        sc = Scenario("t", net.name, {"ehr_db": 9, "pc_admin1": 8, "dc1": 9}, "x")
        qt, _ = QS.tight_qubo(net, sc)
        _, x = QS.exact_milp(qt)
        on = {qt.names[i] for i, v in enumerate(x) if v}
        self.assertFalse(any(n + "#seg" in on for n in on))


class TestComponents(unittest.TestCase):
    def test_partition_and_value(self):
        net = QS.cluster(2); sc = QS.incident(net, 30, 1)
        qt, _ = QS.tight_qubo(net, sc)
        comps = QS.components(qt)
        self.assertEqual(sorted(i for idx, _ in comps for i in idx), list(range(qt.n)))
        total = qt.const + sum(QS.exact_milp(cq)[0] for _, cq in comps)
        self.assertAlmostEqual(total, QS.exact_milp(qt)[0], places=6)


if __name__ == "__main__":
    unittest.main()
