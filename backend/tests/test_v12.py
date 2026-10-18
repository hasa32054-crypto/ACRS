"""v12/v13 unit tests: determinism of the decision (the v9 rate limiter was not), floor safety, immunity v13 rule,
recovery gate refusals, ML-DSA envelope rejection. Standard library only."""
import json
import random
import subprocess
import sys
import unittest
from pathlib import Path

from qacrs import phase16_v11 as P16
from qacrs import qubo_v7 as V7
from qacrs import safety_checks as S
from qacrs.v12 import immunity as IM
from qacrs.v12 import qubo_v12 as Q

INC = P16.INC


def real_pairs():
    out = []
    for p in sorted(INC.glob("*.json")):
        d, net, scs = P16.load(p)
        if net is not None:
            out += [(net, sc, d) for sc in scs]
    return out


class TestDeterminism(unittest.TestCase):
    def test_same_decision_across_processes(self):
        """The v9 limiter kept hosts in set-iteration order (hash-randomised per process). v12 must not."""
        code = ("import json,sys;from qacrs import phase16_v11 as P;from qacrs.v12 import qubo_v12 as Q\n"
                "out=[]\n"
                "for p in sorted(P.INC.glob('*.json')):\n"
                "    d,net,scs=P.load(p)\n"
                "    if net is None: continue\n"
                "    for sc in scs:\n"
                "        dd=Q.decide_v12(net,sc); out.append([sc.id,sorted(dd.isolate),sorted(dd.segment),dd.status])\n"
                "print(json.dumps(out))")
        runs = []
        for seed in ("1", "7", "4242"):
            r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True,
                               env={"PYTHONHASHSEED": seed, "PATH": "/usr/bin:/bin"}, cwd=str(Path(__file__).parent.parent))
            runs.append(json.loads(r.stdout))
        self.assertEqual(runs[0], runs[1]); self.assertEqual(runs[1], runs[2])


class TestFloor(unittest.TestCase):
    def test_floor_never_isolates_never_isolatable_or_critical(self):
        for net, sc, _ in real_pairs():
            fl = Q.safety_floor(net, sc)
            for h in fl.isolate:
                m = net.machine(h); self.assertTrue(m.isolatable and not m.critical, h)
            for h in fl.segment:
                self.assertTrue(net.machine(h).critical, h)

    def test_gate_never_rejects_v12(self):
        for net, sc, _ in real_pairs():
            d = Q.decide_v12(net, sc)
            self.assertNotEqual(d.status, S.REJECTED, sc.id)
            self.assertNotEqual(d.status, S.NOT_CONTAINED, sc.id)

    def test_risk9_isolatable_noncritical_is_isolated(self):
        for net, sc, _ in real_pairs():
            d = Q.decide_v12(net, sc)
            for h, r in sc.hacked.items():
                m = net.machine(h)
                if r >= 9 and m.isolatable and not m.critical:
                    self.assertIn(h, d.isolate, (sc.id, h))


class TestImmunityV13(unittest.TestCase):
    def test_v13_never_costs_a_live_service(self):
        from qacrs.v12 import phase18_survive_immune as P18
        for p in sorted(INC.glob("*.json")):
            d, net, scs = P16.load(p)
            if net is None: continue
            path = P18.path_of(d)
            if len(path) < 2: continue
            before = Q.evaluate_policy(net, scs[-1], "v12")
            im = IM.Immunity(v13=True); im.learn(net, path, [], p.stem)
            after = Q.evaluate_policy(net, scs[-1], "v12", im)
            self.assertLessEqual(len(after["services_down_after_approval"]), len(before["services_down_after_approval"]), p.stem)


class TestRecoveryGate(unittest.TestCase):
    def test_readmit_high_risk_refused(self):
        from qacrs.v12 import recover as RC
        net, sc, _ = real_pairs()[0]
        st = RC.State(net)
        RC.apply_alert(st, dict(sc.hacked))
        h = max(sc.hacked, key=sc.hacked.get)
        if sc.hacked[h] < S.HIGH_RISK:
            st.risk[h] = 9
        with self.assertRaises(RC.Refused):
            RC.run_command(st, f"readmit {h}", who="eng1")


class TestPQSign(unittest.TestCase):
    def test_tampered_envelope_rejected(self):
        from qacrs.v12 import pqsign as PQ
        from qacrs import hassan_v9 as V9
        net, sc, _ = real_pairs()[0]
        pk, sk = PQ.keygen(); key = b"k"
        eng = V9.EngineV9(net); cert = eng.decide(sc).certificate
        env = PQ.sign_certificate(cert, sk, key)
        self.assertTrue(PQ.verify_envelope(env, pk, key))
        bad = json.loads(json.dumps(env)); bad["certificate"]["status"] = "CONTAINED" if cert["status"] != "CONTAINED" else "ESCALATED"
        self.assertFalse(PQ.verify_envelope(bad, pk, key))


if __name__ == "__main__":
    unittest.main()
