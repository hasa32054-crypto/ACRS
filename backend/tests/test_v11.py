"""v11 tests: fusion, the white-box attacker, the formal model and both provers (Z3 tests skip if z3 is missing).

    cd backend && python -m unittest tests.test_v11 -v
"""
from __future__ import annotations

import importlib.util
import random
import unittest
from pathlib import Path

from qacrs import formal_v11 as FV
from qacrs import hassan_v9 as V9
from qacrs import sensors_v11 as SV
from qacrs.network import Scenario, build

HAS_Z3 = importlib.util.find_spec("z3") is not None
HAS_GATE = (Path(FV.__file__).parent / "gate_v11.py").exists()


def clean(net, truth):
    """Noiseless honest readings: every source of a hacked machine reports the true risk, healthy ones report 0."""
    return {m.name: (truth.hacked.get(m.name, 0),) * SV.N_SOURCES for m in net.machines}


class Fusion(unittest.TestCase):
    def test_rules(self):
        self.assertEqual(SV.fuse_one((3, 9, 5), "single"), 3)
        self.assertEqual(SV.fuse_one((3, 9, 5), "max"), 9)
        self.assertEqual(SV.fuse_one((3, 9, 5), "median"), 5)
        self.assertEqual(SV.fuse_one((3, 4, 4), "mean"), 4)      # 3.67 -> 4
        self.assertEqual(SV.fuse_one((0, 0, 1), "mean"), 0)      # 0.33 -> 0

    def test_p6_median_bounded_everywhere(self):
        self.assertTrue(FV.exhaustive_median_p6()["proved"])

    def test_fused_scenario_drops_zero(self):
        net = build(1)
        r = {m.name: (0, 0, 0) for m in net.machines}
        r["web1"] = (7, 0, 7)
        self.assertEqual(SV.fuse(net, r, "median").hacked, {"web1": 7})
        self.assertEqual(SV.fuse(net, r, "single").hacked, {"web1": 7})

    def test_honest_readings_shape_and_range(self):
        net = build(1)
        t = Scenario("t", net.name, {"app1": 10, "pc_nurse": 1}, "t")
        h = SV.honest_readings(net, t, random.Random(1), random.Random(2))
        self.assertEqual(len(h), len(net.machines))
        self.assertTrue(all(len(v) == 3 for v in h.values()))
        self.assertTrue(all(9 <= v <= 10 for v in h["app1"]) and all(1 <= v <= 2 for v in h["pc_nurse"]))


class Attacker(unittest.TestCase):
    def setUp(self):
        self.net = build(1)
        self.truth = Scenario("t", self.net.name, {"pc_nurse": 8, "app1": 8}, "attack chain(s): pc_nurse -> app1")
        self.honest = clean(self.net, self.truth)
        self.lat = set(V9.hops_of(self.truth))

    def test_single_source_can_be_used_to_hide(self):
        r = SV.exhaustive(SV.Defender(self.net, "single", False), self.truth, self.honest, self.lat, 1, goals=("A2",))
        self.assertTrue(r["goals"]["A2"]["success"])          # one forged source = the only source

    def test_median_resists_one_forged_source_on_clean_readings(self):
        # P6: with two identical honest readings the median cannot move, so no Γ=1 attack can change anything.
        for rule, ndr in (("median", False), ("median", True)):
            r = SV.exhaustive(SV.Defender(self.net, rule, ndr), self.truth, self.honest, self.lat, 1)
            self.assertFalse(any(g["success"] for g in r["goals"].values()), rule)

    def test_outcome_is_judged_on_the_truth(self):
        d = SV.Defender(self.net, "single", False)
        o = d.outcome(self.truth, self.honest, None)
        self.assertEqual(o.healthy_isolated, 0)
        self.assertIn(o.truth_status, ("CONTAINED", "CONTAINED_PENDING_APPROVAL", "NOT_CONTAINED"))

    def test_beam_returns_valid_attack(self):
        r = SV.beam(SV.Defender(self.net, "single", False), self.truth, self.honest, self.lat, "A2", 2, width=5)
        if r["success"]:
            self.assertLessEqual(len(r["attack"]), 2)


class FormalModel(unittest.TestCase):
    def test_model_matches_real_code(self):
        net = build(1)
        for path in ("X", "S") + (("G",) if HAS_GATE else ()):
            self.assertEqual(FV.fidelity(net, path, 300, 11)["mismatches"], 0, path)

    def test_highs_proves_executor_safety_rules(self):
        spec = FV.Spec.of(build(1))
        for p in ("P1", "P2", "P5"):
            self.assertTrue(FV.milp_prove(spec, "X", p)["proved"], p)

    def test_highs_finds_documented_gaps(self):
        """Pre-registered finding: the executor can isolate an unreported machine (P3) and the service adapter passes
        a wrong solver output through (P1). The counterexample must also violate the plain-Python reference model."""
        spec = FV.Spec.of(build(1))
        for path, p in (("X", "P3"), ("S", "P1")):
            r = FV.milp_prove(spec, path, p)
            self.assertFalse(r["proved"])
            self.assertTrue(r["counterexample"]["reference_model_agrees"])

    @unittest.skipUnless(HAS_GATE, "gate_v11.py not added yet")
    def test_gate_proves_everything_and_catches_mutations(self):
        spec = FV.Spec.of(build(2))
        for p in FV.PROPS:
            self.assertTrue(FV.milp_prove(spec, "G", p)["proved"], p)
        for mut, p in zip(FV.MUTATIONS, ("P1", "P5", "P4")):
            self.assertFalse(FV.milp_prove(spec, "G", p, mut)["proved"], mut)
        # defence in depth: removing only the gate's own never-isolate filter is still safe (engine rejection remains)
        self.assertTrue(FV.milp_prove(spec, "G", "P1", "skip_never_isolate_filter_only")["proved"])
        self.assertTrue(FV.milp_prove(spec, "G", "P4", "segment_any_filter_only")["proved"])

    @unittest.skipUnless(HAS_GATE, "gate_v11.py not added yet")
    def test_service_marks_only_gated_actions_automatic(self):
        from qacrs import hassan as H, hassan_service as HS
        net = build(1)
        sc = Scenario("probe", net.name, {"pc_nurse": 8}, "probe")
        for bad in (["mri"], ["db"], ["web1"]):
            eng = H.Engine(net, solver=lambda n_, s_, b=bad: (set(b), set(), "injected"),
                           limiter=H.RateLimiter(limit=10 ** 9))
            acts = HS.to_acrs(net, eng.decide(sc), sc=sc)["actions"]
            self.assertFalse([a for a in acts if a["auto"] and a["level"] == "ISOLATE"], bad)
            self.assertTrue([a for a in acts if not a["auto"] and a["target"] == bad[0]], bad)
        acts = HS.to_acrs(net, eng.decide(sc))["actions"]          # no scenario given -> nothing automatic
        self.assertFalse([a for a in acts if a["auto"] and a["level"] in ("ISOLATE", "SEGMENT")])

    @unittest.skipUnless(HAS_Z3, "z3-solver not installed (pip install z3-solver)")
    def test_z3_agrees_with_highs(self):
        spec = FV.Spec.of(build(1))
        for path in ("X", "S") + (("G",) if HAS_GATE else ()):
            for p in FV.PROPS:
                self.assertEqual(FV.z3_prove(spec, path, p)["proved"], FV.milp_prove(spec, path, p)["proved"], (path, p))
        self.assertTrue(FV.z3_median_p6()["proved"])


if __name__ == "__main__":
    unittest.main()
