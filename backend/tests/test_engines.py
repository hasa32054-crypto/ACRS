"""Engine unit tests: risk, decision, state machine, response plan, evidence, verification gate."""
import unittest
from datetime import datetime, timedelta, timezone

from app.engines import state_machine as sm
from app.engines.decision import decide
from app.engines.detection import detect
from app.engines.evidence import collect, verify_chain
from app.engines.recovery import gate
from app.engines.response import plan, verify_containment
from app.engines.risk import assess, attribute
from app.engines.types import Asset, Event, Level, State
from app.services import simulators
from app.services.seed_data import asset_rows

ASSETS = {r["ip"]: Asset(**r) for r in asset_rows()}


def analyse(scenario: str, ip: str | None = None, **kw):
    events, _ = simulators.build(scenario)
    ip = ip or sorted({e.src_ip for e in events})[0]
    evs = sorted([e for e in events if e.src_ip == ip], key=lambda e: e.ts)
    dets = detect(evs)
    attr = attribute(ip, evs, ASSETS)
    ra = assess(dets, attr.asset, evs, attr.conflict)
    return evs, dets, attr, ra, decide(attr, ra, dets, **kw)


class RiskTests(unittest.TestCase):
    def test_explainability_matrix_sums_to_score(self):
        _, _, _, ra, _ = analyse("tier1_c2_hr")
        total = sum(f.contribution for f in ra.risk_factors) + sum(ra.adjustments.values())
        self.assertAlmostEqual(ra.risk, round(total), delta=1)
        self.assertEqual({f.name for f in ra.risk_factors},
                         {"signal_severity", "source_correlation", "threat_intel", "behavior_anomaly",
                          "asset_sensitivity", "blast_radius"})

    def test_tier0_high_risk_high_confidence(self):  # edge case 7
        _, _, _, ra, d = analyse("tier0_dc_cred_dump")
        self.assertGreaterEqual(ra.risk, 95)
        self.assertGreaterEqual(ra.confidence, 95)
        self.assertEqual(d.level, Level.EMERGENCY_RESTRICT)

    def test_single_source_confidence_cap(self):
        now = datetime.now(timezone.utc)
        evs = [Event(now - timedelta(seconds=i), "firewall", "net_conn", "10.20.1.11",
                     data={"dest_ip": "185.220.101.47", "dest_port": 4444}) for i in range(4)]
        ra = assess(detect(evs), ASSETS["10.20.1.11"], evs, False)
        self.assertLessEqual(ra.confidence, 55)

    def test_normal_traffic_no_detection(self):
        now = datetime.now(timezone.utc)
        evs = [Event(now - timedelta(seconds=i * 7), "firewall", "net_conn", "10.20.1.11",
                     data={"dest_ip": "20.10.1.1", "dest_port": 443}) for i in range(10)]
        self.assertEqual(detect(evs), [])


class DecisionTests(unittest.TestCase):
    def test_tier1_c2_surgical(self):  # edge case 8
        _, _, _, ra, d = analyse("tier1_c2_hr")
        self.assertGreaterEqual(ra.risk, 90)
        self.assertEqual(d.level, Level.SURGICAL)
        self.assertTrue(d.auto_execute)
        self.assertEqual(d.deadline_s, 15)

    def test_tier2_no_human(self):  # edge case 9
        _, _, _, _, d = analyse("tier2_workstation")
        self.assertEqual(d.level, Level.FULL_ISOLATION)
        self.assertEqual(d.approvals_required, 0)
        self.assertEqual(d.deadline_s, 90)

    def test_tier0_two_approvers_and_7s(self):
        _, _, _, _, d = analyse("tier0_dc_cred_dump")
        self.assertEqual((d.approvals_required, d.escalation_level, d.deadline_s), (2, Level.FULL_ISOLATION, 7))

    def test_change_window_asks_human(self):  # edge case 2
        _, _, _, ra, d = analyse("erp_change_window_fp")
        self.assertIn("change_window", ra.adjustments)
        self.assertFalse(d.auto_execute)

    def test_non_isolatable(self):  # edge case 1
        _, dets, attr, _, d = analyse("mri_non_isolatable")
        self.assertEqual(d.level, Level.COMPENSATING)
        names = {c.name for c in plan(d.level, attr.asset, dets)}
        self.assertNotIn("ISOLATE_ASSET", names)
        self.assertIn("APPLY_MICROSEGMENTATION", names)

    def test_ransomware_fast_path_segment(self):
        _, _, _, _, first = analyse("ransomware_finance", "10.40.5.23", segment_hits=0)
        _, _, _, _, third = analyse("ransomware_finance", "10.40.5.44", segment_hits=2)
        self.assertEqual(first.level, Level.FULL_ISOLATION)
        self.assertFalse(first.segment_restrict)
        self.assertTrue(third.segment_restrict)

    def test_circuit_breaker(self):
        _, _, _, _, d = analyse("tier1_c2_hr", recent_auto=5)
        self.assertFalse(d.auto_execute)
        self.assertTrue(d.circuit_breaker)
        self.assertFalse(analyse("tier1_c2_hr")[4].circuit_breaker)

    def test_unknown_asset(self):
        _, _, attr, _, d = analyse("unknown_host")
        self.assertFalse(attr.ok)
        self.assertEqual(d.level, Level.RESTRICT)
        self.assertIsNotNone(d.hold_after_verify)


class StateMachineTests(unittest.TestCase):
    def test_main_path_is_valid(self):
        for a, b in zip(sm.MAIN_PATH, sm.MAIN_PATH[1:]):
            self.assertTrue(sm.can(a, b), (a, b))

    def test_invalid_transitions(self):
        with self.assertRaises(sm.InvalidTransition):
            sm.check(State.DETECT, State.CONTAIN)
        with self.assertRaises(sm.InvalidTransition):
            sm.check(State.CLOSE, State.ROLLED_BACK)
        self.assertTrue(sm.can(State.OBSERVE, State.ROLLED_BACK))


class ResponseTests(unittest.TestCase):
    def test_surgical_scope_and_jump_host(self):
        _, dets, attr, _, d = analyse("tier1_c2_hr")
        cmds = plan(d.level, attr.asset, dets)
        targets = {c.target for c in cmds}
        self.assertTrue(targets <= {"HR-APP-01", "perimeter-fw", "dns-rpz", "HR-DB-01,HR-API-GW"}, targets)
        q = next(c for c in cmds if c.name == "APPLY_MICROSEGMENTATION")
        self.assertEqual(q.params["allow_inbound_from"], "10.99.0.10")
        self.assertIn("DRAIN_FROM_POOL", {c.name for c in cmds})

    def test_probes(self):
        asset = ASSETS["10.20.1.11"]
        ok = verify_containment(Level.SURGICAL, {"ISOLATE_ASSET"}, asset)
        self.assertTrue(all(p["pass"] for p in ok))
        bad = verify_containment(Level.SURGICAL, {"BLOCK_C2"}, asset)
        self.assertFalse(all(p["pass"] for p in bad))

    def test_evidence_chain_and_gate(self):
        evs, dets, attr, _, d = analyse("tier1_c2_hr")
        recs = collect("inc-1", attr.asset, d.level, evs, dets)
        self.assertEqual(recs[0]["kind"], "memory_dump")
        self.assertEqual(verify_chain(recs), (True, None))
        recs[1]["sha256"] = "f" * 64
        self.assertEqual(verify_chain(recs), (False, 1))
        g = gate([{"stage": s, "ok": True} for s in ("reimage_patch", "rotate_credentials", "reconfigure_cis",
                  "vulnerability_scan", "edr_rescan_ioc_sweep", "autoruns_diff", "service_health")], True)
        self.assertTrue(g["passed"])
        self.assertEqual(len(g["items"]), 9)


if __name__ == "__main__":
    unittest.main()
