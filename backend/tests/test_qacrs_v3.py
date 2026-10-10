"""v3 tests: escalation gate, mock firewall executor, blind-test kit, sensitivity, scaling, IBM circuit maths.

    cd backend && python -m unittest tests.test_qacrs_v3 -v
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import numpy as np

from qacrs import escalation as E
from qacrs import independent_test as IT
from qacrs import qubo_builder as QB
from qacrs import safety_checks as S
from qacrs.network import Scenario, build as build_net, scenarios
from qacrs.phase3_compare import q_acrs
from qacrs.policy_executor import AdapterError, MockFirewallAdapter, PolicyAuditLog, PolicyExecutor

NET = build_net(1)
RESULTS = Path(__file__).resolve().parents[1] / "qacrs" / "results" / "v3"


def sc(hacked, sid="t"):
    return Scenario(sid, NET.name, hacked, "test")


class TestEscalationGate(unittest.TestCase):
    def test_g1_critical_left_restricted_is_escalated(self):
        d = E.decide(NET, sc({"db": 8}), set())
        self.assertEqual(d.status, E.ESCALATED)
        self.assertEqual(d.escalations[0]["rule"], "G1")
        self.assertEqual(d.isolate_now, [])                       # the gate never adds automatic isolation

    def test_g2_never_isolatable_path(self):
        d = E.decide(NET, sc({"lab": 3}), set())
        self.assertEqual(d.status, E.ESCALATED)
        self.assertEqual(d.escalations[0]["rule"], "G2")
        self.assertEqual(d.escalations[0]["target"], "db")

    def test_uncovered_failure_stays_silent(self):
        d = E.decide(NET, sc({"web1": 9}), set())                 # isolatable, not critical
        self.assertEqual(d.status, S.NOT_CONTAINED)
        d = E.decide(NET, sc({"db": 8, "web1": 9}), set())        # one covered, one not -> still silent
        self.assertEqual(d.status, S.NOT_CONTAINED)

    def test_gate_does_not_touch_other_statuses(self):
        self.assertEqual(E.decide(NET, sc({"mri": 9}), {"mri"}).status, S.REJECTED)
        self.assertEqual(E.decide(NET, sc({"web1": 7}), {"web1"}).status, S.CONTAINED)
        self.assertEqual(E.decide(NET, sc({"db": 8}), {"db"}).status, S.PENDING)

    def test_dev_set_q_acrs_has_no_silent_failure(self):
        for net in (build_net(1), build_net(2)):
            for s in scenarios(net):
                self.assertNotEqual(E.decide(net, s, q_acrs(net, s)[0]).status, S.NOT_CONTAINED, msg=s.id)


class TestPolicyExecutor(unittest.TestCase):
    def make(self, fail_next=0, retries=2, dry_run=False):
        ad = MockFirewallAdapter(fail_next); log = PolicyAuditLog()
        return PolicyExecutor(NET, ad, log, max_retries=retries, dry_run=dry_run), ad, log

    def test_valid_policy_applied(self):
        ex, ad, log = self.make()
        r = ex.execute(sc({"web1": 7, "pc_recep": 3}), {"web1"})
        self.assertEqual(r.status, "APPLIED")
        self.assertEqual(ad.rules, {"web1": "ISOLATE", "pc_recep": "RESTRICT"})
        self.assertEqual(log.entries[-1]["status"], "APPLIED")

    def test_default_is_dry_run(self):
        ex = PolicyExecutor(NET, MockFirewallAdapter(), PolicyAuditLog())
        r = ex.execute(sc({"web1": 7}), {"web1"})
        self.assertEqual(r.status, "PLANNED_DRY_RUN")
        self.assertEqual(ex.adapter.rules, {})

    def test_never_isolatable_rejected_nothing_applied(self):
        ex, ad, _ = self.make()
        self.assertEqual(ex.execute(sc({"mri": 9}), {"mri"}).status, "REJECTED")
        self.assertEqual(ad.rules, {}); self.assertEqual(ad.calls, 0)

    def test_critical_needs_two_different_approvers(self):
        ex, ad, _ = self.make()
        s = sc({"db": 8})
        self.assertEqual(ex.execute(s, {"db"}).status, "BLOCKED_AWAITING_APPROVAL")
        self.assertEqual(ex.execute(s, {"db"}, {"db": ["ali", "ali"]}).status, "BLOCKED_AWAITING_APPROVAL")
        self.assertEqual(ad.rules, {})
        self.assertEqual(ex.execute(s, {"db"}, {"db": ["ali", "sara"]}).status, "APPLIED")
        self.assertEqual(ad.rules, {"db": "ISOLATE"})

    def test_unknown_device_rejected(self):
        ex, ad, _ = self.make()
        self.assertEqual(ex.execute(sc({"ghost": 5}), set()).status, "REJECTED")
        self.assertEqual(ex.execute(sc({"web1": 5}), {"ghost"}).status, "REJECTED")
        self.assertEqual(ad.calls, 0)

    def test_retry_then_success(self):
        ex, ad, log = self.make(fail_next=2, retries=2)
        self.assertEqual(ex.execute(sc({"web1": 7}), {"web1"}).status, "APPLIED")
        self.assertEqual(sum(e["status"] == "RULE_FAILED" for e in log.entries), 2)

    def test_retries_exhausted_rolls_back(self):
        ex, ad, _ = self.make(retries=1)
        s = sc({"web1": 7, "pc_recep": 3})
        orig = ad.apply
        def flaky(target, action):
            if target == "pc_recep":
                raise AdapterError("down")
            orig(target, action)
        ad.apply = flaky
        r = ex.execute(s, {"web1"})
        self.assertEqual(r.status, "FAILED_ROLLED_BACK")
        self.assertEqual(ad.rules, {})                              # web1 rule was rolled back

    def test_idempotent(self):
        ex, ad, _ = self.make()
        s = sc({"web1": 7})
        ex.execute(s, {"web1"}); calls = ad.calls
        self.assertEqual(ex.execute(s, {"web1"}).status, "ALREADY_APPLIED")
        self.assertEqual(ad.calls, calls)

    def test_rollback(self):
        ex, ad, log = self.make()
        r = ex.execute(sc({"web1": 7}), {"web1"})
        self.assertTrue(ex.rollback(r.policy_id)); self.assertEqual(ad.rules, {})
        self.assertFalse(ex.rollback(r.policy_id))
        self.assertEqual(log.entries[-1]["status"], "ROLLED_BACK")

    def test_escalation_is_reported(self):
        ex, ad, _ = self.make()
        r = ex.execute(sc({"db": 8}), set())
        self.assertEqual(r.status, "APPLIED_WITH_ESCALATION")
        self.assertEqual(ad.rules, {"db": "RESTRICT"})

    def test_real_adapter_refused(self):
        class Real(MockFirewallAdapter):
            is_real = True
        with self.assertRaises(ValueError):
            PolicyExecutor(NET, Real(), PolicyAuditLog())

    def test_audit_log_file_is_append_only_jsonl(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "audit.jsonl"
            ex = PolicyExecutor(NET, MockFirewallAdapter(), PolicyAuditLog(p), dry_run=False)
            ex.execute(sc({"web1": 7}), {"web1"})
            lines = p.read_text().splitlines()
            self.assertGreaterEqual(len(lines), 2)
            self.assertTrue(all("policy_id" in json.loads(x) for x in lines))


class TestIndependentKit(unittest.TestCase):
    def write(self, d, doc):
        p = Path(d) / "blind.json"; p.write_text(json.dumps(doc)); return p

    def test_template_is_rejected_until_consent(self):
        doc, errors = IT.load(IT.KIT / "TEMPLATE.json")
        self.assertTrue(any("consent" in e for e in errors))

    def test_not_blind_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p = self.write(d, {"author_role": "x", "consent_to_publish": True, "created_date": "2026-10-12",
                               "saw_qacrs_decisions_before_writing": True, "scenarios": [{}]})
            self.assertTrue(any("blind" in e for e in IT.load(p)[1]))

    def test_scenario_validation(self):
        self.assertEqual(IT.scenario_errors({"id": "a", "network": "net12", "hacked": {"web1": 5}})[1], [])
        self.assertTrue(IT.scenario_errors({"id": "a", "network": "net99", "hacked": {"web1": 5}})[1])
        self.assertTrue(IT.scenario_errors({"id": "a", "network": "net12", "hacked": {"ghost": 5}})[1])
        self.assertTrue(IT.scenario_errors({"id": "a", "network": "net12", "hacked": {"web1": 12}})[1])

    def test_lock_matches_code(self):
        if not IT.LOCK.exists():
            self.skipTest("lock not written yet")
        self.assertEqual(IT.check_lock(), [])


class TestSensitivity(unittest.TestCase):
    def test_spread_context_restores(self):
        from qacrs.phase5_sensitivity import spread
        before = QB.SPREAD
        with spread(1.5):
            self.assertAlmostEqual(QB.SPREAD, before * 1.5)
        self.assertEqual(QB.SPREAD, before)

    def test_baseline_reproduces_v2_decisions(self):
        from qacrs.phase5_sensitivity import run_config
        stored = json.loads((RESULTS.parent / "phase3_compare.json").read_text())
        base = run_config()["decisions"]
        for r in stored["rows"]:
            self.assertEqual(base[r["scenario"]], r["q_acrs"]["isolated"], msg=r["scenario"])

    def test_results_file(self):
        p = RESULTS / "sensitivity.json"
        if not p.exists():
            self.skipTest("run phase5_sensitivity first")
        d = json.loads(p.read_text())
        self.assertEqual(d["baseline"]["rejected"], 0)
        self.assertTrue(all(r["rejected"] == 0 for r in d["one_at_a_time"] + d["pareto"]))


class TestScaling(unittest.TestCase):
    def test_results_file(self):
        p = RESULTS / "scaling.json"
        if not p.exists():
            self.skipTest("run phase5_scaling first")
        d = json.loads(p.read_text())
        self.assertEqual(len(d["rows"]), 75)
        for r in d["rows"]:
            self.assertLessEqual(r["qubits"], r["variables_after_reduction"])
            self.assertLessEqual(r["variables_after_reduction"], r["machines"])


class TestIbmCircuitMaths(unittest.TestCase):
    """The gate list built for Qiskit (RZ, RZZ, RX) must give the simulator's probabilities exactly."""

    def test_gate_sequence_equals_simulator(self):
        from qacrs.ising import to_ising
        from qacrs.lesson4_ibm_scaled import P, problem, tuned
        for sid in ("net12_h04", "net12_h01"):
            net, s, q = problem(sid)
            theta, ideal, vals, scale = tuned(q)
            n = q.n
            _, h, J = to_ising(0.0, {i: a / scale for i, a in q.lin.items()}, {k: b / scale for k, b in q.quad.items()}, n)
            k = np.arange(2 ** n); z = 1 - 2 * ((k[:, None] >> np.arange(n)) & 1)
            psi = np.full(2 ** n, 2 ** (-n / 2), complex)
            for g, b in zip(theta[:P], theta[P:]):
                for i in range(n):
                    psi *= np.exp(-1j * g * h[i] * z[:, i])                  # RZ(2 g h)
                for (i, j), w in J.items():
                    psi *= np.exp(-1j * g * w * z[:, i] * z[:, j])           # RZZ(2 g w)
                c, sn = np.cos(b), -1j * np.sin(b)                           # RX(2 b)
                for i in range(n):
                    v = psi.reshape(-1, 2, 2 ** i); a0, a1 = v[:, 0, :].copy(), v[:, 1, :].copy()
                    v[:, 0, :], v[:, 1, :] = c * a0 + sn * a1, sn * a0 + c * a1
            self.assertLess(np.abs(np.abs(psi) ** 2 - ideal).max(), 1e-9, msg=sid)


if __name__ == "__main__":
    unittest.main()


class TestEscalationV5(unittest.TestCase):
    """v5 G3 twin-dilemma gate (docs/qacrs/PREREGISTRATION_v5.md). Crafted cases only, not the 9002 set."""

    def test_g3_both_twins_hacked(self):
        from qacrs import escalation_v5 as E5
        s = sc({"app1": 9, "app2": 4})
        d = E5.decide(NET, s, {"app1"})                    # app2 restricted keeps app2 -> db open
        self.assertEqual(d.status, E.ESCALATED)
        g3 = [e for e in d.escalations if e["rule"] == "G3"]
        self.assertEqual(g3[0]["target"], "app2")
        self.assertIn("nurse_app", g3[0]["services_at_stake"])
        self.assertEqual(d.isolate_now, ["app1"])           # never adds automatic isolation

    def test_g3_not_used_when_isolation_is_free(self):
        from qacrs import escalation_v5 as E5
        d = E5.decide(NET, sc({"web1": 9}), set())          # isolating web1 alone downs no service
        self.assertEqual(d.status, S.NOT_CONTAINED)

    def test_v5_keeps_v3_outcomes_otherwise(self):
        from qacrs import escalation_v5 as E5
        for hk, iso in (({"mri": 9}, {"mri"}), ({"web1": 7}, {"web1"}), ({"db": 8}, {"db"}), ({"db": 8}, set()),
                        ({"lab": 3}, set())):
            self.assertEqual(E5.decide(NET, sc(hk), iso).status, E.decide(NET, sc(hk), iso).status, msg=str(hk))


class TestStatsHelpers(unittest.TestCase):
    def test_wilson_known_value(self):
        from qacrs.stats import wilson
        lo, hi = wilson(0, 100)
        self.assertAlmostEqual(lo, 0.0, places=12); self.assertAlmostEqual(hi, 0.0370, places=3)

    def test_mcnemar(self):
        from qacrs.stats import mcnemar_exact
        self.assertEqual(mcnemar_exact(0, 0), 1.0)
        self.assertAlmostEqual(mcnemar_exact(0, 10), 2 * 0.5 ** 10, places=12)

    def test_sandbox_adapter_refuses_non_loopback(self):
        from qacrs.sandbox_lab import SandboxIptablesAdapter
        with self.assertRaises(ValueError):
            SandboxIptablesAdapter({"web1": "10.0.0.5"})
        PolicyExecutor(NET, SandboxIptablesAdapter({"web1": "127.40.1.3"}), PolicyAuditLog())   # allowed
