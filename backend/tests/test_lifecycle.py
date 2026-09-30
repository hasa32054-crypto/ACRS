"""Lifecycle tests with the in-memory store and scaled-down timers (time_scale=0.02).

Covers the state machine end-to-end, the 7s/15s/90s/60s timers (scaled), the
Emergency Queue, approvals, rollback, and the spec's edge cases 1-9.
"""
import asyncio
import time
import unittest

from app.engines.state_machine import MAIN_PATH
from app.engines.types import State
from app.services import simulators
from app.services.memory_store import InMemoryStore
from app.services.publisher import LocalPublisher
from app.workers.lifecycle import ActionError, Orchestrator, Settings

SCALE = 0.02


class Base(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.store = InMemoryStore()
        self.pub = LocalPublisher()
        self.orch = Orchestrator(self.store, self.pub,
                                 Settings(time_scale=SCALE, stage_pacing_s=0, latency_scale=0.02))

    async def asyncTearDown(self):
        for t in list(self.orch.tasks.values()):
            t.cancel()
        await asyncio.sleep(0)

    async def run_scenario(self, name, mode="success", failure=None):
        events, sim = simulators.build(name, mode, failure)
        return await self.orch.ingest(events, "test", sim)

    async def wait_state(self, iid, *states, timeout=8.0):
        want = {getattr(s, "value", s) for s in states}
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            inc = await self.store.get_incident(iid)
            if inc["state"] in want or (inc.get("hold_reason") and "HOLD" in want):
                return inc
            await asyncio.sleep(0.01)
        inc = await self.store.get_incident(iid)
        self.fail(f"{iid} stuck in {inc['state']} (hold={inc.get('hold_reason')}), wanted {want}")

    def path(self, iid):
        return [t["to_state"] for t in self.store.transitions if t["incident_id"] == iid]


class FullLifecycle(Base):
    async def test_tier1_c2_full_path_to_close(self):  # edge case 8 + main path
        [iid] = await self.run_scenario("tier1_c2_hr")
        inc = await self.wait_state(iid, State.CLOSE)
        self.assertEqual(self.path(iid), [s.value for s in MAIN_PATH])
        self.assertEqual(inc["level"], "SURGICAL")
        self.assertLess(inc["mttc_ms"], 15_000 * SCALE * 1000)
        hr2 = await self.store.get_asset(6)
        self.assertEqual(hr2["status"], "healthy")          # the redundant node was never touched
        hr1 = await self.store.get_asset(5)
        self.assertEqual(hr1["status"], "healthy")          # re-entered after verification
        acts = {a["action_type"] for a in await self.store.list_actions(iid)}
        self.assertTrue({"APPLY_MICROSEGMENTATION", "ISOLATE_ASSET", "PROTECT_DATABASE", "DRAIN_FROM_POOL",
                         "HARDEN_ENTRY_POINT", "SET_NETWORK_STAGE"} <= acts)
        audit = [a for a in await self.store.list_audit(iid) if a["actor"] == "ACRS"]
        self.assertTrue(any(a["action"] == "ISOLATE_ASSET" for a in audit))
        banners = [m.get("banner") for m in self.pub.history if m.get("incident_id") == iid]
        self.assertIn("ENTRY_POINT_HARDENED", banners)
        self.assertIn("THREAT_NEUTRALIZED", banners)

    async def test_tier2_no_human(self):  # edge case 9
        [iid] = await self.run_scenario("tier2_workstation")
        inc = await self.wait_state(iid, State.CLOSE)
        self.assertEqual(inc["level"], "FULL_ISOLATION")
        self.assertEqual(await self.store.list_approvals(iid), [])
        self.assertFalse([a for a in await self.store.list_audit(iid) if a["actor"] not in ("ACRS", "test")])

    async def test_duplicate_telemetry_correlates(self):
        [a] = await self.run_scenario("tier1_c2_hr")
        [b] = await self.run_scenario("tier1_c2_hr")
        self.assertEqual(a, b)
        self.assertEqual(len(self.store.incidents), 1)


class HumanInTheLoop(Base):
    async def test_tier0_two_person_rule(self):  # edge case 7
        [iid] = await self.run_scenario("tier0_dc_cred_dump")
        inc = await self.wait_state(iid, State.OBSERVE)
        self.assertEqual(inc["level"], "EMERGENCY_RESTRICT")
        self.assertEqual((inc["pending_level"], inc["approvals_required"]), ("FULL_ISOLATION", 2))
        r1 = await self.orch.approve(iid, "alice")
        self.assertFalse(r1["executed"])
        with self.assertRaises(ActionError):
            await self.orch.approve(iid, "alice")
        r2 = await self.orch.approve(iid, "bob")
        self.assertTrue(r2["executed"])
        self.assertEqual((await self.store.get_incident(iid))["level"], "FULL_ISOLATION")
        acts = {a["action_type"] for a in await self.store.list_actions(iid)}
        self.assertTrue({"WITHDRAW_SERVICE_RECORD", "ISOLATE_ASSET"} <= acts)

    async def test_change_window_false_positive(self):  # edge case 2
        [iid] = await self.run_scenario("erp_change_window_fp")
        inc = await self.wait_state(iid, State.PENDING_APPROVAL)
        self.assertEqual(await self.store.list_actions(iid), [])
        out = await self.orch.rollback(iid, "analyst", "approved vendor sync during change window")
        self.assertEqual(out["actions_undone"], 0)
        inc = await self.store.get_incident(iid)
        self.assertEqual(inc["state"], "ROLLED_BACK")
        self.assertTrue(inc["false_positive"])

    async def test_non_isolatable_hold_then_confirm(self):  # edge case 1
        [iid] = await self.run_scenario("mri_non_isolatable")
        inc = await self.wait_state(iid, State.VERIFY, "HOLD")
        await asyncio.sleep(0.05)
        inc = await self.store.get_incident(iid)
        self.assertEqual(inc["level"], "COMPENSATING")
        self.assertIsNotNone(inc["hold_reason"])
        self.assertNotIn("ISOLATE_ASSET", {a["action_type"] for a in await self.store.list_actions(iid)})
        await self.orch.confirm(iid, "clinical-eng")
        await self.wait_state(iid, State.CLOSE)

    async def test_rollback_mid_lifecycle_undoes_everything(self):
        [iid] = await self.run_scenario("tier1_c2_hr")
        await self.wait_state(iid, State.OBSERVE)
        out = await self.orch.rollback(iid, "analyst", "test")
        self.assertGreater(out["actions_undone"], 0)
        self.assertTrue(all(a["status"] != "succeeded" for a in await self.store.list_actions(iid)))
        self.assertEqual((await self.store.get_asset(5))["status"], "healthy")


class FailureModes(Base):
    async def test_integration_down_tier1_escalates_then_engineer_recovers(self):  # edge case 3
        [iid] = await self.run_scenario("tier1_c2_hr", "failure")
        t0 = time.monotonic()
        inc = await self.wait_state(iid, State.ESCALATED)
        self.assertGreaterEqual(time.monotonic() - t0, 15 * SCALE * 0.8)
        self.assertIn("Isolation controller unavailable", inc["escalation_reason"])
        self.assertIn(iid, [i["id"] for i in await self.store.list_incidents(state="ESCALATED")])
        verify_first = await self.orch.engineer_command(iid, "eng", "RUN_VERIFICATION")
        self.assertFalse(verify_first["passed"])
        await self.orch.engineer_command(iid, "eng", "ISOLATE_ASSET")
        res = await self.orch.engineer_command(iid, "eng", "RUN_VERIFICATION")
        self.assertTrue(res["resumed"])
        await self.wait_state(iid, State.CLOSE)

    async def test_tier2_timeout_goes_to_emergency_queue(self):  # edge case 6 (90 s, scaled)
        [iid] = await self.run_scenario("tier2_workstation", "failure")
        t0 = time.monotonic()
        await self.wait_state(iid, State.ESCALATED)
        self.assertGreaterEqual(time.monotonic() - t0, 90 * SCALE * 0.8)

    async def test_gate_fails_twice_then_escalates(self):  # edge case 4
        [iid] = await self.run_scenario("cloud_workload", "failure")
        inc = await self.wait_state(iid, State.ESCALATED)
        self.assertEqual(inc["escalated_from"], "REMEDIATE")
        self.assertEqual(inc["remediation_attempts"], 2)
        self.assertEqual(self.path(iid).count("REMEDIATE"), 2)
        await self.orch.engineer_command(iid, "eng", "RUN_VERIFICATION")
        await self.wait_state(iid, State.CLOSE)

    async def test_iob_returns_during_observation(self):  # edge case 5
        [iid] = await self.run_scenario("ioc_return_hr")
        inc = await self.wait_state(iid, State.CLOSE)
        p = self.path(iid)
        self.assertIn("REMEDIATE", p[p.index("OBSERVE") + 1:])
        self.assertEqual(inc["cycle"], 2)

    async def test_watchdog_escalates_orphaned_containment(self):
        [iid] = await self.run_scenario("tier1_c2_hr", "failure")
        await self.wait_state(iid, State.CONTAIN)
        self.orch.tasks.pop(iid).cancel()           # simulate a crashed worker
        await asyncio.sleep(15 * SCALE + 2.1)
        self.assertEqual(await self.orch.sweep(), 1)
        self.assertEqual((await self.store.get_incident(iid))["state"], "ESCALATED")


class RansomwareAndUnknown(Base):
    async def test_ransomware_segment_restricted_once(self):
        ids = await self.run_scenario("ransomware_finance")
        self.assertEqual(len(ids), 3)
        for iid in ids:
            await self.wait_state(iid, State.VERIFY, State.REMEDIATE, State.HARDEN, State.OBSERVE,
                                  State.RE_ENTRY, State.LEARN, State.CLOSE)
        seg = [a for iid in ids for a in await self.store.list_actions(iid)
               if a["action_type"] == "RESTRICT_SEGMENT_LATERAL"]
        self.assertEqual(len(seg), 1)
        self.assertEqual(seg[0]["target"], "user-finance")

    async def test_unknown_host_restrict_and_hold(self):
        [iid] = await self.run_scenario("unknown_host")
        await self.wait_state(iid, "HOLD")
        await asyncio.sleep(0.05)
        inc = await self.store.get_incident(iid)
        self.assertEqual(inc["state"], "VERIFY")
        self.assertEqual(inc["level"], "RESTRICT")
        self.assertIsNone(inc["asset_id"])



class RateLimit(unittest.IsolatedAsyncioTestCase):
    async def test_local_fixed_window(self):
        from app.services.ratelimit import RateLimiter
        rl = RateLimiter(per_minute=5)
        self.assertTrue((await rl.hit("c", 5))[0])
        self.assertFalse((await rl.hit("c", 1))[0])
        self.assertTrue((await rl.hit("other", 1))[0])


if __name__ == "__main__":
    unittest.main()
