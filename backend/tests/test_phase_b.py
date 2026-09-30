"""Phase B: Response Memory, hourly report, and the 40-scenario Attack Simulation Lab."""
import asyncio
import time
import unittest
from collections import Counter
from datetime import datetime, timedelta, timezone

from app.engines import memory as rmem
from app.engines import reports
from app.engines.decision import decide
from app.engines.detection import detect
from app.engines.risk import assess, attribute
from app.engines.types import Asset
from app.services import simulators
from app.services.memory_store import InMemoryStore
from app.services.publisher import LocalPublisher
from app.services.seed_data import asset_rows
from app.workers.lifecycle import ActionError, Orchestrator, Settings

ASSETS = {r["ip"]: Asset(**r) for r in asset_rows()}
FP = {"attack_type": "Command & Control", "rules": ["ACRS-NET-001", "ACRS-TI-001"], "mitre": ["T1071"],
      "entry_vector": "unknown", "asset_role": "workstation", "tier": 2, "environment": "on-prem",
      "level": "RESTRICT"}
SETTLED = {"CLOSE", "ESCALATED", "PENDING_APPROVAL", "MONITOR", "ROLLED_BACK"}


class MemoryEngine(unittest.TestCase):
    def test_similarity(self):
        self.assertEqual(rmem.similarity(FP, dict(FP)), 1.0)
        other = {**FP, "asset_role": "hr-app"}
        self.assertLess(rmem.similarity(FP, other), rmem.SIMILARITY_THRESHOLD)
        close = {**FP, "mitre": ["T1071", "T1105"]}           # one MITRE tag differs
        self.assertLess(rmem.similarity(FP, close), rmem.SIMILARITY_THRESHOLD)

    def test_only_approved_patterns_match(self):
        pending = {"id": "p1", "status": "PENDING_VALIDATION", "fingerprint": FP, "level": "RESTRICT"}
        self.assertIsNone(rmem.best_match(FP, [pending])[0])
        approved = {**pending, "status": "APPROVED"}
        self.assertEqual(rmem.best_match(FP, [approved])[0]["id"], "p1")

    def test_tier_policy_guard(self):
        p = {"level": "SURGICAL"}
        self.assertFalse(rmem.may_apply(p, {"auto_execute": True, "level": "RESTRICT"}, 2)[0])
        self.assertFalse(rmem.may_apply({"level": "RESTRICT"}, {"auto_execute": False, "level": "RESTRICT"}, 2)[0])
        self.assertFalse(rmem.may_apply({"level": "RESTRICT"}, {"auto_execute": True, "level": "RESTRICT"}, 0)[0])
        self.assertTrue(rmem.may_apply({"level": "RESTRICT"}, {"auto_execute": True, "level": "RESTRICT"}, 2)[0])


class ReportEngine(unittest.TestCase):
    def test_kpis(self):
        now = datetime.now(timezone.utc)
        base = {"started_at": now - timedelta(seconds=30), "detected_at": now, "tier": 2, "state": "CLOSE",
                "attack_type": "C2", "level": "RESTRICT", "asset_id": 1, "contained_at": now}
        incs = [{**base, "mttc_ms": 2000, "auto_executed": True},
                {**base, "mttc_ms": 90000, "auto_executed": True, "sla_breached": True, "asset_id": 2},
                {**base, "state": "ROLLED_BACK", "false_positive": True, "mttc_ms": None, "contained_at": None}]
        r = reports.build(incs, now - timedelta(hours=1), now, 20)
        k = r["kpis"]
        self.assertEqual((k["incidents"], k["auto_contained"], k["false_positives"]), (3, 2, 1))
        self.assertEqual(k["mttc_within_target_pct"], 50.0)
        self.assertEqual(k["assets_contained"], 2)
        self.assertEqual(k["business_continuity_pct"], 90.0)
        self.assertEqual(k["mttd_ms_avg"], 30000)
        self.assertTrue(r["recommendations"])


class ScenarioCatalog(unittest.TestCase):
    def test_forty_scenarios_across_eight_categories(self):
        self.assertEqual(len(simulators.SCENARIOS), 40)
        cats = Counter(v["category"] for v in simulators.SCENARIOS.values())
        self.assertEqual(set(cats), set(simulators.CATEGORIES))
        self.assertTrue(all(n >= 4 for n in cats.values()), cats)

    def test_every_scenario_detects_and_decides(self):
        for sid in simulators.SCENARIOS:
            for mode in ("success", "failure"):
                events, profile = simulators.build(sid, mode)
                self.assertEqual(profile["mode"], mode)
                if mode == "failure":
                    self.assertIn(profile["failure"], simulators.FAILURE_MODES)
            for ip in {e.src_ip for e in events}:
                evs = sorted([e for e in events if e.src_ip == ip], key=lambda e: e.ts)
                dets = detect(evs)
                self.assertTrue(dets, f"{sid}/{ip}: no detection")
                a = attribute(ip, evs, ASSETS)
                decide(a, assess(dets, a.asset, evs, a.conflict), dets)


class Base(unittest.IsolatedAsyncioTestCase):
    def make(self):
        return Orchestrator(InMemoryStore(), LocalPublisher(),
                            Settings(time_scale=0.02, stage_pacing_s=0, latency_scale=0.02))

    async def settle(self, orch, iid, timeout=15.0):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            inc = await orch.store.get_incident(iid)
            if inc["state"] in SETTLED or inc.get("hold_reason"):
                await asyncio.sleep(0.02)
                inc = await orch.store.get_incident(iid)
                if inc["state"] in SETTLED or inc.get("hold_reason"):
                    return inc
            await asyncio.sleep(0.02)
        raise AssertionError(f"{iid} did not settle: {inc['state']}")


class ResponseMemoryLifecycle(Base):
    async def test_edge_case_10_pattern_reuse(self):
        orch = self.make()
        events, sim = simulators.build("response_memory_repeat")
        [first] = await orch.ingest(events, "test", sim)
        inc = await self.settle(orch, first)
        self.assertIsNotNone(inc["hold_reason"])            # first time: medium band pauses for a human
        await orch.confirm(first, "analyst")
        inc = await self.settle(orch, first)
        self.assertEqual(inc["state"], "CLOSE")
        [pattern] = await orch.store.list_patterns()
        self.assertEqual(pattern["status"], "PENDING_VALIDATION")
        with self.assertRaises(ActionError):
            await orch.review_pattern("missing", "eng", True)
        await orch.review_pattern(pattern["id"], "engineer", True, "validated response")

        events, sim = simulators.build("response_memory_repeat")
        [second] = await orch.ingest(events, "test", sim)
        self.assertNotEqual(first, second)
        inc = await self.settle(orch, second)
        self.assertEqual(inc["state"], "CLOSE")               # second time: no pause, fully automatic
        self.assertTrue(inc["memory"]["applied"])
        self.assertGreaterEqual(inc["memory"]["score"], 0.96)
        banners = [m.get("banner") for m in orch.pub.history if m.get("incident_id") == second]
        self.assertIn("RESPONSE_PATTERN_APPLIED", banners)
        self.assertEqual((await orch.store.get_pattern(pattern["id"]))["hits"], 1)
        for t in orch.tasks.values():
            t.cancel()

    async def test_pending_pattern_is_not_reused(self):
        orch = self.make()
        for _ in range(2):
            events, sim = simulators.build("response_memory_repeat")
            [iid] = await orch.ingest(events, "test", sim)
            inc = await self.settle(orch, iid)
            self.assertIsNotNone(inc["hold_reason"])
            await orch.confirm(iid, "analyst")
            await self.settle(orch, iid)
        [p] = await orch.store.list_patterns()
        self.assertEqual(p["occurrences"], 2)
        self.assertEqual(p["hits"], 0)

    async def test_report_generation(self):
        orch = self.make()
        events, sim = simulators.build("tier2_workstation")
        [iid] = await orch.ingest(events, "test", sim)
        await self.settle(orch, iid)
        r = await orch.generate_report(3600)
        self.assertEqual(r["kpis"]["incidents"], 1)
        self.assertEqual(len(await orch.store.list_reports()), 1)


class AllScenariosEndToEnd(Base):
    async def test_forty_scenarios_success_and_failure(self):
        async def one(sid, mode):
            orch = self.make()
            events, sim = simulators.build(sid, mode)
            ids = await orch.ingest(events, "test", sim)
            out = [await self.settle(orch, i, timeout=25) for i in ids]
            for t in orch.tasks.values():
                t.cancel()
            return sid, mode, out

        results = await asyncio.gather(*(one(s, m) for s in simulators.SCENARIOS for m in ("success", "failure")))
        for sid, mode, incs in results:
            self.assertTrue(incs, f"{sid}/{mode}: no incident")
            for inc in incs:
                if mode == "success" and sid != "ioc_return_hr":
                    self.assertNotEqual(inc["state"], "ESCALATED", f"{sid}: {inc.get('escalation_reason')}")
                if mode == "failure" and inc["auto_executed"] and inc.get("tier") != 0 \
                        and not inc.get("hold_reason") \
                        and (inc["simulation"] or {}).get("failure") in ("integration_down", "gate_fail"):
                    self.assertEqual(inc["state"], "ESCALATED", f"{sid}/{mode} ended {inc['state']}")


if __name__ == "__main__":
    unittest.main()
