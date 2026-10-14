"""SAIF booth: hardening, attack memory, QR, signed plans, agent rules, evidence, and the HTTP API."""
import http.client
import json
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path

TMP = tempfile.mkdtemp(prefix="hassan-booth-test-")
os.environ["HASSAN_SECRET_DIR"] = str(Path(TMP) / "secrets")
os.environ["HASSAN_DATA_DIR"] = str(Path(TMP) / "data")

from qacrs.booth import agent as A, evidence, qr, secure  # noqa: E402
from qacrs.booth.core import Booth, ZONES  # noqa: E402
from qacrs.booth.memory import AttackMemory, invariants  # noqa: E402

KEY = b"k" * 32
BOOTH = Booth(KEY)


class TestSecure(unittest.TestCase):
    def test_seal_open_tamper_stale_replay(self):
        n = secure.NonceCache()
        env = secure.seal({"isolate": ["web1"]}, KEY)
        self.assertEqual(secure.open_envelope(env, KEY, n)[1], "ok")
        self.assertEqual(secure.open_envelope(env, KEY, n)[1], "replayed plan")
        env = secure.seal({"isolate": []}, KEY); env["plan"]["isolate"] = ["ehr_db"]
        self.assertEqual(secure.open_envelope(env, KEY, n)[1], "bad signature")
        self.assertEqual(secure.open_envelope(secure.seal({}, b"other" * 8), KEY, n)[1], "bad signature")
        old = secure.seal({}, KEY, now=time.time() - 120)
        self.assertEqual(secure.open_envelope(old, KEY, n)[1], "stale or future plan")
        self.assertEqual(secure.open_envelope({"plan": {}}, KEY, n)[1], "malformed envelope")
        self.assertEqual(secure.open_envelope("x", KEY, n)[1], "malformed envelope")

    def test_secret_file_is_private_and_stable(self):
        a, b = secure.load_secret("t1"), secure.load_secret("t1")
        self.assertEqual(a, b)
        self.assertEqual(oct((Path(os.environ["HASSAN_SECRET_DIR"]) / "t1").stat().st_mode & 0o777), "0o600")

    def test_validation(self):
        names = BOOTH.names
        self.assertEqual(secure.attack({"hacked": {"web1": 8}, "forged": ["web1"]}, names), ({"web1": 8}, ["web1"]))
        bad = [{"hacked": {"nope": 8}}, {"hacked": {"web1": True}}, {"hacked": {"web1": 11}}, {"hacked": {"web1": "8"}},
               {"hacked": {}}, {"hacked": {"web1": 8}, "extra": 1}, {"hacked": {"web1": 8}, "forged": ["dc1"]},
               {"hacked": {m: 5 for m in sorted(names)[:21]}}, {"forged": []}, []]
        for b in bad:
            with self.assertRaises(secure.Invalid, msg=b):
                secure.attack(b, names)
        self.assertEqual(secure.label("  <b>هجوم</b>  ١ "), "bهجوم/b ١")
        for b in ["", "x" * 41, 5, "<>"]:
            with self.assertRaises(secure.Invalid):
                secure.label(b)

    def test_client_limiter(self):
        now = [0.0]
        lim = secure.ClientLimiter(limit=3, window=10, clock=lambda: now[0])
        self.assertEqual([lim.allow("a") for _ in range(4)], [True, True, True, False])
        self.assertTrue(lim.allow("b"))
        now[0] = 11
        self.assertTrue(lim.allow("a"))


class TestQR(unittest.TestCase):
    def test_decodes_with_opencv(self):
        try:
            import cv2
            import numpy as np
        except ImportError:
            self.skipTest("OpenCV not installed")
        dets = [cv2.QRCodeDetector()] + ([cv2.QRCodeDetectorAruco()] if hasattr(cv2, "QRCodeDetectorAruco") else [])
        for text in ["HASSAN", evidence.REPO, "حسان " * 20, "z" * 213]:
            m = qr.encode(text); n = len(m)
            img = np.full((n + 8, n + 8), 255, np.uint8)
            for r in range(n):
                for c in range(n):
                    if m[r][c]:
                        img[r + 4, c + 4] = 0
            img = cv2.resize(img, ((n + 8) * 8, (n + 8) * 8), interpolation=cv2.INTER_NEAREST)
            self.assertIn(text, [d.detectAndDecode(img)[0] for d in dets])   # the classic detector is flaky on v7+

    def test_too_long(self):
        with self.assertRaises(ValueError):
            qr.encode("x" * 214)


class TestCore(unittest.TestCase):
    def test_every_machine_in_one_zone(self):
        self.assertEqual(sorted(m for z in ZONES for m in z["machines"]), sorted(BOOTH.names))

    def test_genuine_chain_keeps_services(self):
        r = BOOTH.decide({"pc_nurse2": 8, "ehr_app2": 8, "ehr_db": 9}, [])
        self.assertEqual(invariants(BOOTH, {"pc_nurse2": 8, "ehr_app2": 8, "ehr_db": 9}, r), [])
        self.assertEqual(r["hassan"]["services_down"], [])
        self.assertGreater(len(r["full_isolation"]["services_down"]), 0)
        self.assertTrue(r["card"]["actions"])

    def test_forged_alerts_cannot_force_outage(self):
        h = {"pc_recep2": 7, "dc1": 9, "ehr_db": 9}
        r = BOOTH.decide(h, ["dc1", "ehr_db"])
        self.assertEqual(r["hassan"]["isolate"], [])
        self.assertEqual(r["hassan"]["services_down"], [])
        self.assertEqual(r["status"], "ESCALATED")

    def test_spread_timeline_matches_engine(self):
        from qacrs import hassan as H, qubo_v7 as V7
        from qacrs.hassan_v9 import spread_v9
        for start in ("pc_recep1", "vpn", "pc_nurse3"):
            for pol, fn, sh in (("none", None, False), ("full", V7.m_full_isolation_safe, False),
                                ("hassan", lambda n, s: H.solve(n, s)[:2], True)):
                tl = BOOTH.spread_timeline([start], pol)
                ref = spread_v9(BOOTH.net, {start}, fn, shield=sh)
                self.assertEqual(tl["encrypted"], ref["encrypted"], (start, pol))
                self.assertEqual(tl["services_unavailable"], ref["services_unavailable"], (start, pol))

    def test_verify_rejects_one_changed_character(self):
        h = {"pc_recep1": 8, "web1": 8}
        r = BOOTH.decide(h, [])
        self.assertTrue(BOOTH.verify(h, r["certificate"], r["signature"])["accepted"])
        c = dict(r["certificate"]); c["status"] = c["status"].lower()
        self.assertFalse(BOOTH.verify(h, c, r["signature"])["accepted"])
        self.assertFalse(BOOTH.verify(h, r["certificate"], "0" * 64)["accepted"])

    def test_judge_flags_unsafe_choice(self):
        j = BOOTH.judge({"pc_doc1": 8, "pacs1": 8}, [], ["ct", "pacs1"], [])
        self.assertTrue(j["safety_violations"])
        self.assertEqual(j["medical_devices_isolated"], ["ct"])


class TestMemory(unittest.TestCase):
    def test_save_regress_delete(self):
        mem = AttackMemory(Path(TMP) / "mem.json")
        e = mem.save(BOOTH, "طبيب ← الأشعة", {"pc_doc1": 8, "pacs1": 8, "pacs_store": 9}, [])
        mem.save(BOOTH, "تزوير", {"pc_recep2": 7, "dc1": 9}, ["dc1"])
        mem.save(BOOTH, "طبيب ← الأشعة", {"pc_doc1": 8, "pacs1": 8, "pacs_store": 9}, [])     # same attack: one entry
        self.assertEqual(len(mem.load()), 2)
        r = mem.regress(BOOTH)
        self.assertEqual((r["total"], r["passed"]), (2, 2))
        self.assertTrue(mem.delete(e["id"]))
        self.assertEqual(len(mem.load()), 1)
        (Path(TMP) / "mem.json").write_text("{broken")
        self.assertEqual(mem.load(), [])


class TestAgent(unittest.TestCase):
    cfg = A.load_config()

    def test_rules_only_from_templates(self):
        lines, ignored = A.rules(self.cfg, {"isolate": ["web1", "web1 -j ACCEPT", "ct"], "segment": ["ehr_db"],
                                            "restrict": ["pc_recep1"]})
        self.assertEqual(ignored, ["ct", "web1 -j ACCEPT"])
        self.assertTrue(all(l.startswith("-A ACRS ") for l in lines))
        self.assertIn("-A ACRS -s 172.30.0.11/32 -j DROP", lines)
        self.assertIn("-A ACRS -d 172.30.0.13/32 -p tcp -m tcp --dport 5432 -j RETURN", lines)
        self.assertEqual(lines[-1], "-A ACRS -j RETURN")
        txt = A.restore_text(lines)
        self.assertTrue(txt.startswith("*filter\n:ACRS - [0:0]\n") and txt.endswith("COMMIT\n"))

    def test_plan_validation(self):
        ok = {"isolate": [], "segment": [], "restrict": [], "ttl_s": 30}
        self.assertEqual(A.validate_plan(ok)["ttl_s"], 30)
        for bad in [ok | {"cmd": "rm"}, ok | {"ttl_s": 0}, ok | {"ttl_s": True}, ok | {"isolate": "web1"},
                    ok | {"isolate": ["x" * 33]}]:
            with self.assertRaises(secure.Invalid):
                A.validate_plan(bad)

    def test_dry_run_agent_handles_only_sealed_plans(self):
        ag = A.Agent(self.cfg, KEY, A.Firewall(False), probe_fn=lambda cfg, c: {})
        code, out = ag.handle("/apply", secure.seal({"isolate": ["web1"], "segment": [], "restrict": [], "ttl_s": 5}, KEY))
        self.assertEqual(code, 200); self.assertTrue(out["dry_run"]); self.assertFalse(out["applied"])
        self.assertEqual(ag.handle("/apply", {"isolate": ["web1"]})[0], 403)
        env = secure.seal({"ask": "health"}, KEY)
        self.assertEqual(ag.handle("/health", env)[0], 200)
        self.assertEqual(ag.handle("/health", env)[1]["error"], "replayed plan")


class TestEvidence(unittest.TestCase):
    def test_numbers_resolve_and_quantum_matches(self):
        ev = evidence.collect()
        self.assertEqual(len(ev["numbers"]), len(evidence.SOURCES))
        self.assertEqual(ev["numbers"]["v7_full_services_down"]["value"], 292)
        q = evidence.quantum_shots()
        share = sum(r["count"] for r in q["rows"] if r["optimal"]) / q["shots"]
        self.assertAlmostEqual(share, q["p_best_real"], places=9)


class TestServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from qacrs.booth.server import make_server
        cls.srv = make_server(0, token="t" * 64, key=KEY, memory=AttackMemory(Path(TMP) / "srv_mem.json"))
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def req(self, method, path, body=None, host=None, token="t" * 64, ctype="application/json", raw=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=20)
        h = {"Host": host or f"127.0.0.1:{self.port}"}
        if token:
            h["X-HASSAN-Token"] = token
        if ctype:
            h["Content-Type"] = ctype
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        c.request(method, path, body=data, headers=h)
        r = c.getresponse(); b = r.read()
        return r.status, dict(r.getheaders()), b

    def test_static_and_headers(self):
        s, h, b = self.req("GET", "/")
        self.assertEqual(s, 200); self.assertIn(b"<html", b)
        self.assertIn("script-src 'self'", h["Content-Security-Policy"])
        self.assertEqual(h["X-Content-Type-Options"], "nosniff")
        for p in ("/../server.py", "/%2e%2e/secure.py", "/app.js/../../server.py", "/etc/passwd"):
            self.assertEqual(self.req("GET", p)[0], 404, p)

    def test_host_and_token_checks(self):
        self.assertEqual(self.req("GET", "/api/session", host="evil.example")[0], 421)
        s, _, b = self.req("GET", "/api/session")
        self.assertEqual((s, json.loads(b)["token"]), (200, "t" * 64))
        body = {"hacked": {"web1": 8}}
        self.assertEqual(self.req("POST", "/api/decide", body, token=None)[0], 401)
        self.assertEqual(self.req("POST", "/api/decide", body, token="x" * 64)[0], 401)
        self.assertEqual(self.req("POST", "/api/decide", body, host="evil.example")[0], 403)
        self.assertEqual(self.req("POST", "/api/decide", body, ctype="text/plain")[0], 415)
        self.assertEqual(self.req("POST", "/api/decide", raw=b"x" * (17 * 1024))[0], 413)
        self.assertEqual(self.req("POST", "/api/decide", raw=b"{not json")[0], 400)
        self.assertEqual(self.req("POST", "/api/decide", {"hacked": {"nope": 8}})[0], 400)
        self.assertEqual(self.req("POST", "/api/nothing", body)[0], 404)

    def test_full_journey(self):
        s, _, b = self.req("POST", "/api/decide", {"hacked": {"pc_doc1": 8, "pacs1": 8, "pacs_store": 9}})
        d = json.loads(b)
        self.assertEqual(s, 200); self.assertIn("receipt_qr", d); self.assertTrue(d["receipt"].startswith("ACRS v9|"))
        s, _, b = self.req("POST", "/api/verify", {"hacked": {"pc_doc1": 8, "pacs1": 8, "pacs_store": 9},
                                                    "certificate": d["certificate"], "signature": d["signature"]})
        self.assertTrue(json.loads(b)["accepted"])
        s, _, b = self.req("POST", "/api/judge", {"hacked": {"pc_doc1": 8, "pacs1": 8}, "isolate": ["pacs1"],
                                                   "segment": [], "seconds": 12.5})
        self.assertEqual(s, 200); self.assertIn("judge", json.loads(b))
        s, _, b = self.req("POST", "/api/spread", {"start": ["pc_recep1"], "policy": "hassan"})
        self.assertEqual(len(json.loads(b)["frames"]), 11)
        self.assertEqual(self.req("POST", "/api/attacks/save", {"name": "x", "hacked": {"web1": 8}, "consent": False})[0], 400)
        s, _, b = self.req("POST", "/api/attacks/save", {"name": "بوابة", "hacked": {"web1": 8}, "consent": True})
        self.assertEqual(s, 200)
        s, _, b = self.req("POST", "/api/attacks/regress", {})
        r = json.loads(b); self.assertEqual(r["passed"], r["total"])
        s, _, b = self.req("GET", "/api/model")
        m = json.loads(b); self.assertEqual(len(m["machines"]), 60); self.assertIn("v7_h1_ratio", m["evidence"]["numbers"])
        self.assertEqual(self.req("POST", "/api/lab", {})[0], 200)


if __name__ == "__main__":
    unittest.main()
