import json
import threading
import unittest
import urllib.error
import urllib.request

from qacrs import hassan as H
from qacrs import hassan_service as SV


class TestAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = SV.make_server(0, limiter_factory=lambda: H.RateLimiter(limit=10 ** 9))
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.srv.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def post(self, obj):
        req = urllib.request.Request(self.base + "/hassan/decide", json.dumps(obj).encode(),
                                     {"Content-Type": "application/json"})
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())

    def test_decide(self):
        code, out = self.post({"network": "net12", "hacked": {"web1": 5, "app1": 6, "db": 8}})
        self.assertEqual(code, 200)
        self.assertIn("db", out["segment"])
        self.assertTrue(out["acrs"]["within_deadline"])
        self.assertTrue(out["card"]["ar"])

    def test_bad_requests(self):
        for body in ({"network": "nope", "hacked": {}}, {"network": "net12"}):
            with self.assertRaises(urllib.error.HTTPError) as e:
                self.post(body)
            self.assertEqual(e.exception.code, 400)

    def test_unknown_machine_rejected(self):
        code, out = self.post({"network": "net12", "hacked": {"ghost": 9}})
        self.assertEqual(out["status"], "REJECTED")


class TestReplay(unittest.TestCase):
    def test_known_and_unknown(self):
        self.assertIsNotNone(SV.replay("net12_ood002_c7"))
        self.assertIsNone(SV.replay("no-such-id"))


if __name__ == "__main__":
    unittest.main()
