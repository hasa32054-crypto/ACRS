import json
import tempfile
import unittest
from pathlib import Path

from qacrs import blind_v9 as B


def sample(n=3):
    return {"author_role": "test fixture (not a blind scenario)", "network": "hospital60", "consent_to_publish": False,
            "saw_hassan_decisions_before_writing": False,
            "scenarios": [{"id": f"t{i}", "hacked": {"pc_recep1": 5, "email": 7, "dc1": 8}, "description": "fixture"}
                          for i in range(n)]}


class TestValidate(unittest.TestCase):
    def test_ok_and_errors(self):
        self.assertEqual(B.validate(sample()), [])
        bad = sample(); bad["scenarios"][0]["hacked"] = {"ghost": 5, "dc1": 11}
        e = B.validate(bad)
        self.assertTrue(any("unknown machine" in x for x in e))
        self.assertTrue(any("1..10" in x for x in e))
        seen = sample(); seen["saw_hassan_decisions_before_writing"] = True
        self.assertTrue(B.validate(seen))

    def test_guide_lists_all_60(self):
        p = B.guide()
        self.assertEqual(sum(1 for l in p.read_text().splitlines() if l.startswith("| ") and l[2].isdigit()), 60)


class TestRunOnce(unittest.TestCase):
    def test_run_then_refuse(self):
        if B.drift():
            self.skipTest("lock not written yet")
        with tempfile.TemporaryDirectory() as d:
            old = B.OUT; B.OUT = Path(d)
            try:
                f = Path(d) / "s.json"; f.write_text(json.dumps(sample()))
                B.run(f)
                with self.assertRaises(SystemExit):
                    B.run(f)
            finally:
                B.OUT = old


if __name__ == "__main__":
    unittest.main()
