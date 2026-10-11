import unittest
from qacrs import executor_v8 as X


class TestChainLog(unittest.TestCase):
    def test_detects_edit_delete_reorder(self):
        log = X.ChainLog()
        for i in range(5):
            log.append(i=i)
        self.assertTrue(X.ChainLog.verify(log.entries))
        e = [dict(x, body=dict(x["body"])) for x in log.entries]; e[2]["body"]["i"] = 99
        self.assertFalse(X.ChainLog.verify(e))
        self.assertFalse(X.ChainLog.verify(log.entries[:2] + log.entries[3:]))
        self.assertFalse(X.ChainLog.verify([log.entries[1], log.entries[0]] + log.entries[2:]))


class TestTTL(unittest.TestCase):
    def test_expiry_and_confirmation(self):
        s = X.RuleStore(); s.add("a", "ISOLATE", "web1", now=0); s.add("b", "ISOLATE", "web2", now=0)
        s.confirm("b", now=1000)
        self.assertEqual(s.expire(now=X.DEFAULT_TTL_S), ["a"])
        self.assertIn("b", s.rules)


class TestDecay(unittest.TestCase):
    def test_low_risk_not_kept(self):
        self.assertEqual(X.isolation_minutes_decaying(5), 0.0)
        self.assertAlmostEqual(X.isolation_minutes_decaying(14), 15.0, places=3)


if __name__ == "__main__":
    unittest.main()
