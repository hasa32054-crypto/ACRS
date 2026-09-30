"""Learning experiment (research/learning.py): the claims shown on the site and in the paper."""
from research.learning import run

RES = run()
R = {r["round"]: r for r in RES["rounds"]}


def test_repeat_rounds_leave_only_tier0():
    # after an engineer handled a trick once, its repeat is stopped, except Tier-0 which always waits for people
    for rid in ("R2", "R4", "R6", "R8"):
        for m in R[rid]["misses_learning"]:
            assert any(h in m for h in ("dc02_lsass_single", "tier0_dc_cred_dump", "pki_c2", "k8s_cp_c2")), m


def test_learning_never_touches_harmless_or_tier0_and_never_isolates():
    for r in RES["rounds"]:
        assert r["learned_on_harmless"] == 0
        assert r["tier0_learned"] == 0
        assert r["max_learned_level"] in (None, "RESTRICT", "COMPENSATING")


def test_deterministic():
    again = run()
    assert [r["miss_learning"] for r in again["rounds"]] == [r["miss_learning"] for r in RES["rounds"]]
