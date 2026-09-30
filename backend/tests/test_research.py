"""The research experiment must be reproducible and its headline findings must hold.

If a change to the decision engine breaks one of these, the poster is out of date: re-run
`python -m research.experiment` and rebuild the poster from the new results.
"""
from app.engines.decision import decide as acrs_decide

from research.experiment import incidents, run_arm, summarise, threshold_sweep, uniform_decide

INCS = incidents()
BASE = summarise(run_arm(INCS, uniform_decide))
ACRS = summarise(run_arm(INCS, acrs_decide))


def test_deterministic():
    again = incidents()
    assert summarise(run_arm(again, acrs_decide)) == ACRS
    assert summarise(run_arm(again, uniform_decide)) == BASE


def test_same_inputs_for_both_arms():
    assert BASE["incidents"] == ACRS["incidents"] == len(INCS)
    assert BASE["malicious"] == ACRS["malicious"]


def test_less_disruption():
    assert ACRS["hosts_offline"] < BASE["hosts_offline"]
    assert ACRS["critical_outages"] < BASE["critical_outages"]
    assert ACRS["safety_devices_offline"] == 0
    assert ACRS["tier0_irreversible_without_human"] == 0
    assert ACRS["benign_hosts_offline"] == 0


def test_attacker_cut_off_as_often():
    assert ACRS["c2_cut_auto"] >= BASE["c2_cut_auto"]


def test_human_effort_categories_cover_every_incident():
    parts = ("no_action", "fully_autonomous", "human_before_recovery", "tier0_two_person_pending", "human_to_contain")
    assert sum(ACRS[k] for k in parts) == ACRS["incidents"]


def test_no_uniform_threshold_matches_acrs():
    for p in threshold_sweep(INCS):
        assert not (p["critical_outages"] <= ACRS["critical_outages"] and p["c2_cut_auto"] >= ACRS["c2_cut_auto"]), p
