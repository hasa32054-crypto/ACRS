"""Learning experiment: does ACRS stop repeated attacks after an engineer handled them once?

Run from the backend folder:
    python -m research.learning

Question
--------
When ACRS does not stop an attacker automatically (a "miss"), an engineer handles that incident by hand.
If the engineer's response is saved (Response Memory) and reused on later incidents that look the same,
how many misses are left when the same attacks come back, including disguised versions of them?

Design (fixed before the run; nothing is random, so re-running gives the same numbers)
------------------------------------------------------------------------------------
* Attacks: the same 40 scenarios as the main experiment (41 malicious incidents + 1 harmless one).
* 8 rounds. Each round replays every incident in one form:
    R1 original   R2 repeat
    R3 new infrastructure (the attacker moves to new IP addresses and domains, so threat-intel feeds no
       longer recognise them; threat-intel events disappear)      R4 the same disguise again
    R5 evasion (the attacker hides from one sensor: every event from that sensor disappears)
    R6 the same evasion again
    R7 both tricks together                                        R8 the same again
* Every variant goes through the unmodified pipeline: detect -> attribute -> assess (risk, confidence) ->
  decide (app.engines.decision). Commands come from app.engines.response.plan, and outcomes are measured
  with research.experiment.measure (the same measurement as the main experiment).
* Miss = a malicious incident where the attacker's outside connection is NOT cut automatically.
* Engineer (simulated): after each round, every miss is handled by hand and saved as an APPROVED pattern
  (fingerprint + the lightest response that cuts the attacker on that asset). The harmless incident is
  marked harmless and never saved. Assumption: the engineer identifies the attacks correctly.
* Learned response (the rule being tested), with guard rails:
    - reused only if the new incident matches an approved pattern at >= 96 % similarity
      (app.engines.memory.similarity / SIMILARITY_THRESHOLD, unchanged);
    - never on a Tier-0 server (those always wait for people);
    - the strongest action it may take is RESTRICT (block the attacker, machine keeps working), or network
      blocking only (COMPENSATING) on a device that must not be switched off. It never isolates a machine.
* Arms compared on the same variants: uniform full isolation, ACRS without learning, ACRS with learning.

All data are simulated. The numbers describe the model's behaviour on synthetic variants.
"""
from __future__ import annotations

import json
from collections import Counter
from dataclasses import replace
from pathlib import Path

from app.engines import memory
from app.engines.decision import decide as acrs_decide
from app.engines.detection import detect
from app.engines.risk import assess, attribute
from app.engines.types import Decision, Level
from app.services import simulators

from .experiment import ASSETS, BENIGN, measure, uniform_decide

OUT = Path(__file__).parent / "results"
ROUNDS = [("R1", "original"), ("R2", "original"), ("R3", "new_infra"), ("R4", "new_infra"),
          ("R5", "evasion"), ("R6", "evasion"), ("R7", "both"), ("R8", "both")]


# ------------------------------------------------------------------------------------ variants
def _is_internal(ip: str) -> bool:
    return ip.startswith(("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.30.", "172.31."))


def _new_ip(old: str) -> str:
    h = sum(ord(c) * (i + 1) for i, c in enumerate(old))
    return f"203.0.{h % 250 + 1}.{(h // 250) % 250 + 1}"          # documentation range, deterministic


def new_infra(events):
    out = []
    for e in events:
        if e.source == "threat_intel":
            continue                                               # new infrastructure: feeds do not know it yet
        data = dict(e.data)
        for k in ("dest_ip", "indicator", "remote_ip"):
            v = data.get(k)
            if isinstance(v, str) and v.count(".") == 3 and not _is_internal(v):
                data[k] = _new_ip(v)
        for k in ("domain", "query"):
            v = data.get(k)
            if isinstance(v, str) and "." in v and not v.endswith((".local", ".corp", ".internal")):
                data[k] = "cdn-" + str(sum(map(ord, v)) % 997) + ".example.net"
        dom = e.c2_domain and ("cdn-" + str(sum(map(ord, e.c2_domain)) % 997) + ".example.net")
        out.append(replace(e, data=data, c2_domain=dom))
    return out


def evasion(events):
    """Hide from one sensor: the source with the most events (ties: alphabetical). Needs >= 2 sources."""
    by = Counter(e.source for e in events)
    if len(by) < 2:
        return list(events)
    drop = sorted(by.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]
    return [e for e in events if e.source != drop]


VARIANTS = {"original": lambda ev: list(ev), "new_infra": new_infra, "evasion": evasion,
            "both": lambda ev: evasion(new_infra(ev))}


def base_streams():
    """(scenario, ip, events) for every incident the 40 scenarios produce, in a fixed order."""
    out = []
    for sid in simulators.SCENARIOS:
        events, _ = simulators.build(sid, "success")
        for ip in sorted({e.src_ip for e in events}):
            evs = sorted([e for e in events if e.src_ip == ip], key=lambda e: e.ts)
            if detect(evs):
                out.append((sid, ip, evs))
    return out


def analyse(sid, ip, evs):
    dets = detect(evs)
    if not dets:
        return None                                                # the attack became invisible: counted as a miss
    attr = attribute(ip, evs, ASSETS)
    ra = assess(dets, attr.asset, evs, attr.conflict)
    return {"scenario": sid, "ip": ip, "attr": attr, "ra": ra, "dets": dets, "segment_hits": 0,
            "benign": sid in BENIGN}


# ------------------------------------------------------------------------------------ memory
def fp_of(inc, level: Level) -> dict:
    a = inc["attr"].asset
    return memory.fingerprint(
        {"attack_type": "+".join(sorted({d.category for d in inc["dets"]})),
         "detections": [{"rule_id": d.rule_id, "mitre": d.mitre} for d in inc["dets"]],
         "entry": {"vector": "unknown"}, "tier": a.tier if a else None, "level": level.value},
        a.role if a else "unknown", a.segment if a else "unknown")


def learned_level(inc) -> Level:
    a = inc["attr"].asset
    return Level.COMPENSATING if (a and not a.isolatable) else Level.RESTRICT


def with_learning(inc, base: Decision, patterns: list[dict]):
    """Returns (decision, used_pattern_id or None, similarity)."""
    a = inc["attr"].asset
    if base.auto_execute or not patterns:
        return base, None, 0.0
    if a is not None and a.tier == 0:
        return base, None, 0.0                                     # Tier-0 always waits for people
    fp = fp_of(inc, base.level)
    p, score = memory.best_match(fp, patterns, approved_only=True)
    if p is None:
        return base, None, score
    lvl = learned_level(inc)
    d = Decision(lvl, True, base.deadline_s, 0,
                 [f"Learned response: matches engineer-approved pattern #{p['id']} at {score:.0%} "
                  f"(>= {memory.SIMILARITY_THRESHOLD:.0%}); strongest allowed action is {lvl.value}"],
                 hold_after_verify="Learned response: a person confirms recovery")
    return d, p["id"], score


# ------------------------------------------------------------------------------------ run
def run() -> dict:
    streams = base_streams()
    patterns: list[dict] = []
    rounds = []
    for rid, kind in ROUNDS:
        row = {"round": rid, "variant": kind, "malicious": 0,
               "miss_uniform": 0, "miss_acrs": 0, "miss_learning": 0,
               "learned_used": 0, "learned_on_harmless": 0, "invisible": 0,
               "offline_learning": 0, "critical_outage_learning": 0, "max_learned_level": None,
               "tier0_learned": 0, "misses_learning": []}
        new_patterns = []
        for sid, ip, evs in streams:
            inc = analyse(sid, ip, VARIANTS[kind](evs))
            benign = sid in BENIGN
            if inc is None:
                if not benign:
                    row["malicious"] += 1; row["invisible"] += 1
                    row["miss_uniform"] += 1; row["miss_acrs"] += 1; row["miss_learning"] += 1
                    row["misses_learning"].append(f"{sid}@{ip} (invisible)")
                continue
            du = uniform_decide(inc["attr"], inc["ra"], inc["dets"])
            da = acrs_decide(inc["attr"], inc["ra"], inc["dets"], 0, 0)
            dl, used, score = with_learning(inc, da, patterns)
            mu, ma, ml = measure(inc, du), measure(inc, da), measure(inc, dl)
            if benign:
                if used is not None:
                    row["learned_on_harmless"] += 1
                continue
            row["malicious"] += 1
            row["miss_uniform"] += not mu["c2_cut"]
            row["miss_acrs"] += not ma["c2_cut"]
            row["miss_learning"] += not ml["c2_cut"]
            row["offline_learning"] += ml["offline"]
            row["critical_outage_learning"] += ml["critical_outage"]
            if used is not None:
                row["learned_used"] += 1
                a = inc["attr"].asset
                row["tier0_learned"] += int(bool(a and a.tier == 0))
                row["max_learned_level"] = dl.level.value if row["max_learned_level"] in (None, "COMPENSATING") else row["max_learned_level"]
            if not ml["c2_cut"]:
                row["misses_learning"].append(f"{sid}@{ip}")
                # the engineer handles it by hand; the response is saved as an approved pattern
                new_patterns.append({"id": len(patterns) + len(new_patterns) + 1, "status": "APPROVED",
                                     "fingerprint": fp_of(inc, da.level), "level": learned_level(inc).value,
                                     "source": f"{rid}:{sid}"})
        patterns.extend(new_patterns)
        row["patterns_after_round"] = len(patterns)
        rounds.append(row)
    return {"note": "Simulated learning experiment. Deterministic: re-running gives the same numbers.",
            "similarity_threshold": memory.SIMILARITY_THRESHOLD, "rounds": rounds,
            "patterns": [{k: p[k] for k in ("id", "level", "source")} for p in patterns]}


def main() -> None:
    res = run()
    OUT.mkdir(exist_ok=True)
    (OUT / "learning.json").write_text(json.dumps(res, indent=2, ensure_ascii=False))
    print(f"{'round':6}{'variant':11}{'mal':>5}{'uniform':>9}{'acrs':>6}{'learn':>7}{'used':>6}{'harmless':>9}{'patterns':>9}")
    for r in res["rounds"]:
        print(f"{r['round']:6}{r['variant']:11}{r['malicious']:>5}{r['miss_uniform']:>9}{r['miss_acrs']:>6}"
              f"{r['miss_learning']:>7}{r['learned_used']:>6}{r['learned_on_harmless']:>9}{r['patterns_after_round']:>9}")
        print("      still missed:", ", ".join(r["misses_learning"]) or "-")


if __name__ == "__main__":
    main()
