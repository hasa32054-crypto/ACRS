"""v14 enforcement gate: the ONE place that turns any engine decision into automatic actions.
Rules: docs/qacrs/PREREGISTRATION_v14.md (E2, "plan if a property fails").

Why it exists: E2 proved (two independent provers) that, with an untrusted solver output, the ACRS service adapter
passed proposed isolations through as automatic even when the engine said REJECTED or "two people needed", and the
firewall executor could isolate a machine nobody reported. The engine files are locked for the blind test, so the
fix sits here, after the engine, and every automatic path goes through it.

    g = enforce(net, scenario, decision)
    g["auto_isolate"], g["auto_segment"]   # what may run with no human
    g["held"]                              # proposed, but waits for people (with the reason)

Rules (each only ever REMOVES actions, so it can never make a decision less safe):
  1. engine status REJECTED, or the decision certificate does not verify  -> nothing automatic
  2. a never-isolate device is never isolated automatically
  3. a critical server is never isolated automatically (two-person rule)
  4. a machine that was not reported hacked is never isolated automatically
  5. only critical servers may be segmented
"""
from __future__ import annotations

from qacrs import hassan as H
from qacrs import hassan_v9 as V9
from qacrs import safety_checks as S
from qacrs.network import Network, Scenario


def certificate_ok(net: Network, sc: Scenario, d) -> bool:
    cert = getattr(d, "certificate", None) or {}
    try:
        if "held" in cert:                                  # v9 certificate (structural claims + optimality)
            return V9.verify_certificate_v9(net, sc, cert)
        return H.verify_certificate(net, sc, cert)          # v8 certificate (structural claims)
    except Exception:
        return False


def enforce(net: Network, sc: Scenario, d) -> dict:
    machines = {m.name: m for m in net.machines}
    reported = set(getattr(sc, "hacked", {}) or {})
    proposed_iso, proposed_seg = list(d.isolate), list(d.segment)
    held: list[dict] = []
    if d.status == S.REJECTED or not certificate_ok(net, sc, d):
        why = "engine rejected the decision" if d.status == S.REJECTED else "decision certificate did not verify"
        held = [{"target": m, "action": "ISOLATE", "reason": why} for m in proposed_iso] + \
               [{"target": m, "action": "SEGMENT", "reason": why} for m in proposed_seg]
        return {"auto_isolate": [], "auto_segment": [], "held": held, "blocked_all": True, "reason": why}
    auto_iso, auto_seg = [], []
    for m in proposed_iso:
        mm = machines.get(m)
        if mm is None:
            held.append({"target": m, "action": "ISOLATE", "reason": "unknown machine"})
        elif not mm.isolatable:
            held.append({"target": m, "action": "ISOLATE", "reason": "never-isolate device"})
        elif mm.critical:
            held.append({"target": m, "action": "ISOLATE", "reason": "critical server: two-person approval"})
        elif m not in reported:
            held.append({"target": m, "action": "ISOLATE", "reason": "not reported hacked"})
        else:
            auto_iso.append(m)
    for m in proposed_seg:
        mm = machines.get(m)
        if mm is not None and mm.critical:
            auto_seg.append(m)
        else:
            held.append({"target": m, "action": "SEGMENT", "reason": "segment only allowed on a critical server"})
    return {"auto_isolate": sorted(auto_iso), "auto_segment": sorted(auto_seg), "held": held,
            "blocked_all": False, "reason": None}


def execute(executor, net: Network, sc: Scenario, d):
    """Path XG: the firewall executor only ever receives what the gate allows (closes P3 on the executor path).
    Returns (gate result, executor result)."""
    g = enforce(net, sc, d)
    return g, executor.execute(sc, g["auto_isolate"])
