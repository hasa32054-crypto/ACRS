"""D3: alert-consistency guard that tells a real detonation from an injected burst.

A real ransomware detonation lights up many hosts at risk 9 at once, but those hosts are CONNECTED: the payload reached
them over the network's links. An injected burst (phase 10 'naive' forger) picks targets at random, so they are
typically not connected. The v9 rule (>= 3 alerts all >= 9 => flag) could not tell the two apart (v11-pilot §3.3).

The 'no compromised path into a non-entry host' rule from the locked guard is kept unchanged (it is re-implemented
here only so that this module does not import private behaviour; the logic is identical).
"""
from __future__ import annotations

from qacrs import hassan as H
from qacrs.network import Network, Scenario

BURST_SIZE, BURST_RISK = H.GUARD_BURST_SIZE, H.GUARD_BURST_RISK   # 3, 9 — unchanged constants


def _components(nodes: set[str], links) -> int:
    adj = {n: set() for n in nodes}
    for a, b in links:
        if a in nodes and b in nodes:
            adj[a].add(b); adj[b].add(a)
    seen, comps = set(), 0
    for n in nodes:
        if n in seen:
            continue
        comps += 1; stack = [n]
        while stack:
            x = stack.pop()
            if x in seen:
                continue
            seen.add(x); stack.extend(adj[x] - seen)
    return comps


def flags_v12(net: Network, sc: Scenario) -> list[str]:
    entries = H.entry_points(net)
    preds: dict[str, set[str]] = {}
    for a, b in net.links:
        preds.setdefault(b, set()).add(a)
    hacked = set(sc.hacked)
    flags = [f"'{m}' reported hacked with no compromised path into it" for m in sorted(hacked)
             if m not in entries and not (preds.get(m, set()) & hacked)]
    burst = [h for h, r in sc.hacked.items() if r >= BURST_RISK]
    if len(burst) >= BURST_SIZE:
        # the burst hosts must be reachable from each other through HACKED hosts (any risk): a payload travels
        # over links from hosts it already owns; a random injection does not
        comps = _components(hacked, net.links)
        if comps > 1:
            flags.append(f"burst of {len(burst)} alerts at risk >= {BURST_RISK}; the {len(hacked)} alerted hosts "
                         f"form {comps} disconnected groups")
    return flags
