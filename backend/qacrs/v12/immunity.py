"""D13: immunity after an incident.

When an incident is closed, the system keeps an *attack-path fingerprint*: the ordered roles of the hosts the attacker
went through, the techniques attributed to each hop, and the links crossed. It installs two things, neither of which
touches a weight or the threshold:

  1. permanent SHIELDS on the links of the path (the v9 SHIELD mechanism: the lateral/admin protocol on that link is
     blocked, the business protocol stays open) -> for the model, a shielded link cannot carry lateral movement, so
     it is removed from the links the engine reasons about;
  2. a FIRST-HOP rule: an alert on a host of the fingerprint's entry role whose outgoing links match the fingerprint's
     first hop is isolated by the safety floor at once, whatever its risk.

A fingerprint is deliberately about ROLES and SHAPE, not hostnames: the same attack on a different workstation of the
same kind must match (the "similar" test), and an attack that enters elsewhere must NOT (the "dissimilar" test).
"""
from __future__ import annotations

import copy
import json
from dataclasses import dataclass, field

from qacrs.network import Network, Scenario


def role_key(net: Network, name: str) -> str:
    """Role class of a host: its name prefix (pc_, web_, srv_, dev_, dc, files) — hostnames are not used."""
    for p in ("pc_", "web_", "srv_", "dev_", "dc", "files"):
        if name.startswith(p):
            return p.rstrip("_")
    return name.split("_")[0]


@dataclass
class Fingerprint:
    incident: str
    roles: list[str]                      # ordered role classes along the path
    techniques: list[str]                 # technique chain as documented (may be empty)
    links: list[tuple[str, str]]          # concrete links crossed (shielded permanently)
    first_hop: tuple[str, str]            # (entry role, next role)

    def as_dict(self) -> dict:
        return {"incident": self.incident, "roles": self.roles, "techniques": self.techniques,
                "links": [list(l) for l in self.links], "first_hop": list(self.first_hop)}


@dataclass
class Immunity:
    fingerprints: list[Fingerprint] = field(default_factory=list)
    shields: set[tuple[str, str]] = field(default_factory=set)

    # ---------------------------------------------------------------- learn
    def learn(self, net: Network, path: list[str], techniques: list[str], incident: str) -> Fingerprint:
        roles = [role_key(net, h) for h in path]
        links = [(a, b) for a, b in zip(path, path[1:]) if (a, b) in net.links]
        fp = Fingerprint(incident, roles, techniques, links, (roles[0], roles[1]) if len(roles) > 1 else (roles[0], ""))
        self.fingerprints.append(fp)
        self.shields |= set(links)
        return fp

    # ---------------------------------------------------------------- apply
    def network(self, net: Network) -> Network:
        """A copy of the network in which shielded links cannot carry lateral movement."""
        if not self.shields:
            return net
        n = copy.deepcopy(net)
        n.links = [l for l in net.links if tuple(l) not in self.shields]
        return n

    v13: bool = False                      # PREREGISTRATION_v13.md: skip first-hop isolation when it costs a live service

    def first_hop_actions(self, net: Network, sc: Scenario) -> dict[str, str]:
        """Hosts to isolate at once because the alert matches a known first hop (role + link shape).

        v13 (D13-v13): a matched host is isolated only if isolating it takes no service down that is currently up;
        otherwise immunity leaves it to the ordinary floor/solver/gate (its path links are shielded anyway)."""
        out = {}
        succ: dict[str, set[str]] = {}
        for a, b in net.links:
            succ.setdefault(a, set()).add(b)
        hacked = set(sc.hacked)
        for h in sc.hacked:
            r = role_key(net, h)
            next_roles = {role_key(net, b) for b in succ.get(h, set())}
            for fp in self.fingerprints:
                if fp.first_hop[0] == r and (not fp.first_hop[1] or fp.first_hop[1] in next_roles):
                    if self.v13 and self._isolation_costs_live_service(net, h, hacked):
                        break                                   # shields only; no isolation by immunity
                    out[h] = f"matches first hop of '{fp.incident}' ({r} -> {fp.first_hop[1]}) -> isolate at once"
                    break
        return out

    @staticmethod
    def _isolation_costs_live_service(net: Network, h: str, hacked: set[str]) -> bool:
        from qacrs import qubo_v7 as V7
        before = set(V7.services_down_v7(net, set(), set(), hacked))
        after = set(V7.services_down_v7(net, {h}, set(), hacked))
        return bool(after - before)

    def as_dict(self) -> dict:
        return {"fingerprints": [f.as_dict() for f in self.fingerprints], "shields": sorted(map(list, self.shields))}

    @classmethod
    def from_dict(cls, d: dict) -> "Immunity":
        im = cls()
        for f in d.get("fingerprints", []):
            im.fingerprints.append(Fingerprint(f["incident"], f["roles"], f["techniques"],
                                               [tuple(l) for l in f["links"]], tuple(f["first_hop"])))
        im.shields = {tuple(l) for l in d.get("shields", [])}
        return im

    def dumps(self) -> str:
        return json.dumps(self.as_dict(), sort_keys=True)
