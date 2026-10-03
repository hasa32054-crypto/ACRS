"""Phase 2: the network of systems that Q-ACRS protects, and the attack scenarios it is tested on.

    cd ~/ACRS/backend && python -m qacrs.network

A network is a list of machines and services:
  * Service      - something people use (appointments website, nurse app, records). It has a VALUE (how bad
                   it is if it goes down) and the machines that run it (replicas / twins). It goes DOWN only
                   if ALL its replicas are isolated.
  * depends_on   - a service also goes down if a machine it depends on is isolated (the app needs the database).
  * isolatable   - False for devices that must never be cut (an MRI in the middle of a scan).
  * critical     - core servers: isolating them needs two people to approve (the two-person rule).
  * links        - who can reach whom. If a hacked machine is NOT isolated and can reach a critical server,
                   the attacker may spread there (lateral movement).

Decision per machine (Phase 2/3):  x = 1 isolate it,  x = 0 restrict it only (cut the attacker's channel,
keep the machine working; this is ACRS's "smallest action that stops the attacker").

All weights here are DESIGN ASSUMPTIONS on a 1-10 scale, not measured data. Phase 5 changes them by +-50% to
check the decisions do not depend on the exact numbers (sensitivity study).
"""
from __future__ import annotations

import json
import random
from dataclasses import asdict, dataclass, field
from pathlib import Path

OUT = Path(__file__).parent / "results"


@dataclass
class Machine:
    name: str
    role: str
    isolatable: bool = True
    critical: bool = False
    disruption: int = 1          # cost of isolating it, even if no service goes down (people lose a tool)


@dataclass
class Service:
    name: str
    value: int                   # cost if this service goes down
    replicas: list[str]          # machines that run it; down only if ALL are isolated (max 2 -> stays quadratic)
    depends_on: list[str] = field(default_factory=list)   # machines it needs; isolating one takes it down


@dataclass
class Network:
    name: str
    machines: list[Machine]
    services: list[Service]
    links: list[tuple[str, str]]  # (from, to): from can open new connections to `to`

    def index(self) -> dict[str, int]:
        return {m.name: i for i, m in enumerate(self.machines)}

    def machine(self, name: str) -> Machine:
        return self.machines[self.index()[name]]


@dataclass
class Scenario:
    id: str
    network: str
    hacked: dict[str, int]       # machine -> leftover risk (1-10) if we only restrict it instead of isolating
    description: str


# ---------------------------------------------------------------- the base network (12 machines) -----------

def department(tag: str = "") -> tuple[list[Machine], list[Service], list[tuple[str, str]]]:
    """One department: website twins, app-server twins, a database, devices and staff PCs."""
    t = tag
    M = [
        Machine(f"web1{t}", "appointments website (twin 1)"),
        Machine(f"web2{t}", "appointments website (twin 2)"),
        Machine(f"app1{t}", "nurse app server (twin 1)"),
        Machine(f"app2{t}", "nurse app server (twin 2)"),
        Machine(f"db{t}", "patient records database", critical=True, disruption=3),
        Machine(f"mri{t}", "MRI console", isolatable=False, disruption=5),
        Machine(f"lab{t}", "lab analyzer", isolatable=False, disruption=4),
        Machine(f"pc_recep{t}", "reception PC"),
        Machine(f"pc_nurse{t}", "nurse station PC"),
        Machine(f"pc_admin{t}", "admin PC", disruption=2),
    ]
    S = [
        Service(f"appointments{t}", 20, [f"web1{t}", f"web2{t}"], depends_on=[f"db{t}"]),
        Service(f"nurse_app{t}", 25, [f"app1{t}", f"app2{t}"], depends_on=[f"db{t}"]),
    ]
    L = [(f"web1{t}", f"app1{t}"), (f"web2{t}", f"app2{t}"),
         (f"app1{t}", f"db{t}"), (f"app2{t}", f"db{t}"),
         (f"pc_nurse{t}", f"app1{t}"), (f"pc_admin{t}", f"db{t}"),
         (f"pc_recep{t}", f"web1{t}"), (f"lab{t}", f"db{t}")]
    return M, S, L


def build(departments: int = 1) -> Network:
    """departments=1 -> 12 machines; each extra department adds 10 (+ shared core stays 2)."""
    machines = [Machine("dc", "domain controller (logins)", critical=True, disruption=4),
                Machine("files", "file server", disruption=2)]
    services = [Service("logins", 30, ["dc"])]
    links: list[tuple[str, str]] = [("files", "dc")]
    for d in range(departments):
        tag = "" if departments == 1 else f"_{chr(ord('a') + d)}"
        M, S, L = department(tag)
        machines += M; services += S; links += L
        links += [(f"pc_admin{tag}", "dc"), (f"pc_nurse{tag}", "files"), (f"pc_recep{tag}", "files")]
    return Network(f"net{len(machines)}", machines, services, links)


# ---------------------------------------------------------------- scenarios ---------------------------------

HAND_MADE = [   # (hacked machine -> leftover risk, description); written by hand for the base network
    ({"web1": 6, "web2": 6}, "Website exploit hits both website twins"),
    ({"web1": 7}, "One website twin runs a web shell"),
    ({"app1": 6, "pc_nurse": 5}, "Phishing on the nurse PC, attacker reaches app server 1"),
    ({"db": 8}, "Database sends records out (exfiltration)"),
    ({"mri": 7}, "MRI console beacons to an attacker (cannot be isolated)"),
    ({"pc_admin": 8, "dc": 7}, "Admin PC stolen credentials used on the domain controller"),
    ({"pc_recep": 4, "pc_nurse": 4, "pc_admin": 4}, "Ransomware spreading across staff PCs"),
    ({"files": 6, "pc_recep": 5}, "Infected file share and the PC that opened it"),
    ({"lab": 5, "db": 6}, "Lab analyzer used as a jump box to the database"),
    ({"web2": 5, "app2": 5, "db": 5}, "Full chain: website -> app -> database on side 2"),
]


def random_scenarios(net: Network, n: int, seed: int) -> list[Scenario]:
    rng = random.Random(seed)
    names = [m.name for m in net.machines]
    out = []
    for k in range(n):
        size = rng.choice([1, 2, 2, 3, 3, 4])
        hacked = {m: rng.randint(3, 9) for m in rng.sample(names, size)}
        out.append(Scenario(f"{net.name}_r{k + 1:02d}", net.name, hacked, f"random: {size} hacked machine(s)"))
    return out


def scenarios(net: Network, n_random: int = 15, seed: int = 2027) -> list[Scenario]:
    hand = [Scenario(f"{net.name}_h{k + 1:02d}", net.name, h, d)
            for k, (h, d) in enumerate(HAND_MADE) if all(m in net.index() for m in h)]
    return hand + random_scenarios(net, n_random, seed)


def check(net: Network) -> None:
    idx = net.index()
    for s in net.services:
        assert 1 <= len(s.replicas) <= 2, f"{s.name}: 1-2 replicas keep the model quadratic"
        for m in s.replicas + s.depends_on:
            assert m in idx, f"{s.name}: unknown machine {m}"
    for a, b in net.links:
        assert a in idx and b in idx, f"bad link {a}->{b}"


# ---------------------------------------------------------------- main --------------------------------------

def main() -> None:
    nets = [build(1), build(2)]
    all_sc = []
    for net in nets:
        check(net)
        sc = scenarios(net)
        all_sc += sc
        print(f"\n=== {net.name}: {len(net.machines)} machines, {len(net.services)} services, "
              f"{len(net.links)} links, {len(sc)} scenarios ===")
        if net is nets[0]:
            print(f"{'machine':12}{'role':34}{'isolate?':10}{'two-person':12}")
            for m in net.machines:
                print(f"{m.name:12}{m.role:34}{'yes' if m.isolatable else 'NEVER':10}{'yes' if m.critical else '':12}")
            print("\nservices:")
            for s in net.services:
                dep = f"  needs {', '.join(s.depends_on)}" if s.depends_on else ""
                print(f"  {s.name:14} value {s.value:>3}  runs on {' + '.join(s.replicas)}{dep}")
        print(f"\npossible decisions for the whole network: 2^{len(net.machines)} = {2 ** len(net.machines):,}")
        for s in sc[:12] if net is nets[0] else sc[:3]:
            hk = ", ".join(f"{m}({r})" for m, r in s.hacked.items())
            print(f"  {s.id:12} {hk:40} {s.description}")
        if net is not nets[0]:
            print(f"  ... ({len(sc)} in total)")

    OUT.mkdir(exist_ok=True)
    (OUT / "networks.json").write_text(json.dumps({
        "note": "Weights are design assumptions (1-10 scale), tested by sensitivity analysis in Phase 5.",
        "networks": [asdict(n) for n in nets], "scenarios": [asdict(s) for s in all_sc]}, indent=1))
    print(f"\nSaved: qacrs/results/networks.json  ({len(all_sc)} scenarios)")


if __name__ == "__main__":
    main()
