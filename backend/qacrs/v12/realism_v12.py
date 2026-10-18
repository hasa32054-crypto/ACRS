"""D4: a generator that looks like the incident record, not like one hospital.

Sectors with their own roles and services; flat or two-tier networks of 20-60 machines; an explicit share of
never-isolatable devices in {0, 10, 30}%; attack chains that walk real links; 1-4 detection moments per chain whose
last moment is a detonation burst (every chain host at risk 9). Seed 12012. Generated once, hashed, never regenerated.

    cd backend && python -m qacrs.v12.realism_v12     -> qacrs/results/v12/realism_v12.json
"""
from __future__ import annotations

import hashlib
import json
import random
from pathlib import Path

from qacrs.network import Machine, Network, Scenario, Service, check
from qacrs.v12 import risk_map as RM

SEED = 12012
N_CHAINS = 400                     # ~1,000 detection moments
OUT = Path(__file__).parent.parent / "results" / "v12"

SECTORS = {
    "health": {
        "servers": [("srv_ehr", "electronic health record", "core", True), ("srv_lis", "laboratory system", "core", True),
                    ("srv_pacs", "imaging archive", "core", True), ("srv_mail", "e-mail", "support", False),
                    ("srv_app1", "clinical app server", "core", False), ("srv_app2", "clinical app server (twin)", "core", False),
                    ("srv_backup", "backup server", "support", False)],
        "devices": [("dev_mri", "MRI console"), ("dev_infusion", "infusion pump gateway"), ("dev_monitor", "patient monitor gateway"),
                    ("dev_lab", "lab analyser")],
        "services": [("emergency_care", "life_critical", ["srv_ehr"], []), ("lab_results", "national_or_10k", ["srv_lis"], ["dc"]),
                     ("imaging", "core", ["srv_pacs"], ["dc"]), ("clinical_app", "core", ["srv_app1", "srv_app2"], ["srv_ehr"]),
                     ("email", "support", ["srv_mail"], [])],
    },
    "finance": {
        "servers": [("srv_core_banking", "core banking database", "core", True), ("srv_swift", "payment messaging", "core", True),
                    ("srv_web_banking", "online banking app", "core", False), ("srv_web_banking2", "online banking app (twin)", "core", False),
                    ("srv_mail", "e-mail", "support", False), ("srv_backup", "backup server", "support", False)],
        "devices": [("dev_atm_gw", "ATM gateway"), ("dev_hsm", "hardware security module")],
        "services": [("payments", "national_or_10k", ["srv_swift"], ["srv_core_banking"]),
                     ("online_banking", "national_or_10k", ["srv_web_banking", "srv_web_banking2"], ["srv_core_banking"]),
                     ("branch_ops", "core", ["srv_core_banking"], ["dc"]), ("email", "support", ["srv_mail"], [])],
    },
    "industry": {
        "servers": [("srv_erp", "ERP", "core", True), ("srv_mes", "manufacturing execution", "core", True),
                    ("srv_hist", "process historian", "core", False), ("srv_mail", "e-mail", "support", False),
                    ("srv_backup", "backup server", "support", False)],
        "devices": [("dev_plc_gw", "PLC gateway"), ("dev_hmi", "HMI station"), ("dev_sis", "safety instrumented system")],
        "services": [("production_line", "life_critical", ["srv_mes"], ["dc"]), ("orders_billing", "core", ["srv_erp"], ["dc"]),
                     ("plant_visibility", "support", ["srv_hist"], []), ("email", "support", ["srv_mail"], [])],
    },
}
TECH_STAGE = {"entry": ["T1566", "T1190", "T1133"], "foothold": ["T1071", "T1219"], "lateral": ["T1021", "T1047"],
              "creds": ["T1003", "T1558"], "impact": ["T1486"]}


def build_network(rng: random.Random, sector: str, n_pcs: int, never_share: float, flat: bool, tag: str) -> Network:
    spec = SECTORS[sector]
    M = [Machine("dc", "domain controller", critical=True, disruption=RM.ROLE_DISRUPTION["core"]),
         Machine("files", "file server", disruption=RM.ROLE_DISRUPTION["support"])]
    for name, role, cls, crit in spec["servers"]:
        M.append(Machine(name, role, critical=crit, disruption=RM.ROLE_DISRUPTION[cls]))
    devs = list(spec["devices"])
    n_never = round(len(devs) * never_share)
    for i, (name, role) in enumerate(devs):
        M.append(Machine(name, role, isolatable=i >= n_never, disruption=RM.ROLE_DISRUPTION["life_critical"] if i < n_never else 2))
    entries = [Machine("web_vpn", "VPN / remote-access appliance", disruption=2),
               Machine("web_portal", "public web portal", disruption=2)]
    M += entries
    for i in range(n_pcs):
        M.append(Machine(f"pc_{i}", "staff workstation", disruption=1))
    S = [Service(n, RM.IMPACT_VALUE[cls], reps, deps) for n, cls, reps, deps in spec["services"]]
    S.append(Service("logins", RM.IMPACT_VALUE["core"], ["dc"]))
    L: list[tuple[str, str]] = [("files", "dc"), ("web_vpn", "dc"), ("web_portal", spec["servers"][2][0])]
    servers = [s[0] for s in spec["servers"]]
    for i in range(n_pcs):
        L += [(f"pc_{i}", "dc"), (f"pc_{i}", "files")]
        if flat:                                             # flat: workstations reach servers and devices directly
            for s in rng.sample(servers, k=min(3, len(servers))):
                L.append((f"pc_{i}", s))
            if devs and rng.random() < 0.3:
                L.append((f"pc_{i}", rng.choice(devs)[0]))
        elif rng.random() < 0.2:
            L.append((f"pc_{i}", rng.choice(servers)))
    for s in servers:                                        # dc and files reach every server (admin protocols)
        L += [("dc", s), ("files", s)]
    for d, _ in devs:
        L.append((rng.choice(servers), d))
    L.append(("web_vpn", rng.choice(servers)))
    net = Network(f"r12_{tag}", M, S, sorted(set(L)))
    check(net)
    return net


def chain(rng: random.Random, net: Network) -> list[str]:
    succ: dict[str, list[str]] = {}
    for a, b in net.links:
        succ.setdefault(a, []).append(b)
    start = rng.choice([m.name for m in net.machines if m.name.startswith(("web_", "pc_"))])
    path, cur = [start], start
    for _ in range(rng.randint(2, 6)):
        nxt = [n for n in succ.get(cur, []) if n not in path]
        if not nxt:
            break
        cur = rng.choice(nxt); path.append(cur)
    return path


def moments(rng: random.Random, net: Network, path: list[str], cid: str) -> list[Scenario]:
    k = rng.randint(1, 4)
    cuts = sorted(rng.sample(range(1, len(path) + 1), k=min(k, len(path))))
    out = []
    for j, c in enumerate(cuts):
        last = j == len(cuts) - 1
        hacked = {}
        for i, h in enumerate(path[:c]):
            if last and c == len(path):
                t = "T1486"
            elif i == 0:
                t = rng.choice(TECH_STAGE["entry"] if c == 1 else TECH_STAGE["foothold"])
            elif h == "dc":
                t = rng.choice(TECH_STAGE["creds"])
            else:
                t = rng.choice(TECH_STAGE["lateral"] + TECH_STAGE["foothold"])
            hacked[h] = RM.risk_of([t])
        out.append(Scenario(f"{cid}/m{j + 1}", net.name, hacked, f"chain {'->'.join(path)} at hop {c}"))
    return out


def generate(seed: int = SEED, n_chains: int = N_CHAINS) -> tuple[list[Network], list[tuple[str, list[Scenario]]]]:
    rng = random.Random(seed)
    nets, scen = [], []
    for c in range(n_chains):
        sector = rng.choice(list(SECTORS))
        net = build_network(rng, sector, rng.randint(8, 45), rng.choice([0.0, 0.1, 0.3]), rng.random() < 0.5, f"{c:03d}")
        nets.append(net)
        scen.append((net.name, moments(rng, net, chain(rng, net), f"c{c:03d}")))
    return nets, scen


def corpus_hash(nets, scen) -> str:
    blob = json.dumps([[n.name, [m.__dict__ for m in n.machines], [s.__dict__ for s in n.services], n.links] for n in nets]
                      + [[k, [s.__dict__ for s in v]] for k, v in scen], sort_keys=True).encode()
    return hashlib.sha256(blob).hexdigest()


if __name__ == "__main__":
    nets, scen = generate()
    OUT.mkdir(parents=True, exist_ok=True)
    n_m = sum(len(v) for _, v in scen)
    meta = {"seed": SEED, "n_chains": len(scen), "n_moments": n_m, "hash": corpus_hash(nets, scen),
            "sizes": [len(n.machines) for n in nets]}
    (OUT / "realism_v12.json").write_text(json.dumps(meta, indent=1))
    print(meta["n_chains"], meta["n_moments"], meta["hash"], min(meta["sizes"]), max(meta["sizes"]))
