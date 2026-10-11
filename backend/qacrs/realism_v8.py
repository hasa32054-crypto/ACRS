"""v8 E: hospital realism — Hospital-60 network (40), MITRE ATT&CK tags (41), patient-minutes (38 / S3),
ransomware spread (42), anticipatory containment (S2).

All weights, patient rates and the network layout are DESIGN ASSUMPTIONS (stated in PREREGISTRATION_v8.md and here).
"""
from __future__ import annotations

from qacrs import qubo_v7 as V7
from qacrs.network import Machine, Network, Scenario, Service, check

# ------------------------------------------------------------------ 40. Hospital-60 network ------------------------
def hospital60() -> Network:
    M = lambda n, role, iso=True, crit=False, d=1: Machine(n, role, iso, crit, d)
    machines = [
        M("dc1", "domain controller 1", crit=True, d=4), M("dc2", "domain controller 2", crit=True, d=4),
        M("files", "file server", d=2), M("backup", "backup server", d=2), M("email", "email server", d=2),
        M("vpn", "VPN gateway", d=2), M("print", "print server"), M("wifi", "wireless controller", d=2),
        M("ehr_app1", "EHR application (twin 1)"), M("ehr_app2", "EHR application (twin 2)"),
        M("ehr_db", "EHR database", crit=True, d=3),
        M("pacs1", "PACS server (twin 1)"), M("pacs2", "PACS server (twin 2)"), M("pacs_store", "PACS image store", crit=True, d=3),
        M("hl7_1", "HL7 interface engine (twin 1)"), M("hl7_2", "HL7 interface engine (twin 2)"),
        M("pharm", "pharmacy system", d=2), M("lis", "laboratory information system", d=2),
        M("er1", "ER tracking board (twin 1)"), M("er2", "ER tracking board (twin 2)"),
        M("web1", "patient portal (twin 1)"), M("web2", "patient portal (twin 2)"),
        M("lab_a1", "lab analyzer 1", iso=False, d=4), M("lab_a2", "lab analyzer 2", iso=False, d=4),
        M("lab_a3", "lab analyzer 3", iso=False, d=4),
        M("ct", "CT scanner console", iso=False, d=5), M("mri", "MRI console", iso=False, d=5),
        M("xray", "X-ray console", iso=False, d=5),
        M("pump_gw", "infusion pump gateway", iso=False, d=5), M("monitor_gw", "patient monitor gateway", iso=False, d=5),
        M("nursecall", "nurse call system", iso=False, d=4), M("badge", "badge access system", d=2),
        M("hvac", "building controller", d=2),
    ]
    pcs = [f"pc_nurse{i}" for i in range(1, 10)] + [f"pc_doc{i}" for i in range(1, 10)] + \
          [f"pc_admin{i}" for i in range(1, 5)] + [f"pc_recep{i}" for i in range(1, 6)]
    machines += [M(p, "staff workstation", d=2 if p.startswith("pc_admin") else 1) for p in pcs]
    services = [
        Service("logins", 30, ["dc1", "dc2"]),
        Service("ehr", 40, ["ehr_app1", "ehr_app2"], ["ehr_db"]),
        Service("imaging", 25, ["pacs1", "pacs2"], ["pacs_store"]),
        Service("hl7", 30, ["hl7_1", "hl7_2"], ["ehr_db"]),
        Service("er_board", 35, ["er1", "er2"], ["ehr_db"]),
        Service("portal", 15, ["web1", "web2"], ["ehr_db"]),
        Service("pharmacy", 20, ["pharm"], ["ehr_db"]),
        Service("lab_results", 20, ["lis"], ["ehr_db"]),
    ]
    L = [("ehr_app1", "ehr_db"), ("ehr_app2", "ehr_db"), ("hl7_1", "ehr_db"), ("hl7_2", "ehr_db"),
         ("er1", "ehr_db"), ("er2", "ehr_db"), ("web1", "ehr_app1"), ("web2", "ehr_app2"), ("pharm", "ehr_db"),
         ("lis", "hl7_1"), ("lis", "hl7_2"), ("lab_a1", "lis"), ("lab_a2", "lis"), ("lab_a3", "lis"),
         ("ct", "pacs1"), ("mri", "pacs2"), ("xray", "pacs1"), ("pacs1", "pacs_store"), ("pacs2", "pacs_store"),
         ("backup", "ehr_db"), ("backup", "pacs_store"), ("vpn", "dc1"), ("vpn", "files"), ("email", "dc1"),
         ("files", "dc1"), ("files", "dc2"), ("monitor_gw", "hl7_1"), ("pump_gw", "pharm"), ("wifi", "dc2"),
         ("badge", "dc2"), ("hvac", "files")]
    for p in pcs:
        if p.startswith(("pc_nurse", "pc_doc")):
            L += [(p, "ehr_app1" if int(p[-1]) % 2 else "ehr_app2"), (p, "files")]
        if p.startswith("pc_doc"):
            L += [(p, "pacs1" if int(p[-1]) % 2 else "pacs2")]
        if p.startswith("pc_admin"):
            L += [(p, "dc1"), (p, "ehr_db"), (p, "backup")]
        if p.startswith("pc_recep"):
            L += [(p, "web1" if int(p[-1]) % 2 else "web2"), (p, "email")]
    net = Network("hospital60", machines, services, L)
    check(net)
    return net


# ------------------------------------------------------------------ 41. MITRE ATT&CK tags ---------------------------
def mitre_tags(net: Network, sc: Scenario) -> dict[str, list[str]]:
    """Rule-based tags (role / position -> technique). IDs are MITRE ATT&CK Enterprise technique IDs."""
    crit = {m.name for m in net.machines if m.critical}
    tags = {}
    chain = sc.description.split(": ", 1)[1].split(" | ") if sc.description.startswith("attack chain") else []
    firsts = {c.split(" -> ")[0] for c in chain}
    for m in sc.hacked:
        t = ["T1071"]                                            # Application Layer Protocol (C2 channel)
        if m.startswith("web"):
            t.append("T1190")                                    # Exploit Public-Facing Application
        elif m.startswith("pc_"):
            t.append("T1566")                                    # Phishing
        if chain and m not in firsts:
            t.append("T1021")                                    # Remote Services (lateral movement)
        if m in crit and (m.startswith("dc")):
            t += ["T1003", "T1078"]                              # OS Credential Dumping, Valid Accounts
        if m in crit and not m.startswith("dc"):
            t += ["T1005", "T1041"]                              # Data from Local System, Exfiltration Over C2
        if m in ("files", "backup"):
            t.append("T1486")                                    # Data Encrypted for Impact
        tags[m] = sorted(set(t))
    return tags


# ------------------------------------------------------------------ 38 / S3. patient-minutes ------------------------
PATIENTS_PER_HOUR = {"logins": 120, "nurse_app": 60, "appointments": 30, "ehr": 120, "imaging": 20, "hl7": 60,
                     "er_board": 25, "portal": 30, "pharmacy": 40, "lab_results": 40}
OUTAGE_MIN = 60


def patient_minutes(services_down: list[str]) -> float:
    """patients arriving during the outage x mean wait (outage / 2). Assumption-driven, labelled as such."""
    tot = 0.0
    for s in services_down:
        base = s.split("_")[0] if s not in PATIENTS_PER_HOUR else s
        pph = PATIENTS_PER_HOUR.get(s, PATIENTS_PER_HOUR.get(base, 30))
        tot += pph * (OUTAGE_MIN / 60) * (OUTAGE_MIN / 2)
    return tot


# ------------------------------------------------------------------ 42. ransomware spread ---------------------------
def spread(net: Network, initial: set[str], policy, ticks: int = 10, decide_at: int = 2, risk: int = 8) -> dict:
    """1 hop per tick along links. At `decide_at`, policy(net, Scenario) -> (iso, seg) is applied to the infected set.
    Isolated: no spread in or out. Segmented: cannot be infected (inbound from infected blocked).
    Restricted machines keep spreading laterally (RESTRICT only cuts the attacker's C2 channel)."""
    infected = set(initial); iso, seg = set(), set()
    for t in range(1, ticks + 1):
        if t == decide_at and policy is not None:
            sc = Scenario("rw", net.name, {m: risk for m in sorted(infected)}, "ransomware")
            iso, seg = policy(net, sc)
            iso = {m for m in iso if not net.machine(m).critical}       # critical isolation waits for approval
        new = {b for a, b in net.links if a in infected and a not in iso and b not in iso and b not in seg}
        infected |= new
    down = V7.services_down_v7(net, iso, seg, infected)
    enc_down = [s.name for s in net.services
                if all(r in infected or r in iso for r in s.replicas) or any(d in infected or d in iso for d in s.depends_on)]
    return {"encrypted": len(infected), "isolated": len(iso), "services_unavailable": sorted(set(down) | set(enc_down))}


# ------------------------------------------------------------------ S2. anticipatory containment --------------------
def next_hop_blocked(net: Network, visible: Scenario, prev: str, hidden: str, iso, seg) -> bool:
    if hidden in iso or hidden in seg or prev in iso:
        return True
    return False
