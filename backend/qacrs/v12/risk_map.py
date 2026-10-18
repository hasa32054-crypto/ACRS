"""D2: the published mapping tables. Shipped with the system; their hash goes into every v12 certificate.

An alert does not arrive as a number. It arrives as an ATT&CK technique (from EDR/NDR/SIEM) on a host with a role, in an
organisation whose services have a documented impact. These tables turn that into the engine's 1-10 scale, so the
number's provenance is part of the system and not of the person running the experiment.
"""
from __future__ import annotations

import hashlib
import json

# ATT&CK technique -> leftover risk if the host is only restricted (1-10). Highest applicable wins.
TECHNIQUE_RISK: dict[str, int] = {
    # destructive payload executed on this host: nothing left to keep running
    "T1486": 9, "T1485": 9, "T1561": 9, "T1490": 9,
    # domain-admin credential theft / kerberoasting: attacker owns the domain
    "T1003": 8, "T1558": 8, "T1003.001": 8, "T1558.003": 8,
    # active command-and-control on the host
    "T1071": 7, "T1219": 7, "T1105": 7, "T1572": 7,
    # lateral-movement tool present
    "T1021": 6, "T1021.001": 6, "T1021.002": 6, "T1047": 6, "T1570": 6, "T1210": 6,
    # initial access only, no confirmed post-exploitation
    "T1190": 5, "T1566": 5, "T1566.001": 5, "T1566.002": 5, "T1133": 5, "T1078": 5, "T1189": 5, "T1204": 5,
    "T1195": 5, "T1195.002": 5,
}
DESTRUCTIVE = {t for t, r in TECHNIQUE_RISK.items() if r >= 9}

# documented impact -> service value
IMPACT_VALUE: dict[str, int] = {"life_critical": 30, "national_or_10k": 25, "core": 20, "support": 10}

# role class -> disruption cost of isolating the machine even if no service goes down
ROLE_DISRUPTION: dict[str, int] = {"life_critical": 5, "core": 3, "support": 2, "workstation": 1}

RISK_FLOOR_ISOLATE = 9          # D1(a): at this risk a hacked isolatable non-critical host is isolated outright
RISK_FLOOR_SEGMENT = 7          # D1(b): at this risk a hacked critical server is segmented outright (= threshold)


def risk_of(techniques: list[str]) -> int:
    """Risk of a host from the techniques attributed to it; unknown techniques do not raise the risk."""
    rs = [TECHNIQUE_RISK[t] for t in techniques if t in TECHNIQUE_RISK]
    rs += [TECHNIQUE_RISK[t.split(".")[0]] for t in techniques if t not in TECHNIQUE_RISK and t.split(".")[0] in TECHNIQUE_RISK]
    return max(rs) if rs else 5


def table_hash() -> str:
    blob = json.dumps({"technique_risk": TECHNIQUE_RISK, "impact_value": IMPACT_VALUE,
                       "role_disruption": ROLE_DISRUPTION, "floor": [RISK_FLOOR_ISOLATE, RISK_FLOOR_SEGMENT]},
                      sort_keys=True).encode()
    return hashlib.sha256(blob).hexdigest()[:16]
