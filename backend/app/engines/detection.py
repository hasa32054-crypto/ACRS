"""Detection Engine: hybrid rule-based + anomaly (UEBA) + threat-intel matching.

Each rule receives the events of ONE asset (already attributed) and returns
zero or more Detections mapped to MITRE ATT&CK techniques.
"""
from __future__ import annotations

import ipaddress
import math
import statistics
from collections import Counter, defaultdict
from datetime import timedelta
from typing import Callable, Iterable

from .policy import LATERAL_PORTS, LOLBINS, SUSPICIOUS_PORTS, THRESHOLDS as T
from .types import Detection, Event


def is_public(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved)


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _window(events: list[Event], seconds: int) -> list[Event]:
    if not events:
        return []
    latest = max(e.ts for e in events)
    start = latest - timedelta(seconds=seconds)
    return [e for e in events if e.ts >= start]


def _of(events: Iterable[Event], event_type: str) -> list[Event]:
    return [e for e in events if e.event_type == event_type]


# ---------------------------------------------------------------- rules

def rule_c2_port(events: list[Event]) -> list[Detection]:
    """Outbound to a public IP on a suspicious port (T1571 / T1071)."""
    conns = [e for e in _of(_window(events, T["c2_window_s"]), "net_conn")
             if is_public(e.data.get("dest_ip", "")) and e.data.get("dest_port") in SUSPICIOUS_PORTS]
    by_dest: dict[tuple, list[Event]] = defaultdict(list)
    for e in conns:
        by_dest[(e.data["dest_ip"], e.data["dest_port"])].append(e)
    out = []
    for (ip, port), evs in by_dest.items():
        if len(evs) >= T["c2_port_min_conns"]:
            sources = sorted({e.source for e in evs})
            for src in sources:
                out.append(Detection(
                    rule_id="ACRS-NET-001", title=f"Outbound C2-like traffic to {ip}:{port}",
                    mitre=["T1571", "T1071"], source=src, category="network",
                    strength=min(1.0, 0.6 + 0.1 * len(evs)),
                    evidence={"dest_ip": ip, "dest_port": port, "count": len(evs)},
                ))
    return out


def rule_beaconing(events: list[Event]) -> list[Detection]:
    """Regular-interval callbacks (T1071.001). CV of inter-arrival < threshold."""
    conns = [e for e in _of(events, "net_conn") if is_public(e.data.get("dest_ip", ""))]
    # Grouped per sensor: mixing firewall/EDR/NDR copies of the same flow would distort the intervals.
    by_dest: dict[tuple[str, str], list[Event]] = defaultdict(list)
    for e in conns:
        by_dest[(e.source, e.data["dest_ip"])].append(e)
    out = []
    for (sensor, ip), evs in by_dest.items():
        if len(evs) < T["beacon_min_conns"]:
            continue
        times = sorted(e.ts for e in evs)
        deltas = [(b - a).total_seconds() for a, b in zip(times, times[1:])]
        mean = statistics.fmean(deltas)
        if mean <= 0:
            continue
        cv = statistics.pstdev(deltas) / mean
        if cv < T["beacon_max_cv"]:
            out.append(Detection(
                rule_id="ACRS-NET-002", title=f"Beaconing to {ip} every ~{mean:.0f}s",
                mitre=["T1071.001"], source=sensor, category="network", strength=0.85,
                evidence={"dest_ip": ip, "count": len(evs), "interval_s": round(mean, 1), "cv": round(cv, 3)},
            ))
    return out


def rule_lolbin_network(events: list[Event]) -> list[Detection]:
    """LOLBin / encoded PowerShell that talks to the network within 60s (T1059.001)."""
    procs = [e for e in _of(events, "process")
             if e.data.get("process", "").lower() in LOLBINS
             and ("-enc" in e.data.get("cmdline", "").lower() or e.data.get("network"))]
    out = []
    for p in procs:
        name = p.data["process"].lower()
        related = [c for c in _of(events, "net_conn")
                   if c.data.get("process", "").lower() == name
                   and 0 <= (c.ts - p.ts).total_seconds() <= T["lolbin_net_window_s"]
                   and is_public(c.data.get("dest_ip", ""))]
        if related or p.data.get("network"):
            out.append(Detection(
                rule_id="ACRS-EDR-001", title=f"{name} spawned with network activity",
                mitre=["T1059.001"], source="edr", category="edr_behavior", strength=0.9,
                evidence={"process": name, "cmdline": p.data.get("cmdline", "")[:200],
                          "parent": p.data.get("parent"), "net_conns": len(related)},
            ))
            break
    return out


def rule_lsass_access(events: list[Event]) -> list[Detection]:
    allow = {"msmpeng.exe", "csfalconservice.exe", "sentinelagent.exe", "wininit.exe"}
    hits = [e for e in _of(events, "lsass_access") if e.data.get("process", "").lower() not in allow]
    if not hits:
        return []
    return [Detection(
        rule_id="ACRS-EDR-002", title="Unauthorized LSASS memory access",
        mitre=["T1003.001"], source="edr", category="edr_behavior", strength=0.95,
        evidence={"process": hits[0].data.get("process"), "count": len(hits)},
    )]


def rule_lateral_fanout(events: list[Event]) -> list[Detection]:
    conns = [e for e in _of(_window(events, T["lateral_window_s"]), "net_conn")
             if not is_public(e.data.get("dest_ip", "0.0.0.0"))
             and e.data.get("dest_port") in LATERAL_PORTS]
    hosts = {e.data["dest_ip"] for e in conns}
    if len(hosts) < T["lateral_min_hosts"]:
        return []
    return [Detection(
        rule_id="ACRS-NET-003", title=f"Lateral fan-out to {len(hosts)} internal hosts",
        mitre=["T1021"], source=conns[0].source, category="network", strength=0.9,
        evidence={"distinct_hosts": len(hosts), "ports": sorted({e.data['dest_port'] for e in conns})},
    )]


def rule_dns_tunnel(events: list[Event]) -> list[Detection]:
    queries = _of(_window(events, 3600), "dns_query")
    by_parent: dict[str, list[str]] = defaultdict(list)
    for q in queries:
        name = q.data.get("query", "")
        labels = name.split(".")
        parent = ".".join(labels[-2:]) if len(labels) >= 2 else name
        by_parent[parent].append(name)
    out = []
    for parent, names in by_parent.items():
        suspicious = [n for n in names
                      if len(n) > T["dns_min_len"] and shannon_entropy(n.split(".")[0]) > T["dns_entropy"]]
        if len(suspicious) >= T["dns_min_queries"]:
            out.append(Detection(
                rule_id="ACRS-DNS-001", title=f"DNS tunneling via {parent}",
                mitre=["T1071.004"], source="dns", category="network", strength=0.85,
                evidence={"domain": parent, "queries": len(suspicious)},
            ))
    return out


def rule_exfiltration(events: list[Event]) -> list[Detection]:
    conns = [e for e in _of(events, "net_conn") if is_public(e.data.get("dest_ip", ""))]
    by_dest: dict[str, int] = defaultdict(int)
    for e in conns:
        by_dest[e.data["dest_ip"]] += int(e.data.get("bytes_out", 0))
    out = []
    for ip, total in by_dest.items():
        if total >= T["exfil_bytes"]:
            out.append(Detection(
                rule_id="ACRS-NET-004", title=f"Large outbound transfer to {ip}",
                mitre=["T1567", "T1048"], source="ndr", category="network", strength=0.8,
                evidence={"dest_ip": ip, "bytes_out": total},
            ))
    return out


def rule_ransomware(events: list[Event]) -> list[Detection]:
    fa = _of(_window(events, 60), "file_activity")
    renames = sum(int(e.data.get("renames", 0)) for e in fa)
    shadow = [e for e in _of(events, "process")
              if "delete shadows" in e.data.get("cmdline", "").lower()
              or "shadowcopy delete" in e.data.get("cmdline", "").lower()]
    if renames < T["ransom_renames_per_min"] and not shadow:
        return []
    return [Detection(
        rule_id="ACRS-EDR-003", title="Ransomware behavior (mass rename / shadow copy deletion)",
        mitre=["T1486", "T1490"], source="edr", category="edr_behavior", strength=1.0,
        fast_path=True, evidence={"renames_per_min": renames, "shadow_delete": bool(shadow)},
    )]


def rule_impossible_travel(events: list[Event]) -> list[Detection]:
    signins = sorted(_of(events, "signin"), key=lambda e: e.ts)
    by_user: dict[str, list[Event]] = defaultdict(list)
    for s in signins:
        by_user[s.data.get("user", "")].append(s)
    out = []
    for user, ss in by_user.items():
        for a, b in zip(ss, ss[1:]):
            if (a.data.get("country") != b.data.get("country")
                    and a.data.get("device_id") != b.data.get("device_id")
                    and (b.ts - a.ts).total_seconds() < T["impossible_travel_s"]):
                out.append(Detection(
                    rule_id="ACRS-IDN-001", title=f"Impossible travel for {user}",
                    mitre=["T1078", "T1550"], source="identity", category="identity", strength=0.8,
                    evidence={"user": user, "from": a.data.get("country"), "to": b.data.get("country")},
                ))
                break
    return out


def rule_cloud_persistence(events: list[Event]) -> list[Detection]:
    risky = {"CreateAccessKey", "AttachRolePolicy", "PutUserPolicy", "CreateLoginProfile"}
    hits = [e for e in _of(events, "cloud_api")
            if e.data.get("api") in risky and not e.data.get("in_change_window")]
    if not hits:
        return []
    return [Detection(
        rule_id="ACRS-CLD-001", title=f"IAM persistence API: {hits[0].data['api']}",
        mitre=["T1098"], source="cloud", category="cloud", strength=0.85,
        evidence={"api": hits[0].data["api"], "principal": hits[0].data.get("principal")},
    )]


def rule_threat_intel(events: list[Event]) -> list[Detection]:
    hits = [e for e in _of(events, "ti_match") if int(e.data.get("confidence", 0)) >= T["ti_min_confidence"]]
    if not hits:
        return []
    best = max(hits, key=lambda e: int(e.data.get("confidence", 0)))
    return [Detection(
        rule_id="ACRS-TI-001", title=f"Threat-intel match: {best.data.get('indicator')}",
        mitre=best.data.get("mitre", []), source="threat_intel", category="threat_intel",
        strength=int(best.data["confidence"]) / 100,
        evidence={"indicator": best.data.get("indicator"), "feed": best.data.get("feed"),
                  "confidence": int(best.data["confidence"])},
    )]


def rule_ueba(events: list[Event]) -> list[Detection]:
    hits = [e for e in _of(events, "ueba_anomaly") if float(e.data.get("sigma", 0)) >= T["ueba_sigma"]]
    if not hits:
        return []
    best = max(hits, key=lambda e: float(e.data["sigma"]))
    return [Detection(
        rule_id="ACRS-UEBA-001", title=f"Behavioral anomaly: {best.data.get('metric')}",
        mitre=[], source="ueba", category="ueba", strength=min(1.0, float(best.data["sigma"]) / 6),
        evidence={"metric": best.data.get("metric"), "sigma": float(best.data["sigma"])},
    )]


RULES: list[Callable[[list[Event]], list[Detection]]] = [
    rule_c2_port, rule_beaconing, rule_lolbin_network, rule_lsass_access, rule_lateral_fanout,
    rule_dns_tunnel, rule_exfiltration, rule_ransomware, rule_impossible_travel,
    rule_cloud_persistence, rule_threat_intel, rule_ueba,
]


def detect(events: list[Event]) -> list[Detection]:
    detections: list[Detection] = []
    for rule in RULES:
        detections.extend(rule(events))
    return detections
