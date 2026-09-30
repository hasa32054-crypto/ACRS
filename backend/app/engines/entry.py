"""Attack classification, entry-point identification, and entry-point hardening."""
from __future__ import annotations

from .detection import is_public
from .threat_intel import lookup
from .types import Detection, Event

ATTACK_TYPES = [  # (rule prefix or id, attack type) in priority order
    ("ACRS-EDR-003", "Ransomware"),
    ("ACRS-EDR-002", "Credential Dumping"),
    ("ACRS-CLD-001", "Cloud Persistence"),
    ("ACRS-NET-003", "Lateral Movement"),
    ("ACRS-NET-004", "Data Exfiltration"),
    ("ACRS-DNS-001", "DNS Tunneling"),
    ("ACRS-IDN-001", "Account Compromise"),
    ("ACRS-NET-001", "Command & Control"),
    ("ACRS-NET-002", "Command & Control"),
    ("ACRS-EDR-001", "Malicious Execution"),
]

ENTRY_RULES = [
    # (predicate over events, entry path, vector, hardening command params)
    (lambda e: e.event_type == "process" and str(e.data.get("parent", "")).lower() in {"w3wp.exe", "httpd", "nginx", "node", "java", "tomcat"},
     "Web application exploitation", "web", {"action": "virtual_patch_and_waf_rule"}),
    (lambda e: e.event_type == "process" and str(e.data.get("parent", "")).lower() in {"outlook.exe", "winword.exe", "excel.exe"},
     "Phishing attachment", "email", {"action": "block_sender_and_attachment_hash"}),
    (lambda e: e.event_type == "signin", "Compromised credentials", "identity", {"action": "enforce_mfa_and_reset"}),
    (lambda e: e.event_type == "cloud_api", "Cloud credential abuse", "cloud", {"action": "scope_down_role_and_rotate_keys"}),
    (lambda e: e.event_type == "net_conn" and e.data.get("dest_port") in {3389, 445} and not is_public(e.data.get("dest_ip", "")),
     "Lateral movement from a peer", "lateral", {"action": "close_smb_rdp_between_workstations"}),
]


def classify(detections: list[Detection]) -> str:
    ids = {d.rule_id for d in detections}
    for rid, name in ATTACK_TYPES:
        if rid in ids:
            return name
    return "Suspicious Activity"


def primary_external_ip(detections: list[Detection], events: list[Event]) -> str | None:
    for d in detections:
        ip = d.evidence.get("dest_ip") or d.evidence.get("indicator")
        if ip and is_public(str(ip)):
            return str(ip)
    for e in events:
        ip = e.data.get("dest_ip")
        if ip and is_public(ip):
            return ip
    return None


def identify_entry(events: list[Event], detections: list[Detection]) -> dict:
    ordered = sorted(events, key=lambda e: e.ts)
    for pred, path, vector, harden in ENTRY_RULES:
        hit = next((e for e in ordered if pred(e)), None)
        if hit:
            return {"path": path, "vector": vector, "first_seen": hit.ts.isoformat(), "harden": harden,
                    "evidence": {k: hit.data.get(k) for k in ("process", "parent", "user", "api") if hit.data.get(k)}}
    first = ordered[0] if ordered else None
    return {"path": "Unknown (under investigation)", "vector": "unknown",
            "first_seen": first.ts.isoformat() if first else None,
            "harden": {"action": "increase_monitoring"}, "evidence": {}}


def attack_source(events: list[Event], detections: list[Detection], confidence: int, entry_path: str) -> dict:
    ip = primary_external_ip(detections, events)
    seen = sorted(e.ts for e in events if e.data.get("dest_ip") == ip) if ip else []
    intel = lookup(ip)
    return {**intel, "first_seen": seen[0].isoformat() if seen else None,
            "last_seen": seen[-1].isoformat() if seen else None,
            "entry_path": entry_path, "confidence": confidence}
