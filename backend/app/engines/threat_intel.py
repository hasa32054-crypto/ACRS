"""Simulated Threat Intelligence (no external calls).

Deterministic enrichment for demo IPs; a real deployment swaps this for MISP/OpenCTI.
Country/city are approximate by nature and labelled as such.
"""
from __future__ import annotations

import hashlib
import ipaddress

KNOWN = {
    "185.220.101.47": ("DE", "Frankfurt (approx.)", "AS208294", "Hosting / Tor exit", 5, "C2 infrastructure"),
    "45.9.148.3": ("NL", "Amsterdam (approx.)", "AS49981", "Bulletproof hosting", 5, "Exfiltration staging"),
    "91.215.85.14": ("RU", "Moscow (approx.)", "AS48693", "VPS provider", 5, "Loader infrastructure"),
    "193.42.33.7": ("MD", "Chisinau (approx.)", "AS200019", "VPS provider", 4, "Botnet C2"),
    "185.100.87.202": ("RO", "Bucharest (approx.)", "AS200651", "Hosting", 4, "Scanner / C2"),
    "46.8.19.33": ("RU", "Saint Petersburg (approx.)", "AS44546", "Hosting", 3, "Suspicious"),
    "52.94.12.80": ("US", "Ashburn (approx.)", "AS16509", "Amazon AWS", 1, "Cloud provider range"),
}
REPUTATION = {1: "benign", 2: "unknown", 3: "suspicious", 4: "malicious", 5: "known-bad"}


def lookup(ip: str | None) -> dict:
    if not ip:
        return {"ip": None, "reputation": "unknown"}
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {"ip": ip, "reputation": "unknown"}
    if addr.is_private:
        return {"ip": ip, "country": "internal", "city": None, "asn": None, "provider": "internal network",
                "reputation": "internal", "tags": []}
    if ip in KNOWN:
        c, city, asn, prov, score, tag = KNOWN[ip]
    else:
        h = int(hashlib.sha256(ip.encode()).hexdigest(), 16)
        c, city, asn, prov, score, tag = ("??", None, f"AS{64512 + h % 1000}", "unattributed", 2, "no match")
    return {"ip": ip, "country": c, "city": city, "asn": asn, "provider": prov,
            "reputation": REPUTATION[score], "reputation_score": score, "tags": [tag]}
