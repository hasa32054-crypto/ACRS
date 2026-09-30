"""Tunable policy. Every number maps to the ACRS design, so reviewers can trace code to design.

Timers can be overridden through environment variables (ACRS_TIER0_TIMER_S, ...).
"""
from __future__ import annotations

import os


def _f(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except ValueError:
        return default


# ------------------------------------------------------------------ detection
SUSPICIOUS_PORTS = {4444, 1337, 9001, 8888, 31337}
LOLBINS = {"powershell.exe", "cmd.exe", "rundll32.exe", "mshta.exe", "wscript.exe", "cscript.exe",
           "regsvr32.exe", "certutil.exe", "bitsadmin.exe",
           # Linux living-off-the-land binaries (flagged only with network activity)
           "curl", "wget", "nc", "ncat", "socat"}
LATERAL_PORTS = {3389, 445, 5985, 5986, 135}

THRESHOLDS = {
    "c2_port_min_conns": 3, "c2_window_s": 300,
    "beacon_min_conns": 20, "beacon_max_cv": 0.15,
    "lolbin_net_window_s": 60,
    "lateral_min_hosts": 10, "lateral_window_s": 600,
    "dns_entropy": 3.8, "dns_min_len": 50, "dns_min_queries": 100,
    "exfil_bytes": 500 * 1024 * 1024,
    "ransom_renames_per_min": 200,
    "ti_min_confidence": 70,
    "ueba_sigma": 3.0,
    "impossible_travel_s": 3600,
}

CORRELATION_WINDOW_S = 300          # sliding window for linking events into one incident
DETECTION_LOOKBACK_S = 3600         # rate-based rules (beaconing, DNS) need a longer view

# ------------------------------------------------------------------ risk (0..100)
RISK_WEIGHTS = {
    "signal_severity": 0.25,        # combined strength of detections (noisy-OR)
    "source_correlation": 0.20,     # independent telemetry sources agreeing
    "threat_intel": 0.15,           # IoC reputation
    "behavior_anomaly": 0.15,       # UEBA deviation or role mismatch
    "asset_sensitivity": 0.15,      # tier
    "blast_radius": 0.10,           # peers, dependents, CMDB criticality
}
# confidence (0..100 %)
CONFIDENCE_WEIGHTS = {
    "independent_sources": 0.45,
    "ioc_reputation": 0.25,
    "evidence_strength": 0.30,
}
SINGLE_SOURCE_CONFIDENCE_CAP = 55   # one sensor alone never reaches auto-containment confidence
TIER_SENSITIVITY = {0: 1.0, 1: 0.8, 2: 0.5}
CRITICALITY_BLAST = {"critical": 1.0, "high": 0.6, "medium": 0.3, "low": 0.1}
ADJUSTMENTS = {"change_window": -15, "attribution_conflict": -10}

# ------------------------------------------------------------------ decision
MEDIUM_FLOOR = 60                   # below: monitor only
MIN_AUTO_CONFIDENCE = 60            # below: no automatic containment

TIER_POLICY = {
    0: {"auto_threshold": 95, "deadline_s": _f("ACRS_TIER0_TIMER_S", 7), "approvals_for_full": 2},
    1: {"auto_threshold": 90, "deadline_s": _f("ACRS_TIER1_TIMER_S", 15), "approvals_for_full": 1},
    2: {"auto_threshold": 85, "deadline_s": _f("ACRS_TIER2_TIMER_S", 90), "approvals_for_full": 0},
}
OBSERVATION_WINDOW_S = _f("ACRS_OBSERVATION_S", 60)
OBSERVATION_CHECKS = 6              # one check every 10 s by default
REENTRY_DWELL_S = _f("ACRS_REENTRY_DWELL_S", 5)
RETRY_INTERVAL_S = _f("ACRS_RETRY_INTERVAL_S", 2)
MAX_REMEDIATION_ATTEMPTS = 2
MAX_CONTAINMENT_CYCLES = 2          # IoB returning more than this -> Emergency Queue

CIRCUIT_BREAKER_MAX = int(_f("ACRS_CIRCUIT_BREAKER_MAX", 5))
CIRCUIT_BREAKER_WINDOW_S = 600
SEGMENT_RESTRICT_MIN_ASSETS = 3
SEGMENT_RESTRICT_WINDOW_S = 300

ROLE_EGRESS_PROFILE: dict[str, set[int]] = {
    "hr-app": {443}, "erp-app": {443}, "database": set(), "domain-controller": {53, 123},
    "k8s-control-plane": {443}, "k8s-node": {443}, "workstation": {80, 443}, "backup": {443},
    "medical-device": set(), "web-frontend": {443}, "api-gateway": {443}, "pki": set(),
    "vpn-gateway": {443, 500, 4500}, "build-server": {443},
}

# SOC investigation channel that survives every containment level (inbound only)
SOC_JUMP_HOST = {"hostname": "soc-jump-01", "ip": "10.99.0.10", "ports": [22, 5985]}
