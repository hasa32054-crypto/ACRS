"""Recovery Engine: remediation pipeline, 9-check Verification Gate, observation, graduated re-entry.

All stages are simulated; each maps to a real tool named in the design.
"""
from __future__ import annotations

import asyncio

from .types import Asset, Detection

REENTRY_STAGES = ["Isolation", "Restricted", "Limited Production", "Full"]

GATE_CHECKS = [
    ("no_ioc", "No IoC match in EDR / YARA sweep"),
    ("no_critical_vulns", "No critical or high vulnerabilities"),
    ("edr_running", "EDR agent healthy and reporting"),
    ("firewall_policy", "Host firewall policy matches baseline"),
    ("secrets_rotated", "All related secrets rotated"),
    ("autoruns_clean", "Autoruns / tasks / services match baseline"),
    ("services_healthy", "Business services pass health checks"),
    ("behavior_normal", "Behaviour within baseline"),
    ("evidence_intact", "Evidence hash chain verified"),
]

FAILURE_STAGE = {"gate_fail": "vulnerability_scan"}


def needs_reimage(asset: Asset, detections: list[Detection]) -> bool:
    if asset.role in ("domain-controller", "k8s-control-plane", "medical-device"):
        return False
    return asset.tier <= 1 or any(d.rule_id in {"ACRS-EDR-002", "ACRS-EDR-003", "ACRS-CLD-001"} for d in detections)


def _stages(asset: Asset, detections: list[Detection]) -> list[tuple[str, str, str]]:
    if asset.role == "domain-controller":
        first = ("credential_reset", "ad tooling", "krbtgt rotated twice, privileged accounts reset")
    elif needs_reimage(asset, detections):
        first = ("reimage_patch", "packer + ansible", "Golden image applied, patch level current")
    else:
        first = ("clean_patch", "edr + wsus/apt", "Malicious artefacts removed, critical patches applied")
    return [
        first,
        ("rotate_credentials", "vault / cyberark", "Service account secrets, keys and local admin rotated"),
        ("reconfigure_cis", "ansible / dsc", "CIS Benchmark applied, host firewall enforced"),
        ("vulnerability_scan", "tenable / openvas", "0 critical, 0 high findings"),
        ("edr_rescan_ioc_sweep", "edr + yara", "No incident IoCs on host or fleet"),
        ("autoruns_diff", "velociraptor", "No unknown persistence"),
        ("service_health", "synthetic checks", "Business services healthy"),
    ]


async def run_pipeline(asset: Asset, detections: list[Detection], fail_stage: str | None = None,
                       latency_s: float = 0.3) -> list[dict]:
    out = []
    for name, tool, detail in _stages(asset, detections):
        await asyncio.sleep(latency_s)
        ok = name != fail_stage
        out.append({"stage": name, "tool": tool, "ok": ok,
                    "detail": detail if ok else f"{name} failed: critical finding remains"})
        if not ok:
            break
    return out


def gate(pipeline: list[dict], evidence_ok: bool, behavior_ok: bool = True) -> dict:
    by = {s["stage"]: s["ok"] for s in pipeline}
    first_ok = next((s["ok"] for s in pipeline[:1]), False)
    values = {
        "no_ioc": by.get("edr_rescan_ioc_sweep", False),
        "no_critical_vulns": by.get("vulnerability_scan", False),
        "edr_running": True,
        "firewall_policy": by.get("reconfigure_cis", False),
        "secrets_rotated": by.get("rotate_credentials", False) and first_ok,
        "autoruns_clean": by.get("autoruns_diff", False),
        "services_healthy": by.get("service_health", False),
        "behavior_normal": behavior_ok,
        "evidence_intact": evidence_ok,
    }
    items = [{"check": c, "passed": bool(values[c]), "description": d} for c, d in GATE_CHECKS]
    return {"passed": all(i["passed"] for i in items), "items": items}


def observation_check(index: int, inject_ioc: bool) -> dict:
    """One periodic check in the observation window. The simulator can inject an IoB at check #3."""
    if inject_ioc and index == 2:
        return {"check": index + 1, "clean": False,
                "finding": "IoB: beacon to known C2 resumed (persistence survived remediation)"}
    return {"check": index + 1, "clean": True, "finding": "no indicators, behaviour within baseline"}
