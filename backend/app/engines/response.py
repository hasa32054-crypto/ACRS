"""Response Engine (SIMULATION ONLY – no real network operations).

plan()              which defensive commands a containment level needs, per layer
ResponseEngine      runs them concurrently through controllers, retries unavailable
                    controllers until the tier deadline, records undo data
verify_containment  post-containment probes (blocked where it must be, jump host open)

Controllers are simulated. Real integrations implement the same Controller
protocol (execute / undo) and plug in without touching the engine.
"""
from __future__ import annotations

import asyncio
import random
import time
from typing import Awaitable, Callable, Protocol

from .policy import RETRY_INTERVAL_S, SOC_JUMP_HOST
from .types import Asset, Command, CommandResult, Detection, Level

CLOUD_ENVS = {"aws", "azure", "gcp"}

PROVIDERS = {
    "network": "illumio / cisco-ise (simulated)",
    "perimeter": "palo-alto (simulated)",
    "endpoint": "edr (simulated)",
    "identity": "entra-id / okta (simulated)",
    "application": "f5 / istio (simulated)",
    "cloud": "aws sg / iam (simulated)",
    "dns": "infoblox rpz (simulated)",
    "database": "db firewall (simulated)",
}

# Controller outages the simulator can inject (edge case: Isolation Controller Unavailable)
FAILURE_PROFILES = {
    "integration_down": {"ISOLATE_ASSET", "APPLY_MICROSEGMENTATION", "RESTRICT_NETWORK", "CLOUD_SG_UPDATE"},
}

ENGINEER_COMMANDS = {"ISOLATE_ASSET", "BLOCK_C2", "PROTECT_DATABASE", "REVOKE_SESSION", "RUN_VERIFICATION"}


class ControllerUnavailable(Exception):
    pass


# ------------------------------------------------------------------ planning

def iocs(detections: list[Detection]) -> tuple[list[str], list[str]]:
    ips: list[str] = []
    domains: list[str] = []
    for d in detections:
        for key in ("dest_ip", "indicator"):
            v = d.evidence.get(key)
            if v and str(v).replace(".", "").isdigit() and v not in ips:
                ips.append(str(v))
            elif key == "indicator" and v and "." in str(v) and v not in domains:
                domains.append(str(v))
        if d.evidence.get("domain") and d.evidence["domain"] not in domains:
            domains.append(d.evidence["domain"])
    return sorted(ips), sorted(domains)


def plan(level: Level, asset: Asset, detections: list[Detection], segment_restrict: bool = False) -> list[Command]:
    h = asset.hostname
    ips, domains = iocs(detections)
    jump = SOC_JUMP_HOST
    out: list[Command] = []

    def add(name, layer, target=h, critical=False, **params):
        out.append(Command(name=name, layer=layer, target=target, params=params, critical=critical))

    if level == Level.MONITOR:
        return out
    if ips:
        add("BLOCK_C2", "perimeter", "perimeter-fw", ips=ips)
    if domains:
        add("DNS_BLOCK", "dns", "dns-rpz", domains=domains)

    if asset.role == "unknown":  # not in CMDB: act on the IP only
        add("RESTRICT_NETWORK", "network", critical=True, scope="ip", via="nac")
        if level in (Level.SURGICAL, Level.FULL_ISOLATION):
            add("APPLY_MICROSEGMENTATION", "network", critical=True, mode="nac_quarantine_vlan")
        return out

    if level == Level.COMPENSATING:
        add("APPLY_MICROSEGMENTATION", "network", critical=True, mode="essential_flows_only",
            note="dACL: clinical/OT flows stay allowed, no port shutdown")
        return out

    if level == Level.EMERGENCY_RESTRICT:
        add("RESTRICT_NETWORK", "network", critical=True, egress="deny_internet")
        add("APPLY_MICROSEGMENTATION", "network", critical=True, mode="inbound_from_paw_only")
        add("REVOKE_SESSION", "identity", scope="sessions_on_host")
        add("ROTATE_SECRETS", "identity", scope="service_accounts_on_host")
        if asset.role == "domain-controller":
            add("WITHDRAW_SERVICE_RECORD", "dns", note="other domain controllers keep serving authentication")
        if asset.role == "k8s-control-plane":
            add("CORDON_NODE", "application", note="remaining control-plane nodes keep quorum")
        if segment_restrict:
            add("RESTRICT_SEGMENT_LATERAL", "network", target=asset.segment, ports=[445, 3389, 5985, 5986])
        return out

    add("RESTRICT_NETWORK", "network", critical=True, egress="deny_internet", new_flows_to_tiers=[0, 1])
    if level in (Level.SURGICAL, Level.FULL_ISOLATION):
        add("APPLY_MICROSEGMENTATION", "network", critical=True, mode="quarantine",
            allow_inbound_from=jump["ip"], allow_ports=jump["ports"])
        add("ISOLATE_ASSET", "endpoint", critical=True,
            mode="full" if level == Level.FULL_ISOLATION else "network_contain", allowlist=[jump["ip"]])
        if asset.dependents:
            add("PROTECT_DATABASE", "database", target=",".join(asset.dependents), deny_from=asset.ip)
        if asset.pool and asset.pool_size >= 2:
            add("DRAIN_FROM_POOL", "application", pool=asset.pool)
        add("REVOKE_SESSION", "identity", scope="sessions_on_host")
        add("ROTATE_SECRETS", "identity", scope="service_accounts_on_host")
        if asset.environment in CLOUD_ENVS:
            add("CLOUD_SG_UPDATE", "cloud", critical=True, instance=asset.cloud_instance_id,
                security_group="acrs-quarantine", iam="attach-deny-policy")
    if segment_restrict:
        add("RESTRICT_SEGMENT_LATERAL", "network", target=asset.segment, ports=[445, 3389, 5985, 5986])
    return out


def plan_hardening(asset: Asset, entry: dict) -> list[Command]:
    layer = {"web": "application", "email": "identity", "identity": "identity", "cloud": "cloud",
             "lateral": "network"}.get(entry.get("vector"), "endpoint")
    return [Command("HARDEN_ENTRY_POINT", layer, asset.hostname,
                    {"entry_path": entry.get("path"), **entry.get("harden", {})}),
            Command("ENABLE_ENHANCED_MONITORING", "endpoint", asset.hostname, {"duration_h": 72})]


# ------------------------------------------------------------------ execution

class Controller(Protocol):
    async def execute(self, cmd: Command, failing: frozenset[str]) -> tuple[str, dict]: ...
    async def undo(self, result: CommandResult) -> bool: ...


class SimulatedController:
    def __init__(self, latency_scale: float = 1.0):
        self.latency_scale = latency_scale

    async def execute(self, cmd: Command, failing: frozenset[str]) -> tuple[str, dict]:
        await asyncio.sleep(random.uniform(0.05, 0.3) * self.latency_scale)
        if cmd.name in failing:
            raise ControllerUnavailable(f"{PROVIDERS.get(cmd.layer, cmd.layer)} unavailable")
        return (f"[SIMULATED] {cmd.name} applied to {cmd.target}",
                {"undo": f"UNDO_{cmd.name}", "target": cmd.target, "params": cmd.params})

    async def undo(self, result: CommandResult) -> bool:
        await asyncio.sleep(random.uniform(0.02, 0.08) * self.latency_scale)
        return True


OnResult = Callable[[CommandResult], Awaitable[None]]


class ResponseEngine:
    def __init__(self, controller: Controller | None = None, retry_interval_s: float = RETRY_INTERVAL_S):
        self.controller = controller or SimulatedController()
        self.retry_interval_s = retry_interval_s

    async def execute(self, commands: list[Command], deadline: float, failing: frozenset[str] = frozenset(),
                      on_result: OnResult | None = None) -> list[CommandResult]:
        """deadline is a time.monotonic() value. Unavailable controllers are retried until then."""

        async def run_one(cmd: Command) -> CommandResult:
            start = time.monotonic()
            attempts = 0
            while True:
                attempts += 1
                try:
                    msg, undo = await self.controller.execute(cmd, failing)
                    res = CommandResult(cmd, True, attempts, int((time.monotonic() - start) * 1000),
                                        PROVIDERS.get(cmd.layer, cmd.layer), msg, undo)
                    break
                except ControllerUnavailable as exc:
                    if deadline - time.monotonic() <= self.retry_interval_s:
                        res = CommandResult(cmd, False, attempts, int((time.monotonic() - start) * 1000),
                                            PROVIDERS.get(cmd.layer, cmd.layer),
                                            f"{exc}: gave up after {attempts} attempts at the deadline")
                        break
                    await asyncio.sleep(self.retry_interval_s)
            if on_result:
                await on_result(res)
            return res

        return list(await asyncio.gather(*(run_one(c) for c in commands)))

    async def undo(self, results: list[CommandResult]) -> list[tuple[CommandResult, bool]]:
        out = []
        for r in reversed(results):
            if r.ok:
                out.append((r, await self.controller.undo(r)))
        return out


def verify_containment(level: Level, succeeded: set[str], asset: Asset) -> list[dict]:
    """Post-containment probes. In a live deployment these run from the host via EDR RTR."""
    probes: list[dict] = []
    if level == Level.MONITOR:
        return probes
    egress = bool(succeeded & {"RESTRICT_NETWORK", "ISOLATE_ASSET", "APPLY_MICROSEGMENTATION"})
    probes.append({"probe": "internet egress from host", "expected": "blocked",
                   "observed": "blocked" if egress else "open", "pass": egress})
    if level in (Level.SURGICAL, Level.FULL_ISOLATION):
        q = bool(succeeded & {"ISOLATE_ASSET", "APPLY_MICROSEGMENTATION"})
        for dep in (asset.dependents or ["critical-systems"])[:3]:
            probes.append({"probe": f"host -> {dep}", "expected": "blocked",
                           "observed": "blocked" if q else "open", "pass": q})
    probes.append({"probe": f"{SOC_JUMP_HOST['hostname']} -> host (investigation, inbound only)",
                   "expected": "allowed", "observed": "allowed", "pass": True})
    return probes
