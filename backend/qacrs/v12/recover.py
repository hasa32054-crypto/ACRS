"""D11 + D12: the recovery terminal and the survivable engine state.

    cd backend && python -m qacrs.v12.recover --state /path/state.json          (interactive)
    cd backend && python -m qacrs.v12.recover --state s.json -c "status" -c "readmit pc_3"

Every command goes through the LOCKED safety checks before it changes anything:
  * readmit <host>      refused while the host's recorded risk >= threshold (7); critical -> two approvals
  * restore <host>      marks the host rebuilt from backup (risk -> 0); critical -> two approvals
  * rotate-creds        marks domain credentials rotated (risk of T1003/T1558-class hosts -> 5)
  * shield <a> <b>      permanent shield on a link (the a->b lateral path is closed); critical target -> two approvals
  * approve <n> <who>   second-person approval for a pending command (two DIFFERENT names)
  * close-incident      extracts the fingerprint (D13) and installs immunity
  * status              shows isolated / segmented / pending / shields / immunity
The audit log is an HMAC chain (each entry signs the previous hash); ML-DSA is layered on top in mldsa.py.
The state is persisted after every change (D12 b): a restart reloads it and never releases an isolated host.
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path

from qacrs import hassan as H
from qacrs import qubo_v7 as V7
from qacrs import safety_checks as S
from qacrs.network import Machine, Network, Scenario, Service
from qacrs.v12 import immunity as IM
from qacrs.v12 import qubo_v12 as Q

SOLVER_BUDGET_MS = 500          # D12(a): if the optimiser does not answer in time, the safety floor + rule stand alone
AUDIT_KEY = os.environ.get("ACRS_AUDIT_KEY", "dev-only-key").encode()


# ------------------------------------------------------------------ state ----------------------------------------
@dataclass
class State:
    network: Network
    risk: dict[str, int] = field(default_factory=dict)          # current recorded risk per host (0 = clean)
    isolated: set[str] = field(default_factory=set)
    segmented: set[str] = field(default_factory=set)
    pending: dict[int, dict] = field(default_factory=dict)      # n -> {cmd, args, approvals:[who]}
    shields: set[tuple[str, str]] = field(default_factory=set)
    immunity: IM.Immunity = field(default_factory=IM.Immunity)
    incident: dict = field(default_factory=dict)                # {"id", "path", "techniques"}
    audit: list[dict] = field(default_factory=list)
    next_id: int = 1

    # ---------------------------------------------------------------- persistence (D12 b)
    def to_json(self) -> str:
        n = self.network
        return json.dumps({
            "network": {"name": n.name, "machines": [m.__dict__ for m in n.machines],
                        "services": [s.__dict__ for s in n.services], "links": [list(l) for l in n.links]},
            "risk": self.risk, "isolated": sorted(self.isolated), "segmented": sorted(self.segmented),
            "pending": self.pending, "shields": sorted(map(list, self.shields)), "immunity": self.immunity.as_dict(),
            "incident": self.incident, "audit": self.audit, "next_id": self.next_id}, sort_keys=True)

    @classmethod
    def from_json(cls, s: str) -> "State":
        d = json.loads(s); n = d["network"]
        net = Network(n["name"], [Machine(**m) for m in n["machines"]], [Service(**x) for x in n["services"]],
                      [tuple(l) for l in n["links"]])
        st = cls(net, d["risk"], set(d["isolated"]), set(d["segmented"]), {int(k): v for k, v in d["pending"].items()},
                 {tuple(l) for l in d["shields"]}, IM.Immunity.from_dict(d["immunity"]), d["incident"], d["audit"], d["next_id"])
        st.immunity.shields |= st.shields
        return st

    def save(self, path: Path) -> None:
        tmp = path.with_suffix(".tmp")
        tmp.write_text(self.to_json(), encoding="utf-8"); os.replace(tmp, path)     # atomic

    @classmethod
    def load(cls, path: Path) -> "State":
        return cls.from_json(path.read_text(encoding="utf-8"))

    # ---------------------------------------------------------------- audit (HMAC chain)
    def log(self, event: str, **kw) -> dict:
        prev = self.audit[-1]["hash"] if self.audit else "0" * 64
        body = {"t": time.time(), "event": event, **kw, "prev": prev}
        h = hmac.new(AUDIT_KEY, json.dumps(body, sort_keys=True).encode(), hashlib.sha256).hexdigest()
        entry = body | {"hash": h}
        self.audit.append(entry)
        return entry

    def audit_ok(self) -> bool:
        prev = "0" * 64
        for e in self.audit:
            body = {k: v for k, v in e.items() if k != "hash"}
            if body["prev"] != prev or not hmac.compare_digest(
                    hmac.new(AUDIT_KEY, json.dumps(body, sort_keys=True).encode(), hashlib.sha256).hexdigest(), e["hash"]):
                return False
            prev = e["hash"]
        return True

    @property
    def scenario(self) -> Scenario:
        return Scenario("live", self.network.name, {h: r for h, r in self.risk.items() if r > 0}, "live state")


# ------------------------------------------------------------------ survivable decision (D12 a) -------------------
def decide_with_budget(net: Network, sc: Scenario, immunity=None, budget_ms: int = SOLVER_BUDGET_MS, solver=H.solve):
    """Run the optimiser under a time budget; on timeout or error fall back to floor + rule_segment (no optimiser)."""
    ex = cf.ThreadPoolExecutor(max_workers=1)
    fut = ex.submit(solver, net, sc)
    fallback = None
    try:
        iso, seg, how = fut.result(timeout=budget_ms / 1000)
        chosen = lambda n, s: (iso, seg, how)  # noqa: E731
    except (cf.TimeoutError, Exception) as e:  # noqa: BLE001 - any solver failure must not stop containment
        fallback = f"solver {'timeout' if isinstance(e, cf.TimeoutError) else 'error: ' + type(e).__name__}"
        chosen = lambda n, s: (*V7.m_rule_segment(n, s), "fallback_rule_segment")  # noqa: E731
    ex.shutdown(wait=False)
    d = Q.decide_v12(net, sc, immunity, solver=chosen)
    d.solver["fallback"] = fallback
    return d


def apply_alert(st: State, hacked: dict[str, int], state_path: Path | None = None) -> Q.DecisionV12:
    """New alert(s) arrive: merge into the live risk map, decide, and NEVER release an already-isolated host."""
    for h, r in hacked.items():
        st.risk[h] = max(st.risk.get(h, 0), int(r))
    d = decide_with_budget(st.network, st.scenario, st.immunity)
    st.isolated |= set(d.isolate)                         # monotone: union only
    st.segmented |= set(d.segment) - st.isolated
    st.log("decision", hacked=hacked, status=d.status, isolate=d.isolate, segment=d.segment, fallback=d.solver["fallback"])
    if state_path:
        st.save(state_path)
    return d


# ------------------------------------------------------------------ terminal commands (D11) -----------------------
class Refused(Exception):
    pass


def _machine(st: State, name: str) -> Machine:
    try:
        return st.network.machine(name)
    except Exception:
        raise Refused(f"unknown host '{name}'")


def _needs_two(st: State, cmd: str, args: list[str], who: str) -> int | None:
    n = st.next_id; st.next_id += 1
    st.pending[n] = {"cmd": cmd, "args": args, "approvals": [who]}
    st.log("pending", id=n, cmd=cmd, args=args, by=who)
    return n


def _execute(st: State, cmd: str, args: list[str], who: str) -> str:
    if cmd == "readmit":
        (h,) = args
        st.isolated.discard(h); st.segmented.discard(h)
        st.log("readmit", host=h, by=who); return f"readmitted {h}"
    if cmd == "restore":
        (h,) = args
        st.risk[h] = 0
        st.log("restore", host=h, by=who); return f"{h} marked restored from backup (risk 0); readmit when ready"
    if cmd == "shield":
        a, b = args
        st.shields.add((a, b)); st.immunity.shields.add((a, b))
        st.log("shield", link=[a, b], by=who); return f"shield installed on {a} -> {b}"
    raise Refused(f"no executor for {cmd}")


def run_command(st: State, line: str, who: str = "engineer") -> str:
    parts = line.split()
    if not parts:
        return ""
    cmd, args = parts[0], parts[1:]
    if cmd == "status":
        sc = st.scenario
        return json.dumps({"risk>0": sc.hacked, "isolated": sorted(st.isolated), "segmented": sorted(st.segmented),
                           "pending": st.pending, "shields": sorted(map(list, st.shields)),
                           "immunity": [f.incident for f in st.immunity.fingerprints], "audit_ok": st.audit_ok()}, indent=1)
    if cmd == "alert":                                   # alert <host> <risk> [host risk ...]
        hacked = {args[i]: int(args[i + 1]) for i in range(0, len(args), 2)}
        d = apply_alert(st, hacked)
        return f"{d.status}: isolate {d.isolate} segment {d.segment} (floor {d.floor['isolate']}/{d.floor['segment']}, fallback={d.solver['fallback']})"
    if cmd == "approve":
        n, second = int(args[0]), args[1]
        p = st.pending.get(n)
        if not p:
            raise Refused(f"no pending command {n}")
        if second in p["approvals"]:
            raise Refused("second approval must come from a DIFFERENT person")
        p["approvals"].append(second); del st.pending[n]
        st.log("approved", id=n, by=second)
        return _execute(st, p["cmd"], p["args"], f"{p['approvals'][0]}+{second}")
    if cmd in ("readmit", "restore"):
        (h,) = args; m = _machine(st, h)
        if cmd == "readmit":
            if st.risk.get(h, 0) >= S.HIGH_RISK:
                raise Refused(f"'{h}' still at risk {st.risk[h]} >= {S.HIGH_RISK}: restore it first")
            # the locked gate must still accept the state WITHOUT this host isolated
            iso = st.isolated - {h}; seg = st.segmented - {h}
            v = V7.check_v7(st.network, st.scenario, iso, seg)
            if v.status in (S.REJECTED, S.NOT_CONTAINED) and any(h in r for r in v.reasons):
                raise Refused(f"readmitting '{h}' would leave: {v.reasons}")
        if m.critical:
            n = _needs_two(st, cmd, args, who); return f"'{h}' is critical: pending #{n}, needs 'approve {n} <second person>'"
        return _execute(st, cmd, args, who)
    if cmd == "rotate-creds":
        changed = [h for h, r in st.risk.items() if r == 8]
        for h in changed:
            st.risk[h] = 5
        st.log("rotate-creds", hosts=changed, by=who); return f"credentials rotated; {len(changed)} credential-theft hosts lowered to 5"
    if cmd == "shield":
        a, b = args; _machine(st, a); mb = _machine(st, b)
        if (a, b) not in st.network.links:
            raise Refused(f"no link {a} -> {b}")
        if mb.critical:
            n = _needs_two(st, cmd, args, who); return f"target '{b}' is critical: pending #{n}"
        return _execute(st, cmd, args, who)
    if cmd == "close-incident":                           # close-incident <id> <path a>b>c> [techniques,comma]
        inc, path = args[0], args[1].split(">")
        tech = args[2].split(",") if len(args) > 2 else []
        if any(st.risk.get(h, 0) >= S.HIGH_RISK for h in path):
            raise Refused("cannot close: a host on the path is still at risk >= 7 (restore or rotate-creds first)")
        fp = st.immunity.learn(st.network, path, tech, inc)
        st.shields |= set(fp.links)
        st.log("close-incident", incident=inc, fingerprint=fp.as_dict(), by=who)
        return f"incident {inc} closed; immunity installed: first hop {fp.first_hop}, {len(fp.links)} links shielded"
    raise Refused(f"unknown command '{cmd}'")


# ------------------------------------------------------------------ cli --------------------------------------------
def main() -> None:
    ap = argparse.ArgumentParser(prog="acrs-recover")
    ap.add_argument("--state", required=True); ap.add_argument("--who", default="engineer")
    ap.add_argument("-c", "--command", action="append", default=[])
    a = ap.parse_args()
    p = Path(a.state)
    st = State.load(p)
    lines = a.command or iter(lambda: input("acrs-recover> "), "quit")
    for line in lines:
        try:
            print(run_command(st, line, a.who))
        except Refused as e:
            st.log("refused", command=line, reason=str(e), by=a.who); print(f"REFUSED: {e}")
        st.save(p)


if __name__ == "__main__":
    main()
