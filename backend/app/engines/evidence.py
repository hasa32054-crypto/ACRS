"""Evidence collection + chain of custody (ISO/IEC 27037 aligned).

Artifacts are ordered by volatility. Each custody record is linked to the
previous one with a SHA-256 hash chain, so any tampering with an earlier
record breaks verification of every later one. In production, artifact bytes
go to S3 Object Lock (compliance mode) and the chain head is signed with KMS.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from .types import Asset, Detection, Event, Level

GENESIS = "0" * 64
VAULT_PREFIX = "s3://acrs-evidence-vault"

RETENTION_DAYS = {
    "memory_dump": 730, "process_tree": 730, "network_pcap": 365, "disk_image": 730,
    "timeline": 730, "hash_manifest": 730,
}

COLLECTORS = {
    "memory_dump": "velociraptor/winpmem",
    "process_tree": "edr-rtr",
    "network_pcap": "arkime (15 min ring buffer)",
    "disk_image": "kape + snapshot (E01)",
    "timeline": "plaso/timesketch",
    "hash_manifest": "acrs",
}


def _sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def chain_hash(prev: str, artifact_sha: str, kind: str, actor: str, ts: str) -> str:
    return _sha256(f"{prev}|{artifact_sha}|{kind}|{actor}|{ts}".encode())


def kinds_for(level: Level, detections: list[Detection]) -> list[str]:
    """Order of volatility: memory first, disk last."""
    kinds = []
    if level in (Level.SURGICAL, Level.FULL_ISOLATION, Level.EMERGENCY_RESTRICT):
        kinds.append("memory_dump")
    kinds += ["process_tree", "network_pcap"]
    persistence = any(d.rule_id in {"ACRS-EDR-002", "ACRS-EDR-003", "ACRS-CLD-001"} for d in detections)
    if level == Level.FULL_ISOLATION or persistence:
        kinds.append("disk_image")
    kinds += ["timeline", "hash_manifest"]
    return kinds


def collect(incident_id: str, asset: Asset, level: Level, events: list[Event],
            detections: list[Detection], prev_chain: str = GENESIS, actor: str = "acrs-engine") -> list[dict]:
    records = []
    prev = prev_chain
    for kind in kinds_for(level, detections):
        ts = datetime.now(timezone.utc).isoformat()
        if kind == "timeline":
            body = [{"ts": e.ts.isoformat(), "source": e.source, "type": e.event_type, "data": e.data}
                    for e in sorted(events, key=lambda x: x.ts)]
        elif kind == "hash_manifest":
            body = [{"kind": r["kind"], "sha256": r["sha256"]} for r in records]
        else:
            body = {"incident": incident_id, "host": asset.hostname, "kind": kind, "collected_at": ts,
                    "note": "simulated artifact manifest; real bytes stream to the vault"}
        blob = json.dumps(body, sort_keys=True, default=str).encode()
        sha = _sha256(blob)
        ch = chain_hash(prev, sha, kind, actor, ts)
        ext = {"memory_dump": "raw", "network_pcap": "pcap", "disk_image": "E01"}.get(kind, "json")
        records.append({
            "kind": kind, "uri": f"{VAULT_PREFIX}/{incident_id}/{kind}.{ext}", "sha256": sha,
            "size_bytes": len(blob), "collector": COLLECTORS[kind], "actor": actor, "collected_at": ts,
            "prev_hash": prev, "chain_hash": ch, "retention_days": RETENTION_DAYS[kind],
        })
        prev = ch
    return records


def verify_chain(records: list[dict], start: str = GENESIS) -> tuple[bool, int | None]:
    """Returns (ok, index_of_first_broken_record)."""
    prev = start
    for i, r in enumerate(records):
        if r["prev_hash"] != prev:
            return False, i
        expected = chain_hash(prev, r["sha256"], r["kind"], r["actor"], r["collected_at"])
        if expected != r["chain_hash"]:
            return False, i
        prev = r["chain_hash"]
    return True, None
