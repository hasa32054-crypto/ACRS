"""Correlation Engine: links events into incidents over a sliding window.

Keys: asset_id, src_ip, user, process_hash, c2_domain (plus external C2 IPs).
Two events belong to the same incident when they share a key inside the window.
A shared C2 key across *different* assets marks the incidents as related (campaign).
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Iterable

from .detection import is_public
from .policy import CORRELATION_WINDOW_S
from .types import Detection, Event

C2_KINDS = ("c2_domain", "c2_ip")


def keys_for(events: Iterable[Event], detections: Iterable[Detection] = (), asset_id: int | None = None) -> set[str]:
    keys: set[str] = set()
    for e in events:
        keys.add(f"src_ip:{e.src_ip}")
        if e.user:
            keys.add(f"user:{e.user.lower()}")
        if e.process_hash:
            keys.add(f"process_hash:{e.process_hash.lower()}")
        if e.c2_domain:
            keys.add(f"c2_domain:{e.c2_domain.lower()}")
    for d in detections:
        ip = d.evidence.get("dest_ip")
        if ip and is_public(ip):
            keys.add(f"c2_ip:{ip}")
        dom = d.evidence.get("domain")
        if dom:
            keys.add(f"c2_domain:{dom.lower()}")
    if asset_id is not None:
        keys.add(f"asset_id:{asset_id}")
    return keys


def asset_keys(keys: set[str]) -> set[str]:
    """Keys that identify the same compromised host (not shared infrastructure)."""
    return {k for k in keys if k.split(":", 1)[0] in ("src_ip", "asset_id", "process_hash")}


def match_incident(new_keys: set[str], open_incidents: list[dict], now: datetime,
                   window_s: int = CORRELATION_WINDOW_S) -> tuple[str | None, list[str]]:
    """Return (incident to merge into, related incident ids).

    open_incidents: [{"id", "keys": set|list, "last_seen": datetime}]
    """
    start = now - timedelta(seconds=window_s)
    own = asset_keys(new_keys)
    c2 = {k for k in new_keys if k.split(":", 1)[0] in C2_KINDS}
    merge, related = None, []
    for inc in open_incidents:
        if inc["last_seen"] < start:
            continue
        inc_keys = set(inc["keys"])
        if own & inc_keys and merge is None:
            merge = inc["id"]
        elif c2 & inc_keys:
            related.append(inc["id"])
    return merge, related


def correlation_weight(event: Event, detections: list[Detection]) -> float:
    """1.0 if the event directly supports a detection, 0.3 if it is context only."""
    for d in detections:
        ev = d.evidence
        if ev.get("dest_ip") and event.data.get("dest_ip") == ev.get("dest_ip"):
            return 1.0
        if event.event_type in ("lsass_access", "file_activity", "ti_match", "ueba_anomaly", "cloud_api", "signin"):
            return 1.0
        if event.event_type == "process" and ev.get("process") and \
                event.data.get("process", "").lower() == str(ev.get("process")).lower():
            return 1.0
        if event.event_type == "dns_query" and ev.get("domain") and \
                event.data.get("query", "").endswith(str(ev["domain"])):
            return 1.0
    return 0.3
