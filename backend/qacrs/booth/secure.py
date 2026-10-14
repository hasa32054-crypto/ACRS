"""Hardening for HASSAN at the booth: a protection tool must not become a hole in what it protects.

- Secrets live OUTSIDE the repo, in ~/.hassan (or $HASSAN_SECRET_DIR), created 0600 with os.urandom.
- The UI API needs a per-install token (constant-time compare). The token is only handed to a loopback client
  whose Host header names this server (DNS-rebinding defence).
- Every containment plan sent to the mini-hospital agent is an HMAC-SHA256 envelope with a timestamp and a
  one-time nonce: a captured plan cannot be replayed, altered, or sent late.
- Strict input validation: only known machine names, bounded sizes, integer risks, no unknown keys.
- Per-client rate limiting.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import stat
import threading
import time
from collections import OrderedDict, deque
from pathlib import Path

PLAN_WINDOW_S = 30            # a plan older (or further in the future) than this is refused
MAX_PICKS = 20                # machines a visitor can mark in one attack
RISK_MIN, RISK_MAX = 1, 10
MAX_NAME = 40                 # attack-button label (display only, never interpreted)


# ------------------------------------------------------------------ secrets -----------------------------------------
def secret_dir() -> Path:
    return Path(os.environ.get("HASSAN_SECRET_DIR") or Path.home() / ".hassan")


def load_secret(name: str, nbytes: int = 32) -> bytes:
    """Read a secret file; create it (0600, random) on first use. Never stored in the repo."""
    d = secret_dir()
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    p = d / name
    if not p.exists():
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(secrets.token_hex(nbytes))
    if os.name == "posix" and stat.S_IMODE(p.stat().st_mode) & 0o077:
        raise PermissionError(f"{p} is readable by other users; run: chmod 600 {p}")
    raw = p.read_text().strip()
    if len(raw) < 32:
        raise ValueError(f"{p} is too short to be a key")
    return bytes.fromhex(raw) if all(c in "0123456789abcdef" for c in raw.lower()) else raw.encode()


def token_ok(given: str | None, expected: str) -> bool:
    return bool(given) and hmac.compare_digest(given.encode(), expected.encode())


# ------------------------------------------------------------------ signed plans ------------------------------------
def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def seal(plan: dict, key: bytes, now: float | None = None) -> dict:
    env = {"plan": plan, "ts": int(now if now is not None else time.time()), "nonce": secrets.token_hex(16)}
    env["sig"] = hmac.new(key, canonical(env), hashlib.sha256).hexdigest()
    return env


class NonceCache:
    """Remembers nonces for PLAN_WINDOW_S x 2; anything seen twice is a replay."""

    def __init__(self, ttl: float = 2 * PLAN_WINDOW_S, max_size: int = 50_000):
        self.ttl, self.max, self._d, self._lock = ttl, max_size, OrderedDict(), threading.Lock()

    def seen_or_add(self, nonce: str, now: float) -> bool:
        with self._lock:
            while self._d and next(iter(self._d.values())) < now - self.ttl:
                self._d.popitem(last=False)
            if nonce in self._d:
                return True
            if len(self._d) >= self.max:
                self._d.popitem(last=False)
            self._d[nonce] = now
            return False


def open_envelope(env, key: bytes, nonces: NonceCache, now: float | None = None) -> tuple[dict | None, str]:
    """Returns (plan, "ok") or (None, reason). Checks shape, signature, freshness, then single use."""
    now = time.time() if now is None else now
    if not isinstance(env, dict) or set(env) != {"plan", "ts", "nonce", "sig"}:
        return None, "malformed envelope"
    if not (isinstance(env["ts"], int) and isinstance(env["nonce"], str) and isinstance(env["sig"], str)
            and isinstance(env["plan"], dict) and len(env["nonce"]) == 32 and len(env["sig"]) == 64):
        return None, "malformed envelope"
    body = {k: env[k] for k in ("plan", "ts", "nonce")}
    if not hmac.compare_digest(hmac.new(key, canonical(body), hashlib.sha256).hexdigest(), env["sig"]):
        return None, "bad signature"
    if abs(now - env["ts"]) > PLAN_WINDOW_S:
        return None, "stale or future plan"
    if nonces.seen_or_add(env["nonce"], now):
        return None, "replayed plan"
    return env["plan"], "ok"


# ------------------------------------------------------------------ validation --------------------------------------
class Invalid(ValueError):
    pass


def _keys(obj: dict, allowed: set, required: set = frozenset()):
    if not isinstance(obj, dict):
        raise Invalid("body must be an object")
    extra = set(obj) - allowed
    if extra:
        raise Invalid(f"unknown field: {sorted(extra)[0][:20]}")
    missing = required - set(obj)
    if missing:
        raise Invalid(f"missing field: {sorted(missing)[0]}")


def machines_list(value, names: set, field: str, limit: int = MAX_PICKS) -> list[str]:
    if not isinstance(value, list) or len(value) > limit:
        raise Invalid(f"{field}: list of at most {limit}")
    out = []
    for m in value:
        if not isinstance(m, str) or m not in names:
            raise Invalid(f"{field}: unknown machine")
        if m not in out:
            out.append(m)
    return out


def attack(body: dict, names: set, extra: set = frozenset()) -> tuple[dict, list[str]]:
    """{"hacked": {machine: risk 1-10}, "forged": [machine, ...]} -> validated (hacked, forged)."""
    _keys(body, {"hacked", "forged"} | set(extra), {"hacked"})
    h = body["hacked"]
    if not isinstance(h, dict) or not 1 <= len(h) <= MAX_PICKS:
        raise Invalid(f"hacked: 1 to {MAX_PICKS} machines")
    hacked = {}
    for m, r in h.items():
        if m not in names:
            raise Invalid("hacked: unknown machine")
        if isinstance(r, bool) or not isinstance(r, int) or not RISK_MIN <= r <= RISK_MAX:
            raise Invalid(f"hacked: risk must be an integer {RISK_MIN}-{RISK_MAX}")
        hacked[m] = r
    forged = machines_list(body.get("forged", []), set(hacked), "forged")
    return hacked, forged


def label(value) -> str:
    """Display-only name of a saved attack button. Plain text; never parsed or executed."""
    if not isinstance(value, str):
        raise Invalid("name must be text")
    s = " ".join(value.split())
    s = "".join(ch for ch in s if ch.isprintable() and ch not in "<>&\"'`\\")
    if not 1 <= len(s) <= MAX_NAME:
        raise Invalid(f"name: 1 to {MAX_NAME} characters")
    return s


# ------------------------------------------------------------------ rate limiting -----------------------------------
class ClientLimiter:
    """At most `limit` requests per `window` seconds per client address."""

    def __init__(self, limit: int = 30, window: float = 10.0, clock=time.monotonic):
        self.limit, self.window, self.clock = limit, window, clock
        self._hits: dict[str, deque] = {}
        self._lock = threading.Lock()

    def allow(self, client: str) -> bool:
        now = self.clock()
        with self._lock:
            q = self._hits.setdefault(client, deque())
            while q and q[0] <= now - self.window:
                q.popleft()
            if len(q) >= self.limit:
                return False
            q.append(now)
            if len(self._hits) > 1000:                         # forget idle clients
                for c in [c for c, d in self._hits.items() if not d]:
                    del self._hits[c]
            return True
