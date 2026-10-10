"""Shared run metadata for v3 experiments (what ran, on which code, when, with which settings)."""
from __future__ import annotations

import hashlib
import platform
import subprocess
import time
from pathlib import Path

import numpy as np

HERE = Path(__file__).parent
CORE = ("network.py", "qubo_builder.py", "safety_checks.py", "escalation.py")


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()[:12]


def code_hashes(extra=()) -> dict:
    return {f: sha(HERE / f) for f in (*CORE, *extra) if (HERE / f).exists()}


def git_commit() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "--short", "HEAD"], cwd=HERE,
                                       stderr=subprocess.DEVNULL).decode().strip()
    except Exception:
        return "unknown"


def meta(experiment: str, extra_files=(), **settings) -> dict:
    return {"experiment": experiment, "version": "v3", "preregistration": "docs/qacrs/PREREGISTRATION_v3.md",
            "date_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "git_commit": git_commit(),
            "code_sha256_prefix": code_hashes(extra_files), "python": platform.python_version(),
            "numpy": np.__version__, "settings": settings, "status": "complete", "warnings": []}
