"""Small, dependency-light statistics used by v4 (scipy for the exact tests)."""
from __future__ import annotations

import math

import numpy as np
from scipy import stats as st


def wilson(k: int, n: int, z: float = 1.959963984540054) -> tuple[float, float]:
    """Wilson score 95% interval for a proportion k/n."""
    if n == 0:
        return (float("nan"), float("nan"))
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def mcnemar_exact(a_only: int, b_only: int) -> float:
    """Two-sided exact McNemar p-value from the two discordant counts."""
    n = a_only + b_only
    return 1.0 if n == 0 else float(st.binomtest(a_only, n, 0.5, alternative="two-sided").pvalue)


def wilcoxon_less(x, y) -> dict:
    """One-sided paired Wilcoxon signed-rank: is x smaller than y? Zero differences dropped (Wilcoxon's rule)."""
    d = np.asarray(x, float) - np.asarray(y, float)
    nz = int((d != 0).sum())
    if nz == 0:
        return {"p": 1.0, "nonzero_pairs": 0, "statistic": None}
    r = st.wilcoxon(x, y, zero_method="wilcox", alternative="less")
    return {"p": float(r.pvalue), "nonzero_pairs": nz, "statistic": float(r.statistic)}


def bootstrap_diff(x, y, reps: int = 10_000, seed: int = 0) -> tuple[float, float]:
    """95% percentile CI of mean(x) - mean(y) for PAIRED samples (resample scenarios)."""
    x, y = np.asarray(x, float), np.asarray(y, float)
    rng = np.random.default_rng(seed)
    idx = rng.integers(0, len(x), size=(reps, len(x)))
    d = x[idx].mean(1) - y[idx].mean(1)
    return (float(np.percentile(d, 2.5)), float(np.percentile(d, 97.5)))
