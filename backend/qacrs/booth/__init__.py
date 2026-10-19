"""SAIF booth «HASSAN»: offline demo app, attack memory, signed plans and the mini-hospital agent.

Nothing here modifies the engine or the blind-test locked files; it only calls them.
"""

# The booth never runs the statistical tests (they produced the published result files). On a laptop without scipy
# (e.g. a Python too new for scipy wheels) we register a stand-in so the engine imports; any call to it fails loudly.
try:  # pragma: no cover - depends on the machine
    import scipy  # noqa: F401
except ImportError:  # pragma: no cover
    import sys as _sys
    import types as _types

    def _needs_scipy(*_a, **_k):
        raise RuntimeError("this statistic needs scipy; the booth does not use it (pip install scipy)")

    _scipy = _types.ModuleType("scipy")
    _scipy.__path__ = []                       # behave as a package
    _scipy.__acrs_stub__ = True
    _sys.modules.setdefault("scipy", _scipy)
    for _sub in ("stats", "optimize", "special", "linalg", "sparse"):
        _m = _types.ModuleType("scipy." + _sub)
        _m.__getattr__ = lambda _n: _needs_scipy
        setattr(_scipy, _sub, _m)
        _sys.modules.setdefault("scipy." + _sub, _m)
