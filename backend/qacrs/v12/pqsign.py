"""D9: ML-DSA-65 (FIPS 204) signature over the v9 certificate — non-repudiation on top of HMAC.

HMAC (locked `hassan.sign`) proves integrity and that *someone with the shared key* produced the certificate; it cannot
prove *which* party did, because verifier and signer hold the same key. ML-DSA is a post-quantum digital signature:
the engine signs with a private key only it holds, anyone verifies with the public key. Shor's algorithm breaks RSA/ECDSA
signatures; ML-DSA (module-lattice) is the NIST standard chosen to replace them.

Implementation: `dilithium-py` (MIT, pure Python, vendored in backend/third_party with its licence and commit hash).
The HMAC stays; this module wraps the certificate, it does not touch the locked files.

    cd backend && python -m qacrs.v12.pqsign      -> qacrs/results/v12/pqsign.json   (T10)
"""
from __future__ import annotations

import copy
import hashlib
import json
import random
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent / "third_party"))
from dilithium_py.ml_dsa import ML_DSA_65  # noqa: E402

from qacrs import hassan as H  # noqa: E402
from qacrs import hassan_v9 as V9  # noqa: E402
from qacrs.v12 import risk_map as RM  # noqa: E402

OUT = HERE.parent / "results" / "v12"
ALG = "ML-DSA-65"


def keygen() -> tuple[bytes, bytes]:
    return ML_DSA_65.keygen()                      # (public, secret)


def canonical(cert: dict) -> bytes:
    return json.dumps(cert, sort_keys=True, separators=(",", ":")).encode()


def sign_certificate(cert: dict, sk: bytes, hmac_key: bytes) -> dict:
    """Return a sealed envelope: certificate + table hash + HMAC (locked) + ML-DSA signature over all of it."""
    body = {"certificate": cert, "risk_table_hash": RM.table_hash(), "alg": ALG}
    body["hmac"] = H.sign(body["certificate"], hmac_key)
    body["sig"] = ML_DSA_65.sign(sk, canonical({k: v for k, v in body.items() if k != "sig"})).hex()
    return body


def verify_envelope(env: dict, pk: bytes, hmac_key: bytes, net=None, sc=None) -> bool:
    """All three must hold: ML-DSA signature, HMAC, and (if net/sc given) the v9 independent checker."""
    try:
        unsigned = {k: v for k, v in env.items() if k != "sig"}
        if not ML_DSA_65.verify(pk, canonical(unsigned), bytes.fromhex(env["sig"])):
            return False
        if env.get("alg") != ALG or env.get("risk_table_hash") != RM.table_hash():
            return False
        if not H.verify_signature(env["certificate"], env["hmac"], hmac_key):
            return False
        if net is not None and sc is not None and not V9.verify_certificate_v9(net, sc, env["certificate"]):
            return False
        return True
    except Exception:  # noqa: BLE001 - any malformed envelope is a rejection
        return False


# ------------------------------------------------------------------ T10 ------------------------------------------
def tamper(env: dict, rng: random.Random, net) -> tuple[dict, str]:
    """The five v9 tampering kinds applied to a sealed envelope, plus two envelope-level kinds."""
    e = copy.deepcopy(env); c = e["certificate"]
    machines = [m.name for m in net.machines]
    kind = rng.choice(("naive_add_isolation", "status_flip", "claims_edit", "smart_remove_action",
                       "sig_bitflip", "table_hash_swap", "resign_with_other_key"))
    if kind == "naive_add_isolation":
        extra = [m for m in machines if m not in c["isolate"]]
        if extra: c["isolate"] = sorted(set(c["isolate"]) | {rng.choice(extra)})
        else: kind = "status_flip"
    if kind == "status_flip":
        c["status"] = "CONTAINED" if c["status"] != "CONTAINED" else "ESCALATED"
    elif kind == "claims_edit":
        if c["claims"]["services_down"] or c["claims"]["open_paths_after"]:
            c["claims"]["services_down"] = []
            c["claims"]["open_paths_after"] = []
        else:                                   # nothing to erase: claim a service is down that is not
            c["claims"]["services_down"] = ["phantom_service"]
    elif kind == "smart_remove_action":
        if c["isolate"]: c["isolate"] = c["isolate"][:-1]
        elif c["segment"]: c["segment"] = c["segment"][:-1]
        else: c["status"] = "CONTAINED"
    elif kind == "sig_bitflip":
        b = bytearray(bytes.fromhex(e["sig"])); i = rng.randrange(len(b)); b[i] ^= 1 << rng.randrange(8); e["sig"] = bytes(b).hex()
    elif kind == "table_hash_swap":
        e["risk_table_hash"] = "0" * 16
    elif kind == "resign_with_other_key":
        _, sk2 = keygen()
        e["sig"] = ML_DSA_65.sign(sk2, canonical({k: v for k, v in e.items() if k != "sig"})).hex()
    return e, kind


def main() -> None:
    from qacrs import phase16_v11 as P16
    rng = random.Random(V9.TAMPER_SEED)
    pk, sk = keygen(); hmac_key = b"demo-hmac-key-not-a-secret"
    base = []; t_sign = []; t_verify = []; checker_rejects = []
    for p in sorted(P16.INC.glob("*.json")):
        d, net, scs = P16.load(p)
        if net is None: continue
        eng = V9.EngineV9(net)
        for sc in scs:
            dd = eng.decide(sc)                       # the locked engine's own certificate (held/fallback/flags)
            cert = dd.certificate
            chk = V9.verify_certificate_v9(net, sc, cert)
            if not chk:                               # v9 observation on real data, published, not hidden
                checker_rejects.append({"scenario": sc.id, "isolate": cert["isolate"], "held": cert["held"],
                                        "claims": {k: v for k, v in cert["claims"].items() if isinstance(v, bool)}})
            t = time.perf_counter(); env = sign_certificate(cert, sk, hmac_key); t_sign.append(1000 * (time.perf_counter() - t))
            t = time.perf_counter(); ok = verify_envelope(env, pk, hmac_key, net if chk else None, sc if chk else None)
            t_verify.append(1000 * (time.perf_counter() - t))
            assert ok, sc.id
            base.append((net, sc, env, chk))
    rejected = {}; accepted = []
    for i in range(1000):
        net, sc, env, chk = base[i % len(base)]
        bad, kind = tamper(env, rng, net)
        ok = verify_envelope(bad, pk, hmac_key, net if chk else None, sc if chk else None)
        rejected.setdefault(kind, [0, 0]); rejected[kind][1] += 1
        if ok: accepted.append({"scenario": sc.id, "kind": kind})
        else: rejected[kind][0] += 1
    med = lambda v: sorted(v)[len(v) // 2]  # noqa: E731
    res = {"alg": ALG, "library": "dilithium-py (MIT) vendored, commit 23cb5ee9", "n_certificates": len(base),
           "sign_ms_median": round(med(t_sign), 2), "verify_ms_median": round(med(t_verify), 2),
           "sign_plus_verify_ms_median": round(med([a + b for a, b in zip(t_sign, t_verify)]), 2),
           "sig_bytes": len(bytes.fromhex(base[0][2]["sig"])), "pk_bytes": len(pk),
           "tamperings": 1000, "rejected_by_kind": rejected, "accepted_tamperings": accepted,
           "v9_checker_rejects_genuine_certificate": checker_rejects,
           "v9_observation": "On real incidents the locked v9 solver can place a critical server in the automatic "
                             "isolate set (gate: PENDING two-person), and the v9 rate limiter (3 automatic isolations "
                             "per 60 s) keeps 3 of the equal-risk hosts in an order that depends on set iteration; "
                             "when a critical server lands there the v9 checker rejects the engine's own certificate. "
                             "Not seen on synthetic data. Locked file, not changed; v12 decides without the limiter.",
           "T10": {"all_rejected": not accepted, "median_le_50ms": med([a + b for a, b in zip(t_sign, t_verify)]) <= 50,
                   "met": (not accepted) and med([a + b for a, b in zip(t_sign, t_verify)]) <= 50}}
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "pqsign.json").write_text(json.dumps(res, indent=1), encoding="utf-8")
    print(json.dumps({k: v for k, v in res.items() if k != "accepted_tamperings"}, indent=1))


if __name__ == "__main__":
    main()
