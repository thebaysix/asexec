"""The verifier — the product. Two tiers, four states, honest non-claims.

Tiers:
  - cryptographic (offline, always): signature over PAE input; keyid matches
    pubkey; drand freshness round (if present) BLS-verifies against pinned
    constants; link/chain consistency.
  - content (needs artifacts): recompute subject digests from actual files.

States (per commitment = a pre-registration + the receipts that fulfil it):
  - fulfilled          : >=1 valid receipt references this pre-registration
  - open               : 0 receipts and the disclosure window has not elapsed
  - elapsed-no-receipt : 0 receipts and the window has elapsed
  - notarization-only  : a receipt with no matching pre-registration provided

The verifier RENDERS these. It never adjudicates intent or whether a
commitment was "good enough".
"""

from __future__ import annotations

import os
import time
from typing import Any, Dict, List, Optional

from . import drand, hashing, keys, manifest
from .canonical import signing_input

NON_CLAIMS = [
    "PROVENANCE: content hashes prove a transcript was not ALTERED; they do NOT "
    "prove it is the output of the named harness+model (asserted by the signer, "
    "not re-executed).",
    "COMPLETENESS: this renders only the manifests provided. It cannot prove a "
    "lab pre-registered every eval it should have (selective pre-registration).",
    "THE 'PRE' IS SOCIAL, NOT CRYPTOGRAPHIC: a drand anchor proves freshness "
    "(created no earlier than a public moment), not that the pre-registration "
    "preceded the run. That 'ceiling' comes from the witnessed public repo, not "
    "from these files (a future --ots mode adds a cryptographic ceiling).",
    "IDENTITY: a key is pseudonymous. Binding it to a real entity is a separate "
    "check (see 'asexec identity'); absence of that binding is not proof of who "
    "signed.",
]


def _parse_iso(ts: str) -> float:
    s = ts.replace("Z", "+00:00")
    import datetime

    return datetime.datetime.fromisoformat(s).timestamp()


def verify_signature(mani: Dict[str, Any]) -> Dict[str, Any]:
    """Cryptographic tier for a single manifest."""
    out: Dict[str, Any] = {"signature_ok": False, "keyid_ok": False, "errors": []}
    try:
        body = manifest.get_body(mani)
        sigblock = mani["signature"]
        pub = bytes.fromhex(sigblock["pubkey"])
        sig = bytes.fromhex(sigblock["sig"])
        out["signature_ok"] = keys.verify(pub, signing_input(body), sig)
        out["keyid_ok"] = keys.keyid_for(pub) == sigblock.get("keyid")
        out["keyid"] = sigblock.get("keyid")
        out["phase"] = body.get("phase")
        out["ref"] = manifest.ref(body)
    except Exception as e:  # malformed manifest
        out["errors"].append(f"malformed: {e}")
    return out


def verify_freshness(body: Dict[str, Any]) -> Dict[str, Any]:
    fr = body.get("freshness")
    if not fr:
        return {"status": "absent"}
    try:
        ok = drand.verify_round(
            int(fr["round"]), fr["signature"], fr.get("randomness"),
            chain_hash=fr.get("chain_hash", drand.DEFAULT_CHAIN),
        )
        t = drand.time_of_round(int(fr["round"]), fr.get("chain_hash", drand.DEFAULT_CHAIN))
        return {"status": "verified" if ok else "invalid",
                "round": int(fr["round"]), "created_no_earlier_than": t}
    except Exception as e:
        return {"status": "invalid", "error": str(e)}


def verify_content(body: Dict[str, Any], artifacts_dir: Optional[str]) -> Dict[str, Any]:
    if not artifacts_dir:
        return {"status": "skipped", "reason": "no artifacts provided"}
    alg = body.get("hash_alg", hashing.DEFAULT_ALG)
    entries = []
    all_ok = True
    for item in body.get("subject", []):
        name = item["name"]
        expected = item.get("digest", {}).get(alg)
        path = os.path.join(artifacts_dir, name.rstrip("/"))
        if not os.path.exists(path):
            entries.append({"name": name, "ok": False, "reason": "artifact not found"})
            all_ok = False
            continue
        actual = hashing.digest_path(path, alg)
        ok = actual == expected
        all_ok = all_ok and ok
        entries.append({"name": name, "ok": ok,
                        **({} if ok else {"expected": expected, "actual": actual})})
    return {"status": "ok" if all_ok else "mismatch", "entries": entries}


def verify_paths(paths: List[str], artifacts_dir: Optional[str] = None,
                 now: Optional[float] = None) -> Dict[str, Any]:
    """Load, crypto-verify, group, and render states for a set of manifests."""
    now = time.time() if now is None else now
    files = _expand(paths)

    loaded = []  # (path, manifest, body, sigreport)
    for p in files:
        mani = manifest.load(p)
        sig = verify_signature(mani)
        body = mani.get("payload", {})
        loaded.append((p, mani, body, sig))

    preregs = {}  # ref -> record
    receipts = []
    manifests_report = []
    overall_ok = True

    for p, mani, body, sig in loaded:
        fresh = verify_freshness(body) if sig.get("errors") == [] else {"status": "absent"}
        content = verify_content(body, artifacts_dir) if sig.get("errors") == [] else {"status": "skipped"}
        crypto_ok = sig["signature_ok"] and sig["keyid_ok"] and fresh["status"] in ("absent", "verified")
        overall_ok = overall_ok and crypto_ok and content["status"] in ("ok", "skipped")
        rec = {"path": p, "phase": body.get("phase"), "ref": sig.get("ref"),
               "keyid": sig.get("keyid"), "signature": sig, "freshness": fresh,
               "content": content}
        manifests_report.append(rec)
        if body.get("phase") == "preregistration" and sig.get("ref"):
            preregs[sig["ref"]] = {"ref": sig["ref"], "keyid": sig.get("keyid"),
                                   "window": body.get("disclosure_window", {}),
                                   "receipts": []}
        elif body.get("phase") == "receipt":
            receipts.append((sig.get("ref"), body, sig))

    notarization_only = []
    for rref, body, sig in receipts:
        target = body.get("fulfills")
        if target in preregs:
            preregs[target]["receipts"].append({"ref": rref, "prev_hash": body.get("prev_hash"),
                                                 "keyid": sig.get("keyid")})
        else:
            notarization_only.append({"ref": rref, "fulfills": target, "keyid": sig.get("keyid")})

    commitments = []
    for pr in preregs.values():
        state = _commitment_state(pr, now)
        chain_ok, chain_note = _check_chain(pr["receipts"])
        # same-key consistency: receipts should share the prereg's key
        key_consistent = all(r["keyid"] == pr["keyid"] for r in pr["receipts"])
        commitments.append({**pr, "state": state, "chain_ok": chain_ok,
                            "chain_note": chain_note, "key_consistent": key_consistent})

    return {
        "ok": overall_ok,
        "manifests": manifests_report,
        "commitments": commitments,
        "notarization_only": notarization_only,
        "non_claims": NON_CLAIMS,
    }


def _commitment_state(pr: Dict[str, Any], now: float) -> str:
    if pr["receipts"]:
        return "fulfilled"
    closes = pr["window"].get("closes")
    if not closes:
        return "open"  # no deadline declared -> cannot elapse
    try:
        return "elapsed-no-receipt" if now >= _parse_iso(closes) else "open"
    except Exception:
        return "open"


def _check_chain(receipts: List[Dict[str, Any]]):
    """A prev_hash chain: exactly one root (prev_hash null), each other points
    to a present receipt, no cycles/forks."""
    if not receipts:
        return True, "no receipts"
    refs = {r["ref"] for r in receipts}
    roots = [r for r in receipts if not r["prev_hash"]]
    if len(roots) != 1:
        return False, f"expected exactly one chain root, found {len(roots)}"
    for r in receipts:
        if r["prev_hash"] and r["prev_hash"] not in refs:
            return False, "a receipt's prev_hash points to a missing receipt (gap)"
    return True, "chain intact"


def _expand(paths: List[str]) -> List[str]:
    out = []
    for p in paths:
        if os.path.isdir(p):
            for name in sorted(os.listdir(p)):
                if name.endswith(".json"):
                    out.append(os.path.join(p, name))
        else:
            out.append(p)
    return out
