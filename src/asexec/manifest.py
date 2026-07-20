"""Manifest construction, signing, and referencing.

A manifest is a small envelope::

    {
      "payloadType": "application/vnd.asexec+json",
      "payload":  { ...the signed body... },
      "signature": {"alg":"ed25519","keyid":..., "pubkey":..., "sig":...}
    }

Only the ``payload`` (body) is signed, over the PAE construction in
``canonical.py``. Bespoke JSON, borrowing in-toto field names (`subject`,
`predicateType`, `predicate`-style `notes`) without the DSSE/in-toto tooling.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Optional

from . import PREDICATE_TYPE, SCHEMA_VERSION
from .canonical import canonical_bytes, signing_input
from .errors import ManifestError
from . import keys

# Mandatory fields whose absence breaks verifiability of commitment ->
# fulfillment / gap (the governing rule from the interview).
_BEDROCK = ("schema_version", "phase", "hash_alg", "subject", "target_identity", "disclosure_window")


def _base_body(phase: str, subject: List[dict], target_identity: dict,
               disclosure_window: dict, hash_alg: str) -> Dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "predicateType": PREDICATE_TYPE,
        "phase": phase,
        "hash_alg": hash_alg,
        "subject": subject,
        "target_identity": target_identity,
        "disclosure_window": disclosure_window,
    }


def _attach_optional(body: Dict[str, Any], *, freshness=None, identity=None,
                     provenance=None, repro_recipe=None, notes=None) -> Dict[str, Any]:
    if freshness is not None:
        body["freshness"] = freshness
    if identity is not None:
        body["identity"] = identity
    if provenance is not None:
        body["provenance"] = provenance
    if repro_recipe is not None:
        body["repro_recipe"] = repro_recipe
    if notes is not None:
        body["notes"] = notes
    return body


def build_preregistration(subject, target_identity, disclosure_window, *,
                          hash_alg="sha-256", **optional) -> Dict[str, Any]:
    body = _base_body("preregistration", subject, target_identity, disclosure_window, hash_alg)
    return _attach_optional(body, **optional)


def build_receipt(subject, target_identity, disclosure_window, *, fulfills,
                  prev_hash=None, hash_alg="sha-256", **optional) -> Dict[str, Any]:
    body = _base_body("receipt", subject, target_identity, disclosure_window, hash_alg)
    body["fulfills"] = fulfills
    body["prev_hash"] = prev_hash
    return _attach_optional(body, **optional)


def ref(body: Dict[str, Any]) -> str:
    """Stable content reference to a manifest body: ``sha-256:<hex>``.

    Computed over the canonical bytes of the body (signature-independent), so
    ``fulfills`` and ``prev_hash`` links are stable regardless of who signed.
    """
    return "sha-256:" + hashlib.sha256(canonical_bytes(body)).hexdigest()


def sign(body: Dict[str, Any], private_key: bytes, public_key: bytes) -> Dict[str, Any]:
    _check_bedrock(body)
    sig = keys.sign(private_key, signing_input(body))
    return {
        "payloadType": "application/vnd.asexec+json",
        "payload": body,
        "signature": {
            "alg": "ed25519",
            "keyid": keys.keyid_for(public_key),
            "pubkey": public_key.hex(),
            "sig": sig.hex(),
        },
    }


def _check_bedrock(body: Dict[str, Any]) -> None:
    missing = [f for f in _BEDROCK if f not in body or body[f] in (None, "", [], {})]
    if missing:
        raise ManifestError(f"manifest body missing mandatory field(s): {', '.join(missing)}")
    if body["phase"] == "receipt" and "fulfills" not in body:
        raise ManifestError("receipt manifest missing mandatory 'fulfills'")


def get_body(manifest: Dict[str, Any]) -> Dict[str, Any]:
    if "payload" not in manifest or "signature" not in manifest:
        raise ManifestError("not an asexec manifest (missing payload/signature)")
    return manifest["payload"]


def save(manifest: Dict[str, Any], path: str) -> None:
    with open(path, "w") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")


def load(path: str) -> Dict[str, Any]:
    with open(path) as f:
        return json.load(f)
