"""Manifest build/sign/ref + bedrock enforcement."""
import pytest

from asexec import keys, manifest
from asexec.canonical import signing_input
from asexec.errors import ManifestError


def _target():
    return {"kind": "api", "provider": "p", "model_id": "m", "endpoint": ""}


def _win():
    return {"closes": "2099-01-01T00:00:00Z"}


def test_ref_is_signature_independent():
    body = manifest.build_preregistration([{"name": "h/", "digest": {"sha-256": "00"}}],
                                          _target(), _win())
    priv1, pub1 = keys.generate()
    priv2, pub2 = keys.generate()
    m1 = manifest.sign(body, priv1, pub1)
    m2 = manifest.sign(dict(body), priv2, pub2)
    # different signatures, same body => same ref
    assert m1["signature"]["sig"] != m2["signature"]["sig"]
    assert manifest.ref(manifest.get_body(m1)) == manifest.ref(manifest.get_body(m2))


def test_sign_then_verify_matches():
    priv, pub = keys.generate()
    body = manifest.build_preregistration([{"name": "h/", "digest": {"sha-256": "00"}}],
                                          _target(), _win())
    m = manifest.sign(body, priv, pub)
    assert keys.verify(pub, signing_input(m["payload"]), bytes.fromhex(m["signature"]["sig"]))


def test_missing_bedrock_rejected():
    priv, pub = keys.generate()
    # no disclosure_window
    body = {"schema_version": "asexec/v1", "phase": "preregistration",
            "hash_alg": "sha-256", "subject": [{"name": "x"}], "target_identity": _target()}
    with pytest.raises(ManifestError):
        manifest.sign(body, priv, pub)


def test_receipt_requires_fulfills():
    priv, pub = keys.generate()
    body = manifest.build_preregistration([{"name": "h/", "digest": {"sha-256": "00"}}],
                                          _target(), _win())
    body["phase"] = "receipt"  # now it's a receipt with no fulfills
    with pytest.raises(ManifestError):
        manifest.sign(body, priv, pub)
