"""The verifier: four states, tamper detection, content, chains — all offline."""
import json

from asexec import keys, manifest
from asexec.verifier import verify_paths


def test_fulfilled(make_commitment):
    c = make_commitment(n_receipts=1)
    rep = verify_paths([c["prereg"]] + c["receipts"], artifacts_dir=c["artifacts"])
    assert rep["ok"] is True
    assert rep["commitments"][0]["state"] == "fulfilled"
    assert rep["commitments"][0]["chain_ok"] is True
    assert rep["commitments"][0]["key_consistent"] is True


def test_open_when_window_future_and_no_receipt(make_commitment):
    c = make_commitment(closes="2099-01-01T00:00:00Z", n_receipts=0)
    rep = verify_paths([c["prereg"]])
    assert rep["commitments"][0]["state"] == "open"
    assert rep["ok"] is True


def test_elapsed_no_receipt(make_commitment):
    c = make_commitment(closes="2000-01-01T00:00:00Z", n_receipts=0)
    rep = verify_paths([c["prereg"]])
    assert rep["commitments"][0]["state"] == "elapsed-no-receipt"


def test_notarization_only(make_commitment):
    c = make_commitment(n_receipts=1)
    # verify the receipt WITHOUT its pre-registration
    rep = verify_paths(c["receipts"])
    assert rep["notarization_only"]
    assert rep["commitments"] == []


def test_tampered_receipt_fails(make_commitment):
    c = make_commitment(n_receipts=1)
    rp = c["receipts"][0]
    m = json.loads(open(rp).read())
    m["payload"]["target_identity"]["model_id"] = "SWAPPED"  # alter signed content
    open(rp, "w").write(json.dumps(m))
    rep = verify_paths([c["prereg"], rp], artifacts_dir=c["artifacts"])
    assert rep["ok"] is False
    sigs = {x["path"]: x["signature"]["signature_ok"] for x in rep["manifests"]}
    assert sigs[rp] is False


def test_content_mismatch_detected(make_commitment):
    c = make_commitment(n_receipts=1)
    # change an artifact after sealing
    import os
    (os.path.join(c["artifacts"], "harness", "eval.py"))
    open(os.path.join(c["artifacts"], "harness", "eval.py"), "w").write("TAMPERED\n")
    rep = verify_paths([c["prereg"]] + c["receipts"], artifacts_dir=c["artifacts"])
    assert rep["ok"] is False
    assert any(m["content"]["status"] == "mismatch" for m in rep["manifests"])


def test_chain_gap_detected(make_commitment):
    c = make_commitment(n_receipts=2)
    # drop the first receipt: second's prev_hash now points to a missing manifest
    rep = verify_paths([c["prereg"], c["receipts"][1]], artifacts_dir=c["artifacts"])
    assert rep["commitments"][0]["chain_ok"] is False


def test_foreign_key_still_verifies_offline(make_commitment):
    # fake-pass guard: verifier trusts nothing but the files; a commitment from a
    # DIFFERENT key than any local key still verifies structurally.
    priv, pub = keys.generate()
    c = make_commitment(n_receipts=1, priv=priv, pub=pub)
    rep = verify_paths([c["prereg"]] + c["receipts"], artifacts_dir=c["artifacts"])
    assert rep["ok"] is True
    assert rep["manifests"][0]["keyid"] == keys.keyid_for(pub)


def test_receipts_from_wrong_key_flagged(make_commitment):
    c = make_commitment(n_receipts=1)
    # re-sign the receipt with a different key -> key inconsistency vs the prereg
    other_priv, other_pub = keys.generate()
    body = manifest.get_body(manifest.load(c["receipts"][0]))
    manifest.save(manifest.sign(body, other_priv, other_pub), c["receipts"][0])
    rep = verify_paths([c["prereg"]] + c["receipts"], artifacts_dir=c["artifacts"])
    assert rep["commitments"][0]["key_consistent"] is False
