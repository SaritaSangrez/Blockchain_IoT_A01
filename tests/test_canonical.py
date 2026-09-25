import pytest

from common.canonical import canonical_json, leaf_hash, node_hash, pop_message, sha256
from common.crypto_utils import derive_did, generate_keypair, public_key_bytes, sign, verify


def _identity():
    key = generate_keypair()
    pk = public_key_bytes(key)
    return key, pk, derive_did(pk)


def test_leaf_is_deterministic_and_32_bytes():
    _, pk, did = _identity()
    assert leaf_hash(did, pk) == leaf_hash(did, pk)
    assert len(leaf_hash(did, pk)) == 32


def test_leaf_matches_documented_formula():
    _, pk, did = _identity()
    assert leaf_hash(did, pk) == sha256(b"\x00" + did.encode() + b"|" + pk)


def test_changing_did_or_pk_changes_leaf():
    _, pk, did = _identity()
    _, pk2, did2 = _identity()
    assert leaf_hash(did, pk) != leaf_hash(did2, pk)
    assert leaf_hash(did, pk) != leaf_hash(did, pk2)


def test_leaf_and_node_are_domain_separated():
    a, b = sha256(b"a"), sha256(b"b")
    assert node_hash(a, b) == sha256(b"\x01" + a + b)
    assert node_hash(a, b) != node_hash(b, a)


def test_leaf_rejects_bad_inputs():
    _, pk, did = _identity()
    with pytest.raises(ValueError):
        leaf_hash("temp01", pk)
    with pytest.raises(ValueError):
        leaf_hash(did, pk[:10])


def test_canonical_json_ignores_key_order():
    assert canonical_json({"b": 1, "a": 2}) == canonical_json({"a": 2, "b": 1})


def test_did_is_key_fingerprint():
    _, pk, did = _identity()
    assert did.startswith("did:iiot:") and len(did) == len("did:iiot:") + 16


def test_sign_verify_and_pop_binding():
    key, pk, did = _identity()
    _, _, other_did = _identity()
    challenge = b"\x07" * 32
    sig = sign(key, pop_message(challenge, did))
    assert verify(pk, pop_message(challenge, did), sig)
    assert not verify(pk, pop_message(challenge, other_did), sig)     # bound to DID
    assert not verify(pk, pop_message(b"\x08" * 32, did), sig)       # bound to challenge
    assert not verify(pk, b"garbage", b"not a signature")            # never raises