import math
import random

import pytest

from common.canonical import leaf_hash, node_hash, sha256
from common.crypto_utils import derive_did, generate_keypair, public_key_bytes
from fog.merkle.merkle_tree import MerkleTree, compute_root, verify_proof


def fake_leaves(n):
    return [sha256(f"device{i}".encode()) for i in range(n)]


def real_leaves(n):
    out = []
    for _ in range(n):
        pk = public_key_bytes(generate_keypair())
        out.append(leaf_hash(derive_did(pk), pk))
    return out


# ---------- hand computed roots ----------

def test_one_leaf_root_is_the_leaf():
    [a] = fake_leaves(1)
    t = MerkleTree([a])
    assert t.root == a
    assert t.get_proof(a) == []
    assert verify_proof(a, [], t.root)


def test_two_leaves():
    a, b = sorted(fake_leaves(2))
    assert MerkleTree([a, b]).root == node_hash(a, b)


def test_three_leaves_promotes_last():
    a, b, c = sorted(fake_leaves(3))
    # level1 = [H(a,b), c]   (c promoted)   root = H(H(a,b), c)
    assert MerkleTree([a, b, c]).root == node_hash(node_hash(a, b), c)


def test_four_leaves():
    a, b, c, d = sorted(fake_leaves(4))
    assert MerkleTree([a, b, c, d]).root == node_hash(node_hash(a, b), node_hash(c, d))


def test_five_leaves():
    a, b, c, d, e = sorted(fake_leaves(5))
    left = node_hash(node_hash(a, b), node_hash(c, d))
    assert MerkleTree([a, b, c, d, e]).root == node_hash(left, e)


def test_seven_leaves():
    a, b, c, d, e, f, g = sorted(fake_leaves(7))
    left = node_hash(node_hash(a, b), node_hash(c, d))
    right = node_hash(node_hash(e, f), g)
    assert MerkleTree([a, b, c, d, e, f, g]).root == node_hash(left, right)


# ---------- every proof verifies, for many sizes including odd ones ----------

@pytest.mark.parametrize("n", [1, 2, 3, 4, 5, 6, 7, 8, 9, 15, 16, 17, 33, 100])
def test_all_proofs_verify(n):
    leaves = real_leaves(n) if n <= 17 else fake_leaves(n)
    t = MerkleTree(leaves)
    for leaf in leaves:
        proof = t.get_proof(leaf)
        assert verify_proof(leaf, proof, t.root)
        assert verify_proof(leaf.hex(), proof, t.root_hex)       # hex inputs work too
        assert len(proof) <= math.ceil(math.log2(n)) if n > 1 else len(proof) == 0


def test_order_independence():
    leaves = fake_leaves(25)
    shuffled = leaves[:]
    random.shuffle(shuffled)
    assert compute_root(leaves) == compute_root(shuffled)


# ---------- tampering must fail ----------

def _flip_bit(hex_str):
    b = bytearray(bytes.fromhex(hex_str))
    b[0] ^= 0x01
    return b.hex()


@pytest.mark.parametrize("n", [2, 3, 5, 7, 16])
def test_tampered_sibling_fails(n):
    leaves = fake_leaves(n)
    t = MerkleTree(leaves)
    for leaf in leaves:
        proof = t.get_proof(leaf)
        for i in range(len(proof)):
            bad = [dict(s) for s in proof]
            bad[i]["sibling"] = _flip_bit(bad[i]["sibling"])
            assert not verify_proof(leaf, bad, t.root)


def test_swapped_side_fails():
    leaves = fake_leaves(8)
    t = MerkleTree(leaves)
    proof = t.get_proof(leaves[0])
    bad = [dict(s) for s in proof]
    bad[0]["side"] = "L" if bad[0]["side"] == "R" else "R"
    assert not verify_proof(leaves[0], bad, t.root)


def test_tampered_identity_fails():
    key = generate_keypair()
    pk = public_key_bytes(key)
    did = derive_did(pk)
    leaves = real_leaves(6) + [leaf_hash(did, pk)]
    t = MerkleTree(leaves)
    proof = t.get_proof(leaf_hash(did, pk))

    other_pk = public_key_bytes(generate_keypair())
    assert not verify_proof(leaf_hash(did, other_pk), proof, t.root)                       # swapped key
    assert not verify_proof(leaf_hash(did[:-1] + "0" if did[-1] != "0" else did[:-1] + "1", pk), proof, t.root)  # edited DID


def test_wrong_root_and_malformed_input_fail():
    leaves = fake_leaves(4)
    t = MerkleTree(leaves)
    proof = t.get_proof(leaves[1])
    assert not verify_proof(leaves[1], proof, sha256(b"other root"))
    assert not verify_proof(leaves[1], proof, "not hex")
    assert not verify_proof(leaves[1], [{"sibling": "zz", "side": "L"}], t.root)
    assert not verify_proof(leaves[1], [{"sibling": proof[0]["sibling"], "side": "X"}], t.root)
    assert not verify_proof(leaves[1], [{"side": "L"}], t.root)


def test_extra_leaf_changes_root():
    leaves = fake_leaves(4)
    assert compute_root(leaves) != compute_root(leaves + [sha256(b"intruder")])


# ---------- input validation ----------

def test_empty_and_duplicate_rejected():
    with pytest.raises(ValueError):
        MerkleTree([])
    a = sha256(b"a")
    with pytest.raises(ValueError):
        MerkleTree([a, a])


def test_unknown_leaf_has_no_proof():
    t = MerkleTree(fake_leaves(3))
    with pytest.raises(KeyError):
        t.get_proof(sha256(b"not registered"))