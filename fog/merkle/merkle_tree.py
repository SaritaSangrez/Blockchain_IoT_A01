"""
Binary Merkle tree over device leaves.

Design decisions (document these in the report):
  1. Leaves are sorted by their byte value before building, so the same
     set of devices always gives the same root regardless of arrival order.
  2. Node hashing uses the 0x01 prefix from common.canonical.node_hash.
  3. Odd node count: the unpaired last node is PROMOTED unchanged to the
     next level (not duplicated). A promoted node adds no step to the proof.
  4. Duplicate leaves are rejected: the same DID+PK cannot appear twice.
  5. A proof step stores the sibling hash AND the side the sibling is on.
"""
from __future__ import annotations

from typing import Dict, List, Sequence, Union

from common.canonical import HASH_LEN, node_hash

ProofPath = List[Dict[str, str]]
HexOrBytes = Union[str, bytes]


def _as_bytes(value: HexOrBytes) -> bytes:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    return bytes.fromhex(value)


class MerkleTree:
    def __init__(self, leaves: Sequence[bytes], sort: bool = True):
        if len(leaves) == 0:
            raise ValueError("cannot build a Merkle tree with zero leaves")
        leaves = [bytes(leaf) for leaf in leaves]
        for leaf in leaves:
            if len(leaf) != HASH_LEN:
                raise ValueError("every leaf must be a 32 byte hash")
        if len(set(leaves)) != len(leaves):
            raise ValueError("duplicate leaf detected")

        self.leaves: List[bytes] = sorted(leaves) if sort else list(leaves)
        self._index: Dict[bytes, int] = {leaf: i for i, leaf in enumerate(self.leaves)}
        self.levels: List[List[bytes]] = self._build(self.leaves)

    @staticmethod
    def _build(leaves: List[bytes]) -> List[List[bytes]]:
        levels = [leaves]
        current = leaves
        while len(current) > 1:
            nxt = []
            for i in range(0, len(current), 2):
                if i + 1 < len(current):
                    nxt.append(node_hash(current[i], current[i + 1]))
                else:
                    nxt.append(current[i])  # promote the unpaired node
            levels.append(nxt)
            current = nxt
        return levels

    # ---------- read access ----------

    @property
    def root(self) -> bytes:
        return self.levels[-1][0]

    @property
    def root_hex(self) -> str:
        return self.root.hex()

    @property
    def size(self) -> int:
        return len(self.leaves)

    @property
    def height(self) -> int:
        """Number of hashing levels above the leaves."""
        return len(self.levels) - 1

    def contains(self, leaf: HexOrBytes) -> bool:
        return _as_bytes(leaf) in self._index

    def index_of(self, leaf: HexOrBytes) -> int:
        leaf = _as_bytes(leaf)
        if leaf not in self._index:
            raise KeyError("leaf is not in this tree")
        return self._index[leaf]

    # ---------- proofs ----------

    def get_proof(self, leaf: HexOrBytes) -> ProofPath:
        """
        Ordered sibling hashes from the leaf up to the root.
        side = "L" means the sibling is on the left:  parent = H(sibling || current)
        side = "R" means the sibling is on the right: parent = H(current || sibling)
        """
        index = self.index_of(leaf)
        path: ProofPath = []
        for level in self.levels[:-1]:
            sibling = index ^ 1
            if sibling < len(level):
                side = "L" if sibling < index else "R"
                path.append({"sibling": level[sibling].hex(), "side": side})
            # else: this node was promoted, no hashing at this level
            index //= 2
        return path

    @staticmethod
    def verify_proof(leaf: HexOrBytes, proof_path: ProofPath, root: HexOrBytes) -> bool:
        """
        Recompute the root from a leaf and its proof path and compare it with
        the trusted root. Returns False (never raises) on malformed input,
        because the verifier receives these values from untrusted devices.
        """
        try:
            expected = _as_bytes(root)
        except (ValueError, TypeError):
            return False
        if len(expected) != HASH_LEN:
            return False
        reconstructed = reconstruct_root(leaf, proof_path)
        return reconstructed is not None and reconstructed == expected


def reconstruct_root(leaf: HexOrBytes, proof_path: ProofPath):
    """
    Climb from the leaf to the root using the proof path.
    Returns the candidate root (32 bytes) or None if the input is malformed.
    Used by the verifier and by the demo/attack scripts to SHOW the root.
    """
    try:
        current = _as_bytes(leaf)
        if len(current) != HASH_LEN:
            return None
        for step in proof_path:
            sibling = _as_bytes(step["sibling"])
            if len(sibling) != HASH_LEN:
                return None
            if step["side"] == "L":
                current = node_hash(sibling, current)
            elif step["side"] == "R":
                current = node_hash(current, sibling)
            else:
                return None
        return current
    except (ValueError, KeyError, TypeError):
        return None


def compute_root(leaves: Sequence[bytes]) -> bytes:
    """Convenience: root of a leaf set (used by benchmarks and tamper checks)."""
    return MerkleTree(leaves).root


# Module level alias so the partner can import the function directly:
#   from fog.merkle.merkle_tree import verify_proof
verify_proof = MerkleTree.verify_proof


if __name__ == "__main__":
    from common.canonical import sha256
    from common.logger import ok, short, step

    step("Merkle tree self check with 7 fake leaves")
    fake = [sha256(f"device{i}".encode()) for i in range(7)]
    tree = MerkleTree(fake)
    print(f"root   = {tree.root_hex}")
    print(f"height = {tree.height}")
    for leaf in tree.leaves:
        proof = tree.get_proof(leaf)
        assert verify_proof(leaf, proof, tree.root)
        ok("merkle", f"leaf {short(leaf.hex())} proof length {len(proof)} verified")