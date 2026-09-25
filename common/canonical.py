"""
Canonical serialization and hashing.

Every component (fog, device, verifier, tests) MUST use these functions.
If two components hash the same identity in different byte formats they
produce different leaves, and every proof breaks.

    leaf  = SHA256( 0x00 || DID_utf8 || 0x7C || PK_compressed )
    node  = SHA256( 0x01 || left || right )

0x00 and 0x01 are domain separation prefixes: a leaf hash can never be
confused with an internal node hash (prevents second preimage tricks).
0x7C is the byte for "|" and separates DID from public key.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"
SEPARATOR = b"|"

HASH_LEN = 32                 # SHA256 output size in bytes
COMPRESSED_PK_LEN = 33        # P256 compressed point size in bytes
POP_CONTEXT = b"IIOT_POP_V1"  # label bound into every proof of possession signature


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def leaf_hash(did: str, pk_bytes: bytes) -> bytes:
    """Ld = H(0x00 || DID || 0x7C || PK). Returns 32 raw bytes."""
    if not isinstance(did, str) or not did.startswith("did:iiot:"):
        raise ValueError(f"invalid DID: {did!r}")
    if not isinstance(pk_bytes, (bytes, bytearray)) or len(pk_bytes) != COMPRESSED_PK_LEN:
        raise ValueError("public key must be 33 bytes (compressed P256 point)")
    return sha256(LEAF_PREFIX + did.encode("utf-8") + SEPARATOR + bytes(pk_bytes))


def node_hash(left: bytes, right: bytes) -> bytes:
    """Internal node = H(0x01 || left || right)."""
    if len(left) != HASH_LEN or len(right) != HASH_LEN:
        raise ValueError("child hashes must be 32 bytes")
    return sha256(NODE_PREFIX + left + right)


def pop_message(challenge: bytes, did: str) -> bytes:
    """
    Exact bytes a device signs to prove possession of its private key.
    Binding the DID and a context label means the signature cannot be
    replayed for another identity or another protocol step.
    """
    return POP_CONTEXT + SEPARATOR + challenge + SEPARATOR + did.encode("utf-8")


def canonical_json(obj: Any) -> bytes:
    """Deterministic JSON: sorted keys, no spaces, UTF8. Used for signing records."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def to_hex(b: bytes) -> str:
    return bytes(b).hex()


def from_hex(s: str) -> bytes:
    return bytes.fromhex(s)