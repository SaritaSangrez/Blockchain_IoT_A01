"""
Local blockchain used as the trusted root registry.

Each block anchors ONE epoch root. A block contains:
    block_index, epoch_id, root, leaf_count, timestamp, fog_id, prev_hash
The fog signs the canonical JSON of those fields, and
    block_hash = SHA256(canonical_json(body + signature))
Each block stores the previous block_hash, so editing any old block breaks
every later link. verify_chain() detects this.

Epochs are FROZEN: an epoch root can be anchored only once, so historical
proofs keep verifying against their original root (needed for revocation demo).
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from common.canonical import canonical_json, sha256
from common.crypto_utils import public_key_bytes, sign, verify
from common.schemas import AnchorRecord

GENESIS_PREV_HASH = "0" * 64
BODY_FIELDS = ("block_index", "epoch_id", "root", "leaf_count", "timestamp", "fog_id", "prev_hash")


class LedgerError(Exception):
    pass


def _body(block: Dict) -> Dict:
    return {k: block[k] for k in BODY_FIELDS}


def _block_hash(body: Dict, signature_hex: str) -> str:
    return sha256(canonical_json({**body, "signature": signature_hex})).hex()


class Ledger:
    def __init__(self, path: Path, signing_key, fog_id: str = "fog_A"):
        self.path = Path(path)
        self.signing_key = signing_key
        self.fog_id = fog_id
        self.fog_pk = public_key_bytes(signing_key)
        self.blocks: List[Dict] = []
        self._root_cache: Dict[int, str] = {}
        self._load()

    # ---------- persistence ----------

    def _load(self) -> None:
        if self.path.exists() and self.path.stat().st_size > 0:
            self.blocks = json.loads(self.path.read_text(encoding="utf-8"))
        self._root_cache = {b["epoch_id"]: b["root"] for b in self.blocks}

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.blocks, indent=2), encoding="utf-8")
        os.replace(tmp, self.path)  # atomic on Windows and Linux

    # ---------- write ----------

    def anchor_root(self, epoch_id: int, root_hex: str, leaf_count: int) -> AnchorRecord:
        if epoch_id in self._root_cache:
            raise LedgerError(f"epoch {epoch_id} is already anchored (epochs are immutable)")
        if len(bytes.fromhex(root_hex)) != 32:
            raise LedgerError("root must be a 32 byte hash in hex")

        prev_hash = self.blocks[-1]["block_hash"] if self.blocks else GENESIS_PREV_HASH
        body = {
            "block_index": len(self.blocks),
            "epoch_id": int(epoch_id),
            "root": root_hex,
            "leaf_count": int(leaf_count),
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "fog_id": self.fog_id,
            "prev_hash": prev_hash,
        }
        signature_hex = sign(self.signing_key, canonical_json(body)).hex()
        block = {**body, "signature": signature_hex, "block_hash": _block_hash(body, signature_hex)}

        self.blocks.append(block)
        self._root_cache[block["epoch_id"]] = root_hex
        self._save()
        return AnchorRecord(**block)

    # ---------- read ----------

    def get_root(self, epoch_id: int) -> Optional[str]:
        """Trusted root for an epoch, or None if that epoch was never anchored."""
        return self._root_cache.get(int(epoch_id))

    def get_block(self, epoch_id: int) -> Optional[AnchorRecord]:
        for b in self.blocks:
            if b["epoch_id"] == int(epoch_id):
                return AnchorRecord(**b)
        return None

    def latest_epoch(self) -> Optional[int]:
        return self.blocks[-1]["epoch_id"] if self.blocks else None

    def __len__(self) -> int:
        return len(self.blocks)

    # ---------- integrity ----------

    def verify_chain(self, trusted_fog_pk: Optional[bytes] = None) -> Tuple[bool, str]:
        """
        Re-read the file from disk (so tampering on disk is caught) and check:
          block index sequence, prev_hash links, block hashes, fog signatures.
        """
        pk = trusted_fog_pk or self.fog_pk
        blocks = json.loads(self.path.read_text(encoding="utf-8")) if self.path.exists() else []
        prev = GENESIS_PREV_HASH
        for i, b in enumerate(blocks):
            try:
                body = _body(b)
            except KeyError as e:
                return False, f"block {i}: missing field {e}"
            if b["block_index"] != i:
                return False, f"block {i}: wrong index {b['block_index']}"
            if b["prev_hash"] != prev:
                return False, f"block {i}: prev_hash does not link to block {i - 1}"
            if not verify(pk, canonical_json(body), bytes.fromhex(b["signature"])):
                return False, f"block {i}: fog signature invalid (contents were modified)"
            if _block_hash(body, b["signature"]) != b["block_hash"]:
                return False, f"block {i}: block_hash mismatch"
            prev = b["block_hash"]
        return True, f"chain valid ({len(blocks)} blocks)"