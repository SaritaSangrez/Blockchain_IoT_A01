"""
Initial trust: pre shared key (PSK) authentication.

The device sends, over TLS:
    Authorization: PSK <provisioning_id>:<psk_hex>
The fog stores only SHA256(psk), hashes the presented key and compares in
constant time (hmac.compare_digest) so timing does not leak information.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
from typing import Dict, Optional, Tuple


class PSKStore:
    def __init__(self, path: Optional[Path] = None, entries: Optional[Dict[str, str]] = None):
        if entries is not None:
            self._hashes = dict(entries)
        elif path is not None and Path(path).exists():
            self._hashes = json.loads(Path(path).read_text(encoding="utf-8"))
        else:
            self._hashes = {}

    @staticmethod
    def hash_psk(psk_hex: str) -> str:
        return hashlib.sha256(bytes.fromhex(psk_hex)).hexdigest()

    def __len__(self) -> int:
        return len(self._hashes)

    def check(self, provisioning_id: str, psk_hex: str) -> bool:
        stored = self._hashes.get(provisioning_id)
        try:
            presented = self.hash_psk(psk_hex)
        except ValueError:
            return False
        if stored is None:
            # still do a comparison so unknown IDs take similar time
            hmac.compare_digest(presented, "0" * 64)
            return False
        return hmac.compare_digest(presented, stored)


def parse_authorization(header: Optional[str]) -> Optional[Tuple[str, str]]:
    """'PSK temp01:abcd...' -> ('temp01', 'abcd...'), or None if malformed."""
    if not header:
        return None
    parts = header.strip().split(" ", 1)
    if len(parts) != 2 or parts[0] != "PSK" or ":" not in parts[1]:
        return None
    prov_id, psk = parts[1].split(":", 1)
    if not prov_id or not psk:
        return None
    return prov_id, psk