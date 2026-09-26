"""
In-memory token state (Member B): which token_ids have been revoked, and
which (token_id, nonce) pairs have already been used.
"""
from __future__ import annotations

import threading
from typing import Set, Tuple


class TokenState:
    def __init__(self):
        self._revoked_token_ids: Set[str] = set()
        self._seen_nonces: Set[Tuple[str, str]] = set()
        self._lock = threading.Lock()

    def revoke(self, token_id: str) -> None:
        with self._lock:
            self._revoked_token_ids.add(token_id)

    def is_revoked(self, token_id: str) -> bool:
        with self._lock:
            return token_id in self._revoked_token_ids

    def nonce_already_used(self, token_id: str, nonce: str) -> bool:
        with self._lock:
            return (token_id, nonce) in self._seen_nonces

    def mark_nonce_used(self, token_id: str, nonce: str) -> None:
        with self._lock:
            self._seen_nonces.add((token_id, nonce))