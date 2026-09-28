"""
In-memory runtime state for Phase 2 / Phase 3 (Member B).

NonceBook   fog-issued, single-use, short-lived nonces. A device asks the fog
            for a fresh nonce before EVERY resource request and signs it.
            The fog accepts a nonce only if
              * the fog itself issued it (devices cannot invent nonces),
              * it was issued for this purpose and this subject
                (a token_id for Phase 2, a DID for Phase 3),
              * it has not expired, and
              * it has never been used before.
            A used nonce is remembered until it expires, so an exact replay
            is reported as "nonce_reused". Expired entries are purged, which
            keeps memory bounded.

TokenState  issued and revoked token ids, plus the NonceBook.
"""
from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass
from typing import Dict, Optional, Set

NONCE_TTL_SECONDS = 30

# consume() results
NONCE_OK = "ok"
NONCE_UNKNOWN = "nonce_unknown"      # never issued by this fog (or already purged)
NONCE_WRONG_SUBJECT = "nonce_not_for_this_request"
NONCE_EXPIRED = "nonce_expired"
NONCE_REUSED = "nonce_reused"


@dataclass
class _NonceEntry:
    purpose: str
    subject: str
    expires_at: float
    used: bool = False


class NonceBook:
    def __init__(self, ttl_seconds: float = NONCE_TTL_SECONDS):
        self.ttl = ttl_seconds
        self._entries: Dict[str, _NonceEntry] = {}
        self._lock = threading.Lock()

    def _purge(self, now: float) -> None:
        dead = [n for n, e in self._entries.items() if now > e.expires_at]
        for n in dead:
            del self._entries[n]

    def issue(self, purpose: str, subject: str) -> str:
        now = time.time()
        nonce = secrets.token_hex(16)
        with self._lock:
            self._purge(now)
            self._entries[nonce] = _NonceEntry(purpose, subject, now + self.ttl)
        return nonce

    def consume(self, purpose: str, subject: str, nonce: str) -> str:
        """Single use: the nonce is burned on the first attempt, pass or fail
        (same rule as the Phase 1 PoP challenge)."""
        now = time.time()
        with self._lock:
            e = self._entries.get(nonce)
            if e is None:
                return NONCE_UNKNOWN
            if e.purpose != purpose or e.subject != subject:
                return NONCE_WRONG_SUBJECT
            if e.used:
                return NONCE_REUSED
            if now > e.expires_at:
                del self._entries[nonce]
                return NONCE_EXPIRED
            e.used = True
            return NONCE_OK

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)


class TokenState:
    def __init__(self, nonce_ttl_seconds: float = NONCE_TTL_SECONDS):
        self._issued: Dict[str, str] = {}          # token_id -> did
        self._revoked_token_ids: Set[str] = set()
        self._lock = threading.Lock()
        self.nonces = NonceBook(nonce_ttl_seconds)

    # ---------- tokens ----------

    def record_issued(self, token_id: str, did: str) -> None:
        with self._lock:
            self._issued[token_id] = did

    def was_issued(self, token_id: str) -> bool:
        with self._lock:
            return token_id in self._issued

    def owner_of(self, token_id: str) -> Optional[str]:
        with self._lock:
            return self._issued.get(token_id)

    def tokens_of(self, did: str) -> list:
        with self._lock:
            return [t for t, d in self._issued.items() if d == did]

    def revoke(self, token_id: str) -> None:
        with self._lock:
            self._revoked_token_ids.add(token_id)

    def is_revoked(self, token_id: str) -> bool:
        with self._lock:
            return token_id in self._revoked_token_ids
