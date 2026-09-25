"""
Proof of possession (Phase 1 step 5).

1. Fog issues a fresh 32 byte random challenge with a short expiry.
2. Device signs pop_message(challenge, did) with its private key.
3. Fog verifies with the submitted public key.
A challenge is SINGLE USE: it is consumed on the first attempt, pass or fail,
so an old signature can never be replayed.
"""
from __future__ import annotations

import secrets
import time

from common.canonical import pop_message
from common.crypto_utils import verify
from fog.storage.device_store import Session


def issue_challenge(session: Session, ttl_seconds: int) -> str:
    session.challenge = secrets.token_bytes(32).hex()
    session.challenge_expires = time.time() + ttl_seconds
    session.challenge_used = False
    return session.challenge


def verify_pop(session: Session, signature_hex: str) -> tuple[bool, str]:
    """Returns (passed, reason). Always consumes the challenge."""
    if session.challenge is None or session.challenge_used:
        return False, "no active challenge (already used or never issued)"
    session.challenge_used = True

    if time.time() > session.challenge_expires:
        return False, "challenge expired"
    try:
        signature = bytes.fromhex(signature_hex)
    except ValueError:
        return False, "signature is not valid hex"

    message = pop_message(bytes.fromhex(session.challenge), session.did)
    if not verify(bytes.fromhex(session.public_key), message, signature):
        return False, "signature does not verify with the submitted public key"
    return True, "signature valid"