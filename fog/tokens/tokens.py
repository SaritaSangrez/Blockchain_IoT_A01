"""
Phase 2: temporary token issuance and access checking (Member B).

A device that already proved key ownership (PoP, Phase 1) but hasn't
been through a finalized batch yet can request a short-lived, fog-signed
token instead. It carries the device's identity, device_type, role, and
an expiry.

Anti-theft: every resource request using the token must ALSO be freshly
signed by the device's own private key (same idea as
fog/registration/pop.py's proof of possession). A copied token by itself
is not enough -- the attacker doesn't have the private key to sign with.
Anti-replay: every request needs a nonce the fog hasn't seen before.
"""
from __future__ import annotations

import secrets
import time

from common.canonical import canonical_json
from common.crypto_utils import public_key_bytes, sign, verify

TOKEN_TTL_SECONDS = 120
TOKEN_ACCESS_LABEL = b"IIOT_TOKEN_ACCESS_V1"


def _signed_fields(token: dict) -> dict:
    return {k: v for k, v in token.items() if k != "signature"}


def issue_token(did: str, public_key_hex: str, device_type: str, role: str,
                 fog_signing_key, ttl_seconds: int = TOKEN_TTL_SECONDS) -> dict:
    fields = {
        "token_id": secrets.token_hex(8),
        "did": did,
        "public_key": public_key_hex,
        "device_type": device_type,
        "role": role,
        "issued_at": time.time(),
        "expires_at": time.time() + ttl_seconds,
    }
    signature = sign(fog_signing_key, canonical_json(fields)).hex()
    return {**fields, "signature": signature}


def token_signature_valid(token: dict, fog_signing_key) -> bool:
    """True only if this token was really issued by this fog, unmodified."""
    try:
        fields = _signed_fields(token)
        sig = bytes.fromhex(token["signature"])
    except (KeyError, ValueError, TypeError):
        return False
    return verify(public_key_bytes(fog_signing_key), canonical_json(fields), sig)


def token_expired(token: dict) -> bool:
    return time.time() > token.get("expires_at", 0)


def access_message(token_id: str, did: str, nonce: str) -> bytes:
    """Exact bytes the DEVICE signs to prove it still holds the private key
    matching this token's public key, for THIS specific request."""
    return TOKEN_ACCESS_LABEL + b"|" + token_id.encode() + b"|" + did.encode() + b"|" + nonce.encode()


def access_signature_valid(token: dict, nonce: str, signature_hex: str) -> bool:
    try:
        pk_bytes = bytes.fromhex(token["public_key"])
        sig = bytes.fromhex(signature_hex)
    except (KeyError, ValueError, TypeError):
        return False
    return verify(pk_bytes, access_message(token["token_id"], token["did"], nonce), sig)