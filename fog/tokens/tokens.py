"""
Phase 2: temporary token issuance and checking (Member B).

A device that has passed PSK + proof of possession and has been QUEUED in the
open batch, but has no inclusion proof yet, can get a short-lived token signed
by the fog. The token carries the device's DID, public key, the device type
and role the fog validated at registration, a provisional scope and an expiry.

The token is a bearer credential only on paper. Every resource request must
ALSO carry a fresh fog-issued nonce signed with the device's private key
(the key whose public half is inside the token). A copied token alone is
useless: the thief cannot produce that signature.

The signed request message binds token, DID, nonce, resource and operation,
so a captured signature cannot be reused for another request or operation.
"""
from __future__ import annotations

import secrets
import time

from common.canonical import canonical_json
from common.crypto_utils import public_key_bytes, sign, verify
from fog.policy.access_policy import PROVISIONAL_OPERATIONS

TOKEN_TTL_SECONDS = 120
TOKEN_ACCESS_LABEL = b"IIOT_TOKEN_ACCESS_V1"
TOKEN_NONCE_PURPOSE = "token_access"


def _signed_fields(token: dict) -> dict:
    return {k: v for k, v in token.items() if k != "signature"}


def issue_token(did: str, public_key_hex: str, device_type: str, role: str,
                fog_signing_key, ttl_seconds: float = TOKEN_TTL_SECONDS,
                epoch_id: int | None = None) -> dict:
    now = time.time()
    fields = {
        "token_id": secrets.token_hex(8),
        "did": did,
        "public_key": public_key_hex,
        "device_type": device_type,
        "role": role,
        "scope": "provisional",
        "allowed_operations": sorted(PROVISIONAL_OPERATIONS),
        "queued_for_epoch": epoch_id,
        "issued_at": now,
        "expires_at": now + ttl_seconds,
    }
    signature = sign(fog_signing_key, canonical_json(fields)).hex()
    return {**fields, "signature": signature}


def token_signature_valid(token: dict, fog_signing_key) -> bool:
    """True only if this token was issued by this fog and not modified."""
    try:
        fields = _signed_fields(token)
        sig = bytes.fromhex(token["signature"])
        return verify(public_key_bytes(fog_signing_key), canonical_json(fields), sig)
    except (KeyError, ValueError, TypeError, AttributeError):
        return False


def token_expired(token: dict) -> bool:
    try:
        return time.time() > float(token.get("expires_at", 0))
    except (TypeError, ValueError):
        return True


def access_message(token_id: str, did: str, nonce: str, resource: str, operation: str) -> bytes:
    """Exact bytes the DEVICE signs for one specific token request."""
    return b"|".join([TOKEN_ACCESS_LABEL, token_id.encode(), did.encode(), nonce.encode(),
                      resource.encode(), operation.encode()])


def sign_access(device_private_key, token: dict, nonce: str, resource: str, operation: str) -> str:
    """Device side helper."""
    return sign(device_private_key, access_message(token["token_id"], token["did"], nonce,
                                                   resource, operation)).hex()


def access_signature_valid(token: dict, nonce: str, resource: str, operation: str,
                           signature_hex: str) -> bool:
    try:
        pk_bytes = bytes.fromhex(token["public_key"])
        sig = bytes.fromhex(signature_hex)
        return verify(pk_bytes, access_message(token["token_id"], token["did"], nonce, resource, operation), sig)
    except (KeyError, ValueError, TypeError, AttributeError):
        return False
