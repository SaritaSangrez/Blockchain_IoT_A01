"""
Revocation (Member B).

Two levels, both effective IMMEDIATELY:

  revoke_device()  flips the device's status to DeviceStatus.REVOKED in the
                   fog's DeviceStore and blacklists every token it was issued.
                   Because every component reads that one status flag:
                     * /tokens/access and /verify deny it on the very next request
                     * GET /proof/{did} (Member A) refuses to hand out new proofs
                     * finalize_epoch() (Member A) leaves it out of every FUTURE
                       epoch root, so it is not in the new active set

  revoke_token()   blacklists one token_id only (e.g. a leaked token) without
                   revoking the device itself.

What revocation does NOT (and should not) change: a proof package issued
before revocation still verifies against the root of ITS epoch, because that
root is immutable history ("was this device registered in epoch 1?" -> yes).
Whether the device may act NOW is a separate check, done on every request.
"""
from __future__ import annotations

from common.logger import warn
from common.schemas import DeviceStatus
from fog.storage.device_store import DeviceStore


def revoke_device(devices: DeviceStore, did: str, token_state=None) -> bool:
    """Marks a device REVOKED (and all its tokens, if token_state is given).
    Returns False if the DID is unknown. Idempotent."""
    if devices.get(did) is None:
        return False
    devices.set_status(did, DeviceStatus.REVOKED)
    revoked_tokens = []
    if token_state is not None:
        for tid in token_state.tokens_of(did):
            token_state.revoke(tid)
            revoked_tokens.append(tid)
    warn("revocation", f"device {did} revoked" +
         (f", tokens {revoked_tokens} blacklisted" if revoked_tokens else ""))
    return True


def revoke_token(token_state, token_id: str) -> bool:
    """Blacklists one token. Returns False if this fog never issued it."""
    if not token_state.was_issued(token_id):
        return False
    token_state.revoke(token_id)
    warn("revocation", f"token {token_id} revoked (device itself not revoked)")
    return True


def is_device_revoked(devices: DeviceStore, did: str) -> bool:
    record = devices.get(did)
    return record is not None and record.status == DeviceStatus.REVOKED
