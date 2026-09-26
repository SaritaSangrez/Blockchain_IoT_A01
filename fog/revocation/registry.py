"""
Revocation (Member B).

Revoking a device just means flipping its status to DeviceStatus.REVOKED
in Member A's DeviceStore. That one flag already does two things for us,
for free, because of how the rest of the project reads device status:

  - fog/batch/routes.py's GET /proof/{did} already refuses to hand out a
    NEW proof for a REVOKED device.
  - fog/batch/epoch_manager.py's finalize_epoch() already drops REVOKED
    devices from every FUTURE epoch root.

What neither of those covers: a device that already has an OLD, still
cryptographically valid proof package from before it was revoked. That
proof will still pass verify_proof_package() -- the math doesn't know
about revocation. So Phase 3 verification (next phase) must call
is_device_revoked() itself, on every request, on top of the proof check.
That's what makes revocation "immediate" instead of "starting next epoch".
"""
from __future__ import annotations

from common.logger import warn
from common.schemas import DeviceStatus
from fog.storage.device_store import DeviceStore


def revoke_device(devices: DeviceStore, did: str) -> bool:
    """Marks a device REVOKED. Returns False if the DID is unknown.
    Safe to call twice on the same device (idempotent)."""
    if devices.get(did) is None:
        return False
    devices.set_status(did, DeviceStatus.REVOKED)
    warn("revocation", f"device {did} revoked")
    return True


def is_device_revoked(devices: DeviceStore, did: str) -> bool:
    record = devices.get(did)
    return record is not None and record.status == DeviceStatus.REVOKED