"""
Credential / metadata validation (Phase 1 step 6).
The fog decides whether an authenticated device is PERMITTED to join this zone.
Full metadata stays at the fog; only H(DID || PK) goes into the tree.
"""
from __future__ import annotations

import re
from typing import Iterable, List

from common.schemas import MetadataRequest

NAME_PATTERN = re.compile(r"^[a-z0-9_]{2,32}$")
ALLOWED_ROLES = {"sensor", "actuator", "controller", "monitor"}
ALLOWED_VENDORS = {"Acme", "Siemens", "Bosch", "ABB", "Honeywell"}


def validate_metadata(meta: MetadataRequest, zone: str, allowed_types: Iterable[str]) -> List[str]:
    """Returns a list of problems. An empty list means the metadata is accepted."""
    errors: List[str] = []
    if not NAME_PATTERN.match(meta.device_name or ""):
        errors.append("device_name must be 2 to 32 chars of a to z, 0 to 9 or underscore")
    if meta.device_type not in set(allowed_types):
        errors.append(f"device_type '{meta.device_type}' is not permitted in this zone")
    if meta.zone != zone:
        errors.append(f"zone '{meta.zone}' does not match this fog's zone '{zone}'")
    if meta.role not in ALLOWED_ROLES:
        errors.append(f"role '{meta.role}' is not one of {sorted(ALLOWED_ROLES)}")
    if meta.vendor not in ALLOWED_VENDORS:
        errors.append(f"vendor '{meta.vendor}' is not an approved vendor")
    return errors