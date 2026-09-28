"""
Access policy (Member B).

Proving WHO a device is (Phase 1 / Phase 3 Merkle proof, Phase 2 token) is a
separate question from deciding WHAT it is allowed to do. This file only
answers the second question.

Three rules live here:

1. POLICY_TABLE      resource type -> operation -> roles allowed to do it.
                     Example from the assignment: a temperature sensor may
                     WRITE temperature readings but must never STOP a
                     production line; only a controller may.

2. ROLES_FOR_TYPE    which roles are plausible for a given device type.
                     A device's role is taken from the metadata it registered
                     with, so without this check a temperature sensor could
                     register (or ask for a token) as "controller" and gain
                     STOP rights. The fog refuses to authorize any device whose
                     registered role does not match its registered type.

3. PROVISIONAL_*     what a device may do on a TEMPORARY token while it waits
                     for batch inclusion (Phase 2 "limited/provisional access"):
                     only read/write, only on its own device type, never stop
                     or stream. Full rights require the Merkle inclusion proof.
"""
from __future__ import annotations

from typing import Optional

# resource type -> operation -> roles allowed to perform it
POLICY_TABLE: dict[str, dict[str, set[str]]] = {
    "temperature_sensor": {"read": {"sensor", "monitor", "controller"}, "write": {"sensor"}, "stop": {"controller"}},
    "pressure_sensor":    {"read": {"sensor", "monitor", "controller"}, "write": {"sensor"}, "stop": {"controller"}},
    "smart_meter":        {"read": {"sensor", "monitor", "controller"}, "write": {"sensor"}, "stop": {"controller"}},
    "camera":             {"read": {"sensor", "monitor", "controller"}, "stream": {"monitor"}, "stop": {"controller"}},
    "valve_controller":   {"read": {"sensor", "monitor", "controller"}, "write": {"actuator", "controller"}, "stop": {"actuator", "controller"}},
    "motor_controller":   {"read": {"sensor", "monitor", "controller"}, "write": {"actuator", "controller"}, "stop": {"actuator", "controller"}},
    "plc":                {"read": {"sensor", "monitor", "controller"}, "write": {"controller"}, "stop": {"controller"}},
}

# device type -> roles that device type may legitimately hold
ROLES_FOR_TYPE: dict[str, set[str]] = {
    "temperature_sensor": {"sensor"},
    "pressure_sensor":    {"sensor"},
    "smart_meter":        {"sensor"},
    "camera":             {"monitor", "sensor"},
    "valve_controller":   {"actuator"},
    "motor_controller":   {"actuator"},
    "plc":                {"controller"},
}

# Phase 2: a token only grants these operations, and only on the device's own type
PROVISIONAL_OPERATIONS: frozenset[str] = frozenset({"read", "write"})

def check_policy(resource: str, operation: str, role: str) -> bool:
    """True if `role` may perform `operation` on a resource of type `resource`."""
    ops = POLICY_TABLE.get(resource)
    if ops is None:
        return False
    allowed_roles = ops.get(operation)
    if allowed_roles is None:
        return False
    return role in allowed_roles

def role_valid_for_type(device_type: Optional[str], role: Optional[str]) -> bool:
    """True if a device of `device_type` may hold `role` (blocks self-assigned privilege)."""
    return bool(device_type) and bool(role) and role in ROLES_FOR_TYPE.get(device_type, set())


def provisional_allowed(own_type: str, resource: str, operation: str) -> bool:
    """Extra restriction for token (not yet batch-registered) devices."""
    return resource == own_type and operation in PROVISIONAL_OPERATIONS
