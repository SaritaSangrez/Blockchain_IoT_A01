"""
Access policy: given a device's type and the operation it wants to
perform, decide which roles are allowed to do it.

Proving WHO a device is (Phase 1 / Phase 3) is a separate question from
deciding WHAT it's allowed to do (this file). Example: a temperature
sensor can WRITE its own readings but must never be able to STOP a
production line -- only a controller can.
"""
from __future__ import annotations

# device_type -> operation -> roles allowed to perform it
POLICY_TABLE: dict[str, dict[str, set[str]]] = {
    "temperature_sensor": {"read": {"sensor", "monitor", "controller"}, "write": {"sensor"}, "stop": {"controller"}},
    "pressure_sensor":    {"read": {"sensor", "monitor", "controller"}, "write": {"sensor"}, "stop": {"controller"}},
    "smart_meter":        {"read": {"sensor", "monitor", "controller"}, "write": {"sensor"}, "stop": {"controller"}},
    "camera":             {"read": {"sensor", "monitor", "controller"}, "stream": {"monitor"}, "stop": {"controller"}},
    "valve_controller":   {"read": {"sensor", "monitor", "controller"}, "write": {"actuator", "controller"}, "stop": {"actuator", "controller"}},
    "motor_controller":   {"read": {"sensor", "monitor", "controller"}, "write": {"actuator", "controller"}, "stop": {"actuator", "controller"}},
    "plc":                {"read": {"sensor", "monitor", "controller"}, "write": {"controller"}, "stop": {"controller"}},
}


def check_policy(device_type: str, operation: str, role: str) -> bool:
    """True if `role` may perform `operation` on `device_type`."""
    ops = POLICY_TABLE.get(device_type)
    if ops is None:
        return False
    allowed_roles = ops.get(operation)
    if allowed_roles is None:
        return False
    return role in allowed_roles