"""
Central configuration shared by the fog node, devices, scripts and tests.
Every path is built from the project root so commands work from anywhere.
"""
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

# Network
FOG_HOST = "localhost"
FOG_PORT = 8443
FOG_BASE_URL = f"https://{FOG_HOST}:{FOG_PORT}"

# Zone served by this fog node (Assignment 1 has exactly one zone)
FOG_ZONE = "factory_A"
FOG_ID = "fog_A"

# TLS material (created by scripts/gen_certs.py, ignored by git)
TLS_DIR = BASE_DIR / "fog" / "tls"
CA_CERT_PATH = TLS_DIR / "ca_cert.pem"
CA_KEY_PATH = TLS_DIR / "ca_key.pem"
FOG_TLS_CERT_PATH = TLS_DIR / "fog_cert.pem"
FOG_TLS_KEY_PATH = TLS_DIR / "fog_tls_key.pem"

# Fog identity key used to sign ledger blocks, proof packages and tokens.
# Deliberately separate from the TLS key.
FOG_SIGNING_KEY_PATH = TLS_DIR / "fog_signing_key.pem"

# Pre shared keys
PSK_STORE_PATH = BASE_DIR / "fog" / "auth" / "psk_store.json"          # fog side: SHA256 of each PSK
DEVICE_PROVISIONING_PATH = BASE_DIR / "devices" / "keystore" / "provisioning.json"  # device side: raw PSKs

# Device private keys
KEYSTORE_DIR = BASE_DIR / "devices" / "keystore"

# Root registry (local blockchain)
LEDGER_PATH = BASE_DIR / "registry" / "data" / "ledger.json"

# Timing rules (seconds)
SESSION_TTL_SECONDS = 300
CHALLENGE_TTL_SECONDS = 30

# Onboarding policy
ALLOWED_DEVICE_TYPES = {
    "temperature_sensor",
    "pressure_sensor",
    "smart_meter",
    "camera",
    "valve_controller",
    "motor_controller",
    "plc",
}

# Devices provisioned by scripts/gen_certs.py.
# name: (device_type, role)
DEMO_DEVICES = {
    "temp01": ("temperature_sensor", "sensor"),
    "pressure01": ("pressure_sensor", "sensor"),
    "meter01": ("smart_meter", "sensor"),
    "camera01": ("camera", "monitor"),
    "valve01": ("valve_controller", "actuator"),
    "motor01": ("motor_controller", "actuator"),
    "plc01": ("plc", "controller"),
    "temp02": ("temperature_sensor", "sensor"),
}

# Extra simulated devices for benchmarks: sim0001 ... sim{N}
SIM_DEVICE_COUNT = 1000

# Epochs
# Admin key for operator actions such as closing an epoch (demo value, not a secret).
ADMIN_KEY = "fog_admin_demo_key"
# If > 0, the fog closes the current epoch automatically every N seconds
# (only when devices are waiting). 0 means close manually via POST /epoch/close.
AUTO_EPOCH_SECONDS = 0
# True: each new epoch root commits to ALL active devices (previously registered,
# not revoked) plus the new batch, so a revoked device disappears from the next root.
# False: each epoch root commits only to its own new batch.
CARRY_FORWARD_ACTIVE = True

# Default metadata values for simulated devices
DEFAULT_VENDOR = "Acme"
SIM_DEVICE_TYPE = ("temperature_sensor", "sensor")