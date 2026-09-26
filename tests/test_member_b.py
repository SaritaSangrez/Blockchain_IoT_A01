"""
Unit tests for Member B's modules: access policy, revocation, tokens.
These are fast, offline tests -- no running fog needed (that's what
attacks/token_attacks.py and scripts/demo_phase2.py are for).

Run:  pytest tests/test_member_b.py
"""
from __future__ import annotations

import time

from common.crypto_utils import generate_keypair, public_key_bytes, sign
from common.schemas import DeviceRecord, DeviceStatus
from fog.policy.access_policy import check_policy
from fog.revocation.registry import is_device_revoked, revoke_device
from fog.storage.device_store import DeviceStore
from fog.tokens.store import TokenState
from fog.tokens.tokens import (
    access_message,
    access_signature_valid,
    issue_token,
    token_expired,
    token_signature_valid,
)


# ---------- access policy ----------

def test_sensor_can_read_and_write_its_own_readings():
    assert check_policy("temperature_sensor", "read", "sensor")
    assert check_policy("temperature_sensor", "write", "sensor")


def test_sensor_cannot_stop_a_production_line():
    # the assignment brief's own minimum example
    assert not check_policy("temperature_sensor", "stop", "sensor")
    assert check_policy("temperature_sensor", "stop", "controller")


def test_unknown_device_type_or_operation_is_denied():
    assert not check_policy("nonexistent_device", "read", "sensor")
    assert not check_policy("temperature_sensor", "reboot", "sensor")


# ---------- revocation ----------

def _store_with_one_device(did: str = "did:iiot:test1") -> DeviceStore:
    store = DeviceStore()
    store.upsert(DeviceRecord(did=did, public_key="00", status=DeviceStatus.REGISTERED, role="sensor"))
    return store


def test_revoke_unknown_did_returns_false():
    store = DeviceStore()
    assert revoke_device(store, "did:iiot:ghost") is False


def test_revoke_known_device_is_immediate_and_idempotent():
    store = _store_with_one_device()
    assert not is_device_revoked(store, "did:iiot:test1")
    assert revoke_device(store, "did:iiot:test1") is True
    assert is_device_revoked(store, "did:iiot:test1")
    assert revoke_device(store, "did:iiot:test1") is True  # calling twice is safe


# ---------- tokens ----------

def test_issued_token_signature_is_valid_and_tampering_is_detected():
    fog_key = generate_keypair()
    token = issue_token("did:iiot:dev1", "aabbcc", "temperature_sensor", "sensor", fog_key)
    assert token_signature_valid(token, fog_key)

    tampered = {**token, "role": "controller"}  # try to escalate role without re-signing
    assert not token_signature_valid(tampered, fog_key)


def test_token_expiry():
    fog_key = generate_keypair()
    token = issue_token("did:iiot:dev1", "aabbcc", "temperature_sensor", "sensor", fog_key, ttl_seconds=0)
    time.sleep(0.05)
    assert token_expired(token)


def test_access_signature_must_come_from_the_devices_own_key():
    fog_key = generate_keypair()
    device_key = generate_keypair()
    token = issue_token("did:iiot:dev1", public_key_bytes(device_key).hex(),
                        "temperature_sensor", "sensor", fog_key)

    nonce = "n1"
    real_sig = sign(device_key, access_message(token["token_id"], token["did"], nonce)).hex()
    assert access_signature_valid(token, nonce, real_sig)

    attacker_key = generate_keypair()  # has the token bytes, not the device's private key
    forged_sig = sign(attacker_key, access_message(token["token_id"], token["did"], nonce)).hex()
    assert not access_signature_valid(token, nonce, forged_sig)


def test_token_state_nonce_reuse_and_revocation():
    state = TokenState()
    assert not state.nonce_already_used("tok1", "n1")
    state.mark_nonce_used("tok1", "n1")
    assert state.nonce_already_used("tok1", "n1")
    assert not state.nonce_already_used("tok1", "n2")  # a different nonce is unaffected

    assert not state.is_revoked("tok1")
    state.revoke("tok1")
    assert state.is_revoked("tok1")
