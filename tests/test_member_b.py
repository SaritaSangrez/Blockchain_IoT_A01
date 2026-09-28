"""
Tests for Member B's modules: access policy, tokens, nonces, revocation,
Phase 2 /tokens/* and Phase 3 /verify endpoints.

Unit tests need nothing running; endpoint tests build an in-process fog with
a temporary key and ledger (FastAPI TestClient), same as tests/test_epoch.py.

Run:  pytest tests/test_member_b.py -v
"""
from __future__ import annotations

import secrets
import tempfile
import time
from pathlib import Path

import config
from common.crypto_utils import generate_keypair, public_key_bytes
from common.schemas import DeviceRecord, DeviceStatus
from devices.device import Device
from devices.runtime_client import (
    build_token_request,
    build_verify_request,
    get_token_nonce,
    get_verify_nonce,
    request_token,
    token_access,
    verify_access,
)
from fog.policy.access_policy import check_policy, provisional_allowed, role_valid_for_type
from fog.revocation.registry import is_device_revoked, revoke_device, revoke_token
from fog.storage.device_store import DeviceStore
from fog.tokens.store import NONCE_EXPIRED, NONCE_OK, NONCE_REUSED, NONCE_UNKNOWN, NONCE_WRONG_SUBJECT, NonceBook, TokenState
from fog.tokens.tokens import access_signature_valid, issue_token, sign_access, token_expired, token_signature_valid

ADMIN = {"X-Admin-Key": config.ADMIN_KEY}


# ======================= unit tests =======================

# ---------- access policy ----------

def test_sensor_may_write_readings_but_not_stop_the_line():
    assert check_policy("temperature_sensor", "write", "sensor")
    assert not check_policy("temperature_sensor", "stop", "sensor")
    assert check_policy("temperature_sensor", "stop", "controller")


def test_unknown_resource_or_operation_is_denied():
    assert not check_policy("nonexistent_device", "read", "sensor")
    assert not check_policy("temperature_sensor", "reboot", "sensor")


def test_role_must_match_device_type():
    assert role_valid_for_type("temperature_sensor", "sensor")
    assert role_valid_for_type("plc", "controller")
    assert not role_valid_for_type("temperature_sensor", "controller")   # self-promotion
    assert not role_valid_for_type("temperature_sensor", None)
    assert not role_valid_for_type(None, "sensor")


def test_provisional_scope_is_limited():
    assert provisional_allowed("temperature_sensor", "temperature_sensor", "write")
    assert provisional_allowed("temperature_sensor", "temperature_sensor", "read")
    assert not provisional_allowed("temperature_sensor", "temperature_sensor", "stop")
    assert not provisional_allowed("temperature_sensor", "plc", "read")


# ---------- nonces ----------

def test_nonce_is_single_use_and_bound_to_its_subject():
    book = NonceBook(ttl_seconds=30)
    n = book.issue("token_access", "tok1")
    assert book.consume("token_access", "tok2", n) == NONCE_WRONG_SUBJECT
    assert book.consume("verify_access", "tok1", n) == NONCE_WRONG_SUBJECT
    assert book.consume("token_access", "tok1", n) == NONCE_OK
    assert book.consume("token_access", "tok1", n) == NONCE_REUSED
    assert book.consume("token_access", "tok1", "never-issued") == NONCE_UNKNOWN


def test_nonce_expires_and_is_purged():
    book = NonceBook(ttl_seconds=0.05)
    n = book.issue("p", "s")
    time.sleep(0.1)
    assert book.consume("p", "s", n) == NONCE_EXPIRED
    book.issue("p", "s")                 # purge runs on issue
    assert len(book) == 1


# ---------- tokens ----------

def test_token_contains_required_fields_and_detects_tampering():
    fog_key = generate_keypair()
    token = issue_token("did:iiot:dev1", "aabbcc", "temperature_sensor", "sensor", fog_key, epoch_id=3)
    for field in ("did", "public_key", "device_type", "role", "scope", "allowed_operations", "expires_at"):
        assert field in token
    assert token_signature_valid(token, fog_key)
    assert not token_signature_valid({**token, "role": "controller"}, fog_key)
    assert not token_signature_valid({**token, "expires_at": token["expires_at"] + 3600}, fog_key)
    assert not token_signature_valid(token, generate_keypair())         # other fog
    assert not token_signature_valid({"garbage": 1}, fog_key)


def test_token_expiry():
    token = issue_token("did:iiot:dev1", "aa", "temperature_sensor", "sensor", generate_keypair(), ttl_seconds=0)
    time.sleep(0.02)
    assert token_expired(token)


def test_request_signature_binds_key_nonce_resource_and_operation():
    fog_key, dev_key, attacker = generate_keypair(), generate_keypair(), generate_keypair()
    token = issue_token("did:iiot:dev1", public_key_bytes(dev_key).hex(), "temperature_sensor", "sensor", fog_key)
    sig = sign_access(dev_key, token, "n1", "temperature_sensor", "write")
    assert access_signature_valid(token, "n1", "temperature_sensor", "write", sig)
    assert not access_signature_valid(token, "n2", "temperature_sensor", "write", sig)      # other nonce
    assert not access_signature_valid(token, "n1", "temperature_sensor", "stop", sig)       # other operation
    assert not access_signature_valid(token, "n1", "plc", "write", sig)                     # other resource
    forged = sign_access(attacker, token, "n1", "temperature_sensor", "write")
    assert not access_signature_valid(token, "n1", "temperature_sensor", "write", forged)   # stolen token


# ---------- revocation ----------

def test_device_revocation_is_immediate_idempotent_and_kills_its_tokens():
    store, state = DeviceStore(), TokenState()
    store.upsert(DeviceRecord(did="did:iiot:t1", public_key="00", status=DeviceStatus.REGISTERED, role="sensor"))
    state.record_issued("tokA", "did:iiot:t1")
    assert revoke_device(store, "did:iiot:ghost", state) is False
    assert revoke_device(store, "did:iiot:t1", state) is True
    assert is_device_revoked(store, "did:iiot:t1") and state.is_revoked("tokA")
    assert revoke_device(store, "did:iiot:t1", state) is True


def test_single_token_revocation():
    state = TokenState()
    assert revoke_token(state, "unknown") is False
    state.record_issued("tokA", "did:iiot:t1")
    assert revoke_token(state, "tokA") is True and state.is_revoked("tokA")


# ======================= endpoint tests =======================

def _env():
    from fastapi.testclient import TestClient
    from fog.auth.psk import PSKStore
    from fog.main import create_app
    names = ["temp01", "plc01", "attacker01"]
    psks = {n: secrets.token_hex(32) for n in names}
    tmp = Path(tempfile.mkdtemp())
    app = create_app(psk_entries={n: PSKStore.hash_psk(p) for n, p in psks.items()},
                     signing_key_path=tmp / "k.pem", ledger_path=tmp / "l.json", verbose=False)
    return app, TestClient(app), psks


def _queued(client, psks, name="temp01", **meta):
    d = Device(name, psk=psks[name], client=client, persist_key=False, verbose=False)
    d.register_start()
    d.prove_possession(d.submit_public_key())
    d.submit_metadata(**meta)
    return d


def _registered(client, psks, name="temp01"):
    d = _queued(client, psks, name)
    client.post("/epoch/close", headers=ADMIN)
    d.fetch_proof()
    return d


def test_token_requires_queued_leaf_and_uses_fog_validated_role():
    _, client, psks = _env()
    d = Device("temp01", psk=psks["temp01"], client=client, persist_key=False, verbose=False)
    d.register_start()
    d.prove_possession(d.submit_public_key())
    r = client.post("/tokens/issue", json={"session_id": d.session_id})
    assert r.status_code == 409                                  # PoP alone is not enough: not queued yet
    d.submit_metadata()
    token = request_token(d)
    assert token["role"] == "sensor" and token["device_type"] == "temperature_sensor"
    assert token["scope"] == "provisional"
    assert client.get("/epoch/current").json()["batch_size"] == 1   # queued for the next batch


def test_token_refused_for_role_escalation():
    _, client, psks = _env()
    d = _queued(client, psks, device_type="temperature_sensor", role="controller")
    assert client.post("/tokens/issue", json={"session_id": d.session_id}).status_code == 403


def test_token_access_allow_provisional_limit_and_replay():
    _, client, psks = _env()
    d = _queued(client, psks)
    token = request_token(d)
    resp, captured = token_access(d, token, "temperature_sensor", "write")
    assert resp["decision"] == "ALLOW"
    assert client.post("/tokens/access", json=captured).json()["reason"] == "nonce_reused"
    assert token_access(d, token, "temperature_sensor", "stop")[0]["reason"] == "provisional_scope"
    assert token_access(d, token, "plc", "read")[0]["reason"] == "provisional_scope"
    body = build_token_request(d.private_key, token, "self-made", "temperature_sensor", "write")
    assert client.post("/tokens/access", json=body).json()["reason"] == "nonce_unknown"


def test_stolen_token_is_useless_without_private_key():
    _, client, psks = _env()
    victim = _queued(client, psks)
    token = request_token(victim)
    attacker = Device("attacker01", psk=psks["attacker01"], client=client, persist_key=False, verbose=False)
    nonce = get_token_nonce(client, token["token_id"])
    body = build_token_request(attacker.private_key, token, nonce, "temperature_sensor", "write")
    assert client.post("/tokens/access", json=body).json()["reason"] == "proof_of_possession_failed"


def test_expired_and_revoked_tokens_are_denied():
    app, client, psks = _env()
    d = _queued(client, psks)
    ctx = app.state.ctx
    short = issue_token(d.did, d.public_key_hex, "temperature_sensor", "sensor", ctx.signing_key, ttl_seconds=0.05)
    ctx.token_state.record_issued(short["token_id"], d.did)
    time.sleep(0.1)
    assert token_access(d, short, "temperature_sensor", "write")[0]["reason"] == "expired"

    token = request_token(d)
    assert client.post("/revocation/revoke", json={"did": d.did, "token_id": token["token_id"],
                                                  "token_only": True}, headers=ADMIN).status_code == 200
    assert token_access(d, token, "temperature_sensor", "write")[0]["reason"] == "revoked"
    assert client.get(f"/revocation/status/{d.did}").json()["revoked"] is False   # device itself still fine


def test_revoke_requires_admin_key():
    _, client, psks = _env()
    d = _queued(client, psks)
    assert client.post("/revocation/revoke", json={"did": d.did}).status_code == 401
    assert client.post("/revocation/revoke", json={"did": "did:iiot:ghost"}, headers=ADMIN).status_code == 404


def test_verify_identity_vs_authorization():
    _, client, psks = _env()
    sensor = _queued(client, psks, "temp01")
    plc = _queued(client, psks, "plc01")
    client.post("/epoch/close", headers=ADMIN)
    sensor.fetch_proof()
    plc.fetch_proof()
    assert verify_access(sensor, "temperature_sensor", "write")[0]["decision"] == "ALLOW"
    denied = verify_access(sensor, "temperature_sensor", "stop")[0]
    assert denied["reason"] == "policy_denied" and denied["identity_verified"] is True
    assert verify_access(plc, "temperature_sensor", "stop")[0]["decision"] == "ALLOW"


def test_verify_rejects_replay_stolen_package_and_tampering():
    _, client, psks = _env()
    d = _registered(client, psks)
    _, captured = verify_access(d, "temperature_sensor", "write")
    assert client.post("/verify", json=captured).json()["reason"] == "nonce_reused"

    attacker = Device("attacker01", psk=psks["attacker01"], client=client, persist_key=False, verbose=False)
    nonce = get_verify_nonce(client, d.did)
    body = build_verify_request(attacker.private_key, d.proof_package, nonce, "temperature_sensor", "write")
    assert client.post("/verify", json=body).json()["reason"] == "proof_of_possession_failed"

    tampered = dict(d.proof_package)
    tampered["proof_path"] = [dict(s) for s in tampered["proof_path"]]
    tampered["leaf"] = "00" * 32
    r = verify_access(d, "temperature_sensor", "write", tampered)[0]
    assert r["decision"] == "DENY" and r["identity_verified"] is False


def test_revoked_device_old_proof_history_vs_current_status():
    app, client, psks = _env()
    d = _queued(client, psks, "temp01")
    plc = _queued(client, psks, "plc01")
    e1 = client.post("/epoch/close", headers=ADMIN).json()["epoch_id"]
    d.fetch_proof()
    client.post("/revocation/revoke", json={"did": d.did}, headers=ADMIN)

    r = verify_access(d, "temperature_sensor", "write")[0]
    assert r["reason"] == "device_revoked" and r["identity_verified"] is True

    closed = client.post("/epoch/close", headers=ADMIN).json()
    assert d.did in closed["excluded"]
    assert client.get(f"/revocation/status/{d.did}").json()["in_latest_active_set"] is False
    moved = {**d.proof_package, "epoch_id": closed["epoch_id"]}
    assert verify_access(d, "temperature_sensor", "write", moved)[0]["detected_by"] == "Merkle verifier"
    assert client.get(f"/proof/{d.did}").status_code == 403
    assert app.state.ctx.ledger.get_root(e1) is not None       # epoch 1 history is untouched
