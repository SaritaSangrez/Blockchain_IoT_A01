"""
Registration protocol tests. The fog runs in process (FastAPI TestClient)
with temporary paths, so no certificates or running server are needed.
The live HTTPS path is tested separately by running the server and devices.
"""
import secrets

import pytest
from fastapi.testclient import TestClient

from common.schemas import DeviceStatus
from devices.device import Device, RegistrationError
from fog.auth.psk import PSKStore
from fog.main import create_app


@pytest.fixture
def env(tmp_path):
    psks = {name: secrets.token_hex(32) for name in ("temp01", "camera01", "plc01")}
    app = create_app(
        psk_entries={k: PSKStore.hash_psk(v) for k, v in psks.items()},
        signing_key_path=tmp_path / "fog_key.pem",
        ledger_path=tmp_path / "ledger.json",
    )
    client = TestClient(app)
    return app, client, psks


def make_device(env, name, psk=None):
    app, client, psks = env
    return Device(name, psk=psk or psks[name], client=client, persist_key=False, verbose=False)


def test_health(env):
    _, client, _ = env
    body = client.get("/health").json()
    assert body["status"] == "ok" and body["registered_psks"] == 3


def test_happy_path(env):
    app, _, _ = env
    d = make_device(env, "temp01")
    result = d.onboard()
    assert result["status"] == "POP_VERIFIED" and result["did"] == d.did
    record = app.state.ctx.devices.get(d.did)
    assert record.status == DeviceStatus.PENDING and record.public_key == d.public_key_hex


def test_several_devices(env):
    for name in ("temp01", "camera01", "plc01"):
        make_device(env, name).onboard()
    assert len(env[0].state.ctx.devices.all()) == 3


def test_wrong_psk_rejected(env):
    d = make_device(env, "temp01", psk=secrets.token_hex(32))
    with pytest.raises(RegistrationError) as e:
        d.register_start()
    assert e.value.status == 401


def test_unknown_device_rejected(env):
    d = make_device(env, "intruder", psk=secrets.token_hex(32))
    with pytest.raises(RegistrationError) as e:
        d.register_start()
    assert e.value.status == 401


def test_missing_header_rejected(env):
    _, client, _ = env
    assert client.post("/register/start").status_code == 401
    assert client.post("/register/start", headers={"Authorization": "Bearer x"}).status_code == 401


def test_cannot_skip_psk(env):
    _, client, _ = env
    d = make_device(env, "temp01")
    r = client.post("/register/pubkey", json={"session_id": "fake", "did": d.did, "public_key": d.public_key_hex})
    assert r.status_code == 404


def test_cannot_skip_to_pop(env):
    d = make_device(env, "temp01")
    d.register_start()
    with pytest.raises(RegistrationError) as e:
        d.prove_possession("00" * 32)
    assert e.value.status == 409


def test_did_must_match_key(env):
    _, client, _ = env
    d = make_device(env, "temp01")
    d.register_start()
    r = client.post("/register/pubkey", json={"session_id": d.session_id, "did": "did:iiot:0000000000000000", "public_key": d.public_key_hex})
    assert r.status_code == 400


def test_invalid_public_key_rejected(env):
    _, client, _ = env
    d = make_device(env, "temp01")
    d.register_start()
    r = client.post("/register/pubkey", json={"session_id": d.session_id, "did": d.did, "public_key": "02" + "ff" * 32})
    assert r.status_code == 400


def test_copied_identity_fails_pop(env):
    """Attacker has a valid PSK and copies a victim's DID + PK, but not the victim's private key."""
    victim = make_device(env, "temp01")
    attacker = make_device(env, "camera01")
    attacker.did, attacker.pk_bytes = victim.did, victim.pk_bytes   # copied public data only
    attacker.register_start()
    challenge = attacker.submit_public_key()
    with pytest.raises(RegistrationError) as e:
        attacker.prove_possession(challenge)                        # signs with its OWN key
    assert e.value.status == 403


def test_old_signature_cannot_be_replayed(env):
    _, client, _ = env
    d = make_device(env, "temp01")
    d.register_start()
    challenge = d.submit_public_key()
    sig = d.sign_challenge(challenge)
    assert client.post("/register/pop", json={"session_id": d.session_id, "signature": sig}).status_code == 200
    # replay the same signature on the same session
    assert client.post("/register/pop", json={"session_id": d.session_id, "signature": sig}).status_code == 409


def test_failed_pop_consumes_challenge(env):
    _, client, _ = env
    d = make_device(env, "temp01")
    d.register_start()
    challenge = d.submit_public_key()
    bad = client.post("/register/pop", json={"session_id": d.session_id, "signature": "3006020101020101"})
    assert bad.status_code == 403
    good_sig = d.sign_challenge(challenge)          # correct signature, but challenge already burned
    assert client.post("/register/pop", json={"session_id": d.session_id, "signature": good_sig}).status_code == 409


def test_expired_challenge_rejected(tmp_path):
    psk = secrets.token_hex(32)
    app = create_app(psk_entries={"temp01": PSKStore.hash_psk(psk)}, signing_key_path=tmp_path / "k.pem",
                     ledger_path=tmp_path / "l.json", challenge_ttl=0)
    d = Device("temp01", psk=psk, client=TestClient(app), persist_key=False, verbose=False)
    d.register_start()
    challenge = d.submit_public_key()
    import time; time.sleep(0.05)
    with pytest.raises(RegistrationError) as e:
        d.prove_possession(challenge)
    assert e.value.status == 403 and "expired" in e.value.detail