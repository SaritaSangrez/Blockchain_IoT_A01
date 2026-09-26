"""
ATTACKS (Member B): replay, stolen valid token, expired/revoked token.

Runs the fog in process (FastAPI TestClient, temporary paths) -- no
certificates or running server needed, same idea as attacks/tamper_proof.py.

Run from the project root:   python attacks/token_attacks.py
"""
from __future__ import annotations

import secrets
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient

from common.crypto_utils import generate_keypair, sign
from common.logger import fail, info, ok, step
from devices.device import Device
from fog.auth.psk import PSKStore
from fog.main import create_app
from fog.revocation.registry import revoke_device
from fog.tokens.tokens import access_message, issue_token

results = []


def record(title, passed):
    (ok if passed else fail)("attack", f"{title}: {'DETECTED as expected' if passed else 'NOT DETECTED -- PROBLEM'}")
    results.append((title, passed))


def make_env():
    psk = secrets.token_hex(32)
    tmp = Path(tempfile.mkdtemp())
    app = create_app(psk_entries={"temp01": PSKStore.hash_psk(psk)},
                     signing_key_path=tmp / "k.pem", ledger_path=tmp / "l.json", verbose=False)
    return app, TestClient(app), psk


def get_token(client, name, psk, device_type="temperature_sensor", role="sensor"):
    d = Device(name, psk=psk, client=client, persist_key=False, verbose=False)
    d.register_start()
    challenge = d.submit_public_key()
    d.prove_possession(challenge)
    r = client.post("/tokens/issue", json={"session_id": d.session_id, "device_type": device_type, "role": role})
    assert r.status_code == 200, r.text
    return d, r.json()


def attack_replay():
    step("ATTACK 1: replay of an exact request")
    _, client, psk = make_env()
    d, token = get_token(client, "temp01", psk)
    nonce = "n-1"
    sig = sign(d.private_key, access_message(token["token_id"], token["did"], nonce)).hex()
    body = {"token": token, "nonce": nonce, "signature": sig, "operation": "read"}

    r1 = client.post("/tokens/access", json=body)
    r2 = client.post("/tokens/access", json=body)  # exact same request replayed
    info("attack", f"first request -> {r1.json()}   |   replayed -> {r2.json()}")
    record("replay of exact request", r1.json()["decision"] == "ALLOW" and r2.json()["reason"] == "nonce_reused")


def attack_stolen_token():
    step("ATTACK 2: stolen valid token used without the private key")
    _, client, psk = make_env()
    d, token = get_token(client, "temp01", psk)

    attacker_key = generate_keypair()  # attacker has the token bytes but NOT temp01's private key
    nonce = "n-attacker-1"
    forged_sig = sign(attacker_key, access_message(token["token_id"], token["did"], nonce)).hex()
    r = client.post("/tokens/access", json={"token": token, "nonce": nonce, "signature": forged_sig, "operation": "read"})
    info("attack", f"attacker replays the token, signs with the wrong key -> {r.json()}")
    record("stolen token without the private key", r.json()["reason"] == "proof_of_possession_failed")


def attack_expired_and_revoked():
    step("ATTACK 3a: expired token")
    app, client, psk = make_env()
    d, _ = get_token(client, "temp01", psk)
    short_token = issue_token(d.did, d.public_key_hex, "temperature_sensor", "sensor",
                              app.state.ctx.signing_key, ttl_seconds=0.3)  # issued directly with a tiny TTL
    time.sleep(0.4)
    nonce = "n-exp-1"
    sig = sign(d.private_key, access_message(short_token["token_id"], short_token["did"], nonce)).hex()
    r = client.post("/tokens/access", json={"token": short_token, "nonce": nonce, "signature": sig, "operation": "read"})
    info("attack", f"token used after its real expiry -> {r.json()}")
    record("expired token rejected", r.json()["reason"] == "expired")

    step("ATTACK 3b: revoked device's token")
    app2, client2, psk2 = make_env()
    d2, token2 = get_token(client2, "temp01", psk2)
    revoke_device(app2.state.ctx.devices, token2["did"])
    nonce2 = "n-rev-1"
    sig2 = sign(d2.private_key, access_message(token2["token_id"], token2["did"], nonce2)).hex()
    r2 = client2.post("/tokens/access", json={"token": token2, "nonce": nonce2, "signature": sig2, "operation": "read"})
    info("attack", f"revoked device tries to use its token -> {r2.json()}")
    record("revoked device's token rejected", r2.json()["reason"] == "revoked")


def main():
    attack_replay()
    attack_stolen_token()
    attack_expired_and_revoked()
    step("SUMMARY")
    for title, passed in results:
        print(f"   {title:<50} {'PASS' if passed else 'FAIL'}")
    (ok if all(p for _, p in results) else fail)("attack", "all attacks detected" if all(p for _, p in results) else "SOME NOT DETECTED")


if __name__ == "__main__":
    main()