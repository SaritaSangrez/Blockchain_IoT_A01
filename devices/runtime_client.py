"""
Device-side helpers for Phase 2 and Phase 3 (Member B).

These wrap one simulated Device (devices/device.py, Member A) and perform the
runtime protocol after onboarding:

  Phase 2  request_token()   POST /tokens/issue
           token_access()    POST /tokens/nonce  -> sign -> POST /tokens/access
  Phase 3  verify_access()   POST /verify/nonce  -> sign -> POST /verify

Each access helper returns (decision_json, request_body) so the attack
scripts can capture a genuine request and replay it byte for byte.
"""
from __future__ import annotations

from typing import Tuple

from fog.tokens.tokens import sign_access
from fog.verification.routes import sign_verify_request


class RuntimeAccessError(Exception):
    pass


def _json_or_raise(r, stage: str) -> dict:
    if r.status_code != 200:
        try:
            detail = r.json().get("detail", r.text)
        except Exception:
            detail = r.text
        raise RuntimeAccessError(f"{stage} failed [{r.status_code}]: {detail}")
    return r.json()


def request_token(device) -> dict:
    """Device must already have passed PoP AND submitted metadata (leaf queued)."""
    return _json_or_raise(device.client.post("/tokens/issue", json={"session_id": device.session_id}),
                          "token issue")


def get_token_nonce(client, token_id: str) -> str:
    return _json_or_raise(client.post("/tokens/nonce", json={"token_id": token_id}), "token nonce")["nonce"]


def build_token_request(private_key, token: dict, nonce: str, resource: str, operation: str) -> dict:
    return {"token": token, "nonce": nonce, "resource": resource, "operation": operation,
            "signature": sign_access(private_key, token, nonce, resource, operation)}


def token_access(device, token: dict, resource: str, operation: str) -> Tuple[dict, dict]:
    nonce = get_token_nonce(device.client, token["token_id"])
    body = build_token_request(device.private_key, token, nonce, resource, operation)
    return device.client.post("/tokens/access", json=body).json(), body


def get_verify_nonce(client, did: str) -> str:
    return _json_or_raise(client.post("/verify/nonce", json={"did": did}), "verify nonce")["nonce"]


def build_verify_request(private_key, pkg: dict, nonce: str, resource: str, operation: str) -> dict:
    return {"proof_package": pkg, "resource": resource, "operation": operation, "nonce": nonce,
            "signature": sign_verify_request(private_key, pkg, nonce, resource, operation)}


def verify_access(device, resource: str, operation: str, pkg: dict | None = None) -> Tuple[dict, dict]:
    pkg = pkg or device.proof_package
    nonce = get_verify_nonce(device.client, pkg["did"])
    body = build_verify_request(device.private_key, pkg, nonce, resource, operation)
    return device.client.post("/verify", json=body).json(), body
