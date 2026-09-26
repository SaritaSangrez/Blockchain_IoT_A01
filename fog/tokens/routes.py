"""
Phase 2 endpoints (Member B).

POST /tokens/issue    device already past PoP -> short-lived signed token
POST /tokens/access    token + fresh nonce + fresh signature -> ALLOW/DENY

After getting a token, the device still calls the EXISTING
/register/metadata endpoint (Member A's, unmodified) to get queued into
the batch -- that already works, because register_metadata only requires
the session to be POP_VERIFIED, and issuing a token doesn't change that.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from common.logger import fail, info, ok
from common.schemas import DeviceStatus
from fog.policy.access_policy import check_policy
from fog.revocation.registry import is_device_revoked
from fog.storage.device_store import POP_VERIFIED
from fog.tokens.tokens import (
    access_signature_valid,
    issue_token,
    token_expired,
    token_signature_valid,
)

router = APIRouter(prefix="/tokens", tags=["tokens"])
SRC = "tokens"


def _ctx(request: Request):
    return request.app.state.ctx


class TokenIssueRequest(BaseModel):
    session_id: str
    device_type: str
    role: str


class TokenAccessRequest(BaseModel):
    token: dict
    nonce: str
    signature: str
    operation: str


@router.post("/issue")
def tokens_issue(body: TokenIssueRequest, request: Request):
    ctx = _ctx(request)
    session = ctx.sessions.get(body.session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="unknown or expired session")
    if session.state != POP_VERIFIED:
        fail(SRC, f"token refused: session is {session.state}, expected {POP_VERIFIED}")
        raise HTTPException(status_code=409, detail=f"proof of possession must pass first (session is {session.state})")

    token = issue_token(session.did, session.public_key, body.device_type, body.role, ctx.signing_key)
    ctx.devices.set_status(session.did, DeviceStatus.TOKENIZED)
    ok(SRC, f"token {token['token_id']} issued to {session.did}, expires in "
            f"{int(token['expires_at'] - token['issued_at'])}s")
    return token


@router.post("/access")
def tokens_access(body: TokenAccessRequest, request: Request):
    ctx = _ctx(request)
    token = body.token

    if not token_signature_valid(token, ctx.signing_key):
        fail(SRC, "DENY: token signature invalid (forged or tampered)")
        return {"decision": "DENY", "reason": "bad_token_signature"}

    if token_expired(token):
        fail(SRC, f"DENY: token {token.get('token_id')} expired")
        return {"decision": "DENY", "reason": "expired"}

    if ctx.token_state.nonce_already_used(token["token_id"], body.nonce):
        fail(SRC, f"DENY: nonce {body.nonce} already used for token {token['token_id']}")
        return {"decision": "DENY", "reason": "nonce_reused"}
    ctx.token_state.mark_nonce_used(token["token_id"], body.nonce)

    if ctx.token_state.is_revoked(token["token_id"]) or is_device_revoked(ctx.devices, token["did"]):
        fail(SRC, f"DENY: {token['did']} / token {token['token_id']} is revoked")
        return {"decision": "DENY", "reason": "revoked"}

    if not access_signature_valid(token, body.nonce, body.signature):
        fail(SRC, f"DENY: {token['did']} did not sign this request with its own key (token alone is not enough)")
        return {"decision": "DENY", "reason": "proof_of_possession_failed"}

    if not check_policy(token["device_type"], body.operation, token["role"]):
        fail(SRC, f"DENY: {token['role']} may not {body.operation} a {token['device_type']}")
        return {"decision": "DENY", "reason": "policy_denied"}

    info(SRC, f"ALLOW: {token['did']} {body.operation} on {token['device_type']}")
    return {"decision": "ALLOW", "reason": "ok"}