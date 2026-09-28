"""
Phase 2 endpoints (Member B): temporary token bridging.

Device flow while the registration batch is still open:

  1. PSK + DID/PK + proof of possession            (Phase 1, /register/*)
  2. POST /register/metadata                        (Phase 1) -> leaf QUEUED in the open batch
  3. POST /tokens/issue   {session_id}              -> short-lived fog-signed token
  4. for EVERY resource request:
       POST /tokens/nonce  {token_id}               -> fresh fog-issued nonce (single use, 30 s)
       POST /tokens/access {token, nonce, resource, operation, signature}
                                                    -> ALLOW / DENY
  5. when the epoch closes the device becomes REGISTERED, fetches its proof
     package and switches to Phase 3 (/verify).

Why the token is issued only AFTER the leaf is queued: the assignment asks
that a tokenized device is queued for the next batch. Requiring the session
to be METADATA_ACCEPTED guarantees that, and it means the token's device
type and role come from the fog's own validated record, never from the
token request itself (a device cannot ask for a better role).

/tokens/access checks, in this order (first failure wins):
  1. token signature   -> bad_token_signature          (forged / modified token)
  2. token expiry      -> expired
  3. nonce             -> nonce_reused / nonce_unknown / nonce_expired / nonce_not_for_this_request
  4. revocation        -> revoked                      (token or device)
  5. device signature  -> proof_of_possession_failed   (stolen token)
  6. provisional scope -> provisional_scope            (token = limited access only)
  7. access policy     -> policy_denied
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from common.logger import fail, info, ok, short
from common.schemas import DeviceStatus
from fog.policy.access_policy import check_policy, provisional_allowed, role_valid_for_type
from fog.revocation.registry import is_device_revoked
from fog.storage.device_store import METADATA_ACCEPTED
from fog.tokens.store import NONCE_OK
from fog.tokens.tokens import (
    TOKEN_NONCE_PURPOSE,
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


class NonceRequest(BaseModel):
    token_id: str


class TokenAccessRequest(BaseModel):
    token: dict
    nonce: str
    resource: str
    operation: str
    signature: str


def _deny(reason: str, detected_by: str, msg: str) -> dict:
    fail(SRC, f"DENY [{detected_by}] {msg}")
    return {"decision": "DENY", "reason": reason, "detected_by": detected_by}


@router.post("/issue")
def tokens_issue(body: TokenIssueRequest, request: Request):
    ctx = _ctx(request)
    session = ctx.sessions.get(body.session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="unknown or expired session")
    if session.state != METADATA_ACCEPTED:
        fail(SRC, f"token refused: session is {session.state}, expected {METADATA_ACCEPTED}")
        raise HTTPException(status_code=409, detail=(
            f"token requires proof of possession AND a queued leaf "
            f"(session is {session.state}, expected {METADATA_ACCEPTED})"))

    record = ctx.devices.get(session.did)
    if record is None:
        raise HTTPException(status_code=404, detail="unknown device")
    if record.status == DeviceStatus.REVOKED:
        fail(SRC, f"token refused: {record.did} is REVOKED")
        raise HTTPException(status_code=403, detail="device is revoked")
    if record.status == DeviceStatus.REGISTERED:
        raise HTTPException(status_code=409, detail="device already has an inclusion proof; use /verify")
    if not role_valid_for_type(record.device_type, record.role):
        fail(SRC, f"token refused: role '{record.role}' is not valid for a {record.device_type}")
        raise HTTPException(status_code=403, detail="registered role does not match device type")

    epoch_id = ctx.epochs.current_epoch_id
    token = issue_token(record.did, record.public_key, record.device_type, record.role,
                        ctx.signing_key, epoch_id=epoch_id)
    ctx.token_state.record_issued(token["token_id"], record.did)
    ctx.devices.set_status(record.did, DeviceStatus.TOKENIZED)
    ok(SRC, f"token {token['token_id']} issued to {record.did} ({record.device_type}, role {record.role}), "
            f"scope provisional {token['allowed_operations']}, expires in "
            f"{int(token['expires_at'] - token['issued_at'])}s, queued for epoch {epoch_id}")
    return token


@router.post("/nonce")
def tokens_nonce(body: NonceRequest, request: Request):
    ctx = _ctx(request)
    if not ctx.token_state.was_issued(body.token_id):
        raise HTTPException(status_code=404, detail="unknown token_id")
    nonce = ctx.token_state.nonces.issue(TOKEN_NONCE_PURPOSE, body.token_id)
    info(SRC, f"fresh nonce {short(nonce, 8)} issued for token {body.token_id} "
              f"(single use, {int(ctx.token_state.nonces.ttl)}s)")
    return {"token_id": body.token_id, "nonce": nonce, "expires_in": ctx.token_state.nonces.ttl}


@router.post("/access")
def tokens_access(body: TokenAccessRequest, request: Request):
    ctx = _ctx(request)
    token = body.token

    if not token_signature_valid(token, ctx.signing_key):
        return _deny("bad_token_signature", "token signature check", "token forged or modified")

    tid, did = token["token_id"], token["did"]
    if token_expired(token):
        return _deny("expired", "token expiry check", f"token {tid} expired")

    nonce_status = ctx.token_state.nonces.consume(TOKEN_NONCE_PURPOSE, tid, body.nonce)
    if nonce_status != NONCE_OK:
        return _deny(nonce_status, "nonce validator", f"nonce {short(body.nonce, 8)} for token {tid}: {nonce_status}")
    info(SRC, f"nonce {short(body.nonce, 8)} fresh -> consumed")

    if ctx.token_state.is_revoked(tid) or is_device_revoked(ctx.devices, did):
        return _deny("revoked", "revocation checker", f"{did} / token {tid} is revoked")

    if not access_signature_valid(token, body.nonce, body.resource, body.operation, body.signature):
        return _deny("proof_of_possession_failed", "proof of possession check",
                     f"request not signed by the private key of {did} (token alone is not enough)")

    if not provisional_allowed(token["device_type"], body.resource, body.operation):
        return _deny("provisional_scope", "provisional scope check",
                     f"token only allows {token['allowed_operations']} on its own {token['device_type']}; "
                     f"'{body.operation}' on {body.resource} needs a finalized inclusion proof")

    if not check_policy(body.resource, body.operation, token["role"]):
        return _deny("policy_denied", "access policy", f"role {token['role']} may not {body.operation} a {body.resource}")

    ok(SRC, f"ALLOW (provisional) {did}: {body.operation} on {body.resource}")
    return {"decision": "ALLOW", "reason": "ok", "access": "provisional"}
