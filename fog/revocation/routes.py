"""
Revocation endpoints (Member B).

POST /revocation/revoke        (admin, X-Admin-Key header)
    {"did": ...}                                  revoke the device and all its tokens
    {"did": ..., "token_id": ..., "token_only": true}
                                                  revoke only that one token
GET  /revocation/status/{did}  current status, revoked tokens, and whether the
                               device is in the latest anchored active set
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel

from common.logger import fail, ok
from fog.revocation.registry import is_device_revoked, revoke_device, revoke_token

router = APIRouter(prefix="/revocation", tags=["revocation"])


class RevokeRequest(BaseModel):
    did: str
    token_id: Optional[str] = None
    token_only: bool = False


def _ctx(request: Request):
    return request.app.state.ctx


@router.post("/revoke")
def revoke(body: RevokeRequest, request: Request, x_admin_key: str = Header(default=None)):
    ctx = _ctx(request)
    if x_admin_key != ctx.admin_key:
        fail("fog", "revoke refused: missing or wrong admin key")
        raise HTTPException(status_code=401, detail="admin key required")

    if body.token_only:
        if not body.token_id:
            raise HTTPException(status_code=422, detail="token_only requires token_id")
        if ctx.token_state.owner_of(body.token_id) != body.did or not revoke_token(ctx.token_state, body.token_id):
            raise HTTPException(status_code=404, detail="unknown token_id for this DID")
        ok("fog", f"token {body.token_id} of {body.did} revoked; device status unchanged")
        return {"did": body.did, "status": ctx.devices.get(body.did).status.value,
                "revoked_tokens": [body.token_id]}

    if not revoke_device(ctx.devices, body.did, ctx.token_state):
        raise HTTPException(status_code=404, detail="unknown DID")
    if body.token_id:
        ctx.token_state.revoke(body.token_id)
    revoked = [t for t in ctx.token_state.tokens_of(body.did) if ctx.token_state.is_revoked(t)]
    ok("fog", f"{body.did} REVOKED immediately; it will be excluded from the next epoch root")
    return {"did": body.did, "status": "REVOKED", "revoked_tokens": revoked}


@router.get("/status/{did}")
def status(did: str, request: Request):
    ctx = _ctx(request)
    record = ctx.devices.get(did)
    if record is None:
        raise HTTPException(status_code=404, detail="unknown DID")
    tokens = ctx.token_state.tokens_of(did)
    return {
        "did": did,
        "status": record.status.value,
        "revoked": is_device_revoked(ctx.devices, did),
        "last_epoch": record.epoch_id,
        "in_latest_active_set": did in ctx.epochs.active_dids,
        "tokens": {t: ("REVOKED" if ctx.token_state.is_revoked(t) else "active") for t in tokens},
    }
