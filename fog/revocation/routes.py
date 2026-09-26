"""
Revocation endpoint (Member B).

POST /revocation/revoke        (admin) mark a device REVOKED, effective immediately.
                                Optionally also blacklist one specific token_id, for
                                the case where you only want to kill one still-open
                                token rather than the whole device.
GET  /revocation/status/{did}  check current revocation status
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel

from common.logger import fail, ok
from fog.revocation.registry import is_device_revoked, revoke_device

router = APIRouter(prefix="/revocation", tags=["revocation"])


class RevokeRequest(BaseModel):
    did: str
    token_id: Optional[str] = None  # optional: also blacklist this one token specifically


def _ctx(request: Request):
    return request.app.state.ctx


@router.post("/revoke")
def revoke(body: RevokeRequest, request: Request, x_admin_key: str = Header(default=None)):
    ctx = _ctx(request)
    if x_admin_key != ctx.admin_key:
        fail("fog", "revoke refused: missing or wrong admin key")
        raise HTTPException(status_code=401, detail="admin key required")

    if not revoke_device(ctx.devices, body.did):
        raise HTTPException(status_code=404, detail="unknown DID")

    if body.token_id:
        # Device-level revocation already blocks every future request for this DID
        # (is_device_revoked() is checked in both /verify and /tokens/access), so
        # this is not required for correctness -- it lets you blacklist one specific
        # token_id explicitly, e.g. if you only want to kill a leaked token without
        # revoking the whole device.
        ctx.token_state.revoke(body.token_id)
        ok("fog", f"{body.did} revoked, token {body.token_id} explicitly blacklisted")
    else:
        ok("fog", f"{body.did} revoked")

    return {"did": body.did, "status": "REVOKED", "token_id": body.token_id}


@router.get("/status/{did}")
def status(did: str, request: Request):
    ctx = _ctx(request)
    if not ctx.devices.exists(did):
        raise HTTPException(status_code=404, detail="unknown DID")
    return {"did": did, "revoked": is_device_revoked(ctx.devices, did)}
