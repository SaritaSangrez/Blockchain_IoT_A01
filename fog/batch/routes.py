"""
Epoch, proof and registry endpoints.

GET  /epoch/current            open epoch id, batch size, queued DIDs
POST /epoch/close              (admin) finalize: sort, build, root, anchor, proofs
GET  /proof/{did}              the device's proof package (latest, or ?epoch_id=)
GET  /registry/root/{epoch_id} trusted root + block from the ledger
GET  /registry/verify          verify the whole hash chain
"""
from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel

from common.logger import fail, info, ok
from common.schemas import DeviceStatus
from fog.batch.epoch_manager import EpochError

router = APIRouter(tags=["epochs"])


class CloseRequest(BaseModel):
    exclude_dids: List[str] = []


def _ctx(request: Request):
    return request.app.state.ctx


@router.get("/epoch/current")
def epoch_current(request: Request):
    ctx = _ctx(request)
    return {
        "epoch_id": ctx.epochs.current_epoch_id,
        "batch_size": ctx.epochs.batch_size(),
        "queued_dids": ctx.epochs.pending_dids(),
        "latest_anchored_epoch": ctx.ledger.latest_epoch(),
    }


@router.post("/epoch/close")
def epoch_close(request: Request, body: Optional[CloseRequest] = None,
                x_admin_key: str = Header(default=None)):
    ctx = _ctx(request)
    if x_admin_key != ctx.admin_key:
        fail("fog", "epoch close refused: missing or wrong admin key")
        raise HTTPException(status_code=401, detail="admin key required")
    try:
        result = ctx.epochs.finalize_epoch(exclude_dids=(body.exclude_dids if body else []))
    except EpochError as e:
        raise HTTPException(status_code=409, detail=str(e))
    return {
        "epoch_id": result.epoch_id,
        "root": result.root,
        "leaf_count": len(result.sorted_leaves),
        "new_devices": result.new_devices,
        "carried_forward": result.carried_forward,
        "excluded": result.excluded,
        "sorted_leaves": result.sorted_leaves,
        "block": result.block.model_dump(),
        "timings_ms": result.timings_ms,
    }


@router.get("/proof/{did}")
def get_proof(did: str, request: Request, epoch_id: Optional[int] = None):
    ctx = _ctx(request)
    rec = ctx.devices.get(did)
    if rec is None:
        raise HTTPException(status_code=404, detail="unknown DID")
    if rec.status == DeviceStatus.REVOKED:
        fail("fog", f"proof request refused: {did} is REVOKED")
        raise HTTPException(status_code=403, detail="device is revoked; no proof issued")
    pkg = ctx.epochs.get_package(did, epoch_id)
    if pkg is None:
        raise HTTPException(status_code=404, detail="no proof yet: device is waiting for the epoch to close")
    info("fog", f"proof package for {did} (epoch {pkg.epoch_id}, {len(pkg.proof_path)} siblings) sent")
    return pkg.model_dump()


@router.get("/registry/root/{epoch_id}")
def registry_root(epoch_id: int, request: Request):
    ctx = _ctx(request)
    block = ctx.ledger.get_block(epoch_id)
    if block is None:
        raise HTTPException(status_code=404, detail=f"epoch {epoch_id} not anchored")
    return {"epoch_id": epoch_id, "root": block.root, "block": block.model_dump()}


@router.get("/registry/verify")
def registry_verify(request: Request):
    valid, msg = _ctx(request).ledger.verify_chain()
    (ok if valid else fail)("ledger", msg)
    return {"valid": valid, "message": msg, "blocks": len(_ctx(request).ledger)}