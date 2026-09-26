"""
Phase 3 endpoint (Member B): verify a device's Merkle proof package and
decide ALLOW/DENY. Reuses Member A's verify_proof_package() completely
for the identity check -- this file only adds what comes AFTER identity
is proven: revocation and access policy.
"""
from __future__ import annotations

from fastapi import APIRouter, Request
from pydantic import BaseModel

from common.crypto_utils import public_key_bytes
from common.logger import fail, info, ok
from fog.policy.access_policy import check_policy
from fog.proofs.proof_package import verify_proof_package
from fog.revocation.registry import is_device_revoked

router = APIRouter(prefix="/verify", tags=["verification"])
SRC = "verify"


def _ctx(request: Request):
    return request.app.state.ctx


class VerifyRequest(BaseModel):
    proof_package: dict
    device_type: str
    operation: str


@router.post("")
def verify_and_authorize(body: VerifyRequest, request: Request):
    ctx = _ctx(request)
    pkg = body.proof_package
    did = pkg.get("did")

    trusted_root = ctx.ledger.get_root(pkg.get("epoch_id"))
    result = verify_proof_package(pkg, trusted_root, public_key_bytes(ctx.signing_key))

    if not result.ok:
        fail(SRC, f"DENY {did}: proof rejected by {result.detected_by} -- {result.reason}")
        return {"decision": "DENY", "reason": result.reason, "detected_by": result.detected_by}

    if is_device_revoked(ctx.devices, did):
        fail(SRC, f"DENY {did}: device revoked (proof was still cryptographically valid)")
        return {"decision": "DENY", "reason": "device_revoked", "detected_by": "revocation check"}

    record = ctx.devices.get(did)
    role = record.role if record and record.role else ""
    if not check_policy(body.device_type, body.operation, role):
        fail(SRC, f"DENY {did}: policy forbids {body.operation} on {body.device_type}")
        return {"decision": "DENY", "reason": "policy_denied", "detected_by": "access policy"}

    ok(SRC, f"ALLOW {did}: {body.operation} on {body.device_type}")
    return {"decision": "ALLOW", "reason": "ok"}