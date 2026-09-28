"""
Phase 3 endpoints (Member B): normal verification and resource access.

  POST /verify/nonce  {did}  -> fresh fog-issued nonce (single use, 30 s)
  POST /verify        {proof_package, resource, operation, nonce, signature}
                             -> ALLOW / DENY

Checks, in this order (first failure wins):
  1. nonce               -> nonce_reused / nonce_unknown / ...   (replay protection)
  2. Merkle proof        -> recompute L_d = H(DID || PK), fetch the TRUSTED root
                            for the stated epoch from the root registry, verify
                            the path and the fog signature (Member A's
                            verify_proof_package; the root inside the package is
                            never trusted)
  3. proof of possession -> the request must be signed with the private key
                            whose public key is inside the proven leaf. A proof
                            package is not secret, so without this anyone who
                            copied it could act as the device.
  4. current status      -> unknown_device / device_revoked / not_registered.
                            A historical proof stays mathematically valid after
                            revocation; current status decides if it may act NOW.
  5. role sanity         -> role_type_mismatch (role must fit the device type)
  6. access policy       -> policy_denied, using the role from the fog's own
                            record (never from the request)

Every response includes identity_verified so the demo can show
"identity proven, but not authorized".
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from common.crypto_utils import public_key_bytes, sign, verify
from common.logger import fail, info, ok, short
from common.schemas import DeviceStatus
from fog.policy.access_policy import check_policy, role_valid_for_type
from fog.proofs.proof_package import verify_proof_package
from fog.tokens.store import NONCE_OK

router = APIRouter(prefix="/verify", tags=["verification"])
SRC = "verify"
VERIFY_LABEL = b"IIOT_VERIFY_ACCESS_V1"
VERIFY_NONCE_PURPOSE = "verify_access"


def verify_message(did: str, epoch_id: int, nonce: str, resource: str, operation: str) -> bytes:
    """Exact bytes the DEVICE signs for one Phase 3 request."""
    return b"|".join([VERIFY_LABEL, did.encode(), str(epoch_id).encode(), nonce.encode(),
                      resource.encode(), operation.encode()])


def sign_verify_request(device_private_key, pkg: dict, nonce: str, resource: str, operation: str) -> str:
    """Device side helper."""
    return sign(device_private_key, verify_message(pkg["did"], pkg["epoch_id"], nonce, resource, operation)).hex()


def _ctx(request: Request):
    return request.app.state.ctx


class VerifyNonceRequest(BaseModel):
    did: str


class VerifyRequest(BaseModel):
    proof_package: dict
    resource: str
    operation: str
    nonce: str
    signature: str


def _deny(did, reason, detected_by, msg, identity_verified=False, epoch_id=None) -> dict:
    fail(SRC, f"DENY {did} [{detected_by}] {msg}")
    return {"decision": "DENY", "reason": reason, "detected_by": detected_by,
            "identity_verified": identity_verified, "epoch_id": epoch_id}


@router.post("/nonce")
def verify_nonce(body: VerifyNonceRequest, request: Request):
    ctx = _ctx(request)
    if not ctx.devices.exists(body.did):
        raise HTTPException(status_code=404, detail="unknown DID")
    nonce = ctx.token_state.nonces.issue(VERIFY_NONCE_PURPOSE, body.did)
    info(SRC, f"fresh nonce {short(nonce, 8)} issued for {body.did} (single use, {int(ctx.token_state.nonces.ttl)}s)")
    return {"did": body.did, "nonce": nonce, "expires_in": ctx.token_state.nonces.ttl}


@router.post("")
def verify_and_authorize(body: VerifyRequest, request: Request):
    ctx = _ctx(request)
    pkg = body.proof_package
    did = pkg.get("did")
    epoch_id = pkg.get("epoch_id")

    # 1. replay protection
    nonce_status = ctx.token_state.nonces.consume(VERIFY_NONCE_PURPOSE, str(did), body.nonce)
    if nonce_status != NONCE_OK:
        return _deny(did, nonce_status, "nonce validator", f"nonce {short(body.nonce, 8)}: {nonce_status}",
                     epoch_id=epoch_id)

    # 2. identity: Merkle inclusion against the TRUSTED root of that epoch
    trusted_root = ctx.ledger.get_root(epoch_id) if isinstance(epoch_id, int) else None
    try:
        result = verify_proof_package(pkg, trusted_root, public_key_bytes(ctx.signing_key))
    except Exception as e:  # malformed package (missing fields, wrong types)
        return _deny(did, "malformed_proof_package", "proof package parser", str(e).splitlines()[0],
                     epoch_id=epoch_id)
    if not result.ok:
        extra = ""
        if result.reconstructed_root and result.trusted_root:
            extra = (f" (reconstructed {short(result.reconstructed_root, 10)} "
                     f"!= anchored {short(result.trusted_root, 10)})")
        return _deny(did, result.reason, result.detected_by, f"proof rejected: {result.reason}{extra}",
                     epoch_id=epoch_id)
    info(SRC, f"{did}: leaf recomputed, proof verified against anchored root "
              f"{short(trusted_root, 10)} of epoch {epoch_id}")

    # 3. proof of possession for THIS request
    try:
        pk_bytes = bytes.fromhex(pkg["public_key"])
    except (KeyError, ValueError, TypeError):
        pk_bytes = b""
    if not verify(pk_bytes, verify_message(did, epoch_id, body.nonce, body.resource, body.operation),
                  bytes.fromhex(body.signature) if _is_hex(body.signature) else b""):
        return _deny(did, "proof_of_possession_failed", "proof of possession check",
                     "valid proof package but request not signed by its private key (copied package?)",
                     identity_verified=True, epoch_id=epoch_id)

    # 4. CURRENT status (historical proof vs current authorization)
    record = ctx.devices.get(did)
    if record is None:
        return _deny(did, "unknown_device", "device status check", "no current record at this fog",
                     identity_verified=True, epoch_id=epoch_id)
    if record.status == DeviceStatus.REVOKED:
        return _deny(did, "device_revoked", "revocation checker",
                     f"proof for epoch {epoch_id} is still mathematically valid, but the device is revoked NOW",
                     identity_verified=True, epoch_id=epoch_id)
    if record.status != DeviceStatus.REGISTERED:
        return _deny(did, "not_registered", "device status check", f"status is {record.status.value}",
                     identity_verified=True, epoch_id=epoch_id)

    # 5. role sanity + 6. access policy (role from the fog's record, not from the request)
    if not role_valid_for_type(record.device_type, record.role):
        return _deny(did, "role_type_mismatch", "access policy",
                     f"registered role '{record.role}' is not valid for a {record.device_type}",
                     identity_verified=True, epoch_id=epoch_id)
    if not check_policy(body.resource, body.operation, record.role):
        return _deny(did, "policy_denied", "access policy",
                     f"identity OK, but role {record.role} may not {body.operation} a {body.resource}",
                     identity_verified=True, epoch_id=epoch_id)

    ok(SRC, f"ALLOW {did} ({record.role}): {body.operation} on {body.resource}")
    return {"decision": "ALLOW", "reason": "ok", "identity_verified": True, "epoch_id": epoch_id,
            "role": record.role}


def _is_hex(s: str) -> bool:
    try:
        bytes.fromhex(s)
        return True
    except (ValueError, TypeError):
        return False
