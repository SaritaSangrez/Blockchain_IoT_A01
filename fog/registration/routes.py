"""
Phase 1 registration endpoints (steps 1 to 5 of the assignment).

POST /register/start    PSK check                 -> session_id
POST /register/pubkey   DID + PK                  -> fresh challenge
POST /register/pop      signature over challenge  -> key ownership proven

The session state machine enforces the order. Nothing about the device
identity is accepted before the PSK succeeds.
"""
from __future__ import annotations

import time

from fastapi import APIRouter, Header, HTTPException, Request

from common.canonical import COMPRESSED_PK_LEN
from common.crypto_utils import derive_did, load_public_key
from common.logger import fail, info, ok, short
from common.schemas import (
    ChallengeResponse,
    MetadataRequest,
    DeviceRecord,
    DeviceStatus,
    PopRequest,
    PopResponse,
    PublicKeyRequest,
    RegisterStartResponse,
)
from fog.auth.psk import parse_authorization
from fog.registration.pop import issue_challenge, verify_pop
from fog.batch.epoch_manager import EpochError
from fog.registration.validation import validate_metadata
from fog.storage.device_store import AUTHENTICATED, KEY_SUBMITTED, METADATA_ACCEPTED, POP_VERIFIED

router = APIRouter(prefix="/register", tags=["registration"])
SRC = "fog"


def _ctx(request: Request):
    return request.app.state.ctx


def _session_or_404(ctx, session_id: str):
    s = ctx.sessions.get(session_id)
    if s is None:
        fail(SRC, f"unknown or expired session {short(session_id, 8)}")
        raise HTTPException(status_code=404, detail="unknown or expired session")
    return s


def _require_state(s, expected: str):
    if s.state != expected:
        fail(SRC, f"session {short(s.session_id, 8)} is in state {s.state}, expected {expected}")
        raise HTTPException(status_code=409, detail=f"wrong step order: session is {s.state}, expected {expected}")


@router.post("/start", response_model=RegisterStartResponse)
def register_start(request: Request, authorization: str = Header(default=None)):
    ctx = _ctx(request)
    parsed = parse_authorization(authorization)
    if parsed is None:
        fail(SRC, "PSK rejected: missing or malformed Authorization header")
        raise HTTPException(status_code=401, detail="missing or malformed PSK header")

    prov_id, psk = parsed
    if not ctx.psk_store.check(prov_id, psk):
        fail(SRC, f"PSK rejected for provisioning id '{prov_id}'")
        raise HTTPException(status_code=401, detail="PSK authentication failed")

    s = ctx.sessions.create(prov_id)
    ok(SRC, f"PSK accepted for '{prov_id}', session {short(s.session_id, 8)} opened")
    return RegisterStartResponse(session_id=s.session_id, expires_in=ctx.sessions.ttl)


@router.post("/pubkey", response_model=ChallengeResponse)
def register_pubkey(body: PublicKeyRequest, request: Request):
    ctx = _ctx(request)
    s = _session_or_404(ctx, body.session_id)
    _require_state(s, AUTHENTICATED)

    try:
        pk_bytes = bytes.fromhex(body.public_key)
        if len(pk_bytes) != COMPRESSED_PK_LEN:
            raise ValueError("wrong length")
        load_public_key(pk_bytes)
    except ValueError:
        fail(SRC, "rejected: public key is not a valid compressed P256 point")
        raise HTTPException(status_code=400, detail="invalid public key")

    expected_did = derive_did(pk_bytes)
    if body.did != expected_did:
        fail(SRC, f"rejected: DID {body.did} is not derived from the submitted key (expected {expected_did})")
        raise HTTPException(status_code=400, detail="DID does not match public key fingerprint")

    existing = ctx.devices.get(body.did)
    if existing is not None:
        fail(SRC, f"rejected: DID {body.did} already known with status {existing.status.value}")
        raise HTTPException(status_code=409, detail=f"DID already known (status {existing.status.value})")
    if ctx.sessions.did_in_use(body.did, s.session_id):
        fail(SRC, f"rejected: DID {body.did} is already in another onboarding session")
        raise HTTPException(status_code=409, detail="DID already in an onboarding session")

    s.did = body.did
    s.public_key = body.public_key
    challenge = issue_challenge(s, ctx.challenge_ttl)
    s.state = KEY_SUBMITTED
    info(SRC, f"received DID {s.did}  PK {short(s.public_key)}")
    info(SRC, f"issued challenge {short(challenge)} (valid {ctx.challenge_ttl}s, single use)")
    return ChallengeResponse(session_id=s.session_id, challenge=challenge, expires_in=ctx.challenge_ttl)


@router.post("/pop", response_model=PopResponse)
def register_pop(body: PopRequest, request: Request):
    ctx = _ctx(request)
    s = _session_or_404(ctx, body.session_id)
    _require_state(s, KEY_SUBMITTED)

    passed, reason = verify_pop(s, body.signature)
    if not passed:
        fail(SRC, f"proof of possession FAILED for {s.did}: {reason}")
        # force the device to restart from /pubkey to get a new challenge
        s.state = AUTHENTICATED
        raise HTTPException(status_code=403, detail=f"proof of possession failed: {reason}")

    s.state = POP_VERIFIED
    s.timings["pop_verified_at"] = time.time()
    ctx.devices.upsert(DeviceRecord(did=s.did, public_key=s.public_key, status=DeviceStatus.PENDING))
    ok(SRC, f"proof of possession PASSED for {s.did}: device owns the private key")
    return PopResponse(session_id=s.session_id, did=s.did, status=POP_VERIFIED)


@router.post("/metadata")
def register_metadata(body: MetadataRequest, request: Request):
    """
    Step 6 to 8: validate metadata, create L_d = H(DID || PK), add it to the open batch.
    The tree is NOT rebuilt here; that happens once per epoch in finalize_epoch().
    """
    ctx = _ctx(request)
    s = _session_or_404(ctx, body.session_id)
    _require_state(s, POP_VERIFIED)

    errors = validate_metadata(body, ctx.zone, ctx.allowed_types)
    if errors:
        for e in errors:
            fail(SRC, f"metadata rejected for {s.did}: {e}")
        raise HTTPException(status_code=422, detail={"metadata_errors": errors})

    record = ctx.devices.get(s.did)
    record.device_name, record.device_type = body.device_name, body.device_type
    record.zone, record.vendor, record.role = body.zone, body.vendor, body.role

    try:
        leaf_hex = ctx.epochs.add_leaf(s.did, bytes.fromhex(s.public_key))
    except EpochError as e:
        raise HTTPException(status_code=409, detail=str(e))
    record.leaf = leaf_hex
    s.state = METADATA_ACCEPTED

    ok(SRC, f"metadata accepted for {body.device_name} ({body.device_type}, role {body.role})")
    info(SRC, f"leaf L_d = H(DID || PK) = {leaf_hex}")
    return {
        "did": s.did,
        "leaf": leaf_hex,
        "epoch_id": ctx.epochs.current_epoch_id,
        "batch_size": ctx.epochs.batch_size(),
        "status": "QUEUED_FOR_BATCH",
    }