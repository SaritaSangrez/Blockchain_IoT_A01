"""
Shared data contract between both group members.
Changing a field here is a team decision: fog, devices, verifier and
tests all depend on these shapes.
"""
from __future__ import annotations

from enum import Enum
from typing import List, Literal, Optional

from pydantic import BaseModel, Field


class DeviceStatus(str, Enum):
    PENDING = "PENDING"          # key ownership proven, waiting for metadata or batch
    TOKENIZED = "TOKENIZED"      # holds a temporary token, waiting for batch (Phase 2)
    REGISTERED = "REGISTERED"    # included in a finalized epoch, has a proof package
    REVOKED = "REVOKED"          # blocked by the fog


# ---------- Registration API (Phase 1) ----------

class RegisterStartResponse(BaseModel):
    session_id: str
    expires_in: int


class PublicKeyRequest(BaseModel):
    session_id: str
    did: str
    public_key: str = Field(description="hex of 33 byte compressed P256 point")


class ChallengeResponse(BaseModel):
    session_id: str
    challenge: str = Field(description="hex of 32 random bytes")
    expires_in: int


class PopRequest(BaseModel):
    session_id: str
    signature: str = Field(description="hex DER ECDSA signature over pop_message(challenge, did)")


class PopResponse(BaseModel):
    session_id: str
    did: str
    status: str


class MetadataRequest(BaseModel):
    session_id: str
    device_name: str
    device_type: str
    zone: str
    vendor: str
    role: str


# ---------- Merkle proof and proof package ----------

class ProofStep(BaseModel):
    sibling: str                      # hex of the sibling hash
    side: Literal["L", "R"]           # which side the SIBLING sits on


class ProofPackage(BaseModel):
    did: str
    public_key: str
    leaf: str
    epoch_id: int
    root: str
    proof_path: List[ProofStep]
    fog_id: str
    fog_signature: str                # fog signs leaf || root || epoch_id


# ---------- Root registry ----------

class AnchorRecord(BaseModel):
    block_index: int
    epoch_id: int
    root: str
    leaf_count: int
    timestamp: str
    fog_id: str
    prev_hash: str
    signature: str
    block_hash: str


class DeviceRecord(BaseModel):
    did: str
    public_key: str
    status: DeviceStatus
    device_name: Optional[str] = None
    device_type: Optional[str] = None
    zone: Optional[str] = None
    vendor: Optional[str] = None
    role: Optional[str] = None
    leaf: Optional[str] = None
    epoch_id: Optional[int] = None