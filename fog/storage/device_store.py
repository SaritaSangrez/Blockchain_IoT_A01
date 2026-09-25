"""
In memory state held by the fog node.

SessionStore:  registration sessions (one per onboarding attempt)
DeviceStore:   device records keyed by DID (status, metadata, leaf, epoch)
"""
from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from common.schemas import DeviceRecord, DeviceStatus

# Registration session states, in the only order they may happen
AUTHENTICATED = "AUTHENTICATED"      # PSK accepted
KEY_SUBMITTED = "KEY_SUBMITTED"      # DID + PK received, challenge issued
POP_VERIFIED = "POP_VERIFIED"        # signature over challenge verified
METADATA_ACCEPTED = "METADATA_ACCEPTED"  # leaf created and queued (next step)


@dataclass
class Session:
    session_id: str
    provisioning_id: str
    created_at: float
    state: str = AUTHENTICATED
    did: Optional[str] = None
    public_key: Optional[str] = None
    challenge: Optional[str] = None
    challenge_expires: float = 0.0
    challenge_used: bool = True
    timings: Dict[str, float] = field(default_factory=dict)


class SessionStore:
    def __init__(self, ttl_seconds: int):
        self.ttl = ttl_seconds
        self._sessions: Dict[str, Session] = {}
        self._lock = threading.Lock()

    def create(self, provisioning_id: str) -> Session:
        s = Session(session_id=secrets.token_hex(16), provisioning_id=provisioning_id, created_at=time.time())
        with self._lock:
            self._sessions[s.session_id] = s
        return s

    def get(self, session_id: str) -> Optional[Session]:
        with self._lock:
            s = self._sessions.get(session_id)
            if s and time.time() > s.created_at + self.ttl:
                del self._sessions[session_id]
                return None
            return s

    def did_in_use(self, did: str, exclude_session: str) -> bool:
        with self._lock:
            return any(
                s.did == did and s.session_id != exclude_session and s.state != AUTHENTICATED
                for s in self._sessions.values()
            )


class DeviceStore:
    def __init__(self):
        self._devices: Dict[str, DeviceRecord] = {}
        self._lock = threading.Lock()

    def upsert(self, record: DeviceRecord) -> None:
        with self._lock:
            self._devices[record.did] = record

    def get(self, did: str) -> Optional[DeviceRecord]:
        with self._lock:
            return self._devices.get(did)

    def exists(self, did: str) -> bool:
        with self._lock:
            return did in self._devices

    def set_status(self, did: str, status: DeviceStatus) -> None:
        with self._lock:
            if did in self._devices:
                self._devices[did].status = status

    def by_status(self, status: DeviceStatus) -> List[DeviceRecord]:
        with self._lock:
            return [d for d in self._devices.values() if d.status == status]

    def all(self) -> List[DeviceRecord]:
        with self._lock:
            return list(self._devices.values())