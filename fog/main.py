"""
Fog node application factory.

create_app() wires every component into one FogContext that routes access
through request.app.state.ctx. Tests call create_app() with temporary
paths; scripts/run_fog.py calls it with the real configuration.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional

from fastapi import FastAPI

import config
from common.crypto_utils import load_or_create_private_key, public_key_bytes
from fog.auth.psk import PSKStore
from fog.registration.routes import router as registration_router
from fog.storage.device_store import DeviceStore, SessionStore
from registry.ledger import Ledger


@dataclass
class FogContext:
    fog_id: str
    zone: str
    signing_key: object
    psk_store: PSKStore
    sessions: SessionStore
    devices: DeviceStore
    ledger: Ledger
    challenge_ttl: int

    @property
    def fog_public_key_hex(self) -> str:
        return public_key_bytes(self.signing_key).hex()


def create_app(
    psk_store_path: Path = config.PSK_STORE_PATH,
    psk_entries: Optional[Dict[str, str]] = None,
    signing_key_path: Path = config.FOG_SIGNING_KEY_PATH,
    ledger_path: Path = config.LEDGER_PATH,
    challenge_ttl: int = config.CHALLENGE_TTL_SECONDS,
    session_ttl: int = config.SESSION_TTL_SECONDS,
) -> FastAPI:
    signing_key = load_or_create_private_key(signing_key_path)
    ctx = FogContext(
        fog_id=config.FOG_ID,
        zone=config.FOG_ZONE,
        signing_key=signing_key,
        psk_store=PSKStore(path=psk_store_path, entries=psk_entries),
        sessions=SessionStore(ttl_seconds=session_ttl),
        devices=DeviceStore(),
        ledger=Ledger(ledger_path, signing_key, fog_id=config.FOG_ID),
        challenge_ttl=challenge_ttl,
    )

    app = FastAPI(title="IIoT Fog Node", version="1.0")
    app.state.ctx = ctx
    app.include_router(registration_router)
    # Partner routers (tokens, verification, revocation) get included here later.

    @app.get("/health")
    def health():
        return {
            "status": "ok",
            "fog_id": ctx.fog_id,
            "zone": ctx.zone,
            "fog_public_key": ctx.fog_public_key_hex,
            "registered_psks": len(ctx.psk_store),
            "anchored_epochs": len(ctx.ledger),
        }

    return app