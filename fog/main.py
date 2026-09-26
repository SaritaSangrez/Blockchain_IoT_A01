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
from fog.batch.epoch_manager import EpochManager
from fog.batch.routes import router as epoch_router
from fog.registration.routes import router as registration_router
from fog.storage.device_store import DeviceStore, SessionStore
from registry.ledger import Ledger

from fog.revocation.routes import router as revocation_router
from fog.tokens.routes import router as tokens_router
from fog.tokens.store import TokenState
from fog.verification.routes import router as verification_router

@dataclass
class FogContext:
    fog_id: str
    zone: str
    signing_key: object
    psk_store: PSKStore
    sessions: SessionStore
    devices: DeviceStore
    ledger: Ledger
    epochs: EpochManager
    challenge_ttl: int
    admin_key: str
    allowed_types: set
    token_state: TokenState

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
    carry_forward: bool = config.CARRY_FORWARD_ACTIVE,
    admin_key: str = config.ADMIN_KEY,
    verbose: bool = True,
) -> FastAPI:
    signing_key = load_or_create_private_key(signing_key_path)
    devices = DeviceStore()
    ledger = Ledger(ledger_path, signing_key, fog_id=config.FOG_ID)
    ctx = FogContext(
        fog_id=config.FOG_ID,
        zone=config.FOG_ZONE,
        signing_key=signing_key,
        psk_store=PSKStore(path=psk_store_path, entries=psk_entries),
        sessions=SessionStore(ttl_seconds=session_ttl),
        devices=devices,
        ledger=ledger,
        epochs=EpochManager(ledger, signing_key, config.FOG_ID, devices,
                            carry_forward=carry_forward, verbose=verbose),
        challenge_ttl=challenge_ttl,
        admin_key=admin_key,
        allowed_types=set(config.ALLOWED_DEVICE_TYPES),
        token_state=TokenState(),
    )

    app = FastAPI(title="IIoT Fog Node", version="1.0")
    app.state.ctx = ctx
    app.include_router(registration_router)
    app.include_router(epoch_router)
    app.include_router(revocation_router)
    app.include_router(tokens_router)
    app.include_router(verification_router)

    @app.get("/health")
    def health():
        return {
            "status": "ok",
            "fog_id": ctx.fog_id,
            "zone": ctx.zone,
            "fog_public_key": ctx.fog_public_key_hex,
            "registered_psks": len(ctx.psk_store),
            "anchored_epochs": len(ctx.ledger),
            "current_epoch": ctx.epochs.current_epoch_id,
            "batch_size": ctx.epochs.batch_size(),
        }

    return app
