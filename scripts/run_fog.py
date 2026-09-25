"""
Start the fog node over HTTPS.
Run from the project root:   python scripts/run_fog.py
Stop with Ctrl+C.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import uvicorn

import config
from common.logger import fail, info, ok, step
from fog.main import create_app


def main():
    step(f"Starting fog node {config.FOG_ID} for zone {config.FOG_ZONE}")
    for p in (config.FOG_TLS_CERT_PATH, config.FOG_TLS_KEY_PATH, config.PSK_STORE_PATH):
        if not p.exists():
            fail("fog", f"missing {p}. Run: python scripts/gen_certs.py")
            sys.exit(1)

    app = create_app()
    ctx = app.state.ctx
    ok("fog", f"loaded {len(ctx.psk_store)} PSK hashes")
    ok("fog", f"fog signing public key {ctx.fog_public_key_hex[:20]}...")
    valid, msg = ctx.ledger.verify_chain()
    (ok if valid else fail)("ledger", msg)
    info("fog", f"open epoch {ctx.epochs.current_epoch_id}, carry forward active devices = {config.CARRY_FORWARD_ACTIVE}")
    if config.AUTO_EPOCH_SECONDS > 0:
        ctx.epochs.start_auto_close(config.AUTO_EPOCH_SECONDS)
    else:
        info("fog", "epochs close manually (POST /epoch/close, or run the demo script)")
    info("fog", f"listening on {config.FOG_BASE_URL}  (TLS enabled)")

    uvicorn.run(
        app,
        host="127.0.0.1",
        port=config.FOG_PORT,
        ssl_certfile=str(config.FOG_TLS_CERT_PATH),
        ssl_keyfile=str(config.FOG_TLS_KEY_PATH),
        log_level="warning",
    )


if __name__ == "__main__":
    main()