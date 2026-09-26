"""
Phase 2 and 3 live demo (assignment demo steps 6 to 10, Member B). The fog
must be running:
    terminal 1:  python scripts/run_fog.py
    terminal 2:  python scripts/demo_phase2.py            (runs straight through)
                 python scripts/demo_phase2.py --pause    (waits for Enter between steps)
                 python scripts/demo_phase2.py --device temp02

Shows, in order:
  STEP 6  temporary-token issuance and provisional resource access for a
          device that hasn't been through a finalized batch yet, then the
          device queues itself for the next batch
  STEP 7  epoch close, then the SAME device proven through Phase 3 (/verify):
          one ALLOWED operation and one DENIED operation, to show identity
          verification and access-control are two separate checks
  STEP 8  the device is revoked; the exact same, still cryptographically
          valid proof is presented again and is now denied -- revocation is
          immediate and does not depend on a new epoch
  STEP 9  runs attacks/token_attacks.py (replay, stolen token, expired
          token, revoked-device token) against a fresh isolated fog instance,
          so token expiry can be demonstrated in under a second live
  STEP 10 prints the already-measured verification / token-access / resource-
          access / throughput results and points to the saved graphs

Can be run standalone (it registers and closes its own batch), or after
scripts/demo_phase1.py -- either way is fine.
"""
from __future__ import annotations

import argparse
import csv
import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import httpx

import config
from common.crypto_utils import generate_keypair, sign
from common.logger import fail, info, ok, short, step, warn
from devices.device import Device, make_tls_client
from fog.tokens.tokens import access_message

DEFAULT_DEVICE = "temp02"  # kept separate from demo_phase1's default devices


def pause(enabled: bool):
    if enabled:
        input("\n   press Enter to continue ...")


def signed_access_body(device: Device, token: dict, nonce: str, operation: str) -> dict:
    signature = sign(device.private_key, access_message(token["token_id"], token["did"], nonce)).hex()
    return {"token": token, "nonce": nonce, "signature": signature, "operation": operation}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--device", default=DEFAULT_DEVICE, help="device used for steps 6 to 8")
    parser.add_argument("--pause", action="store_true")
    args = parser.parse_args()

    admin = make_tls_client()
    try:
        health = admin.get("/health").json()
    except httpx.ConnectError:
        fail("demo", f"cannot reach {config.FOG_BASE_URL}. Start it first: python scripts/run_fog.py")
        sys.exit(1)

    step("STEP 0  Fog node status")
    ok("demo", f"connected over TLS to {health['fog_id']} (zone {health['zone']})")
    info("demo", f"open epoch {health['current_epoch']}, anchored epochs so far {health['anchored_epochs']}")
    pause(args.pause)

    device_type, role = config.DEMO_DEVICES.get(args.device, config.SIM_DEVICE_TYPE)

    # ---------------------------------------------------------------
    step(f"STEP 6  Temporary-token bridging for {args.device} (batch still open)")
    d = Device(args.device, persist_key=False)
    d.register_start()
    challenge = d.submit_public_key()
    d.prove_possession(challenge)
    info("demo", f"{args.device} has proven key ownership but has NOT called /register/metadata yet: "
                 "no leaf, no batch entry, no proof package exist for it yet")

    r = d.client.post("/tokens/issue", json={"session_id": d.session_id, "device_type": device_type, "role": role})
    if r.status_code != 200:
        fail("demo", f"token issue failed: {r.text}")
        sys.exit(1)
    token = r.json()
    ok(args.device, f"temporary token {short(token['token_id'], 8)} issued, "
                    f"expires in {int(token['expires_at'] - token['issued_at'])}s")

    nonce = secrets.token_hex(8)
    access_r = d.client.post("/tokens/access", json=signed_access_body(d, token, nonce, "read"))
    info("demo", f"provisional resource access on the token alone -> {access_r.json()}")

    d.submit_metadata(device_type=device_type, role=role)
    info("demo", f"{args.device} is now queued for the next batch -- the token was only a bridge, "
                 "not a substitute for the inclusion proof")
    pause(args.pause)

    # ---------------------------------------------------------------
    step(f"STEP 7  Close the batch, then verify {args.device} through Phase 3 (/verify)")
    r = admin.post("/epoch/close", headers={"X-Admin-Key": config.ADMIN_KEY})
    if r.status_code != 200:
        fail("demo", f"epoch close failed: {r.text}")
        sys.exit(1)
    closed = r.json()
    ok("demo", f"epoch {closed['epoch_id']} closed, root {short(closed['root'], 16)}, "
               f"{closed['leaf_count']} leaves anchored")
    pkg = d.fetch_proof()

    r_allow = admin.post("/verify", json={"proof_package": pkg, "device_type": device_type, "operation": "read"})
    ok("verifier", f"{args.device} requests READ -> {r_allow.json()}")

    r_deny = admin.post("/verify", json={"proof_package": pkg, "device_type": device_type, "operation": "stop"})
    fail("verifier", f"{args.device} requests STOP -> {r_deny.json()}")
    info("demo", "same valid identity proof, two different authorization outcomes: "
                 "identity verification and access-control policy are separate steps")
    pause(args.pause)

    # ---------------------------------------------------------------
    step(f"STEP 8  Revoke {args.device}, then re-present the SAME still-valid proof")
    before = admin.get(f"/revocation/status/{d.did}").json()
    info("demo", f"revocation status before: {before}")
    admin.post("/revocation/revoke", json={"did": d.did}, headers={"X-Admin-Key": config.ADMIN_KEY})
    after = admin.get(f"/revocation/status/{d.did}").json()
    ok("demo", f"revocation status after:  {after}")

    r_after = admin.post("/verify", json={"proof_package": pkg, "device_type": device_type, "operation": "read"})
    fail("verifier", f"{args.device} requests READ again -> {r_after.json()}")
    info("demo", "the Merkle proof is still cryptographically TRUE -- revocation is a separate, immediate check "
                 "on top of identity. This is the historical-proof-vs-current-status distinction the brief asks for.")
    pause(args.pause)
    d.close()

    # ---------------------------------------------------------------
    step("STEP 9  Attack demonstrations")
    info("demo", "runs replay / stolen-token / expired-token / revoked-token against a fresh, isolated "
                 "fog instance (needed to fast-forward an expiry live) -- see attacks/token_attacks.py")
    from attacks.token_attacks import main as run_attacks
    run_attacks()
    pause(args.pause)

    # ---------------------------------------------------------------
    step("STEP 10  Performance and scalability results")
    info("demo", "to reproduce or extend the sweep: "
                 "python benchmarks/bench_verifications.py --runs 5 --counts 5 10 25 50 100")
    summary_path = Path(__file__).resolve().parent.parent / "benchmarks" / "results" / "verification_summary.csv"
    if summary_path.exists():
        with summary_path.open(newline="") as f:
            rows = list(csv.DictReader(f))
        print(f"\n   {'devices':>8} {'verify (ms)':>13} {'token (ms)':>12} {'seq rps':>10} {'concurrent rps':>16}")
        for row in rows:
            print(f"   {row['n_devices']:>8} "
                  f"{float(row['verification_latency_ms_mean']):>13.3f} "
                  f"{float(row['token_access_latency_ms_mean']):>12.3f} "
                  f"{float(row['throughput_sequential_rps_mean']):>10.2f} "
                  f"{float(row['throughput_concurrent_rps_mean']):>16.2f}")
        ok("demo", "graphs: benchmarks/graphs/graph2_verification_latency.png, "
                   "token_access_latency.png, graph3_throughput.png")
    else:
        warn("demo", "no results yet -- run benchmarks/bench_verifications.py first")

    admin.close()


if __name__ == "__main__":
    main()
