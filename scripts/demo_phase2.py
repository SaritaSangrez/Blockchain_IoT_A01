"""
Phase 2 and 3 live demo (assignment demo steps 6 to 10, Member B).

Normal use (fog running over HTTPS, ideally right after demo_phase1.py so the
tree already holds the Phase 1 devices):
    terminal 1:  python scripts/run_fog.py
    terminal 2:  python scripts/demo_phase2.py --pause

Without a separate fog (in-process fog with a temporary ledger, handy for a
quick check; PSKs are read from devices/keystore/provisioning.json):
    python scripts/demo_phase2.py --inprocess

STEP 6  temp02 authenticates (PSK + PoP), its leaf is QUEUED in the open batch,
        it receives a temporary fog-signed token and uses it with a fresh
        fog-issued nonce per request. Provisional scope: WRITE its own reading
        is allowed, STOP or touching another device type is not.
STEP 7  the epoch closes; temp02 fetches its inclusion proof and uses Phase 3.
        Same valid identity, different decisions: sensor WRITE -> ALLOW,
        sensor STOP -> DENY (policy), controller STOP -> ALLOW.
STEP 8  temp02 is revoked: token and old proof are denied immediately, the old
        proof is still valid HISTORY for its epoch, and the next epoch root no
        longer contains temp02.
STEP 9  attack demonstrations (attacks/token_attacks.py)
STEP 10 performance results (benchmarks/bench_verifications.py)
"""
from __future__ import annotations

import argparse
import csv
import json
import secrets
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import httpx

import config
from common.crypto_utils import public_key_bytes
from common.logger import fail, info, ok, short, step, warn
from devices.device import Device, load_psk, make_tls_client
from devices.runtime_client import request_token, token_access, verify_access
from fog.proofs.proof_package import verify_proof_package

ADMIN = {"X-Admin-Key": config.ADMIN_KEY}
ROOT = Path(__file__).resolve().parent.parent


def pause(enabled: bool):
    if enabled:
        input("\n   press Enter to continue ...")


def show_decision(who: str, what: str, resp: dict):
    line = f"{who} {what} -> {resp.get('decision')} ({resp.get('reason')})"
    if resp.get("detected_by"):
        line += f"  detected by: {resp['detected_by']}"
    if "identity_verified" in resp:
        line += f"  identity_verified={resp['identity_verified']}"
    (ok if resp.get("decision") == "ALLOW" else fail)("decision", line)


def make_transport(inprocess: bool):
    """Returns (new_client_fn, psk_for_fn, fog_public_key_bytes_or_None)."""
    if not inprocess:
        return (lambda: make_tls_client()), load_psk, None
    from fastapi.testclient import TestClient
    from fog.auth.psk import PSKStore
    from fog.main import create_app
    psks = json.loads(config.DEVICE_PROVISIONING_PATH.read_text(encoding="utf-8"))
    tmp = Path(tempfile.mkdtemp())
    app = create_app(psk_entries={n: PSKStore.hash_psk(p) for n, p in psks.items()},
                     signing_key_path=tmp / "fog_signing_key.pem", ledger_path=tmp / "ledger.json")
    client = TestClient(app)
    return (lambda: client), (lambda n: psks[n]), public_key_bytes(app.state.ctx.signing_key)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--device", default="temp02", help="sensor used for the token / revocation steps")
    parser.add_argument("--controller", default="plc01", help="controller used to show a STOP that is allowed")
    parser.add_argument("--pause", action="store_true", help="wait for Enter between steps")
    parser.add_argument("--inprocess", action="store_true", help="run against an in-process fog (no run_fog.py)")
    parser.add_argument("--skip-attacks", action="store_true")
    args = parser.parse_args()

    new_client, psk_for, fog_pk = make_transport(args.inprocess)
    admin = new_client()
    try:
        health = admin.get("/health").json()
    except httpx.ConnectError:
        fail("demo", f"cannot reach {config.FOG_BASE_URL}. Start it first: python scripts/run_fog.py "
                     f"(or use --inprocess)")
        sys.exit(1)
    if fog_pk is None:
        fog_pk = bytes.fromhex(health["fog_public_key"])

    step("STEP 0  Fog node status")
    ok("demo", f"connected to {health['fog_id']} (zone {health['zone']})")
    info("demo", f"open epoch {health['current_epoch']}, anchored epochs so far {health['anchored_epochs']}")

    dev_type, dev_role = config.DEMO_DEVICES.get(args.device, config.SIM_DEVICE_TYPE)
    ctl_type, ctl_role = config.DEMO_DEVICES.get(args.controller, ("plc", "controller"))
    pause(args.pause)

    # ------------------------------------------------------------------
    step(f"STEP 6  Temporary-token bridging for {args.device} (registration batch still OPEN)")
    d = Device(args.device, psk=psk_for(args.device), client=new_client(), persist_key=False)
    d.register_start()
    d.prove_possession(d.submit_public_key())
    d.submit_metadata(device_type=dev_type, role=dev_role)
    current = admin.get("/epoch/current").json()
    info("demo", f"{args.device} is authenticated and QUEUED for epoch {current['epoch_id']} "
                 f"(batch size {current['batch_size']}), but the tree is not built yet -> no inclusion proof")
    r = d.client.get(f"/proof/{d.did}")
    warn("demo", f"GET /proof/{short(d.did, 10)} -> HTTP {r.status_code} {r.json().get('detail')}")

    token = request_token(d)
    ok(args.device, f"temporary token received: id {token['token_id']}, role {token['role']}, "
                    f"scope {token['scope']} {token['allowed_operations']}, "
                    f"valid {int(token['expires_at'] - token['issued_at'])}s, fog signature {short(token['signature'], 8)}")

    resp, body = token_access(d, token, dev_type, "write")
    info(args.device, f"asked fog for a fresh nonce {short(body['nonce'], 8)}, signed "
                      f"(token_id|did|nonce|resource|operation) with its private key")
    show_decision(args.device, f"[token] WRITE {dev_type}", resp)
    resp, _ = token_access(d, token, dev_type, "stop")
    show_decision(args.device, f"[token] STOP {dev_type}", resp)
    resp, _ = token_access(d, token, ctl_type, "read")
    show_decision(args.device, f"[token] READ {ctl_type}", resp)
    info("demo", "a token gives only limited, provisional access; full rights need the inclusion proof")

    ctl = Device(args.controller, psk=psk_for(args.controller), client=new_client(), persist_key=False, verbose=False)
    ctl.register()
    ok("demo", f"controller {args.controller} ({ctl_role}) also joined the same open batch")
    pause(args.pause)

    # ------------------------------------------------------------------
    step(f"STEP 7  Close the batch, then Phase 3 verification and authorization")
    closed = admin.post("/epoch/close", headers=ADMIN).json()
    epoch1 = closed["epoch_id"]
    ok("demo", f"epoch {epoch1} closed: {closed['leaf_count']} leaves ({closed['new_devices']} new, "
               f"{closed['carried_forward']} carried forward), root {short(closed['root'], 16)} anchored "
               f"as block {closed['block']['block_index']}")
    pkg = d.fetch_proof()
    ctl.fetch_proof()
    info(args.device, f"leaf {short(pkg['leaf'], 10)}, {len(pkg['proof_path'])} sibling hashes, epoch {pkg['epoch_id']}")

    resp, _ = verify_access(d, dev_type, "write")
    show_decision(args.device, f"[proof] WRITE {dev_type}", resp)
    resp, _ = verify_access(d, dev_type, "stop")
    show_decision(args.device, f"[proof] STOP {dev_type}", resp)
    resp, _ = verify_access(ctl, dev_type, "stop")
    show_decision(args.controller, f"[proof] STOP {dev_type}", resp)
    info("demo", "identity verification (Merkle proof) and authorization (role policy) are separate steps: "
                 "the sensor's identity is proven, yet STOP is denied")
    pause(args.pause)

    # ------------------------------------------------------------------
    step(f"STEP 8  Revocation of {args.device}: historical proof vs current authorization")
    info("demo", f"status before: {admin.get(f'/revocation/status/{d.did}').json()}")
    r = admin.post("/revocation/revoke", json={"did": d.did}, headers=ADMIN).json()
    warn("demo", f"operator revoked {args.device}: {r}")

    resp, _ = token_access(d, token, dev_type, "read")
    show_decision(args.device, "[old token, still unexpired] READ", resp)
    resp, _ = verify_access(d, dev_type, "write", pkg)
    show_decision(args.device, f"[old proof, epoch {epoch1}] WRITE", resp)

    root1 = admin.get(f"/registry/root/{epoch1}").json()["root"]
    hist = verify_proof_package(pkg, root1, fog_pk)
    ok("audit", f"was {args.device} a member of epoch {epoch1}? {hist.ok} ({hist.reason}) -- history does not change")

    closed2 = admin.post("/epoch/close", headers=ADMIN).json()
    epoch2 = closed2["epoch_id"]
    ok("demo", f"epoch {epoch2} closed: {closed2['leaf_count']} leaves, excluded {closed2['excluded']}, "
               f"root {short(closed2['root'], 16)}")
    status = admin.get(f"/revocation/status/{d.did}").json()
    info("demo", f"status after: {status['status']}, in latest active set: {status['in_latest_active_set']}")
    moved = {**pkg, "epoch_id": epoch2}
    resp, _ = verify_access(d, dev_type, "write", moved)
    show_decision(args.device, f"[old proof relabelled as epoch {epoch2}]", resp)
    r = d.client.get(f"/proof/{d.did}")
    warn("demo", f"new proof for {args.device} -> HTTP {r.status_code} {r.json().get('detail')}")
    info("demo", f"old proof = true history of epoch {epoch1}; current status = REVOKED -> no access now, "
                 f"and not a member of epoch {epoch2}")
    d.close()
    ctl.close()
    pause(args.pause)

    # ------------------------------------------------------------------
    if not args.skip_attacks:
        step("STEP 9  Attack demonstrations (fresh isolated fog per attack)")
        from attacks.token_attacks import main as run_attacks
        run_attacks()
        pause(args.pause)

    # ------------------------------------------------------------------
    step("STEP 10  Performance and scalability results")
    summary_path = ROOT / "benchmarks" / "results" / "verification_summary.csv"
    if summary_path.exists():
        with summary_path.open(newline="") as f:
            rows = list(csv.DictReader(f))
        cols = [("verify_crypto_us_mean", "verify (us)"), ("token_check_us_mean", "token chk (us)"),
                ("verify_e2e_ms_mean", "verify e2e (ms)"), ("token_e2e_ms_mean", "token e2e (ms)"),
                ("throughput_seq_rps_mean", "seq rps"), ("throughput_conc_rps_mean", "conc rps")]
        cols = [(c, h) for c, h in cols if rows and c in rows[0]]
        print("\n   " + f"{'devices':>8}" + "".join(f"{h:>17}" for _, h in cols))
        for row in rows:
            print("   " + f"{row['n_devices']:>8}" + "".join(f"{float(row[c]):>17.3f}" for c, _ in cols))
        ok("demo", "graphs: benchmarks/graphs/graph2_verification_latency.png, graph3_throughput.png, "
                   "token_access_latency.png")
    else:
        warn("demo", "no results yet -- run python benchmarks/bench_verifications.py first")
    info("demo", "reproduce: python benchmarks/bench_verifications.py --runs 5 --counts 5 10 25 50 100")
    admin.close()


if __name__ == "__main__":
    main()
