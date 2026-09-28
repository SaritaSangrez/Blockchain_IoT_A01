"""
ATTACKS (Member B): replay, stolen token, expired token, revoked token.

  1   replay of an exact request   -> DENY nonce_reused                (nonce validator)
  2   stolen valid token           -> DENY proof_of_possession_failed  (proof of possession check)
  3a  expired token                -> DENY expired                     (token expiry check)
  3b  revoked token                -> DENY revoked                     (revocation checker)

Every attack runs against a fresh fog created in process (FastAPI TestClient,
temporary signing key and ledger, fresh PSKs), so nothing touches the demo
ledger and token expiry can be shown in under a second. The victim device
goes through the REAL protocol first: PSK, DID/PK, proof of possession,
metadata (leaf queued), then a temporary token.

Results are also saved to benchmarks/results/attack_token_results.csv.

Run from the project root:   python attacks/token_attacks.py
"""
from __future__ import annotations

import csv
import secrets
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient

import config
from common.logger import fail, info, ok, step
from devices.device import Device
from devices.runtime_client import build_token_request, get_token_nonce, request_token, token_access
from fog.auth.psk import PSKStore
from fog.main import create_app
from fog.tokens.tokens import issue_token

RESULTS_CSV = Path(__file__).resolve().parent.parent / "benchmarks" / "results" / "attack_token_results.csv"
ADMIN = {"X-Admin-Key": config.ADMIN_KEY}
RESOURCE, OPERATION = "temperature_sensor", "write"
results = []


def record(attack: str, expected: str, response: dict, passed: bool):
    (ok if passed else fail)("attack", f"{attack}: {'DETECTED' if passed else 'NOT DETECTED -- PROBLEM'} -> "
                                       f"{response.get('decision')} / {response.get('reason')} / "
                                       f"{response.get('detected_by')}")
    results.append({"attack": attack, "expected": expected, "decision": response.get("decision"),
                    "reason": response.get("reason"), "detected_by": response.get("detected_by"),
                    "as_expected": "yes" if passed else "NO"})


# ---------- environment ----------

def make_env():
    names = ["temp01", "attacker01"]
    psks = {n: secrets.token_hex(32) for n in names}
    tmp = Path(tempfile.mkdtemp())
    app = create_app(psk_entries={n: PSKStore.hash_psk(p) for n, p in psks.items()},
                     signing_key_path=tmp / "k.pem", ledger_path=tmp / "l.json", verbose=False)
    return app, TestClient(app), psks


def queued_device(client, psks, name="temp01") -> Device:
    """PSK + DID/PK + PoP + metadata: authenticated and queued in the open batch."""
    d = Device(name, psk=psks[name], client=client, persist_key=False, verbose=False)
    d.register_start()
    d.prove_possession(d.submit_public_key())
    d.submit_metadata()
    return d


# ---------- attacks ----------

def attack_replay():
    step("ATTACK 1: replay of an exact request")
    _, client, psks = make_env()
    d = queued_device(client, psks)
    token = request_token(d)
    first, captured = token_access(d, token, RESOURCE, OPERATION)
    info("attack", f"genuine request with fog nonce {captured['nonce'][:8]}... -> {first['decision']}")
    replayed = client.post("/tokens/access", json=captured).json()      # byte-identical resend
    info("attack", f"attacker resends the captured request unchanged (same nonce) -> {replayed}")
    record("1 replay of exact request", "DENY nonce_reused", replayed,
           first["decision"] == "ALLOW" and replayed.get("reason") == "nonce_reused")


def attack_stolen_token():
    step("ATTACK 2: stolen valid token used from another device")
    _, client, psks = make_env()
    victim = queued_device(client, psks, "temp01")
    token = request_token(victim)
    attacker = Device("attacker01", psk=psks["attacker01"], client=client, persist_key=False, verbose=False)
    info("attack", f"attacker {attacker.did} copied token {token['token_id']} of {victim.did}")
    nonce = get_token_nonce(client, token["token_id"])
    body = build_token_request(attacker.private_key, token, nonce, RESOURCE, OPERATION)
    r = client.post("/tokens/access", json=body).json()
    info("attack", f"token genuine and unexpired, nonce fresh, but signed with the ATTACKER's key -> {r}")
    record("2 stolen valid token", "DENY proof_of_possession_failed", r,
           r.get("reason") == "proof_of_possession_failed")


def attack_expired_token():
    step("ATTACK 3a: expired token")
    app, client, psks = make_env()
    d = queued_device(client, psks)
    ctx = app.state.ctx
    # issued by the fog's real issuer, only with a 0.3 s lifetime so expiry can be shown live
    token = issue_token(d.did, d.public_key_hex, "temperature_sensor", "sensor", ctx.signing_key, ttl_seconds=0.3)
    ctx.token_state.record_issued(token["token_id"], d.did)
    time.sleep(0.4)
    r, _ = token_access(d, token, RESOURCE, OPERATION)
    info("attack", f"genuine token, fresh nonce, correct signature, used after expiry -> {r}")
    record("3a expired token", "DENY expired", r, r.get("reason") == "expired")


def attack_revoked_token():
    step("ATTACK 3b: revoked token")
    _, client, psks = make_env()
    d = queued_device(client, psks)
    token = request_token(d)
    before, _ = token_access(d, token, RESOURCE, OPERATION)
    client.post("/revocation/revoke", json={"did": d.did}, headers=ADMIN)
    after, _ = token_access(d, token, RESOURCE, OPERATION)
    info("attack", f"before revocation -> {before['decision']}; right after revocation -> {after}")
    record("3b revoked token", "DENY revoked", after,
           before["decision"] == "ALLOW" and after.get("reason") == "revoked")


def main():
    attack_replay()
    attack_stolen_token()
    attack_expired_token()
    attack_revoked_token()

    step("SUMMARY")
    print(f"   {'attack':<28} {'decision':<9} {'reason':<28} {'detected by':<28} ok")
    for row in results:
        print(f"   {row['attack']:<28} {row['decision']:<9} {row['reason']:<28} {row['detected_by']:<28} "
              f"{row['as_expected']}")
    RESULTS_CSV.parent.mkdir(parents=True, exist_ok=True)
    with RESULTS_CSV.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(results[0].keys()))
        writer.writeheader()
        writer.writerows(results)
    info("attack", f"results saved to {RESULTS_CSV.relative_to(RESULTS_CSV.parents[2])}")
    all_ok = all(r["as_expected"] == "yes" for r in results)
    (ok if all_ok else fail)("attack", "every attack was detected" if all_ok else "SOME ATTACKS WERE NOT DETECTED")
    return all_ok


if __name__ == "__main__":
    sys.exit(0 if main() else 1)