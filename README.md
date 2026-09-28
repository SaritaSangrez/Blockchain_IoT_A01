# Blockchain_IoT_A01

Single Zone IIoT Decentralized Identity Management Framework (Assignment 1)

Group members: Sarita Sangrez (23i-2088), Amna Ali (23i-2067)

One fog node, one zone, multiple simulated devices. Devices authenticate with a PSK over TLS, generate a DID and a P256 key pair, prove possession of the private key, and are collected into a registration batch. When the epoch closes the fog sorts the leaves, builds one Merkle tree, anchors one root in a signed hash chained ledger, and issues a signed proof package to every device.

## Setup (Windows PowerShell)

```
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python scripts\gen_certs.py
```

`gen_certs.py` creates the zone CA, the fog HTTPS certificate, the fog signing key and one PSK per
device. These files are git ignored; every group member runs it once.

## Run the system

Terminal 1, fog node over HTTPS:

```
python scripts\run_fog.py
```

Terminal 2, Phase 1 demo (demo steps 1 to 5):

```
python scripts\demo_phase1.py --pause
```

Register individual devices: `python devices\device.py temp02 motor01`

Close an epoch manually: `POST https://localhost:8443/epoch/close` with header `X-Admin-Key`.

## Attacks

```
python attacks\tamper_proof.py
```

## Tests

```
pytest
```

## Benchmarks

```
python benchmarks\bench_batch.py
python benchmarks\bench_batch_vs_individual.py
python benchmarks\bench_registration.py
```

CSV files go to `benchmarks/results`, graphs to `benchmarks/graphs`.

## Main endpoints

| Method | Path | Purpose |
|---|---|---|
| POST | /register/start | PSK check, opens a session |
| POST | /register/pubkey | DID + public key, returns a fresh challenge |
| POST | /register/pop | signature over the challenge (proof of possession) |
| POST | /register/metadata | metadata validation, leaf creation, added to the open batch |
| GET | /epoch/current | open epoch and queued devices |
| POST | /epoch/close | admin: sort, build tree, anchor root, issue proofs |
| GET | /proof/{did} | device proof package |
| GET | /registry/root/{epoch_id} | anchored root and block |
| GET | /registry/verify | verify the ledger hash chain |
| GET | /health | fog status |

Phase 2 / Phase 3 / revocation endpoints (Member B):

| Method | Endpoint | Description |
|---|---|---|
| POST | `/tokens/issue` | `{session_id}` of a device that passed PoP AND is queued (`/register/metadata` done) -> short-lived fog-signed token; type and role come from the fog's validated record |
| POST | `/tokens/nonce` | `{token_id}` -> fresh fog-issued nonce (single use, 30 s) |
| POST | `/tokens/access` | `{token, nonce, resource, operation, signature}` -> ALLOW/DENY. Checks token signature, expiry, nonce, revocation, device signature (PoP), provisional scope (read/write on own type only), policy |
| POST | `/verify/nonce` | `{did}` -> fresh fog-issued nonce (single use, 30 s) |
| POST | `/verify` | `{proof_package, resource, operation, nonce, signature}` -> ALLOW/DENY. Checks nonce, Merkle proof against the anchored root, PoP, current status/revocation, role/type, policy |
| POST | `/revocation/revoke` | admin (`X-Admin-Key`): `{did}` revokes the device and all its tokens; `{did, token_id, token_only: true}` revokes one token only |
| GET | `/revocation/status/{did}` | current status, token states, and whether the device is in the latest epoch root |

Device side helpers for these calls: `devices/runtime_client.py`.


## Phase 2 / 3 demo, attacks, benchmarks, tests (Member B)

Terminal 2, Phase 2/3 demo (demo steps 6 to 10). Run it right after
`demo_phase1.py` without restarting the fog, so the tree holds all devices:

```
python scripts\demo_phase2.py --pause
```

Quick check without a separate fog (in-process fog, temporary ledger):

```
python scripts\demo_phase2.py --inprocess
```

Attacks (replay, stolen token, stolen proof package, expired/revoked token,
forged token, role escalation); results also saved to
`benchmarks\results\attack_token_results.csv`:

```
python attacks\token_attacks.py
```

Verification / token validation / resource access / throughput benchmark
(fresh fog per device count, so the tree really has N leaves):

```
python benchmarks\bench_verifications.py --runs 5 --counts 5 10 25 50 100 --workers 8
```

Output: `benchmarks\results\verification_raw.csv`, `verification_summary.csv`,
`benchmarks\graphs\graph2_verification_latency.png`, `graph3_throughput.png`,
`token_access_latency.png`.

Tests for policy, nonces, tokens, revocation and the Phase 2/3 endpoints:

```
pytest tests\test_member_b.py -v
```
