# Blockchain_IoT_A01

Single Zone IIoT Decentralized Identity Management Framework (Assignment 1)

Group members: Sarita Sangrez (23i-2088),Mishal Sangrez (23i-2067)

One fog node, one zone, multiple simulated devices. Devices authenticate with a PSK over TLS,
generate a DID and a P256 key pair, prove possession of the private key, and are collected into
a registration batch. When the epoch closes the fog sorts the leaves, builds one Merkle tree,
anchors one root in a signed hash chained ledger, and issues a signed proof package to every device.

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