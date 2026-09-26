"""
Member B performance evaluation: verification latency (Phase 3, /verify),
token/resource-access latency (Phase 2, /tokens/access), and throughput.

Starts its own fog node over real HTTPS on a separate port with a
temporary ledger, same approach as benchmarks/bench_registration.py.

Design decision (mention in the report): "token validation" and
"resource-access latency" are measured as ONE number. For a Phase 2
device, checking its token IS the resource-access decision -- there is
no separate step, so a second synthetic measurement would just duplicate
the first under a different name.

Requires:  python scripts/gen_certs.py  (already done)
Run:       python benchmarks/bench_verifications.py
           python benchmarks/bench_verifications.py --runs 5 --counts 5 10 25 50 100 --workers 8
"""
from __future__ import annotations

import argparse
import json
import secrets
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import uvicorn

import config
from benchmarks.bench_utils import environment, line_plot, save_raw_and_summary
from common.crypto_utils import sign
from common.logger import fail, ok, set_quiet, step
from devices.device import Device, make_tls_client
from fog.main import create_app
from fog.tokens.tokens import access_message

BENCH_PORT = 8544
BENCH_URL = f"https://localhost:{BENCH_PORT}"
DEVICE_TYPE, ROLE = "temperature_sensor", "sensor"  # matches config.SIM_DEVICE_TYPE


def start_fog(tmp: Path):
    app = create_app(ledger_path=tmp / "ledger.json", verbose=False)
    cfg = uvicorn.Config(app, host="127.0.0.1", port=BENCH_PORT, log_level="error",
                         ssl_certfile=str(config.FOG_TLS_CERT_PATH), ssl_keyfile=str(config.FOG_TLS_KEY_PATH))
    server = uvicorn.Server(cfg)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(100):
        if server.started:
            return server, thread
        time.sleep(0.05)
    raise RuntimeError("benchmark fog did not start")


def register_batch(names, psks):
    """Registers `names` as devices (PSK + PoP + metadata) and returns the
    Device objects, each still holding its own private key and client."""
    devices = []
    for nm in names:
        d = Device(nm, psk=psks[nm], client=make_tls_client(BENCH_URL), persist_key=False, verbose=False)
        d.register()
        devices.append(d)
    return devices


def measure_verification(devices):
    """Time each device's /verify call once. Returns list of seconds."""
    times = []
    for d in devices:
        t0 = time.perf_counter()
        r = d.client.post("/verify", json={"proof_package": d.proof_package,
                                            "device_type": DEVICE_TYPE, "operation": "read"})
        times.append(time.perf_counter() - t0)
        assert r.json()["decision"] == "ALLOW", r.json()
    return times


def measure_token_access(names, psks):
    """Full Phase 2 flow for fresh devices: PoP, issue token, then time the
    /tokens/access call (this IS the resource-access decision)."""
    times = []
    for nm in names:
        d = Device(nm, psk=psks[nm], client=make_tls_client(BENCH_URL), persist_key=False, verbose=False)
        d.register_start()
        challenge = d.submit_public_key()
        d.prove_possession(challenge)
        token = d.client.post("/tokens/issue", json={
            "session_id": d.session_id, "device_type": DEVICE_TYPE, "role": ROLE
        }).json()

        nonce = secrets.token_hex(8)
        signature = sign(d.private_key, access_message(token["token_id"], token["did"], nonce)).hex()
        t0 = time.perf_counter()
        r = d.client.post("/tokens/access", json={
            "token": token, "nonce": nonce, "signature": signature, "operation": "read"
        })
        times.append(time.perf_counter() - t0)
        assert r.json()["decision"] == "ALLOW", r.json()
    return times


def verify_once(d):
    r = d.client.post("/verify", json={"proof_package": d.proof_package,
                                        "device_type": DEVICE_TYPE, "operation": "read"})
    return r.json()["decision"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=5)
    ap.add_argument("--counts", type=int, nargs="+", default=[5, 10, 25, 50, 100])
    ap.add_argument("--workers", type=int, default=8)
    args = ap.parse_args()

    if not config.DEVICE_PROVISIONING_PATH.exists():
        fail("bench", "run python scripts/gen_certs.py first")
        sys.exit(1)
    psks = json.loads(config.DEVICE_PROVISIONING_PATH.read_text(encoding="utf-8"))
    names = [f"sim{i:04d}" for i in range(1, max(args.counts) + 1)]
    if any(n not in psks for n in names):
        fail("bench", "not enough provisioned simulated devices; raise SIM_DEVICE_COUNT and rerun gen_certs.py --force")
        sys.exit(1)

    set_quiet(True)
    step("Benchmark: verification, token/resource-access latency, throughput")
    print(f"   environment: {environment()}")
    tmp = Path(tempfile.mkdtemp())
    server, thread = start_fog(tmp)

    rows = []
    for n in args.counts:
        batch_names = names[:n]
        for run in range(1, args.runs + 1):
            devices = register_batch(batch_names, psks)
            admin = make_tls_client(BENCH_URL)
            admin.post("/epoch/close", headers={"X-Admin-Key": config.ADMIN_KEY})
            for d in devices:
                d.fetch_proof()

            verify_times = measure_verification(devices)
            token_times = measure_token_access(batch_names, psks)

            t0 = time.perf_counter()
            for d in devices:
                verify_once(d)
            seq_wall = time.perf_counter() - t0

            t0 = time.perf_counter()
            with ThreadPoolExecutor(max_workers=args.workers) as pool:
                list(pool.map(verify_once, devices))
            con_wall = time.perf_counter() - t0

            rows.append({
                "n_devices": n, "run": run,
                "verification_latency_ms": sum(verify_times) / len(verify_times) * 1000,
                "token_access_latency_ms": sum(token_times) / len(token_times) * 1000,
                "throughput_sequential_rps": n / seq_wall,
                "throughput_concurrent_rps": n / con_wall,
            })
        last = [r for r in rows if r["n_devices"] == n]
        print(f"   N = {n:<4} verify {sum(r['verification_latency_ms'] for r in last) / len(last):7.3f} ms | "
              f"token {sum(r['token_access_latency_ms'] for r in last) / len(last):7.3f} ms | "
              f"throughput seq {sum(r['throughput_sequential_rps'] for r in last) / len(last):7.1f} rps, "
              f"{args.workers} workers {sum(r['throughput_concurrent_rps'] for r in last) / len(last):7.1f} rps")

    server.should_exit = True
    thread.join(timeout=5)

    summary = save_raw_and_summary(rows, "verification")
    g1 = line_plot(summary, [("verification_latency_ms", "Merkle proof verification (/verify)")],
                   "Verification latency vs number of devices", "Latency (ms)",
                   "graph2_verification_latency.png")
    g2 = line_plot(summary, [("token_access_latency_ms", "Token check / resource access (/tokens/access)")],
                   "Token / resource-access latency vs number of devices", "Latency (ms)",
                   "token_access_latency.png")
    g3 = line_plot(summary, [("throughput_sequential_rps", "Sequential"),
                             ("throughput_concurrent_rps", f"Concurrent ({args.workers} workers)")],
                   "Verification throughput vs number of devices", "Verifications per second",
                   "graph3_throughput.png")
    set_quiet(False)
    ok("bench", "CSV: benchmarks/results/verification_raw.csv and _summary.csv")
    ok("bench", f"graphs: benchmarks/graphs/{g1.name}, {g2.name}, {g3.name}")


if __name__ == "__main__":
    main()