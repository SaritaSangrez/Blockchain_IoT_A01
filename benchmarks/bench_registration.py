"""
Registration latency and registration throughput over REAL HTTPS.

Starts its own fog node on port 8543 with the real TLS certificates and a
temporary ledger, so it never touches your demo fog or registry/data/ledger.json.
Each simulated device (sim0001, sim0002, ...) does the full device side of
Phase 1: TLS + PSK, DID + PK, challenge signature (PoP), metadata.

Requires:  python scripts/gen_certs.py  (already done)
Run:       python benchmarks/bench_registration.py
           python benchmarks/bench_registration.py --runs 5 --counts 5 10 25 50 100 --workers 8
"""
from __future__ import annotations

import argparse
import json
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
from common.logger import fail, ok, set_quiet, step
from devices.device import Device, make_tls_client
from fog.main import create_app

BENCH_PORT = 8543
BENCH_URL = f"https://localhost:{BENCH_PORT}"


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


def register_one(name, psk):
    d = Device(name, psk=psk, client=make_tls_client(BENCH_URL), persist_key=False, verbose=False)
    t0 = time.perf_counter()
    d.register()
    elapsed = time.perf_counter() - t0
    d.close()
    return elapsed


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
    step("Benchmark: registration latency and throughput over HTTPS")
    print(f"   environment: {environment()}")
    tmp = Path(tempfile.mkdtemp())
    server, thread = start_fog(tmp)
    register_one(names[0], psks[names[0]])  # warm up

    rows = []
    for n in args.counts:
        batch_names = names[:n]
        for run in range(1, args.runs + 1):
            t0 = time.perf_counter()
            lat = [register_one(nm, psks[nm]) for nm in batch_names]
            seq_wall = time.perf_counter() - t0

            t0 = time.perf_counter()
            with ThreadPoolExecutor(max_workers=args.workers) as pool:
                list(pool.map(lambda nm: register_one(nm, psks[nm]), batch_names))
            con_wall = time.perf_counter() - t0

            rows.append({
                "n_devices": n, "run": run,
                "registration_latency_ms": sum(lat) / n * 1000,
                "registration_latency_max_ms": max(lat) * 1000,
                "throughput_sequential_rps": n / seq_wall,
                "throughput_concurrent_rps": n / con_wall,
            })
        last = [r for r in rows if r["n_devices"] == n]
        print(f"   N = {n:<4} latency {sum(r['registration_latency_ms'] for r in last) / len(last):7.2f} ms/device | "
              f"throughput seq {sum(r['throughput_sequential_rps'] for r in last) / len(last):6.1f} reg/s, "
              f"{args.workers} workers {sum(r['throughput_concurrent_rps'] for r in last) / len(last):6.1f} reg/s")

    server.should_exit = True
    thread.join(timeout=5)

    summary = save_raw_and_summary(rows, "registration")
    g1 = line_plot(summary, [("registration_latency_ms", "Mean per device (TLS + PSK + PoP + metadata)")],
                   "Registration latency vs number of devices", "Latency per device (ms)",
                   "registration_latency.png")
    g2 = line_plot(summary, [("throughput_sequential_rps", "Sequential"),
                             ("throughput_concurrent_rps", f"Concurrent ({args.workers} workers)")],
                   "Registration throughput vs number of devices", "Registrations per second",
                   "registration_throughput.png")
    set_quiet(False)
    ok("bench", "CSV: benchmarks/results/registration_raw.csv and _summary.csv")
    ok("bench", f"graphs: benchmarks/graphs/{g1.name}, {g2.name}")


if __name__ == "__main__":
    main()