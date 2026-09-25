"""
Graph 1: number of devices vs batch registration (processing) time.
Also measures proof generation latency per device, proof length and size.

Runs fully in process (no server needed), with a temporary ledger per run.
    python benchmarks/bench_batch.py
    python benchmarks/bench_batch.py --runs 10 --counts 5 10 25 50 100 250 500 1000
"""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from benchmarks.bench_utils import environment, line_plot, save_raw_and_summary
from common.crypto_utils import derive_did, generate_keypair, public_key_bytes
from common.logger import info, ok, set_quiet, step
from common.schemas import DeviceRecord, DeviceStatus
from fog.batch.epoch_manager import EpochManager
from fog.storage.device_store import DeviceStore
from registry.ledger import Ledger


def identities(n):
    out = []
    for _ in range(n):
        pk = public_key_bytes(generate_keypair())
        out.append((derive_did(pk), pk))
    return out


def one_run(ids, fog_key):
    with tempfile.TemporaryDirectory() as tmp:
        store = DeviceStore()
        ledger = Ledger(Path(tmp) / "ledger.json", fog_key)
        mgr = EpochManager(ledger, fog_key, "fog_A", store, verbose=False)
        t0 = time.perf_counter()
        for did, pk in ids:
            store.upsert(DeviceRecord(did=did, public_key=pk.hex(), status=DeviceStatus.PENDING))
            mgr.add_leaf(did, pk)
        add_ms = (time.perf_counter() - t0) * 1000
        r = mgr.finalize_epoch()
        pkgs = list(r.packages.values())
        n = len(ids)
        return {
            "n_devices": n,
            "add_leaf_us_per_device": add_ms * 1000 / n,
            "sort_ms": r.timings_ms["sort_ms"],
            "build_ms": r.timings_ms["build_ms"],
            "batch_ms": r.timings_ms["batch_ms"],
            "anchor_ms": r.timings_ms["anchor_ms"],
            "proofs_total_ms": r.timings_ms["proofs_ms"],
            "proof_gen_us_per_device": r.timings_ms["proofs_ms"] * 1000 / n,
            "finalize_total_ms": r.timings_ms["total_ms"],
            "proof_length_avg": sum(len(p.proof_path) for p in pkgs) / n,
            "proof_package_bytes_avg": sum(len(json.dumps(p.model_dump())) for p in pkgs) / n,
        }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=10)
    ap.add_argument("--counts", type=int, nargs="+", default=[5, 10, 25, 50, 100, 250, 500, 1000])
    args = ap.parse_args()
    set_quiet(True)

    step("Benchmark: batch processing time and proof generation")
    print(f"   environment: {environment()}")
    fog_key = generate_keypair()
    rows = []
    for n in args.counts:
        ids = identities(n)
        one_run(ids, fog_key)  # warm up (not recorded)
        for run in range(1, args.runs + 1):
            row = one_run(ids, fog_key)
            row["run"] = run
            rows.append(row)
        last = [r for r in rows if r["n_devices"] == n]
        avg = sum(r["batch_ms"] for r in last) / len(last)
        print(f"   N = {n:<5} batch (sort+build+root) avg {avg:8.3f} ms   "
              f"proof gen {sum(r['proof_gen_us_per_device'] for r in last) / len(last):7.1f} us/device")

    summary = save_raw_and_summary(rows, "batch_processing")
    g1 = line_plot(summary, [("batch_ms", "Sort + build tree + root")],
                   "Graph 1: Number of devices vs batch registration time",
                   "Batch processing time (ms)", "graph1_batch_time.png")
    g1b = line_plot(summary, [("finalize_total_ms", "Full epoch close (incl. anchor and signed proofs)"),
                              ("batch_ms", "Sort + build tree + root only")],
                    "Epoch finalization cost breakdown", "Time (ms)", "epoch_finalize_breakdown.png")
    g2 = line_plot(summary, [("proof_gen_us_per_device", "Proof generation per device")],
                   "Proof generation latency per device", "Microseconds per device", "proof_generation_latency.png")
    g3 = line_plot(summary, [("proof_length_avg", "Sibling hashes per proof")],
                   "Proof size grows as log2(N)", "Average proof length", "proof_length.png", logx=True)
    ok("bench", "CSV: benchmarks/results/batch_processing_raw.csv and _summary.csv")
    for g in (g1, g1b, g2, g3):
        ok("bench", f"graph: benchmarks/graphs/{g.name}")
    set_quiet(False)


if __name__ == "__main__":
    main()