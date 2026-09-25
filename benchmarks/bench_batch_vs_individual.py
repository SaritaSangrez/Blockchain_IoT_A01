"""
Batch vs individual registration experiment.

INDIVIDUAL: after EVERY arrival the fog rebuilds the tree, anchors a new root
            in the ledger, and must refresh the proofs of all existing devices.
BATCH:      devices are collected, then ONE tree, ONE root anchor and N proofs.

Measured per N: total tree time, total anchor time, total proof time,
root/ledger updates, proofs (re)issued, and existing proofs whose sibling
path actually changed.

    python benchmarks/bench_batch_vs_individual.py
    python benchmarks/bench_batch_vs_individual.py --runs 5 --counts 5 10 25 50 100 250 500
"""
from __future__ import annotations

import argparse
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import matplotlib.pyplot as plt

from benchmarks.bench_utils import GRAPHS, environment, save_raw_and_summary
from common.canonical import leaf_hash
from common.crypto_utils import derive_did, generate_keypair, public_key_bytes
from common.logger import ok, set_quiet, step
from fog.merkle.merkle_tree import MerkleTree
from registry.ledger import Ledger


def make_leaves(n):
    out = []
    for _ in range(n):
        pk = public_key_bytes(generate_keypair())
        out.append(leaf_hash(derive_did(pk), pk))
    return out


def individual(leaves, fog_key):
    with tempfile.TemporaryDirectory() as tmp:
        ledger = Ledger(Path(tmp) / "l.json", fog_key)
        tree_s = anchor_s = proof_s = 0.0
        proofs_issued = paths_changed = 0
        current, issued = [], {}
        for k, leaf in enumerate(leaves, start=1):
            current.append(leaf)
            t0 = time.perf_counter()
            tree = MerkleTree(current)
            t1 = time.perf_counter()
            ledger.anchor_root(k, tree.root_hex, tree.size)
            t2 = time.perf_counter()
            fresh = {l: tree.get_proof(l) for l in current}
            t3 = time.perf_counter()
            paths_changed += sum(1 for l, p in issued.items() if fresh[l] != p)
            proofs_issued += len(fresh)
            issued = fresh
            tree_s += t1 - t0
            anchor_s += t2 - t1
            proof_s += t3 - t2
        return tree_s, anchor_s, proof_s, len(ledger), proofs_issued, paths_changed


def batch(leaves, fog_key):
    with tempfile.TemporaryDirectory() as tmp:
        ledger = Ledger(Path(tmp) / "l.json", fog_key)
        t0 = time.perf_counter()
        tree = MerkleTree(leaves)
        t1 = time.perf_counter()
        ledger.anchor_root(1, tree.root_hex, tree.size)
        t2 = time.perf_counter()
        proofs = {l: tree.get_proof(l) for l in leaves}
        t3 = time.perf_counter()
        return t1 - t0, t2 - t1, t3 - t2, len(ledger), len(proofs), 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=5)
    ap.add_argument("--counts", type=int, nargs="+", default=[5, 10, 25, 50, 100, 250, 500])
    args = ap.parse_args()
    set_quiet(True)
    step("Benchmark: batch vs individual registration")
    print(f"   environment: {environment()}")
    fog_key = generate_keypair()
    rows = []
    for n in args.counts:
        leaves = make_leaves(n)
        for run in range(1, args.runs + 1):
            for mode, fn in (("individual", individual), ("batch", batch)):
                tree_s, anchor_s, proof_s, updates, issued, changed = fn(leaves, fog_key)
                rows.append({
                    "n_devices": n, "run": run, "mode": mode,
                    "tree_ms": tree_s * 1000, "anchor_ms": anchor_s * 1000, "proof_ms": proof_s * 1000,
                    "total_ms": (tree_s + anchor_s + proof_s) * 1000,
                    "root_updates": updates, "proofs_issued": issued, "existing_paths_changed": changed,
                })
        ind = [r for r in rows if r["n_devices"] == n and r["mode"] == "individual"]
        bat = [r for r in rows if r["n_devices"] == n and r["mode"] == "batch"]
        ti = sum(r["total_ms"] for r in ind) / len(ind)
        tb = sum(r["total_ms"] for r in bat) / len(bat)
        print(f"   N = {n:<4} individual {ti:10.2f} ms, {ind[0]['root_updates']:>4} root updates | "
              f"batch {tb:8.2f} ms, 1 root update | speedup x{ti / tb:,.1f}")

    import pandas as pd
    raw = pd.DataFrame(rows)
    raw.to_csv(Path(__file__).resolve().parent / "results" / "batch_vs_individual_raw.csv", index=False)
    summary = raw.drop(columns=["run"]).groupby(["n_devices", "mode"]).mean().reset_index()
    summary.to_csv(Path(__file__).resolve().parent / "results" / "batch_vs_individual_summary.csv", index=False)

    fig, axes = plt.subplots(1, 3, figsize=(15, 4.5))
    panels = [("total_ms", "Total fog processing time (ms)", True),
              ("root_updates", "Root / ledger updates", True),
              ("proofs_issued", "Proofs issued or refreshed", True)]
    for ax, (col, label, logy) in zip(axes, panels):
        for mode, marker in (("individual", "s"), ("batch", "o")):
            d = summary[summary["mode"] == mode]
            ax.plot(d["n_devices"], d[col], marker=marker, linewidth=1.8, label=mode.capitalize())
        ax.set_xlabel("Number of devices")
        ax.set_ylabel(label)
        ax.set_title(label)
        if logy:
            ax.set_yscale("log")
        ax.grid(True, alpha=0.3)
        ax.legend()
    fig.suptitle("Batch vs individual registration")
    fig.tight_layout()
    out = GRAPHS / "batch_vs_individual.png"
    fig.savefig(out, dpi=160)
    plt.close(fig)
    ok("bench", "CSV: benchmarks/results/batch_vs_individual_raw.csv and _summary.csv")
    ok("bench", f"graph: benchmarks/graphs/{out.name}")
    set_quiet(False)


if __name__ == "__main__":
    main()