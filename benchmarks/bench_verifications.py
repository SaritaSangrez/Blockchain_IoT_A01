"""
Member B performance evaluation: verification, token validation, resource
access and throughput as the number of registered devices grows.

For every device count N a FRESH fog is started (own temporary ledger), N
devices are registered and ONE epoch is closed, so the Merkle tree really
contains N leaves. (Reusing one fog would let carry-forward grow the tree
across runs and the x axis would be wrong.) Another N devices are then left
queued in the open batch and given temporary tokens for the Phase 2 metrics.
Each measurement is repeated --runs times on that tree.

Metrics (per run, averaged over all N devices):
  verify_crypto_us     verify_proof_package(): recompute leaf, climb the proof
                       path, compare with the trusted root, check fog signature
                       (pure computation, in process)          -> assignment "verification latency"
  token_check_us       token signature + expiry + nonce + revocation checks
                       (pure computation, in process)          -> "temporary-token validation"
  verify_e2e_ms        nonce request + device signature + POST /verify until
                       ALLOW over HTTPS                        -> "resource-access latency" (Phase 3)
  token_e2e_ms         nonce request + device signature + POST /tokens/access
                       until ALLOW over HTTPS                  -> "resource-access latency" (Phase 2)
  throughput_seq_rps   complete Phase 3 verifications per second, one client
  throughput_conc_rps  same with --workers parallel clients
  proof_siblings       average proof length (grows with log2 N)

Graphs: graph2_verification_latency.png (required graph 2),
        graph3_throughput.png (required graph 3), token_access_latency.png

Run:
    python benchmarks/bench_verifications.py
    python benchmarks/bench_verifications.py --runs 5 --counts 5 10 25 50 100 --workers 8
    python benchmarks/bench_verifications.py --inprocess      (no TLS server; quick check)
"""
from __future__ import annotations

import argparse
import json
import secrets
import statistics
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config
from benchmarks.bench_utils import environment, line_plot, save_raw_and_summary
from common.crypto_utils import public_key_bytes
from common.logger import fail, ok, set_quiet, step
from devices.device import Device, make_tls_client
from devices.runtime_client import request_token, token_access, verify_access
from fog.main import create_app
from fog.proofs.proof_package import verify_proof_package
from fog.revocation.registry import is_device_revoked
from fog.tokens.tokens import TOKEN_NONCE_PURPOSE, token_expired, token_signature_valid

BENCH_PORT = 8544
DEVICE_TYPE, ROLE = config.SIM_DEVICE_TYPE      # temperature_sensor / sensor
RESOURCE, OPERATION = DEVICE_TYPE, "write"       # an operation that must end in ALLOW
ADMIN = {"X-Admin-Key": config.ADMIN_KEY}


# ---------- fog lifecycle ----------

class Fog:
    """One fresh fog per device count: over HTTPS (default) or in process."""

    def __init__(self, port: int, inprocess: bool, psks: dict):
        self.tmp = Path(tempfile.mkdtemp())
        self.inprocess = inprocess
        if inprocess:
            from fastapi.testclient import TestClient
            from fog.auth.psk import PSKStore
            self.app = create_app(psk_entries={n: PSKStore.hash_psk(p) for n, p in psks.items()},
                                  signing_key_path=self.tmp / "k.pem", ledger_path=self.tmp / "l.json",
                                  verbose=False)
            self._client = TestClient(self.app)
            self.new_client = lambda: self._client
            return
        import uvicorn
        self.app = create_app(ledger_path=self.tmp / "ledger.json", verbose=False)
        cfg = uvicorn.Config(self.app, host="127.0.0.1", port=port, log_level="error",
                             ssl_certfile=str(config.FOG_TLS_CERT_PATH), ssl_keyfile=str(config.FOG_TLS_KEY_PATH))
        self.server = uvicorn.Server(cfg)
        self.thread = threading.Thread(target=self.server.run, daemon=True)
        self.thread.start()
        for _ in range(200):
            if self.server.started:
                break
            time.sleep(0.05)
        else:
            raise RuntimeError("benchmark fog did not start")
        url = f"https://localhost:{port}"
        self.new_client = lambda: make_tls_client(url)

    @property
    def ctx(self):
        return self.app.state.ctx

    def stop(self):
        if not self.inprocess:
            self.server.should_exit = True
            self.thread.join(timeout=5)


def onboard(fog: Fog, name: str, psk: str) -> Device:
    d = Device(name, psk=psk, client=fog.new_client(), persist_key=False, verbose=False)
    d.register_start()
    d.prove_possession(d.submit_public_key())
    d.submit_metadata(device_type=DEVICE_TYPE, role=ROLE)
    return d


# ---------- measurements ----------

def measure_verify_crypto(fog: Fog, devices) -> float:
    fog_pk = public_key_bytes(fog.ctx.signing_key)
    times = []
    for d in devices:
        root = fog.ctx.ledger.get_root(d.proof_package["epoch_id"])     # trusted root lookup is part of it
        t0 = time.perf_counter()
        res = verify_proof_package(d.proof_package, root, fog_pk)
        times.append(time.perf_counter() - t0)
        assert res.ok, res.reason
    return statistics.mean(times) * 1e6


def measure_token_check(fog: Fog, tokens) -> float:
    ctx = fog.ctx
    times = []
    for token in tokens:
        nonce = ctx.token_state.nonces.issue(TOKEN_NONCE_PURPOSE, token["token_id"])   # not timed
        t0 = time.perf_counter()
        valid = (token_signature_valid(token, ctx.signing_key)
                 and not token_expired(token)
                 and ctx.token_state.nonces.consume(TOKEN_NONCE_PURPOSE, token["token_id"], nonce) == "ok"
                 and not ctx.token_state.is_revoked(token["token_id"])
                 and not is_device_revoked(ctx.devices, token["did"]))
        times.append(time.perf_counter() - t0)
        assert valid
    return statistics.mean(times) * 1e6


def one_verification(d: Device) -> str:
    resp, _ = verify_access(d, RESOURCE, OPERATION)
    return resp["decision"]


def measure_verify_e2e(devices) -> float:
    times = []
    for d in devices:
        t0 = time.perf_counter()
        decision = one_verification(d)
        times.append(time.perf_counter() - t0)
        assert decision == "ALLOW"
    return statistics.mean(times) * 1000


def measure_token_e2e(token_devices) -> float:
    times = []
    for d, token in token_devices:
        t0 = time.perf_counter()
        resp, _ = token_access(d, token, RESOURCE, OPERATION)
        times.append(time.perf_counter() - t0)
        assert resp["decision"] == "ALLOW", resp
    return statistics.mean(times) * 1000


def measure_throughput(devices, workers: int, min_requests: int) -> tuple[float, float]:
    reps = max(1, -(-min_requests // len(devices)))          # ceil: at least min_requests per measurement
    work = devices * reps
    t0 = time.perf_counter()
    for d in work:
        one_verification(d)
    seq = len(work) / (time.perf_counter() - t0)
    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=workers) as pool:
        decisions = list(pool.map(one_verification, work))
    conc = len(work) / (time.perf_counter() - t0)
    assert all(x == "ALLOW" for x in decisions)
    return seq, conc


# ---------- main ----------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=5)
    ap.add_argument("--counts", type=int, nargs="+", default=[5, 10, 25, 50, 100])
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--min-requests", type=int, default=200, help="requests per throughput measurement")
    ap.add_argument("--inprocess", action="store_true", help="in-process fog without TLS (quick check)")
    args = ap.parse_args()

    need = 2 * max(args.counts)
    if args.inprocess:
        psks = {f"sim{i:04d}": secrets.token_hex(32) for i in range(1, need + 1)}
    else:
        if not config.DEVICE_PROVISIONING_PATH.exists():
            fail("bench", "run python scripts/gen_certs.py first")
            sys.exit(1)
        psks = json.loads(config.DEVICE_PROVISIONING_PATH.read_text(encoding="utf-8"))
    names = [f"sim{i:04d}" for i in range(1, need + 1)]
    if any(n not in psks for n in names):
        fail("bench", f"need {need} provisioned sim devices; raise SIM_DEVICE_COUNT and rerun gen_certs.py --force")
        sys.exit(1)

    set_quiet(True)
    step("Benchmark: verification, token validation, resource access, throughput")
    print(f"   environment: {environment()}  |  transport: {'in-process' if args.inprocess else 'HTTPS'}")

    rows = []
    for idx, n in enumerate(args.counts):
        fog = Fog(BENCH_PORT + idx, args.inprocess, psks)
        try:
            members = [onboard(fog, nm, psks[nm]) for nm in names[:n]]
            closed = fog.new_client().post("/epoch/close", headers=ADMIN).json()
            assert closed["leaf_count"] == n, closed
            for d in members:
                d.fetch_proof()
            waiting = [onboard(fog, nm, psks[nm]) for nm in names[n:2 * n]]   # stay queued in the open batch
            tokens = [(d, request_token(d)) for d in waiting]
            siblings = statistics.mean(len(d.proof_package["proof_path"]) for d in members)

            one_verification(members[0])                                  # warm-up, not recorded
            for run in range(1, args.runs + 1):
                seq, conc = measure_throughput(members, args.workers, args.min_requests)
                rows.append({
                    "n_devices": n, "run": run, "tree_leaves": closed["leaf_count"],
                    "proof_siblings": siblings,
                    "verify_crypto_us": measure_verify_crypto(fog, members),
                    "token_check_us": measure_token_check(fog, [t for _, t in tokens]),
                    "verify_e2e_ms": measure_verify_e2e(members),
                    "token_e2e_ms": measure_token_e2e(tokens),
                    "throughput_seq_rps": seq,
                    "throughput_conc_rps": conc,
                })
        finally:
            fog.stop()
        last = [r for r in rows if r["n_devices"] == n]
        m = lambda k: statistics.mean(r[k] for r in last)   # noqa: E731
        print(f"   N = {n:<4} tree {closed['leaf_count']:<4} siblings {siblings:4.1f} | verify {m('verify_crypto_us'):7.1f} us, "
              f"e2e {m('verify_e2e_ms'):6.2f} ms | token {m('token_check_us'):7.1f} us, e2e {m('token_e2e_ms'):6.2f} ms | "
              f"{m('throughput_seq_rps'):6.1f} rps seq, {m('throughput_conc_rps'):6.1f} rps x{args.workers}")

    summary = save_raw_and_summary(rows, "verification")
    g2 = line_plot(summary, [("verify_crypto_us", "Proof verification (leaf + path + trusted root + fog signature)")],
                   "Verification latency vs number of devices", "Latency (µs)", "graph2_verification_latency.png")
    g2b = line_plot(summary, [("verify_e2e_ms", "Phase 3: /verify (nonce + signed request)"),
                              ("token_e2e_ms", "Phase 2: /tokens/access (nonce + signed request)")],
                    "End-to-end resource-access latency vs number of devices", "Latency (ms)",
                    "token_access_latency.png")
    g3 = line_plot(summary, [("throughput_seq_rps", "Sequential (1 client)"),
                             ("throughput_conc_rps", f"Concurrent ({args.workers} clients)")],
                   "Verification throughput vs number of devices", "Verifications per second",
                   "graph3_throughput.png")
    set_quiet(False)
    ok("bench", "CSV: benchmarks/results/verification_raw.csv and verification_summary.csv")
    ok("bench", f"graphs: benchmarks/graphs/{g2.name}, {g2b.name}, {g3.name}")


if __name__ == "__main__":
    main()
