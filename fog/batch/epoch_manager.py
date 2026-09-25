"""
Epoch (registration window) manager.

add_leaf()        appends a device leaf to the OPEN batch. It never builds the tree.
finalize_epoch()  runs once when the window closes:
                    1. collect leaves (new batch + active devices if carry forward)
                    2. drop revoked / excluded devices
                    3. sort deterministically
                    4. build the Merkle tree, compute the root
                    5. anchor the root in the ledger
                    6. build and sign one proof package per device
                    7. open the next epoch
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional

from common.canonical import leaf_hash
from common.logger import info, ok, short, warn
from common.schemas import AnchorRecord, DeviceStatus, ProofPackage
from fog.merkle.merkle_tree import MerkleTree
from fog.proofs.proof_package import build_proof_package
from fog.storage.device_store import DeviceStore
from registry.ledger import Ledger


class EpochError(Exception):
    pass


@dataclass
class PendingEntry:
    did: str
    public_key: str
    leaf: bytes
    queued_at: float


@dataclass
class EpochResult:
    epoch_id: int
    root: str
    block: AnchorRecord
    sorted_leaves: List[Dict[str, str]]
    packages: Dict[str, ProofPackage]
    new_devices: int
    carried_forward: int
    excluded: List[str]
    timings_ms: Dict[str, float] = field(default_factory=dict)


class EpochManager:
    def __init__(self, ledger: Ledger, signing_key, fog_id: str, devices: DeviceStore,
                 carry_forward: bool = True, verbose: bool = True):
        self.ledger = ledger
        self.signing_key = signing_key
        self.fog_id = fog_id
        self.devices = devices
        self.carry_forward = carry_forward
        self.verbose = verbose
        latest = ledger.latest_epoch()
        self.current_epoch_id: int = (latest + 1) if latest is not None else 1
        self.pending: Dict[str, PendingEntry] = {}
        self.packages: Dict[int, Dict[str, ProofPackage]] = {}
        self.latest_package: Dict[str, ProofPackage] = {}
        self.active_dids: set = set()   # devices committed in the most recent root
        self._lock = threading.RLock()
        self._timer: Optional[threading.Thread] = None

    def _log(self, fn, msg):
        if self.verbose:
            fn("epoch", msg)

    # ---------- open batch ----------

    def add_leaf(self, did: str, pk_bytes: bytes) -> str:
        """Queue a device for the current epoch. O(1): no tree work here."""
        with self._lock:
            if did in self.pending:
                raise EpochError(f"{did} is already queued for epoch {self.current_epoch_id}")
            leaf = leaf_hash(did, pk_bytes)
            self.pending[did] = PendingEntry(did, pk_bytes.hex(), leaf, time.time())
            self._log(info, f"leaf {short(leaf.hex())} queued for epoch {self.current_epoch_id} "
                            f"(batch size now {len(self.pending)})")
            return leaf.hex()

    def batch_size(self) -> int:
        with self._lock:
            return len(self.pending)

    def pending_dids(self) -> List[str]:
        with self._lock:
            return list(self.pending)

    # ---------- close batch ----------

    def finalize_epoch(self, exclude_dids: Optional[Iterable[str]] = None) -> EpochResult:
        with self._lock:
            t_start = time.perf_counter()
            excluded = set(exclude_dids or [])
            revoked = {d.did for d in self.devices.by_status(DeviceStatus.REVOKED)}
            blocked = excluded | revoked

            members: Dict[str, PendingEntry] = {}
            carried = 0
            if self.carry_forward:
                for rec in self.devices.by_status(DeviceStatus.REGISTERED):
                    if rec.did not in blocked and rec.did not in self.pending:
                        members[rec.did] = PendingEntry(rec.did, rec.public_key, bytes.fromhex(rec.leaf), 0.0)
                        carried += 1
            new = 0
            for did, entry in self.pending.items():
                if did not in blocked:
                    members[did] = entry
                    new += 1

            dropped = sorted(d for d in blocked if d in self.pending or d in self.active_dids)
            if not members:
                raise EpochError("nothing to finalize: the batch is empty")

            epoch_id = self.current_epoch_id

            # 1. deterministic sort (timed separately for the benchmark)
            t0 = time.perf_counter()
            leaves_sorted = sorted(e.leaf for e in members.values())
            t1 = time.perf_counter()
            # 2. build the tree once for the whole batch
            tree = MerkleTree(leaves_sorted, sort=False)
            t2 = time.perf_counter()
            # 3. anchor one root for the epoch
            block = self.ledger.anchor_root(epoch_id, tree.root_hex, tree.size)
            t3 = time.perf_counter()
            # 4. one proof package per device
            by_leaf = {e.leaf: e for e in members.values()}
            packages: Dict[str, ProofPackage] = {}
            for leaf in tree.leaves:
                e = by_leaf[leaf]
                packages[e.did] = build_proof_package(e.did, e.public_key, leaf, tree, epoch_id,
                                                      self.fog_id, self.signing_key)
            t4 = time.perf_counter()

            # 5. update device state
            for did, pkg in packages.items():
                rec = self.devices.get(did)
                if rec is not None:
                    rec.status = DeviceStatus.REGISTERED
                    rec.leaf = pkg.leaf
                    rec.epoch_id = epoch_id
                self.latest_package[did] = pkg
            self.packages[epoch_id] = packages
            self.active_dids = set(packages)
            self.pending = {}
            self.current_epoch_id = epoch_id + 1

            timings = {
                "sort_ms": (t1 - t0) * 1000,
                "build_ms": (t2 - t1) * 1000,
                "batch_ms": (t2 - t0) * 1000,
                "anchor_ms": (t3 - t2) * 1000,
                "proofs_ms": (t4 - t3) * 1000,
                "total_ms": (time.perf_counter() - t_start) * 1000,
            }
            sorted_view = [{"index": i, "leaf": l.hex(), "did": by_leaf[l].did} for i, l in enumerate(tree.leaves)]

            self._log(ok, f"epoch {epoch_id} finalized: {tree.size} leaves "
                          f"({new} new, {carried} carried forward, {len(dropped)} excluded)")
            self._log(ok, f"root {tree.root_hex}")
            self._log(ok, f"anchored as block {block.block_index}, hash {short(block.block_hash)}")
            if dropped:
                self._log(warn, f"excluded from this root: {', '.join(dropped)}")

            return EpochResult(epoch_id, tree.root_hex, block, sorted_view, packages, new, carried,
                               dropped, timings)

    # ---------- lookups ----------

    def get_package(self, did: str, epoch_id: Optional[int] = None) -> Optional[ProofPackage]:
        with self._lock:
            if epoch_id is None:
                return self.latest_package.get(did)
            return self.packages.get(epoch_id, {}).get(did)

    # ---------- optional automatic window ----------

    def start_auto_close(self, interval_seconds: int) -> None:
        def loop():
            while True:
                time.sleep(interval_seconds)
                if self.batch_size() > 0:
                    try:
                        self.finalize_epoch()
                    except EpochError as e:
                        self._log(warn, str(e))
        self._timer = threading.Thread(target=loop, daemon=True)
        self._timer.start()
        self._log(info, f"automatic epoch close every {interval_seconds}s")