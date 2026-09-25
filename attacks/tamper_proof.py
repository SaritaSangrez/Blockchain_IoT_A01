"""
ATTACK: tampered identity / tampered proof.

Setup: a fog (in process, with a temporary ledger) registers 4 devices into
epoch 1 and 3 more into epoch 2. The attacker holds temp01's genuine proof
package and modifies it in different ways, then presents it to the verifier.

The verifier is the SAME function the fog uses (verify_proof_package):
it recomputes the leaf from DID + PK and checks the proof against the root
anchored in the ledger, never against a root supplied by the device.

Run from the project root:   python attacks/tamper_proof.py
"""
from __future__ import annotations

import copy
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from common.canonical import leaf_hash
from common.crypto_utils import derive_did, generate_keypair, public_key_bytes
from common.logger import fail, info, ok, short, step
from common.schemas import DeviceRecord, DeviceStatus
from fog.batch.epoch_manager import EpochManager
from fog.merkle.merkle_tree import compute_root
from fog.proofs.proof_package import verify_proof_package
from fog.storage.device_store import DeviceStore
from registry.ledger import Ledger

results = []


def new_identity():
    key = generate_keypair()
    pk = public_key_bytes(key)
    return derive_did(pk), pk


def present(title, pkg, ledger, fog_pk, epoch_override=None, expect_ok=False):
    epoch = epoch_override if epoch_override is not None else pkg["epoch_id"]
    trusted = ledger.get_root(epoch)
    r = verify_proof_package(pkg, trusted, fog_pk)
    print()
    info("attack", title)
    if r.recomputed_leaf:
        info("verifier", f"recomputed leaf     {short(r.recomputed_leaf, 16)}")
    if r.reconstructed_root:
        info("verifier", f"reconstructed root  {short(r.reconstructed_root, 16)}")
    if r.trusted_root:
        info("verifier", f"anchored root       {short(r.trusted_root, 16)}  (epoch {epoch}, from ledger)")
    if r.ok:
        (ok if expect_ok else fail)("verifier", f"ACCEPTED: {r.reason}")
    else:
        ok("verifier", f"REJECTED by {r.detected_by}: {r.reason}")
    results.append((title, "ACCEPTED" if r.ok else "REJECTED", r.detected_by, r.ok == expect_ok))


def main():
    tmp = Path(tempfile.mkdtemp())
    fog_key = generate_keypair()
    fog_pk = public_key_bytes(fog_key)
    store = DeviceStore()
    ledger = Ledger(tmp / "ledger.json", fog_key)
    mgr = EpochManager(ledger, fog_key, "fog_A", store, verbose=False)

    step("SETUP  register temp01, pressure01, camera01, plc01 into epoch 1")
    ids = {}
    for name in ("temp01", "pressure01", "camera01", "plc01"):
        did, pk = new_identity()
        ids[name] = (did, pk)
        store.upsert(DeviceRecord(did=did, public_key=pk.hex(), status=DeviceStatus.PENDING, device_name=name))
        mgr.add_leaf(did, pk)
        info("setup", f"{name:<11} {did}")
    e1 = mgr.finalize_epoch()
    ok("setup", f"epoch 1 root {short(e1.root, 16)} anchored")
    for name in ("motor01", "valve01", "meter01"):
        did, pk = new_identity()
        store.upsert(DeviceRecord(did=did, public_key=pk.hex(), status=DeviceStatus.PENDING, device_name=name))
        mgr.add_leaf(did, pk)
    e2 = mgr.finalize_epoch()
    ok("setup", f"epoch 2 root {short(e2.root, 16)} anchored (7 devices)")

    genuine = e1.packages[ids["temp01"][0]].model_dump()

    step("BASELINE  genuine temp01 proof package")
    present("0. unmodified proof package", genuine, ledger, fog_pk, expect_ok=True)

    step("ATTACKS  attacker modifies the proof package")
    p = copy.deepcopy(genuine)
    p["did"] = p["did"][:-1] + ("0" if p["did"][-1] != "0" else "1")
    p["leaf"] = leaf_hash(p["did"], bytes.fromhex(p["public_key"])).hex()
    present("1. modified DID (leaf recomputed to match)", p, ledger, fog_pk)

    p = copy.deepcopy(genuine)
    evil_did, evil_pk = new_identity()
    p["public_key"] = evil_pk.hex()
    p["leaf"] = leaf_hash(p["did"], evil_pk).hex()
    present("2. temp01's DID with the attacker's public key", p, ledger, fog_pk)

    p = copy.deepcopy(genuine)
    p["did"], p["public_key"] = evil_did, evil_pk.hex()
    p["leaf"] = leaf_hash(evil_did, evil_pk).hex()
    present("3. attacker's own DID+PK with temp01's proof path", p, ledger, fog_pk)

    p = copy.deepcopy(genuine)
    p["leaf"] = e1.packages[ids["camera01"][0]].leaf
    present("3b. only the leaf field swapped for camera01's leaf", p, ledger, fog_pk)

    p = copy.deepcopy(genuine)
    s = bytearray(bytes.fromhex(p["proof_path"][0]["sibling"])); s[0] ^= 0x01
    p["proof_path"][0]["sibling"] = s.hex()
    present("4. one bit flipped in sibling hash 0", p, ledger, fog_pk)

    p = copy.deepcopy(genuine)
    p["proof_path"][0]["side"] = "L" if p["proof_path"][0]["side"] == "R" else "R"
    present("5. left/right order of sibling 0 swapped", p, ledger, fog_pk)

    p = copy.deepcopy(genuine)
    p["proof_path"] = p["proof_path"][:-1]
    present("6. last sibling removed from the path", p, ledger, fog_pk)

    p = copy.deepcopy(genuine)
    p["epoch_id"] = 2
    present("7. epoch 1 proof presented as epoch 2 (wrong root)", p, ledger, fog_pk)

    p = copy.deepcopy(genuine)
    p["epoch_id"] = 99
    present("8. claims an epoch that was never anchored", p, ledger, fog_pk)

    step("COMMIT TAMPER  change camera01's key AFTER the root was anchored (slide 33)")
    tampered_leaves = []
    for item in e1.sorted_leaves:
        if item["did"] == ids["camera01"][0]:
            _, forged_pk = new_identity()
            tampered_leaves.append(leaf_hash(ids["camera01"][0], forged_pk))
            info("attack", f"camera01 leaf {short(item['leaf'])} replaced by {short(tampered_leaves[-1].hex())}")
        else:
            tampered_leaves.append(bytes.fromhex(item["leaf"]))
    recomputed = compute_root(tampered_leaves).hex()
    info("verifier", f"root rebuilt from revealed leaves {short(recomputed, 16)}")
    info("verifier", f"root anchored in ledger          {short(ledger.get_root(1), 16)}")
    detected = recomputed != ledger.get_root(1)
    (ok if detected else fail)("verifier", "REJECTED: rebuilt root does not match the anchored commitment" if detected else "NOT DETECTED")
    results.append(("9. camera01 key changed after anchoring", "REJECTED" if detected else "ACCEPTED", "root comparison", detected))

    step("LEDGER TAMPER  attacker edits the anchored root on disk")
    blocks = json.loads(ledger.path.read_text())
    blocks[0]["root"] = "ff" * 32
    ledger.path.write_text(json.dumps(blocks))
    valid, msg = ledger.verify_chain()
    (ok if not valid else fail)("ledger", f"REJECTED by hash chain check: {msg}" if not valid else "NOT DETECTED")
    results.append(("10. anchored root edited in ledger file", "REJECTED" if not valid else "ACCEPTED", "ledger verify_chain", not valid))

    step("SUMMARY")
    print(f"   {'attack':<54} {'result':<9} {'detected by':<20} as expected")
    for title, res, where, expected in results:
        mark = "yes" if expected else "NO"
        print(f"   {title:<54} {res:<9} {where:<20} {mark}")
    import csv
    out = Path(__file__).resolve().parent.parent / "benchmarks" / "results" / "attack_tamper_results.csv"
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["attack", "result", "detected_by", "as_expected"])
        w.writerows(results)
    info("attack", f"results saved to benchmarks/results/{out.name}")
    all_ok = all(r[3] for r in results)
    (ok if all_ok else fail)("attack", "every tampering attempt was detected" if all_ok else "SOME ATTACKS WERE NOT DETECTED")


if __name__ == "__main__":
    main()