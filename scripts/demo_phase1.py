"""
Phase 1 live demo (assignment demo steps 1 to 5). The fog must be running:
    terminal 1:  python scripts/run_fog.py
    terminal 2:  python scripts/demo_phase1.py            (runs straight through)
                 python scripts/demo_phase1.py --pause    (waits for Enter between steps)
                 python scripts/demo_phase1.py --devices temp01 camera01 plc01

Shows: PSK OK, DID, PK, challenge, signature valid, leaf hash, batch size,
sorted leaf order, root, ledger block hash, proof path, and a step by step
proof verification that ends in TRUE.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import httpx

import config
from common.canonical import node_hash
from common.logger import fail, info, ok, short, step, warn
from devices.device import Device, RegistrationError, make_tls_client
from fog.proofs.proof_package import verify_proof_package

DEFAULT_DEVICES = ["temp01", "pressure01", "camera01", "plc01", "meter01", "valve01"]


def pause(enabled: bool):
    if enabled:
        input("\n   press Enter to continue ...")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--devices", nargs="+", default=DEFAULT_DEVICES)
    parser.add_argument("--show", default=None, help="device whose proof is verified step by step")
    parser.add_argument("--pause", action="store_true")
    args = parser.parse_args()
    focus = args.show or args.devices[0]

    admin = make_tls_client()
    try:
        health = admin.get("/health").json()
    except httpx.ConnectError:
        fail("demo", f"cannot reach {config.FOG_BASE_URL}. Start it first: python scripts/run_fog.py")
        sys.exit(1)

    step("STEP 0  Fog node status")
    ok("demo", f"connected over TLS to {health['fog_id']} (zone {health['zone']})")
    info("demo", f"fog signing public key {short(health['fog_public_key'], 16)}")
    info("demo", f"open epoch {health['current_epoch']}, anchored epochs so far {health['anchored_epochs']}")
    pause(args.pause)

    # ---------------------------------------------------------------
    step("STEP 1 and 2  PSK authentication, DID + key generation, proof of possession, metadata")
    devices = {}
    for name in args.devices:
        print()
        d = Device(name, persist_key=False)        # fresh key pair each demo run
        try:
            d.register()
            devices[d.did] = d
        except RegistrationError as e:
            fail("demo", f"{name} could not register: {e}")
    pause(args.pause)

    # ---------------------------------------------------------------
    step("STEP 3  Devices collected into the open registration batch")
    cur = admin.get("/epoch/current").json()
    info("demo", f"epoch {cur['epoch_id']} is OPEN, batch size = {cur['batch_size']}")
    for did in cur["queued_dids"]:
        name = devices[did].name if did in devices else "(earlier device)"
        info("demo", f"   queued  {name:<11} {did}")
    info("demo", "no tree has been built yet: add_leaf() only appends")
    pause(args.pause)

    # ---------------------------------------------------------------
    step("STEP 4  Close epoch: sort leaves, build tree, compute root, anchor in ledger")
    r = admin.post("/epoch/close", headers={"X-Admin-Key": config.ADMIN_KEY})
    if r.status_code != 200:
        fail("demo", f"epoch close failed: {r.text}")
        sys.exit(1)
    closed = r.json()
    info("demo", f"sorted leaf order ({closed['leaf_count']} leaves, "
                 f"{closed['new_devices']} new, {closed['carried_forward']} carried forward):")
    for item in closed["sorted_leaves"]:
        name = devices[item["did"]].name if item["did"] in devices else "(earlier device)"
        print(f"      [{item['index']}] {item['leaf']}  {name}")
    ok("demo", f"epoch {closed['epoch_id']} root R = {closed['root']}")
    b = closed["block"]
    ok("demo", f"anchored as ledger block {b['block_index']}")
    info("demo", f"   block hash {b['block_hash']}")
    info("demo", f"   prev hash  {b['prev_hash']}")
    info("demo", f"   signed by  {b['fog_id']} at {b['timestamp']}")
    t = closed["timings_ms"]
    info("demo", f"   batch processing {t['batch_ms']:.3f} ms (sort {t['sort_ms']:.3f} + build {t['build_ms']:.3f}), "
                 f"anchor {t['anchor_ms']:.2f} ms, proofs {t['proofs_ms']:.2f} ms")
    chain = admin.get("/registry/verify").json()
    (ok if chain["valid"] else fail)("ledger", chain["message"])
    pause(args.pause)

    # ---------------------------------------------------------------
    step(f"STEP 5  Proof generation and verification for {focus}")
    d = next((x for x in devices.values() if x.name == focus), None)
    if d is None:
        warn("demo", f"{focus} did not register in this run")
        return
    pkg = d.fetch_proof()
    d.save_proof()
    info(d.name, f"DID  {pkg['did']}")
    info(d.name, f"leaf {pkg['leaf']}")
    for i, s in enumerate(pkg["proof_path"]):
        info(d.name, f"   sibling {i}: {s['sibling']}  (on the {'left' if s['side'] == 'L' else 'right'})")

    trusted = admin.get(f"/registry/root/{pkg['epoch_id']}").json()["root"]
    info("verifier", f"trusted root for epoch {pkg['epoch_id']} from ledger: {short(trusted, 16)}")
    current = bytes.fromhex(pkg["leaf"])
    info("verifier", f"h0 = leaf                      {short(current.hex(), 16)}")
    for i, s in enumerate(pkg["proof_path"]):
        sib = bytes.fromhex(s["sibling"])
        current = node_hash(sib, current) if s["side"] == "L" else node_hash(current, sib)
        formula = "H(sibling || h)" if s["side"] == "L" else "H(h || sibling)"
        info("verifier", f"h{i + 1} = {formula:<24} {short(current.hex(), 16)}")

    result = verify_proof_package(pkg, trusted, bytes.fromhex(health["fog_public_key"]))
    if result.ok:
        ok("verifier", f"reconstructed root == anchored root, fog signature valid  ->  VERIFICATION TRUE")
    else:
        fail("verifier", f"VERIFICATION FALSE: {result.reason} (detected by {result.detected_by})")
    info("demo", f"proof package saved to devices/keystore/{d.name}_proof.json")

    for x in devices.values():
        x.close()
    admin.close()


if __name__ == "__main__":
    main()