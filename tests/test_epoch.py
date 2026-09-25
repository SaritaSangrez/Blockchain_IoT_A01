"""
Tests for metadata validation, batching, epoch finalization, proof packages
and the revocation exclusion hook.
"""
import secrets

import pytest
from fastapi.testclient import TestClient

from common.canonical import leaf_hash
from common.crypto_utils import derive_did, generate_keypair, public_key_bytes
from common.schemas import DeviceRecord, DeviceStatus, MetadataRequest
from devices.device import Device, RegistrationError
from fog.auth.psk import PSKStore
from fog.batch.epoch_manager import EpochError, EpochManager
from fog.main import create_app
from fog.merkle.merkle_tree import verify_proof
from fog.proofs.proof_package import verify_proof_package
from fog.registration.validation import validate_metadata
from fog.storage.device_store import DeviceStore
from registry.ledger import Ledger

ADMIN = {"X-Admin-Key": "test_admin"}


# ---------- helpers ----------

def identity():
    pk = public_key_bytes(generate_keypair())
    return derive_did(pk), pk


@pytest.fixture
def manager(tmp_path):
    key = generate_keypair()
    store = DeviceStore()
    ledger = Ledger(tmp_path / "ledger.json", key)
    return EpochManager(ledger, key, "fog_A", store, carry_forward=True, verbose=False), store, key


def queue(manager_tuple, n):
    mgr, store, _ = manager_tuple
    out = []
    for _ in range(n):
        did, pk = identity()
        store.upsert(DeviceRecord(did=did, public_key=pk.hex(), status=DeviceStatus.PENDING))
        mgr.add_leaf(did, pk)
        out.append((did, pk))
    return out


# ---------- metadata validation ----------

def meta(**kw):
    base = dict(session_id="x", device_name="temp01", device_type="temperature_sensor",
                zone="factory_A", vendor="Acme", role="sensor")
    base.update(kw)
    return MetadataRequest(**base)


def test_valid_metadata_accepted():
    assert validate_metadata(meta(), "factory_A", {"temperature_sensor"}) == []


@pytest.mark.parametrize("field,value", [
    ("device_type", "toaster"), ("zone", "factory_B"), ("role", "boss"),
    ("vendor", "Unknown"), ("device_name", "Bad Name!"),
])
def test_invalid_metadata_rejected(field, value):
    assert validate_metadata(meta(**{field: value}), "factory_A", {"temperature_sensor"})


# ---------- batching ----------

def test_add_leaf_does_not_anchor(manager):
    queue(manager, 5)
    mgr = manager[0]
    assert mgr.batch_size() == 5
    assert len(mgr.ledger) == 0            # nothing anchored until the epoch closes


def test_duplicate_queue_rejected(manager):
    mgr = manager[0]
    did, pk = identity()
    mgr.add_leaf(did, pk)
    with pytest.raises(EpochError):
        mgr.add_leaf(did, pk)


def test_empty_epoch_rejected(manager):
    with pytest.raises(EpochError):
        manager[0].finalize_epoch()


@pytest.mark.parametrize("n", [1, 2, 3, 5, 7, 10])
def test_finalize_builds_one_root_and_valid_packages(manager, n):
    mgr, store, key = manager
    devs = queue(manager, n)
    result = mgr.finalize_epoch()
    assert result.epoch_id == 1 and len(mgr.ledger) == 1
    assert mgr.ledger.get_root(1) == result.root
    assert [x["leaf"] for x in result.sorted_leaves] == sorted(x["leaf"] for x in result.sorted_leaves)
    for did, pk in devs:
        pkg = result.packages[did]
        assert pkg.leaf == leaf_hash(did, pk).hex()
        assert verify_proof(pkg.leaf, [s.model_dump() for s in pkg.proof_path], result.root)
        assert verify_proof_package(pkg, mgr.ledger.get_root(1), public_key_bytes(key)).ok
        assert store.get(did).status == DeviceStatus.REGISTERED
    assert mgr.batch_size() == 0 and mgr.current_epoch_id == 2


def test_all_devices_in_batch_share_one_root(manager):
    queue(manager, 6)
    result = manager[0].finalize_epoch()
    assert {p.root for p in result.packages.values()} == {result.root}


# ---------- carry forward and revocation hook ----------

def test_next_epoch_carries_active_devices(manager):
    mgr, store, key = manager
    first = queue(manager, 3)
    r1 = mgr.finalize_epoch()
    queue(manager, 2)
    r2 = mgr.finalize_epoch()
    assert r2.new_devices == 2 and r2.carried_forward == 3 and len(r2.sorted_leaves) == 5
    # old proof still verifies against the OLD root (history is preserved)
    old = r1.packages[first[0][0]]
    assert verify_proof_package(old, mgr.ledger.get_root(1), public_key_bytes(key)).ok
    assert not verify_proof_package(old, mgr.ledger.get_root(2), public_key_bytes(key)).ok


def test_revoked_device_excluded_from_next_root(manager):
    mgr, store, key = manager
    devs = queue(manager, 4)
    r1 = mgr.finalize_epoch()
    victim = devs[0][0]
    store.set_status(victim, DeviceStatus.REVOKED)          # what the partner's revocation does
    queue(manager, 1)
    r2 = mgr.finalize_epoch()
    assert victim in r2.excluded
    assert victim not in r2.packages
    assert victim not in {x["did"] for x in r2.sorted_leaves}
    old_pkg = r1.packages[victim]
    assert verify_proof_package(old_pkg, mgr.ledger.get_root(1), public_key_bytes(key)).ok      # historical: still true
    assert not verify_proof_package(old_pkg, mgr.ledger.get_root(2), public_key_bytes(key)).ok  # current root: not a member


def test_exclude_dids_hook(manager):
    mgr, store, _ = manager
    devs = queue(manager, 3)
    result = mgr.finalize_epoch(exclude_dids=[devs[1][0]])
    assert devs[1][0] in result.excluded and devs[1][0] not in result.packages
    assert len(result.sorted_leaves) == 2


def test_manager_resumes_epoch_numbering(tmp_path):
    key = generate_keypair()
    ledger = Ledger(tmp_path / "l.json", key)
    ledger.anchor_root(1, "ab" * 32, 1)
    ledger.anchor_root(2, "cd" * 32, 1)
    assert EpochManager(ledger, key, "fog_A", DeviceStore(), verbose=False).current_epoch_id == 3


# ---------- proof package tampering ----------

def test_package_tampering_detected(manager):
    mgr, store, key = manager
    devs = queue(manager, 5)
    r = mgr.finalize_epoch()
    fog_pk = public_key_bytes(key)
    good = r.packages[devs[0][0]].model_dump()
    root = mgr.ledger.get_root(1)

    bad = dict(good); bad["did"] = devs[1][0]
    assert verify_proof_package(bad, root, fog_pk).detected_by == "identity check"

    bad = dict(good); bad["public_key"] = devs[1][1].hex()
    assert verify_proof_package(bad, root, fog_pk).detected_by == "identity check"

    bad = dict(good); bad["proof_path"] = [dict(s) for s in good["proof_path"]]
    bad["proof_path"][0]["sibling"] = "00" * 32
    assert verify_proof_package(bad, root, fog_pk).detected_by == "Merkle verifier"

    bad = dict(good); bad["fog_signature"] = good["fog_signature"][:-2] + "00"
    assert not verify_proof_package(bad, root, fog_pk).ok

    assert verify_proof_package(good, None, fog_pk).detected_by == "root registry"


# ---------- HTTP endpoints ----------

@pytest.fixture
def env(tmp_path):
    names = ["temp01", "pressure01", "camera01", "plc01", "motor01"]
    psks = {n: secrets.token_hex(32) for n in names}
    app = create_app(psk_entries={k: PSKStore.hash_psk(v) for k, v in psks.items()},
                     signing_key_path=tmp_path / "k.pem", ledger_path=tmp_path / "l.json",
                     admin_key="test_admin", verbose=False)
    return app, TestClient(app), psks


def dev(env, name):
    return Device(name, psk=env[2][name], client=env[1], persist_key=False, verbose=False)


def test_full_http_flow(env):
    app, client, _ = env
    devices = [dev(env, n) for n in ("temp01", "pressure01", "camera01", "plc01")]
    for d in devices:
        out = d.register()
        assert out["status"] == "QUEUED_FOR_BATCH"
    assert client.get("/epoch/current").json()["batch_size"] == 4

    with pytest.raises(RegistrationError) as e:
        devices[0].fetch_proof()                            # no proof before the epoch closes
    assert e.value.status == 404

    assert client.post("/epoch/close").status_code == 401   # admin key required
    closed = client.post("/epoch/close", headers=ADMIN).json()
    assert closed["leaf_count"] == 4 and closed["block"]["epoch_id"] == 1

    fog_pk = bytes.fromhex(client.get("/health").json()["fog_public_key"])
    trusted = client.get("/registry/root/1").json()["root"]
    for d in devices:
        pkg = d.fetch_proof()
        assert verify_proof_package(pkg, trusted, fog_pk).ok
    assert client.get("/registry/verify").json()["valid"]


def test_metadata_rejected_over_http(env):
    d = dev(env, "temp01")
    d.register_start()
    d.prove_possession(d.submit_public_key())
    with pytest.raises(RegistrationError) as e:
        d.submit_metadata(device_type="toaster")
    assert e.value.status == 422


def test_metadata_requires_pop_first(env):
    d = dev(env, "temp01")
    d.register_start()
    with pytest.raises(RegistrationError) as e:
        d.submit_metadata()
    assert e.value.status == 409


def test_registered_did_cannot_reenroll(env):
    app, client, psks = env
    d = dev(env, "temp01")
    d.register()
    again = Device("temp01", psk=psks["temp01"], client=client, persist_key=False, verbose=False)
    again.private_key, again.pk_bytes, again.did = d.private_key, d.pk_bytes, d.did
    again.register_start()
    with pytest.raises(RegistrationError) as e:
        again.submit_public_key()
    assert e.value.status == 409


def test_revoked_device_gets_no_proof(env):
    app, client, _ = env
    d = dev(env, "camera01")
    d.register()
    client.post("/epoch/close", headers=ADMIN)
    app.state.ctx.devices.set_status(d.did, DeviceStatus.REVOKED)
    with pytest.raises(RegistrationError) as e:
        d.fetch_proof()
    assert e.value.status == 403


def test_close_with_exclude_over_http(env):
    app, client, _ = env
    a, b = dev(env, "temp01"), dev(env, "plc01")
    a.register(); b.register()
    out = client.post("/epoch/close", headers=ADMIN, json={"exclude_dids": [b.did]}).json()
    assert out["leaf_count"] == 1 and b.did in out["excluded"]