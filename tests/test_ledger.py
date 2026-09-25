import json

import pytest

from common.canonical import sha256
from common.crypto_utils import generate_keypair, public_key_bytes
from registry.ledger import Ledger, LedgerError


def root(i):
    return sha256(f"root{i}".encode()).hex()


@pytest.fixture
def key():
    return generate_keypair()


@pytest.fixture
def ledger(tmp_path, key):
    return Ledger(tmp_path / "ledger.json", key)


def test_anchor_and_get_root(ledger):
    rec = ledger.anchor_root(1, root(1), leaf_count=5)
    assert rec.block_index == 0 and rec.epoch_id == 1
    assert ledger.get_root(1) == root(1)
    assert ledger.get_root(99) is None


def test_blocks_are_linked(ledger):
    a = ledger.anchor_root(1, root(1), 5)
    b = ledger.anchor_root(2, root(2), 7)
    assert b.prev_hash == a.block_hash
    assert ledger.latest_epoch() == 2
    assert ledger.verify_chain() == (True, "chain valid (2 blocks)")


def test_epoch_is_immutable(ledger):
    ledger.anchor_root(1, root(1), 5)
    with pytest.raises(LedgerError):
        ledger.anchor_root(1, root(2), 5)


def test_bad_root_rejected(ledger):
    with pytest.raises(LedgerError):
        ledger.anchor_root(1, "abcd", 5)


def test_persists_across_restart(tmp_path, key):
    Ledger(tmp_path / "l.json", key).anchor_root(3, root(3), 4)
    reloaded = Ledger(tmp_path / "l.json", key)
    assert reloaded.get_root(3) == root(3)
    assert reloaded.verify_chain()[0]


def _tamper(ledger, fn):
    blocks = json.loads(ledger.path.read_text())
    fn(blocks)
    ledger.path.write_text(json.dumps(blocks))


def test_modified_root_detected(ledger):
    for e in range(1, 4):
        ledger.anchor_root(e, root(e), 5)
    _tamper(ledger, lambda b: b[1].update(root=root(99)))
    ok, msg = ledger.verify_chain()
    assert not ok and "block 1" in msg


def test_rehashed_block_still_breaks_link(ledger):
    """Attacker edits block 0 and recomputes its hash: block 1's prev_hash no longer matches."""
    from common.canonical import canonical_json
    for e in range(1, 3):
        ledger.anchor_root(e, root(e), 5)

    def edit(b):
        b[0]["leaf_count"] = 500
        body = {k: b[0][k] for k in ("block_index", "epoch_id", "root", "leaf_count", "timestamp", "fog_id", "prev_hash")}
        b[0]["block_hash"] = sha256(canonical_json({**body, "signature": b[0]["signature"]})).hex()
    _tamper(ledger, edit)
    assert not ledger.verify_chain()[0]


def test_deleted_block_detected(ledger):
    for e in range(1, 4):
        ledger.anchor_root(e, root(e), 5)
    _tamper(ledger, lambda b: b.pop(1))
    assert not ledger.verify_chain()[0]


def test_wrong_fog_key_detected(ledger):
    ledger.anchor_root(1, root(1), 5)
    impostor = public_key_bytes(generate_keypair())
    assert not ledger.verify_chain(trusted_fog_pk=impostor)[0]