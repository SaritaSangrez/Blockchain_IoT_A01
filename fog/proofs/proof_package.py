"""
Proof packages: the reusable membership evidence each device keeps.

    P_d = { DID, PK, L_d, proof path, epoch_id, root, fog_id, fog signature }

The fog signs canonical_json({did, leaf, root, epoch_id, fog_id}), which binds
this leaf to this root and epoch (slide 29, sigma_i,d).

verify_proof_package() is the verifier used by the fog in Phase 3 and by the
tamper attack script. It NEVER trusts the leaf or root inside the package:
it recomputes the leaf from DID + PK and compares against the root taken
from the ledger for that epoch.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Union

from common.canonical import canonical_json, leaf_hash
from common.crypto_utils import sign, verify
from common.schemas import ProofPackage, ProofStep
from fog.merkle.merkle_tree import MerkleTree, reconstruct_root


def package_message(did: str, leaf_hex: str, root_hex: str, epoch_id: int, fog_id: str) -> bytes:
    return canonical_json({"did": did, "leaf": leaf_hex, "root": root_hex, "epoch_id": int(epoch_id), "fog_id": fog_id})


def build_proof_package(did: str, pk_hex: str, leaf: bytes, tree: MerkleTree,
                        epoch_id: int, fog_id: str, signing_key) -> ProofPackage:
    root_hex = tree.root_hex
    path = tree.get_proof(leaf)
    signature = sign(signing_key, package_message(did, leaf.hex(), root_hex, epoch_id, fog_id)).hex()
    return ProofPackage(
        did=did, public_key=pk_hex, leaf=leaf.hex(), epoch_id=epoch_id, root=root_hex,
        proof_path=[ProofStep(**s) for s in path], fog_id=fog_id, fog_signature=signature,
    )


@dataclass
class VerificationResult:
    ok: bool
    reason: str
    detected_by: str
    recomputed_leaf: Optional[str] = None
    reconstructed_root: Optional[str] = None
    trusted_root: Optional[str] = None


def verify_proof_package(pkg: Union[ProofPackage, dict], trusted_root_hex: Optional[str],
                         fog_pk_bytes: bytes) -> VerificationResult:
    """
    Order of checks (each names the component that rejects):
      1. recompute L_d = H(DID || PK)                      identity check
      2. claimed leaf must equal the recomputed leaf        identity check
      3. trusted root must exist for this epoch             root registry
      4. climb the proof path to a candidate root           Merkle verifier
      5. candidate root must equal the ANCHORED root        Merkle verifier
      6. fog signature over (did, leaf, root, epoch, fog)   signature check
    """
    if isinstance(pkg, dict):
        pkg = ProofPackage(**pkg)
    path = [s.model_dump() for s in pkg.proof_path]

    try:
        recomputed = leaf_hash(pkg.did, bytes.fromhex(pkg.public_key)).hex()
    except ValueError as e:
        return VerificationResult(False, f"malformed identity: {e}", "identity check")

    if recomputed != pkg.leaf:
        return VerificationResult(False, "claimed leaf does not equal H(DID || PK)", "identity check",
                                  recomputed_leaf=recomputed)

    if trusted_root_hex is None:
        return VerificationResult(False, f"no anchored root for epoch {pkg.epoch_id}", "root registry",
                                  recomputed_leaf=recomputed)

    candidate = reconstruct_root(recomputed, path)
    if candidate is None:
        return VerificationResult(False, "malformed proof path", "Merkle verifier",
                                  recomputed_leaf=recomputed, trusted_root=trusted_root_hex)
    candidate_hex = candidate.hex()

    if candidate_hex != trusted_root_hex:
        return VerificationResult(False, "reconstructed root does not match anchored root", "Merkle verifier",
                                  recomputed, candidate_hex, trusted_root_hex)

    msg = package_message(pkg.did, pkg.leaf, pkg.root, pkg.epoch_id, pkg.fog_id)
    if pkg.root != trusted_root_hex or not verify(fog_pk_bytes, msg, bytes.fromhex(pkg.fog_signature)):
        return VerificationResult(False, "fog signature on proof package is invalid", "signature check",
                                  recomputed, candidate_hex, trusted_root_hex)

    return VerificationResult(True, "membership proven for this epoch", "all checks passed",
                              recomputed, candidate_hex, trusted_root_hex)