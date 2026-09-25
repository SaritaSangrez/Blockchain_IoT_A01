"""
ECC helpers on NIST P256 (SECP256R1) with ECDSA SHA256.
Public keys travel as 33 byte compressed points (hex in JSON).
Signatures travel as DER bytes (hex in JSON).
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

CURVE = ec.SECP256R1()
DID_PREFIX = "did:iiot:"


def generate_keypair() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(CURVE)


def public_key_bytes(key) -> bytes:
    """Compressed point of a private or public key object."""
    if isinstance(key, ec.EllipticCurvePrivateKey):
        key = key.public_key()
    return key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)


def load_public_key(pk_bytes: bytes) -> ec.EllipticCurvePublicKey:
    """Raises ValueError if the bytes are not a valid P256 point."""
    return ec.EllipticCurvePublicKey.from_encoded_point(CURVE, bytes(pk_bytes))


def sign(private_key: ec.EllipticCurvePrivateKey, message: bytes) -> bytes:
    return private_key.sign(message, ec.ECDSA(hashes.SHA256()))


def verify(pk_bytes: bytes, message: bytes, signature: bytes) -> bool:
    """True only if the signature is valid. Never raises on bad input."""
    try:
        load_public_key(pk_bytes).verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def derive_did(pk_bytes: bytes) -> str:
    """
    DID derived from the public key: did:iiot:<first 16 hex chars of SHA256(PK)>.
    A DID that is a fingerprint of the key cannot be claimed with another key.
    """
    return DID_PREFIX + hashlib.sha256(bytes(pk_bytes)).hexdigest()[:16]


def save_private_key(private_key: ec.EllipticCurvePrivateKey, path: Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    path.write_bytes(pem)


def load_private_key(path: Path) -> ec.EllipticCurvePrivateKey:
    return serialization.load_pem_private_key(Path(path).read_bytes(), password=None)


def load_or_create_private_key(path: Path) -> ec.EllipticCurvePrivateKey:
    path = Path(path)
    if path.exists():
        return load_private_key(path)
    key = generate_keypair()
    save_private_key(key, path)
    return key