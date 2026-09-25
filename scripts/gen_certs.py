"""
One time setup. Creates:
  fog/tls/ca_cert.pem, ca_key.pem         self signed zone CA (devices trust this)
  fog/tls/fog_cert.pem, fog_tls_key.pem   HTTPS certificate for localhost, signed by the CA
  fog/tls/fog_signing_key.pem             fog ECDSA identity key (ledger, proofs, tokens)
  fog/auth/psk_store.json                 fog side: SHA256(PSK) per provisioning ID
  devices/keystore/provisioning.json      device side: raw PSK per device (factory provisioning)

Run from the project root:   python scripts/gen_certs.py
Add  --force  to regenerate everything.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import secrets
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

import config
from common.crypto_utils import public_key_bytes, save_private_key
from common.logger import info, ok, step, warn


def _write_key(key, path: Path) -> None:
    save_private_key(key, path)


def _write_cert(cert, path: Path) -> None:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def make_ca():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "IIoT Assignment"),
        x509.NameAttribute(NameOID.COMMON_NAME, "IIoT Zone CA"),
    ])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False, data_encipherment=False,
                key_agreement=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def make_server_cert(ca_key, ca_cert):
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "IIoT Assignment"),
            x509.NameAttribute(NameOID.COMMON_NAME, config.FOG_HOST),
        ]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
            ]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    return key, cert


def provision_psks():
    """Each device gets its own 32 byte PSK. The fog stores only the hash."""
    names = list(config.DEMO_DEVICES) + [f"sim{i:04d}" for i in range(1, config.SIM_DEVICE_COUNT + 1)]
    device_side, fog_side = {}, {}
    for name in names:
        psk = secrets.token_hex(32)
        device_side[name] = psk
        fog_side[name] = hashlib.sha256(bytes.fromhex(psk)).hexdigest()
    config.PSK_STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    config.DEVICE_PROVISIONING_PATH.parent.mkdir(parents=True, exist_ok=True)
    config.PSK_STORE_PATH.write_text(json.dumps(fog_side, indent=2), encoding="utf-8")
    config.DEVICE_PROVISIONING_PATH.write_text(json.dumps(device_side, indent=2), encoding="utf-8")
    return len(names)


def main():
    force = "--force" in sys.argv
    step("Generating TLS certificates, fog signing key and device PSKs")
    config.TLS_DIR.mkdir(parents=True, exist_ok=True)

    if config.CA_CERT_PATH.exists() and not force:
        warn("setup", "certificates already exist, use --force to regenerate")
    else:
        ca_key, ca_cert = make_ca()
        _write_key(ca_key, config.CA_KEY_PATH)
        _write_cert(ca_cert, config.CA_CERT_PATH)
        ok("setup", f"zone CA created      -> {config.CA_CERT_PATH.name}")

        srv_key, srv_cert = make_server_cert(ca_key, ca_cert)
        _write_key(srv_key, config.FOG_TLS_KEY_PATH)
        _write_cert(srv_cert, config.FOG_TLS_CERT_PATH)
        ok("setup", f"fog TLS cert created -> {config.FOG_TLS_CERT_PATH.name} (SAN: localhost, 127.0.0.1)")

    if config.FOG_SIGNING_KEY_PATH.exists() and not force:
        warn("setup", "fog signing key already exists, keeping it")
    else:
        signing = ec.generate_private_key(ec.SECP256R1())
        _write_key(signing, config.FOG_SIGNING_KEY_PATH)
        ok("setup", f"fog signing key      -> PK {public_key_bytes(signing).hex()[:20]}...")

    if config.PSK_STORE_PATH.exists() and not force:
        warn("setup", "PSK store already exists, keeping it")
    else:
        n = provision_psks()
        ok("setup", f"provisioned {n} device PSKs (fog keeps hashes only)")

    info("setup", "done")


if __name__ == "__main__":
    main()