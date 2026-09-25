"""
Simulated IIoT device.

Holds its own P256 key pair (private key never leaves the device), derives
its DID from the public key, and runs the onboarding protocol with the fog:
    1. PSK bootstrap over TLS   -> session
    2. send DID + PK            -> challenge
    3. sign challenge           -> proof of possession
    4. send metadata            -> leaf queued in the open batch
    5. after the epoch closes   -> fetch and verify its proof package

Quick run from the project root (fog must be running):
    python devices/device.py temp01 camera01
Each device uses a fresh key pair every run, so you can rerun freely.
"""
from __future__ import annotations

import json
import ssl
import sys
import time
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import httpx

import config
from common.canonical import pop_message
from common.crypto_utils import derive_did, load_or_create_private_key, public_key_bytes, sign
from common.logger import fail, info, ok, short, step


class RegistrationError(Exception):
    def __init__(self, stage: str, status: int, detail: str):
        super().__init__(f"{stage} failed [{status}]: {detail}")
        self.stage, self.status, self.detail = stage, status, detail


def load_psk(name: str) -> str:
    data = json.loads(config.DEVICE_PROVISIONING_PATH.read_text(encoding="utf-8"))
    if name not in data:
        raise KeyError(f"no provisioned PSK for device '{name}'")
    return data[name]


def make_tls_client(base_url: str = config.FOG_BASE_URL, timeout: float = 10.0) -> httpx.Client:
    """HTTPS client that trusts ONLY the zone CA (real certificate verification)."""
    ctx = ssl.create_default_context(cafile=str(config.CA_CERT_PATH))
    return httpx.Client(base_url=base_url, verify=ctx, timeout=timeout)


class Device:
    def __init__(
        self,
        name: str,
        psk: Optional[str] = None,
        client: Optional[httpx.Client] = None,
        keystore_dir: Path = config.KEYSTORE_DIR,
        persist_key: bool = True,
        verbose: bool = True,
    ):
        self.name = name
        self.psk = psk if psk is not None else load_psk(name)
        self.client = client if client is not None else make_tls_client()
        self.verbose = verbose

        if persist_key:
            self.private_key = load_or_create_private_key(Path(keystore_dir) / f"{name}_key.pem")
        else:
            from common.crypto_utils import generate_keypair
            self.private_key = generate_keypair()

        self.pk_bytes = public_key_bytes(self.private_key)
        self.did = derive_did(self.pk_bytes)
        self.session_id: Optional[str] = None
        self.leaf: Optional[str] = None
        self.proof_package: Optional[dict] = None
        self.timings: dict = {}

    @property
    def public_key_hex(self) -> str:
        return self.pk_bytes.hex()

    def _log(self, fn, msg: str) -> None:
        if self.verbose:
            fn(self.name, msg)

    def _post(self, stage: str, path: str, **kwargs) -> dict:
        r = self.client.post(path, **kwargs)
        if r.status_code != 200:
            detail = r.json().get("detail", r.text) if r.headers.get("content-type", "").startswith("application/json") else r.text
            self._log(fail, f"{stage} rejected [{r.status_code}]: {detail}")
            raise RegistrationError(stage, r.status_code, detail)
        return r.json()

    # ---------- protocol steps ----------

    def register_start(self) -> str:
        data = self._post("register_start", "/register/start",
                          headers={"Authorization": f"PSK {self.name}:{self.psk}"})
        self.session_id = data["session_id"]
        self._log(ok, f"PSK authenticated, session {short(self.session_id, 8)}")
        return self.session_id

    def submit_public_key(self) -> str:
        self._log(info, f"DID {self.did}  PK {short(self.public_key_hex)}")
        data = self._post("submit_public_key", "/register/pubkey",
                          json={"session_id": self.session_id, "did": self.did, "public_key": self.public_key_hex})
        self._log(info, f"received challenge {short(data['challenge'])}")
        return data["challenge"]

    def sign_challenge(self, challenge_hex: str) -> str:
        return sign(self.private_key, pop_message(bytes.fromhex(challenge_hex), self.did)).hex()

    def prove_possession(self, challenge_hex: str) -> dict:
        signature = self.sign_challenge(challenge_hex)
        data = self._post("prove_possession", "/register/pop",
                          json={"session_id": self.session_id, "signature": signature})
        self._log(ok, f"proof of possession accepted, status {data['status']}")
        return data

    def submit_metadata(self, device_type: Optional[str] = None, role: Optional[str] = None,
                        vendor: str = config.DEFAULT_VENDOR, zone: str = config.FOG_ZONE) -> dict:
        default_type, default_role = config.DEMO_DEVICES.get(self.name, config.SIM_DEVICE_TYPE)
        body = {
            "session_id": self.session_id,
            "device_name": self.name,
            "device_type": device_type or default_type,
            "zone": zone,
            "vendor": vendor,
            "role": role or default_role,
        }
        data = self._post("submit_metadata", "/register/metadata", json=body)
        self.leaf = data["leaf"]
        self._log(ok, f"metadata accepted, leaf {short(data['leaf'])} queued for epoch "
                      f"{data['epoch_id']} (batch size {data['batch_size']})")
        return data

    def fetch_proof(self, epoch_id: Optional[int] = None) -> dict:
        params = {"epoch_id": epoch_id} if epoch_id is not None else None
        r = self.client.get(f"/proof/{self.did}", params=params)
        if r.status_code != 200:
            raise RegistrationError("fetch_proof", r.status_code, r.json().get("detail", r.text))
        self.proof_package = r.json()
        self._log(ok, f"received proof package: epoch {self.proof_package['epoch_id']}, "
                      f"{len(self.proof_package['proof_path'])} sibling hashes")
        return self.proof_package

    def save_proof(self, keystore_dir: Path = config.KEYSTORE_DIR) -> Path:
        path = Path(keystore_dir) / f"{self.name}_proof.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.proof_package, indent=2), encoding="utf-8")
        return path

    def register(self) -> dict:
        """Full Phase 1 device side: PSK, DID + PK, PoP, metadata."""
        t0 = time.perf_counter()
        self.register_start()
        challenge = self.submit_public_key()
        self.prove_possession(challenge)
        result = self.submit_metadata()
        self.timings["register_seconds"] = time.perf_counter() - t0
        return result

    def onboard(self) -> dict:
        """Steps 1 to 5 end to end, with timing for the registration latency metric."""
        t0 = time.perf_counter()
        self.register_start()
        challenge = self.submit_public_key()
        result = self.prove_possession(challenge)
        self.timings["onboard_seconds"] = time.perf_counter() - t0
        self._log(info, f"onboarding (PSK + PoP) took {self.timings['onboard_seconds'] * 1000:.1f} ms")
        return result

    def close(self) -> None:
        self.client.close()


if __name__ == "__main__":
    names = sys.argv[1:] or ["temp01"]
    for n in names:
        step(f"Onboarding device {n}")
        d = Device(n, persist_key=False)
        try:
            d.register()
        except RegistrationError as e:
            fail(n, str(e))
        except httpx.ConnectError:
            fail(n, f"cannot reach fog at {config.FOG_BASE_URL}. Is scripts/run_fog.py running?")
        finally:
            d.close()