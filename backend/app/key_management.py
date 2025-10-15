import base64
import hashlib
import json
import secrets
from pathlib import Path
from typing import Dict, List, Tuple

from app.crypto import aes_gcm_decrypt, aes_gcm_encrypt
from app.models import Metadata

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
METADATA_DIR = DATA_DIR / "metadata"
STEGO_DIR = DATA_DIR / "stego"
KEYSTORE_FILE = DATA_DIR / "keystore.json"


def _ensure_directories() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    METADATA_DIR.mkdir(parents=True, exist_ok=True)
    STEGO_DIR.mkdir(parents=True, exist_ok=True)


def load_keystore() -> Dict:
    if not KEYSTORE_FILE.exists():
        return {}
    with open(KEYSTORE_FILE, "r", encoding="utf-8") as handle:
        raw = json.load(handle)
    if "kek" in raw:
        raw["kek"]["value"] = base64.b64decode(raw["kek"]["value"].encode("utf-8"))
        salt = raw["kek"].get("salt")
        if salt:
            raw["kek"]["salt"] = base64.b64decode(salt.encode("utf-8"))
    return raw


def save_keystore(store: Dict) -> None:
    payload = {}
    if "kek" in store:
        record = {
            "value": base64.b64encode(store["kek"]["value"]).decode("utf-8"),
            "version": store["kek"].get("version", 1),
        }
        salt = store["kek"].get("salt")
        if salt:
            record["salt"] = base64.b64encode(salt).decode("utf-8")
        payload["kek"] = record
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with open(KEYSTORE_FILE, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)


def generate_kek(password: str) -> bytes:
    salt = secrets.token_bytes(16)
    kek = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000, dklen=32)
    store = load_keystore()
    version = store.get("kek", {}).get("version", 0) + 1
    store["kek"] = {"value": kek, "version": version, "salt": salt}
    save_keystore(store)
    return kek


def generate_dek() -> bytes:
    return secrets.token_bytes(32)


def wrap_dek(dek: bytes, kek: bytes) -> bytes:
    return aes_gcm_encrypt(kek, dek)


def unwrap_dek(wrapped: bytes, kek: bytes) -> bytes:
    return aes_gcm_decrypt(kek, wrapped)


def metadata_path(resource_id: str) -> Path:
    return METADATA_DIR / f"{resource_id}.json"


def load_metadata(resource_id: str) -> Metadata:
    path = metadata_path(resource_id)
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    return Metadata(**data)


def save_metadata(metadata: Metadata) -> None:
    _ensure_directories()
    metadata.save(metadata_path(metadata.resource_id).as_posix())


def rotate_kek(old_kek: bytes) -> Tuple[bytes, List[Dict[str, str]], int]:
    new_kek = secrets.token_bytes(32)
    updated: List[Dict[str, str]] = []
    if METADATA_DIR.exists():
        for path in METADATA_DIR.glob("*.json"):
            with open(path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
            metadata = Metadata(**data)
            dek = unwrap_dek(metadata.wrapped_dek, old_kek)
            metadata.set_wrapped_dek(wrap_dek(dek, new_kek))
            metadata.kek_version += 1
            metadata.update_hmac(new_kek)
            metadata.save(path.as_posix())
            updated.append(
                {
                    "key_id": metadata.key_id,
                    "resource_id": metadata.resource_id,
                    "wrapped_dek_b64": metadata.wrapped_dek_b64,
                    "has_secret": bool(metadata.encrypted_secret_b64),
                }
            )
    store = load_keystore()
    version = store.get("kek", {}).get("version", 0) + 1
    salt = secrets.token_bytes(16)
    store["kek"] = {"value": new_kek, "version": version, "salt": salt}
    save_keystore(store)
    return new_kek, updated, version


def revoke_key(resource_id: str) -> None:
    path = metadata_path(resource_id)
    if not path.exists():
        return
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    metadata = Metadata(**data)
    metadata.phase = "revoked"
    store = load_keystore()
    kek_value = store.get("kek", {}).get("value")
    if kek_value:
        metadata.update_hmac(kek_value)
    metadata.save(path.as_posix())
