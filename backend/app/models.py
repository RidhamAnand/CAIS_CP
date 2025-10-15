import base64
import json
from pathlib import Path
from typing import Optional

from pydantic import BaseModel

from app.crypto import aes_gcm_decrypt, aes_gcm_encrypt, hmac_generate


def _canonical_json(data: dict) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


class Metadata(BaseModel):
    key_id: str
    resource_id: str
    created_at: str
    phase: str
    kek_version: int
    wrapped_dek_b64: str
    encrypted_secret_b64: Optional[str] = None
    hmac: Optional[str] = None

    @property
    def wrapped_dek(self) -> bytes:
        return base64.b64decode(self.wrapped_dek_b64.encode("utf-8"))

    def set_wrapped_dek(self, wrapped: bytes) -> None:
        self.wrapped_dek_b64 = base64.b64encode(wrapped).decode("utf-8")

    def _payload_dict(self) -> dict:
        return self.dict()

    def _dict_without_hmac(self) -> dict:
        data = self.dict()
        data.pop("hmac", None)
        return data

    def save(self, path: str) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(self.dict(), handle, indent=2)

    def to_payload(self, kek: bytes) -> bytes:
        payload = _canonical_json(self._payload_dict()).encode("utf-8")
        return aes_gcm_encrypt(kek, payload)

    @classmethod
    def from_payload(cls, payload: bytes, kek: bytes) -> "Metadata":
        raw = aes_gcm_decrypt(kek, payload)
        data = json.loads(raw.decode("utf-8"))
        return cls(**data)

    def generate_hmac(self, kek: bytes) -> str:
        material = _canonical_json(self._dict_without_hmac()).encode("utf-8")
        return hmac_generate(kek, material).hex()

    def update_hmac(self, kek: bytes) -> None:
        self.hmac = self.generate_hmac(kek)

    def verify_hmac(self, kek: bytes) -> bool:
        if not self.hmac:
            return False
        material = _canonical_json(self._dict_without_hmac()).encode("utf-8")
        expected = hmac_generate(kek, material).hex()
        return expected == self.hmac


class ResourceRequest(BaseModel):
    resource_id: str
    operator: str
    secret: Optional[str] = None


class RotationResponse(BaseModel):
    new_version: int
    updated_keys: int


class AuditEntry(BaseModel):
    timestamp: str
    operation: str
    key_id: str
    operator: str
    prev_hash: str
    hash: str
    details: Optional[dict] = None
