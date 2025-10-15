import base64
import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from app.crypto import aes_gcm_decrypt
from app.models import AuditEntry

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
AUDIT_FILE = DATA_DIR / "audit_log.jsonl"


def _canonical(data: Dict) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def _last_hash() -> str:
    if not AUDIT_FILE.exists():
        return "GENESIS"
    with open(AUDIT_FILE, "r", encoding="utf-8") as handle:
        lines = handle.readlines()
    if not lines:
        return "GENESIS"
    return json.loads(lines[-1])["hash"]


def log_operation(phase: str, key_id: str, operator: str, details: Optional[Dict] = None) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "operation": phase,
        "key_id": key_id,
        "operator": operator,
        "prev_hash": _last_hash(),
    }
    if details:
        entry["details"] = details
    entry["hash"] = hashlib.sha256(_canonical({k: v for k, v in entry.items() if k != "hash"}).encode("utf-8")).hexdigest()
    with open(AUDIT_FILE, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry) + "\n")


def load_audit_log() -> List[AuditEntry]:
    if not AUDIT_FILE.exists():
        return []
    entries: List[AuditEntry] = []
    with open(AUDIT_FILE, "r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            payload = json.loads(line)
            entries.append(AuditEntry(**payload))
    return entries


def verify_audit_chain() -> bool:
    if not AUDIT_FILE.exists():
        return True
    prev_hash = "GENESIS"
    with open(AUDIT_FILE, "r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            payload = json.loads(line)
            if payload.get("prev_hash") != prev_hash:
                return False
            computed = hashlib.sha256(_canonical({k: v for k, v in payload.items() if k != "hash"}).encode("utf-8")).hexdigest()
            if computed != payload.get("hash"):
                return False
            prev_hash = payload.get("hash")
    return True


def recover_key_from_audit(key_id: str, kek: bytes) -> Optional[bytes]:
    if not AUDIT_FILE.exists():
        return None
    wrapped_b64 = None
    with open(AUDIT_FILE, "r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            payload = json.loads(line)
            if payload.get("key_id") != key_id:
                continue
            details = payload.get("details") or {}
            wrapped_b64 = details.get("wrapped_dek_b64") or wrapped_b64
    if not wrapped_b64:
        return None
    wrapped = base64.b64decode(wrapped_b64.encode("utf-8"))
    return aes_gcm_decrypt(kek, wrapped)
