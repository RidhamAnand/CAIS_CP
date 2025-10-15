import base64
import uuid
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel

from app.audit import log_operation, load_audit_log, recover_key_from_audit, verify_audit_chain
from app.crypto import aes_gcm_decrypt, aes_gcm_encrypt
from app.key_management import (
    STEGO_DIR,
    generate_dek,
    generate_kek,
    load_keystore,
    metadata_path,
    revoke_key,
    rotate_kek,
    save_metadata,
    unwrap_dek,
    wrap_dek,
)
from app.models import AuditEntry, Metadata, ResourceRequest, RotationResponse
from app.steganography import calculate_seed, embed_payload, extract_payload


app = FastAPI(title="Stego Key Management")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

keystore_state = load_keystore()


class ProvisionRequest(BaseModel):
    password: str
    operator: str


class GenerationResponse(BaseModel):
    key_id: str
    metadata: Metadata


class ExtractionResponse(BaseModel):
    key_id: str
    dek_hex: str
    metadata: Metadata
    secret: Optional[str] = None


class AuditChainStatus(BaseModel):
    valid: bool
    entries: List[AuditEntry]


def _require_kek() -> dict:
    if "kek" not in keystore_state:
        raise HTTPException(status_code=400, detail="KEK not provisioned")
    return keystore_state["kek"]


@app.post("/provision")
def provision(req: ProvisionRequest):
    global keystore_state
    generate_kek(req.password)
    keystore_state = load_keystore()
    log_operation("provision", "KEK", req.operator)
    return {"message": "KEK provisioned", "version": keystore_state["kek"]["version"]}


@app.post("/generate", response_model=GenerationResponse)
def generate(req: ResourceRequest):
    kek_record = _require_kek()
    dek = generate_dek()
    key_id = f"DEK-{uuid.uuid4().hex[:8].upper()}"
    wrapped = wrap_dek(dek, kek_record["value"])
    metadata = Metadata(
        key_id=key_id,
        resource_id=req.resource_id,
        created_at=datetime.utcnow().isoformat() + "Z",
        phase="generated",
        kek_version=kek_record["version"],
        wrapped_dek_b64="",
    )
    metadata.set_wrapped_dek(wrapped)
    secret_text = (req.secret or "").strip()
    if secret_text:
        encrypted_secret = aes_gcm_encrypt(dek, secret_text.encode("utf-8"))
        metadata.encrypted_secret_b64 = base64.b64encode(encrypted_secret).decode("utf-8")
    metadata.update_hmac(kek_record["value"])
    save_metadata(metadata)
    log_operation(
        "generate",
        key_id,
        req.operator,
        details={
            "resource_id": req.resource_id,
            "wrapped_dek_b64": metadata.wrapped_dek_b64,
            "has_secret": bool(metadata.encrypted_secret_b64),
        },
    )
    return GenerationResponse(key_id=key_id, metadata=metadata)


@app.post("/embed")
def embed(
    resource_id: str = Form(...),
    operator: str = Form(...),
    cover_image: UploadFile = File(...),
):
    kek_record = _require_kek()
    path = metadata_path(resource_id)
    if not path.exists():
        raise HTTPException(status_code=404, detail="Metadata not found")
    metadata = Metadata.parse_file(path)
    seed = calculate_seed(kek_record["value"], metadata.resource_id)
    payload = metadata.to_payload(kek_record["value"])

    cover_path = Path(STEGO_DIR) / cover_image.filename
    cover_path.parent.mkdir(parents=True, exist_ok=True)
    with open(cover_path, "wb") as handle:
        handle.write(cover_image.file.read())

    try:
        stego_path = embed_payload(cover_path.as_posix(), payload, seed)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    metadata.phase = "embedded"
    metadata.update_hmac(kek_record["value"])
    save_metadata(metadata)
    log_operation(
        "embed",
        metadata.key_id,
        operator,
        details={"resource_id": metadata.resource_id, "stego_filename": Path(stego_path).name},
    )
    filename = Path(stego_path).name
    return {
        "filename": filename,
        "download_url": f"/stego/{filename}",
    }


@app.get("/stego/{filename}")
def get_stego(filename: str):
    file_path = Path(STEGO_DIR) / filename
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Stego image not found")
    return FileResponse(file_path)


@app.post("/extract", response_model=ExtractionResponse)
def extract(
    resource_id: str = Form(...),
    operator: str = Form(...),
    stego_image: UploadFile = File(...),
):
    kek_record = _require_kek()
    seed = calculate_seed(kek_record["value"], resource_id)
    temp_path = Path(STEGO_DIR) / f"temp_{stego_image.filename}"
    temp_path.parent.mkdir(parents=True, exist_ok=True)
    with open(temp_path, "wb") as handle:
        handle.write(stego_image.file.read())
    try:
        payload = extract_payload(temp_path.as_posix(), seed)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    finally:
        if temp_path.exists():
            temp_path.unlink()
    metadata = Metadata.from_payload(payload, kek_record["value"])
    if metadata.resource_id != resource_id:
        raise HTTPException(status_code=400, detail="Resource identifier mismatch")
    if not metadata.verify_hmac(kek_record["value"]):
        raise HTTPException(status_code=400, detail="Integrity verification failed")
    dek = unwrap_dek(metadata.wrapped_dek, kek_record["value"])
    metadata.phase = "extracted"
    metadata.update_hmac(kek_record["value"])
    save_metadata(metadata)
    secret_plaintext: Optional[str] = None
    if metadata.encrypted_secret_b64:
        encrypted_secret = base64.b64decode(metadata.encrypted_secret_b64.encode("utf-8"))
        secret_plaintext = aes_gcm_decrypt(dek, encrypted_secret).decode("utf-8")
    log_operation(
        "extract",
        metadata.key_id,
        operator,
        details={
            "resource_id": resource_id,
            "wrapped_dek_b64": metadata.wrapped_dek_b64,
            "secret_recovered": bool(secret_plaintext),
        },
    )
    return ExtractionResponse(
        key_id=metadata.key_id,
        dek_hex=dek.hex(),
        metadata=metadata,
        secret=secret_plaintext,
    )


@app.post("/rotate", response_model=RotationResponse)
def rotate(operator: str = Form(...)):
    global keystore_state
    kek_record = _require_kek()
    _, updated_entries, new_version = rotate_kek(kek_record["value"])
    keystore_state = load_keystore()
    for entry in updated_entries:
        log_operation("rewrap", entry["key_id"], operator, details=entry)
    log_operation(
        "rotate",
        "KEK",
        operator,
        details={"updated_keys": len(updated_entries), "version": new_version},
    )
    return RotationResponse(new_version=new_version, updated_keys=len(updated_entries))


@app.post("/revoke")
def revoke(req: ResourceRequest):
    revoke_key(req.resource_id)
    log_operation("revoke", req.resource_id, req.operator)
    return {"message": "Key revoked"}


@app.get("/audit", response_model=AuditChainStatus)
def audit():
    entries = load_audit_log()
    return AuditChainStatus(valid=verify_audit_chain(), entries=entries)


@app.get("/recover/{key_id}")
def recover(key_id: str):
    kek_record = _require_kek()
    dek = recover_key_from_audit(key_id, kek_record["value"])
    if dek is None:
        raise HTTPException(status_code=404, detail="Key not found in audit log")
    return {"key_id": key_id, "dek_hex": dek.hex()}
