import base64
import json
import secrets
from datetime import datetime
from pathlib import Path

import typer

from app import key_management
from app.audit import load_audit_log, log_operation, recover_key_from_audit, verify_audit_chain
from app.crypto import aes_gcm_decrypt, aes_gcm_encrypt
from app.models import Metadata
from app.steganography import calculate_seed, embed_payload, extract_payload

cli = typer.Typer(help="Secure key management CLI")


def _ensure_kek() -> dict:
    store = key_management.load_keystore()
    if "kek" not in store:
        typer.echo("KEK is not provisioned. Run provision command first.")
        raise typer.Exit(code=1)
    return store["kek"]


def _load_metadata_by_key_id(key_id: str) -> tuple[Metadata, Path]:
    if not key_management.METADATA_DIR.exists():
        typer.echo("No metadata directory found.")
        raise typer.Exit(code=1)
    for path in key_management.METADATA_DIR.glob("*.json"):
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        metadata = Metadata(**payload)
        if metadata.key_id == key_id:
            return metadata, path
    typer.echo(f"Metadata for key {key_id} not found." )
    raise typer.Exit(code=1)


def _load_metadata_by_resource(resource_id: str) -> tuple[Metadata, Path]:
    path = key_management.metadata_path(resource_id)
    if not path.exists():
        typer.echo(f"Metadata for resource {resource_id} not found.")
        raise typer.Exit(code=1)
    with open(path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)
    return Metadata(**payload), path


@cli.command()
def provision(operator: str = typer.Option(..., help="Operator issuing the KEK")):
    password = typer.prompt("Enter operator password", hide_input=True, confirmation_prompt=True)
    key_management.generate_kek(password)
    log_operation("provision", "KEK", operator)
    typer.echo("KEK provisioned successfully.")


@cli.command()
def generate_key(
    resource: str = typer.Option(..., help="Resource identifier"),
    operator: str = typer.Option(..., help="Operator name"),
    secret: str = typer.Option(
        "",
        "--secret",
        help="Optional plaintext secret to encrypt with the generated DEK",
    ),
):
    kek_record = _ensure_kek()
    dek = key_management.generate_dek()
    key_id = f"DEK-{secrets.token_hex(4).upper()}"
    wrapped = key_management.wrap_dek(dek, kek_record["value"])
    metadata = Metadata(
        key_id=key_id,
        resource_id=resource,
        created_at=datetime.utcnow().isoformat() + "Z",
        phase="generated",
        kek_version=kek_record["version"],
        wrapped_dek_b64="",
    )
    metadata.set_wrapped_dek(wrapped)
    secret_text = secret.strip()
    if secret_text:
        encrypted_secret = aes_gcm_encrypt(dek, secret_text.encode("utf-8"))
        metadata.encrypted_secret_b64 = base64.b64encode(encrypted_secret).decode("utf-8")
    metadata.update_hmac(kek_record["value"])
    key_management.save_metadata(metadata)
    log_operation(
        "generate",
        key_id,
        operator,
        details={
            "resource_id": resource,
            "wrapped_dek_b64": metadata.wrapped_dek_b64,
            "has_secret": bool(metadata.encrypted_secret_b64),
        },
    )
    typer.echo(f"Generated DEK {key_id} for resource {resource}.")
    if secret_text:
        typer.echo("Secret encrypted and stored with metadata.")


@cli.command()
def embed_key(
    dek: str = typer.Option(..., help="Key identifier"),
    cover: Path = typer.Option(..., exists=True, readable=True, help="Cover PNG path"),
    operator: str = typer.Option(..., help="Operator name"),
):
    kek_record = _ensure_kek()
    metadata, path = _load_metadata_by_key_id(dek)
    seed = calculate_seed(kek_record["value"], metadata.resource_id)
    payload = metadata.to_payload(kek_record["value"])
    try:
        stego_path = embed_payload(str(cover), payload, seed)
    except ValueError as exc:
        typer.echo(f"Embedding failed: {exc}")
        raise typer.Exit(code=1)
    metadata.phase = "embedded"
    metadata.update_hmac(kek_record["value"])
    key_management.save_metadata(metadata)
    log_operation(
        "embed",
        metadata.key_id,
        operator,
        details={"resource_id": metadata.resource_id, "stego_filename": Path(stego_path).name},
    )
    typer.echo(f"Embedded payload into {stego_path}.")


@cli.command()
def extract_key(
    resource: str = typer.Option(..., help="Resource identifier"),
    stego: Path = typer.Option(..., exists=True, readable=True, help="Stego PNG path"),
    operator: str = typer.Option(..., help="Operator name"),
):
    kek_record = _ensure_kek()
    seed = calculate_seed(kek_record["value"], resource)
    try:
        payload = extract_payload(str(stego), seed)
    except ValueError as exc:
        typer.echo(f"Extraction failed: {exc}")
        raise typer.Exit(code=1)
    metadata = Metadata.from_payload(payload, kek_record["value"])
    if metadata.resource_id != resource:
        typer.echo("Resource mismatch detected.")
        raise typer.Exit(code=1)
    if not metadata.verify_hmac(kek_record["value"]):
        typer.echo("Metadata integrity check failed.")
        raise typer.Exit(code=1)
    dek = key_management.unwrap_dek(metadata.wrapped_dek, kek_record["value"])
    metadata.phase = "extracted"
    metadata.update_hmac(kek_record["value"])
    key_management.save_metadata(metadata)
    log_operation(
        "extract",
        metadata.key_id,
        operator,
        details={
            "resource_id": resource,
            "wrapped_dek_b64": metadata.wrapped_dek_b64,
            "secret_recovered": bool(metadata.encrypted_secret_b64),
        },
    )
    typer.echo(f"DEK for {resource}: {dek.hex()}")
    if metadata.encrypted_secret_b64:
        encrypted_secret = base64.b64decode(metadata.encrypted_secret_b64.encode("utf-8"))
        secret_plaintext = aes_gcm_decrypt(dek, encrypted_secret).decode("utf-8")
        typer.echo(f"Decrypted secret: {secret_plaintext}")


@cli.command(name="rotate-kek")
def rotate_kek(operator: str = typer.Option(..., help="Operator name")):
    kek_record = _ensure_kek()
    _, updated_entries, version = key_management.rotate_kek(kek_record["value"])
    for entry in updated_entries:
        log_operation("rewrap", entry["key_id"], operator, details=entry)
    log_operation(
        "rotate",
        "KEK",
        operator,
        details={"updated_keys": len(updated_entries), "version": version},
    )
    typer.echo(f"KEK rotated to version {version}. Updated {len(updated_entries)} keys.")


@cli.command()
def view_audit():
    entries = load_audit_log()
    if not entries:
        typer.echo("No audit entries available.")
        return
    valid = verify_audit_chain()
    typer.echo(f"Audit chain valid: {valid}")
    for entry in entries:
        typer.echo(json.dumps(entry.dict(), indent=2))


@cli.command()
def recover_key(
    key_id: str = typer.Option(..., help="Key identifier"),
):
    kek_record = _ensure_kek()
    dek = recover_key_from_audit(key_id, kek_record["value"])
    if dek is None:
        typer.echo("No recovery data available for key.")
        raise typer.Exit(code=1)
    typer.echo(f"Recovered key {key_id}: {dek.hex()}")


if __name__ == "__main__":
    cli()
