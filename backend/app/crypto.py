import os
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)
from cryptography.hazmat.primitives.asymmetric import padding

def aes_gcm_encrypt(key: bytes, data: bytes) -> bytes:
    if len(key) not in (16, 24, 32):
        raise ValueError("AES-GCM key must be 128, 192, or 256 bits")
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    return nonce + aesgcm.encrypt(nonce, data, None)


def aes_gcm_decrypt(key: bytes, data: bytes) -> bytes:
    if len(key) not in (16, 24, 32):
        raise ValueError("AES-GCM key must be 128, 192, or 256 bits")
    nonce = data[:12]
    ciphertext = data[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


def hmac_generate(key: bytes, data: bytes) -> bytes:
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()


def hmac_verify(key: bytes, data: bytes, tag: bytes) -> bool:
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    try:
        h.verify(tag)
        return True
    except Exception:
        return False


def sign_data(private_key_pem: bytes, data: bytes) -> bytes:
    private_key = load_pem_private_key(private_key_pem, password=None)
    return private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


def verify_signature(public_key_pem: bytes, data: bytes, signature: bytes) -> bool:
    public_key = load_pem_public_key(public_key_pem)
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False
