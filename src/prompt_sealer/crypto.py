import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def generate_key() -> bytes:
    return secrets.token_bytes(32)

def generate_nonce() -> bytes:
    return secrets.token_bytes(12)

def encrypt_data(plaintext: bytes, nonce: bytes) -> bytes:
    aesgcm = AESGCM(key)