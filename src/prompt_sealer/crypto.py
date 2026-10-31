import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def generate_key() -> bytes:
    return secrets.token_bytes(32)

def generate_nonce() -> bytes:
    return secrets.token_bytes(12)

def encrypt_data(plaintext: bytes, key: bytes, nonce: bytes) -> tuple[bytes, bytes]:
    nonce = generate_nonce()
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce, ciphertext

def decrypt_data(ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce,ciphertext, None)
    return plaintext

