import secrets
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey, Ed25519PrivateKey

def roll_seed() -> bytes:
    return secrets.token_bytes(32)

def nonce_seed() -> bytes:
     return secrets.token_bytes(12)

def mint_stamp() -> Ed25519PrivateKey:
     return Ed25519PrivateKey.generate()

def reveal_badge(stamp_key : Ed25519PrivateKey) -> Ed25519PublicKey:
    return stamp_key.public_key()

def stamp_note(stamp_key : Ed25519PrivateKey, note : bytes) -> bytes:
    return stamp_key.sign(note)

def check_mark(badge : Ed25519PublicKey, mark : bytes, note : bytes) -> bool:
    try:
        badge.verify(mark, note)
        return True
    except InvalidSignature:
         return False

def seal_text(raw_note : bytes, lock_key : bytes, extra : bytes | None = None) -> tuple[bytes, bytes]:
    if len(lock_key) != 32:
        raise ValueError("Encryption key must be exactly 32 bytes.")
    if not isinstance(raw_note, bytes):
        raise TypeError("Plain-Text must be bytes.")
    iv = nonce_seed()
    box = AESGCM(lock_key).encrypt(iv, raw_note, extra)
    return iv, box

def unseal_text(ciphertext: bytes, key: bytes, nonce: bytes, extra : bytes | None = None) -> bytes:
    if len(key) != 32:
            raise ValueError("Encryption key must be exactly 32 bytes.")
    if len(nonce) != 12:
            raise ValueError("Nonce must be exactly 12 bytes.")
    try:
        plaintext = AESGCM(key).decrypt(nonce,ciphertext, extra)
    except InvalidTag:
         raise ValueError("Invalid Data cannot be decrypted")
    return plaintext