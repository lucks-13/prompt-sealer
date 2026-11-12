import secrets
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey, X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey, Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

def roll_seed() -> bytes:
    return secrets.token_bytes(32)

def nonce_seed() -> bytes:
     return secrets.token_bytes(12)

def mint_pair() -> X25519PrivateKey:
     return X25519PrivateKey.generate()

def expose_token(seed : X25519PrivateKey) -> X25519PublicKey:
    return seed.public_key()

def blend_secret(vault_key : X25519PrivateKey, peer : X25519PublicKey) -> bytes:
    return vault_key.exchange(peer)

def forge_lock(bridge : bytes, grain : bytes | None, label : bytes) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=grain, info=label)
    return hkdf.derive(bridge)

def pack_remote(badge : X25519PublicKey) -> bytes:
    return badge.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)

def read_remote(raw_key : bytes) -> X25519PublicKey:
    if len(raw_key) != 32:
        raise ValueError("X25519 public key must be exactly 32 bytes.")
    return X25519PublicKey.from_public_bytes(raw_key)

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