import secrets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey, X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat



def generate_key() -> bytes:
    return secrets.token_bytes(32)

def generate_nonce() -> bytes:
    return secrets.token_bytes(12)

def generate_private_key() -> X25519PrivateKey:
     return X25519PrivateKey.generate()

def generate_public_key(private_key : X25519PrivateKey) -> X25519PublicKey:
     return private_key.public_key()

def generate_shared_secret(private_key : X25519PrivateKey, peer_public_key : X25519PublicKey) -> bytes:
     return private_key.exchange(peer_public_key)

def derive_encryption_key(shared_secret : bytes) -> bytes:
     hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"prompt-sealer-encryption")
     return hkdf.derive(shared_secret)



def encrypt_data(plaintext: bytes, key: bytes) -> tuple[bytes, bytes]:
    if len(key) != 32:
        raise ValueError("Encryption key must be exactly 32 bytes.")
    if not isinstance(plaintext, bytes):
        raise TypeError("Plain-Text must be bytes.")
    nonce = generate_nonce()
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce, ciphertext

def decrypt_data(ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
    if len(key) != 32:
            raise ValueError("Encryption key must be exactly 32 bytes.")
    if len(nonce) != 12:
            raise ValueError("Nonce must be exactly 12 bytes.")
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce,ciphertext, None)
    return plaintext

