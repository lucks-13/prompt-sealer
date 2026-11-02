import win32crypt
import pywintypes
from pathlib import Path
import json
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from prompt_sealer.crypto import generate_signing_private_key, generate_private_key

def fresh_seed() -> bytes:
    return secrets.token_bytes(32)

def pull_stamp(stored_key : bytes) -> Ed25519PrivateKey:
    key = unprotect_data(stored_key)
    return Ed25519PrivateKey.from_private_bytes(key)

def protect_data(data : bytes) -> bytes:
    protected = win32crypt.CryptProtectData(data, "Prompt Sealer", None, None, None, 0)
    return protected

def expose_pair(private_key : X25519PrivateKey) -> X25519PublicKey:
    return private_key.public_key()

def restore_pair(stored_key : bytes) -> X25519PrivateKey:
    key = unprotect_data(stored_key)
    return X25519PrivateKey.from_private_bytes(key)

def fetch_cache(path : Path) -> bytes:
    if not path.exists():
        raise FileExistsError("Vault file does not exist.")
    return path.read_bytes()

def unprotect_data(data : bytes) -> bytes:
    try:
        result = win32crypt.CryptUnprotectData(data, None, None, None, 0)
        return result[1]
    except pywintypes.error:
        raise ValueError("Unable to decrypt protected data.") from None

def store_private_key(private_key : X25519PrivateKey) -> bytes:
    raw_key = private_key.private_bytes(encoding=Encoding.Raw, format=PrivateFormat.Raw, encryption_algorithm=NoEncryption())
    return protect_data(raw_key)

def load_private_key(stored_key : bytes) -> X25519PrivateKey:
    raw_key = unprotect_data(stored_key)
    return X25519PrivateKey.from_private_bytes(raw_key)

def save_vault(data : bytes, path : Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)

def store_signing_key(private_key : Ed25519PrivateKey) -> bytes:
    raw_key = private_key.private_bytes(encoding=Encoding.Raw, format=PrivateFormat.Raw, encryption_algorithm=NoEncryption())
    return protect_data(raw_key)

def open_blob(blob : bytes) -> bytes:
    try:
        result = win32crypt.CryptUnprotectData(blob, None, None, None, 0)
        return result[1]
    except pywintypes.error:
        raise ValueError("Unable to decrypt protection data.") from None

def load_signing_key(stored_key : bytes) -> Ed25519PrivateKey:
    raw_key = unprotect_data(stored_key)
    return Ed25519PrivateKey.from_private_bytes(raw_key)

def stash_mark(private_key : Ed25519PrivateKey) -> bytes:
    key = private_key.private_bytes(encoding=Encoding.Raw, format=PrivateFormat.Raw, encryption_algorithm=NoEncryption())
    return protect_data(key)

def stash_badge(private_key : Ed25519PrivateKey) -> bytes:
    key_bytes = private_key.private_bytes(encoding=Encoding.Raw)

def seal_blob(data : bytes) -> bytes:
    return win32crypt.CryptProtectData(data, "Prompt Sealer", None, None, None, 0)

