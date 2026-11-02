import json
import win32crypt
import pywintypes
from pathlib import Path
from prompt_sealer.crypto import mint_pair, mint_stamp
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

def seal_blob(data : bytes) -> bytes:
    return win32crypt.CryptProtectData(data, "Prompt Sealer", None, None, None, 0)

def unlock_record(blob : bytes) -> bytes:
    try:
        result = win32crypt.CryptUnprotectData(blob, None, None, None, 0)
        return result[1]
    except pywintypes.error:
        raise ValueError("Unable to decrypt protected data.") from None

def tuck_away(vault_key : X25519PrivateKey) -> bytes:
    key_bytes = vault_key.private_bytes(encoding=Encoding.Raw, format=PrivateFormat.Raw, encryption_algorithm=NoEncryption())
    return seal_blob(key_bytes)

def unpack_token(saved_key : bytes) -> X25519PrivateKey:
    key = unlock_record(saved_key)
    return X25519PrivateKey.from_private_bytes(key)

def tuck_badge(private_key : Ed25519PrivateKey) -> bytes:
    key_data = private_key.private_bytes(encoding=Encoding.Raw, format=PrivateFormat.Raw, encryption_algorithm=NoEncryption())
    return seal_blob(key_data)

def bring_badge(blob : bytes) -> Ed25519PrivateKey:
    key_data = unlock_record(blob)
    return Ed25519PrivateKey.from_private_bytes(key_data)

def write_cache(data : bytes, path : Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)

def fetch_store (location : Path) -> bytes:
    if not location.exists():
        raise FileNotFoundError("Vault file does not exist.")
    return location.read_bytes()

def init_vault(location : Path) -> None:
    if location.exists()