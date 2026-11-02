import win32crypt
import pywintypes
from pathlib import Path
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

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

def tag_message(stamp : Ed25519PrivateKey, note : bytes) -> bytes:
    return stamp.sign(note)

def bring_badge(blob : bytes) -> Ed25519PrivateKey:
    key_data = unlock_record(blob)
    return Ed25519PrivateKey.from_private_bytes(key_data)

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

def audit_mark(badge : Ed25519PrivateKey, signature : bytes, payload : bytes) -> bool:
    try:
        badge.verify(signature, payload)
        return True
    except InvalidSignature:
        return False

def scan_store(path : Path) -> bytes:
    if not path.exists():
        raise FileNotFoundError("Vault file does not exist.")
    return path.read_bytes()

def open_blob(blob : bytes) -> bytes:
    try:
        result = win32crypt.CryptUnprotectData(blob, None, None, None, 0)
        return result[1]
    except pywintypes.error:
        raise ValueError("Unable to decrypt protection data.") from None

def fetch_badge(stored_key : bytes) -> Ed25519PrivateKey:
    key_bytes = unprotect_data(stored_key)
    return Ed25519PrivateKey.from_private_bytes(key_bytes)



def stash_mark(private_key : Ed25519PrivateKey) -> bytes:
    key = private_key.private_bytes(encoding=Encoding.Raw, format=PrivateFormat.Raw, encryption_algorithm=NoEncryption())
    return protect_data(key)

def stash_badge(private_key : Ed25519PrivateKey) -> bytes:
    key_bytes = private_key.private_bytes(encoding=Encoding.Raw, format=PrivateFormat.Raw, encryption_algorithm=NoEncryption())
    return seal_blob(key_bytes)

def seal_blob(data : bytes) -> bytes:
    return win32crypt.CryptProtectData(data, "Prompt Sealer", None, None, None, 0)

def write_store(payload : bytes, location : Path) -> None:
    location.parent.mkdir(parents=True, exist_ok=True)
    location.write_bytes(payload)

def hide_token(token : X25519PrivateKey) -> bytes:
    return seal_blob(key_data)

def tuck_away(private_key : X25519PrivateKey) -> bytes:
    key_bytes = private_key.private_bytes(encoding=Encoding.Raw, format=PrivateFormat.Raw, encryption_algorithm=NoEncryption())
    return seal_blob(key_bytes)

def unlock_record(blob : bytes) -> bytes:
    try:
        result = win32crypt.CryptUnprotectData(blob, None, None, None, 0)
        return result[1]
    except pywintypes.error:
        raise ValueError("Unable to decrypt protected data.") from None

def write_cache(data : bytes, path : Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def tuck_badge(private_key : Ed25519PrivateKey) -> bytes:
    key_data = private_key.private_bytes(encoding=Encoding.Raw, format=PrivateFormat.Raw, encryption_algorithm=NoEncryption())
    return seal_blob(key_data)

def show_badge(stamp : Ed25519PrivateKey) -> Ed25519PublicKey:
    return stamp.public_key()

def fetch_store (location : Path) -> bytes:
    if not location.exists():
        raise FileNotFoundError("Vault file does not exist.")
    return location.read_bytes()