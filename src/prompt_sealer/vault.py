import win32crypt
import pywintypes
from pathlib import Path
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

def protect_data(data : bytes) -> bytes:
    protected = win32crypt.CryptProtectData(data, "Prompt Sealer", None, None, None, 0)
    return protected

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
    path.

