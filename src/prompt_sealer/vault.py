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

def create_vault() -> bytes:
    en_key = mint_pair()
    sign_key = mint_stamp()
    p_en_key = tuck_away(en_key)
    p_sign_key = tuck_badge(sign_key)
    vault_data = {
        "encryption_key" : p_en_key.hex(),
        "signing_key" : p_sign_key.hex()
    }
    return json.dumps(vault_data).encode("utf-8")

def init_vault(location : Path) -> None:
    if location.exists():
        raise FileExistsError("Vault already exists.")
    vault_data = create_vault()
    write_cache(vault_data, location)

def open_vault(location : Path) -> tuple[X25519PrivateKey, Ed25519PrivateKey]:
    try:
        data = json.loads(fetch_store(location).decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError
        if set(data) != {"encryption_key", "signing_key"}:
            raise ValueError
        en_key = bytes.fromhex(data["encryption_key"])
        sg_key = bytes.fromhex(data["signing_key"])
        return unpack_token(en_key), bring_badge(sg_key)
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError):
        raise ValueError("Vault is invalid or cannot be unlocked.") from None

def check_vault(location : Path) -> bool:
    open_vault(location)
    return True

def destroy_vault(location : Path) -> None:
    if not location.exists():
        raise FileNotFoundError("Vault file does not exist.")
    location.unlink()


