import json
import win32crypt
import pywintypes
from pathlib import Path
from prompt_sealer.crypto import mint_stamp, roll_seed
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

def seal_blob(data : bytes) -> bytes:
    return win32crypt.CryptProtectData(data, "Prompt Sealer", None, None, None, 0)

def unlock_record(blob : bytes) -> bytes:
    try:
        return win32crypt.CryptUnprotectData(blob, None, None, None, 0)[1]
    except (pywintypes.error, TypeError, ValueError):
        raise ValueError("Unable to decrypt protected data.") from None

def tuck_badge(private_key : Ed25519PrivateKey) -> bytes:
    key_data = private_key.private_bytes(encoding=Encoding.Raw, format=PrivateFormat.Raw, encryption_algorithm=NoEncryption())
    return seal_blob(key_data)

def bring_badge(blob : bytes) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(unlock_record(blob))

def fetch_store (location : Path) -> bytes:
    if not location.exists():
        raise FileNotFoundError("Vault file does not exist.")
    return location.read_bytes()

def create_vault() -> bytes:
    sign_key = mint_stamp()
    machine_secret = roll_seed()
    vault_data = {
        "version" : 1,
        "signing_key" : tuck_badge(sign_key).hex(),
        "machine_secret" : seal_blob(machine_secret).hex()
    }
    return json.dumps(vault_data).encode("utf-8")

def init_vault(location : Path) -> None:
    if location.exists():
        raise FileExistsError("Vault already exists.")
    location.parent.mkdir(parents=True, exist_ok=True)
    location.write_bytes(create_vault())

def open_vault(location : Path) -> tuple[Ed25519PrivateKey, bytes]:
    try:
        data = json.loads(fetch_store(location).decode("utf-8"))
        if data["version"] != 1:
            raise ValueError
        sg_key = bytes.fromhex(data["signing_key"])
        machine_secret = unlock_record(bytes.fromhex(data["machine_secret"]))
        return bring_badge(sg_key), machine_secret
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError):
        raise ValueError("Vault is invalid or cannot be unlocked.") from None

def check_vault(location : Path) -> bool:
    open_vault(location)
    return True

def destroy_vault(location : Path) -> None:
    if not location.exists():
        raise FileNotFoundError("Vault file does not exist.")
    location.unlink()