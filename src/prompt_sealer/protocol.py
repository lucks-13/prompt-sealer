import hashlib
import json
import time
from pathlib import Path
from prompt_sealer.crypto import forge_lock

def read_sealed(source : Path) -> dict:
    if not source.exists():
        raise FileNotFoundError("Sealed prompt file does not exists.")
    if not source.is_file():
        raise ValueError("Sealed prompt path must be a file.")
    try:
        record = json.loads(source.read_bytes().decode("utf-8"))
        if not isinstance(record, dict):
            raise ValueError
        if set(record) != {
            "version",
            "file_id",
            "expires",
            "challenge",
            "nonce",
            "ciphertext"
        }:
            raise ValueError
        if record["version"] != 1:
            raise ValueError
        if not isinstance(record["file_id"], str):
            raise ValueError
        if not isinstance(record["expires"], int):
            raise ValueError
        if not isinstance(record["challenge"], str):
            raise ValueError
        bytes.fromhex(record["file_id"])
        bytes.fromhex(record["challenge"])
        bytes.fromhex(record["nonce"])
        bytes.fromhex(record["ciphertext"])

        return record
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError):
        raise ValueError("Prompt file is invalid.") from None

def make_code_a(machine_secret : bytes, file_id : bytes, challenge : bytes) -> str:
    proof = forge_lock(machine_secret, file_id, b"prompt-sealer-code-a")
    data = proof + challenge
    return hashlib.sha256(data).hexdigest()[:12].upper()

def verify_code_a(machine_secret : bytes, file_id : bytes, challenge : bytes, code : str) -> bool:
    excepted = make_code_a(machine_secret, file_id, challenge)
    return code.strip().upper() == excepted

def make_code_b(machine_secret : bytes, file_id : bytes, challenge : bytes) -> str:
    proof = forge_lock(machine_secret, file_id, b"prompt-sealer-code-b")
    data = proof + challenge
    return hashlib.sha256(data).hexdigest()[:12].upper()

def check_expire(expires : int) -> bool:
    return int(time.time()) < expires

def authorize(source : Path, machine_secret : bytes, code_a : str) -> str:
    record = read_sealed(source)
    file_id = bytes.fromhex(record["file_id"])
    challenge = bytes.fromhex(record["challenge"])
    if not check_expire(record["expires"]):
        raise ValueError("Prompt file has expired.")
    if not verify_code_a(machine_secret, file_id, challenge, code_a):
        raise ValueError("Invalid access code.")
    return make_code_b(machine_secret, file_id, challenge)