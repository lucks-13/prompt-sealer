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

def make_code_a