import hashlib
import hmac
import json
import secrets
import time
from pathlib import Path
from prompt_sealer.crypto import forge_lock
from prompt_sealer.sealer import derive_prompt_key, unseal_prompt

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
        if not isinstance(record["file_id"], str) or len(bytes.fromhex(record["file_id"])) != 32:
            raise ValueError
        if not isinstance(record["expires"], int):
            raise ValueError
        if not isinstance(record["challenge"], str)  or len(bytes.fromhex(record["challenge"])) != 32:
            raise ValueError
        if len(bytes.fromhex(record["nonce"])) != 12:
            raise ValueError
        if not bytes.fromhex(record["ciphertext"]):
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
    return hmac.compare_digest(code.strip().upper(), excepted)

def make_code_b() -> str:
    return secrets.token_hex(16).upper()

def check_expire(expires : int) -> bool:
    return int(time.time()) < expires

def authorize(source : Path, machine_secret : bytes, code_a : str, state_path : Path) -> str:
    record = read_sealed(source)
    file_id = bytes.fromhex(record["file_id"])
    challenge = bytes.fromhex(record["challenge"])
    if not check_expire(record["expires"]):
        raise ValueError("Prompt file has expired.")
    if not verify_code_a(machine_secret, file_id, challenge, code_a):
        raise ValueError("Invalid access code.")
    code_b = make_code_b()
    state = {}
    if state_path.exists():
        try:
            state = json.loads(state_path.read_bytes().decode("utf-8"))
            if not isinstance(state,dict):
                raise ValueError
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, V)
    state[file_id.hex()] = {
        "code_b" : code_b,
        "expires" : record["expires"],
        "used" : False,
    }
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_bytes(json.dumps(state, separators=(",", ":")).encode("utf-8"))
    return code_b

def redeem(source : Path, machine_secret : bytes, code_b : str, state_path : Path) -> bytes:
    record = read_sealed(source)
    file_id = record["file_id"]
    if not check_expire(record["expires"]):
        raise ValueError("Prompt file has expired.")
    if not state_path.exists():
        raise ValueError("No authorization exists.")
    try:
        state = json.loads(state_path.read_bytes().decode("utf-8"))
        entry = state[file_id]
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError):
        raise ValueError("No authorization exists.") from None
    if entry["used"]:
        raise ValueError("Access code has already been used.")
    if int(time.time()) >= entry["expires"]:
        raise ValueError("Authorization has expired.")
    if not hmac.compare_digest(code_b.strip().upper(), entry["code_b"]):
        raise ValueError("Invalid access code.")
    key = derive_prompt_key(machine_secret, bytes.fromhex(file_id))
    plaintext = unseal_prompt(source.read_bytes(), key)
    entry["used"] = True
    state_path.write_bytes(json.dumps(state, separators=(",",":")).encode("utf-8"))
    return plaintext