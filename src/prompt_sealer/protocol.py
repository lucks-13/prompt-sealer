import hmac
import hashlib
import json
import secrets
import time
from pathlib import Path
from prompt_sealer.sealer import unseal_prompt

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
        if record["version"] != 2:
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

def make_code_a() -> str:
    return secrets.token_hex(6).upper()

def make_code_b() -> str:
    return secrets.token_hex(16).upper()

def check_expire(expires : int) -> bool:
    return int(time.time()) < expires

def verify_code_a (code_a : str, exp_h : str) -> bool:
    val = hashlib.sha256(code_a.strip().upper().encode("utf-8")).hexdigest()
    return hmac.compare_digest(val, exp_h)

def authorize(source : Path, code_a : str, prompt_key : bytes, state_path : Path) -> str:
    if len(prompt_key) != 32:
        raise ValueError("Invalid prompt key.")
    record = read_sealed(source)
    file_id = bytes.fromhex(record["file_id"])
    if not check_expire(record["expires"]):
        raise ValueError("Prompt file has expired.")
    if not code_a.strip():
        raise ValueError("Access code is required.")
    code_b = make_code_b()
    state = {}
    if state_path.exists():
        try:
            state = json.loads(state_path.read_bytes().decode("utf-8"))
            if not isinstance(state,dict):
                raise ValueError
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
            raise ValueError("Authorization state is invalid.") from None
    state[file_id.hex()] = {
        "code_a" : code_a.strip().upper(),
        "code_b" : code_b,
        "prompt_key" : prompt_key.hex(),
        "expires" : record["expires"],
        "used" : False,
    }
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_bytes(json.dumps(state, separators=(",", ":")).encode("utf-8"))
    return code_b

def redeem(source : Path, code_b : str, state_path : Path) -> bytes:
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
    if not isinstance(entry, dict):
        raise ValueError("Authorization is invalid.")
    if not isinstance(entry.get("code_b"), str) or not isinstance(entry.get("expires"), int):
        raise ValueError("Authorization is invalid.")
    if not isinstance(entry.get("prompt_key"), (str, type(None))):
        raise ValueError("Authorization is invalid.")
    if not isinstance(entry.get("used"), bool):
        raise ValueError("Authorization is invalid.")
    if entry["used"]:
        raise ValueError("Access code has already been used.")
    if int(time.time()) >= entry["expires"]:
        raise ValueError("Authorization has expired.")
    if not hmac.compare_digest(code_b.strip().upper(), entry["code_b"]):
        raise ValueError("Invalid access code.")
    try:
        key = bytes.fromhex(entry["prompt_key"])
    except ValueError:
        raise ValueError("Authorization is invalid.") from None
    if len(key) != 32:
        raise ValueError("Authorization is invalid.")
    plaintext = unseal_prompt(source.read_bytes(), key)
    entry["used"] = True
    entry["prompt_key"] = None
    state_path.write_bytes(json.dumps(state, separators=(",",":")).encode("utf-8"))
    return plaintext