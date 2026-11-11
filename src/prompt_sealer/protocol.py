import hashlib
import hmac
import json
import time
from pathlib import Path
from prompt_sealer.sealer import make_code_a, attach_code_b, derive_prompt_key, read_prompt, unwrap_p_key, unseal_prompt

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
            "code_a_hash",
            "bootstrap",
            "nonce",
            "ciphertext",
            "wrapped_key"
        }:
            raise ValueError
        if type(record["version"]) is not int or record["version"] != 1:
            raise ValueError
        if not isinstance(record["file_id"], str) or len(bytes.fromhex(record["file_id"])) != 32:
            raise ValueError
        if not isinstance(record["expires"], int) or record["expires"] <= 0:
            raise ValueError
        if not isinstance(record["challenge"], str)  or len(bytes.fromhex(record["challenge"])) != 32:
            raise ValueError
        if not isinstance(record["code_a_hash"], str) or len(record["code_a_hash"]) != 64:
            raise ValueError
        if not isinstance(record["bootstrap"], str) or not record["bootstrap"]:
            raise ValueError
        nonce = bytes.fromhex(record["nonce"])
        ciphertext = bytes.fromhex(record["ciphertext"])
        if len(nonce) != 12 or not ciphertext:
            raise ValueError
        if record["wrapped_key"] is not None:
            wrap_key = bytes.fromhex(record["wrapped_key"])
        if len(wrap_key) <= 12:
            raise ValueError
        return record
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError):
        raise ValueError("Prompt file is invalid.") from None

def make_code_b(code_a : str, machine : bytes, file_id : bytes) -> str:
    if not isinstance(code_a, str):
        raise TypeError("Code A must be a string.")
    if len(machine) != 32:
        raise ValueError("Machine secret must be exactly 32 bytes.")
    if len(file_id) != 32:
        raise ValueError("File ID must be exactly 32 bytes.")
    message = (
        b"prompt-sealer-code-b:"
        + code_a.strip().upper().encode("utf-8")
        + file_id    
    )
    value = hmac.new(machine, message, hashlib.sha256).hexdigest()[:32]
    return value.upper()

def check_expire(expires : int) -> bool:
    return int(time.time()) < expires

def verify_code_a (code_a : str, challenge : bytes) -> bool:
    exp_h = make_code_a(challenge)
    return hmac.compare_digest(code_a.strip().upper(), exp_h)

def authorize(source : Path, code_a : str, prompt_key : bytes, file_id : bytes, state_path : Path) -> str:
    if len(prompt_key) != 32:
        raise ValueError("Invalid prompt key.")
    if len(file_id) != 32:
        raise ValueError("Invalid File ID.")
    record = read_sealed(source)
    files_id = bytes.fromhex(record["file_id"])
    if not hmac.compare_digest(files_id, file_id):
        raise ValueError("Invalid sealed prompt.")
    if not check_expire(record["expires"]):
        raise ValueError("Prompt file has expired.")
    challenge = bytes.fromhex(record["challenge"])
    if not verify_code_a(code_a, challenge):
        raise ValueError("Invalid access code.")
    if record["wrapped_key"] is not None:
        raise ValueError("Prompt has already been authorized.")
    p_key = derive_prompt_key(prompt_key, file_id)
    code_b = make_code_b(code_a, prompt_key, file_id)
    sealed = attach_code_b(source.read_bytes(), p_key, code_b)
    source.write_bytes(sealed)
    state = {}
    if state_path.exists():
        try:
            state = json.loads(state_path.read_bytes().decode("utf-8"))
            if not isinstance(state,dict):
                raise ValueError
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
            raise ValueError("Authorization state is invalid.") from None
    state[file_id.hex()] = {
        "code_b_hash" : hash
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