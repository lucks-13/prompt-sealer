import hashlib
import hmac
import json
import os
import tempfile
import time
from pathlib import Path
from prompt_sealer.sealer import make_code_a, attach_code_b, unwrap_p_key, unseal_prompt

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
        if len(nonce) != 12 or len(ciphertext) < 16:
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

def write_atomic(source : Path, data : bytes) -> None:
    source.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{source.name}.", dir=source.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, source)
    except Exception:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass
        raise

def read_state(state_path : Path) -> dict:
    if not state_path.exists():
        return {}
    try:
        state = json.loads(state_path.read_bytes().decode("utf-8"))
        if not isinstance(state, dict):
            raise ValueError
        return state
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError):
        raise ValueError("Authorization state is invalid.") from None

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
    code_a_hash = hashlib.sha256(code_a.strip().upper().encode("utf-8")).hexdigest()
    if not hmac.compare_digest(code_a_hash, record["code_a_hash"]):
        raise ValueError("Invalid sealed prompt.")
    if record["wrapped_key"] is not None:
        raise ValueError("Prompt has already been authorized.")
    state = read_state(state_path)
    file_id_hex = file_id.hex()
    if file_id_hex in state:
        entry = state[file_id_hex]
        if (isinstance(entry, dict) and entry.get("used") is True):
            raise ValueError("Prompt access has already been used.")
        raise ValueError("Prompt has already been authorized.")
    code_b = make_code_b(code_a, prompt_key, file_id)
    sealed = attach_code_b(source.read_bytes(), prompt_key, code_b)
    state[file_id_hex] = {
        "code_b_hash" : hashlib.sha256(code_b.strip().upper().encode("utf-8")).hexdigest(),
        "expires" : record["expires"],
        "used" : False
    }
    sealed_b = source.read_bytes()
    state_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        write_atomic(source, sealed)
        write_atomic(state_path, json.dumps(state, sort_keys=True, separators=(",",":")).encode("utf-8"))
    except Exception:
        try:
            write_atomic(source, sealed_b)
        except Exception:
            pass
        state.pop(file_id_hex, None)
        raise
    return code_b

def redeem(source : Path, code_b : str, state_path : Path) -> bytes:
    record = read_sealed(source)
    file_id = record["file_id"]
    if not check_expire(record["expires"]):
        raise ValueError("Prompt file has expired.")
    if record["wrapped_key"] is None:
        raise ValueError("Prompt has not been authorized.")
    state = read_state(state_path)
    entry = state.get(file_id)
    if not isinstance(entry, dict):
        raise ValueError("No Authorization exists.")
    if not isinstance(entry.get("code_b_hash"), str) or len(entry["code_b_hash"]) != 64:
        raise ValueError("Authorization is invalid.")
    if not isinstance(entry.get("expires"), int):
        raise ValueError("Authorization is invalid.")
    if not isinstance(entry.get("used"), bool):
        raise ValueError("Authorization is invalid.")
    if entry["used"]:
        raise ValueError("Access code has already been used.")
    if int(time.time()) >= entry["expires"]:
        raise ValueError("Authorization has expired.")
    code_b_hash = hashlib.sha256(code_b.strip().upper().encode("utf-8")).hexdigest()
    if not hmac.compare_digest(code_b_hash, entry["code_b_hash"]):
        raise ValueError("Invalid access code.")
    wrap_key = bytes.fromhex(record["wrapped_key"])
    try:
        p_key = unwrap_p_key(wrap_key, code_b, bytes.fromhex(file_id))
        plaintext = unseal_prompt(source.read_bytes(), p_key)
    except (ValueError, TypeError):
        raise ValueError("Invalid access code.") from None
    old_state = state_path.read_bytes()
    old_source = source.read_bytes()
    entry["used"] = True
    record["wrapped_key"] = None
    consumed = json.dumps(record, sort_keys=True, separators=(",",":")).encode("utf-8")
    try:
        write_atomic(source, consumed)
        write_atomic(state_path, json.dumps(state, sort_keys=True, separators=(",",":")).encode("utf-8"))
    except Exception:
        try :
            write_atomic(source, old_source)
            write_atomic(state_path, old_state)
        except Exception:
            pass
        raise
    return plaintext