import hashlib
import hmac
import json
import os
import tempfile
import time
from pathlib import Path
from prompt_sealer.sealer import make_code_a, unwrap_p_key, unseal_prompt
from prompt_sealer.crypto import check_mark

def read_sealed(source : Path) -> dict:
    if not source.exists():
        raise FileNotFoundError("Sealed prompt file does not exists.")
    try:
        record = json.loads(source.read_bytes().decode("utf-8"))
        if record["version"] != 1:
            raise ValueError
        return record
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError):
        raise ValueError("Prompt file is invalid.") from None
    
def make_code_b(machine : bytes, file_id : bytes) -> str:
    message = b"prompt-sealer-code-b:" + file_id
    return hmac.new(machine, message, hashlib.sha256).hexdigest()[:32].upper()

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
    
def authorize(source : Path, code_a : str, machine_secret : bytes, file_id : bytes, state_path : Path, signing_key) -> str:
    if len(machine_secret) != 32:
        raise ValueError("Invalid machine secret.")
    if len(file_id) != 32:
        raise ValueError("Invalid File ID.")
    record = read_sealed(source)
    s_record = dict(record)
    sign = bytes.fromhex(s_record.pop("signature"))
    s_data = json.dumps(s_record, sort_keys=True, separators=(",",":")).encode("utf-8")
    if not check_mark(signing_key.public_key(), sign, s_data):
        raise ValueError("Invalid sealed prompt")
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
    state = read_state(state_path)
    file_id_hex = file_id.hex()
    if file_id_hex in state:
        entry = state[file_id_hex]
        if (isinstance(entry, dict) and entry.get("used") is True):
            raise ValueError("Prompt access has already been used.")
        raise ValueError("Prompt has already been authorized.")
    code_b = make_code_b(machine_secret, file_id)
    state[file_id_hex] = {
        "code_b_hash" : hashlib.sha256(code_b.strip().upper().encode("utf-8")).hexdigest(),
        "expires" : record["expires"],
        "used" : False
    }
    state_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        write_atomic(state_path, json.dumps(state, sort_keys=True, separators=(",",":")).encode("utf-8"))
    except Exception:
        state.pop(file_id_hex, None)
        raise
    return code_b

def redeem(source : Path, code_b : str, state_path : Path) -> bytes:
    record = read_sealed(source)
    file_id = record["file_id"]
    if not check_expire(record["expires"]):
        raise ValueError("Prompt file has expired.")
    state = read_state(state_path)
    entry = state.get(file_id)
    if not isinstance(entry, dict):
        raise ValueError("No Authorization exists.")
    if entry["used"]:
        raise ValueError("Access code has already been used.")
    if int(time.time()) >= entry["expires"]:
        raise ValueError("Authorization has expired.")
    code_b_hash = hashlib.sha256(code_b.strip().upper().encode("utf-8")).hexdigest()
    if not hmac.compare_digest(code_b_hash, entry["code_b_hash"]):
        raise ValueError("Invalid access code.")
    wrap_key = bytes.fromhex(record["wrapped_key"])
    p_key = unwrap_p_key(wrap_key, code_b, bytes.fromhex(file_id))
    plaintext = unseal_prompt(source.read_bytes(), p_key)
    old_state = state_path.read_bytes() if state_path.exists() else b"{}"
    entry["used"] = True
    try:
        write_atomic(state_path, json.dumps(state, sort_keys=True, separators=(",",":")).encode("utf-8"))
    except Exception:
        try :
            write_atomic(state_path, old_state)
        except Exception:
            pass
        raise
    return plaintext