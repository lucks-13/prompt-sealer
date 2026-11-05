import json
from pathlib import Path
from prompt_sealer.crypto import seal_text, unseal_text
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

def read_prompt(location : Path) -> bytes:
    if not location.exists():
        raise FileNotFoundError("Prompt file does not exist.")
    if not location.is_file():
        raise ValueError("Prompt path must be a file.")
    if location.suffix.lower() not in {".txt", ".md"}:
        raise ValueError("Prompt file must be .txt or .md")
    return location.read_bytes()

def derive_prompt_key(machine_secret : bytes, file_id : bytes) -> bytes:
    if len(machine_secret) != 32 or len(file_id) != 32:
        raise ValueError("Machine secret and file ID must be exactly 32 bytes.")
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=file_id, info=b"prompt-sealer-prompt-key").derive(machine_secret)

def seal_prompt(prompt : bytes, key : bytes, file_id : bytes, expires : int, challenge : bytes) -> bytes:
    if len(file_id) != 32:
        raise ValueError("File ID must be exactly 32 bytes.")
    if len(challenge) != 32:
        raise ValueError("Challenge must be exactly 32 bytes.")
    if type(expires) is not int or expires <= 0:
        raise ValueError("Invalid expiration timestamp.")
    extra = json.dumps(
        {
            "version" : 1,
            "field_id" : file_id.hex(),
            "expires" : expires,
            "challenge" : challenge.hex(),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    nonce, ciphertext = seal_text(prompt, key, extra)
    record = {
        "version" : 1,
        "file_id" : file_id.hex(),
        "expires" : expires,
        "challenge" : challenge.hex(),
        "nonce" : nonce.hex(),
        "ciphertext" : ciphertext.hex(),
    }
    return json.dumps(record).encode("utf-8")

def unseal_prompt(blob : bytes, key : bytes) -> bytes:
    try:
        record = json.loads(blob.decode("utf-8"))
        if not isinstance(record, dict):
            raise ValueError
        if set(record) != {"version", "file_id", "expires", "challenge", "nonce", "ciphertext"}:
            raise ValueError
        if record["version"] != 1 or type(record["version"] is not int):
            raise ValueError
        if not isinstance(record["file_id"], str) or len(bytes.fromhex(record["file_id"])) != 32:
            raise ValueError
        if type(record["expires"]) is not int or record["expires"] <= 0:
            raise ValueError
        if not isinstance(record["challenge"], str) or len(bytes.fromhex(record["challenge"])) != 32:
            raise ValueError
        nonce = bytes.fromhex(record["nonce"])
        ciphertext = bytes.fromhex(record["ciphertext"])
        extra = json.dumps(
            {
                "version" : record["version"],
                "file_id" : record["file_id"],
                "expires" : record["expires"],
                "challenge" : record["challenge"]
            },
            sort_keys=True,
            separators=(",", ":")
        ).encode("utf-8")

        return unseal_text(ciphertext, key, nonce, extra)
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError):
        raise ValueError("Prompt file is invalid or cannot be decrypted.") from None

def seal_file(source : Path, dest : Path, key : bytes, file_id : bytes, expires : int, challenge : bytes) -> None:
    prompt = read_prompt(source)
    sealed = seal_prompt(prompt, key, file_id, expires, challenge)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(sealed)

def unseal_file(source : Path, dest : Path, key : bytes) -> None:
    if not source.exists():
        raise FileNotFoundError("Sealed prompt file does not exist.")
    if not source.is_file():
        raise ValueError("Sealed prompt path must be a file.")
    prompt = unseal_prompt(source.read_bytes(), key)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(prompt)

