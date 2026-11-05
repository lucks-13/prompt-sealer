import json
from pathlib import Path
from prompt_sealer.crypto import seal_text, unseal_text

def read_prompt(location : Path) -> bytes:
    if not location.exists():
        raise FileNotFoundError("Prompt file does not exist.")
    if not location.is_file():
        raise ValueError("Prompt path must be a file.")
    if location.suffix.lower() not in {".txt", ".md"}:
        raise ValueError("Prompt file must be .txt or .md")
    return location.read_bytes()

def seal_prompt(prompt : bytes, key : bytes) -> bytes:
    nonce, ciphertext = seal_text(prompt, key)
    record = {
        "nonce" : nonce.hex(),
        "ciphertext" : ciphertext.hex(),
    }
    return json.dumps(record).encode("utf-8")

def unseal_prompt(blob : bytes, key : bytes) -> bytes:
    try:
        record = json.loads(blob.decode("utf-8"))
        if not isinstance(record, dict):
            raise ValueError
        if set(record) != {"nonce", "ciphertext"}:
            raise ValueError
        nonce = bytes.fromhex(record["nonce"])
        ciphertext = bytes.fromhex(record["ciphertext"])
        return unseal_text(ciphertext, key, nonce)
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError):
        raise ValueError("Prompt file is invalid or cannot be decrypted.") from None

def seal_file(source : Path, dest : Path, key : bytes) -> None:
    prompt = read_prompt(source)
    sealed = seal_prompt(prompt, key)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(sealed)

def unseal_file(source : Path, dest : Path, key : bytes) -> None:
    if not source.exists():
        raise FileNotFoundError("Se")