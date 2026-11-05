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

