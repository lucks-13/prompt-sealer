from pathlib import Path

def read_prompt(location : Path) -> bytes:
    if not location.exists():
        raise FileNotFoundError("Prompt file does not exist.")
    if not location.is_file():
        raise ValueError("Prompt path must be a file.")
    if location.suffix.lower() not in {".txt", ".md"}:
        raise ValueError("Prompt file must be .txt or .md")
    return location.read_bytes()
