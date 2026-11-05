from pathlib import Path

def read_prompt(location : Path) -> bytes:
    if not location.exists():
        raise F