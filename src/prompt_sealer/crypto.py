import secrets

def generate_key() -> bytes:
    return secrets.token_bytes(32)