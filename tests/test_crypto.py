from prompt_sealer.crypto import generate_key, generate_nonce

def test_generate_key_length():
    key = generate_key()
    assert len(key) == 32

def test_generate_key_is_random():
    key1 = generate_key()
    key2 = generate_key()
    assert key1 != key2

def test_generate_key_returns_bytes():
    key = generate_key()
    assert isinstance(key, bytes)

def test_generate_nonce_length():
    nonce = generate_nonce()
    assert len(nonce) == 12

def test_generate_nonce_returns_bytes():
    nonce = generate_nonce()
    assert isinstance(nonce, bytes)

def test_generate_nonce_is_random():
    nonce1 = generate_nonce()
    nonce2 = generate_nonce()
    assert nonce1 != nonce2