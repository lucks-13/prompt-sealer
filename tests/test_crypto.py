from prompt_sealer.crypto import generate_key

def test_generate_key_length():
    key = generate_key()
    assert len(key) == 32

def test_generate_key_is_random():
    key1 = generate_key()
    key2 = generate_key()
    assert key1 != key2

def test_generate_key_returns_byte