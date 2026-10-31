import pytest
from cryptography.exceptions import InvalidTag
from prompt_sealer.crypto import generate_key, generate_nonce, encrypt_data, decrypt_data

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

def test_encrypt_data_returns_bytes():
    key = generate_key()
    plaintext = b"Hello Prompt Sealer"
    nonce, ciphertext = encrypt_data(plaintext, key)
    assert isinstance(nonce, bytes)
    assert isinstance(ciphertext, bytes)

def test_encrypted_data_is_different():
    key = generate_key()
    plaintext = b"Hello Prompt Sealer"
    nonceciphertext = encrypt_data(plaintext, key, nonce)
    assert ciphertext != plaintext

def test_encrypted_data_contains_authenication_tag():
    key = generate_key()
    nonce = generate_nonce()
    plaintext = b"Hello Prompt Sealer"
    ciphertext = encrypt_data(plaintext, key, nonce)
    assert len(ciphertext) == len(plaintext) + 16

def test_encrypt_and_decrypt():
    key = generate_key()
    plaintext = b"Hello Prompt Sealer"
    nonce, ciphertext = encrypt_data(plaintext, key)
    decrypted = decrypt_data(ciphertext, key, nonce)
    assert decrypted == plaintext

def test_decryption_with_wrong_key():
    key = generate_key()
    dummy_key = generate_key()
    nonce = generate_nonce()
    plaintext = b"Hello Prompt Sealer"
    ciphertext = encrypt_data(plaintext, key, nonce)
    with pytest.raises(InvalidTag):
        decrypt_data(ciphertext, dummy_key, nonce)

def test_decryption_with_tampered_ciphertext():
    key = generate_key()
    nonce = generate_nonce()
    plaintext = b"Hello Prompt Sealer"
    ciphertext = encrypt_data(plaintext, key, nonce)
    tamper = (ciphertext[:-1] + bytes([ciphertext[-1] ^ 1]))
    with pytest.raises(InvalidTag):
        decrypt_data(tamper, key, nonce)
