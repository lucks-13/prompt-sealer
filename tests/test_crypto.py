import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey, X25519PrivateKey
from prompt_sealer.crypto import generate_key, generate_nonce, encrypt_data, decrypt_data, generate_public_key, generate_private_key, generate_shared_secret, derive_encryption_key, serialize_public_key

def test_generate_public_key():
    private_key = generate_private_key()
    public_key = generate_public_key(private_key)
    assert isinstance(public_key, X25519PublicKey)

def test_generate_private_key():
    private_key = generate_private_key()
    assert isinstance(private_key, X25519PrivateKey)

def test_generate_shared_secret():
    private_1 = generate_private_key()
    public_1 = generate_public_key(private_1)
    
    private_2 = generate_private_key()
    public_2 = generate_public_key(private_2)

    secret_1 = generate_shared_secret(private_1, public_2)
    secret_2 = generate_shared_secret(private_2, public_1)
    
    assert secret_1 == secret_2
    assert len(secret_1) == 32
    assert len(secret_2) == 32

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
    nonce, ciphertext = encrypt_data(plaintext, key)
    assert ciphertext != plaintext

def test_encrypted_data_contains_authenication_tag():
    key = generate_key()
    plaintext = b"Hello Prompt Sealer"
    nonce, ciphertext = encrypt_data(plaintext, key)
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
    plaintext = b"Hello Prompt Sealer"
    nonce, ciphertext = encrypt_data(plaintext, key)
    with pytest.raises(InvalidTag):
        decrypt_data(ciphertext, dummy_key, nonce)

def test_decryption_with_tampered_ciphertext():
    key = generate_key()
    plaintext = b"Hello Prompt Sealer"
    nonce, ciphertext = encrypt_data(plaintext, key)
    tamper = (ciphertext[:-1] + bytes([ciphertext[-1] ^ 1]))
    with pytest.raises(InvalidTag):
        decrypt_data(tamper, key, nonce)

def test_encrypt_rejects_invalid_key_length():
    plaintext = b"Hello Prompt Sealer"
    key = b"short"
    with pytest.raises(ValueError):
        encrypt_data(plaintext, key)

def test_decrypt_rejects_invalid_nonce_length():
    key = generate_key()
    invalid_nonce = b"short"
    ciphertext = b"some ciphertext"
    with pytest.raises(ValueError):
        decrypt_data(ciphertext, key, invalid_nonce)

def test_encrpt_rejects_non_bytes_plaintext():
    key = generate_key()
    with pytest.raises(TypeError):
        encrypt_data("Hello Prompt Sealer", key)

def test_encrypt_decrypt_empty_plaintext():
    key = generate_key()
    plaintext = b""
    nonce, ciphertext = encrypt_data(plaintext, key)
    decrypted = decrypt_data(ciphertext, key, nonce)
    assert decrypted == plaintext

def test_encrypt_generates_different_nonces():
    key = generate_key()
    plaintext = b"Hello Prompt Sealer"
    nonce1, ciphertext1 = encrypt_data(plaintext, key)
    nonce2, ciphertext2 = encrypt_data(plaintext, key)
    assert nonce1 != nonce2

def test_derive_encryption_key():
    shared_secret = generate_key()
    encryption_key = derive_encryption_key(shared_secret)
    assert isinstance(encryption_key, bytes)
    assert len(encryption_key) == 32

def test_serialize_public_key():
    private_key = generate_private_key()
    public_key = generate_public_key(private_key)
    serialized = serialize_public_key(public_key)
    assert isinstance(serialized, bytes)
    assert len(serialized) == 32

def test_entire_flow():
    private_1 = generate_private_key()
    public_1 = generate_public_key(private_1)
        
    private_2 = generate_private_key()
    public_2 = generate_public_key(private_2)
    
    secret_1 = generate_shared_secret(private_1, public_2)
    secret_2 = generate_shared_secret(private_2, public_1)

    key_1 = derive_encryption_key(secret_1)
    key_2 = derive_encryption_key(secret_2)

    assert key_1 == key_2
    plaintext = b"Hello Prompt Sealer"
    nonce, ciphertext = encrypt_data(plaintext, key_1)
    decrypted_text = decrypt_data(ciphertext, key_2, nonce)
    assert decrypted_text == plaintext
