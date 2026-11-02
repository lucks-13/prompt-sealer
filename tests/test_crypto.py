import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey, X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey, Ed25519PrivateKey
from prompt_sealer.crypto import roll_seed, nonce_seed, mint_pair, expose_token, blend_secret, forge_lock, pack_remote, read_remote, mint_stamp, reveal_badge, stamp_note, check_mark, seal_text, unseal_text

def test_roll_seed():
    key = roll_seed()
    assert isinstance(key, bytes)
    assert len(key) == 32

def test_nonce_seed():
    key = nonce_seed()
    assert isinstance(key, bytes)
    assert len(key) == 12

def test_mint_pair():
    private_key = mint_pair()
    assert isinstance(private_key, X25519PrivateKey)

def test_expose_token():
    private_key = mint_pair()
    public_key = expose_token(private_key)
    assert isinstance(public_key, X25519PublicKey)

def test_blend_secret():
    private_1 = mint_pair()
    public_1 = expose_token(private_1)
    
    private_2 = mint_pair()
    public_2 = expose_token(private_2)

    secret_1 = blend_secret(private_1, public_2)
    secret_2 = blend_secret(private_2, public_1)
    
    assert secret_1 == secret_2
    assert len(secret_1) == 32
    assert len(secret_2) == 32

def test_forge_lock():
    shared_secret = roll_seed()
    salt = roll_seed()
    encryption_key = forge_lock(shared_secret, salt)
    assert isinstance(encryption_key, bytes)
    assert len(encryption_key) == 32

def test_pack_remote():
    public_key = expose_token(mint_pair())
    serialized = pack_remote(public_key)
    assert isinstance(serialized, bytes)
    assert len(serialized) == 32

def test_read_remote():
    public_key = expose_token(mint_pair())
    serialize = pack_remote(public_key)
    deserialize = read_remote(serialize)
    assert isinstance(deserialize, X25519PublicKey)
    assert deserialize == public_key

def test_read_remote_reject_invalid_length():
    with pytest.raises(ValueError):
        read_remote(b"key")

def test_mint_stamp():
    key = mint_stamp()
    assert isinstance(key, Ed25519PrivateKey)

def test_reveal_badge():
    private_key = mint_stamp()
    public_key = reveal_badge(private_key)
    assert isinstance(public_key, Ed25519PublicKey)

def test_stamp_note():
    private_key = mint_stamp()
    sign = stamp_note(private_key,b"Hello Prompt Sealer")
    assert isinstance(sign, bytes)

def test_valid_signature():
    private_key = mint_stamp()
    public_key = reveal_badge(private_key)
    message = b"Hello Prompt Sealer"
    signature = stamp_note(private_key, message)
    assert check_mark(public_key, signature, message) is True

def test_modified_message_signature():
    private_key = mint_stamp()
    public_key  = reveal_badge(private_key)
    message = b"Hello Prompt Sealer"
    sign = stamp_note(private_key, message)
    modified_message = b"Hello Prompt Sealer, Modified"
    assert check_mark(public_key, sign, modified_message) is False

def test_signature_with_wrong_public_key():
    private_key = mint_stamp()
    wrong_private_key = mint_stamp()

    public_key = reveal_badge(private_key)
    wrong_public_key = reveal_badge(wrong_private_key)

    message = b"Hello Prompt Sealer"
    sign = stamp_note(private_key, message)
    assert check_mark(wrong_public_key, sign, message) is False

def test_seal_test():
    key = roll_seed()
    plaintext = b"Hello Prompt Sealer"
    nonce, ciphertext = seal_text(plaintext, key)
    assert isinstance(nonce, bytes)
    assert isinstance(ciphertext, bytes)
    assert len(nonce) == 12
    assert len(ciphertext) == len(plaintext) + 16

def test_unseal_text():
    key = roll_seed()
    plaintext = b"Hello Prompt Sealer"
    nonce, ciphertext = seal_text(plaintext, key)
    decrypted = unseal_text(ciphertext, key, nonce)
    assert decrypted == plaintext

def test_decryption_with_wrong_key():
    key = roll_seed()
    dummy_key = roll_seed()
    plaintext = b"Hello Prompt Sealer"
    nonce, ciphertext = seal_text(plaintext, key)
    with pytest.raises(InvalidTag):
        unseal_text(ciphertext, dummy_key, nonce)

def test_unseal_with_tampered_ciphertext():
    key = roll_seed()
    plaintext = b"Hello Prompt Sealer"
    nonce, ciphertext = seal_text(plaintext, key)
    tamper = (ciphertext[:-1] + bytes([ciphertext[-1] ^ 1]))
    with pytest.raises(InvalidTag):
        unseal_text(tamper, key, nonce)

def test_seal_text_rejects_non_bytes():
    with pytest.raises(TypeError):
        seal_text("key", roll_seed())

def test_unseak_reject_invalid_key():
    with pytest.raises(ValueError):
        unseal_text(b"key",b"", non)

# def test_encrypt_rejects_invalid_key_length():
#     plaintext = b"Hello Prompt Sealer"
#     key = b"short"
#     with pytest.raises(ValueError):
#         encrypt_data(plaintext, key)

# def test_decrypt_rejects_invalid_nonce_length():
#     key = generate_key()
#     invalid_nonce = b"short"
#     ciphertext = b"some ciphertext"
#     with pytest.raises(ValueError):
#         decrypt_data(ciphertext, key, invalid_nonce)

# def test_encrpt_rejects_non_bytes_plaintext():
#     key = generate_key()
#     with pytest.raises(TypeError):
#         encrypt_data("Hello Prompt Sealer", key)

# def test_encrypt_decrypt_empty_plaintext():
#     key = generate_key()
#     plaintext = b""
#     nonce, ciphertext = encrypt_data(plaintext, key)
#     decrypted = decrypt_data(ciphertext, key, nonce)
#     assert decrypted == plaintext

# def test_encrypt_generates_different_nonces():
#     key = generate_key()
#     plaintext = b"Hello Prompt Sealer"
#     nonce1, ciphertext1 = encrypt_data(plaintext, key)
#     nonce2, ciphertext2 = encrypt_data(plaintext, key)
#     assert nonce1 != nonce2



# def test_key_exchange_using_serialized_key():
#     private_1 = generate_private_key()
#     public_1 = generate_public_key(private_1)
            
#     private_2 = generate_private_key()
#     public_2 = generate_public_key(private_2)

#     key_1 = deserialize_public_key(serialize_public_key(public_2))
#     key_2 = deserialize_public_key(serialize_public_key(public_1))

#     secret_1 = generate_shared_secret(private_1, key_1)
#     secret_2 = generate_shared_secret(private_2, key_2)
#     assert secret_1 == secret_2

# def test_entire_flow():
#     private_1 = generate_private_key()
#     public_1 = generate_public_key(private_1)
        
#     private_2 = generate_private_key()
#     public_2 = generate_public_key(private_2)
    
#     secret_1 = generate_shared_secret(private_1, public_2)
#     secret_2 = generate_shared_secret(private_2, public_1)

#     salt = generate_key()

#     key_1 = derive_encryption_key(secret_1, salt)
#     key_2 = derive_encryption_key(secret_2, salt)

#     assert key_1 == key_2
#     plaintext = b"Hello Prompt Sealer"
#     nonce, ciphertext = encrypt_data(plaintext, key_1)
#     decrypted_text = decrypt_data(ciphertext, key_2, nonce)
#     assert decrypted_text == plaintext

