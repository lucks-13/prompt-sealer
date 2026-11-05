import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from prompt_sealer.crypto import roll_seed, nonce_seed, mint_pair, expose_token, blend_secret, forge_lock, pack_remote, read_remote, mint_stamp, reveal_badge, stamp_note, check_mark, seal_text, unseal_text

def test_random_generation():
    seed = roll_seed()
    nonce = nonce_seed()
    assert isinstance(seed, bytes)
    assert len(seed) == 32
    assert isinstance(nonce, bytes)
    assert len(nonce) == 12
    assert seed != roll_seed()
    assert nonce != nonce_seed()

def test_key_exchange():
    private_1 = mint_pair()
    public_1 = expose_token(private_1)
    
    private_2 = mint_pair()
    public_2 = expose_token(private_2)

    secret_1 = blend_secret(private_1, public_2)
    secret_2 = blend_secret(private_2, public_1)
    
    assert secret_1 == secret_2
    packed = pack_remote(public_1)
    restored = read_remote(packed)
    assert restored == public_1
    assert isinstance(private_1, X25519PrivateKey)
    assert len(secret_1) == 32
    assert len(secret_2) == 32

def test_key_derivation():
    private_1 = mint_pair()
    private_2 = mint_pair()

    secret_1 = blend_secret(private_1, expose_token(private_2))
    secret_2 = blend_secret(private_2, expose_token(private_1))

    salt = roll_seed()

    key_1 = forge_lock(secret_1, salt)
    key_2 = forge_lock(secret_2, salt)

    assert key_1 == key_2
    len(key_1) == 32
    plaintext = b"Hello Prompt Sealer"
    nonce, ciphertext = seal_text(plaintext, key_1)
    decrypted_text = unseal_text(ciphertext, key_2, nonce)
    assert decrypted_text == plaintext

def test_signature_flow():
    private_key = mint_stamp()
    public_key = reveal_badge(private_key)
    message = b"Hello Prompt Sealer"
    signature = stamp_note(private_key, message)
    assert isinstance(private_key, Ed25519PrivateKey)
    assert check_mark(public_key, signature, message)
    altered_message = b"Modified Prompt"
    assert not check_mark(public_key, signature, altered_message)

def test_encryption_roundtrip():
    key = roll_seed()
    plaintext = b"Secret prompt content"
    nonce, ciphertext = seal_text(plaintext, key)
    decrypted = unseal_text(ciphertext, key, nonce)
    assert decrypted == plaintext
    assert ciphertext != plaintext
    assert len(nonce) == 12

def test_encryption_rejects_invalid_data():
    key = roll_seed()
    wrong_key = roll_seed()
    plaintext = b"Secret prompt content"
    nonce, ciphertext = seal_text(plaintext, key)
    with pytest.raises(InvalidTag):
        unseal_text(ciphertext, wrong_key, nonce)
    tampered = bytearray(ciphertext)
    tampered[0] ^= 1
    with pytest.raises(InvalidTag):
        unseal_text(bytes(tampered), key)
