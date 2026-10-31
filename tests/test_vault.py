import pytest
from prompt_sealer.crypto import generate_private_key
from prompt_sealer.vault import protect_data, unprotect_data, store_private_key
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption

def test_protect_data_returns_bytes():
    data = b"Hello Prompt Sealer"
    protected = protect_data(data)
    assert isinstance(protected, bytes)

def test_protected_data_differs_from_orginal():
    data = b"Hello Prompt Sealer"
    protected = protect_data(data)
    assert protected != data

def test_unprotected_data():
    data = b"Hello Prompt Sealer"
    protected = protect_data(data)
    decrypted = unprotect_data(protected)
    assert decrypted == data

def test_empty_unprotected_data():
    data = b""
    protected = protect_data(data)
    decrypted = unprotect_data(protected)
    assert decrypted == data

def test_unprotect_invalid_data():
    with pytest.raises(ValueError, match="Unable to decrypt protected data."):
        unprotect_data(b"Hello Prompt Sealer")

def test_store_private_key_returns_bytes():
    private_key = generate_private_key()
    stored_key = store_private_key(private_key)
    assert isinstance(stored_key, bytes)

def test_stored_private_key_is_protected():
    private_key = generate_private_key()
    raw_key = private_key.private_bytes(encoding=Encoding.Raw, format=PrivateFormat.Raw, encryption_algorithm=NoEncryption())
    stored_key = store_private_key(private_key)
    assert stored_key != raw_key


