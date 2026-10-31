import pytest
from prompt_sealer.vault import protect_data, unprotect_data

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
        unprotect_data(b"invalid protected data")


