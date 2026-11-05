import json
import pytest
from pathlib import Path
from prompt_sealer.crypto import mint_pair, mint_stamp
from prompt_sealer.vault import seal_blob, unlock_record, tuck_away, unpack_token, tuck_badge, bring_badge, write_cache, fetch_store, create_vault, init_vault
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

def test_seal_blob():
    data = b"Hello Prompt Sealer"
    protected = seal_blob(data)
    assert isinstance(protected, bytes)
    assert protected != data

def test_unlock_record():
    data = b"Hello Prompt Sealer"
    protected = seal_blob(data)
    decrypted = unlock_record(protected)
    assert decrypted == data

def test_empty_unlock_record():
    data = b""
    protected = seal_blob(data)
    decrypted = unlock_record(protected)
    assert decrypted == data

def test_unlock_record_invalid_data():
    with pytest.raises(ValueError, match="Unable to decrypt protected data."):
        unlock_record(b"Hello Prompt Sealer")

def test_tuck_away():
    private_key = mint_pair()
    stored_key = tuck_away(private_key)
    assert isinstance(stored_key, bytes)

def test_unpack_token():
    original_key = mint_pair()
    stored_key = tuck_away(original_key)
    restored_key = unpack_token(stored_key)
    assert isinstance(restored_key, X25519PrivateKey)
    assert restored_key.public_key() == original_key.public_key()

def test_unpack_token_invalid_data():
    with pytest.raises(ValueError):
        unpack_token(b"Hello Prompt Sealer")

def test_tuck_badge():
    private_key = mint_stamp()
    stored_key = tuck_badge(private_key)
    assert isinstance(stored_key, bytes)

def test_bring_badge():
    original_key = mint_stamp()
    stored_key = tuck_badge(original_key)
    restored_key = bring_badge(stored_key)
    assert isinstance(restored_key, Ed25519PrivateKey)
    assert restored_key.public_key() == original_key.public_key()

def test_write_and_fetch_store(tmp_path):
    data = b"Hello Prompt Sealer"
    vault_path = tmp_path / "vault.dat"
    write_cache(data, vault_path)
    loaded_data = fetch_store(vault_path)
    assert loaded_data == data

def test_write_cache_create_parent_dir(tmp_path):
    data = b"Hello Prompt Sealer"
    vault_path = tmp_path / "nested" / "folder" / "vault.dat"
    write_cache(data, vault_path)
    assert vault_path.exists()

def test_fetch_store_missing_vault():
    missing_path = Path("missing_vault.dat")
    with pytest.raises(FileNotFoundError):
        fetch_store(missing_path)

def test_create_vault():
    vault = create_vault()
    data = json.loads(vault.decode("utf-8"))
    assert "encryption_key" in data
    assert "signing_key" in data