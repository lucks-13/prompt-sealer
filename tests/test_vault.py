import json
import pytest
from pathlib import Path
from prompt_sealer.crypto import mint_pair, mint_stamp
from prompt_sealer.vault import seal_blob, unlock_record, tuck_away, unpack_token, tuck_badge, bring_badge, write_cache, fetch_store, create_vault, init_vault, open_vault, check_vault, destroy_vault
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

def test_dpapi_flow():
    data = b"Hello Prompt Sealer"
    protected = seal_blob(data)
    assert isinstance(protected, bytes)
    assert protected != data
    assert unlock_record(protected) == data

def test_key_storage_flow():
    en_key = mint_pair()
    sg_key = mint_stamp()

    restored_en = unpack_token(tuck_away(en_key))
    restored_sg = bring_badge(tuck_badge(sg_key))

    assert isinstance(restored_en, X25519PrivateKey)
    assert isinstance(restored_sg, Ed25519PrivateKey)

    assert restored_en.public_key() == en_key.public_key()
    assert restored_sg.public_key() == sg_key.public_key()

def test_vault_file_flow(tmp_path):
    path = tmp_path / "nested" / "vault.dat"
    data = b"Vault test data"
    write_cache(data, path)
    assert fetch_store(path) == data

def test_vault_creation_and_loading(tmp_path):
    path = tmp_path / "vault.dat"
    init_vault(path)
    assert path.exists()
    assert check_vault(path) is True
    data = json.loads(fetch_store(path).decode("utf-8"))
    assert set(data) == {"encryption_key", "signing_key"}
    en_key, sg_key = open_vault(path)
    assert isinstance(en_key, X25519PrivateKey)
    assert isinstance(sg_key, Ed25519PrivateKey)

def test_invalid_vault(tmp_path):
    path = tmp_path / "vault.dat"
    path.write_bytes(b"Invalid Vault")
    with pytest.raises(ValueError):
        open_vault(path)

def test_vault_protection_and_cleanup(tmp_path):
    

def test_vault_destruction(tmp_path):
    path = tmp_path / "vault.dat"
    init_vault(path)
    assert path.exists()
    destroy_vault(path)
    assert not path.exists()
    with pytest.raises(FileNotFoundError):
        destroy_vault(path)