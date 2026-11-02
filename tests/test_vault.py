import pytest
from pathlib import Path
from prompt_sealer.crypto import mint_pair, mint_stamp
from prompt_sealer.vault import seal_blob, unlock_record, tuck_away, unpack_token, tuck_badge, write_cache, fetch_store
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

# def test_seal_blob():
#     data = b"Hello Prompt Sealer"
#     protected = seal_blob(data)
#     assert isinstance(protected, bytes)
#     assert protected != data

# def test_unprotected_data():
#     data = b"Hello Prompt Sealer"
#     protected = protect_data(data)
#     decrypted = unprotect_data(protected)
#     assert decrypted == data

# def test_empty_unprotected_data():
#     data = b""
#     protected = protect_data(data)
#     decrypted = unprotect_data(protected)
#     assert decrypted == data

# def test_unprotect_invalid_data():
#     with pytest.raises(ValueError, match="Unable to decrypt protected data."):
#         unprotect_data(b"Hello Prompt Sealer")

# def test_store_private_key_returns_bytes():
#     private_key = generate_private_key()
#     stored_key = store_private_key(private_key)
#     assert isinstance(stored_key, bytes)

# def test_stored_private_key_is_protected():
#     private_key = generate_private_key()
#     raw_key = private_key.private_bytes(encoding=Encoding.Raw, format=PrivateFormat.Raw, encryption_algorithm=NoEncryption())
#     stored_key = store_private_key(private_key)
#     assert stored_key != raw_key

# def test_load_private_key_returns_private_key():
#     original_key = generate_private_key()
#     stored_key = store_private_key(original_key)
#     loaded_key = load_private_key(stored_key)
#     assert isinstance(loaded_key, type(original_key))

# def test_original_key_and_loaded_key_matches():
#     original_key = generate_private_key()
#     stored_key = store_private_key(original_key)
#     loaded_key = load_private_key(stored_key)
#     original_public = original_key.public_key()
#     loaded_public = loaded_key.public_key()
#     assert original_public == loaded_public

# def test_load_private_key_rejects_invalid_data():
#     with pytest.raises(ValueError):
#         load_private_key(b"Hello Prompt Sealer")

# def test_save_and_read_vault(tmp_path):
#     data = b"Hello Prompt Sealer"
#     vault_path = tmp_path / "vault.dat"
#     save_vault(data, vault_path)
#     loaded_data = read_vault(vault_path)
#     assert loaded_data == data

# def test_save_vault_create_parent_dir(tmp_path):
#     data = b"Hello Prompt Sealer"
#     vault_path = tmp_path / "nested" / "folder" / "vault.dat"
#     save_vault(data, vault_path)
#     assert vault_path.exists()

# def test_read_missing_vault():
#     missing_path = Path("missing_vault.dat")
#     with pytest.raises(FileNotFoundError):
#         read_vault(missing_path)

# def test_store_signing_key():
#     private_key = generate_signing_private_key()
#     stored_key = store_signing_key(private_key)
#     assert isinstance(stored_key, bytes)

# def test_load_signing_key():
#     original_key = generate_signing_private_key()
#     stored_key = store_signing_key(original_key)
#     loaded_key = load_signing_key(stored_key)
#     assert isinstance(loaded_key, Ed25519PrivateKey)

# def test_loaded_signing_key_matches_original():
#     original_key = generate_signing_private_key()
#     stored_key = store_signing_key(original_key)
#     loaded_key = load_signing_key(stored_key)
#     assert original_key.public_key() == loaded_key.public_key()
    