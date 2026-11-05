import pytest
from prompt_sealer.sealer import read_prompt

def test_read_prompt(tmp_path):
    path = tmp_path / "prompt.md"
    content = b"Prompt"
    path.write_bytes(content)
    assert read_prompt(path) == content

def test_read_prompt_rejects_invalid(tmp_path):
    missing = tmp_path / "missing.md"
    with pytest.raises(FileNotFoundError):
        read_prompt(missing)
    folder = tmp_path / "prompts"
    folder