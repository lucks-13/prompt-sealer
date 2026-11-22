import json
import time
from pathlib import Path
from typer.testing import CliRunner
from prompt_sealer import cli, protocol, sealer

runner = CliRunner()

def patch_paths(monkeypatch, tmp_path : Path) -> tuple[Path, Path]:
    vault_file = tmp_path / "vault.dat"
    state_file = tmp_path / "state.json"
    monkeypatch.setattr(cli, "vault_path", vault_file)
    monkeypatch.setattr(cli, "state_path", state_file)
    return vault_file, state_file

def test_seal_authorize_redeem(monkeypatch, tmp_path : Path):
    vault_file, state