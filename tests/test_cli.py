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
    vault_file, state_file = patch_paths(monkeypatch, tmp_path)
    prompt_file = tmp_path / "prompt.txt"
    sealed_file = tmp_path / "sealed.json"
    redeemed_file = tmp_path / "redeemed.txt"
    prompt_file.write_text("Testing Prompt", encoding="utf-8")
    res = runner.invoke(cli.app, ["init"])
    assert res.exit_code == 0
    assert vault_file.exists()
    res = runner.invoke(cli.app, ["check"])
    assert res.exit_code == 0
    res = runner.invoke(cli.app)