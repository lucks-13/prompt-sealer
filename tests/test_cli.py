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
    prompt_file.write_text("Test Prompt", encoding="utf-8")
    res = runner.invoke(cli.app, ["init"])
    assert res.exit_code == 0
    assert vault_file.exists()
    res = runner.invoke(cli.app, ["check"])
    assert res.exit_code == 0
    res = runner.invoke(cli.app, ["seal", str(prompt_file), str(sealed_file)], input="0\n15\n")
    assert res.exit_code == 0
    assert sealed_file.exists()
    sealed_before = sealed_file.read_bytes()
    record = json.loads(sealed_before.decode("utf-8"))
    assert record["expires"] >= int(time.time()) + 14 * 60
    code_a = sealer.make_code_a(bytes.fromhex(record["challenge"]))
    res = runner.invoke(cli.app, ["authorize-prompt", str(sealed_file), code_a])
    assert res.exit_code == 0
    assert "Access Code B :" in res.stdout
    code_b = res.stdout.split("Access Code B :")[1].strip().splitlines()[0].strip()
    assert sealed_file.read_bytes() == sealed_before
    state = json.loads(state_file.read_text(encoding="utf-8"))
    assert state[record["file_id"]]["used"] is False
    res = runner.invoke(cli.app, ["redeem-prompt", str(sealed_file), code_b, str(redeemed_file)])
    assert res.exit_code == 0
    assert redeemed_file.exists()
    redeemed_text = redeemed_file.read_text(encoding="utf-8")
    assert "--- Protected User Prompt ---" in redeemed_text
    assert "Test Prompt" in redeemed_text
    assert sealed_file.read_bytes() == sealed_before
    state = json.loads(sealed_file.read_text(encoding="utf-8"))
    assert state[record["file_id"]]["used"] is True
    res = runner.invoke(cli.app, ["redeem-prompt", str(sealed_file), code_b, str(tmp_path / "again.txt")])
    assert res.exit_code == 1

def test_wrong_code_and_tampered(monkeypatch, tmp_path : Path):
    p