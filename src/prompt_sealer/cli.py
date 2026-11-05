import typer
from pathlib import Path
from prompt_sealer.vault import init_vault, check_vault

app = typer.Typer(name="prompt-sealer",help="Seal and manage encrypted prompt files.")

vault_path = Path.home() / ".prompt-sealer" / "vault.dat"

@app.callback()
def main():
    pass

@ 