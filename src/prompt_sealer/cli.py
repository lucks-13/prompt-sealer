import typer
from pathlib import Path
from prompt_sealer.vault import init_vault, check_vault

app = typer.Typer(name="prompt-sealer",help="Seal and manage encrypted prompt files.")

vault_path = Path.home() / ".prompt-sealer" / "vault.dat"

@app.callback()
def main():
    pass

@app.command()
def init():
    try:
        init_vault(vault_path)
        typer.echo("Vault initialized successfully.")
    except FileExistsError:
        typer.echo("Vault already exists.")
        raise typer.Exit(code=1)

@app.command()
def check():
    try:
        check_vault(vault_path)
        typer.echo("Vault is valid.")
    except FileNotFoundError:
        typer.echo("Vault does not exist.")
        raise typer.Exit(code=1)
    except ValueError:
        typer.echo("Vault is invalid or cannot be unlocked.")
        raise typer.Exit(code=1)

if __name__ == "__main__":
    app()