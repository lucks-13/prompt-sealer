import typer
from pathlib import Path
from prompt_sealer.sealer import derive_prompt_key, seal_file, unseal_file
from prompt_sealer.vault import init_vault, check_vault,destroy_vault, open_vault
from cryptography.exceptions import InvalidTag

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

@app.command()
def seal(source : Path = typer.Argument(..., help="Prompt file to seal."), dest : Path = typer.Argument(..., help="Output sealed file.")):
    try:
        en_key, _ = open_vault(vault_path)
        p_key = derive_prompt_key(en_key)
        seal_file(source, dest, p_key)
        typer.echo(f"Prompt sealed : {dest}")
    except FileNotFoundError as error:
        typer.echo(str(error))
        raise typer.Exit(code=1)
    except ValueError as error:
        typer.echo(str(error))
        raise typer.Exit(code=1)

@app.command()
def unseal(source : Path = typer.Argument(..., help="Sealed prompt file."), dest : Path = typer.Argument(..., help="Output prompt file.")):
    try:
        en_key, _ = open_vault(vault_path)
        p_key = derive_prompt_key(en_key)
        unseal_file(source, dest, p_key)
        typer.echo(f"Prompt restored : {dest}")
    except FileNotFoundError as error:
        typer.echo(str(error))
        raise typer.Exit(code=1)
    except ValueError as error:
        typer.echo(str(error))
        raise typer.Exit(code=1)

@app.command()
def destroy(force : bool = typer.Option(False, "--force", help="Delete the vault without confirmation.")):
    if not force:
        confirmed = typer.confirm("Delete the prompt sealer vault ?")
        if not confirmed:
            typer.echo("Vault was not deleted.")
            raise typer.Exit()
    try:
        destroy_vault(vault_path)
        typer.echo("Vault destroyed.")
    except FileNotFoundError:
        typer.echo("Vault does not exist.")
        raise typer.Exit(code=1)

if __name__ == "__main__":
    app()