import typer
from pathlib import Path
from prompt_sealer.sealer import derive_prompt_key, seal_file
from prompt_sealer.vault import init_vault, check_vault,destroy_vault, open_vault
from prompt_sealer.crypto import roll_seed
from prompt_sealer.protocol import authorize, redeem
import time
import json

app = typer.Typer(name="prompt-sealer",help="Seal and manage encrypted prompt files.")

vault_path = Path.home() / ".prompt-sealer" / "vault.dat"
state_path = Path.home() / ".prompt-sealer" / "state.json"

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
        open_vault(vault_path)
        file_id = roll_seed()
        challenge = roll_seed()
        expires = int(time.time()) + 3600
        seal_file(source, dest, file_id, expires, challenge)
        typer.echo(f"Prompt sealed : {dest}")
        typer.echo("")
        typer.echo("Share this sealed file with Ai :")
        typer.echo(f"File : {dest.resolve()}")
    except FileNotFoundError as error:
        typer.echo(str(error))
        raise typer.Exit(code=1)
    except ValueError as error:
        typer.echo(str(error))
        raise typer.Exit(code=1)

@app.command()
def authorize_prompt(source : Path = typer.Argument(..., help="Sealed prompt file."), code_a : str = typer.Argument(..., help="Access code A.")):
    try:
        _, _, machine_secret = open_vault(vault_path)
        file_id = bytes.fromhex(json.loads(source.read_bytes().decode("utf-8"))["file_id"])
        p_key = derive_prompt_key(machine_secret, file_id)
        code_b = authorize(source, code_a, p_key, state_path)
        typer.echo(f"Access Code B : {code_b}")
    except (FileNotFoundError, ValueError) as error:
        typer.echo(str(error))
        raise typer.Exit(code=1)

@app.command()
def redeem_prompt(source : Path = typer.Argument(..., help="Sealed prompt file."), code_b : str = typer.Argument(..., help="Access code B."), dest : Path = typer.Argument(..., help="Output plaintext prompt file.")):
    try:
        prompt = redeem(source, code_b, state_path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(prompt)
        typer.echo(f"Prompt redeemed : {dest}")
    except (FileNotFoundError, ValueError) as error:
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