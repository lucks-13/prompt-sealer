import json
import time
from pathlib import Path
from typer.testing import CliRunner
from prompt_sealer import cli, protocol, sealer

runner = CliRunner()

def patc