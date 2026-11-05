import hashlib
import json
import time
from prompt_sealer.crypto import forge_lock
def read_sealed(source : Path)