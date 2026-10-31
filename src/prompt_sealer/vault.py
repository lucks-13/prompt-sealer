import win32crypt
import pywintypes

def protect_data(data : bytes) -> bytes:
    protected = win32crypt.CryptProtectData(data, "Prompt Sealer", None, None, None, 0)
    return protected

def unprotect_data(data : bytes) -> bytes:
    try:
        result = win32crypt.CryptUnprotectData(data, None, None, None, 0)
        return result[1]
    except pywintypes.error:
        raise ValueError("")

