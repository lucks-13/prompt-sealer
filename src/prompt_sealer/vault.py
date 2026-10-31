import win32crypt

def protect_data(data : data) -> bytes:
    protect_data = win32crypt.CryptProtectData(data, "Prompt Sealer", None, None, 0)
    return protect_data

