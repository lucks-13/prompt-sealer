import win32crypt

def protect_data(data : bytes) -> bytes:
    protect_data = win32crypt.CryptProtectData(data, "Prompt Sealer", None, None, None, 0)
    return protect_data

def unprotect_data(data : bytes) -> bytes:
    result = win32crypt.CryptUnProtectData(data, "Prompt Sealer", None, None, None, 0)
    return result[1]

