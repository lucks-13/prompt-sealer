from prompt_sealer.vault import protect_data

def test_protect_data_returns_bytes():
    data = b"Hello Prompt Sealer"
    protected = protect_data(data)
    assert isinstance(protected, bytes)

def test_protected_data_differs_from_orginal():
    data = b"Hello Prompt Sealer"
    