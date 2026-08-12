import os
from cryptography.fernet import Fernet

def _fernet() -> Fernet | None:
    key = os.getenv("API_KEY_ENC_KEY")
    if not key:
        return None
    return Fernet(key.encode())

def load_api_key() -> str:
    """Load the API key from env or encrypted file."""
    f = _fernet()
    path = os.getenv("API_KEY_ENC_FILE")
    if f and path and os.path.exists(path):
        with open(path, "rb") as fh:
            return f.decrypt(fh.read()).decode()
    key = os.getenv("ISSUER_API_KEY")
    if not key:
        raise RuntimeError("ISSUER_API_KEY or an encrypted API key file is required")
    return key

def rotate_api_key(new_key: str) -> None:
    """Rotate the API key by writing an encrypted file."""
    f = _fernet()
    path = os.getenv("API_KEY_ENC_FILE")
    if not (f and path):
        raise RuntimeError("encryption key or file path not set")
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, mode=0o700, exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(f.encrypt(new_key.encode()))
    os.environ["ISSUER_API_KEY"] = new_key
