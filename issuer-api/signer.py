from abc import ABC, abstractmethod
from typing import Protocol
import base64
from did_utils import sign_ed25519

class Signer(Protocol):
    def sign(self, data: bytes) -> bytes:
        ...

class LocalSigner:
    """Signer that holds a local base64-encoded Ed25519 secret key."""
    def __init__(self, seckey_b64: str):
        self._seckey_b64 = seckey_b64

    def sign(self, data: bytes) -> bytes:
        return sign_ed25519(self._seckey_b64, data)

class KMSSigner:
    """Placeholder for KMS/HSM backed signer."""
    def __init__(self, key_id: str):
        self.key_id = key_id

    def sign(self, data: bytes) -> bytes:
        raise NotImplementedError("KMS signer not implemented in demo")
