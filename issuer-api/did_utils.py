import base64
from dataclasses import dataclass
from nacl import signing
import os

@dataclass
class DIDKey:
    did: str
    pubkey_b64: str
    seckey_b64: str

def new_did():
    sk = signing.SigningKey.generate()
    pk = sk.verify_key
    pub_b64 = base64.b64encode(bytes(pk)).decode()
    sec_b64 = base64.b64encode(bytes(sk)).decode()
    domain = os.getenv("DID_WEB_DOMAIN", "example.org")
    did = f"did:web:{domain}"
    return DIDKey(did=did, pubkey_b64=pub_b64, seckey_b64=sec_b64)

def sign_ed25519(seckey_b64: str, payload: bytes) -> str:
    sk = signing.SigningKey(base64.b64decode(seckey_b64))
    sig = sk.sign(payload).signature
    return base64.b64encode(sig).decode()

def verify_ed25519(pubkey_b64: str, payload: bytes, sig_b64: str) -> bool:
    try:
        vk = signing.VerifyKey(base64.b64decode(pubkey_b64))
        vk.verify(payload, base64.b64decode(sig_b64))
        return True
    except Exception:
        return False
