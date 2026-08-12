import base64
from dataclasses import dataclass
from nacl import signing

@dataclass
class DIDKey:
    did: str
    pubkey_b64: str
    seckey_b64: str

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def _base58btc(data: bytes) -> str:
    value = int.from_bytes(data, "big")
    encoded = ""
    while value:
        value, remainder = divmod(value, 58)
        encoded = _B58[remainder] + encoded
    leading_zeroes = len(data) - len(data.lstrip(b"\0"))
    return "1" * leading_zeroes + (encoded or "1")

def _base58btc_decode(value: str) -> bytes:
    number = 0
    for char in value:
        number = number * 58 + _B58.index(char)
    decoded = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    return b"\0" * (len(value) - len(value.lstrip("1"))) + decoded

def public_key_multibase(pubkey_b64: str) -> str:
    return "z" + _base58btc(b"\xed\x01" + base64.b64decode(pubkey_b64))

def public_key_from_multibase(value: str) -> str:
    decoded = _base58btc_decode(value.removeprefix("z"))
    if not decoded.startswith(b"\xed\x01") or len(decoded) != 34:
        raise ValueError("not an Ed25519 public key multibase value")
    return base64.b64encode(decoded[2:]).decode()

def new_did():
    sk = signing.SigningKey.generate()
    pk = sk.verify_key
    pub_b64 = base64.b64encode(bytes(pk)).decode()
    sec_b64 = base64.b64encode(bytes(sk)).decode()
    # did:key Ed25519 identifiers use the multicodec ed25519-pub prefix
    # (0xed01) followed by the raw 32-byte public key, base58btc encoded.
    fingerprint = "z" + _base58btc(b"\xed\x01" + bytes(pk))
    did = f"did:key:{fingerprint}"
    return DIDKey(did=did, pubkey_b64=pub_b64, seckey_b64=sec_b64)

def sign_ed25519(seckey_b64: str, payload: bytes) -> str:
    sk = signing.SigningKey(base64.b64decode(seckey_b64))
    sig = sk.sign(payload).signature
    return "z" + _base58btc(sig)

def verify_ed25519(pubkey_b64: str, payload: bytes, sig_b64: str) -> bool:
    try:
        vk = signing.VerifyKey(base64.b64decode(pubkey_b64))
        signature = _base58btc_decode(sig_b64[1:]) if sig_b64.startswith("z") else base64.b64decode(sig_b64)
        vk.verify(payload, signature)
        return True
    except Exception:
        return False
