import json, time, hashlib
from dataclasses import dataclass
from did_utils import verify_ed25519
from signer import Signer

@dataclass
class VC:
    vc_id: str
    payload: dict
    signature: str

def vc_id_from_payload(payload: dict) -> str:
    h = hashlib.sha256(json.dumps(payload, separators=(",",":")).encode()).hexdigest()
    return "vcid:" + h

def make_vc(issuer_did: str, pubkey_b64: str, manifest_digest: str, contract_address: str,
            exp_secs: int = 3600*24*90):
    now = int(time.time())
    payload = {
        "type": ["VerifiableCredential", "OCIVerifiableImage"],
        "issuer": issuer_did,
        "issuedAt": now,
        "expiration": now + exp_secs,
        "credentialSubject": {
            "manifestDigest": manifest_digest,
            "contractAddress": contract_address.lower(),
            "issuerPublicKeyBase64": pubkey_b64
        }
    }
    return payload

def sign_vc(signer: Signer, payload: dict) -> VC:
    vcid = vc_id_from_payload(payload)
    body = json.dumps(payload, separators=(",",":")).encode()
    sig = signer.sign(body)
    return VC(vc_id=vcid, payload=payload, signature=sig)

def verify_vc(vc: VC) -> bool:
    pub = vc.payload["credentialSubject"]["issuerPublicKeyBase64"]
    body = json.dumps(vc.payload, separators=(",",":")).encode()
    return verify_ed25519(pub, body, vc.signature)
