import time
from datetime import datetime, timezone
from dataclasses import dataclass
from web3 import Web3
from pyld import jsonld
from did_utils import verify_ed25519
from signer import Signer

@dataclass
class VC:
    vc_id: str
    payload: dict
    signature: str

_VC_CONTEXT = {
    "id": "@id", "type": "@type",
    "VerifiableCredential": "https://www.w3.org/2018/credentials#VerifiableCredential",
    "ContainerImageCredential": "https://w3id.org/cbc-provenance#ContainerImageCredential",
    "issuer": {"@id": "https://www.w3.org/2018/credentials#issuer", "@type": "@id"},
    "issuanceDate": {"@id": "https://www.w3.org/2018/credentials#issuanceDate", "@type": "http://www.w3.org/2001/XMLSchema#dateTime"},
    "expirationDate": {"@id": "https://www.w3.org/2018/credentials#expirationDate", "@type": "http://www.w3.org/2001/XMLSchema#dateTime"},
    "credentialSubject": "https://www.w3.org/2018/credentials#credentialSubject",
    "image": "https://w3id.org/cbc-provenance#image",
    "manifestDigest": "https://w3id.org/cbc-provenance#manifestDigest",
    "reference": "https://w3id.org/cbc-provenance#reference",
    "cbc": "https://w3id.org/cbc-provenance#contractBindingContext",
    "chainId": {"@id": "https://w3id.org/cbc-provenance#chainId", "@type": "http://www.w3.org/2001/XMLSchema#integer"},
    "contractAddress": "https://w3id.org/cbc-provenance#contractAddress",
    "didDocCid": "https://w3id.org/cbc-provenance#didDocumentCid",
    "buildMetadata": {"@id": "https://w3id.org/cbc-provenance#buildMetadata", "@type": "@json"},
    "proof": "https://w3id.org/security#proof",
    "Ed25519Signature2020": "https://w3id.org/security#Ed25519Signature2020",
    "created": {"@id": "http://purl.org/dc/terms/created", "@type": "http://www.w3.org/2001/XMLSchema#dateTime"},
    "verificationMethod": {"@id": "https://w3id.org/security#verificationMethod", "@type": "@id"},
    "proofPurpose": {"@id": "https://w3id.org/security#proofPurpose", "@type": "@vocab"},
    "assertionMethod": "https://w3id.org/security#assertionMethod",
}

def _document_loader(url, options=None):
    if url == "https://www.w3.org/2018/credentials/v1":
        return {"contextUrl": None, "documentUrl": url, "document": {"@context": _VC_CONTEXT}}
    raise ValueError(f"remote JSON-LD context is not allowed: {url}")

def canonicalize(payload: dict) -> bytes:
    """URDNA2015-normalize the proof-free VC to canonical N-Quads."""
    normalized = jsonld.normalize(payload, {
        "algorithm": "URDNA2015",
        "format": "application/n-quads",
        "documentLoader": _document_loader,
    })
    return normalized.encode("utf-8")

def vc_id_from_payload(payload: dict) -> str:
    return "urn:vcid:" + Web3.keccak(canonicalize(payload)).hex()

def make_vc(issuer_did: str, manifest_digest: str, contract_address: str,
            chain_id: int, did_doc_cid: str, image_reference: str | None = None,
            build_metadata: dict | None = None, exp_secs: int = 3600*24*90):
    now = int(time.time())
    issued = datetime.fromtimestamp(now, timezone.utc).isoformat().replace("+00:00", "Z")
    expires = datetime.fromtimestamp(now + exp_secs, timezone.utc).isoformat().replace("+00:00", "Z")
    payload = {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "type": ["VerifiableCredential", "ContainerImageCredential"],
        "issuer": issuer_did,
        "issuanceDate": issued,
        "expirationDate": expires,
        "credentialSubject": {
            "image": {
                "manifestDigest": manifest_digest,
                **({"reference": image_reference} if image_reference else {}),
            },
            "cbc": {
                "chainId": chain_id,
                "contractAddress": contract_address.lower(),
            },
            # Lets the verifier bind the resolved DID Document to the CID
            # registered on-chain for this issuer.
            "didDocCid": did_doc_cid,
            **({"buildMetadata": build_metadata} if build_metadata else {}),
        }
    }
    return payload

def sign_vc(signer: Signer, payload: dict) -> VC:
    vcid = vc_id_from_payload(payload)
    body = canonicalize({**payload, "proof": proof_options(payload)})
    sig = signer.sign(body)
    return VC(vc_id=vcid, payload=payload, signature=sig)

def verify_vc(vc: VC, pub: str) -> bool:
    body = canonicalize({**vc.payload, "proof": proof_options(vc.payload)})
    return verify_ed25519(pub, body, vc.signature)

def proof_options(payload: dict) -> dict:
    return {
        "type": "Ed25519Signature2020",
        "created": payload["issuanceDate"],
        "verificationMethod": f'{payload["issuer"]}#key-1',
        "proofPurpose": "assertionMethod",
    }

def parse_vc_time(value: str) -> int:
    return int(datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp())
