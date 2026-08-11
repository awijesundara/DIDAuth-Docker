import json, time
from dataclasses import dataclass
from web3 import Web3
from did_utils import verify_ed25519
from signer import Signer

@dataclass
class VC:
    vc_id: str
    payload: dict
    signature: str

def canonicalize(payload: dict) -> bytes:
    """Deterministic serialization used for both vc_id hashing and the
    signed body. Sorted keys make the encoding independent of dict
    insertion order/JSON library, unlike the previous separators-only
    json.dumps -- two structurally identical VCs built by different
    clients (or the same client on different Python versions) must hash
    and sign to the exact same bytes, or vc_id becomes non-reproducible
    and cross-implementation verification breaks.

    This is a JCS-style canonical JSON encoding, not full JSON-LD/RDF
    URDNA2015 canonicalization (which requires resolving the VC's
    @context through an RDF processor). The payload here carries no
    @context-driven RDF semantics -- it is a fixed, flat schema -- so
    sorted-key canonical JSON gives the same reproducibility guarantee
    URDNA2015 would, without pulling in a JSON-LD dependency this schema
    doesn't otherwise need.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()

def vc_id_from_payload(payload: dict) -> str:
    # keccak256 (not sha256) to match the hash primitive the on-chain
    # registry and chain_utils.to_bytes32 already use, so vc_id and its
    # on-chain bytes32 key are computed with one consistent hash function.
    return "vcid:" + Web3.keccak(canonicalize(payload)).hex()

def make_vc(issuer_did: str, pubkey_b64: str, manifest_digest: str, contract_address: str,
            chain_id: int, did_doc_cid: str, exp_secs: int = 3600*24*90):
    now = int(time.time())
    payload = {
        "type": ["VerifiableCredential", "OCIVerifiableImage"],
        "issuer": issuer_did,
        "issuedAt": now,
        "expiration": now + exp_secs,
        "credentialSubject": {
            "manifestDigest": manifest_digest,
            # CBC = (chainId, contractAddress): both fields must be inside
            # the signed payload, or a VC issued for one chain/contract
            # pair can be replayed against a verifier expecting a
            # different chain that happens to share a contract address.
            "contractAddress": contract_address.lower(),
            "chainId": chain_id,
            "issuerPublicKeyBase64": pubkey_b64,
            # Lets a verifier fetch the issuer's DID Document and tie the
            # embedded signing key back to what was actually registered
            # on-chain for this issuer, instead of trusting whatever key
            # the VC itself claims to have been signed with.
            "didDocCid": did_doc_cid,
        }
    }
    return payload

def sign_vc(signer: Signer, payload: dict) -> VC:
    vcid = vc_id_from_payload(payload)
    body = canonicalize(payload)
    sig = signer.sign(body)
    return VC(vc_id=vcid, payload=payload, signature=sig)

def verify_vc(vc: VC) -> bool:
    pub = vc.payload["credentialSubject"]["issuerPublicKeyBase64"]
    body = canonicalize(vc.payload)
    return verify_ed25519(pub, body, vc.signature)
