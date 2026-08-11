import hmac
import os, time
from fastapi import FastAPI, HTTPException, Header, Response
from pydantic import BaseModel
from dotenv import load_dotenv
from cachetools import TTLCache
from prometheus_client import Counter, Histogram, generate_latest
from web3 import Web3
from did_utils import new_did
from vc_utils import make_vc, sign_vc, verify_vc, vc_id_from_payload, VC
from ipfs_utils import init as ipfs_init, add_json, cat
from chain_utils import connect, to_bytes32, tx_send
from signer import LocalSigner, KMSSigner
from secrets_utils import load_api_key, rotate_api_key

load_dotenv()
ipfs_init(os.getenv("IPFS_API"))
API_KEY = load_api_key()
CONTRACT_ADDRESS = os.getenv("CONTRACT_ADDRESS")
# Clock-skew allowance for issuedAt/expiration checks, matching the
# manuscript's delta=5s -- verifier and issuer clocks are assumed
# NTP-synchronized but not identical to the second.
CLOCK_SKEW_SECS = 5

app = FastAPI(title="DID Docker VC Issuer/Verifier")

STATE = {"did": None, "seckey": None, "pubkey": None, "issuerDidB32": None,
         "didCidB32": None, "didDocCid": None, "signer": None}
_CHAIN_ID_CACHE = {"value": None}

REV_CACHE = TTLCache(maxsize=1024, ttl=30)
VERIFY_REQS = Counter("vc_verify_requests_total", "Total VC verification requests")
VERIFY_FAILS = Counter("vc_verify_failures_total", "VC verification failures")
VERIFY_DUR = Histogram("vc_verify_duration_seconds", "VC verification duration")
CACHE_HITS = Counter("vc_verify_cache_hits_total", "Revocation cache hits")

class DIDRegisterReq(BaseModel):
    did_doc: dict

class IssueReq(BaseModel):
    manifest_digest: str
    contract_address: str

class RecordReq(BaseModel):
    vc_cid: str
    vc_id: str

class VerifyReq(BaseModel):
    manifest_digest: str
    contract_address: str
    chain_id: int
    vc_cid: str

class RevokeReq(BaseModel):
    vc_id: str

class RotateReq(BaseModel):
    new_key: str

def get_chain_id() -> int:
    # Cached after first lookup: the RPC endpoint's chain doesn't change
    # for the lifetime of the process, and this is called on every
    # /vc/issue -- an uncached call would add an RPC round-trip per issuance.
    if _CHAIN_ID_CACHE["value"] is None:
        w3, _, _ = connect()
        _CHAIN_ID_CACHE["value"] = w3.eth.chain_id
    return _CHAIN_ID_CACHE["value"]

def _extract_pubkey_from_doc(did_doc: dict) -> str | None:
    methods = did_doc.get("verificationMethod") or []
    if methods and isinstance(methods, list) and isinstance(methods[0], dict):
        return methods[0].get("publicKeyBase64")
    return None

def require_api_key(x_api_key: str | None):
    # Use a constant-time comparison: a plain `!=` short-circuits on the
    # first mismatching byte, which leaks timing information an attacker
    # can use to recover the key byte-by-byte.
    if x_api_key is None or not hmac.compare_digest(x_api_key, API_KEY):
        raise HTTPException(status_code=401, detail="invalid api key")

@app.post("/did/register")
def did_register(req: DIDRegisterReq, x_api_key: str | None = Header(None)):
    require_api_key(x_api_key)
    dk = new_did()
    if os.getenv("SIGNER_BACKEND") == "kms":
        STATE["signer"] = KMSSigner(os.getenv("KMS_KEY_ID", ""))
    else:
        STATE["signer"] = LocalSigner(dk.seckey_b64)
    # The published DID Document's verificationMethod/id must reflect the
    # key we actually just generated and will sign VCs with -- not
    # whatever the caller happened to pass in req.did_doc. Publishing an
    # unrelated caller-supplied document would break the DID-integrity
    # tie-back at verification time: the verifier compares the VC's
    # signing key against this document's key, so they have to genuinely
    # match. Extra caller-supplied fields (e.g. service endpoints) are
    # preserved; id/verificationMethod are always overwritten.
    did_doc = dict(req.did_doc)
    did_doc["id"] = dk.did
    did_doc["verificationMethod"] = [{
        "id": f"{dk.did}#key-1",
        "type": "Ed25519VerificationKey2020",
        "controller": dk.did,
        "publicKeyBase64": dk.pubkey_b64,
    }]
    cid = add_json(did_doc)
    STATE["did"] = dk.did
    STATE["seckey"] = dk.seckey_b64
    STATE["pubkey"] = dk.pubkey_b64
    STATE["didDocCid"] = cid
    w3, c, acct = connect()
    tx = c.functions.registerDID(to_bytes32(dk.did), to_bytes32(cid)).build_transaction({"from": acct.address})
    tx_send(w3, acct, tx)
    STATE["issuerDidB32"] = to_bytes32(dk.did)
    STATE["didCidB32"] = to_bytes32(cid)
    return {"did": dk.did, "didDocCid": cid, "pubkey_b64": dk.pubkey_b64}

@app.post("/vc/issue")
def issue(req: IssueReq, x_api_key: str | None = Header(None)):
    require_api_key(x_api_key)
    if not STATE["did"]:
        raise HTTPException(400, "register DID first")
    # chain_id comes from the RPC connection the issuer itself is using,
    # not from the request body -- the issuer must stamp the chain it is
    # actually anchoring this VC's lifecycle on, not a value the caller
    # could otherwise spoof.
    payload = make_vc(
        STATE["did"], STATE["pubkey"], req.manifest_digest, req.contract_address,
        get_chain_id(), STATE["didDocCid"],
    )
    vc = sign_vc(STATE["signer"], payload)
    obj = {"vcId": vc.vc_id, "vc": vc.payload, "proof": {"type":"Ed25519Signature2020","sigBase64": vc.signature}}
    vc_cid = add_json(obj)
    return {"vc_id": vc.vc_id, "ipfs_cid": vc_cid, "vc": obj}

@app.post("/vc/record")
def record(req: RecordReq, x_api_key: str | None = Header(None)):
    require_api_key(x_api_key)
    w3, c, acct = connect()
    tx = c.functions.recordVC(
        to_bytes32(req.vc_id), STATE["issuerDidB32"], to_bytes32(req.vc_cid)
    ).build_transaction({"from": acct.address})
    r = tx_send(w3, acct, tx)
    return {"status": "recorded", "tx": r.transactionHash.hex()}

@app.post("/vc/revoke")
def revoke(req: RevokeReq, x_api_key: str | None = Header(None)):
    require_api_key(x_api_key)
    w3, c, acct = connect()
    tx = c.functions.revokeVC(to_bytes32(req.vc_id)).build_transaction({"from": acct.address})
    r = tx_send(w3, acct, tx)
    return {"status":"revoked","tx": r.transactionHash.hex()}

@app.post("/apikey/rotate")
def api_key_rotate(req: RotateReq, x_api_key: str | None = Header(None)):
    global API_KEY
    require_api_key(x_api_key)
    rotate_api_key(req.new_key)
    API_KEY = req.new_key
    return {"status": "rotated"}

@app.post("/vc/verify")
def verify(req: VerifyReq):
    start = time.time()
    VERIFY_REQS.inc()
    try:
        obj = cat(req.vc_cid)
        # Recompute vc_id from the fetched payload rather than trusting
        # obj["vcId"] as stored on IPFS: IPFS content is attacker-postable
        # (anyone can pin arbitrary JSON), so a self-declared "vcId" field
        # inside that JSON is not evidence of anything. If we keyed the
        # on-chain recorded/revoked lookup off that untrusted field, an
        # attacker could pin a blob whose payload/signature they fully
        # control but whose declared vcId happens to match some other,
        # legitimately-recorded VC, and inherit its recorded/not-revoked
        # status. The on-chain key must be derived server-side from the
        # actual payload content.
        payload = obj["vc"]
        vc_id = vc_id_from_payload(payload)
        V = VC(vc_id=vc_id, payload=payload, signature=obj["proof"]["sigBase64"])
        if not verify_vc(V):
            raise HTTPException(400, "bad signature")
        subject = V.payload["credentialSubject"]
        if subject["manifestDigest"] != req.manifest_digest:
            raise HTTPException(400, "digest mismatch")
        if subject["contractAddress"].lower() != req.contract_address.lower():
            raise HTTPException(400, "contract mismatch")
        # CBC = (chainId, contractAddress): contract-address equality alone
        # is not replay-resistant across chains that happen to reuse the
        # same address (e.g. via CREATE2, or simple coincidence on two
        # independent testnets) -- both halves of the pair must match the
        # verifier's own expected context.
        if subject.get("chainId") != req.chain_id:
            raise HTTPException(400, "chain mismatch")
        now = int(time.time())
        if now + CLOCK_SKEW_SECS < V.payload["issuedAt"]:
            raise HTTPException(400, "not yet valid")
        if now >= V.payload["expiration"] + CLOCK_SKEW_SECS:
            raise HTTPException(400, "expired")

        cached = REV_CACHE.get(vc_id)
        if cached:
            recorded, revoked = cached
            CACHE_HITS.inc()
        else:
            w3, c, _ = connect()
            recorded = c.functions.isVCRecorded(to_bytes32(vc_id)).call()
            revoked  = c.functions.isVCRevoked(to_bytes32(vc_id)).call()
            REV_CACHE[vc_id] = (recorded, revoked)

        if not recorded:
            return {"vc_id": vc_id, "recorded": recorded, "revoked": revoked, "valid": False}

        # DID-integrity tie-back: confirm (a) this vcId was actually
        # recorded under the issuer DID the VC itself claims, and (b) the
        # signing key embedded in the VC matches the key published in the
        # DID Document that this issuer registered on-chain -- not merely
        # a key of the attacker's choosing embedded in a well-formed VC.
        w3, c, _ = connect()
        issuer_did = V.payload["issuer"]
        recorded_issuer_hash = c.functions.getVCIssuer(to_bytes32(vc_id)).call()
        if recorded_issuer_hash != to_bytes32(issuer_did):
            raise HTTPException(400, "VC issuer does not match on-chain record")
        did_doc_cid = subject.get("didDocCid")
        if not did_doc_cid:
            raise HTTPException(400, "missing didDocCid")
        on_chain_doc_hash = c.functions.didCid(recorded_issuer_hash).call()
        if on_chain_doc_hash != Web3.keccak(text=did_doc_cid):
            raise HTTPException(400, "DID document CID does not match on-chain registration")
        did_doc = cat(did_doc_cid)
        doc_pubkey = _extract_pubkey_from_doc(did_doc)
        if not doc_pubkey or doc_pubkey != subject["issuerPublicKeyBase64"]:
            raise HTTPException(400, "VC signing key not bound to registered DID document")

        return {"vc_id": vc_id, "recorded": recorded, "revoked": revoked, "valid": recorded and not revoked}
    except HTTPException:
        VERIFY_FAILS.inc()
        raise
    finally:
        VERIFY_DUR.observe(time.time() - start)

@app.get("/metrics")
def metrics():
    return Response(generate_latest(), media_type="text/plain")
