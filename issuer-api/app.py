import os, time
from fastapi import FastAPI, HTTPException, Header, Response
from pydantic import BaseModel
from dotenv import load_dotenv
from cachetools import TTLCache
from prometheus_client import Counter, Histogram, generate_latest
from did_utils import new_did
from vc_utils import make_vc, sign_vc, verify_vc, VC
from ipfs_utils import init as ipfs_init, add_json, cat
from chain_utils import connect, to_bytes32, tx_send
from signer import LocalSigner, KMSSigner
from secrets_utils import load_api_key, rotate_api_key

load_dotenv()
ipfs_init(os.getenv("IPFS_API"))
API_KEY = load_api_key()
CONTRACT_ADDRESS = os.getenv("CONTRACT_ADDRESS")

app = FastAPI(title="DID Docker VC Issuer/Verifier")

STATE = {"did": None, "seckey": None, "pubkey": None, "issuerDidB32": None, "didCidB32": None, "signer": None}

REV_CACHE = TTLCache(maxsize=1024, ttl=300)
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
    vc_cid: str

class RevokeReq(BaseModel):
    vc_id: str

class RotateReq(BaseModel):
    new_key: str

def require_api_key(x_api_key: str | None):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="invalid api key")

@app.post("/did/register")
def did_register(req: DIDRegisterReq, x_api_key: str | None = Header(None)):
    require_api_key(x_api_key)
    dk = new_did()
    cid = add_json(req.did_doc)
    STATE["did"] = dk.did
    STATE["seckey"] = dk.seckey_b64
    STATE["pubkey"] = dk.pubkey_b64
    if os.getenv("SIGNER_BACKEND") == "kms":
        STATE["signer"] = KMSSigner(os.getenv("KMS_KEY_ID", ""))
    else:
        STATE["signer"] = LocalSigner(dk.seckey_b64)
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
    payload = make_vc(STATE["did"], STATE["pubkey"], req.manifest_digest, req.contract_address)
    vc = sign_vc(STATE["signer"], payload)
    obj = {"vcId": vc.vc_id, "vc": vc.payload, "proof": {"type":"Ed25519Signature2020","sigBase64": vc.signature}}
    vc_cid = add_json(obj)
    return {"vc_id": vc.vc_id, "ipfs_cid": vc_cid, "vc": obj}

@app.post("/vc/record")
def record(req: RecordReq, x_api_key: str | None = Header(None)):
    require_api_key(x_api_key)
    w3, c, acct = connect()
    tx = c.functions.recordVC(to_bytes32(req.vc_id), STATE["issuerDidB32"], to_bytes32(req.vc_cid))         .build_transaction({"from": acct.address})
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
        vc_id = obj["vcId"]
        V = VC(vc_id=vc_id, payload=obj["vc"], signature=obj["proof"]["sigBase64"])
        if not verify_vc(V):
            raise HTTPException(400, "bad signature")
        if V.payload["credentialSubject"]["manifestDigest"] != req.manifest_digest:
            raise HTTPException(400, "digest mismatch")
        if V.payload["credentialSubject"]["contractAddress"].lower() != req.contract_address.lower():
            raise HTTPException(400, "contract mismatch")
        cached = REV_CACHE.get(vc_id)
        if cached:
            recorded, revoked = cached
            CACHE_HITS.inc()
        else:
            w3, c, _ = connect()
            recorded = c.functions.isVCRecorded(to_bytes32(vc_id)).call()
            revoked  = c.functions.isVCRevoked(to_bytes32(vc_id)).call()
            REV_CACHE[vc_id] = (recorded, revoked)
        return {"vc_id": vc_id, "recorded": recorded, "revoked": revoked, "valid": recorded and not revoked}
    except HTTPException:
        VERIFY_FAILS.inc()
        raise
    finally:
        VERIFY_DUR.observe(time.time() - start)

@app.get("/metrics")
def metrics():
    return Response(generate_latest(), media_type="text/plain")
