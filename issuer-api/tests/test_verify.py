"""Manuscript-aligned issuer and verifier security tests."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("ISSUER_API_KEY", "test-key")
os.environ.setdefault("CONTRACT_ADDRESS", "0x00000000000000000000000000000000000abc")
os.environ.setdefault("RPC_URL", "http://unused.invalid")

import pytest
from fastapi.testclient import TestClient
import app as service

HEADERS = {"x-api-key": os.environ["ISSUER_API_KEY"]}


class Store:
    chain_id = 421614


@pytest.fixture(autouse=True)
def wired(monkeypatch):
    state = Store()
    state.dids, state.vcs, state.blobs = {}, {}, {}

    class Call:
        def __init__(self, value): self.value = value
        def call(self): return self.value()
        def build_transaction(self, _): self.value(); return {}

    class Functions:
        def registerDID(self, did, cid): return Call(lambda: state.dids.__setitem__(did, cid))
        def recordVC(self, vcid, did, cid): return Call(lambda: state.vcs.__setitem__(vcid, {"issuer": did, "revoked": False, "cid": cid}))
        def revokeVC(self, vcid): return Call(lambda: state.vcs[vcid].__setitem__("revoked", True))
        def isVCRecorded(self, vcid): return Call(lambda: vcid in state.vcs)
        def isVCRevoked(self, vcid): return Call(lambda: state.vcs.get(vcid, {}).get("revoked", False))
        def getVCIssuer(self, vcid): return Call(lambda: state.vcs[vcid]["issuer"])
        def getVCRecord(self, vcid): return Call(lambda: (state.vcs[vcid]["issuer"], state.vcs[vcid]["cid"], 0, True, state.vcs[vcid]["revoked"]))
        def didCid(self, did): return Call(lambda: state.dids.get(did, b"\0" * 32))

    class Eth: chain_id = state.chain_id
    class W3: eth = Eth()
    class Contract: functions = Functions()
    class Account: address = "0x0000000000000000000000000000000000dead"
    class Receipt:
        transactionHash = type("Hash", (), {"hex": lambda self: "0xabc"})()

    def add_json(value):
        cid = f"bafy-test-{len(state.blobs) + 1}"
        state.blobs[cid] = value
        return cid

    monkeypatch.setattr(service, "connect", lambda: (W3(), Contract(), Account()))
    monkeypatch.setattr(service, "tx_send", lambda *_: Receipt())
    monkeypatch.setattr(service, "add_json", add_json)
    monkeypatch.setattr(service, "cat", lambda cid: state.blobs[cid])
    service._CHAIN_ID_CACHE["value"] = None
    service.REV_CACHE.clear()
    service.STATE.update({"did": None, "seckey": None, "pubkey": None, "issuerDidB32": None,
                          "didCidB32": None, "didDocCid": None, "signer": None})
    return state


@pytest.fixture
def client():
    return TestClient(service.app)


def issue_and_record(client, digest="sha256:" + "a" * 64):
    assert client.post("/did/register", json={"did_doc": {}}, headers=HEADERS).status_code == 200
    issued = client.post("/vc/issue", json={"manifest_digest": digest}, headers=HEADERS).json()
    response = client.post("/vc/record", json={"vc_cid": issued["ipfs_cid"], "vc_id": issued["vc_id"]}, headers=HEADERS)
    assert response.status_code == 200, response.text
    return issued


def verify(client, issued, digest=None):
    subject = issued["vc"]["vc"]["credentialSubject"]
    return client.post("/vc/verify", json={
        "manifest_digest": digest or subject["image"]["manifestDigest"],
        "vc_cid": issued["ipfs_cid"],
    })


def test_w3c_did_key_vc_and_valid_lifecycle(client):
    issued = issue_and_record(client)
    payload = issued["vc"]["vc"]
    assert payload["@context"] == ["https://www.w3.org/2018/credentials/v1"]
    assert payload["issuer"].startswith("did:key:z")
    assert payload["credentialSubject"]["cbc"]["chainId"] == 421614
    assert issued["vc"]["proof"]["type"] == "Ed25519Signature2020"
    assert verify(client, issued).json()["valid"] is True


def test_digest_tampering_fails_closed(client):
    issued = issue_and_record(client)
    response = verify(client, issued, "sha256:" + "b" * 64)
    assert response.status_code == 400
    assert response.json()["detail"] == "digest mismatch"


def test_operator_configured_cbc_rejects_cross_context_replay(client, monkeypatch):
    issued = issue_and_record(client)
    monkeypatch.setattr(service, "CONTRACT_ADDRESS", "0x00000000000000000000000000000000000def")
    response = verify(client, issued)
    assert response.status_code == 400
    assert response.json()["detail"] == "contract mismatch"


def test_unrecorded_and_revoked_credentials_are_denied(client):
    assert client.post("/did/register", json={"did_doc": {}}, headers=HEADERS).status_code == 200
    issued = client.post("/vc/issue", json={"manifest_digest": "sha256:" + "c" * 64}, headers=HEADERS).json()
    assert verify(client, issued).json()["valid"] is False
    client.post("/vc/record", json={"vc_cid": issued["ipfs_cid"], "vc_id": issued["vc_id"]}, headers=HEADERS)
    client.post("/vc/revoke", json={"vc_id": issued["vc_id"]}, headers=HEADERS)
    service.REV_CACHE.clear()
    result = verify(client, issued).json()
    assert result["valid"] is False and result["revoked"] is True


def test_stored_vcid_is_not_trusted(client, wired):
    issued = issue_and_record(client)
    forged = dict(issued["vc"])
    forged["vc"] = {**forged["vc"], "credentialSubject": {**forged["vc"]["credentialSubject"],
        "image": {"manifestDigest": "sha256:" + "d" * 64}}}
    cid = f"bafy-test-{len(wired.blobs) + 1}"
    wired.blobs[cid] = forged
    response = client.post("/vc/verify", json={"manifest_digest": "sha256:" + "d" * 64, "vc_cid": cid})
    assert response.status_code == 400
    assert response.json()["detail"] == "bad signature"


def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}
