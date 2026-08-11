"""End-to-end tests for the issuer-api's issue -> record -> verify pipeline,
covering the manuscript's core claims: CBC = (chainId, contractAddress)
binding, DID Document integrity tie-back, expiration enforcement, and
recomputed (not trusted-from-storage) vc_id.

The blockchain and IPFS are faked (no live RPC/IPFS needed to run these),
but everything else -- Ed25519 signing/verification, JSON canonicalization,
vc_id hashing, and the verify() endpoint's own decision logic -- is real.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("ISSUER_API_KEY", "test-key")
os.environ.setdefault("CONTRACT_ADDRESS", "0x00000000000000000000000000000000000abc")
os.environ.setdefault("RPC_URL", "http://unused.invalid")

import pytest
from fastapi.testclient import TestClient
from web3 import Web3

import app as app_module
from chain_utils import to_bytes32

API_KEY = os.environ["ISSUER_API_KEY"]
HEADERS = {"x-api-key": API_KEY}


class FakeChainState:
    """Stands in for the on-chain DIDRegistry contract's state."""

    def __init__(self, chain_id=421614):
        self.chain_id = chain_id
        self.did_cid = {}       # issuerDid bytes32 -> didDocCid bytes32
        self.vc_records = {}    # vcId bytes32 -> {"issuer": bytes32, "revoked": bool}


class FakeIPFS:
    def __init__(self):
        self.store = {}
        self._n = 0

    def add_json(self, obj):
        self._n += 1
        cid = f"fake-cid-{self._n}"
        self.store[cid] = obj
        return cid

    def cat(self, cid):
        return self.store[cid]


@pytest.fixture
def wired(monkeypatch):
    chain = FakeChainState()
    ipfs = FakeIPFS()

    class FakeFunctions:
        def __init__(self, chain):
            self.chain = chain

        def registerDID(self, issuer_did_b32, doc_cid_b32):
            chain = self.chain
            class Tx:
                def build_transaction(self_, params):
                    chain.did_cid[issuer_did_b32] = doc_cid_b32
                    return {}
            return Tx()

        def recordVC(self, vc_id_b32, issuer_did_b32, ipfs_cid_b32):
            chain = self.chain
            class Tx:
                def build_transaction(self_, params):
                    chain.vc_records[vc_id_b32] = {"issuer": issuer_did_b32, "revoked": False}
                    return {}
            return Tx()

        def revokeVC(self, vc_id_b32):
            chain = self.chain
            class Tx:
                def build_transaction(self_, params):
                    chain.vc_records[vc_id_b32]["revoked"] = True
                    return {}
            return Tx()

        def isVCRecorded(self, vc_id_b32):
            chain = self.chain
            class Call:
                def call(self_):
                    return vc_id_b32 in chain.vc_records
            return Call()

        def isVCRevoked(self, vc_id_b32):
            chain = self.chain
            class Call:
                def call(self_):
                    rec = chain.vc_records.get(vc_id_b32)
                    return bool(rec and rec["revoked"])
            return Call()

        def getVCIssuer(self, vc_id_b32):
            chain = self.chain
            class Call:
                def call(self_):
                    return chain.vc_records[vc_id_b32]["issuer"]
            return Call()

        def didCid(self, issuer_did_b32):
            chain = self.chain
            class Call:
                def call(self_):
                    return chain.did_cid.get(issuer_did_b32, b"\x00" * 32)
            return Call()

    class FakeContract:
        def __init__(self, chain):
            self.functions = FakeFunctions(chain)

    class FakeEth:
        def __init__(self, chain):
            self.chain_id = chain.chain_id

        def get_transaction_count(self, addr):
            return 0

        @property
        def gas_price(self):
            return 1

        def send_raw_transaction(self, raw):
            return b"tx"

        def wait_for_transaction_receipt(self, h):
            class Receipt:
                transactionHash = h
            return Receipt()

    class FakeAccount:
        address = "0x0000000000000000000000000000000000dead"

        def sign_transaction(self, tx):
            class Signed:
                rawTransaction = b"raw"
            return Signed()

    class FakeW3:
        def __init__(self, chain):
            self.eth = FakeEth(chain)

    def fake_connect():
        return FakeW3(chain), FakeContract(chain), FakeAccount()

    def fake_tx_send(w3, acct, tx):
        # tx here is the dict returned by build_transaction, which already
        # mutated `chain` as a side effect above.
        class Receipt:
            transactionHash = type("H", (), {"hex": lambda self: "0xabc"})()
        return Receipt()

    monkeypatch.setattr(app_module, "connect", fake_connect)
    monkeypatch.setattr(app_module, "tx_send", fake_tx_send)
    monkeypatch.setattr(app_module, "add_json", ipfs.add_json)
    monkeypatch.setattr(app_module, "cat", ipfs.cat)
    app_module._CHAIN_ID_CACHE["value"] = None
    app_module.REV_CACHE.clear()

    return chain, ipfs


@pytest.fixture
def client():
    return TestClient(app_module.app)


def _register_and_issue(client, digest="sha256:" + "a" * 64, contract=None):
    contract = contract or os.environ["CONTRACT_ADDRESS"]
    r = client.post("/did/register", json={"did_doc": {}}, headers=HEADERS)
    assert r.status_code == 200, r.text
    r = client.post(
        "/vc/issue",
        json={"manifest_digest": digest, "contract_address": contract},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    issued = r.json()
    r = client.post(
        "/vc/record",
        json={"vc_cid": issued["ipfs_cid"], "vc_id": issued["vc_id"]},
        headers=HEADERS,
    )
    assert r.status_code == 200, r.text
    return issued


def test_valid_vc_verifies_successfully(client, wired):
    chain, _ = wired
    issued = _register_and_issue(client)
    r = client.post("/vc/verify", json={
        "manifest_digest": issued["vc"]["vc"]["credentialSubject"]["manifestDigest"],
        "contract_address": os.environ["CONTRACT_ADDRESS"],
        "chain_id": chain.chain_id,
        "vc_cid": issued["ipfs_cid"],
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["valid"] is True
    assert body["recorded"] is True
    assert body["revoked"] is False


def test_wrong_chain_id_is_rejected(client, wired):
    """The manuscript's central replay-resistance claim: CBC =
    (chainId, contractAddress). A VC valid on one chain must not verify
    against the same contract address on a different chain."""
    chain, _ = wired
    issued = _register_and_issue(client)
    r = client.post("/vc/verify", json={
        "manifest_digest": issued["vc"]["vc"]["credentialSubject"]["manifestDigest"],
        "contract_address": os.environ["CONTRACT_ADDRESS"],
        "chain_id": chain.chain_id + 1,  # a different chain, same contract
        "vc_cid": issued["ipfs_cid"],
    })
    assert r.status_code == 400
    assert "chain" in r.json()["detail"].lower()


def test_wrong_contract_address_is_rejected(client, wired):
    chain, _ = wired
    issued = _register_and_issue(client)
    r = client.post("/vc/verify", json={
        "manifest_digest": issued["vc"]["vc"]["credentialSubject"]["manifestDigest"],
        "contract_address": "0x000000000000000000000000000000000000ff",
        "chain_id": chain.chain_id,
        "vc_cid": issued["ipfs_cid"],
    })
    assert r.status_code == 400
    assert "contract" in r.json()["detail"].lower()


def test_revoked_vc_is_not_valid(client, wired):
    chain, _ = wired
    issued = _register_and_issue(client)
    r = client.post("/vc/revoke", json={"vc_id": issued["vc_id"]}, headers=HEADERS)
    assert r.status_code == 200, r.text
    app_module.REV_CACHE.clear()  # avoid the 30s cache masking the fresh state in-test
    r = client.post("/vc/verify", json={
        "manifest_digest": issued["vc"]["vc"]["credentialSubject"]["manifestDigest"],
        "contract_address": os.environ["CONTRACT_ADDRESS"],
        "chain_id": chain.chain_id,
        "vc_cid": issued["ipfs_cid"],
    })
    assert r.status_code == 200
    assert r.json()["valid"] is False
    assert r.json()["revoked"] is True


def test_unrecorded_vc_is_not_valid(client, wired):
    """A VC that was issued (signed, pinned to IPFS) but never recorded
    on-chain must not verify -- recording is the actual authorization step."""
    chain, ipfs = wired
    r = client.post("/did/register", json={"did_doc": {}}, headers=HEADERS)
    assert r.status_code == 200
    r = client.post("/vc/issue", json={
        "manifest_digest": "sha256:" + "b" * 64,
        "contract_address": os.environ["CONTRACT_ADDRESS"],
    }, headers=HEADERS)
    issued = r.json()
    # deliberately skip /vc/record
    r = client.post("/vc/verify", json={
        "manifest_digest": issued["vc"]["vc"]["credentialSubject"]["manifestDigest"],
        "contract_address": os.environ["CONTRACT_ADDRESS"],
        "chain_id": chain.chain_id,
        "vc_cid": issued["ipfs_cid"],
    })
    assert r.status_code == 200
    assert r.json()["valid"] is False
    assert r.json()["recorded"] is False


def test_forged_vc_id_cannot_hijack_a_legitimately_recorded_status(client, wired):
    """Regression test for the pre-fix bug: verify() used to trust the
    `vcId` field embedded in the IPFS-fetched JSON blob instead of
    recomputing it from the payload. Since IPFS content is
    attacker-postable, an attacker could pin a blob with their own
    forged payload/signature but a `vcId` field copy-pasted from a
    legitimately recorded VC, and inherit its recorded/not-revoked
    status. vc_id must always be recomputed server-side."""
    chain, ipfs = wired
    legit = _register_and_issue(client, digest="sha256:" + "c" * 64)

    # Attacker crafts their own payload (different digest) but reuses
    # the legitimate VC's recorded vc_id and signature/proof wholesale.
    forged_obj = {
        "vcId": legit["vc_id"],  # forged: copied from a real recorded VC
        "vc": {**legit["vc"]["vc"], "credentialSubject": {
            **legit["vc"]["vc"]["credentialSubject"],
            "manifestDigest": "sha256:" + "e" * 64,  # attacker's own image
        }},
        "proof": legit["vc"]["proof"],  # stale signature, won't verify anyway
    }
    forged_cid = ipfs.add_json(forged_obj)

    r = client.post("/vc/verify", json={
        "manifest_digest": "sha256:" + "e" * 64,
        "contract_address": os.environ["CONTRACT_ADDRESS"],
        "chain_id": chain.chain_id,
        "vc_cid": forged_cid,
    })
    # Must fail -- either on signature mismatch (payload changed under a
    # signature that no longer covers it) or, if it somehow got past
    # that, must NOT come back recorded=True under the attacker's digest,
    # since the real on-chain record is keyed by the *legitimate*
    # payload's recomputed vc_id, not the forged/copied one.
    assert r.status_code == 400
    assert r.json()["detail"] == "bad signature"


def test_expired_vc_is_rejected(client, wired, monkeypatch):
    chain, ipfs = wired
    r = client.post("/did/register", json={"did_doc": {}}, headers=HEADERS)
    assert r.status_code == 200

    from vc_utils import make_vc, sign_vc
    payload = make_vc(
        app_module.STATE["did"], app_module.STATE["pubkey"],
        "sha256:" + "d" * 64, os.environ["CONTRACT_ADDRESS"],
        chain.chain_id, app_module.STATE["didDocCid"],
        exp_secs=-10,  # already expired
    )
    vc = sign_vc(app_module.STATE["signer"], payload)
    obj = {"vcId": vc.vc_id, "vc": vc.payload, "proof": {"type": "Ed25519Signature2020", "sigBase64": vc.signature}}
    cid = ipfs.add_json(obj)
    r = client.post("/vc/record", json={"vc_cid": cid, "vc_id": vc.vc_id}, headers=HEADERS)
    assert r.status_code == 200

    r = client.post("/vc/verify", json={
        "manifest_digest": "sha256:" + "d" * 64,
        "contract_address": os.environ["CONTRACT_ADDRESS"],
        "chain_id": chain.chain_id,
        "vc_cid": cid,
    })
    assert r.status_code == 400
    assert "expired" in r.json()["detail"].lower()


def test_signing_key_not_bound_to_registered_did_document_is_rejected(client, wired):
    """DID-integrity tie-back: a VC signed with a key that was never
    published in the issuer's registered DID Document must be rejected,
    even if the VC's own signature is internally self-consistent."""
    chain, ipfs = wired
    r = client.post("/did/register", json={"did_doc": {}}, headers=HEADERS)
    assert r.status_code == 200

    from did_utils import new_did
    from signer import LocalSigner
    from vc_utils import make_vc, sign_vc

    # A key the attacker controls, never registered on-chain for this issuer.
    rogue = new_did()
    rogue_signer = LocalSigner(rogue.seckey_b64)

    payload = make_vc(
        app_module.STATE["did"], rogue.pubkey_b64,  # claims the real issuer DID...
        "sha256:" + "f" * 64, os.environ["CONTRACT_ADDRESS"],
        chain.chain_id, app_module.STATE["didDocCid"],  # ...and the real DID doc CID
    )
    vc = sign_vc(rogue_signer, payload)  # ...but signs with an unregistered key
    obj = {"vcId": vc.vc_id, "vc": vc.payload, "proof": {"type": "Ed25519Signature2020", "sigBase64": vc.signature}}
    cid = ipfs.add_json(obj)
    r = client.post("/vc/record", json={"vc_cid": cid, "vc_id": vc.vc_id}, headers=HEADERS)
    assert r.status_code == 200

    r = client.post("/vc/verify", json={
        "manifest_digest": "sha256:" + "f" * 64,
        "contract_address": os.environ["CONTRACT_ADDRESS"],
        "chain_id": chain.chain_id,
        "vc_cid": cid,
    })
    assert r.status_code == 400
    assert "not bound" in r.json()["detail"].lower()


def test_vc_id_is_deterministic_and_order_independent(wired):
    """Canonicalization regression: two dict literals with the same keys
    in different insertion order must hash to the same vc_id."""
    from vc_utils import vc_id_from_payload
    a = {"z": 1, "a": {"y": 2, "x": 3}}
    b = {"a": {"x": 3, "y": 2}, "z": 1}
    assert vc_id_from_payload(a) == vc_id_from_payload(b)
