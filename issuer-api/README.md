# Issuer and verifier API

This FastAPI service implements the manuscript's DID/VC lifecycle and
admission predicate. It generates an Ed25519 `did:key`, publishes its DID
Document and VCs to IPFS, records lifecycle state on-chain, and verifies
credentials for the Kubernetes webhook.

The expected CBC is derived from `RPC_URL` and `CONTRACT_ADDRESS`. Verification
callers submit only the pulled manifest digest and candidate VC CID; they
cannot select the verifier trust context.

The VC identifier is Keccak-256 over the URDNA2015-normalized proof-free W3C
VC. Verification independently recomputes it, binds the proof key to the
on-chain DID Document CID, and checks the signed digest/CBC/time window before
consulting membership and revocation state.

Copy `.env.example` to `.env` and supply all secrets. There is deliberately no
default API key. Use a private authenticated network or mTLS around lifecycle
write endpoints in production.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app:app --host 0.0.0.0 --port 8080
```

OpenAPI documentation is served by FastAPI at `/docs`; health and Prometheus
metrics are available at `/health` and `/metrics`.
