# DID + VC Contract-Bound Container Image PoC

This PoC binds an OCI image manifest digest and the issuing smart contract address into a Verifiable Credential (VC), stores the VC on IPFS, and records/revokes its lifecycle on an Arbitrum Sepolia smart contract. A FastAPI service issues and verifies VCs.

## 1) Deploy the contract

```bash
cd contracts-hardhat
cp .env.example .env   # fill ARBITRUM_SEPOLIA_RPC and DEPLOYER_PK
npm i
npm run build
npm run deploy:arb
# Note the printed address, export it as CONTRACT_ADDRESS in your shell
```

## 2) Start IPFS (Kubo)

```bash
docker run -d --name ipfs -p 5001:5001 ipfs/kubo:latest
```

## 3) Run the FastAPI service

```bash
cd issuer-api
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # fill RPC_URL, CONTRACT_ADDRESS, DEPLOYER_PK (same key), IPFS_API, ISSUER_API_KEY
uvicorn app:app --reload --port 8080
```

## 4) Build a demo image & get its OCI digest

```bash
cd ..
./scripts/build_demo_image.sh
DIGEST=$(./scripts/extract_digest.sh local/demo:latest)
export CONTRACT_ADDRESS=0x<your-deployed-registry>
export ISSUER_API_KEY=supersecret
```

## 5) Issue + record a VC

```bash
./scripts/issue_vc.sh "$DIGEST"
# outputs vc_issue.json with vc_id and ipfs_cid
```

## 6) Verify and Revoke

```bash
CID=$(jq -r .ipfs_cid vc_issue.json)
curl -s -X POST http://127.0.0.1:8080/vc/verify -H "Content-Type: application/json"   -d "{"manifest_digest":"$DIGEST","contract_address":"$CONTRACT_ADDRESS","vc_cid":"$CID"}" | jq .

VCID=$(jq -r .vc_id vc_issue.json)
./scripts/revoke_vc.sh "$VCID"

curl -s -X POST http://127.0.0.1:8080/vc/verify -H "Content-Type: application/json"   -d "{"manifest_digest":"$DIGEST","contract_address":"$CONTRACT_ADDRESS","vc_cid":"$CID"}" | jq .
```

## Notes
- This PoC uses a minimal `did:web`-style DID and Ed25519 signatures. Replace with your production DID method and key management as needed.
- IPFS JSON responses are assumed; CID tampering breaks integrity by design.
This repo now includes a Kubernetes ValidatingWebhook server, Helm chart, and a sample Kyverno policy wrapping `/vc/verify`.






Deploy contract: contracts-hardhat → fill .env, npm i, npm run build, npm run deploy:arb.

Start IPFS: docker run -d --name ipfs -p 5001:5001 ipfs/kubo:latest.

Run API: issuer-api → create venv, pip install -r requirements.txt, fill .env, uvicorn app:app --port 8080.

Build demo image: ./scripts/build_demo_image.sh then DIGEST=$(./scripts/extract_digest.sh local/demo:latest).

Issue+record VC: export CONTRACT_ADDRESS=0x...; export ISSUER_API_KEY=supersecret; ./scripts/issue_vc.sh "$DIGEST".

Verify / revoke using the vc/verify endpoint and scripts/revoke_vc.sh.