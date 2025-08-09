#!/usr/bin/env bash
set -euo pipefail
API="http://127.0.0.1:8080"
KEY="${ISSUER_API_KEY:-supersecret}"
CONTRACT="${CONTRACT_ADDRESS:?export CONTRACT_ADDRESS first}"
DIGEST="${1:?pass manifest digest (e.g., sha256:abcd...)}"

curl -s -X POST "$API/did/register" -H "x-api-key: $KEY"   -H "Content-Type: application/json" -d '{"did_doc":{"id":"did:web:example.org","verificationMethod":[]}}' >/dev/null

curl -s -X POST "$API/vc/issue" -H "x-api-key: $KEY"   -H "Content-Type: application/json"   -d "{"manifest_digest":"$DIGEST","contract_address":"$CONTRACT"}" | tee vc_issue.json

VCID=$(jq -r .vc_id vc_issue.json)
CID=$(jq -r .ipfs_cid vc_issue.json)

echo "VCID=$VCID"
echo "CID=$CID"

curl -s -X POST "$API/vc/record" -H "x-api-key: $KEY"   -H "Content-Type: application/json"   -d "{"vc_cid":"$CID","vc_id":"$VCID"}" | jq .
