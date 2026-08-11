#!/usr/bin/env bash
set -euo pipefail
API="http://127.0.0.1:8080"
KEY="${ISSUER_API_KEY:-supersecret}"
CONTRACT="${CONTRACT_ADDRESS:?export CONTRACT_ADDRESS first}"
DIGEST="${1:?pass manifest digest (e.g., sha256:abcd...)}"

# Built with `jq -n` rather than shell-interpolated string literals: the
# previous "{"key":"$VAR"}" form produces UNQUOTED JSON keys/values once
# bash concatenates the adjacent quoted/unquoted segments (verified: it
# emits `{manifest_digest:sha256:abc,...}`, not valid JSON), so every
# request here used to fail server-side JSON parsing before this fix.
curl -sf -X POST "$API/did/register" -H "x-api-key: $KEY" -H "Content-Type: application/json" \
  -d '{"did_doc":{"service":[]}}' >/dev/null

curl -sf -X POST "$API/vc/issue" -H "x-api-key: $KEY" -H "Content-Type: application/json" \
  -d "$(jq -n --arg d "$DIGEST" --arg c "$CONTRACT" '{manifest_digest:$d, contract_address:$c}')" \
  | tee vc_issue.json

VCID=$(jq -r .vc_id vc_issue.json)
CID=$(jq -r .ipfs_cid vc_issue.json)

echo "VCID=$VCID"
echo "CID=$CID"

curl -sf -X POST "$API/vc/record" -H "x-api-key: $KEY" -H "Content-Type: application/json" \
  -d "$(jq -n --arg cid "$CID" --arg vcid "$VCID" '{vc_cid:$cid, vc_id:$vcid}')" | jq .
