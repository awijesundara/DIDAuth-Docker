#!/usr/bin/env bash
set -euo pipefail
API="http://127.0.0.1:8080"
KEY="${ISSUER_API_KEY:-supersecret}"
CID="${1:?CID}"
VCID="${2:?VCID}"
curl -sf -X POST "$API/vc/record" -H "x-api-key: $KEY" -H "Content-Type: application/json" \
  -d "$(jq -n --arg cid "$CID" --arg vcid "$VCID" '{vc_cid:$cid, vc_id:$vcid}')" | jq .
