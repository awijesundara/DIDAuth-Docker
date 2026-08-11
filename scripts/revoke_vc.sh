#!/usr/bin/env bash
set -euo pipefail
API="http://127.0.0.1:8080"
KEY="${ISSUER_API_KEY:-supersecret}"
VCID="${1:?VCID}"
curl -sf -X POST "$API/vc/revoke" -H "x-api-key: $KEY" -H "Content-Type: application/json" \
  -d "$(jq -n --arg vcid "$VCID" '{vc_id:$vcid}')" | jq .
