#!/usr/bin/env bash
# Demonstrates that the same signed VC is accepted only by a verifier whose
# operator-configured CBC matches the VC. VERIFY_A and VERIFY_B must point to
# independently configured verifier deployments.
set -euo pipefail

VC_CID=${1:?VC CID}
DIGEST=${2:?sha256 manifest digest}
VERIFY_A=${3:?verifier URL for the issuing CBC}
VERIFY_B=${4:?verifier URL for a different CBC}

payload=$(jq -n --arg digest "$DIGEST" --arg cid "$VC_CID" \
  '{manifest_digest:$digest, vc_cid:$cid}')

echo "Issuing CBC (expected valid)"
curl -sf -X POST "$VERIFY_A" -H 'Content-Type: application/json' -d "$payload" | jq .

echo "Different operator-configured CBC (expected rejection)"
if curl -sf -X POST "$VERIFY_B" -H 'Content-Type: application/json' -d "$payload"; then
  echo "ERROR: replay was unexpectedly accepted" >&2
  exit 1
fi
echo "Replay rejected"
