#!/usr/bin/env bash
# Demonstrate replay attack failure by pushing an image to two registries.
# Usage: replay_demo.sh IMAGE REG1 REG2 VC_CID DIGEST CONTRACT1 CONTRACT2 VERIFY_URL
set -euo pipefail
IMAGE=$1
REG1=$2
REG2=$3
VC_CID=$4
DIGEST=$5
CONTRACT1=$6
CONTRACT2=$7
VERIFY_URL=$8

# Push to first registry
FULL1=$REG1/$IMAGE
docker push $FULL1
# Tag and push same image to second registry
FULL2=$REG2/$IMAGE
docker tag $FULL1 $FULL2
docker push $FULL2

echo "Verifying image in registry1 (should pass)"
curl -s $VERIFY_URL -H 'Content-Type: application/json' \
  -d '{"manifest_digest":"'$DIGEST'","contract_address":"'$CONTRACT1'","vc_cid":"'$VC_CID'"}'

echo "Verifying image in registry2 with original VC (should fail)"
curl -s $VERIFY_URL -H 'Content-Type: application/json' \
  -d '{"manifest_digest":"'$DIGEST'","contract_address":"'$CONTRACT2'","vc_cid":"'$VC_CID'"}'
