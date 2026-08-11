#!/usr/bin/env bash
# Demonstrate replay attack failure by pushing an image to two registries
# and, separately, by replaying the same (digest, contract) pair under a
# different chain id -- the two halves of CBC = (chainId, contractAddress).
# Usage: replay_demo.sh IMAGE REG1 REG2 VC_CID DIGEST CONTRACT1 CONTRACT2 CHAIN1 CHAIN2 VERIFY_URL
set -euo pipefail
IMAGE=$1
REG1=$2
REG2=$3
VC_CID=$4
DIGEST=$5
CONTRACT1=$6
CONTRACT2=$7
CHAIN1=$8
CHAIN2=$9
VERIFY_URL=${10}

# Push to first registry
FULL1=$REG1/$IMAGE
docker push $FULL1
# Tag and push same image to second registry
FULL2=$REG2/$IMAGE
docker tag $FULL1 $FULL2
docker push $FULL2

echo "Verifying image in registry1, correct CBC (should pass)"
curl -s $VERIFY_URL -H 'Content-Type: application/json' \
  -d '{"manifest_digest":"'$DIGEST'","contract_address":"'$CONTRACT1'","chain_id":'$CHAIN1',"vc_cid":"'$VC_CID'"}'

echo "Verifying image in registry2 with original VC, different contract (should fail: contract mismatch)"
curl -s $VERIFY_URL -H 'Content-Type: application/json' \
  -d '{"manifest_digest":"'$DIGEST'","contract_address":"'$CONTRACT2'","chain_id":'$CHAIN1',"vc_cid":"'$VC_CID'"}'

echo "Verifying with original VC, same contract, different chain (should fail: chain mismatch)"
curl -s $VERIFY_URL -H 'Content-Type: application/json' \
  -d '{"manifest_digest":"'$DIGEST'","contract_address":"'$CONTRACT1'","chain_id":'$CHAIN2',"vc_cid":"'$VC_CID'"}'
