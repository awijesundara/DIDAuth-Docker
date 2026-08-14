# Threat model

This document defines the security boundary implemented by CBC-Provenance. It
tracks Section 4 and Table 3 of the accompanying manuscript.

## Protected assets

- The integrity and provenance of OCI images admitted to Kubernetes.
- The binding between a manifest digest, issuer DID, and expected CBC.
- The accuracy and freshness of VC membership and revocation state.

The trust anchors are the configured Layer-2 contract, the issuer DID Document
CID registered in that contract, and the operator-provisioned expected CBC.
IPFS indexes and Pod annotations are untrusted discovery metadata.

## Assumptions

- The verifier's `chainId` and `contractAddress` configuration is controlled by
  cluster operators through audited deployment configuration.
- Arbitrum RPC results reflect canonical state after practical finality.
- Verifier clocks are synchronized within the configured five-second skew.
- The admission webhook and control plane are not compromised.
- The maintainer's signing and DID-controller keys are not compromised.
- IPFS and RPC availability are operational concerns; failure denies admission.

## Adversary

The adversary can observe, intercept, reorder, substitute, and replay network
messages; publish arbitrary IPFS objects; control an OCI registry; submit Pods
and annotations permitted by Kubernetes RBAC; and attempt to forge or mutate
credentials. Build-system, maintainer-key, verifier-binary, and full
control-plane compromise are outside this model.

## Threats and controls

| ID | Threat | Enforced control |
|---|---|---|
| T1 | Image tampering | Admission requires a digest-pinned reference and equality with the signed `manifestDigest`. |
| T2 | Cross-context replay | Signed `CBCvc` must equal operator-controlled `CBCexp`; membership is queried from that contract. |
| T3 | Credential forgery | URDNA2015-normalized Ed25519 proof must verify using the key in the on-chain-bound DID Document. |
| T4 | Stale revocation | Status is read on-chain and cached for 30 seconds; timeouts fail closed. The bound is `Δ = t_finality + TTL_cache + ε_network`. |
| T5 | Metadata leakage | Only hashes/CIDs and lifecycle state are stored on-chain; optional build metadata stays in the off-chain VC. |
| T6 | Downgrade or rollback | The VC validity window is enforced. Stricter release/freshness policy remains an operator policy. |
| T7 | Admission TOCTOU | Tag-only images are rejected; the admitted digest is the digest the runtime pulls. The webhook should run after mutating webhooks. |

## Verification predicate

For each init, application, and ephemeral container, admission requires:

1. A syntactically valid `image@sha256:<64 hex>` reference.
2. Retrieval of the candidate VC and issuer DID Document within timeout.
3. Equality between the DID Document CID and its on-chain registration.
4. Equality between `CBCvc` and the RPC/deployment-derived `CBCexp`.
5. A valid Ed25519Signature2020 proof over the canonical document.
6. `issuanceDate <= now + δ` and `now < expirationDate + δ`.
7. Equality between the image-reference digest and signed manifest digest.
8. Recomputed `vcId = keccak256(URDNA2015(VC_without_proof))`.
9. On-chain membership, matching issuer and CID, and non-revocation.

Any failure denies the complete Pod.

## Availability and residual risk

Fail-closed operation protects integrity but converts an IPFS, RPC, DNS, or
webhook outage into an admission outage. Production deployments should use at
least two webhook replicas, redundant IPFS pinning/gateways, redundant RPC
providers, monitoring, and carefully controlled emergency procedures.

API keys limit and audit off-chain lifecycle operations but are not a signing
trust anchor. Production issuance should use short-lived credentials, mTLS,
scoped DID delegates, encrypted secrets, and an implemented HSM/KMS signer.

The current design does not determine whether an authorized maintainer issued
a VC for a vulnerable image. SLSA build controls, SBOM/vulnerability policy,
multi-party issuance, and key-rotation governance complement this layer.
