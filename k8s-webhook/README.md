# Kubernetes validating webhook

The webhook evaluates every init, application, and ephemeral container in a
Pod. Images must be immutable `name@sha256:<digest>` references. The webhook
sends only the digest and discovered credential CID to the verifier and denies
the complete Pod if any image fails.

Credential discovery annotations are:

- `cbc.provenance/vc` for a single-image Pod;
- `cbc.provenance/vc-<container-name>` for each image in a multi-image Pod.

Annotations locate candidate credentials; they are not trust anchors. CBC,
signature, DID Document, lifecycle, and digest validation occurs in the issuer
API against operator-controlled configuration.

The server uses TLS 1.3 on port 8443, a five-second verifier timeout, and
fail-closed responses. The Helm chart deploys two replicas with health probes;
the ValidatingWebhookConfiguration uses `failurePolicy: Fail`.

```bash
go build ./...
go test ./...
```
