# DIDRegistry

The Solidity 0.8.21 registry is the on-chain trust anchor for CBC-Provenance.
It stores content hashes rather than credential JSON and supports:

- DID registration and DID Document CID updates;
- per-DID ownership and explicitly authorized delegates;
- individual and batch VC recording;
- immutable issuer/CID/timestamp membership records;
- one-way VC revocation and read-only validity queries.

VC identifiers and arbitrary-length DIDs/CIDs are mapped to `bytes32` using
Keccak-256 by the client. Write operations are authorized against the DID
associated with the VC; unrelated accounts cannot record or revoke it.

```bash
cp .env.example .env
npm install
npm test
npm run deploy:arb
```

Deployment requires `ARBITRUM_SEPOLIA_RPC` and `DEPLOYER_PK`. The deployer does
not automatically control another account's DID: the account that first
registers a DID becomes its owner and may authorize delegates.
