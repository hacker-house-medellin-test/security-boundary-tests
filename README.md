# hacker-house-medellin-test/security-boundary-tests

Tenant isolation, replay protection, signature verification, path traversal, SSRF, redaction, and CI supply-chain boundary tests.

This repository is the `security` deep-test suite for `hacker-house-medellin`. It is intentionally dependency-light and deterministic so failures can be reproduced locally without production credentials or customer data.

## Run

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
python scripts/verify_repository.py
```

The initial model is executable rather than a placeholder. Product adapters should be added through focused pull requests while preserving the reference-model tests as an oracle.

## HHM application boundary coverage

The HHM-specific reference tests add deterministic, network-free checks for:

- Shared Auth `anonymous`, `unauthenticated`, and `degraded` separation, with
  product authorization based only on the exact verified provider tuple;
- opt-in Flutter/desktop `hhm.p2p.v1` sessions bound to a backend-certified
  installation, peer key, house, negotiated capability, encrypted-envelope
  session, nonce, message ID, sequence, expiry, AEAD result, and explicit
  sharing consent;
- pre-cryptographic attempt accounting with nonce, message, and sequence replay
  state committed atomically only after AEAD authentication and payload-policy
  decoding succeed;
- peer-delivered application updates that still require the canonical release
  signature, exact app/platform/channel, digest, size, and a newer version;
- inert private HTML components and exact WebSocket origin, frame, and message
  boundaries; and
- committed SOPS ciphertext with a MAC and multiple public age recipients,
  while rejecting plaintext environment and private-key paths.

The peer schema and fixture are vendored byte-for-byte from
`hacker-house-medellin/hhm-interfaces` commit
`f694bc9b58907db918f0449b5d04a5763f8fa745`. Tests verify their recorded
SHA-256 provenance before exercising the contract and make no network request.

Bluetooth discovery or proximity never authenticates a resident, unlocks a
door, commits server-owned presence, transports a credential, or authorizes a
release.

Tracking: https://github.com/ORESoftware/ai-agent-coordinator.rs/issues/139
