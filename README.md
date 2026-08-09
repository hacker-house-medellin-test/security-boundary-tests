# hacker-house-medellin-test/security-boundary-tests

Tenant isolation, replay protection, signature verification, path traversal, SSRF, redaction, and CI supply-chain boundary tests.

This repository is the `security` deep-test suite for `hacker-house-medellin`. It is intentionally dependency-light and deterministic so failures can be reproduced locally without production credentials or customer data.

## Run

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
python scripts/verify_repository.py
```

The initial model is executable rather than a placeholder. Product adapters should be added through focused pull requests while preserving the reference-model tests as an oracle.

Tracking: https://github.com/ORESoftware/ai-agent-coordinator.rs/issues/139
