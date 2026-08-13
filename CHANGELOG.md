# Changelog

All notable changes to AgentGate are documented in this file.

The project follows [Semantic Versioning](https://semver.org/) for its public
educational-MVP releases.

## [0.1.0] - 2026-08-13

### Added

- Proof-bound Ed25519 workload identity with short-lived, task-scoped credentials.
- Default-deny OPA authorization for seven contained synthetic tools.
- Exact-request, expiring, one-shot administrator approvals.
- Authoritative provenance and conservative untrusted-data propagation.
- HMAC-linked audit records with an independently MACed checkpoint.
- A deterministic 50-scenario security evaluation and persisted metrics API.
- A React administrator console with strict runtime API-response validation.
- Backend, policy, frontend, CodeQL, Docker Compose, and Chromium browser CI gates.
- Complete local demonstration, security, architecture, API, and contribution guides.

### Security

- Unknown tools, malformed requests, unavailable policy, invalid proofs, stale
  credentials, approval substitution/replay, and incomplete provenance fail closed.
- Runtime credentials, private keys, full arguments, and sensitive results are
  excluded from ordinary logs and administrative responses.

### Limitations

- This is a local educational MVP using synthetic fixtures and adapters. It is
  not production ready and must not control real systems, accounts, or data.

[0.1.0]: https://github.com/aariffaadlee/AgentGate/releases/tag/v0.1.0
