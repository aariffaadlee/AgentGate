# Security policy

AgentGate is an educational, local security architecture demonstration. It is
not a production security product and must not protect real credentials, data,
accounts, or external systems.

## Supported versions

Security fixes are applied to the current `main` branch. There are no supported
release branches or production maintenance commitments.

## Reporting a vulnerability

Do not publish an exploitable report, secret, or personal data in a public issue.
Use the repository host's private vulnerability-reporting feature when enabled,
or contact the repository owner privately. Include:

- the affected commit and component;
- prerequisites and a minimal synthetic reproduction;
- observed and expected security behavior;
- impact within the documented trust model; and
- suggested mitigations, if known.

Do not include live tokens, `.env` contents, private keys, database dumps, or
third-party data. Acknowledgement and remediation timelines are best-effort
because this is a portfolio project, not a staffed security service.

## Safe research boundary

Testing is welcome against a local clone containing only the included synthetic
fixtures. Do not target infrastructure or accounts you do not own, perform
denial-of-service testing against shared services, or connect the adapters to real
email, filesystems, databases, cloud accounts, or MCP servers. Use disposable
credentials and databases.

## Security design references

- [Security model](docs/security-model.md)
- [Architecture and trust boundaries](docs/architecture.md)
- [STRIDE threat model](docs/threat-model.md)
- [Identity and proof protocol](docs/identity-protocol.md)
- [Evaluation methodology](docs/evaluation-methodology.md)

## Explicit non-guarantees

A passing test suite or evaluation does not prove freedom from vulnerabilities,
prompt-injection resistance, production suitability, regulatory compliance, or
safe operation with real systems. Container controls are defense in depth, not a
hostile multi-tenant sandbox. The audit checkpoint is tamper-evident, not WORM or
externally witnessed storage.
