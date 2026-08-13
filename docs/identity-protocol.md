# AgentGate identity and request-proof protocol

**Status:** Phase 2 educational protocol, version 1
**Security boundary:** agent workload to AgentGate API

This protocol demonstrates workload-key possession and replay resistance without
claiming standards-compliant DPoP or production PKI. AgentGate remains the
authoritative enforcement point; claims supplied by an agent never create grants.

## Principals and key separation

- Administrators authenticate with a short-lived JWT whose audience is
  `agentgate-admin`.
- Agents authenticate with a different JWT audience, `agentgate-tools`.
- An agent registers only an Ed25519 public JWK with exact members `kty`, `crv`,
  and `x`. Private JWK member `d` and every unknown member are rejected.
- AgentGate calculates the RFC 7638 public-key thumbprint. A unique thumbprint
  binds one key to one stable agent identity.
- Token signing and task-instruction encryption use independent 32-byte keys.
  Production configuration rejects the documented development values.

The bootstrap admin secret is a local educational mechanism, not enterprise SSO.
It is compared in constant time against configuration and represented in the
database only by a salted scrypt verifier. It never appears in an API response.

## Task-scoped workload token

`POST /agents/{agent_id}/tokens` accepts only a task ID and a fresh issuance
proof. AgentGate loads the assigned agent and exact capabilities from PostgreSQL.
It rejects inactive agents/tasks, unassigned or differently assigned tasks, and
tasks with no capabilities.

The server-signed Ed25519 JWT contains:

| Claim | Meaning |
| --- | --- |
| `iss` | Configured AgentGate issuer. |
| `aud` | Workload-only `agentgate-tools` audience. |
| `sub` | Stable agent UUID. |
| `task_id` | One assigned task UUID. |
| `capabilities` | Exact grants copied from stored task capabilities. |
| `jti` | Random token identifier; only its SHA-256 digest is persisted. |
| `iat`, `nbf`, `exp` | UTC numeric dates with at most a five-minute default lifetime. |
| `cnf.jkt` | Registered Ed25519 JWK thumbprint. |

The verifier fixes the algorithm to `EdDSA`, validates `kid`, issuer, strict
single audience, required claims, timestamps, maximum lifetime, and strict claim
shape. It then loads the credential row and checks agent/task assignment,
capabilities, thumbprint, revocation, and persisted timestamps again.

## Signed request proof

Every issuance request uses a compact Ed25519 JWS in `X-Agent-Proof`. Every later
workload request uses the same form plus an access-token hash.

```json
{
  "sub": "agent UUID",
  "htm": "POST",
  "htu": "/agents/{agent UUID}/tokens",
  "body_hash": "sha256:<canonical-body digest>",
  "ath": null,
  "iat": 1786432800,
  "exp": 1786432830,
  "jti": "one-time proof UUID"
}
```

The protected header must be exactly compatible with `alg=EdDSA` and
`typ=agentgate-proof+jwt`. For a protected request, `ath` is
`sha256:<digest of the exact encoded access token>`. An issuance proof must omit
`ath`; callers cannot downgrade the expected proof form.

The body digest uses UTF-8 canonical JSON: sorted object keys, no insignificant
whitespace, preserved Unicode, normalized JSON scalar types, and no non-finite
numbers. The verifier compares method, path, body digest, token digest, agent ID,
and relevant thumbprints without content-dependent early return for sensitive
digests.

Proof lifetime defaults to 30 seconds with five seconds of clock skew. The
SHA-256 digest of every proof `jti` is inserted into a unique PostgreSQL column in
the same transaction as issuance or authentication. A concurrent second use
loses the uniqueness race and returns `PROOF_REPLAYED`.

## Revocation

Administrator revocation changes the agent and all active credential rows to
revoked and appends a revocation fact containing actor, reason, and effective UTC
time. Records and security history are not deleted. Every protected request
checks live database state, so a cryptographically valid token fails immediately
after revocation with `CREDENTIAL_REVOKED`.

## OPA contract

AgentGate sends only server-verified identity and task context to
`data.agentgate.authorization.decision`. OPA returns `deny`,
`require_approval`, or `allow` with stable reason codes and policy version.

Transport failure, timeout, non-success HTTP status, oversized response,
undefined result, unknown decision, empty/mismatched reason codes, extra response
fields, or malformed JSON becomes a synthetic denial with
`POLICY_ENGINE_ERROR`. No previous allow result is cached. OPA and PostgreSQL are
internal-only Compose services.

The Rego suite covers default denial, inactive/revoked/expired identity,
issuer/audience/proof context, capability and task scope, unknown tools, invalid
arguments, untrusted-only sensitive intent, approval requirements and binding,
approval expiry/replay, resource/rate limits, and legitimate low/medium/approved
high-risk decisions.

## Residual risks

- Theft of both the private workload key and a current token allows use until
  expiry or revocation.
- The local bootstrap secret and process-held signing/encryption keys are not an
  HSM or managed key service.
- HTTP is acceptable only on the isolated local demonstration network. A remote
  deployment requires authenticated TLS or stronger workload transport identity.
- Database/OPA integration is fail-closed but single-node in the MVP.
- Tool authorization is wired to the contained execution path in Phase 3.
  High-risk requests stop at `pending_approval`; exact approval creation and
  consumption arrive in Phase 4.
