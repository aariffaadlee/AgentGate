# AgentGate API guide

The API is a local JSON/HTTP interface. Under Docker Compose it is bound to
`http://127.0.0.1:8000`; the dashboard accesses the same API through `/api` on
the frontend origin. OpenAPI and interactive docs exist only when
`AGENTGATE_DOCS_ENABLED=true`.

## Authentication classes

| Class | Credential | Additional proof | Intended endpoints |
| --- | --- | --- | --- |
| Public operations | None | None | Health only. |
| Bootstrap exchange | Bootstrap secret in JSON body | None | `POST /admin/session` only. |
| Administrator | `Authorization: Bearer <admin-token>` | None | Registration, tasks, approvals, audit, metrics, administrative lists. |
| Workload | `Authorization: Bearer <workload-token>` | `X-Agent-Proof: <signed-JWS>` | Tool request and workload-owned reads. |
| Pre-token workload | None | `X-Agent-Proof: <signed-JWS>` | Token issuance for the registered agent key. |

The workload proof is Ed25519-signed and covers subject, method, path, canonical
body hash, issue/expiry times, one-time ID, and—after issuance—the bearer-token
hash. See [identity-protocol.md](identity-protocol.md) for exact claims.

## Endpoint summary

| Method and path | Authentication | Success | Purpose |
| --- | --- | ---: | --- |
| `GET /health/live` | Public | 200 | Process liveness only. |
| `GET /health`, `GET /health/ready` | Public | 200 or 503 | PostgreSQL and OPA readiness without connection details. |
| `POST /admin/session` | Bootstrap exchange | 200 | Issue a short-lived admin-audience token. |
| `POST /agents` | Admin | 201 | Register a name and public Ed25519 JWK. |
| `GET /agents` | Admin | 200 | List sanitized workload identities. |
| `POST /tasks` | Admin | 201 | Assign one agent, exact capabilities, and trusted owner intent. |
| `GET /tasks` | Admin | 200 | List sanitized tasks and grants. |
| `GET /tasks/{task_id}` | Admin or owning proof-bound workload | 200 | Read one task without its full instruction. |
| `POST /agents/{agent_id}/tokens` | Pre-token proof | 201 | Issue a short task-bound workload token. |
| `POST /agents/{agent_id}/revoke` | Admin | 200 | Revoke the identity and active credentials. |
| `POST /tool-requests` | Proof-bound workload | 201, 202, or 403 | Evaluate and optionally execute one exact action. |
| `GET /tool-requests` | Admin | 200 | List up to 200 sanitized request records. |
| `GET /tool-requests/{request_id}` | Admin or owning proof-bound workload | 200 | Read sanitized state for one request. |
| `GET /approvals` | Admin | 200 | List exact pending/history records with redacted arguments. |
| `POST /approvals/{id}/approve` | Admin | 200 | Approve the displayed argument hash and consume once. |
| `POST /approvals/{id}/reject` | Admin | 200 | Reject without dispatch. |
| `GET /audit/events` | Admin | 200 | Read a bounded, filterable redacted timeline. |
| `POST /audit/verify` | Admin | 200 | Verify the complete HMAC chain and external checkpoint. |
| `GET /metrics/security` | Admin | 200 or 404 | Read the latest completed persisted evaluation only. |

## Core request examples

Examples use placeholders; never paste a real credential into source control or a
shell history shared with others.

Create a task as an administrator:

```json
{
  "assigned_agent_id": "10000000-0000-4000-8000-000000000001",
  "title": "Review synthetic VPN guidance",
  "trusted_instruction_summary": "Search and prepare a synthetic notice.",
  "trusted_instruction": "Search the synthetic VPN policy and send the approved notice.",
  "capabilities": ["documents.search", "email.send"]
}
```

Propose an allowed low-risk search with a bearer token and fresh proof:

```http
POST /tool-requests
Authorization: Bearer <workload-token>
X-Agent-Proof: <fresh-proof-for-this-body>
Content-Type: application/json
```

```json
{
  "task_id": "20000000-0000-4000-8000-000000000002",
  "tool_name": "documents.search",
  "arguments": {"query": "VPN policy", "max_results": 2},
  "influence_ids": ["30000000-0000-4000-8000-000000000003"]
}
```

A `201` response has `decision: "allow"` and `status: "succeeded"` when the
bounded synthetic adapter succeeds. The response can contain the immediate typed
result for the owner; administrative collection reads deliberately set full
`result` to `null`.

An unregistered action such as `tool_name: "shell.exec"` returns `403` with a
sanitized tool-request record, `decision: "deny"`, and stable reason codes. No
adapter is selected or dispatched.

A permitted `email.send` request with trusted intent returns `202`,
`decision: "require_approval"`, `status: "pending_approval"`, and an
`approval_id`. It has not executed. The administrator reads the approval and
submits only the displayed exact hash:

```json
{
  "argument_hash": "sha256:<64 lowercase hexadecimal characters>",
  "reason": "Approved for the synthetic demonstration."
}
```

Approval revalidates live identity, task, capability, provenance, schema, stored
arguments, expiry, and OPA policy. A changed hash, expired record, or replay does
not execute.

## Tool request fields

`tool_name` must match the static registry exactly. `arguments` is validated by
that tool's strict schema. `influence_ids` identifies same-task provenance records
whose labels are loaded by the server; clients cannot supply labels. The response
exposes operational state, reason codes, policy version, redacted summaries,
sizes, latency, and content-free provenance references. It never exposes stored
encrypted arguments.

## Stable error envelope

Errors outside the policy-result record use one non-reflective envelope:

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "The request did not match the required schema.",
    "request_id": "00000000-0000-4000-8000-000000000000",
    "fields": [{"path": "body.tool_name", "error_type": "string_pattern_mismatch"}]
  }
}
```

The `X-Request-ID` response header contains the same server-validated correlation
identifier. Internal exceptions, submitted values, credentials, and stack traces
are not reflected.

## Pagination and limits

Administrative request and audit collections use bounded query parameters rather
than unbounded exports. Tool-request `limit` is 1–200, default 100. Audit `limit`
is 1–200 and supports `after_sequence`, correlation/task/request IDs, and an exact
event type. Phase 9 does not implement cursor pagination for every collection.
