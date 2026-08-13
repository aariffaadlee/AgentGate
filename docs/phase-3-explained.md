# Phase 3 explained: contained tool gateway and enforcement path

Phase 3 turns the Phase 2 identity and OPA layers into a functioning policy
enforcement point. An authenticated agent can now request one of seven synthetic
tools, but it cannot select executable code, bypass schema validation, supply its
own risk tier, or call an adapter directly.

**Phase status:** complete
**Primary objective:** mediate every synthetic tool request through strict
validation, deterministic policy, bounded execution, and durable request records
**Approval boundary:** high-risk requests are persisted as `pending_approval`
and are not executed; the approval state machine is Phase 4

## 1. End-to-end enforcement flow

```mermaid
sequenceDiagram
    participant A as "Agent"
    participant API as "AgentGate API"
    participant DB as "PostgreSQL"
    participant OPA as "OPA"
    participant T as "Static adapter"
    A->>API: "POST /tool-requests + JWT + one-time proof"
    API->>DB: "Validate live credential/task and consume proof"
    API->>API: "Exact registry lookup and strict argument validation"
    API->>DB: "Consume atomic rate slot and store encrypted request"
    API->>OPA: "Complete server-assembled authorization input"
    OPA-->>API: "deny | require_approval | allow + reasons"
    alt "deny"
        API->>DB: "Persist decision and denied status"
        API-->>A: "403 with reason codes"
    else "require approval"
        API->>DB: "Persist pending_approval status"
        API-->>A: "202; no adapter dispatch"
    else "allow and PEP guards agree"
        API->>T: "Invoke fixed typed adapter under timeout"
        T-->>API: "Declared result model"
        API->>DB: "Store sanitized summary and final status"
        API-->>A: "201 with bounded sanitized result"
    end
```

The JWT and proof are verified before the tool service is entered. The proof is
bound to the HTTP method, path, complete canonical body, bearer-token hash,
agent, timestamp window, and a one-time identifier. Replaying the same HTTP
request therefore fails before another rate slot or tool request is created.

## 2. Immutable executable registry

[backend/app/tools/registry.py](../backend/app/tools/registry.py) contains the
only mapping from a tool name to executable adapter code. Each definition fixes:

- the exact tool name and required capability;
- risk tier;
- strict argument and result model;
- adapter callable;
- execution timeout;
- request and response byte limits;
- fixed-window rate limit; and
- schema and adapter versions.

No request field is converted into an import path, function name, command,
hostname, SQL statement, or filesystem root. Unknown names have no adapter.

The complete seven-tool manifest is:

| Tool | Risk | Phase 3 behavior |
| --- | --- | --- |
| `documents.search` | Low | Searches the bounded synthetic corpus and server-labels matches as untrusted external documents. |
| `tickets.read` | Low | Returns one allowlisted synthetic ticket and labels its text as an untrusted support ticket. |
| `email.create_draft` | Medium | Creates a process-local mock draft after recipient, subject, and body validation. |
| `email.send` | High | Adapter simulates delivery, but the PEP always stops at `require_approval` in Phase 3. |
| `files.read` | Medium | Reads a bounded UTF-8 file only from the dedicated sandbox. |
| `files.write` | High | Implements contained atomic writing, but the PEP cannot dispatch it before Phase 4 approval. |
| `database.query` | Medium | Runs one exact query template over bounded synthetic records; SQL text is not an input. |

## 3. Checksummed database mirror

The database `tool_registry` table is a queryable mirror, not the executable
authority. AgentGate hashes the sorted manifest, including schemas and limits.
On non-test startup it performs one of two operations:

1. install all seven rows when the mirror is completely empty; or
2. require every name, version, risk, constraint, enabled flag, and manifest
   checksum to match trusted code exactly.

A partial, extra, disabled, or modified row fails startup. During a request, a
second comparison prevents dispatch if a row changes after startup. Changing a
description or database row therefore cannot redirect an adapter or downgrade
its risk.

## 4. Strict request schemas

[backend/app/tools/schemas.py](../backend/app/tools/schemas.py) uses strict
Pydantic models with `extra="forbid"`. Security-relevant coercion is disabled:
strings cannot silently become integers or booleans, and nested unexpected
properties fail validation.

The outer request accepts only:

```json
{
  "task_id": "UUID",
  "tool_name": "exact.capability",
  "arguments": {}
}
```

The UUID parser accepts only its canonical JSON string form. Argument property
names are bounded, JSON numbers must be finite, and duplicate JSON names are
rejected by middleware before FastAPI parsing. The normalized validated object,
not the caller's raw representation, is hashed for policy and future approval
binding.

Invalid arguments still become a persisted authenticated tool attempt and an OPA
decision with `arguments_valid=false`. They can never reach an adapter.

## 5. Email containment

Email arguments accept one bounded ASCII address without display-name syntax,
a bounded subject, and a bounded body. The mock mailbox has no SMTP, DNS, HTTP,
or external account integration.

`email.create_draft` may run when explicitly granted. It returns only a synthetic
message identifier and status; it does not echo the body. `email.send` is present
so its adapter and schema can be tested, but an ordinary Phase 3 call receives
`HIGH_RISK_APPROVAL_REQUIRED` and causes zero mailbox delivery operations.

## 6. Filesystem containment

The file schema accepts only forward-slash relative paths ending in `.txt`,
`.md`, `.json`, or `.csv`. It rejects:

- absolute, drive-qualified, UNC, and backslash paths;
- `.` and `..` segments;
- empty/repeated segments;
- percent-encoded ambiguous paths;
- NULs and colon syntax; and
- unsupported file types.

The adapter then performs a second, filesystem-aware check. It resolves the
sandbox and target parent, verifies containment with `relative_to`, rejects
symbolic links and Windows reparse points in existing components, requires
regular files, and applies no-follow open flags where the platform provides
them.

Reads are UTF-8 only and capped at 64 KiB. Writes are capped at 16 KiB. New files
are written to a completed temporary file and atomically linked into place so an
existing target is not replaced accidentally. Approved overwrite behavior uses
atomic replacement. The actual preflight existence state—not merely the
caller's `overwrite` value—is supplied to OPA.

These controls reduce filesystem time-of-check/time-of-use risk, but they do not
claim to replace OS/container isolation against a hostile local process with
concurrent write access.

## 7. Synthetic query templates

`database.query` accepts one of three identifiers:

- `assets.by_owner` with only `owner`;
- `assets.by_status` with only `status`; or
- `users.by_department` with only `department`.

The adapter loads a strict, size-bounded synthetic fixture and applies exact
equality to the named field. There is no SQL parser or SQL input property. A
payload such as `' OR 1=1 --` remains an ordinary comparison string and returns
no records rather than changing query structure.

## 8. Rate and resource governance

Migration
[0003_tool_rate_limits.py](../backend/migrations/versions/0003_tool_rate_limits.py)
adds a unique counter scope consisting of agent, task, tool, and fixed-window
start. PostgreSQL `INSERT ... ON CONFLICT DO UPDATE ... WHERE` consumes a slot
atomically. When the counter reaches the static limit, no increment is returned
and OPA receives `rate_exceeded=true`.

Unknown names share an `__unknown__` bucket, preventing an attacker from evading
the limit by generating endless unique tool names.

Transport middleware enforces the global body ceiling before JSON parsing. Each
tool then applies a lower request limit. Adapter execution uses
`asyncio.timeout`, and every returned object must pass the declared result model
and encoded byte limit. Oversized or malformed adapter output is rejected rather
than partially leaked.

## 9. Encrypted request persistence

Every authenticated attempt creates a `tool_requests` row before OPA evaluation,
including unknown, invalid, denied, and rate-limited requests. The row records
identity, credential, task, correlation ID, tool, risk, canonical argument hash,
status, sizes, timing, and stable errors.

Full arguments are stored only as AES-256-GCM ciphertext with a fresh nonce and
request-specific associated data. The plaintext is not copied into logs or API
responses. `redacted_arguments` contains only field names, sizes, and a narrow
allowlist of operational identifiers.

Each OPA result creates an immutable `policy_decisions` row with outcome, reason
codes, policy version, OPA decision ID where available, input hash, and measured
latency. Successful execution stores only a sanitized result summary. The full
result is returned to the authenticated caller once and is not exposed by the
request lookup endpoint.

## 10. Deterministic policy and PEP guards

The service builds OPA input exclusively from authenticated and server-owned
state: live identity/task/credential facts, static manifest metadata, normalized
arguments, actual limits, and a conservative current provenance context.

OPA retains precedence `deny > require_approval > allow`. In addition, the PEP
refuses to dispatch an `allow` response unless all of these are independently
true:

- static and database registry metadata match;
- arguments passed validation and preflight;
- task identity matches the service command;
- the exact capability exists;
- rate and request limits passed;
- risk is low or medium; and
- the allow reason matches that risk class.

An inconsistent allow is converted to `POLICY_ENGINE_ERROR` and denied. This is
defense in depth against a malformed or spoofed policy response; it does not
duplicate the complete Rego policy in application code.

## 11. REST behavior

`POST /tool-requests` requires a workload token and fresh `X-Agent-Proof`:

- `201 Created` — authorized adapter completed successfully;
- `202 Accepted` — OPA requires approval and no adapter ran;
- `403 Forbidden` — deterministic policy denial with reason codes;
- `502 Bad Gateway` — authorization succeeded but contained execution failed;
- `504 Gateway Timeout` — authorization succeeded but adapter timeout fired; or
- the existing stable authentication/validation error envelope.

`GET /tool-requests/{request_id}` accepts an administrator session or a fresh
proof-bound token from the owning agent/task. It returns the status, decision,
reason codes, timings, sizes, and sanitized summary. It never returns ciphertext,
nonces, argument plaintext, bearer tokens, or full stored results.

## 12. Operational audit events

The PEP emits structured, redacted events for request receipt, policy decision,
and completion. Those events contain correlation and record identifiers, status,
reason codes, and bounded timings—not request arguments or tool results.

The durable `tool_requests` and `policy_decisions` rows reconstruct Phase 3 state
transitions. They are not yet the tamper-evident audit chain: keyed chaining,
external checkpoints, verification API/CLI, and mutation detection intentionally
remain Phase 6.

## 13. Verification evidence

The Phase 3 test matrix covers:

- all seven schemas and adapters;
- allowed low- and medium-risk execution;
- high-risk non-dispatch;
- unknown and out-of-capability tools;
- strict types and unexpected properties;
- duplicate names and non-finite JSON;
- path traversal, symlink/reparse checks, binary files, and size limits;
- SQL-injection-shaped values as inert template parameters;
- token-bound proof replay;
- atomic rate-limit behavior;
- timeout and invalid/oversized result handling;
- manifest installation and drift rejection;
- encrypted argument storage and sanitized summaries; and
- malicious/inconsistent allow responses blocked by the PEP.

The completed Phase 3 gate produced:

- 167 passing Python tests;
- 2 explicit integration skips because no live PostgreSQL or OPA URL was
  configured;
- 89.38% branch-aware Python coverage;
- clean Ruff lint and format checks;
- a clean strict MyPy run over the application;
- a clean Bandit scan;
- successful package-consistency and bytecode-compilation checks;
- successful offline Alembic upgrade and downgrade through revision `0003`; and
- clean secret-pattern and forbidden dynamic-execution scans.

The host does not provide Docker, so live PostgreSQL and full Compose startup
remain unexecuted. Windows also denied creation of a real symbolic link; the
fallback test simulates the link classification and verifies fail-closed adapter
behavior, while a real symlink test remains part of the portable test case for a
host that permits creation.

The Rego policy was unchanged from the previously passing Phase 2 gate of 23/23
tests with 100% reported rule coverage. A fresh binary run could not be performed
because no local OPA binary/service was present and the pinned binary download
failed in this environment.

## 14. Remaining limitations and Phase 4 handoff

Phase 3 does not create an approval record, authenticate an approving human for
a particular action, consume approval once, or resume the stored request. A
high-risk action therefore cannot succeed through the public tool endpoint yet.

Phase 4 will use the already persisted agent, task, tool, encrypted arguments,
and canonical argument hash to implement expiring, exact, one-shot approvals.
It must re-evaluate OPA and execute only the original authenticated ciphertext,
including the required one-character substitution and replay demonstrations.

Full cross-request provenance propagation is Phase 5, tamper-evident audit
integrity is Phase 6, and measured adversarial reports are Phase 7.
