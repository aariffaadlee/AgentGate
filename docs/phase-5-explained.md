# Phase 5 explained: authoritative provenance and trust propagation

Phase 5 makes the origin and trust of data an explicit authorization input. An
agent may say which existing records influenced a request, but it cannot assign
their source type or trust label. AgentGate loads those facts from its database,
rejects invalid references, persists the influence relationship, and propagates
untrusted data through later tool outputs.

**Phase status:** complete
**Security objective:** content retrieved from a ticket, document, website,
email, or another agent must not independently authorize a sensitive action.
**Acceptance proof:** the synthetic prompt injection in `TICKET-002` is labelled
untrusted and an attempted `email.send` influenced only by that ticket is denied
before an approval record or adapter dispatch can occur.

## 1. Trust model

AgentGate uses three labels:

| Label | Meaning | Authority conveyed |
| --- | --- | --- |
| `trusted` | A server-created record of task-owner intent or local configuration. | May establish trusted intent, but never bypasses capabilities, risk policy, or approval. |
| `untrusted` | Externally controlled content such as a document, ticket, website, email, or another agent's output. | Data only; cannot independently justify a high-risk action. |
| `unknown` | Data whose trust cannot be established, including conservatively classified derived output. | Cannot independently justify a high-risk action. |

Only a trusted `user_instruction` or `local_configuration` record counts as
trusted intent. A label alone is insufficient. This prevents a trusted-looking
tool result from being treated as task-owner authority.

Task creation now creates the initial trusted `user_instruction` provenance
record in the same transaction as the task and its exact capabilities. Its
content hash is the task's trusted-instruction hash, its creator is the task
owner, and the task API returns only the record ID—not the original instruction.

## 2. Authoritative influence protocol

An agent submits content-free record references with a tool request:

```json
{
  "task_id": "00000000-0000-4000-8000-000000000000",
  "tool_name": "email.send",
  "arguments": {
    "recipient": "student@example.test",
    "subject": "Account notice",
    "body": "Please review the attached guidance."
  },
  "influence_ids": [
    "11111111-1111-4111-8111-111111111111",
    "22222222-2222-4222-8222-222222222222"
  ]
}
```

The outer schema accepts at most 32 unique canonical UUIDs. It does not contain
fields for a trust label, source type, content hash, creator, or task. Unknown
outer fields are rejected, so a caller cannot add `"trust_label": "trusted"`.

For every request, AgentGate:

1. Loads the referenced records by ID.
2. Requires an exact one-to-one match between submitted IDs and loaded rows.
3. Requires every row to belong to the authenticated request's task.
4. Builds the OPA summary from stored labels and source types only.
5. Persists each accepted relation in `tool_request_influences`.

A missing ID, duplicate ID, cross-task ID, or otherwise incomplete lookup makes
`provenance.context_valid` false. OPA returns `PROVENANCE_INVALID`, and the
gateway cannot dispatch.

## 3. Server classification of tool output

Classification follows the selected internal adapter, not claims embedded in
the returned JSON:

| Tool output | Server source type | Server label |
| --- | --- | --- |
| `documents.search` match | `external_document` | `untrusted` |
| `tickets.read` result | `support_ticket` | `untrusted` |
| Any other tool result with an untrusted influence | `tool_output` | `untrusted` |
| Other tool result without an untrusted influence | `tool_output` | `unknown` |

An external result's embedded `provenance` property is removed before hashing
and ignored for classification. The server calculates a canonical SHA-256
content hash and assigns the task, tool request, creator, source reference, and
label. Database constraints require canonical hashes, prevent self-parenting,
limit a record to one creator identity, and make each request/record influence
pair unique.

Derived results obey a conservative trust rule: a result can never become more
trusted than an untrusted material input. Even output based only on trusted input
is `unknown`, because successful tool execution does not turn generated content
into new user authority.

## 4. Policy rules

Every OPA input contains:

```json
{
  "provenance": {
    "labels": ["trusted", "untrusted"],
    "source_types": ["support_ticket", "user_instruction"],
    "untrusted_influence": true,
    "trusted_intent_present": true,
    "context_valid": true
  }
}
```

The policy evaluates provenance together with the existing live identity,
capability, registry, arguments, limits, risk, and approval state:

- invalid context denies every risk tier with `PROVENANCE_INVALID`;
- a high-risk request with untrusted influence but no trusted intent denies with
  `UNTRUSTED_ONLY_SENSITIVE_INTENT`;
- a high-risk request with unknown provenance but no trusted intent denies with
  `UNKNOWN_PROVENANCE_SENSITIVE_INTENT`;
- trusted task-owner intent plus untrusted facts may reach the normal high-risk
  approval path, but it is not directly allowed;
- low- and medium-risk requests remain subject to capabilities, schemas, limits,
  and all other policy rules, while their outputs retain conservative labels.

This distinction allows a trusted owner to ask for an action using external facts
without pretending those facts are trusted. Human approval remains mandatory for
the high-risk action.

## 5. Approval-time revalidation

Influences are part of the stored request, not transient input to the initial OPA
call. When an administrator approves a high-risk request, the approval service
reloads the persisted influence rows and their authoritative provenance records,
rebuilds the summary, and sends it to the fresh OPA evaluation.

Execution additionally requires `context_valid` at the policy-enforcement point.
Therefore an approval cannot compensate for a missing, cross-task, or invalid
provenance reference. The exact-argument binding, expiry, one-shot consumption,
identity checks, and capability checks from Phase 4 still apply unchanged.

## 6. Indirect prompt-injection demonstration

The synthetic fixture `TICKET-002` contains hostile instructions attempting to
cause credential exfiltration. The end-to-end HTTP test performs this sequence:

1. The workload reads `TICKET-002` through `tickets.read`.
2. AgentGate returns content-free metadata for a new record classified as
   `support_ticket` / `untrusted`.
3. The workload references that record as the sole influence on `email.send`.
4. OPA returns `deny` with `UNTRUSTED_ONLY_SENSITIVE_INTENT`.
5. AgentGate returns HTTP 403, creates no approval, and never dispatches the
   synthetic mail adapter.

Related tests prove that a forged trusted label in a tool result is ignored,
unknown and cross-task references fail closed, and untrusted ticket content stays
untrusted after passing through `email.create_draft`.

## 7. Safe API views

`POST /tool-requests` and `GET /tool-requests/{request_id}` return two metadata
lists:

- `influences`: the authoritative records declared for this request;
- `produced_provenance`: records created from successful tool output.

Each entry contains only the record ID, source type, trust label, source
reference, and content hash. The API does not return stored content, encrypted
arguments, provenance attributes, creator internals, or task-owner instructions.
The returned IDs can be supplied on a later request within the same task.

## 8. Main implementation files

- `backend/app/services/provenance.py` validates influence sets, builds policy
  summaries, classifies outputs, hashes content, and propagates trust.
- `backend/app/models/provenance.py` defines records and request influence facts;
  migration `0004_provenance_influences.py` adds their database constraints and
  indexes.
- `backend/app/services/tools.py` loads, authorizes, persists, and returns
  provenance on the normal request path.
- `backend/app/services/approvals.py` revalidates stored influences before an
  approved request can execute.
- `backend/app/api/tools.py` enforces the content-free influence contract.
- `policies/agentgate.rego` contains the fail-closed provenance rules.
- `backend/tests/test_provenance_service.py` and
  `backend/tests/test_tool_api.py` contain the Phase 5 attack demonstrations.

## 9. Verification and limitations

The Phase 5 backend suite passes 184 tests with 86.05% coverage; two environment-
dependent migration tests are skipped when a disposable PostgreSQL database is
not configured. Rego includes direct tests for invalid, untrusted-only, and
unknown-only sensitive provenance. Those tests require an OPA binary or the
Compose service, neither of which is available in the current local shell.

This phase does not claim to solve prompt injection or implement complete dynamic
information-flow control. A malicious agent can omit a real influence ID, and a
human can approve harmful but syntactically valid intent. The controls make
declared provenance authoritative, task-scoped, persistent, policy-visible, and
testable; they do not prove that the agent declared every causal input. External
Phase 6 now supplies the next defense-in-depth layer: a keyed audit chain and
external checkpoint that detect tampering with recorded security events. Phase 7
is the next implementation gate.
