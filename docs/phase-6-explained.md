# Phase 6 explained: keyed audit integrity and verification

Phase 6 turns AgentGate's security transitions into a reconstructable,
tamper-evident event chain. Every event is redacted before persistence, linked to
the previous event with HMAC-SHA-256, and committed against a separately stored,
MACed head checkpoint. Administrators can query the timeline or verify the whole
chain; the same verifier is available as a command-line tool.

**Phase status:** complete
**Security objective:** a database-only attacker who modifies, inserts, deletes,
reorders, or truncates audit rows must be detected.
**Acceptance proof:** the automated mutation matrix detects all five attack
classes, while an untouched multi-event chain and its external checkpoint verify.

## 1. Events recorded

The API emits security events for these successful state transitions:

| Area | Event types | Important safe fields |
| --- | --- | --- |
| Administrator identity | `identity.admin_session_issued` | Actor ID and expiry, never the token or bootstrap secret. |
| Workload identity | `identity.agent_registered`, `identity.credential_issued`, `identity.agent_revoked` | Agent/task IDs, key thumbprint, capability names, expiry, status, and reason code. |
| Task authority | `task.created` | Assignment, exact capabilities, trusted-instruction hash, and trusted provenance ID. |
| Tool request | `tool.requested` | Tool/risk, canonical argument hash, redacted argument summary, size, and declared influence IDs. |
| Policy | `policy.decided` | Outcome, reason codes, version, input hash, decision ID, and latency. |
| Approval | `approval.pending`, `approval.consumed`, `approval.rejected` | Exact request/hash binding, state, expiry/row version, and whether an admin reason was present. |
| Execution | `tool.succeeded`, `tool.failed`, `tool.denied` | Status, bounded result summary, error code, response size, and execution latency. |

Approval text is deliberately not copied into the audit payload. Neither are raw
tool arguments, encrypted arguments, complete tool results, access tokens,
private keys, administrator bootstrap secrets, or trusted task instructions.

## 2. Reconstructable request sequences

All events for a tool action carry the original request correlation ID, agent or
administrator actor, task ID, and tool-request ID.

```text
Allowed read:
  tool.requested -> policy.decided -> tool.succeeded

Denied request:
  tool.requested -> policy.decided -> tool.denied

High-risk request:
  tool.requested -> policy.decided -> approval.pending

Approved continuation:
  approval.consumed -> policy.decided -> tool.succeeded | tool.failed

Rejected continuation:
  approval.rejected -> tool.denied
```

The initial and approval-time `policy.decided` records remain distinguishable by
their position and actor. An administrator can filter the timeline by correlation,
task, tool request, event type, or sequence cursor.

## 3. Redaction and content limits

Every draft passes through the same recursive redactor used by structured logs
before it can be hashed or stored. Sensitive key names such as `password`,
`authorization`, `private_key`, `secret`, and token/key suffixes become
`[REDACTED]`. Recognizable bearer tokens, JWTs, and URL passwords inside strings
are also removed.

The resulting value must be a JSON object and its canonical representation may
not exceed 65,536 bytes. Event types use a restricted lowercase namespace. A
system event cannot claim a principal ID, while agent and administrator events
must identify their actor. Database constraints independently require object
payloads and this actor rule.

## 4. Keyed event chain

The first row has sequence `1` and a previous hash of 64 zeroes. Each later row
uses the preceding row's event hash. The event HMAC covers:

- sequence, event ID, and chain ID;
- event type and normalized UTC timestamp;
- correlation, actor, task, and tool-request references;
- the complete redacted payload; and
- the previous event hash.

All UUIDs and timestamps have one canonical representation and JSON keys are
sorted before HMAC-SHA-256. The database stores the 64-character lowercase
hexadecimal MAC. Constraints require positive sequences, canonical previous/current
hashes, unique event IDs and hashes, and a JSON-object payload.

The audit key is an independent 32-byte secret. Configuration rejects reuse of
the signing, data-encryption, or audit key and rejects the public development
value in production mode.

## 5. Serialized append and external checkpoint

The PostgreSQL repository takes one session-level advisory lock before reading or
extending the chain. While holding that lock it:

1. Loads the complete sequence and external checkpoint.
2. Runs the full verifier and refuses to append to an inconsistent history.
3. Calculates contiguous explicit sequence numbers and HMAC links.
4. Commits the event batch to PostgreSQL.
5. Atomically replaces the checkpoint file while the advisory lock is still held.
6. Releases the lock.

The checkpoint is stored outside PostgreSQL and contains only format version,
chain ID, latest sequence, head hash, update time, and its own HMAC. Docker Compose
mounts it on the separate `audit-checkpoint` volume. File updates use a flushed
temporary file followed by `os.replace`, so readers see either the old complete
checkpoint or the new complete checkpoint, never a partially written document.

PostgreSQL and a filesystem cannot participate in one portable atomic transaction.
AgentGate therefore commits the database row first. If the checkpoint replacement
then fails, the committed database head and old checkpoint disagree; verification
and every later append fail closed until an operator investigates. This favors
detectable unavailability over silently accepting an unanchored history.

## 6. Verification algorithm

The shared verifier checks, in order:

1. sequence starts at one and has no gaps or reordering;
2. every event uses the single genesis chain ID;
3. every `previous_hash` equals the verified predecessor;
4. every event HMAC recomputes with constant-time comparison;
5. a non-empty database has an external checkpoint;
6. the checkpoint HMAC is valid; and
7. checkpoint chain ID, sequence, and head hash equal the database tail.

Stable failure codes include `SEQUENCE_GAP`, `CHAIN_ID_MISMATCH`,
`PREVIOUS_HASH_MISMATCH`, `EVENT_HASH_MISMATCH`, `CHECKPOINT_MISSING`,
`CHECKPOINT_INVALID`, `CHECKPOINT_MAC_INVALID`, and
`CHECKPOINT_HEAD_MISMATCH`. A valid empty or populated chain reports
`CHAIN_VALID`.

The external checkpoint is what makes tail truncation detectable: the shortened
database can remain internally consistent, but it cannot match the independently
MACed latest sequence and head.

## 7. Administrative API

Both endpoints require the administrator token audience. A workload token is
rejected even if it belongs to an agent represented in the timeline.

```http
GET /audit/events?after_sequence=120&limit=100&correlation_id=<uuid>
Authorization: Bearer <administrator-token>
```

The response is ordered by sequence and contains the chain metadata plus the
already-redacted payload. `limit` is restricted to 1–200. Optional filters are
available for task ID, tool-request ID, and event type.

```http
POST /audit/verify
Authorization: Bearer <administrator-token>
```

Verification is read-only. Its response contains validity, stable reason code,
event count, last verified sequence, chain ID, head hash, and the first failing
sequence when applicable.

## 8. Command-line verification

Run the same verifier from the repository root with the configured database,
audit key, and checkpoint path:

```powershell
.venv\Scripts\python scripts\verify_audit.py
```

The command prints one JSON object. Exit code `0` means the chain is valid, `1`
means integrity verification failed, and `2` means verification could not run.
It never repairs, rewrites, or checkpoints the chain.

## 9. Tampering tests

The Phase 6 tests create a valid three-event chain and then directly alter its
stored representation without recomputing trusted MACs:

| Attack | Detection |
| --- | --- |
| Modify a payload | `EVENT_HASH_MISMATCH` |
| Delete a middle row | `SEQUENCE_GAP` |
| Insert a forged row | `EVENT_HASH_MISMATCH` |
| Reorder rows | `SEQUENCE_GAP` |
| Truncate the tail | `CHECKPOINT_HEAD_MISMATCH` |
| Modify checkpoint MAC | `CHECKPOINT_MAC_INVALID` |
| Corrupt checkpoint JSON | `CHECKPOINT_INVALID` |

Additional tests prove recursive secret redaction, refusal to extend a modified
chain, one contiguous sequence under 20 concurrent append attempts, filtered
timeline behavior, and administrator/workload audience separation.

The complete Phase 6 backend suite passes 199 tests with 85.00% branch-aware
coverage. Two integration checks remain skipped in this shell because they
require a disposable live PostgreSQL database and a live OPA service. Offline
upgrade/downgrade rendering still verifies the complete migration history.

## 10. Main implementation files

- `backend/app/services/audit.py` owns redaction, canonical HMAC construction,
  atomic checkpoint files, and verification.
- `backend/app/db/audit.py` owns the PostgreSQL advisory lock and serialized append.
- `backend/app/services/audit_events.py` creates safe tool/approval event batches.
- `backend/app/api/audit.py` provides the administrator timeline and verifier.
- `backend/migrations/versions/0005_audit_integrity.py` adds chain constraints.
- `scripts/verify_audit.py` is the read-only command-line verifier.
- `backend/tests/test_audit_service.py` contains the tampering matrix.

## 11. Boundaries and next phase

This is tamper-evident, not immutable storage. A database-only attacker, or a
checkpoint-volume attacker without the HMAC key, is detected. An attacker who
simultaneously controls the application process, audit key, database, and
checkpoint volume can forge a replacement history. Production systems should
anchor signed heads in an independent transparency or WORM service.

Audit writes occur immediately after the primary endpoint transition has
committed. A process crash in that narrow interval can leave a request without
its expected event batch; the API otherwise treats audit failure as request
failure. Cross-resource transactional outbox recovery is outside this educational
MVP and should be added before production use.

Phase 7 now supplies the scenario runner and measured security reports. Audit
completeness and chain-verification rates are calculated from per-scenario
evidence, not hard-coded dashboard values. Phase 8 is the next implementation
gate.
