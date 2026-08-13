# AgentGate threat model

**Method:** STRIDE plus OWASP agentic-security abuse cases
**Scope:** local educational MVP defined in [phase-0-plan.md](phase-0-plan.md)
**Review triggers:** new tool/connector, identity protocol change, policy or
approval change, new provenance source, model/provider change, or deployment
beyond a single trusted local host

## Security objectives

- Only an active, authenticated workload possessing its registered private key
  may use its own unexpired task credential.
- Every tool action is explicitly authorized for the exact task, capability,
  validated arguments, provenance, approval, and resource state.
- The language model and retrieved content can request an action but cannot grant
  authority, alter policy facts, or choose an executable adapter.
- High-impact actions require a separate authorized human decision bound to the
  exact action and consumable once.
- Sensitive values are minimized, encrypted where recoverability is necessary,
  and redacted from logs/API views.
- Security events can be reconstructed and database-only tampering is detectable.
- Abuse is bounded by request, response, time, and rate limits.

## Assets

| ID | Asset | Security properties |
| --- | --- | --- |
| A-01 | Agent credentials and workload private keys | Confidentiality, authenticity, short lifetime, non-replay. |
| A-02 | Human approval decisions and admin credential | Authenticity, integrity, exact binding, non-replay, accountability. |
| A-03 | Tool arguments | Integrity, schema validity, task binding, confidentiality where sensitive. |
| A-04 | Sensitive tool results and synthetic mailbox/files | Confidentiality, integrity, bounded disclosure. |
| A-05 | Agent memory and context | Task isolation, provenance integrity, resistance to poisoning. |
| A-06 | Rego policies and static tool manifest | Integrity, version traceability, default-deny availability. |
| A-07 | Audit records and external chain checkpoint | Completeness, ordering, integrity, controlled disclosure. |
| A-08 | MCP/tool-server configuration and adapter mapping | Integrity, allowlisting, non-bypassability. |
| A-09 | Task definitions, owners, and capabilities | Integrity, least privilege, tenant/task isolation. |
| A-10 | Provenance labels and relationships | Integrity, source authenticity, conservative propagation. |
| A-11 | Runtime secrets and encryption/audit/signing keys | Confidentiality, integrity, separation from database and logs. |
| A-12 | Availability and laptop resources | Bounded CPU, memory, storage, calls, and latency. |

## Actors

- **Task owner:** supplies legitimate goals but can also attempt direct prompt
  injection.
- **Registered agent:** expected to follow the protocol; its model may be confused
  or fully attacker-influenced.
- **Local administrator:** trusted to register/revoke agents and decide approvals;
  mistakes or credential theft remain possible.
- **External-content attacker:** controls text inside a document, ticket, website,
  email-like record, or another agent's output.
- **Network/process attacker:** may copy tokens, replay requests, call endpoints
  directly, or exploit exposed services, but initially does not control the host.
- **Database attacker:** can modify PostgreSQL rows but initially lacks runtime
  signing, encryption, and audit-checkpoint keys and the checkpoint volume.
- **Dependency/configuration attacker:** attempts to poison tool metadata, policy,
  images, packages, or local configuration.

## Trust boundaries

The detailed data flow is in [architecture.md](architecture.md). Threats are
assessed across these boundaries:

1. **TB-1 User to agent** — user goals enter probabilistic planning.
2. **TB-2 External content to agent** — retrieved data may contain instructions.
3. **TB-3 Agent to AgentGate** — all workload identity and action requests cross an
   authenticated, size-limited API boundary.
4. **TB-4 AgentGate to OPA** — authoritative structured context leaves the PEP and
   a decision returns from the PDP.
5. **TB-5 AgentGate to tool adapter** — validated data reaches side-effect code.
6. **TB-6 Administrator to approval service** — independent human authority acts
   on a pending request.
7. **TB-7 Application to database** — security state crosses into mutable storage.

## STRIDE summary

| STRIDE category | Representative AgentGate threats | Main controls |
| --- | --- | --- |
| Spoofing | Agent impersonation, stolen token use, cross-agent credentials, admin impersonation | Ed25519 workload key, proof-bound short JWT, separate admin audience, revocation, replay store. |
| Tampering | Argument substitution, policy/tool poisoning, provenance changes, audit modification | Canonical hashes, static manifest, server-assigned provenance, migrations/constraints, keyed audit chain/checkpoint. |
| Repudiation | Denied/sent action disputed, approval actor disputed, audit row deletion | Correlation IDs, identity-bound events, append flow, approval actions, hash chain and checkpoint. |
| Information disclosure | Credential exfiltration, sensitive results/logs, file escape | Redaction, encrypted payloads, response schemas/limits, sandbox containment, least privilege. |
| Denial of service | Excessive calls, oversized bodies/results, slow tools/OPA, agent loops | Rate/size/time limits, bounded queries, health/readiness, fail closed. |
| Elevation of privilege | Prompt injection, unknown tool, wildcard capability, SQL/shell/code execution, confused deputy | Exact capabilities, OPA default deny, strict schemas, fixed adapters/query templates, provenance policy, approvals. |

## Agentic-security alignment

The model incorporates current OWASP guidance on prompt injection, tool abuse,
privilege escalation, data exfiltration, memory poisoning, goal hijacking,
excessive autonomy, approval manipulation, multi-agent propagation, resource
exhaustion, and supply-chain risk. The key architectural response is to assume the
agent can be compromised while keeping authorization and execution deterministic
outside it. References:

- [OWASP AI Agent Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html)
- [OWASP Agentic AI: Threats and Mitigations](https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/)

## Threat register and regression evidence

Residual risk assumes all named controls and tests pass. Test names are stable
design identifiers; the implemented suites may group equivalent assertions into
service, API, policy, infrastructure, and evaluation tests.

| ID / STRIDE | Threat and entry point | Required precondition | Affected assets | Security controls | Regression case | Residual risk |
| --- | --- | --- | --- | --- | --- | --- |
| AGT-001 / T,E | **Direct prompt injection** through TB-1 asks the agent to ignore policy and send data. | Attacker can submit task/user text. | A-03, A-04, A-09 | Model is non-authoritative; exact task capabilities; strict tool schemas; OPA; approval for high risk. | `test_direct_prompt_cannot_expand_capabilities` | Injection may change allowed low-risk queries or cause nuisance approval requests within the task's existing scope. |
| AGT-002 / T,E | **Indirect injection in a support ticket** crosses TB-2 and requests `email.send` or secret disclosure. | Agent reads attacker-controlled ticket text. | A-03, A-04, A-05, A-10 | `tickets.read` output is always untrusted; influence propagation; sensitive action denied when only untrusted intent exists. | `test_ticket_injection_cannot_authorize_email_send` | A malicious agent may omit influence IDs; protocol isolation and evaluations expose but do not fully solve omission. |
| AGT-003 / T,E | **Malicious instruction in a retrieved document** crosses TB-2. | Attacker can alter a synthetic external document. | A-03, A-05, A-10 | Source-based label; document content treated as data; derived trust is conservative; capability/approval checks remain independent. | `test_document_instruction_remains_untrusted` | Legitimate instructions embedded in documents need explicit trusted user confirmation. |
| AGT-004 / T,E | **Tool-description poisoning** changes a description to induce unsafe use or downgrade risk. | Attacker influences model context, DB mirror, or config text. | A-06, A-08, A-09 | Version-controlled executable manifest and schemas; startup checksum; descriptions never select adapter/risk/capability; unknown mismatch fails. | `test_poisoned_tool_description_cannot_change_manifest` | Repository/build-pipeline compromise can alter both manifest and tests; CI review/signing is future hardening. |
| AGT-005 / S,E | **Agent impersonation** calls AgentGate using a guessed agent ID. | API is reachable. | A-01, A-09 | Registered public key; request JWS; token signature/claims; constant-time hash comparison; generic errors. | `test_agent_id_without_key_is_rejected` | Stolen workload private key enables impersonation until revocation. |
| AGT-006 / S,E | **Cross-agent credential use** copies Agent A's token into Agent B's process. | Attacker obtains another agent's encoded token but not its private key. | A-01, A-09 | `sub` and `cnf.jkt`; per-request proof covers token and body; registered key must match. | `test_stolen_token_fails_with_other_agent_key` | Theft of both token and corresponding key succeeds during the short validity window. |
| AGT-007 / S,E | **Cross-task token reuse** applies a valid Agent A token to another task. | Same agent has or discovers another task ID. | A-01, A-09 | `task_id` claim, request proof/body binding, stored credential-task relation, OPA task equality, resource ownership checks. | `test_token_cannot_cross_task_boundary` | Over-broad capabilities on the original task still permit their intended scope. |
| AGT-008 / I,S | **Credential exfiltration** via logs, errors, dashboard, tool arguments, or model context. | Attacker can trigger errors/read UI or persuade agent to transmit a token. | A-01, A-11 | Central recursive redaction; no token persistence; safe errors; sensitive headers excluded; strict tool schemas reject token fields; short TTL and proof binding. | `test_tokens_and_secrets_are_redacted_recursively` | Token plus private-key theft from agent memory/host remains possible; endpoint compromise is outside MVP isolation. |
| AGT-009 / T,I,E | **Path traversal** in `files.read/write` escapes the sandbox using `..`, drive/UNC, absolute, encoded, or separator tricks. | Agent has a file capability. | A-03, A-04, A-11 | Relative-path schema; decoding once; absolute/dot-segment rejection; canonical containment; dedicated volume; allowed extension/size. | `test_file_traversal_matrix_is_rejected` | Filesystem/Unicode edge cases require platform-specific regression tests. |
| AGT-010 / T,I,E | **Symbolic-link or Windows reparse-point escape** targets data outside the sandbox. | Attacker can place a link/reparse point within the sandbox or race path checks. | A-04, A-11 | Reject links in every existing component; resolved parent containment; no-follow primitives where available; container volume isolation. | `test_symlink_escape_is_rejected` and `test_reparse_point_escape_is_rejected` | Cross-platform TOCTOU behavior is not eliminated; hostile shared sandbox writers are out of scope. |
| AGT-011 / T,I,E | **SQL injection** enters through `database.query`. | Agent has query capability and controls parameters. | A-03, A-04, A-07 | Exact query-template enum; typed bounded parameters; SQL text is not accepted; SQLAlchemy parameter binding; read-only synthetic DB role where practical. | `test_sql_payload_is_data_not_query` | Logic abuse of an overly broad approved template remains possible and requires template review. |
| AGT-012 / S,T,E | **Approval replay** reuses an already consumed approval or races two approvals. | Attacker observes an approval ID or sends concurrent requests. | A-02, A-03, A-04 | Admin auth; row lock/transaction; one-way state machine; consumed timestamp; one execution; audit. | `test_approval_is_consumed_once_under_race` | Database/application compromise can tamper with state; audit may detect after the fact. |
| AGT-013 / T,E | **Approval argument substitution** changes one character, task, agent, or tool after approval. | Attacker can submit a modified request or manipulate a row. | A-02, A-03, A-04 | Approval binds all IDs and canonical argument hash; constant-time comparison; execute only original authenticated ciphertext; re-run OPA. | `test_one_character_change_invalidates_approval` | Canonicalization bugs are security-critical; differential/property tests are required. |
| AGT-014 / T,R | **Audit-record modification, insertion, deletion, reordering, or truncation** occurs at TB-7. | Attacker can write PostgreSQL but lacks audit key/checkpoint volume. | A-02, A-06, A-07 | Monotonic sequence; HMAC hash chain; advisory-lock append; separate MACed checkpoint; verifier API/CLI. | `test_audit_mutation_matrix_fails_verification` | Combined API/key/checkpoint compromise can forge history; no external immutable anchor in MVP. |
| AGT-015 / D | **Excessive tool invocation** exhausts CPU, storage, OPA, or synthetic services. | Valid or compromised agent loops rapidly. | A-07, A-12 | Per-agent/task/tool rate state; OPA deny; adapter timeout; bounded retry behavior; request quota; audit/metrics. | `test_rate_limit_blocks_excess_calls` | Single-node DB-backed limiter is not a globally distributed quota and can itself face load. |
| AGT-016 / E | **Unknown tool request** tries `shell.exec`, a misspelling, or a crafted adapter name. | Agent can submit arbitrary tool-name text. | A-04, A-08, A-09 | Exact static lookup; `known=false` in OPA; default deny; no reflection/dynamic import; audit. | `test_unknown_tool_is_denied_and_never_dispatched` | A malicious code release that registers an unsafe adapter is supply-chain risk. |
| AGT-017 / T,E | **Schema bypass with unexpected JSON fields**, duplicates, type coercion, or nested payload tricks. | Agent controls request JSON. | A-03, A-04 | Body size/content type; strict outer and per-tool Pydantic models; `extra=forbid`; strict types; duplicate-key rejection during parsing; canonicalization after validation. | `test_unexpected_and_duplicate_fields_are_rejected` | Parser differentials between components must be regression tested when libraries change. |
| AGT-018 / D,I | **Oversized request or response** consumes memory or exfiltrates excessive data. | Attacker can send large body/query or select high-volume result. | A-04, A-07, A-12 | ASGI body limit before JSON parse; bounded fields/counts; adapter result model; byte/item ceilings; explicit truncation/denial; no full result in audit. | `test_request_and_result_size_limits` | Compressed/streaming edge cases need separate controls if later enabled. |
| AGT-019 / T,E | **Memory poisoning** persists external instructions into later tasks or agents. | Agent/demo memory accepts retrieved content. | A-05, A-09, A-10 | Task-scoped memory/provenance; no automatic cross-task writes; untrusted label persists; bounded retention; no memory authority. | `test_untrusted_memory_cannot_cross_task_or_grant_capability` | Semantic contamination within the same task can still influence allowed low-risk behavior. |
| AGT-020 / S,E | **Confused deputy behavior** uses a more privileged task/agent/admin to act for untrusted content or another agent. | Attacker can pass content or identifiers to a privileged actor. | A-01, A-02, A-04, A-09, A-10 | Exact owner/task/agent binding; provenance propagation; no delegated wildcard; admin approval is not agent capability; resource checks at every read. | `test_privileged_agent_cannot_deputize_for_untrusted_only_intent` | A human approver can intentionally authorize a harmful but syntactically valid request. |
| AGT-021 / T,E | **OPA policy tampering or fail-open behavior** weakens default deny. | Attacker changes bundle/file, spoofs OPA response, or OPA becomes unavailable. | A-06, A-09 | Read-only versioned policy mount; expected policy version; internal network; strict decision schema; deny on timeout/error/undefined; policy tests in CI. | `test_opa_failure_and_malformed_decision_fail_closed` | Host/build compromise can replace API and policy together; artifact signing is later hardening. |
| AGT-022 / S,E | **Admin credential theft or cross-use of workload token** approves an action. | Attacker reaches admin endpoint with workload token or steals admin session. | A-02, A-04, A-11 | Separate issuer/audience/role and signing/config path; short admin session; origin/CORS/CSP; exact authorization middleware; audit actor. | `test_workload_token_cannot_call_admin_endpoint` | Local browser/host compromise can act as admin; MFA/SSO is out of scope. |
| AGT-023 / I,T | **Sensitive result leakage** through dashboard, API polling, policy input, or audit events. | Attacker can view another request or logs. | A-04, A-07 | Agent/task ownership checks; admin summaries; result response schemas; encryption at rest; recursive redaction; OPA receives only needed/redacted data. | `test_sensitive_results_are_scoped_and_redacted` | Authorized admin can see operational metadata; traffic confidentiality depends on deployment transport. |
| AGT-024 / T,E | **Provenance forgery or omission** claims untrusted data is trusted or excludes a source. | Agent controls influence fields or database attacker edits provenance. | A-03, A-05, A-10 | Only IDs accepted; labels/source loaded server-side; parent hashes; conservative propagation; invalid/missing referenced IDs deny; audit. | `test_agent_supplied_trust_label_is_ignored` | A malicious agent may omit a real influence; full dynamic information-flow tracking is outside MVP. |
| AGT-025 / D,T | **Replay of signed tool HTTP request** repeats an otherwise valid low-risk or pending action. | Attacker records token, proof, and body during validity window. | A-01, A-03, A-04, A-12 | Proof ID uniqueness, timestamp window, method/path/body/token hash binding, request idempotency rules, database replay record. | `test_signed_request_proof_cannot_be_replayed` | Loss of replay-store availability fails closed and reduces availability. |

## Abuse-case coverage matrix

The evaluation dataset includes both malicious and legitimate neighbors so a
control is not considered effective merely because it blocks everything.

| Control family | Malicious cases | Legitimate neighbor |
| --- | --- | --- |
| Capability scope | Unknown/out-of-task/cross-task tools | Explicit low-risk `documents.search` and `tickets.read`. |
| Provenance | Ticket/document/other-agent instructions requesting sensitive action | User explicitly requests a draft based on untrusted ticket facts. |
| Approval | Replay, expiry, substitution, wrong admin/workload token | Exact unexpired approval for synthetic `email.send`. |
| File containment | Traversal, absolute/UNC, symlink/reparse, oversized/forbidden type | Read/write an allowed relative synthetic file. |
| Query containment | SQL text, tautology/comment payload, unexpected parameter | Known template with valid typed parameters. |
| Resource limits | Burst loop, slow adapter, oversized input/output | Calls immediately below each configured limit. |
| Identity | Expired/revoked/wrong issuer/audience/key/task/proof replay | Valid proof-bound short-lived task token. |
| Audit | Mutation/insertion/deletion/truncation | Untouched multi-event allowed, denied, and approved sequences. |

## Risk treatment priorities

1. **Must block before any adapter exists:** identity/key binding, task capability
   isolation, strict schemas, unknown-tool denial, OPA fail-closed behavior.
2. **Must block before high-risk tools execute:** exact one-shot approval,
   provenance-sensitive denial, encrypted stored arguments, admin separation.
3. **Must prove before security claims:** audit mutation detection and adversarial
   metrics with false-positive/false-negative calculations.
4. **Accepted only for local educational MVP:** single-host trust, custom
   proof-of-possession protocol, application-held audit/encryption keys, DB-backed
   limits, provenance omission risk, filesystem TOCTOU residual, and no immutable
   external audit anchor.

## Validation and maintenance

- Every threat above receives at least one automated negative test; high-risk
  state machines also receive concurrent/property tests.
- Every denial test asserts both non-dispatch and a stable reason code.
- Evaluation reports record actual policy/enforcement latency and audit
  completeness; no metric is written into documentation until measured.
- Policy or static-manifest changes require corresponding Rego/unit/evaluation
  updates in the same review.
- Dependency, container-image, and frontend changes run lint, type, unit,
  integration, policy, Bandit, dependency-audit, and build gates.
- Residual risks are reviewed at each phase boundary and whenever this project is
  connected to non-synthetic data or deployed beyond the trusted local laptop.
