# Resume-ready AgentGate summary

Use claims below only with the repository and measured denominator available for
context. Do not describe AgentGate as production-deployed or independently
validated.

## One-line project description

Built AgentGate, a local Zero Trust policy-enforcement runtime that mediates
synthetic AI-agent tool calls outside the model using proof-bound workload
identity, task-scoped least privilege, OPA policy, exact-request human approval,
provenance controls, and tamper-evident audit evidence.

## Resume bullets

- Architected and implemented a FastAPI/PostgreSQL/OPA enforcement path for seven
  strictly typed synthetic tools, with default-deny policy, task-scoped exact
  capabilities, server-owned rate/size/time limits, and fail-closed dependency
  behavior.
- Designed Ed25519 proof-of-possession workload identity: short-lived task-bound
  JWTs plus one-time request proofs bound to method, path, canonical body, and
  token hash; added immediate persisted revocation checks.
- Built expiring, one-shot administrator approvals bound to agent, task, tool, and
  canonical argument hash, including fresh policy evaluation and transactional
  consumption before dispatch.
- Added authoritative provenance and conservative untrusted-data propagation to
  block sensitive actions derived only from prompt-injected document/ticket
  content.
- Implemented an HMAC-linked redacted audit chain with an independently MACed
  checkpoint and mutation/deletion/insertion/truncation verification tests.
- Created a React/TypeScript security console with strict runtime response validation
  and Chromium approval-flow coverage, plus a deterministic evaluation
  harness; the recorded synthetic policy-contract baseline passed 50/50 cases
  (20 legitimate, 30 adversarial) with a 0/30 measured attack-success rate.
- Established pinned CI gates for Python and TypeScript quality, dependency
  auditing, CodeQL, OPA coverage, Docker Compose health, a proof-bound end-to-end
  demo, and persisted evaluation evidence.

## Interview explanation

The key design decision was to treat the AI agent as a potentially compromised
workload, not as the authorization authority. The agent can propose an action,
but deterministic services authenticate the workload, reconstruct live task and
provenance context, validate a static schema, ask OPA, and select an internal
adapter. High-risk proposals remain non-executable until a human approves the
exact stored argument hash; approval is then revalidated and consumed once.

The strongest honest limitation is that the evaluation is a deterministic
synthetic policy-contract suite, not a live LLM red-team or production benchmark.
The project demonstrates security architecture and engineering controls; it does
not claim prompt injection is solved.

## Portfolio links within the repository

- [README and measured results](../README.md)
- [Security architecture](architecture.md)
- [Threat model](threat-model.md)
- [API guide](api.md)
- [Demonstration script](demonstration.md)
- [Phase 9 verification](phase-9-explained.md)
