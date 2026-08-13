# AgentGate Phase 0 plan

**Status:** approved historical baseline; Phases 1 through 9 are now implemented
**Date:** 2026-08-11
**Project:** AgentGate: A Zero Trust Security Runtime for AI Agents

## Repository inspection

The repository was inspected before any project files were created.

- The workspace was an empty Git repository on `master` with no commits.
- No source files, uncommitted user changes, or generated artifacts existed.
- No `AGENTS.md` or other repository-local instructions existed.
- Phase 0 therefore establishes the first project files; it does not replace or
  reinterpret existing work.

## Exact MVP boundary

The AgentGate MVP is a local, educational security runtime that proves the
following end-to-end path:

1. An administrator registers an agent's public workload key and creates a task
   with an explicit capability set.
2. The agent proves possession of its private key and receives a short-lived,
   task-scoped access token.
3. Every structured tool request reaches the AgentGate policy-enforcement point;
   demo tools have no agent-reachable network interface.
4. AgentGate authenticates the token and request proof, loads authoritative task
   and provenance state, strictly validates arguments, checks rate/resource
   state, and sends one complete decision document to OPA.
5. OPA returns one deterministic outcome: `deny`, `require_approval`, or `allow`,
   plus stable reason codes. A missing, malformed, or unavailable policy response
   is a denial.
6. Allowed requests run only through a registered in-process adapter. Approval
   requests bind to the stored request's agent, task, tool, and canonical argument
   hash and are consumed exactly once.
7. Every transition is recorded in a redacted, keyed hash chain whose integrity
   can be verified by both an API endpoint and a command-line script.
8. A 50-scenario minimum evaluation suite measures legitimate and adversarial
   behavior and produces JSON and Markdown reports.
9. A small React dashboard exposes only administrative views and actions: agents,
   tasks, decisions, pending approvals, audit status, and measured evaluation
   metrics.

The MVP includes all seven synthetic tools in the brief:
`documents.search`, `tickets.read`, `email.create_draft`, `email.send`,
`files.read`, `files.write`, and `database.query`.

### MVP exit criteria

The implementation is not called complete until each acceptance criterion in the
project brief is represented by an automated test or a documented, repeatable
demonstration. In particular:

| Capability | Required proof |
| --- | --- |
| Workload identity | An agent-bound request proof succeeds; a stolen token used without the agent key fails. |
| Task isolation | The same agent token fails against a different task, even when that task grants the requested tool. |
| Least privilege | An explicitly granted low-risk read succeeds and a missing capability is denied. |
| Approval integrity | A high-risk request is pending; exact approval succeeds once; expiry, replay, and a one-character substitution fail. |
| Provenance control | Ticket/document injection remains labelled untrusted and cannot independently cause a sensitive action. |
| Tool containment | Traversal, symlink escape, arbitrary SQL, unknown tools, and extra JSON fields are rejected. |
| Resource governance | Rate, request-size, response-size, and execution-time limits are enforced outside the model. |
| Audit integrity | A complete normal chain verifies; direct database modification, insertion, deletion, and truncation tests fail verification. |
| Evaluation | Reports contain measured metrics from at least 20 legitimate and 30 adversarial scenarios. |
| Local operation | The documented Docker Compose workflow starts the API, PostgreSQL, OPA, and frontend without a paid API or model download. |

The brief's acceptance criteria map to planned evidence as follows:

| ID | Acceptance evidence |
| --- | --- |
| AC-01 | Registration, task creation, proof-of-possession token issuance, and claim-validation integration tests. |
| AC-02 | Network/dependency test proving the demo-agent container can reach AgentGate but no adapter endpoint exists. |
| AC-03 | Allowed `documents.search` or `tickets.read` request with complete policy and audit records. |
| AC-04 | Missing-capability scenario returning `CAPABILITY_MISSING` with zero adapter dispatches. |
| AC-05 | `email.send` returning pending status and an exact-bound approval record. |
| AC-06 | Approved original request re-evaluated and executed once from server-stored arguments. |
| AC-07 | Required one-character argument-substitution test returning `APPROVAL_ARGUMENT_MISMATCH`. |
| AC-08 | Expired and concurrently replayed approval tests returning stable denial reasons. |
| AC-09 | Synthetic ticket injection scenario denied as untrusted-only sensitive intent. |
| AC-10 | Traversal plus Linux symlink and Windows reparse-point containment tests. |
| AC-11 | Allowed, denied, pending, approved, and executed sequences reconstruct correctly by correlation ID. |
| AC-12 | Direct audit mutation/deletion/insertion/truncation tests fail chain/checkpoint verification. |
| AC-13 | A real evaluation run writes JSON/Markdown reports and internally consistent measured metrics. |
| AC-14 | Clean documented Docker Compose build/start and all service health checks. |
| AC-15 | CI gates for backend/policy/frontend tests, typing, lint, dependency and security scans. |
| AC-16 | Secret-pattern scan plus repository review confirming only fake/synthetic fixtures. |

### Deliberately out of scope

- Real email, banking, cloud, production database, filesystem, or MCP connectors.
- Arbitrary terminal, shell, Python execution, dynamic imports, or user-supplied
  adapter code.
- Production key management, hardware-backed keys, enterprise SSO, mTLS PKI, or
  high-availability deployment.
- A distributed rate limiter or multi-region transaction semantics.
- A general-purpose operating-system sandbox. File controls are defense in depth
  around a dedicated synthetic-data volume, not a replacement for container/OS
  isolation.
- Model training, model-output safety classification, or a claim that prompt
  injection is solved. The system limits what a compromised agent can do.
- Production-grade immutable/WORM audit storage or external transparency-log
  anchoring.
- Ollama as a required dependency. An optional adapter may generate demo tool-call
  requests, but deterministic fixtures drive the core tests and evaluation.

## Assumptions

- Runtime Python is 3.12 or newer. PostgreSQL, not SQLite, is the integration-test
  database so security-relevant transaction behavior is not silently changed.
- All persisted timestamps use timezone-aware UTC and identifiers use UUIDs,
  except for the monotonic audit sequence.
- Tool capabilities are exact names such as `tickets.read`; no wildcard capability
  exists in the MVP.
- Agent registration and task creation are administrative operations. The agent
  cannot self-grant a key, task, owner, capability, risk tier, or provenance label.
- The dashboard is an administrative client. Admin credentials use a different
  audience and authorization path from workload credentials.
- The authoritative executable tool registry is version-controlled code. The
  database registry is a queryable mirror for policy context and the dashboard;
  a mismatch fails closed.
- Test-only keys and synthetic identities are visibly marked and never accepted by
  non-test configuration.
- OPA is the policy decision point. AgentGate remains the policy enforcement point:
  it authenticates inputs, builds context, enforces the decision, and never treats
  `require_approval` as permission to execute.

## Engineering sequence and gates

| Phase | Deliverable | Exit gate before continuing |
| --- | --- | --- |
| 0 | MVP boundary, architecture, threat model, proposed Phase 1 files | Document review; no unresolved foundational trust-boundary decision. |
| 1 | FastAPI, configuration, PostgreSQL models/migration, logging, errors, health, test foundation | Unit and PostgreSQL integration tests pass; migration upgrades a clean database. |
| 2 | Agent keys, proof-bound tokens, task capabilities, revocation, OPA policy | JWT/proof negative tests and every Rego rule test pass against real OPA. |
| 3 | Static tool registry, schemas, seven safe adapters, limits, request audit | Positive, negative, timeout, rate, traversal, SQL, and schema tests pass. |
| 4 | Exact-request, one-shot approval workflow and admin separation | Expiry/replay/substitution tests pass, including the one-character demonstration. |
| 5 | Server-assigned provenance and taint propagation | Direct/indirect injection and confused-deputy tests pass. |
| 6 | Keyed audit chain, external checkpoint, verification API/CLI | Mutation, deletion, insertion, and truncation tests are detected. |
| 7 | Expandable scenario runner and measured reports | At least 50 scenarios run and report internally consistent metrics. |
| 8 | React/TypeScript dashboard | Frontend tests/build pass; secrets and full sensitive results are absent from views. |
| 9 | CI, scans, Compose verification, complete documentation | Test/type/lint/security/build/evaluation gates pass; limitations remain explicit. |

## Original proposed Phase 1 changes

The following file plan was recorded during Phase 0 and was subsequently
implemented and extended by Phases 1 and 2.

```text
AgentGate/
├── backend/
│   ├── app/
│   │   ├── api/
│   │   │   ├── errors.py
│   │   │   ├── health.py
│   │   │   └── middleware.py
│   │   ├── db/
│   │   │   ├── base.py
│   │   │   └── session.py
│   │   ├── models/
│   │   │   ├── approval.py
│   │   │   ├── audit.py
│   │   │   ├── evaluation.py
│   │   │   ├── identity.py
│   │   │   ├── policy.py
│   │   │   ├── provenance.py
│   │   │   ├── task.py
│   │   │   └── tool.py
│   │   ├── config.py
│   │   ├── logging.py
│   │   └── main.py
│   ├── migrations/
│   │   ├── versions/0001_initial_schema.py
│   │   └── env.py
│   ├── tests/
│   │   ├── integration/test_migrations.py
│   │   ├── test_config.py
│   │   ├── test_errors.py
│   │   ├── test_health.py
│   │   └── conftest.py
│   ├── alembic.ini
│   ├── Dockerfile
│   └── pyproject.toml
├── scripts/
│   └── wait_for_postgres.py
├── .dockerignore
├── .env.example
├── .gitignore
├── docker-compose.yml
└── README.md
```

### Phase 1 implementation notes

- `config.py` will use a strict settings model; startup rejects missing secrets,
  unsafe production defaults, malformed origins, and invalid size/timeout values.
- The initial migration will create the normalized schema described in
  [architecture.md](architecture.md), including constraints and indexes, even
  though later phases add behavior around those tables. This avoids a temporary
  incompatible data model.
- Structured JSON logging will use a central redaction processor. Exception
  handlers will return a stable envelope with an opaque request ID and will never
  serialize raw exceptions.
- Health will distinguish liveness from readiness. `/health` reports component
  status without version banners, credentials, connection strings, or stack
  traces.
- Compose in Phase 1 will start the API and PostgreSQL with health checks. OPA and
  frontend services will be added when their implemented components arrive in
  Phases 2 and 8; no nonfunctional placeholder containers will be added.
- Dependency versions will be selected and pinned at implementation time from
  mutually compatible current stable releases. The lock/pin diff and audit output
  will be reviewable rather than guessed in this design document.
- Unit tests will remain fast and isolated; database behavior and migrations will
  run against PostgreSQL in Compose/CI.

## Phase 0 deliverables

- [Architecture and security design](architecture.md)
- [STRIDE and agentic-security threat model](threat-model.md)
- This MVP/phase plan and proposed Phase 1 file list

Phase 1 should begin only after this baseline is accepted or amended.
