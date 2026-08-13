# Phase 1 explained: secure backend and persistence foundation

Phase 1 implemented the security-sensitive infrastructure on which later
identity and tool mediation depend. It created a FastAPI service with strict
configuration, bounded HTTP handling, redacted structured logs, a normalized
PostgreSQL schema, reversible migrations, and hardened local containers.

**Phase status:** complete
**Primary objective:** make the service safe and observable before adding
authorization or execution
**Historical Phase 1 verification:** 50 passed, 1 live-PostgreSQL test skipped,
94.42% branch-aware coverage

## 1. Why the foundation came first

Adding tokens or tool calls to an unreliable foundation would make later
security claims difficult to trust. Phase 1 therefore addressed the supporting
controls first:

- configuration must reject unsafe production values;
- logs and errors must not disclose credentials;
- requests must be correlated without trusting caller-supplied identifiers;
- oversized or encoded bodies must be rejected before expensive parsing;
- database access must be bounded and lifecycle-managed;
- persisted security facts must have explicit constraints; and
- local containers must minimize unnecessary exposure and privilege.

At the end of this phase, the application could start, report health, connect to
PostgreSQL, migrate its schema, and handle malformed traffic safely. It could
not yet authenticate agents or execute tools.

## 2. Application structure and lifecycle

The service uses an application factory in
[backend/app/main.py](../backend/app/main.py). Centralizing construction makes
configuration and dependencies explicit and allows tests to create isolated app
instances.

Startup performs the following work:

1. load and validate typed settings;
2. configure structured JSON logging;
3. create the bounded async database engine and session factory;
4. register middleware, exception handlers, and API routes; and
5. expose shared dependencies through application state.

The lifespan handler owns cleanup and disposes of the async engine during
shutdown. This prevents connection leakage and gives tests a deterministic
lifecycle.

The current application factory also wires Phase 2 identity and OPA services.
Those additions follow the same dependency pattern established in Phase 1; they
were not part of the original Phase 1 deliverable.

## 3. Strict environment configuration

[backend/app/config.py](../backend/app/config.py) uses typed settings with the
`AGENTGATE_` prefix. Declared settings with malformed or unsafe values fail
during startup rather than silently selecting an insecure default. Unrelated
extra environment values are ignored.

Important foundation controls include:

- the database URL is a secret value and is excluded from normal
  representations;
- only the asynchronous PostgreSQL driver form, `postgresql+asyncpg`, is
  accepted;
- connection pool, timeout, body-size, CORS, and documentation settings are
  bounded and validated;
- permissive wildcard CORS is not used with credentials;
- production mode rejects known development credentials and unsafe debug
  settings; and
- API documentation is an explicit setting instead of an unavoidable endpoint.

Phase 2 later added signing, encryption, bootstrap, token, proof, and OPA
settings to the same configuration boundary.

## 4. Structured logging and secret redaction

[backend/app/logging.py](../backend/app/logging.py) configures structured JSON
events through `structlog`. Machine-readable events make security analysis and
future audit integration more reliable than free-form log strings.

The redaction layer recursively examines nested mappings and collections. Field
names associated with passwords, authorization headers, cookies, tokens, keys,
and secrets are replaced before serialization. Secret-wrapper objects are also
handled without revealing their underlying value.

HTTP access logging records a small allowlist of metadata, including the trusted
request ID, method, path, status, and duration. It deliberately does not log
request bodies, query strings, headers, or exception text. This
reduces the chance that an otherwise useful access log becomes a credential or
sensitive-data sink.

## 5. HTTP boundary controls

[backend/app/api/middleware.py](../backend/app/api/middleware.py) establishes a
defensive request boundary.

### Trusted request correlation

The application accepts a caller correlation identifier only when it is a valid
UUID and normalizes it before use; otherwise it generates a fresh UUID. It
returns the canonical value in the response. Arbitrary strings therefore cannot
inject log syntax or create ambiguous identifiers.

### Body limits before JSON parsing

The middleware rejects bodies that exceed the configured limit using the
declared length and while receiving streamed chunks. It also rejects ambiguous
duplicate `Content-Length` values and unsupported content encodings. These
checks happen before JSON parsing, reducing memory and decompression risks.

### Restrictive response headers

Security headers reduce browser-side exposure, including MIME sniffing,
framing, referrer leakage, and overly broad content loading. CORS is limited to
configured local origins rather than reflecting arbitrary origins.

### Stable access events

Successful and failed responses produce bounded access metadata. Internal
exceptions are logged in a controlled form without reflecting their details to
the caller.

## 6. Stable API errors

[backend/app/api/errors.py](../backend/app/api/errors.py) returns a consistent
error envelope containing a stable code, a safe message, the request ID, and
optional field-level validation details.

The handler normalizes validation failures instead of exposing framework
objects or submitted secret values. Unexpected exceptions map to a generic
internal error. Clients can therefore act on stable codes while operational
details remain in controlled logs.

## 7. Health and readiness

[backend/app/api/health.py](../backend/app/api/health.py) separates process
liveness from dependency readiness:

- `/health/live` answers whether the API process is alive;
- `/health` provides a concise service-health response; and
- `/health/ready` checks whether required dependencies are usable.

In Phase 1, readiness primarily represented database connectivity. Phase 2
extended it to include the OPA service health check. Keeping liveness and
readiness separate prevents a
temporary dependency failure from being mistaken for a dead process while also
preventing traffic from reaching an unusable instance.

## 8. Database access

[backend/app/db/session.py](../backend/app/db/session.py) creates an async
SQLAlchemy engine using `asyncpg`. Pool size, overflow, acquisition timeout,
connection pre-ping, and health-check timeout are controlled through validated
settings.

Sessions are created through a scoped dependency and closed at the end of the
request. Business code receives a session rather than creating unmanaged
connections. Database URLs remain secret-bearing values and are not included in
ordinary logs.

## 9. Normalized security schema

The initial migration,
[0001_initial_schema.py](../backend/migrations/versions/0001_initial_schema.py),
created normalized tables covering:

- agent identities, credentials, and revocations;
- tasks and exact capability grants;
- tool definitions and tool requests;
- policy decisions and approval records;
- provenance labels and propagation relationships;
- audit events and chain checkpoints; and
- evaluation runs and individual evaluation results.

The schema uses UUID identifiers, timezone-aware timestamps, explicit enums,
foreign keys, uniqueness constraints, indexes, and JSONB only where structured
variable data is appropriate. Exact capability naming rules reject wildcard
grants.

Encoded access tokens and private keys have no persistence column. Credential
records are designed to hold token identifier hashes and public binding facts,
while proof replay protection uses unique digests. Approval records include the
fields needed to bind a future approval to one exact request.

The migration has an explicit downgrade path. Offline SQL generation is tested,
and the optional live integration test upgrades and downgrades a disposable
PostgreSQL database whose name is clearly marked for testing.

Phase 2 added a second migration for task-to-agent assignment. That later change
is described in [Phase 2](phase-2-explained.md).

## 10. Container and network hardening

The [backend/Dockerfile](../backend/Dockerfile) uses a pinned Python 3.12 slim
base, installs only required runtime dependencies, and runs the application as
an unprivileged user.

[docker-compose.yml](../docker-compose.yml) applies local defense in depth:

- the API binds only to `127.0.0.1` on the host;
- PostgreSQL is available only on an internal Compose network;
- containers use health checks and explicit dependencies;
- the API root filesystem is read-only with a small writable temporary area;
- `no-new-privileges` prevents gaining additional process privileges; and
- resource and process limits reduce accidental exhaustion.

OPA appears in the current Compose file because it was added in Phase 2.

## 11. Verification performed in Phase 1

The Phase 1 gate finished with:

- 50 passing tests;
- 1 skipped live PostgreSQL migration test because Docker/PostgreSQL was not
  available in the execution environment;
- 94.42% branch-aware Python coverage;
- clean Ruff linting and formatting checks;
- strict MyPy validation;
- clean Bandit static analysis;
- dependency consistency and vulnerability checks; and
- successful offline Alembic upgrade and downgrade SQL generation.

Tests covered configuration rejection, secret-safe representations, logging
redaction, error normalization, request IDs, security headers, CORS behavior,
body limits, health checks, database construction, model constraints, migration
shape, and container configuration.

The live PostgreSQL and full Compose runtime gates remained environmental
limitations, not silently claimed successes.

## 12. What Phase 1 did not implement

Phase 1 did not provide:

- administrator or workload authentication;
- agent public-key registration;
- task-assigned capabilities or JWT issuance;
- proof-of-possession or replay protection;
- revocation enforcement;
- OPA policy evaluation;
- tool validation or execution;
- human approval, provenance propagation, audit chaining, or evaluations.

This distinction is important: a secure web-service foundation is necessary,
but it is not itself an agent security gateway.

## 13. How Phase 1 prepared Phase 2

Phase 2 could add identity and deterministic policy without rebuilding basic
infrastructure. It reused the settings boundary for cryptographic configuration,
the database lifecycle for live credential checks, the migration discipline for
assignment constraints, stable errors for authentication failures, request IDs
for decision correlation, and readiness for OPA dependency checks.

The result is a layered system in which identity and policy code rely on a
tested, bounded, and observable substrate.

## 14. What this phase demonstrates

Phase 1 demonstrates secure backend engineering beyond endpoint creation:
secret-safe configuration, fail-fast validation, async resource lifecycle,
defensive middleware, structured observability, normalized security data,
reversible migrations, container least privilege, and honest verification of
what was and was not exercised.
