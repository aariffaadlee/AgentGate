# Phase 9 explained: delivery gates and portfolio completion

Phase 9 turns the implemented AgentGate MVP into a reviewable, repeatable
portfolio project. It adds no broader tool authority. Its purpose is to make the
existing security claims reproducible, document their limits, and exercise the
real public API through a proof-bound client.

## 1. Phase outcome

The completed source tree now includes:

- a five-job CI workflow for backend, frontend, OPA, CodeQL, and Compose;
- commit-pinned third-party actions and a checksum-pinned OPA download;
- weekly bounded Dependabot configuration for Python, npm/pnpm, and Actions;
- Python and JavaScript production dependency audits;
- an API-only demonstration client with fresh Ed25519 request proofs;
- security policy, contribution guide, MIT license, API guide, security model,
  demonstration talk track, and resume-safe summary;
- a clearly labelled synthetic dashboard screenshot; and
- a retained Phase 9 evaluation report with exact denominator, hashes, executor
  boundary, metrics, and scenario evidence.

The project remains an educational local MVP. Phase 9 improves evidence and
delivery discipline; it does not convert the system into a production service.

## 2. Continuous integration design

`.github/workflows/ci.yml` separates independent failure domains:

| Job | Enforced evidence |
| --- | --- |
| Backend | Locked install, Ruff format/lint, strict MyPy, pytest with coverage, Bandit, `pip check`, third-party `pip-audit`, byte-compilation, deterministic evaluation. |
| Frontend | Frozen pnpm install, zero-warning ESLint, Vitest, strict runtime response contracts, a Chromium approval-flow smoke test, TypeScript/Vite production build, and high-severity production dependency audit. |
| Policy | SHA-256 verification of OPA 1.18.2, Rego tests, and a 90% policy-coverage threshold. |
| CodeQL | `security-extended` analysis for Python and JavaScript/TypeScript. |
| Compose | Ephemeral secrets, config validation, clean image build, health-gated startup, host and proxy probes, persisted evaluation, proof-bound demo, logs on failure, unconditional volume cleanup. |

Workflow permissions default to read-only. CodeQL alone receives
`security-events: write`. Concurrency cancels stale runs for the same branch/ref.
Every `uses:` reference is a 40-character commit SHA. The OPA executable is
accepted only after its published checksum matches.

The Compose job uses `development`, not `test`, application mode so startup
installs/verifies the static executable-tool manifest before the demonstration.
Generated credentials exist only in the ephemeral workflow environment and `.env`
file; `docker compose down --volumes` runs even after a failure.

## 3. Dependency and static security gates

Python dependencies are exact-pinned in `backend/pyproject.toml`. The audit skips
only the local editable `agentgate-backend` distribution, which has no PyPI
advisory identity, while auditing every installed third-party package. Omitting
`--strict` is intentional: current `pip-audit` treats an editable local project as
an audit error even with `--skip-editable`; vulnerability findings still produce
a non-zero exit.

Frontend dependencies and the pnpm package manager are pinned, installed from the
frozen lockfile, and audited with production-only/high-severity failure semantics.
Bandit covers the backend application, while CodeQL adds interprocedural analysis
for both implementation languages. Dependabot suggestions remain subject to all
gates and human review.

## 4. Proof-bound demonstration client

`demo_agent/client.py` proves that a client can use the intended protocol without
an adapter shortcut. It:

1. exchanges the local bootstrap secret for an admin-audience session;
2. generates an in-memory Ed25519 key and registers only the public JWK;
3. creates a task with exact grants and trusted owner intent;
4. signs the pre-token request and obtains a task-bound workload token;
5. signs an allowed `documents.search` request;
6. signs a denied, unregistered `shell.exec` request;
7. signs an `email.send` request that stops pending high-risk approval;
8. copies the server-displayed exact argument hash into the approve operation; and
9. verifies the complete audit chain and external checkpoint.

Each workload operation has a distinct one-time proof. The client permits only a
loopback HTTP(S) API origin, disables redirects, bounds time, requires JSON, and
turns failures into content-free reason codes. Its returned summary excludes
bootstrap/admin/workload credentials, key material, trusted full instructions,
email arguments, adapter results, and raw response bodies.

The Compose CI job runs this client against the real API, PostgreSQL, and OPA.
Unit contract tests additionally verify public-key-only registration, separate
administrator/workload authorization headers, four distinct request proofs, exact
hash submission, non-loopback rejection, and credential-free output.

## 5. Documentation and portfolio evidence

Phase 9 adds these reviewer entry points:

- `README.md` — problem, external-authorization rationale, Mermaid architecture,
  trust boundaries, installation, demo, allow/deny/approval examples, measured
  metrics, screenshot, limitations, and disclaimer;
- `SECURITY.md` — private reporting, safe-research boundary, support and
  non-guarantees;
- `CONTRIBUTING.md` — environment, gates, and security-change checklist;
- `docs/api.md` — authentication classes, endpoint/status matrix, examples,
  sanitized errors, and collection limits;
- `docs/security-model.md` — principals, authority, enforcement order, failure
  semantics, residual risk, and non-goals;
- `docs/demonstration.md` — exact local commands, expected safe output, and a
  reviewer talk track; and
- `docs/resume-summary.md` — concise claims that preserve the synthetic
  denominator and avoid production overstatement.

The screenshot at `docs/assets/phase-8-dashboard.png` was captured from a local
synthetic fixture. Phase 8 visual QA covered 1440×1000 and 720×900 viewports with
no browser console errors or warnings; the responsive layout remained usable.

## 6. Phase 9 verification evidence

The final local gates on Windows/Python 3.12.13 produced:

- backend pytest: 214 passed, 2 skipped live-service integration tests;
- branch-aware backend coverage: 85.27% (80% minimum);
- Ruff formatting and lint: passed across app, tests, migrations, demo, scripts;
- strict MyPy: passed across the backend app and demo client;
- Bandit, `pip check`, and Python byte-compilation: passed;
- repository secret-pattern scan: passed without printing matched content;
- Python third-party dependency audit: no known vulnerabilities found;
- frontend ESLint: passed with zero warnings;
- frontend Vitest: 6/6 passed;
- Playwright Chromium: 1/1 administrator authentication and exact-approval flow passed;
- TypeScript/Vite: production build passed (215.74 kB JavaScript and 22.94 kB
  CSS before gzip);
- frontend production dependency audit: no known vulnerabilities found;
- workflow/Dependabot YAML parsing and static commit-pin assertions: passed; and
- fresh deterministic evaluation: 50/50 scenarios passed (20 legitimate, 30
  adversarial), 0/30 attack successes, 30/30 unauthorized actions blocked,
  100% approval accuracy, audit completeness, and chain verification.

Fresh evaluation identity:

- run ID: `7b8896fe-4d93-470e-b862-542409cbc628`;
- scenario-set hash:
  `sha256:f3c1fd010768130832643794ffd04543dd55f82e70ba30776939805223801bb0`;
- configuration hash:
  `sha256:8262c231b3a78af89f95e67e8cba1823cf51b2570bb320a6ca2cc6784e6805bc`;
- mean/p95 policy-contract latency: 0.032162 ms / 0.045000 ms; and
- mean enforcement latency: 12.391704 ms.

The two local pytest skips require a disposable PostgreSQL service and live OPA.
Neither Docker nor an OPA executable is installed on this host, so the live
migration, live Rego, image build, Compose startup, persisted evaluation, and real
demo cannot honestly be reported as locally executed. The CI policy and Compose
jobs are the executable gates for those exact checks; Phase 9 does not silently
convert their absence into a pass.

## 7. Interpretation limits

The 50-case result measures the deterministic policy-contract executor declared
in the report, not a live language model or production traffic. A zero measured
attack-success rate means 0 of 30 declared adversarial cases received `allow`; it
does not estimate the probability of unknown attacks. Local timing over 50 cases
is regression evidence, not a capacity or latency service-level objective.

The dashboard remains a browser process, not an authority. Successful response
contracts are runtime-validated field by field and fail closed on unknown or
malformed shapes. A compromised browser, host, administrator, application, database plus
checkpoint authority, or supply chain can exceed this MVP's security boundary.
No documentation or CI result should be represented as formal verification,
independent assessment, compliance, or production readiness.
