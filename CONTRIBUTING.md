# Contributing to AgentGate

Contributions should preserve AgentGate's central invariant: the model proposes a
structured action, while deterministic code outside the model decides and
enforces whether it may execute.

## Development setup

Use Python 3.12+, Node.js 24+, pnpm 11+, Docker Compose v2, and the OPA version
pinned in the CI workflow. Copy `.env.example` to `.env` and replace every fake
secret with an independent local value. Never commit `.env` or generated keys.

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -e ".\backend[dev]"
Set-Location frontend
pnpm install --frozen-lockfile
```

## Required local gates

Run from the repository root unless a command changes directory:

```powershell
.venv\Scripts\python -m ruff format --check backend demo_agent scripts
.venv\Scripts\python -m ruff check backend demo_agent scripts
.venv\Scripts\python -m mypy backend\app demo_agent
.venv\Scripts\python -m pytest backend
.venv\Scripts\python -m bandit -q -r backend\app
.venv\Scripts\python -m pip check
.venv\Scripts\python -m pip_audit --skip-editable
.venv\Scripts\python scripts\check_repository_secrets.py
.venv\Scripts\python scripts\run_evaluation.py
opa test policies --coverage --threshold 90
Set-Location frontend
pnpm lint
pnpm test
pnpm build
pnpm exec playwright install chromium
pnpm test:e2e
pnpm audit --prod --audit-level high
```

On a Docker-capable host also run:

```powershell
docker compose config --quiet
docker compose build --pull
docker compose up --detach --wait
docker compose exec -T api python /scripts/run_evaluation.py --persist
docker compose down --volumes --remove-orphans
```

CI additionally runs `pip-audit`, CodeQL, live PostgreSQL/OPA checks, the
proof-bound demo, and the complete Compose startup workflow.

## Security change checklist

- Treat every agent field as untrusted until server-side validation.
- Keep tool names, schemas, risk tiers, limits, and adapters in the static
  registry; never dynamically import caller-selected code.
- Derive capabilities, task state, provenance labels, approval state, and policy
  context from authoritative storage.
- Require a fresh token-bound Ed25519 proof for each workload request.
- Make errors fail closed and expose only stable reason codes.
- Do not log tokens, keys, full arguments, instructions, response bodies, or
  connection strings.
- Preserve exact-hash, expiring, one-shot approvals and approval-time
  re-evaluation.
- Add positive, negative, replay, malformed-input, and outage tests for new
  authorization paths.
- Update the threat model, API documentation, and phase evidence when a trust
  boundary or claim changes.

## Pull requests

Keep changes focused and explain the threat or failure mode being addressed.
Document test evidence and any gate that could not run locally. Use only synthetic
fixtures. Do not weaken a security assertion merely to make a test pass; update
the design and its evidence together when an invariant genuinely changes.
