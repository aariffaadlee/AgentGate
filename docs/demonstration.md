# AgentGate portfolio demonstration

This script demonstrates the complete Phase 9 security loop using only local,
synthetic data. It does not require an LLM or paid API.

## Prerequisites

Start the Compose stack after replacing all fake values in `.env`:

```powershell
Copy-Item .env.example .env
docker compose up --build --detach --wait
```

Install the backend package in a Python 3.12 virtual environment. Load the same
bootstrap secret used by Compose into the current process without passing it as a
command-line argument:

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -e ".\backend"
$env:AGENTGATE_ADMIN_BOOTSTRAP_SECRET = (Get-Content .env |
  Where-Object { $_ -like 'AGENTGATE_ADMIN_BOOTSTRAP_SECRET=*' } |
  ForEach-Object { $_.Substring($_.IndexOf('=') + 1) })
.venv\Scripts\python scripts\run_demo.py
Remove-Item Env:AGENTGATE_ADMIN_BOOTSTRAP_SECRET
```

The client accepts only an HTTP(S) loopback API origin. Override the default only
when needed with `AGENTGATE_API_URL=http://127.0.0.1:8000`.

## What the demonstration proves

The client performs these API operations in order:

1. Exchanges the bootstrap secret for a separate admin-audience session.
2. Generates a fresh in-process Ed25519 private key and registers only its public
   JWK.
3. Creates a task granting exactly `documents.search` and `email.send` with a
   server-created trusted-intent provenance record.
4. Signs the token request and obtains a five-minute task-bound workload token.
5. Signs an allowed `documents.search`; AgentGate evaluates and executes it.
6. Signs an unknown `shell.exec`; AgentGate denies it without an adapter.
7. Signs a high-risk `email.send`; AgentGate holds it pending approval.
8. Lists approvals, copies the exact canonical argument hash, approves it, and
   observes one-shot consumption/execution.
9. Runs the complete audit-chain and external-checkpoint verifier.

Every workload operation uses a distinct request proof. The private key never
leaves the client process. The client calls no adapter, OPA endpoint, database, or
synthetic fixture directly.

## Expected sanitized output

The exact UUIDs vary. A successful run prints one JSON object like:

```json
{
  "agent_id": "<uuid>",
  "allowed_decision": "allow",
  "allowed_request_id": "<uuid>",
  "approval_id": "<uuid>",
  "approval_status": "consumed",
  "audit_reason_code": "CHAIN_VALID",
  "audit_valid": true,
  "denied_reason_codes": ["ARGUMENTS_INVALID", "CAPABILITY_MISSING", "UNKNOWN_TOOL"],
  "denied_request_id": "<uuid>",
  "status": "passed",
  "task_id": "<uuid>"
}
```

The output intentionally excludes the bootstrap secret, administrator/workload
tokens, private/public key material, trusted full instruction, email arguments,
search results, and arbitrary API response bodies. A failure prints only a stable
demo reason code.

## Reviewer talk track

- Start with the dashboard and point out that it is a view over server decisions,
  not a policy engine.
- Run the script and identify the allow, deny, pending approval, consumed
  approval, and valid audit evidence.
- Open the approval card and show its redacted arguments and exact SHA-256 binding.
- Explain that the one-character substitution, expiry, and replay scenarios are
  separate automated negative tests/evaluation cases.
- Show the Phase 7 report with its denominator and executor limitation before
  quoting any rate.
- End with the known limitations: synthetic tools, local bootstrap admin, no
  hostile-tenant isolation, no production claim.

Stop the local environment when finished:

```powershell
docker compose down
```
