# AgentGate evaluation methodology

This document defines how AgentGate's Phase 7 security measurements are created,
interpreted, and reproduced. The harness measures a versioned deterministic
policy-contract executor over synthetic scenarios. It does not claim that the
same rates will hold for a live model, live OPA service, production data, or an
Internet-facing deployment.

## 1. Evaluation questions

The baseline answers four bounded questions:

1. Do legitimate neighbors reach their expected allow or approval path?
2. Do adversarial requests avoid receiving direct execution authority?
3. Do approval-relevant cases preserve exact approval and provenance rules?
4. Does every scenario produce its required audit sequence, with a chain that
   verifies at the scenario checkpoint?

It does not estimate the probability that an unconstrained model will discover
an unrepresented attack, correctly declare every causal provenance influence, or
resist social engineering outside the protocol.

## 2. Scenario format

Scenario sources are strict JSON documents under `evaluations/scenarios/`. Each
file has `schema_version: 1` and a non-empty `scenarios` array. A source case
contains:

| Field | Purpose |
| --- | --- |
| `scenario_id` | Stable unique identifier used in persistence and reports. |
| `kind` | `legitimate` or `adversarial`; determines rate denominators. |
| `category` | Control family such as identity, approval, or provenance. |
| `agent_task` | Synthetic task description. |
| `trusted_instructions` | Synthetic task-owner authority. |
| `untrusted_content` | Optional attacker-controlled document/ticket/tool text. |
| `requested_tool_action` | Exact tool name and structured arguments. |
| `capabilities` | Exact task grants; wildcards are not supported. |
| `controls` | Server-authoritative facts varied by the case. |
| `expected_security_decision` | `deny`, `require_approval`, or `allow`. |
| `expected_reason_code` | Expected primary stable reason. |
| `approval_relevant` | Includes the case in approval-accuracy measurement. |

Actual decision, actual reason codes, pass status, policy latency, enforcement
latency, audit completeness, and chain validity are observations and therefore
appear only in generated reports and persisted `evaluation_results`, never as
caller-supplied source truth.

The loader rejects duplicate JSON properties, non-finite numbers, extra fields,
type coercion, duplicate scenario IDs, symlinked or oversized files, empty
catalogs, and more than 10,000 scenarios. It merges files in a stable order and
sorts cases by ID, so adding files or growing beyond 200 cases requires no code
change.

## 3. Baseline composition

The required baseline contains exactly 50 scenarios:

- 20 legitimate cases;
- 30 adversarial cases; and
- 12 approval-relevant cases spanning legitimate use and bypass attempts.

Category counts are:

| Category | Cases |
| --- | ---: |
| Approval | 7 |
| Provenance | 6 |
| File containment | 6 |
| Query containment | 6 |
| Schema validation | 5 |
| Identity | 5 |
| Resource limits | 5 |
| Capability scope | 3 |
| Tool containment | 2 |
| Indirect prompt injection | 2 |
| Task isolation | 1 |
| Policy fail-closed | 1 |
| Least privilege | 1 |

The cases include legitimate neighbors so a deny-all implementation cannot score
as effective. Examples include an allowed fixed-template query beside arbitrary
SQL, an allowed sandbox file read beside traversal, an allowed untrusted ticket
read beside ticket-induced email sending, and an exact approved send beside
substitution, expiry, and replay.

## 4. Executor boundary

The current engine ID is
`agentgate-deterministic-policy-contract-v1`. It uses the production static tool
registry and strict Pydantic argument schemas, then evaluates the same
server-authoritative facts and precedence as the versioned Rego policy:

- identity and token state;
- task/capability and registry state;
- strict argument validity;
- provenance context and trusted intent;
- approval binding, expiry, and consumption;
- rate/request/response limits; and
- low, medium, and high risk.

It is intentionally independent of an LLM. It also does not contact OPA. The
engine identity and configuration hash are included in every report, making it
incorrect to describe these numbers as a live OPA or end-to-end Compose result.
When a live executor is added, it must use a distinct engine ID so its reports
cannot be confused with this baseline.

## 5. Pass criteria

A scenario passes only when all four conditions hold:

1. actual decision equals expected decision;
2. primary actual reason equals expected reason;
3. all three required audit events are observed; and
4. the complete evaluation audit chain and checkpoint verify.

Every observation retains all actual reason codes even though persistence also
stores the primary sorted reason for compact queries.

The expected audit sequence is:

```text
evaluation.requested
evaluation.policy_decided
evaluation.completed
```

Audit payloads contain IDs, category, tool name, argument hash, decision,
reasons, latency, engine ID, and whether execution authority was granted. They do
not copy trusted instructions, untrusted prompt text, or raw arguments.

## 6. Metric definitions

Let:

- `A` be adversarial results;
- `L` be legitimate results;
- `P` be approval-relevant results;
- `allow(x)` mean actual decision is `allow`; and
- `pass(x)` mean the complete pass criteria above hold.

| Metric | Formula |
| --- | --- |
| Total scenarios | `|A| + |L|` |
| Attack-success rate | `count(allow(x), x in A) / |A|` |
| Unauthorized-action block rate | `count(not allow(x), x in A) / |A|` |
| Legitimate-task completion rate | `count(pass(x) and actual != deny, x in L) / |L|` |
| False-positive rate | `count(actual == deny, x in L) / |L|` |
| False-negative rate | `count(allow(x), x in A) / |A|` |
| Approval-enforcement accuracy | `count(pass(x), x in P) / |P|` |
| Mean policy latency | Arithmetic mean of measured decision-engine milliseconds. |
| p95 policy latency | Nearest-rank 95th percentile of decision-engine milliseconds. |
| Mean enforcement latency | Mean from scenario start through audit append and verification. |
| Audit-record completeness | Sum of per-case observed/expected record ratios divided by total cases. |
| Audit-chain verification rate | Verified scenario checkpoints divided by total cases. |

`require_approval` counts as blocked for an adversarial action because it conveys
no execution authority. It is not counted as an attack success. An adversarial
case expected to be denied still fails its scenario expectation if it merely
reaches approval, even though the block-rate metric remains safe.

Rates use exact case counts and are rounded to six decimal places. Latencies are
wall-clock observations from `perf_counter_ns`, not claimed service-level
objectives. With only 50 local cases, they are useful for regression comparison,
not capacity planning or statistically representative performance claims.

## 7. Reproducibility and integrity

The runner records:

- a canonical SHA-256 hash over all normalized, ID-sorted scenarios;
- a canonical SHA-256 hash over engine/configuration metadata;
- UTC start and completion timestamps;
- every per-scenario observation; and
- paths to atomically written JSON and Markdown reports.

Reports are written by flushing a temporary file and replacing the destination.
The JSON report is the machine-readable source; Markdown is derived from the same
in-memory report document. `evaluation_runs` stores hashes and aggregate metrics,
while `evaluation_results` stores enough evidence to recompute classification,
latency, audit completeness, and chain-verification rates.

## 8. Running the evaluation

From the repository root:

```powershell
.venv\Scripts\python scripts\run_evaluation.py
```

This validates the 20/30 minimum and writes reports without requiring a database.
The final JSON line includes run ID, hashes, report paths, metrics, and
`persisted: false`. The exit code is `0` only when every scenario passes, `1`
when the run completes with any failed scenario, and `2` when evaluation cannot
run.

To save the run to a migrated configured PostgreSQL database:

```powershell
.venv\Scripts\python scripts\run_evaluation.py --persist
```

The default Compose deployment intentionally does not expose PostgreSQL on a host
port. Run persistence inside the API container instead:

```powershell
docker compose exec api python /scripts/run_evaluation.py --persist
```

Administrators can then read only the latest completed aggregate at
`GET /metrics/security`. If no completed persisted run exists, the endpoint
returns `NO_EVALUATION_DATA` rather than fabricated zeros.

## 9. Interpretation limits

A clean baseline means the listed synthetic cases matched their policy-contract
expectations in this specific run. It does not prove the absence of unknown
attacks, model-level prompt-injection resistance, production immutability,
provenance completeness, or external-system safety. Reported zero rates have a
small fixed denominator and must always be accompanied by the scenario count,
catalog hash, configuration hash, and executor ID.
