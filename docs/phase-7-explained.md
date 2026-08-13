# Phase 7 explained: measured adversarial evaluation

Phase 7 adds a strict, expandable red-team catalog and a deterministic runner
that produces evidence-backed JSON and Markdown reports. It measures both
malicious cases and legitimate neighbors, stores enough per-case evidence to
recompute aggregate rates, and exposes only the latest completed persisted
metrics to administrators.

**Phase status:** complete
**Baseline:** 20 legitimate plus 30 adversarial scenarios
**Security objective:** replace unmeasured safety claims with versioned,
reproducible observations and explicit limitations.

## 1. Evaluation pipeline

```text
Strict JSON catalog
  -> duplicate/type/size/baseline validation
  -> canonical scenario-set hash
  -> deterministic policy-contract execution
  -> three-event keyed audit sequence per case
  -> actual decision/reason/latency/audit evidence
  -> recomputed aggregate metrics
  -> atomic JSON + Markdown reports
  -> optional transactional PostgreSQL persistence
```

The input catalog never supplies an actual result. The runner creates actual
decision, reason codes, pass status, policy and enforcement latency, audit
completeness, and chain status after execution.

## 2. Scenario coverage

The source files are:

- `evaluations/scenarios/legitimate.json` — 20 allowed or correctly held
  legitimate operations;
- `evaluations/scenarios/adversarial.json` — 30 attacks expected to be denied.

They cover identity expiry/revocation/proof failure, cross-task credentials,
missing capability, unknown tools and registry drift, malformed arguments,
traversal and forbidden extensions, fixed-query containment, email field
injection, rate/resource limits, policy outage, invalid/unknown/untrusted
provenance, support-ticket/document prompt injection, and exact approval
substitution/expiry/replay.

Legitimate neighbors include bounded reads, fixed queries, safe drafts, inert
SQL-shaped parameter values, untrusted data treated as data, requests correctly
entering approval, and exact approved actions.

The strict loader merges up to 1,000 bounded files and 10,000 unique scenarios,
so the dataset can expand beyond 200 cases without changing the runner.

## 3. Measurement engine

The current report identifies its executor as
`agentgate-deterministic-policy-contract-v1`. It uses the production static tool
registry and strict argument models and mirrors the Rego decision contract over
synthetic authoritative facts. It does not call an LLM, OPA, PostgreSQL, or real
external tool.

This boundary is intentional and visible in the report configuration and
limitations. The result measures deterministic contract behavior on this host;
it is not represented as a live OPA/Compose, model-red-team, or production
effectiveness result.

## 4. Persisted evidence

Migration `0006_evaluation_evidence.py` extends each result with:

- legitimate/adversarial scenario kind;
- expected and actual primary reason codes;
- measured policy and enforcement latency;
- audit completeness; and
- per-scenario audit-chain validity.

Evaluation-run scenario and configuration hashes are constrained to canonical
SHA-256 values. Policy latency must be nonnegative. The run keeps aggregate
metrics and report paths, while each scenario ID is unique within its run.

The repository first persists `running`, then commits results and `completed` as
one completion transaction. A runner exception marks the persisted run `failed`
without inventing partial aggregate metrics.

## 5. Reports

`scripts/run_evaluation.py` writes one canonical JSON report and one derived
Markdown report using atomic file replacement. Each report contains:

- run ID, UTC timestamps, status, source files, and engine configuration;
- scenario-set and configuration hashes;
- explicit metric definitions;
- all source context required by the brief;
- expected and actual decision/reason evidence;
- pass state and measured latency;
- audit completeness and chain status; and
- limitations preventing overinterpretation.

Report filenames use the run UUID so separate runs do not silently overwrite one
another. Generated reports are ignored by Git because timings and run IDs are
runtime evidence, not source definitions.

## 6. Measured baseline result

The completed local baseline run is
`8ee9aff5-b9b4-49e2-83c4-19b011c5d891` with:

- scenario-set hash
  `sha256:f3c1fd010768130832643794ffd04543dd55f82e70ba30776939805223801bb0`;
- configuration hash
  `sha256:8262c231b3a78af89f95e67e8cba1823cf51b2570bb320a6ca2cc6784e6805bc`;
- 50/50 scenarios passing;
- 20 legitimate and 30 adversarial observations;
- attack-success and false-negative rates of `0.0`;
- unauthorized-action block rate of `1.0`;
- legitimate completion and approval accuracy of `1.0`;
- false-positive rate of `0.0`;
- mean policy latency of `0.031446 ms` and nearest-rank p95 of `0.050800 ms`;
- mean enforcement latency of `12.924580 ms`; and
- audit completeness and chain-verification rates of `1.0`.

These are measured values from this one deterministic 50-case run. They are not
rounded marketing claims or forecasts for a live deployment. The generated
reports retain every denominator and per-scenario observation.

## 7. Metrics API

`GET /metrics/security` requires the separate administrator token audience. It
returns the run ID, scenario/configuration hashes, timestamps, and aggregate
metrics from the most recent completed persisted run.

It does not expose report filesystem paths, scenario prompt text, credentials, or
partial/running results. With no completed run it returns HTTP 404 and
`NO_EVALUATION_DATA`; it never substitutes hard-coded dashboard values.

## 8. Main implementation files

- `backend/app/services/evaluation.py` owns strict loading, reference execution,
  metric calculation, and report generation.
- `backend/app/db/evaluation.py` persists run state/results and reads the latest
  completed measurement.
- `backend/app/api/metrics.py` provides the admin-only measured aggregate.
- `evaluations/scenarios/*.json` is the versioned 50-case baseline.
- `scripts/run_evaluation.py` runs file-only or persisted evaluations.
- `docs/evaluation-methodology.md` defines formulas and interpretation.
- `backend/tests/test_evaluation_service.py` verifies catalog and metric integrity.

## 9. Verification result

After Phase 7, the complete backend suite passes 209 tests with 85.65% branch-
aware coverage; two checks remain skipped because this host has neither a live
PostgreSQL test database nor a live OPA service. Ruff, strict MyPy, and focused
Phase 7 tests pass. The final Ruff format/lint, strict MyPy, Bandit, `pip check`,
byte-compilation, migration, secret-pattern, and dynamic-execution gates also
pass after the implementation and documentation changes.

## 10. Limitations and Phase 8 handoff (completed)

The deterministic executor duplicates the policy contract for offline evaluation;
policy parity therefore depends on updating Rego tests and evaluation cases
together. Phase 9 should add a separate live-OPA/HTTP engine ID and compare its
decisions against this catalog when Docker is available.

The 50 fixed scenarios are regression evidence, not statistical sampling. They
do not solve provenance omission, unknown attacks, model compromise, or combined
application/key/database/checkpoint compromise.

Phase 8 can now build the administrator dashboard from real agent/task/request,
approval, audit, and `GET /metrics/security` data. It must show run identity and
denominators alongside rates and must not present missing metrics as zero.

That handoff is implemented in [the Phase 8 walkthrough](phase-8-explained.md).
The console uses authenticated administrative collections, presents missing
evaluation data explicitly, and retains the measurement boundary described here.
