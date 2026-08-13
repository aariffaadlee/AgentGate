"""Strict scenario loading, deterministic evaluation, metrics, and reports."""

import asyncio
import json
import math
import os
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter_ns
from typing import Literal, Protocol, cast
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from app.auth.crypto import canonical_json, canonical_sha256
from app.db.base import utc_now
from app.models.audit import AuditEvent
from app.models.enums import (
    AuditActorType,
    EvaluationRunStatus,
    EvaluationScenarioKind,
    PolicyOutcome,
    RiskTier,
)
from app.models.evaluation import EvaluationResult, EvaluationRun
from app.services.audit import (
    GENESIS_HASH,
    AuditEventDraft,
    AuditRepository,
    AuditService,
    CheckpointStore,
    build_audit_event,
    create_checkpoint,
    verify_audit_chain,
)
from app.tools.registry import STATIC_TOOL_REGISTRY, StaticToolRegistry

SCENARIO_FORMAT_VERSION = 1
REPORT_FORMAT_VERSION = 1
EVALUATION_ENGINE_ID = "agentgate-deterministic-policy-contract-v1"
MAX_SCENARIO_FILES = 1_000
MAX_SCENARIOS = 10_000
MAX_SCENARIO_FILE_BYTES = 4_194_304
EXPECTED_AUDIT_EVENTS_PER_SCENARIO = 3


class StrictEvaluationModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class RequestedToolAction(StrictEvaluationModel):
    tool_name: str = Field(
        min_length=3,
        max_length=120,
        pattern=r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$",
    )
    arguments: dict[str, object] = Field(max_length=32)


class ScenarioControls(StrictEvaluationModel):
    """Synthetic authoritative facts varied by red-team scenarios."""

    agent_active: bool = True
    token_context_valid: bool = True
    credential_expired: bool = False
    credential_revoked: bool = False
    proof_valid: bool = True
    task_matches: bool = True
    registry_matches: bool = True
    preflight_valid: bool = True
    provenance_valid: bool = True
    untrusted_influence: bool = False
    unknown_provenance: bool = False
    trusted_intent_present: bool = False
    rate_exceeded: bool = False
    request_size_exceeded: bool = False
    response_size_exceeded: bool = False
    approval_status: Literal["none", "pending", "approved", "rejected", "expired", "consumed"] = (
        "none"
    )
    approval_argument_matches: bool = True
    approval_expired: bool = False
    approval_consumed: bool = False
    policy_engine_available: bool = True


class EvaluationScenario(StrictEvaluationModel):
    """Versioned input case; actual observations are added only by the runner."""

    scenario_id: str = Field(
        min_length=3,
        max_length=80,
        pattern=r"^[a-z][a-z0-9_-]+$",
    )
    kind: EvaluationScenarioKind
    category: str = Field(
        min_length=3,
        max_length=80,
        pattern=r"^[a-z][a-z0-9_-]+$",
    )
    agent_task: str = Field(min_length=3, max_length=300)
    trusted_instructions: str = Field(min_length=3, max_length=1_000)
    untrusted_content: str | None = Field(default=None, max_length=2_000)
    requested_tool_action: RequestedToolAction
    capabilities: list[str] = Field(min_length=1, max_length=16)
    controls: ScenarioControls = Field(default_factory=ScenarioControls)
    expected_security_decision: PolicyOutcome
    expected_reason_code: str = Field(
        min_length=3,
        max_length=80,
        pattern=r"^[A-Z][A-Z0-9_]+$",
    )
    approval_relevant: bool = False

    @field_validator("kind", mode="before")
    @classmethod
    def parse_kind(cls, value: object) -> object:
        if isinstance(value, str):
            try:
                return EvaluationScenarioKind(value)
            except ValueError:
                return value
        return value

    @field_validator("expected_security_decision", mode="before")
    @classmethod
    def parse_expected_decision(cls, value: object) -> object:
        if isinstance(value, str):
            try:
                return PolicyOutcome(value)
            except ValueError:
                return value
        return value

    @field_validator("capabilities")
    @classmethod
    def validate_capabilities(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("scenario capabilities must be unique")
        return value


class ScenarioFile(StrictEvaluationModel):
    schema_version: Literal[1]
    scenarios: list[EvaluationScenario] = Field(min_length=1, max_length=MAX_SCENARIOS)


@dataclass(frozen=True)
class ScenarioCatalog:
    scenarios: list[EvaluationScenario]
    scenario_set_hash: str
    source_files: list[str]

    def require_baseline(self, *, legitimate: int = 20, adversarial: int = 30) -> None:
        legitimate_count = sum(
            scenario.kind is EvaluationScenarioKind.LEGITIMATE for scenario in self.scenarios
        )
        adversarial_count = sum(
            scenario.kind is EvaluationScenarioKind.ADVERSARIAL for scenario in self.scenarios
        )
        if legitimate_count < legitimate or adversarial_count < adversarial:
            raise ValueError(
                "scenario baseline requires at least "
                f"{legitimate} legitimate and {adversarial} adversarial cases"
            )


class EvaluationMetrics(StrictEvaluationModel):
    total_scenarios: int
    legitimate_scenarios: int
    adversarial_scenarios: int
    passed_scenarios: int
    attack_success_rate: float
    unauthorized_action_block_rate: float
    legitimate_task_completion_rate: float
    false_positive_rate: float
    false_negative_rate: float
    approval_enforcement_accuracy: float
    mean_policy_latency_ms: float
    p95_policy_latency_ms: float
    mean_enforcement_latency_ms: float
    audit_record_completeness: float
    audit_chain_verification_rate: float


@dataclass(frozen=True)
class ScenarioObservation:
    actual_decision: PolicyOutcome
    reason_code: str
    reason_codes: list[str]
    policy_latency_ms: float
    enforcement_latency_ms: float
    expected_audit_events: int
    observed_audit_events: int
    audit_chain_valid: bool


@dataclass(frozen=True)
class EvaluationOutcome:
    run: EvaluationRun
    results: list[EvaluationResult]
    metrics: EvaluationMetrics


class EvaluationRepository(Protocol):
    async def start(self, run: EvaluationRun) -> None: ...

    async def complete(
        self,
        run: EvaluationRun,
        results: Sequence[EvaluationResult],
    ) -> None: ...

    async def fail(self, run: EvaluationRun) -> None: ...


class ScenarioExecutor(Protocol):
    engine_id: str

    async def execute(self, scenario: EvaluationScenario) -> ScenarioObservation: ...


class FileOnlyEvaluationRepository:
    """Explicit no-database mode for reproducible local report generation."""

    async def start(self, run: EvaluationRun) -> None:
        del run

    async def complete(
        self,
        run: EvaluationRun,
        results: Sequence[EvaluationResult],
    ) -> None:
        del run, results

    async def fail(self, run: EvaluationRun) -> None:
        del run


class DeterministicScenarioExecutor:
    """Evaluation-only reference executor mirroring the versioned Rego contract."""

    engine_id = EVALUATION_ENGINE_ID

    def __init__(
        self,
        *,
        checkpoint_path: Path,
        audit_key: bytes,
        registry: StaticToolRegistry = STATIC_TOOL_REGISTRY,
    ) -> None:
        self._registry = registry
        self._audit_repository = _MemoryAuditRepository()
        self._audit = AuditService(
            self._audit_repository,
            key=audit_key,
            checkpoint_path=checkpoint_path,
        )

    async def execute(self, scenario: EvaluationScenario) -> ScenarioObservation:
        enforcement_started = perf_counter_ns()
        policy_started = perf_counter_ns()
        decision, reason_codes = _evaluate_scenario(scenario, self._registry)
        policy_latency_ms = _elapsed_ms(policy_started)
        correlation_id = uuid5(NAMESPACE_URL, f"agentgate:evaluation:{scenario.scenario_id}")
        actor_id = uuid5(NAMESPACE_URL, f"agentgate:evaluation:agent:{scenario.scenario_id}")
        task_id = uuid5(NAMESPACE_URL, f"agentgate:evaluation:task:{scenario.scenario_id}")
        await self._audit.append(
            AuditEventDraft(
                event_type="evaluation.requested",
                correlation_id=correlation_id,
                actor_type=AuditActorType.AGENT,
                actor_id=actor_id,
                task_id=task_id,
                payload={
                    "scenario_id": scenario.scenario_id,
                    "category": scenario.category,
                    "tool_name": scenario.requested_tool_action.tool_name,
                    "arguments_hash": canonical_sha256(scenario.requested_tool_action.arguments),
                },
            ),
            AuditEventDraft(
                event_type="evaluation.policy_decided",
                correlation_id=correlation_id,
                actor_type=AuditActorType.SYSTEM,
                actor_id=None,
                task_id=task_id,
                payload={
                    "scenario_id": scenario.scenario_id,
                    "decision": decision.value,
                    "reason_codes": reason_codes,
                    "policy_latency_ms": policy_latency_ms,
                    "engine_id": self.engine_id,
                },
            ),
            AuditEventDraft(
                event_type="evaluation.completed",
                correlation_id=correlation_id,
                actor_type=AuditActorType.SYSTEM,
                actor_id=None,
                task_id=task_id,
                payload={
                    "scenario_id": scenario.scenario_id,
                    "decision": decision.value,
                    "executed": decision is PolicyOutcome.ALLOW,
                },
            ),
        )
        observed = await self._audit.timeline(
            after_sequence=0,
            limit=10,
            correlation_id=correlation_id,
        )
        verification = await self._audit.verify()
        return ScenarioObservation(
            actual_decision=decision,
            reason_code=reason_codes[0],
            reason_codes=reason_codes,
            policy_latency_ms=policy_latency_ms,
            enforcement_latency_ms=_elapsed_ms(enforcement_started),
            expected_audit_events=EXPECTED_AUDIT_EVENTS_PER_SCENARIO,
            observed_audit_events=len(observed),
            audit_chain_valid=verification.valid,
        )


class EvaluationRunner:
    """Execute a catalog, persist evidence, and atomically generate both reports."""

    def __init__(
        self,
        *,
        executor: ScenarioExecutor,
        repository: EvaluationRepository,
        reports_dir: Path,
    ) -> None:
        self._executor = executor
        self._repository = repository
        self._reports_dir = reports_dir.resolve(strict=False)

    async def run(self, catalog: ScenarioCatalog) -> EvaluationOutcome:
        configuration = {
            "engine_id": self._executor.engine_id,
            "scenario_format_version": SCENARIO_FORMAT_VERSION,
            "report_format_version": REPORT_FORMAT_VERSION,
            "expected_audit_events_per_scenario": EXPECTED_AUDIT_EVENTS_PER_SCENARIO,
        }
        started_at = utc_now()
        run = EvaluationRun(
            id=uuid4(),
            scenario_set_hash=catalog.scenario_set_hash,
            configuration_hash=canonical_sha256(configuration),
            status=EvaluationRunStatus.RUNNING,
            started_at=started_at,
            completed_at=None,
            metrics=None,
            json_report_path=None,
            markdown_report_path=None,
        )
        await self._repository.start(run)
        try:
            evidence: list[tuple[EvaluationScenario, ScenarioObservation]] = []
            results: list[EvaluationResult] = []
            for scenario in catalog.scenarios:
                observation = await self._executor.execute(scenario)
                audit_completeness = min(
                    observation.observed_audit_events / observation.expected_audit_events,
                    1.0,
                )
                passed = bool(
                    observation.actual_decision is scenario.expected_security_decision
                    and observation.reason_code == scenario.expected_reason_code
                    and audit_completeness == 1.0
                    and observation.audit_chain_valid
                )
                evidence.append((scenario, observation))
                results.append(
                    EvaluationResult(
                        id=uuid4(),
                        evaluation_run_id=run.id,
                        scenario_id=scenario.scenario_id,
                        category=scenario.category,
                        scenario_kind=scenario.kind,
                        expected_decision=scenario.expected_security_decision,
                        actual_decision=observation.actual_decision,
                        expected_reason_code=scenario.expected_reason_code,
                        reason_code=observation.reason_code,
                        passed=passed,
                        policy_latency_ms=observation.policy_latency_ms,
                        enforcement_latency_ms=observation.enforcement_latency_ms,
                        audit_completeness=audit_completeness,
                        audit_chain_valid=observation.audit_chain_valid,
                        created_at=utc_now(),
                    )
                )

            metrics = calculate_metrics(catalog.scenarios, results)
            completed_at = utc_now()
            report_stem = f"evaluation-{run.id}"
            json_path = self._reports_dir / f"{report_stem}.json"
            markdown_path = self._reports_dir / f"{report_stem}.md"
            report = _report_document(
                run=run,
                completed_at=completed_at,
                catalog=catalog,
                configuration=configuration,
                metrics=metrics,
                evidence=evidence,
                results=results,
            )
            _atomic_write(json_path, canonical_json(report))
            _atomic_write(markdown_path, _markdown_report(report).encode("utf-8"))

            run.status = EvaluationRunStatus.COMPLETED
            run.completed_at = completed_at
            run.metrics = cast(dict[str, object], metrics.model_dump(mode="json"))
            run.json_report_path = str(json_path)
            run.markdown_report_path = str(markdown_path)
            await self._repository.complete(run, results)
            return EvaluationOutcome(run, results, metrics)
        except Exception:
            run.status = EvaluationRunStatus.FAILED
            run.completed_at = utc_now()
            await self._repository.fail(run)
            raise


def load_scenario_catalog(directory: Path) -> ScenarioCatalog:
    """Load strict duplicate-free JSON files in a stable order without code execution."""

    root = directory.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("scenario path must be a directory")
    files = sorted(path for path in root.glob("*.json") if path.is_file())
    if not files or len(files) > MAX_SCENARIO_FILES:
        raise ValueError("scenario file count is outside the supported range")

    scenarios: list[EvaluationScenario] = []
    seen: set[str] = set()
    for path in files:
        if path.is_symlink() or path.stat().st_size > MAX_SCENARIO_FILE_BYTES:
            raise ValueError("scenario files must be regular bounded files")
        try:
            decoded = json.loads(
                path.read_text(encoding="utf-8"),
                object_pairs_hook=_unique_object,
                parse_constant=_reject_json_constant,
            )
            scenario_file = ScenarioFile.model_validate(decoded)
        except (OSError, UnicodeError, ValueError, ValidationError) as exc:
            raise ValueError(f"scenario file is invalid: {path.name}") from exc
        for scenario in scenario_file.scenarios:
            if scenario.scenario_id in seen:
                raise ValueError(f"duplicate scenario ID: {scenario.scenario_id}")
            seen.add(scenario.scenario_id)
            scenarios.append(scenario)
            if len(scenarios) > MAX_SCENARIOS:
                raise ValueError("scenario catalog exceeds the supported size")

    scenarios.sort(key=lambda item: item.scenario_id)
    material = [scenario.model_dump(mode="json") for scenario in scenarios]
    return ScenarioCatalog(
        scenarios=scenarios,
        scenario_set_hash=canonical_sha256(material),
        source_files=[path.name for path in files],
    )


def calculate_metrics(
    scenarios: Sequence[EvaluationScenario],
    results: Sequence[EvaluationResult],
) -> EvaluationMetrics:
    """Calculate only metrics backed by individual observations."""

    if not scenarios or len(scenarios) != len(results):
        raise ValueError("metrics require one result per scenario")
    scenario_by_id = {scenario.scenario_id: scenario for scenario in scenarios}
    if len(scenario_by_id) != len(scenarios) or {result.scenario_id for result in results} != set(
        scenario_by_id
    ):
        raise ValueError("metric evidence does not match the scenario catalog")

    legitimate = [
        result for result in results if result.scenario_kind is EvaluationScenarioKind.LEGITIMATE
    ]
    adversarial = [
        result for result in results if result.scenario_kind is EvaluationScenarioKind.ADVERSARIAL
    ]
    approval_cases = [
        result for result in results if scenario_by_id[result.scenario_id].approval_relevant
    ]
    policy_latencies = [result.policy_latency_ms for result in results]
    return EvaluationMetrics(
        total_scenarios=len(results),
        legitimate_scenarios=len(legitimate),
        adversarial_scenarios=len(adversarial),
        passed_scenarios=sum(result.passed for result in results),
        attack_success_rate=_rate(
            sum(result.actual_decision is PolicyOutcome.ALLOW for result in adversarial),
            len(adversarial),
        ),
        unauthorized_action_block_rate=_rate(
            sum(result.actual_decision is not PolicyOutcome.ALLOW for result in adversarial),
            len(adversarial),
        ),
        legitimate_task_completion_rate=_rate(
            sum(
                result.passed and result.actual_decision is not PolicyOutcome.DENY
                for result in legitimate
            ),
            len(legitimate),
        ),
        false_positive_rate=_rate(
            sum(result.actual_decision is PolicyOutcome.DENY for result in legitimate),
            len(legitimate),
        ),
        false_negative_rate=_rate(
            sum(result.actual_decision is PolicyOutcome.ALLOW for result in adversarial),
            len(adversarial),
        ),
        approval_enforcement_accuracy=_rate(
            sum(result.passed for result in approval_cases),
            len(approval_cases),
        ),
        mean_policy_latency_ms=_mean(policy_latencies),
        p95_policy_latency_ms=_percentile_95(policy_latencies),
        mean_enforcement_latency_ms=_mean([result.enforcement_latency_ms for result in results]),
        audit_record_completeness=round(
            sum(result.audit_completeness for result in results) / len(results),
            6,
        ),
        audit_chain_verification_rate=_rate(
            sum(result.audit_chain_valid for result in results),
            len(results),
        ),
    )


def _evaluate_scenario(
    scenario: EvaluationScenario,
    registry: StaticToolRegistry,
) -> tuple[PolicyOutcome, list[str]]:
    controls = scenario.controls
    definition = registry.get(scenario.requested_tool_action.tool_name)
    known = definition is not None and controls.registry_matches
    arguments_valid = False
    if definition is not None and controls.preflight_valid:
        try:
            definition.argument_model.model_validate(scenario.requested_tool_action.arguments)
            arguments_valid = True
        except ValidationError:
            arguments_valid = False

    deny: set[str] = set()
    if not controls.policy_engine_available:
        deny.add("POLICY_ENGINE_ERROR")
    if not controls.agent_active:
        deny.add("AGENT_INACTIVE")
    if not controls.token_context_valid:
        deny.add("TOKEN_CONTEXT_INVALID")
    if controls.credential_expired:
        deny.add("CREDENTIAL_EXPIRED")
    if controls.credential_revoked:
        deny.add("CREDENTIAL_REVOKED")
    if not controls.proof_valid:
        deny.add("PROOF_INVALID")
    if not controls.task_matches:
        deny.add("CROSS_TASK_CREDENTIAL")
    if scenario.requested_tool_action.tool_name not in scenario.capabilities:
        deny.add("CAPABILITY_MISSING")
    if not known:
        deny.add("UNKNOWN_TOOL")
    if not arguments_valid:
        deny.add("ARGUMENTS_INVALID")
    if not controls.provenance_valid:
        deny.add("PROVENANCE_INVALID")
    risk = definition.risk_tier if definition is not None else None
    if (
        risk is RiskTier.HIGH
        and controls.untrusted_influence
        and not controls.trusted_intent_present
    ):
        deny.add("UNTRUSTED_ONLY_SENSITIVE_INTENT")
    if (
        risk is RiskTier.HIGH
        and controls.unknown_provenance
        and not controls.trusted_intent_present
    ):
        deny.add("UNKNOWN_PROVENANCE_SENSITIVE_INTENT")
    if controls.approval_status == "approved" and not controls.approval_argument_matches:
        deny.add("APPROVAL_ARGUMENT_MISMATCH")
    if controls.approval_status == "approved" and controls.approval_expired:
        deny.add("APPROVAL_EXPIRED")
    if controls.approval_consumed or controls.approval_status == "consumed":
        deny.add("APPROVAL_REPLAYED")
    if controls.rate_exceeded:
        deny.add("RATE_LIMIT_EXCEEDED")
    if controls.request_size_exceeded or controls.response_size_exceeded:
        deny.add("RESOURCE_LIMIT_EXCEEDED")
    if deny:
        return PolicyOutcome.DENY, sorted(deny)

    approval_valid = bool(
        controls.approval_status == "approved"
        and controls.approval_argument_matches
        and not controls.approval_expired
        and not controls.approval_consumed
    )
    overwrite = bool(
        scenario.requested_tool_action.tool_name == "files.write"
        and scenario.requested_tool_action.arguments.get("overwrite") is True
    )
    approval_reasons: set[str] = set()
    if risk is RiskTier.HIGH and not approval_valid:
        approval_reasons.add("HIGH_RISK_APPROVAL_REQUIRED")
    if overwrite and not approval_valid:
        approval_reasons.add("FILE_OVERWRITE_APPROVAL_REQUIRED")
    if approval_reasons:
        return PolicyOutcome.REQUIRE_APPROVAL, sorted(approval_reasons)
    if risk is RiskTier.LOW:
        return PolicyOutcome.ALLOW, ["LOW_RISK_CAPABILITY_ALLOWED"]
    if risk is RiskTier.MEDIUM and not overwrite:
        return PolicyOutcome.ALLOW, ["MEDIUM_RISK_CAPABILITY_ALLOWED"]
    if risk is RiskTier.HIGH and approval_valid:
        return PolicyOutcome.ALLOW, ["APPROVAL_VALID"]
    return PolicyOutcome.DENY, ["DEFAULT_DENY"]


class _MemoryAuditRepository(AuditRepository):
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []
        self._lock = asyncio.Lock()

    async def append_batch(
        self,
        drafts: Sequence[AuditEventDraft],
        *,
        key: bytes,
        checkpoint_store: CheckpointStore,
    ) -> list[AuditEvent]:
        async with self._lock:
            checkpoint = checkpoint_store.read()
            verification = verify_audit_chain(self.events, checkpoint, key)
            if not verification.valid:
                raise RuntimeError(f"evaluation audit chain invalid: {verification.reason_code}")
            chain_id = self.events[0].chain_id if self.events else uuid4()
            sequence = self.events[-1].sequence if self.events else 0
            previous_hash = self.events[-1].event_hash if self.events else GENESIS_HASH
            appended = []
            for draft in drafts:
                sequence += 1
                event = build_audit_event(
                    draft,
                    sequence=sequence,
                    chain_id=chain_id,
                    previous_hash=previous_hash,
                    key=key,
                )
                appended.append(event)
                previous_hash = event.event_hash
            self.events.extend(appended)
            checkpoint_store.write(create_checkpoint(appended[-1], key))
            return appended

    async def list_events(
        self,
        *,
        after_sequence: int,
        limit: int,
        correlation_id: UUID | None,
        task_id: UUID | None,
        tool_request_id: UUID | None,
        event_type: str | None,
    ) -> Sequence[AuditEvent]:
        selected = [event for event in self.events if event.sequence > after_sequence]
        if correlation_id is not None:
            selected = [event for event in selected if event.correlation_id == correlation_id]
        if task_id is not None:
            selected = [event for event in selected if event.task_id == task_id]
        if tool_request_id is not None:
            selected = [event for event in selected if event.tool_request_id == tool_request_id]
        if event_type is not None:
            selected = [event for event in selected if event.event_type == event_type]
        return selected[:limit]

    async def list_all_events(self) -> Sequence[AuditEvent]:
        return self.events


def _report_document(
    *,
    run: EvaluationRun,
    completed_at: datetime,
    catalog: ScenarioCatalog,
    configuration: Mapping[str, object],
    metrics: EvaluationMetrics,
    evidence: Sequence[tuple[EvaluationScenario, ScenarioObservation]],
    results: Sequence[EvaluationResult],
) -> dict[str, object]:
    result_by_id = {result.scenario_id: result for result in results}
    entries: list[dict[str, object]] = []
    for scenario, observation in evidence:
        result = result_by_id[scenario.scenario_id]
        entries.append(
            {
                "scenario_id": scenario.scenario_id,
                "kind": scenario.kind.value,
                "category": scenario.category,
                "agent_task": scenario.agent_task,
                "trusted_instructions": scenario.trusted_instructions,
                "untrusted_content": scenario.untrusted_content,
                "requested_tool_action": scenario.requested_tool_action.model_dump(mode="json"),
                "expected_security_decision": scenario.expected_security_decision.value,
                "actual_decision": observation.actual_decision.value,
                "expected_reason_code": scenario.expected_reason_code,
                "reason_code": observation.reason_code,
                "reason_codes": observation.reason_codes,
                "passed": result.passed,
                "policy_latency_ms": result.policy_latency_ms,
                "enforcement_latency_ms": result.enforcement_latency_ms,
                "audit_completeness": result.audit_completeness,
                "audit_chain_valid": result.audit_chain_valid,
            }
        )
    return {
        "report_format_version": REPORT_FORMAT_VERSION,
        "run": {
            "id": str(run.id),
            "status": EvaluationRunStatus.COMPLETED.value,
            "started_at": _timestamp(run.started_at),
            "completed_at": _timestamp(completed_at),
            "scenario_set_hash": run.scenario_set_hash,
            "configuration_hash": run.configuration_hash,
            "scenario_source_files": catalog.source_files,
            "configuration": dict(configuration),
        },
        "metric_definitions": _metric_definitions(),
        "metrics": metrics.model_dump(mode="json"),
        "results": entries,
        "limitations": [
            "This run measures the deterministic policy-contract executor, not a live OPA service.",
            "Scenario fixtures are synthetic and do not establish production effectiveness.",
            "Attack success means an adversarial request received allow; "
            "require_approval is blocked.",
        ],
    }


def _markdown_report(report: Mapping[str, object]) -> str:
    run = cast(Mapping[str, object], report["run"])
    metrics = cast(Mapping[str, object], report["metrics"])
    results = cast(Sequence[Mapping[str, object]], report["results"])
    definitions = cast(Mapping[str, object], report["metric_definitions"])
    lines = [
        "# AgentGate security evaluation report",
        "",
        f"- Run ID: `{run['id']}`",
        f"- Scenario-set hash: `{run['scenario_set_hash']}`",
        f"- Configuration hash: `{run['configuration_hash']}`",
        f"- Started: `{run['started_at']}`",
        f"- Completed: `{run['completed_at']}`",
        "",
        "## Measured metrics",
        "",
        "| Metric | Value |",
        "| --- | ---: |",
    ]
    for name, value in metrics.items():
        lines.append(f"| `{name}` | {_markdown_value(value)} |")
    lines.extend(["", "## Metric definitions", ""])
    for name, definition in definitions.items():
        lines.append(f"- `{name}` — {definition}")
    lines.extend(
        [
            "",
            "## Scenario results",
            "",
            "| Scenario | Kind | Category | Expected | Actual | Reason | Pass | "
            "Policy ms | Audit |",
            "| --- | --- | --- | --- | --- | --- | ---: | ---: | ---: |",
        ]
    )
    for result in results:
        lines.append(
            "| "
            + " | ".join(
                [
                    f"`{result['scenario_id']}`",
                    str(result["kind"]),
                    str(result["category"]),
                    str(result["expected_security_decision"]),
                    str(result["actual_decision"]),
                    f"`{result['reason_code']}`",
                    "yes" if result["passed"] else "no",
                    f"{float(cast(float, result['policy_latency_ms'])):.6f}",
                    f"{float(cast(float, result['audit_completeness'])):.2%}",
                ]
            )
            + " |"
        )
    lines.extend(["", "## Limitations", ""])
    lines.extend(f"- {item}" for item in cast(Sequence[str], report["limitations"]))
    return "\n".join(lines) + "\n"


def _metric_definitions() -> dict[str, str]:
    return {
        "attack_success_rate": "Adversarial scenarios receiving allow / adversarial scenarios.",
        "unauthorized_action_block_rate": (
            "Adversarial scenarios denied or held for approval / adversarial scenarios."
        ),
        "legitimate_task_completion_rate": (
            "Legitimate scenarios matching the expected non-deny path / legitimate scenarios."
        ),
        "false_positive_rate": "Legitimate scenarios denied / legitimate scenarios.",
        "false_negative_rate": "Adversarial scenarios allowed / adversarial scenarios.",
        "approval_enforcement_accuracy": (
            "Approval-relevant scenarios matching decision, reason, and audit expectations / "
            "approval-relevant scenarios."
        ),
        "mean_policy_latency_ms": "Arithmetic mean of measured decision-engine latency.",
        "p95_policy_latency_ms": "Nearest-rank 95th percentile decision-engine latency.",
        "mean_enforcement_latency_ms": (
            "Arithmetic mean from scenario enforcement start through audit verification."
        ),
        "audit_record_completeness": (
            "Observed required audit records / expected required audit records."
        ),
        "audit_chain_verification_rate": (
            "Scenario checkpoints at which the complete audit chain verified / total scenarios."
        ),
    }


def _atomic_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            prefix=f".{path.name}.",
            suffix=".tmp",
            dir=path.parent,
            delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
            temporary.write(content)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_path, path)
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink(missing_ok=True)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON property")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON value is forbidden: {value}")


def _rate(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 6) if denominator else 0.0


def _mean(values: Sequence[float]) -> float:
    return round(sum(values) / len(values), 6) if values else 0.0


def _percentile_95(values: Sequence[float]) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return round(ordered[max(math.ceil(0.95 * len(ordered)) - 1, 0)], 6)


def _elapsed_ms(started_ns: int) -> float:
    return round(max(perf_counter_ns() - started_ns, 0) / 1_000_000, 6)


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _markdown_value(value: object) -> str:
    if isinstance(value, float):
        return f"{value:.6f}"
    return str(value)
