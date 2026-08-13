"""Phase 7 scenario catalog, runner, metrics, and report tests."""

import asyncio
import json
from pathlib import Path

import pytest

from app.models.enums import EvaluationRunStatus, EvaluationScenarioKind, PolicyOutcome
from app.services.evaluation import (
    DeterministicScenarioExecutor,
    EvaluationRunner,
    FileOnlyEvaluationRepository,
    calculate_metrics,
    load_scenario_catalog,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCENARIOS = PROJECT_ROOT / "evaluations" / "scenarios"


def test_baseline_catalog_has_strict_unique_expandable_20_30_split() -> None:
    catalog = load_scenario_catalog(SCENARIOS)
    catalog.require_baseline()

    assert len(catalog.scenarios) == 50
    assert len({scenario.scenario_id for scenario in catalog.scenarios}) == 50
    assert (
        sum(scenario.kind is EvaluationScenarioKind.LEGITIMATE for scenario in catalog.scenarios)
        == 20
    )
    assert (
        sum(scenario.kind is EvaluationScenarioKind.ADVERSARIAL for scenario in catalog.scenarios)
        == 30
    )
    assert catalog.scenario_set_hash.startswith("sha256:")
    assert catalog.source_files == ["adversarial.json", "legitimate.json"]
    assert all(scenario.agent_task for scenario in catalog.scenarios)
    assert all(scenario.trusted_instructions for scenario in catalog.scenarios)
    assert all(scenario.requested_tool_action.tool_name for scenario in catalog.scenarios)


@pytest.mark.parametrize(
    "document",
    [
        '{"schema_version":1,"schema_version":1,"scenarios":[]}',
        '{"schema_version":1,"scenarios":[{"scenario_id":NaN}]}',
        '{"schema_version":1,"scenarios":[]}',
    ],
)
def test_catalog_rejects_duplicate_nonfinite_or_empty_documents(
    tmp_path: Path,
    document: str,
) -> None:
    (tmp_path / "invalid.json").write_text(document, encoding="utf-8")

    with pytest.raises(ValueError, match="scenario file is invalid"):
        load_scenario_catalog(tmp_path)


def test_catalog_rejects_duplicate_scenario_ids_across_files(tmp_path: Path) -> None:
    source = json.loads((SCENARIOS / "legitimate.json").read_text(encoding="utf-8"))
    source["scenarios"] = [source["scenarios"][0]]
    (tmp_path / "one.json").write_text(json.dumps(source), encoding="utf-8")
    (tmp_path / "two.json").write_text(json.dumps(source), encoding="utf-8")

    with pytest.raises(ValueError, match="duplicate scenario ID"):
        load_scenario_catalog(tmp_path)


async def test_runner_generates_complete_measured_json_and_markdown_reports(
    tmp_path: Path,
    settings,
) -> None:
    catalog = load_scenario_catalog(SCENARIOS)
    executor = DeterministicScenarioExecutor(
        checkpoint_path=tmp_path / "audit" / "head.json",
        audit_key=settings.audit_hmac_key_bytes,
    )
    reports = tmp_path / "reports"
    outcome = await EvaluationRunner(
        executor=executor,
        repository=FileOnlyEvaluationRepository(),
        reports_dir=reports,
    ).run(catalog)

    assert outcome.run.status is EvaluationRunStatus.COMPLETED
    assert outcome.metrics.total_scenarios == 50
    assert outcome.metrics.passed_scenarios == 50
    assert outcome.metrics.attack_success_rate == 0.0
    assert outcome.metrics.unauthorized_action_block_rate == 1.0
    assert outcome.metrics.legitimate_task_completion_rate == 1.0
    assert outcome.metrics.false_positive_rate == 0.0
    assert outcome.metrics.false_negative_rate == 0.0
    assert outcome.metrics.approval_enforcement_accuracy == 1.0
    assert outcome.metrics.audit_record_completeness == 1.0
    assert outcome.metrics.audit_chain_verification_rate == 1.0
    assert outcome.metrics.mean_policy_latency_ms >= 0
    assert outcome.metrics.p95_policy_latency_ms >= outcome.metrics.mean_policy_latency_ms / 50
    assert outcome.run.json_report_path is not None
    assert outcome.run.markdown_report_path is not None

    json_report = Path(outcome.run.json_report_path)
    markdown_report = Path(outcome.run.markdown_report_path)
    decoded = json.loads(await asyncio.to_thread(json_report.read_text, encoding="utf-8"))
    assert decoded["run"]["scenario_set_hash"] == catalog.scenario_set_hash
    assert decoded["metrics"] == outcome.metrics.model_dump(mode="json")
    assert len(decoded["results"]) == 50
    assert all("actual_decision" in result for result in decoded["results"])
    assert all("enforcement_latency_ms" in result for result in decoded["results"])
    markdown = await asyncio.to_thread(markdown_report.read_text, encoding="utf-8")
    assert "Metric definitions" in markdown


async def test_metrics_recompute_false_positive_and_false_negative_from_evidence(
    tmp_path: Path,
    settings,
) -> None:
    catalog = load_scenario_catalog(SCENARIOS)
    outcome = await EvaluationRunner(
        executor=DeterministicScenarioExecutor(
            checkpoint_path=tmp_path / "head.json",
            audit_key=settings.audit_hmac_key_bytes,
        ),
        repository=FileOnlyEvaluationRepository(),
        reports_dir=tmp_path / "reports",
    ).run(catalog)
    legitimate = next(
        result
        for result in outcome.results
        if result.scenario_kind is EvaluationScenarioKind.LEGITIMATE
    )
    adversarial = next(
        result
        for result in outcome.results
        if result.scenario_kind is EvaluationScenarioKind.ADVERSARIAL
    )
    legitimate.actual_decision = PolicyOutcome.DENY
    legitimate.passed = False
    adversarial.actual_decision = PolicyOutcome.ALLOW
    adversarial.passed = False

    metrics = calculate_metrics(catalog.scenarios, outcome.results)

    assert metrics.false_positive_rate == 0.05
    assert metrics.false_negative_rate == 0.033333
    assert metrics.attack_success_rate == 0.033333
    assert metrics.unauthorized_action_block_rate == 0.966667
    assert metrics.legitimate_task_completion_rate == 0.95
