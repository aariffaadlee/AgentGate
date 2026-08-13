"""Run the deterministic AgentGate security scenario catalog."""

import argparse
import asyncio
import json
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = PROJECT_ROOT / "backend"
sys.path.insert(0, str(BACKEND_ROOT))

from app.config import get_settings  # noqa: E402
from app.db.evaluation import SQLAlchemyEvaluationRepository  # noqa: E402
from app.db.session import Database  # noqa: E402
from app.services.evaluation import (  # noqa: E402
    DeterministicScenarioExecutor,
    EvaluationRunner,
    FileOnlyEvaluationRepository,
    load_scenario_catalog,
)


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--scenarios",
        type=Path,
        default=PROJECT_ROOT / "evaluations" / "scenarios",
        help="Directory containing strict JSON scenario files.",
    )
    parser.add_argument(
        "--reports",
        type=Path,
        default=PROJECT_ROOT / "evaluations" / "reports",
        help="Directory for generated JSON and Markdown reports.",
    )
    parser.add_argument(
        "--persist",
        action="store_true",
        help="Persist the run and results to the configured PostgreSQL database.",
    )
    return parser.parse_args()


async def _run(arguments: argparse.Namespace) -> int:
    settings = get_settings()
    catalog = load_scenario_catalog(arguments.scenarios)
    catalog.require_baseline()
    with tempfile.TemporaryDirectory(prefix="agentgate-evaluation-") as temporary:
        executor = DeterministicScenarioExecutor(
            checkpoint_path=Path(temporary) / "audit-head.json",
            audit_key=settings.audit_hmac_key_bytes,
        )
        if not arguments.persist:
            runner = EvaluationRunner(
                executor=executor,
                repository=FileOnlyEvaluationRepository(),
                reports_dir=arguments.reports,
            )
            outcome = await runner.run(catalog)
        else:
            database = Database(settings)
            try:
                async with database.session_factory() as session:
                    runner = EvaluationRunner(
                        executor=executor,
                        repository=SQLAlchemyEvaluationRepository(session),
                        reports_dir=arguments.reports,
                    )
                    outcome = await runner.run(catalog)
            finally:
                await database.dispose()

    print(
        json.dumps(
            {
                "run_id": str(outcome.run.id),
                "status": outcome.run.status.value,
                "scenario_set_hash": outcome.run.scenario_set_hash,
                "configuration_hash": outcome.run.configuration_hash,
                "json_report_path": outcome.run.json_report_path,
                "markdown_report_path": outcome.run.markdown_report_path,
                "metrics": outcome.metrics.model_dump(mode="json"),
                "persisted": bool(arguments.persist),
            },
            sort_keys=True,
        )
    )
    return 0 if outcome.metrics.passed_scenarios == outcome.metrics.total_scenarios else 1


def main() -> int:
    arguments = _arguments()
    try:
        return asyncio.run(_run(arguments))
    except (OSError, RuntimeError, ValueError):
        print(
            json.dumps(
                {
                    "status": "failed",
                    "reason_code": "EVALUATION_FAILED",
                },
                sort_keys=True,
            )
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
