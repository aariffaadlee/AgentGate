"""Measured-only security metrics endpoint tests."""

from datetime import UTC, datetime
from uuid import uuid4

from app.api.identity import get_identity_service
from app.api.metrics import get_security_metrics_service
from app.config import Settings
from app.main import create_app
from app.models.enums import EvaluationRunStatus
from app.models.evaluation import EvaluationRun
from app.services.identity import IdentityService
from tests.support import app_client
from tests.test_identity_service import FakeIdentityRepository


class FakeMetricsService:
    def __init__(self, run: EvaluationRun | None) -> None:
        self.run = run

    async def latest(self) -> EvaluationRun | None:
        return self.run


async def test_metrics_endpoint_returns_only_latest_measured_run(settings: Settings) -> None:
    application = create_app(settings)
    identity = IdentityService(FakeIdentityRepository(), settings)
    token = await identity.create_admin_session(settings.admin_bootstrap_secret.get_secret_value())
    now = datetime.now(UTC)
    run = EvaluationRun(
        id=uuid4(),
        scenario_set_hash="sha256:" + ("a" * 64),
        configuration_hash="sha256:" + ("b" * 64),
        status=EvaluationRunStatus.COMPLETED,
        started_at=now,
        completed_at=now,
        metrics={"total_scenarios": 50, "attack_success_rate": 0.0},
        json_report_path="evaluations/reports/measured.json",
        markdown_report_path="evaluations/reports/measured.md",
    )
    application.dependency_overrides[get_identity_service] = lambda: identity
    application.dependency_overrides[get_security_metrics_service] = lambda: FakeMetricsService(run)

    async with app_client(application) as client:
        unauthenticated = await client.get("/metrics/security")
        response = await client.get(
            "/metrics/security",
            headers={"Authorization": f"Bearer {token.encoded}"},
        )

    assert unauthenticated.status_code == 401
    assert response.status_code == 200
    assert response.json()["evaluation_run_id"] == str(run.id)
    assert response.json()["metrics"] == run.metrics
    assert "report_path" not in response.text


async def test_metrics_endpoint_does_not_invent_missing_measurements(settings: Settings) -> None:
    application = create_app(settings)
    identity = IdentityService(FakeIdentityRepository(), settings)
    token = await identity.create_admin_session(settings.admin_bootstrap_secret.get_secret_value())
    application.dependency_overrides[get_identity_service] = lambda: identity
    application.dependency_overrides[get_security_metrics_service] = lambda: FakeMetricsService(
        None
    )

    async with app_client(application) as client:
        response = await client.get(
            "/metrics/security",
            headers={"Authorization": f"Bearer {token.encoded}"},
        )

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "NO_EVALUATION_DATA"
