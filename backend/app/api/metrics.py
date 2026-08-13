"""Administrator-only measured security metrics endpoint."""

from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Request, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.errors import AgentGateError
from app.api.identity import require_admin
from app.db.evaluation import SecurityMetricsService, SQLAlchemyEvaluationRepository
from app.db.session import get_session
from app.services.identity import AdminPrincipal

router = APIRouter(prefix="/metrics", tags=["metrics"])


class SecurityMetricsResponse(BaseModel):
    """Latest persisted measurement; absent data is never replaced by invented values."""

    model_config = ConfigDict(extra="forbid")

    evaluation_run_id: UUID
    scenario_set_hash: str
    configuration_hash: str
    started_at: datetime
    completed_at: datetime
    metrics: dict[str, object]


async def get_security_metrics_service(
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> SecurityMetricsService:
    del request
    return SecurityMetricsService(SQLAlchemyEvaluationRepository(session))


@router.get("/security", response_model=SecurityMetricsResponse)
async def get_security_metrics(
    administrator: Annotated[AdminPrincipal, Depends(require_admin)],
    service: Annotated[SecurityMetricsService, Depends(get_security_metrics_service)],
) -> SecurityMetricsResponse:
    """Return the most recent complete evaluation's measured aggregates."""

    del administrator
    run = await service.latest()
    if run is None or run.completed_at is None or run.metrics is None:
        raise AgentGateError(
            status.HTTP_404_NOT_FOUND,
            "NO_EVALUATION_DATA",
            "No completed security evaluation is available.",
        )
    return SecurityMetricsResponse(
        evaluation_run_id=run.id,
        scenario_set_hash=run.scenario_set_hash,
        configuration_hash=run.configuration_hash,
        started_at=run.started_at,
        completed_at=run.completed_at,
        metrics=run.metrics,
    )
