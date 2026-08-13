"""Transactional persistence and measured-metrics reads for evaluation runs."""

from collections.abc import Sequence

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.enums import EvaluationRunStatus
from app.models.evaluation import EvaluationResult, EvaluationRun


class SQLAlchemyEvaluationRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def start(self, run: EvaluationRun) -> None:
        self._session.add(run)
        await self._session.commit()

    async def complete(
        self,
        run: EvaluationRun,
        results: Sequence[EvaluationResult],
    ) -> None:
        self._session.add_all(results)
        await self._session.commit()

    async def fail(self, run: EvaluationRun) -> None:
        await self._session.rollback()
        self._session.add(run)
        await self._session.commit()

    async def latest_completed(self) -> EvaluationRun | None:
        result = await self._session.execute(
            select(EvaluationRun)
            .where(EvaluationRun.status == EvaluationRunStatus.COMPLETED)
            .order_by(EvaluationRun.completed_at.desc(), EvaluationRun.id.desc())
            .limit(1)
        )
        return result.scalar_one_or_none()


class SecurityMetricsService:
    """Expose only aggregate metrics from an actually completed persisted run."""

    def __init__(self, repository: SQLAlchemyEvaluationRepository) -> None:
        self._repository = repository

    async def latest(self) -> EvaluationRun | None:
        return await self._repository.latest_completed()
