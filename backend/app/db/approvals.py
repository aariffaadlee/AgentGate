"""Transactional PostgreSQL persistence for exact-bound approvals."""

from datetime import UTC, datetime
from types import TracebackType
from uuid import UUID

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession, AsyncSessionTransaction

from app.models.approval import ApprovalAction, ApprovalRequest
from app.models.enums import ApprovalStatus, ToolRequestStatus
from app.models.identity import Agent, AgentCredential, Revocation
from app.models.policy import PolicyDecision
from app.models.provenance import ProvenanceRecord, ToolRequestInfluence
from app.models.task import Task, TaskCapability
from app.models.tool import ToolRegistry, ToolRequest
from app.services.approvals import (
    ApprovalBundle,
    ApprovalNotFoundError,
    ApprovalRecord,
    LockedApproval,
)


class SQLAlchemyLockedApproval:
    """Hold the approval and request row locks through policy re-evaluation."""

    def __init__(self, session: AsyncSession, approval_id: UUID) -> None:
        self._session = session
        self._approval_id = approval_id
        self._transaction: AsyncSessionTransaction | None = None
        self._bundle: ApprovalBundle | None = None

    @property
    def bundle(self) -> ApprovalBundle:
        if self._bundle is None:
            raise RuntimeError("approval lock has not been entered")
        return self._bundle

    async def __aenter__(self) -> LockedApproval:
        # Administrator authentication performs a read on the same request-scoped
        # session. End that read transaction before opening the security transaction.
        if self._session.in_transaction():
            await self._session.rollback()
        self._transaction = self._session.begin()
        await self._transaction.__aenter__()
        try:
            self._bundle = await self._load_bundle()
        except Exception as exc:
            await self._transaction.__aexit__(type(exc), exc, exc.__traceback__)
            self._transaction = None
            raise
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None:
        if self._transaction is None:
            return None
        await self._transaction.__aexit__(exc_type, exc_value, traceback)
        return None

    def add_action(self, action: ApprovalAction) -> None:
        self._session.add(action)

    def add_policy_decision(self, decision: PolicyDecision) -> None:
        self._session.add(decision)

    async def _load_bundle(self) -> ApprovalBundle:
        approval_result = await self._session.execute(
            select(ApprovalRequest).where(ApprovalRequest.id == self._approval_id).with_for_update()
        )
        approval = approval_result.scalar_one_or_none()
        if approval is None:
            raise ApprovalNotFoundError

        request_result = await self._session.execute(
            select(ToolRequest).where(ToolRequest.id == approval.tool_request_id).with_for_update()
        )
        request = request_result.scalar_one_or_none()
        if request is None:
            raise ApprovalNotFoundError
        credential = await self._session.get(AgentCredential, request.credential_id)
        agent = await self._session.get(Agent, request.agent_id)
        task = await self._session.get(Task, request.task_id)
        if credential is None or agent is None or task is None:
            raise ApprovalNotFoundError

        registry_tool = (
            await self._session.get(ToolRegistry, request.tool_registry_id)
            if request.tool_registry_id is not None
            else None
        )
        capability_result = await self._session.execute(
            select(TaskCapability.capability)
            .where(TaskCapability.task_id == task.id)
            .order_by(TaskCapability.capability)
        )
        revocation_result = await self._session.execute(
            select(Revocation.id)
            .where(
                Revocation.effective_at <= datetime.now(UTC),
                or_(
                    Revocation.agent_id == agent.id,
                    Revocation.credential_id == credential.id,
                ),
            )
            .limit(1)
        )
        decision_result = await self._session.execute(
            select(PolicyDecision)
            .where(PolicyDecision.tool_request_id == request.id)
            .order_by(PolicyDecision.created_at.desc(), PolicyDecision.id.desc())
            .limit(1)
        )
        influence_result = await self._session.execute(
            select(ProvenanceRecord)
            .join(
                ToolRequestInfluence,
                ToolRequestInfluence.provenance_record_id == ProvenanceRecord.id,
            )
            .where(ToolRequestInfluence.tool_request_id == request.id)
            .order_by(ProvenanceRecord.created_at, ProvenanceRecord.id)
        )
        return ApprovalBundle(
            approval=approval,
            request=request,
            decision=decision_result.scalar_one_or_none(),
            registry_tool=registry_tool,
            credential=credential,
            agent=agent,
            task=task,
            capabilities=list(capability_result.scalars().all()),
            revoked=revocation_result.scalar_one_or_none() is not None,
            influences=list(influence_result.scalars().all()),
        )


class SQLAlchemyApprovalRepository:
    """Expire, lock, consume, and finalize approval-backed tool requests."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    def lock(self, approval_id: UUID) -> SQLAlchemyLockedApproval:
        return SQLAlchemyLockedApproval(self._session, approval_id)

    async def list_approvals(self, now: datetime) -> list[ApprovalRecord]:
        if self._session.in_transaction():
            await self._session.rollback()
        async with self._session.begin():
            expired_result = await self._session.execute(
                select(ApprovalRequest)
                .where(
                    ApprovalRequest.status == ApprovalStatus.PENDING,
                    ApprovalRequest.expires_at <= now,
                )
                .with_for_update(skip_locked=True)
            )
            for approval in expired_result.scalars().all():
                approval.status = ApprovalStatus.EXPIRED
                approval.row_version += 1
                request_result = await self._session.execute(
                    select(ToolRequest)
                    .where(ToolRequest.id == approval.tool_request_id)
                    .with_for_update()
                )
                request = request_result.scalar_one_or_none()
                if request is not None and request.status is ToolRequestStatus.PENDING_APPROVAL:
                    request.status = ToolRequestStatus.DENIED
                    request.error_code = "APPROVAL_EXPIRED"
                    request.completed_at = now

        result = await self._session.execute(
            select(ApprovalRequest)
            .order_by(
                ApprovalRequest.created_at.desc(),
                ApprovalRequest.id.desc(),
            )
            .limit(100)
        )
        records: list[ApprovalRecord] = []
        for approval in result.scalars().all():
            request = await self._session.get(ToolRequest, approval.tool_request_id)
            if request is None:
                continue
            decision_result = await self._session.execute(
                select(PolicyDecision)
                .where(PolicyDecision.tool_request_id == request.id)
                .order_by(PolicyDecision.created_at.desc(), PolicyDecision.id.desc())
                .limit(1)
            )
            records.append(ApprovalRecord(approval, request, decision_result.scalar_one_or_none()))
        return records

    async def finish_tool_request(
        self,
        request: ToolRequest,
        *,
        status: ToolRequestStatus,
        error_code: str | None,
        response_size_bytes: int | None,
        result_summary: dict[str, object] | None,
        execution_latency_ms: int | None,
        completed_at: datetime,
        produced_provenance: list[ProvenanceRecord],
    ) -> ToolRequest:
        request.status = status
        request.error_code = error_code
        request.response_size_bytes = response_size_bytes
        request.result_summary = result_summary
        request.execution_latency_ms = execution_latency_ms
        request.completed_at = completed_at
        self._session.add_all(produced_provenance)
        await self._session.commit()
        await self._session.refresh(request)
        return request
