"""PostgreSQL persistence for the static tool mirror, rate limits, and requests."""

from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.models.approval import ApprovalRequest
from app.models.enums import ToolRequestStatus
from app.models.policy import PolicyDecision
from app.models.provenance import ProvenanceRecord, ToolRequestInfluence
from app.models.tool import ToolRateLimitWindow, ToolRegistry, ToolRequest
from app.services.tools import RateLimitResult, ToolRequestBundle
from app.tools.registry import StaticToolRegistry, ToolDefinition


class ToolManifestMismatchError(RuntimeError):
    """The queryable database mirror differs from executable trusted code."""


async def verify_or_install_tool_manifest(
    session_factory: async_sessionmaker[AsyncSession],
    registry: StaticToolRegistry,
) -> None:
    """Install an empty mirror once, then fail startup on every divergence."""

    async with session_factory() as session:
        result = await session.execute(select(ToolRegistry).order_by(ToolRegistry.name))
        rows = list(result.scalars().all())
        if not rows:
            session.add_all(_registry_row(definition, registry) for definition in registry)
            await session.commit()
            return
        expected_names = {definition.name for definition in registry}
        if {row.name for row in rows} != expected_names or len(rows) != len(registry):
            raise ToolManifestMismatchError("tool registry names differ from static manifest")
        definitions = {definition.name: definition for definition in registry}
        if any(not _row_matches(row, definitions[row.name], registry) for row in rows):
            raise ToolManifestMismatchError("tool registry metadata differs from static manifest")


def _registry_row(
    definition: ToolDefinition,
    registry: StaticToolRegistry,
) -> ToolRegistry:
    return ToolRegistry(
        id=uuid4(),
        name=definition.name,
        risk_tier=definition.risk_tier,
        schema_version=definition.schema_version,
        adapter_version=definition.adapter_version,
        manifest_checksum=registry.manifest_checksum,
        enabled=True,
        constraints=registry.database_constraints(definition),
    )


def _row_matches(
    row: ToolRegistry,
    definition: ToolDefinition,
    registry: StaticToolRegistry,
) -> bool:
    return bool(
        row.enabled
        and row.risk_tier == definition.risk_tier
        and row.schema_version == definition.schema_version
        and row.adapter_version == definition.adapter_version
        and row.manifest_checksum == registry.manifest_checksum
        and row.constraints == registry.database_constraints(definition)
    )


class SQLAlchemyToolRequestRepository:
    """Persist Phase 3 transitions and update rate windows atomically."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_registry_tool(self, name: str) -> ToolRegistry | None:
        result = await self._session.execute(select(ToolRegistry).where(ToolRegistry.name == name))
        return result.scalar_one_or_none()

    async def get_provenance_records(
        self,
        record_ids: list[UUID],
    ) -> list[ProvenanceRecord]:
        if not record_ids:
            return []
        result = await self._session.execute(
            select(ProvenanceRecord)
            .where(ProvenanceRecord.id.in_(record_ids))
            .order_by(ProvenanceRecord.id)
        )
        return list(result.scalars().all())

    async def consume_rate_limit(
        self,
        *,
        agent_id: UUID,
        task_id: UUID,
        tool_name: str,
        now: datetime,
        limit: int,
        window_seconds: int,
    ) -> RateLimitResult:
        epoch = int(now.timestamp())
        start_epoch = epoch - (epoch % window_seconds)
        window_started_at = datetime.fromtimestamp(start_epoch, tz=UTC)
        statement = (
            insert(ToolRateLimitWindow)
            .values(
                id=uuid4(),
                agent_id=agent_id,
                task_id=task_id,
                tool_name=tool_name,
                window_started_at=window_started_at,
                request_count=1,
            )
            .on_conflict_do_update(
                constraint="uq_tool_rate_limit_scope_window",
                set_={"request_count": ToolRateLimitWindow.request_count + 1},
                where=ToolRateLimitWindow.request_count < limit,
            )
            .returning(ToolRateLimitWindow.request_count)
        )
        result = await self._session.execute(statement)
        count = result.scalar_one_or_none()
        await self._session.commit()
        return RateLimitResult(
            allowed=count is not None,
            request_count=count if count is not None else limit,
            limit=limit,
            window_started_at=window_started_at,
        )

    async def create_tool_request(
        self,
        request: ToolRequest,
        influences: list[ProvenanceRecord],
    ) -> ToolRequest:
        self._session.add(request)
        await self._session.flush()
        self._session.add_all(
            ToolRequestInfluence(
                id=uuid4(),
                tool_request_id=request.id,
                provenance_record_id=record.id,
            )
            for record in influences
        )
        await self._session.commit()
        await self._session.refresh(request)
        return request

    async def store_policy_decision(self, decision: PolicyDecision) -> PolicyDecision:
        self._session.add(decision)
        await self._session.commit()
        await self._session.refresh(decision)
        return decision

    async def create_pending_approval(
        self,
        request: ToolRequest,
        approval: ApprovalRequest,
    ) -> ApprovalRequest:
        """Atomically make the request pending and persist its exact binding."""

        request.status = ToolRequestStatus.PENDING_APPROVAL
        request.error_code = None
        request.completed_at = None
        self._session.add(approval)
        await self._session.commit()
        await self._session.refresh(request)
        await self._session.refresh(approval)
        return approval

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

    async def get_tool_request(self, request_id: UUID) -> ToolRequestBundle | None:
        request = await self._session.get(ToolRequest, request_id)
        if request is None:
            return None
        result = await self._session.execute(
            select(PolicyDecision)
            .where(PolicyDecision.tool_request_id == request_id)
            .order_by(PolicyDecision.created_at.desc(), PolicyDecision.id.desc())
            .limit(1)
        )
        approval = await self._session.execute(
            select(ApprovalRequest).where(ApprovalRequest.tool_request_id == request_id)
        )
        influence_result = await self._session.execute(
            select(ProvenanceRecord)
            .join(
                ToolRequestInfluence,
                ToolRequestInfluence.provenance_record_id == ProvenanceRecord.id,
            )
            .where(ToolRequestInfluence.tool_request_id == request_id)
            .order_by(ProvenanceRecord.created_at, ProvenanceRecord.id)
        )
        produced_result = await self._session.execute(
            select(ProvenanceRecord)
            .where(ProvenanceRecord.tool_request_id == request_id)
            .order_by(ProvenanceRecord.created_at, ProvenanceRecord.id)
        )
        return ToolRequestBundle(
            request=request,
            decision=result.scalar_one_or_none(),
            approval=approval.scalar_one_or_none(),
            influences=list(influence_result.scalars().all()),
            produced_provenance=list(produced_result.scalars().all()),
        )

    async def list_tool_requests(self, limit: int) -> list[ToolRequestBundle]:
        result = await self._session.execute(
            select(ToolRequest.id)
            .order_by(ToolRequest.created_at.desc(), ToolRequest.id.desc())
            .limit(limit)
        )
        bundles: list[ToolRequestBundle] = []
        for request_id in result.scalars().all():
            bundle = await self.get_tool_request(request_id)
            if bundle is not None:
                bundles.append(bundle)
        return bundles
