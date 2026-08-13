"""Phase 3 policy-enforcement orchestration for every synthetic tool request."""

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from time import perf_counter
from typing import Protocol
from uuid import UUID, uuid4

import structlog
from fastapi import status
from pydantic import ValidationError

from app.api.errors import AgentGateError
from app.auth.crypto import EnvelopeCipher, canonical_json, canonical_sha256
from app.config import Settings
from app.models.approval import ApprovalRequest
from app.models.enums import ApprovalStatus, PolicyOutcome, ToolRequestStatus
from app.models.policy import PolicyDecision
from app.models.provenance import ProvenanceRecord
from app.models.tool import ToolRegistry, ToolRequest
from app.policies.client import (
    AuthorizationDecision,
    AuthorizationInput,
    PolicyAgent,
    PolicyApproval,
    PolicyClient,
    PolicyLimits,
    PolicyRequest,
    PolicyTask,
    PolicyToken,
    PolicyTool,
)
from app.services.identity import AgentPrincipal
from app.services.provenance import (
    ProvenanceContext,
    create_output_records,
    summarize_influences,
)
from app.tools.adapters import ToolAdapterError
from app.tools.gateway import PreparedArguments, ToolExecutionResult, ToolGateway
from app.tools.registry import (
    UNKNOWN_TOOL_LIMITS,
    StaticToolRegistry,
    ToolDefinition,
)

logger = structlog.get_logger(__name__)


@dataclass(frozen=True)
class RateLimitResult:
    allowed: bool
    request_count: int
    limit: int
    window_started_at: datetime


@dataclass(frozen=True)
class ToolRequestBundle:
    request: ToolRequest
    decision: PolicyDecision | None
    approval: ApprovalRequest | None
    influences: list[ProvenanceRecord]
    produced_provenance: list[ProvenanceRecord]


class ToolRequestRepository(Protocol):
    async def get_registry_tool(self, name: str) -> ToolRegistry | None: ...

    async def get_provenance_records(self, record_ids: list[UUID]) -> list[ProvenanceRecord]: ...

    async def consume_rate_limit(
        self,
        *,
        agent_id: UUID,
        task_id: UUID,
        tool_name: str,
        now: datetime,
        limit: int,
        window_seconds: int,
    ) -> RateLimitResult: ...

    async def create_tool_request(
        self,
        request: ToolRequest,
        influences: list[ProvenanceRecord],
    ) -> ToolRequest: ...

    async def store_policy_decision(self, decision: PolicyDecision) -> PolicyDecision: ...

    async def create_pending_approval(
        self,
        request: ToolRequest,
        approval: ApprovalRequest,
    ) -> ApprovalRequest: ...

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
    ) -> ToolRequest: ...

    async def get_tool_request(self, request_id: UUID) -> ToolRequestBundle | None: ...

    async def list_tool_requests(self, limit: int) -> list[ToolRequestBundle]: ...


@dataclass(frozen=True)
class ToolRequestCommand:
    task_id: UUID
    tool_name: str
    arguments: dict[str, object]
    request_size_bytes: int
    influence_ids: list[UUID] = field(default_factory=list)


@dataclass(frozen=True)
class ToolRequestOutcome:
    request: ToolRequest
    decision: AuthorizationDecision
    result: dict[str, object] | None
    approval: ApprovalRequest | None = None
    influences: list[ProvenanceRecord] = field(default_factory=list)
    produced_provenance: list[ProvenanceRecord] = field(default_factory=list)
    policy_decision: PolicyDecision | None = None


class ToolRequestService:
    """Persist, authorize, dispatch, and finalize one authenticated request."""

    def __init__(
        self,
        *,
        repository: ToolRequestRepository,
        registry: StaticToolRegistry,
        gateway: ToolGateway,
        policy_client: PolicyClient,
        settings: Settings,
    ) -> None:
        self._repository = repository
        self._registry = registry
        self._gateway = gateway
        self._policy_client = policy_client
        self._settings = settings
        self._cipher = EnvelopeCipher(settings.data_encryption_key_bytes)

    async def process(
        self,
        *,
        principal: AgentPrincipal,
        command: ToolRequestCommand,
        correlation_id: UUID,
    ) -> ToolRequestOutcome:
        """Apply the complete Phase 3 PEP path; no decision can bypass this method."""

        if command.task_id != principal.task.id:
            raise AgentGateError(
                status.HTTP_403_FORBIDDEN,
                "CROSS_TASK_CREDENTIAL",
                "The workload credential is not valid for the requested task.",
            )
        now = datetime.now(UTC)
        definition = self._registry.get(command.tool_name)
        limits = definition.limits if definition is not None else UNKNOWN_TOOL_LIMITS
        registry_row = await self._repository.get_registry_tool(command.tool_name)
        registry_matches = _registry_row_matches(
            registry_row,
            definition,
            self._registry,
        )
        requested_influences = await self._repository.get_provenance_records(command.influence_ids)
        provenance = summarize_influences(
            records=requested_influences,
            requested_ids=command.influence_ids,
            task_id=principal.task.id,
        )
        prepared, arguments_valid, preparation_error = await self._prepare_arguments(
            definition,
            command.arguments,
        )
        canonical_arguments = (
            prepared.normalized_arguments if prepared is not None else command.arguments
        )
        argument_hash = canonical_sha256(canonical_arguments)
        request_id = uuid4()
        encrypted_arguments, nonce = self._cipher.encrypt(
            canonical_json(command.arguments),
            associated_data=_tool_request_aad(request_id),
        )

        rate = await self._repository.consume_rate_limit(
            agent_id=principal.agent.id,
            task_id=principal.task.id,
            tool_name=command.tool_name if definition is not None else "__unknown__",
            now=now,
            limit=limits.rate_limit,
            window_seconds=limits.rate_window_seconds,
        )
        request_size_exceeded = command.request_size_bytes > limits.max_request_bytes
        known = definition is not None and registry_matches
        tool_request = ToolRequest(
            id=request_id,
            correlation_id=correlation_id,
            agent_id=principal.agent.id,
            credential_id=principal.credential.id,
            task_id=principal.task.id,
            tool_registry_id=registry_row.id if known and registry_row is not None else None,
            tool_name=command.tool_name,
            risk_tier=definition.risk_tier if definition is not None else None,
            arguments_ciphertext=encrypted_arguments,
            arguments_nonce=nonce,
            redacted_arguments=_redacted_argument_summary(
                command.arguments,
                len(encrypted_arguments),
                len(command.influence_ids),
            ),
            argument_hash=argument_hash,
            status=ToolRequestStatus.RECEIVED,
            request_size_bytes=command.request_size_bytes,
        )
        tool_request = await self._repository.create_tool_request(
            tool_request,
            provenance.records,
        )
        await logger.ainfo(
            "tool_request_received",
            tool_request_id=str(tool_request.id),
            correlation_id=str(correlation_id),
            agent_id=str(principal.agent.id),
            task_id=str(principal.task.id),
            tool_name=command.tool_name,
        )

        policy_input = _authorization_input(
            principal=principal,
            definition=definition,
            requested_tool_name=command.tool_name,
            known=known,
            arguments_valid=arguments_valid and preparation_error is None,
            policy_arguments=(
                prepared.policy_arguments if prepared is not None and arguments_valid else {}
            ),
            argument_hash=argument_hash,
            body_size_bytes=command.request_size_bytes,
            rate_exceeded=not rate.allowed,
            request_size_exceeded=request_size_exceeded,
            settings=self._settings,
            now=now,
            provenance=provenance,
        )
        started = perf_counter()
        decision = await self._policy_client.evaluate(policy_input)
        policy_latency_ms = (perf_counter() - started) * 1000
        if decision.decision is PolicyOutcome.ALLOW and not _ready_to_execute(
            principal=principal,
            definition=definition,
            prepared=prepared,
            known=known,
            arguments_valid=arguments_valid,
            rate=rate,
            request_size_exceeded=request_size_exceeded,
            decision=decision,
            provenance=provenance,
        ):
            decision = _policy_engine_denial()

        persisted_decision = PolicyDecision(
            id=uuid4(),
            tool_request_id=tool_request.id,
            opa_decision_id=decision.opa_decision_id,
            outcome=decision.decision,
            reason_codes=decision.reason_codes,
            policy_version=decision.policy_version,
            input_hash=canonical_sha256(policy_input.model_dump(mode="json")),
            latency_ms=policy_latency_ms,
        )
        await self._repository.store_policy_decision(persisted_decision)
        await logger.ainfo(
            "tool_request_decided",
            tool_request_id=str(tool_request.id),
            correlation_id=str(correlation_id),
            decision=decision.decision.value,
            reason_codes=decision.reason_codes,
            policy_latency_ms=round(policy_latency_ms, 3),
        )

        if decision.decision is PolicyOutcome.DENY:
            error_code = preparation_error or decision.reason_codes[0]
            await self._finish(
                tool_request,
                status=ToolRequestStatus.DENIED,
                error_code=error_code,
            )
            return ToolRequestOutcome(
                tool_request,
                decision,
                None,
                influences=provenance.records,
                policy_decision=persisted_decision,
            )
        if decision.decision is PolicyOutcome.REQUIRE_APPROVAL:
            approval_created_at = datetime.now(UTC)
            approval = ApprovalRequest(
                id=uuid4(),
                tool_request_id=tool_request.id,
                agent_id=tool_request.agent_id,
                task_id=tool_request.task_id,
                tool_name=tool_request.tool_name,
                argument_hash=argument_hash,
                status=ApprovalStatus.PENDING,
                expires_at=approval_created_at
                + timedelta(seconds=self._settings.approval_ttl_seconds),
                consumed_at=None,
                row_version=1,
                created_at=approval_created_at,
            )
            await self._repository.create_pending_approval(tool_request, approval)
            await logger.ainfo(
                "approval_requested",
                approval_id=str(approval.id),
                tool_request_id=str(tool_request.id),
                correlation_id=str(correlation_id),
                tool_name=tool_request.tool_name,
                argument_hash=argument_hash,
                expires_at=approval.expires_at.isoformat(),
            )
            return ToolRequestOutcome(
                tool_request,
                decision,
                None,
                approval,
                provenance.records,
                policy_decision=persisted_decision,
            )

        if definition is None or prepared is None:
            await self._finish(
                tool_request,
                status=ToolRequestStatus.DENIED,
                error_code="POLICY_ENGINE_ERROR",
            )
            return ToolRequestOutcome(
                tool_request,
                _policy_engine_denial(),
                None,
                influences=provenance.records,
                policy_decision=persisted_decision,
            )

        execution_started = perf_counter()
        tool_request.status = ToolRequestStatus.RUNNING
        try:
            execution = await self._gateway.execute(definition, prepared)
        except ToolAdapterError as exc:
            elapsed_ms = round((perf_counter() - execution_started) * 1000)
            await self._finish(
                tool_request,
                status=ToolRequestStatus.FAILED,
                error_code=exc.code,
                execution_latency_ms=elapsed_ms,
            )
            return ToolRequestOutcome(
                tool_request,
                decision,
                None,
                influences=provenance.records,
                policy_decision=persisted_decision,
            )

        elapsed_ms = round((perf_counter() - execution_started) * 1000)
        produced_provenance = create_output_records(
            request=tool_request,
            execution=execution,
            influences=provenance.records,
        )
        await self._finish_success(
            tool_request,
            execution,
            elapsed_ms,
            produced_provenance,
        )
        return ToolRequestOutcome(
            tool_request,
            decision,
            execution.result,
            influences=provenance.records,
            produced_provenance=produced_provenance,
            policy_decision=persisted_decision,
        )

    async def get(self, request_id: UUID) -> ToolRequestBundle | None:
        return await self._repository.get_tool_request(request_id)

    async def list_for_admin(self, limit: int) -> list[ToolRequestBundle]:
        """Return newest-first sanitized request bundles for administrators."""

        return await self._repository.list_tool_requests(limit)

    async def _prepare_arguments(
        self,
        definition: ToolDefinition | None,
        arguments: dict[str, object],
    ) -> tuple[PreparedArguments | None, bool, str | None]:
        if definition is None:
            return None, False, None
        try:
            return await self._gateway.prepare(definition, arguments), True, None
        except ValidationError:
            return None, False, "ARGUMENTS_INVALID"
        except ToolAdapterError as exc:
            return None, False, exc.code

    async def _finish(
        self,
        request: ToolRequest,
        *,
        status: ToolRequestStatus,
        error_code: str | None = None,
        execution_latency_ms: int | None = None,
    ) -> None:
        await self._repository.finish_tool_request(
            request,
            status=status,
            error_code=error_code,
            response_size_bytes=None,
            result_summary=None,
            execution_latency_ms=execution_latency_ms,
            completed_at=datetime.now(UTC),
            produced_provenance=[],
        )
        await _log_completion(request)

    async def _finish_success(
        self,
        request: ToolRequest,
        execution: ToolExecutionResult,
        execution_latency_ms: int,
        produced_provenance: list[ProvenanceRecord],
    ) -> None:
        await self._repository.finish_tool_request(
            request,
            status=ToolRequestStatus.SUCCEEDED,
            error_code=None,
            response_size_bytes=execution.size_bytes,
            result_summary=execution.summary,
            execution_latency_ms=execution_latency_ms,
            completed_at=datetime.now(UTC),
            produced_provenance=produced_provenance,
        )
        await _log_completion(request)


def _registry_row_matches(
    row: ToolRegistry | None,
    definition: ToolDefinition | None,
    registry: StaticToolRegistry,
) -> bool:
    if row is None or definition is None:
        return False
    return bool(
        row.enabled
        and row.name == definition.name
        and row.risk_tier is definition.risk_tier
        and row.schema_version == definition.schema_version
        and row.adapter_version == definition.adapter_version
        and row.manifest_checksum == registry.manifest_checksum
        and row.constraints == registry.database_constraints(definition)
    )


def _authorization_input(
    *,
    principal: AgentPrincipal,
    definition: ToolDefinition | None,
    requested_tool_name: str,
    known: bool,
    arguments_valid: bool,
    policy_arguments: dict[str, object],
    argument_hash: str,
    body_size_bytes: int,
    rate_exceeded: bool,
    request_size_exceeded: bool,
    settings: Settings,
    now: datetime,
    provenance: ProvenanceContext,
) -> AuthorizationInput:
    return AuthorizationInput(
        agent=PolicyAgent(id=principal.agent.id, status=principal.agent.status),
        task=PolicyTask(id=principal.task.id, owner_id=principal.task.owner_admin_id),
        token=PolicyToken(
            issuer=principal.claims.iss,
            audience=principal.claims.aud,
            expected_issuer=settings.token_issuer,
            expected_audience=settings.token_audience,
            expires_at=datetime.fromtimestamp(principal.claims.exp, tz=UTC),
            task_id=principal.claims.task_id,
            capabilities=principal.capabilities,
            revoked=False,
            proof_valid=True,
        ),
        tool=PolicyTool(
            name=requested_tool_name,
            known=known,
            risk=definition.risk_tier if definition is not None else None,
        ),
        request=PolicyRequest(
            arguments_valid=arguments_valid,
            arguments=policy_arguments,
            argument_hash=argument_hash,
            body_size_bytes=body_size_bytes,
        ),
        provenance=provenance.policy,
        approval=PolicyApproval(
            status="none",
            argument_hash=None,
            expires_at=None,
            consumed=False,
        ),
        limits=PolicyLimits(
            rate_exceeded=rate_exceeded,
            request_size_exceeded=request_size_exceeded,
            expected_response_size_exceeded=False,
        ),
        now=now,
    )


def _ready_to_execute(
    *,
    principal: AgentPrincipal,
    definition: ToolDefinition | None,
    prepared: PreparedArguments | None,
    known: bool,
    arguments_valid: bool,
    rate: RateLimitResult,
    request_size_exceeded: bool,
    decision: AuthorizationDecision,
    provenance: ProvenanceContext,
) -> bool:
    if definition is None:
        return False
    return bool(
        known
        and prepared is not None
        and arguments_valid
        and rate.allowed
        and not request_size_exceeded
        and provenance.policy.context_valid
        and definition.required_capability in principal.capabilities
        and definition.risk_tier.value in {"low", "medium"}
        and decision.reason_codes[0]
        in {"LOW_RISK_CAPABILITY_ALLOWED", "MEDIUM_RISK_CAPABILITY_ALLOWED"}
    )


def _redacted_argument_summary(
    arguments: dict[str, object],
    encrypted_size: int,
    influence_count: int,
) -> dict[str, object]:
    summary: dict[str, object] = {
        "fields": sorted(arguments),
        "encrypted_size_bytes": encrypted_size,
        "influence_count": influence_count,
    }
    for name in ("ticket_id", "query_id", "path", "max_results", "overwrite"):
        value = arguments.get(name)
        if isinstance(value, (str, int, bool)):
            summary[name] = value
    return summary


def _tool_request_aad(request_id: UUID) -> bytes:
    return b"agentgate:tool-request:" + request_id.bytes


def _policy_engine_denial() -> AuthorizationDecision:
    return AuthorizationDecision(
        decision=PolicyOutcome.DENY,
        reason_codes=["POLICY_ENGINE_ERROR"],
        policy_version="unavailable",
    )


async def _log_completion(request: ToolRequest) -> None:
    await logger.ainfo(
        "tool_request_completed",
        tool_request_id=str(request.id),
        correlation_id=str(request.correlation_id),
        status=request.status.value,
        error_code=request.error_code,
        execution_latency_ms=request.execution_latency_ms,
        response_size_bytes=request.response_size_bytes,
    )
