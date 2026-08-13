"""Phase 4 exact-request administrative approval and one-shot execution."""

import hmac
import json
from collections.abc import Sequence
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from datetime import UTC, datetime
from time import perf_counter
from typing import Protocol, cast
from uuid import UUID, uuid4

import structlog
from cryptography.exceptions import InvalidTag
from fastapi import status
from pydantic import ValidationError

from app.api.errors import AgentGateError
from app.auth.crypto import EnvelopeCipher, canonical_sha256
from app.config import Settings
from app.models.approval import ApprovalAction, ApprovalRequest
from app.models.enums import (
    AdministratorStatus,
    AgentStatus,
    ApprovalActionType,
    ApprovalStatus,
    CredentialStatus,
    PolicyOutcome,
    TaskStatus,
    ToolRequestStatus,
)
from app.models.identity import Agent, AgentCredential
from app.models.policy import PolicyDecision
from app.models.provenance import ProvenanceRecord
from app.models.task import Task
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
from app.services.identity import AdminPrincipal
from app.services.provenance import create_output_records, summarize_influences
from app.services.tools import _policy_engine_denial, _registry_row_matches
from app.tools.adapters import ToolAdapterError
from app.tools.gateway import PreparedArguments, ToolExecutionResult, ToolGateway
from app.tools.registry import StaticToolRegistry, ToolDefinition

logger = structlog.get_logger(__name__)


class ApprovalNotFoundError(Exception):
    """The locked approval does not exist."""


@dataclass(frozen=True)
class ApprovalBundle:
    """All current authoritative records covered by the approval lock."""

    approval: ApprovalRequest
    request: ToolRequest
    decision: PolicyDecision | None
    registry_tool: ToolRegistry | None
    credential: AgentCredential
    agent: Agent
    task: Task
    capabilities: list[str]
    revoked: bool
    influences: list[ProvenanceRecord]


@dataclass(frozen=True)
class ApprovalRecord:
    """Sanitized approval state returned by the service layer."""

    approval: ApprovalRequest
    request: ToolRequest
    decision: PolicyDecision | None


class LockedApproval(Protocol):
    """Mutation surface available while the database row lock is held."""

    @property
    def bundle(self) -> ApprovalBundle: ...

    def add_action(self, action: ApprovalAction) -> None: ...

    def add_policy_decision(self, decision: PolicyDecision) -> None: ...


class ApprovalRepository(Protocol):
    """Persistence contract that keeps approval evaluation under a row lock."""

    def lock(self, approval_id: UUID) -> AbstractAsyncContextManager[LockedApproval]: ...

    async def list_approvals(self, now: datetime) -> Sequence[ApprovalRecord]: ...

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


class ApprovalService:
    """Authorize an administrator and consume an exact approval at most once."""

    def __init__(
        self,
        *,
        repository: ApprovalRepository,
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

    async def list_records(self, administrator: AdminPrincipal) -> Sequence[ApprovalRecord]:
        """Return only sanitized approval summaries to an active administrator."""

        _require_active_administrator(administrator)
        return await self._repository.list_approvals(datetime.now(UTC))

    async def approve(
        self,
        *,
        approval_id: UUID,
        expected_argument_hash: str,
        administrator: AdminPrincipal,
        reason: str | None,
    ) -> ApprovalRecord:
        """Re-evaluate and execute only the authenticated stored request."""

        _require_active_administrator(administrator)
        administrator_id = administrator.administrator.id
        prepared: PreparedArguments | None = None
        definition: ToolDefinition | None = None
        persisted_decision: PolicyDecision | None = None
        deferred_error: AgentGateError | None = None
        bundle: ApprovalBundle | None = None

        try:
            async with self._repository.lock(approval_id) as locked:
                bundle = locked.bundle
                now = datetime.now(UTC)
                state_error = _approval_state_error(bundle, now)
                if state_error is not None:
                    if state_error.code == "APPROVAL_EXPIRED":
                        _expire(bundle, now)
                    deferred_error = state_error
                elif not _expected_hash_matches(bundle, expected_argument_hash):
                    deferred_error = _approval_error(
                        status.HTTP_409_CONFLICT,
                        "APPROVAL_ARGUMENT_MISMATCH",
                    )
                else:
                    definition = self._registry.get(bundle.request.tool_name)
                    try:
                        arguments = self._decrypt_original_arguments(bundle.request)
                        prepared = (
                            await self._gateway.prepare(definition, arguments)
                            if definition
                            else None
                        )
                    except (InvalidTag, ToolAdapterError, ValidationError, TypeError, ValueError):
                        prepared = None

                    recomputed_hash = (
                        canonical_sha256(prepared.normalized_arguments)
                        if prepared is not None
                        else ""
                    )
                    if not _stored_binding_matches(
                        bundle,
                        definition,
                        self._registry,
                        recomputed_hash,
                    ):
                        deferred_error = _approval_error(
                            status.HTTP_409_CONFLICT,
                            "APPROVAL_ARGUMENT_MISMATCH",
                        )
                    else:
                        bundle.approval.status = ApprovalStatus.APPROVED
                        bundle.approval.row_version += 1
                        locked.add_action(
                            ApprovalAction(
                                id=uuid4(),
                                approval_request_id=bundle.approval.id,
                                administrator_id=administrator_id,
                                action=ApprovalActionType.APPROVE,
                                reason=reason,
                                created_at=now,
                            )
                        )
                        policy_input = _authorization_input(
                            bundle=bundle,
                            definition=cast(ToolDefinition, definition),
                            prepared=cast(PreparedArguments, prepared),
                            registry=self._registry,
                            settings=self._settings,
                            now=now,
                        )
                        started = perf_counter()
                        try:
                            decision = await self._policy_client.evaluate(policy_input)
                        except Exception:
                            decision = _policy_engine_denial()
                        policy_latency_ms = (perf_counter() - started) * 1000
                        if (
                            not _ready_to_execute(
                                bundle=bundle,
                                definition=definition,
                                prepared=prepared,
                                decision=decision,
                                now=now,
                            )
                            and decision.decision is not PolicyOutcome.DENY
                        ):
                            decision = _policy_engine_denial()
                        persisted_decision = PolicyDecision(
                            id=uuid4(),
                            tool_request_id=bundle.request.id,
                            opa_decision_id=decision.opa_decision_id,
                            outcome=decision.decision,
                            reason_codes=decision.reason_codes,
                            policy_version=decision.policy_version,
                            input_hash=canonical_sha256(policy_input.model_dump(mode="json")),
                            latency_ms=policy_latency_ms,
                            created_at=now,
                        )
                        locked.add_policy_decision(persisted_decision)

                        # Consumption is committed before dispatch. Adapter failure cannot
                        # make this authority reusable.
                        bundle.approval.status = ApprovalStatus.CONSUMED
                        bundle.approval.consumed_at = now
                        bundle.approval.row_version += 1
                        if decision.decision is PolicyOutcome.ALLOW:
                            bundle.request.status = ToolRequestStatus.RUNNING
                            bundle.request.error_code = None
                            bundle.request.completed_at = None
                        else:
                            bundle.request.status = ToolRequestStatus.DENIED
                            bundle.request.error_code = decision.reason_codes[0]
                            bundle.request.completed_at = now
                            deferred_error = _approval_error(
                                status.HTTP_403_FORBIDDEN,
                                decision.reason_codes[0],
                            )
        except ApprovalNotFoundError as exc:
            raise _not_found() from exc

        if deferred_error is not None:
            raise deferred_error
        if bundle is None or definition is None or prepared is None or persisted_decision is None:
            raise _approval_error(status.HTTP_403_FORBIDDEN, "POLICY_ENGINE_ERROR")

        await logger.ainfo(
            "approval_consumed",
            approval_id=str(bundle.approval.id),
            tool_request_id=str(bundle.request.id),
            administrator_id=str(administrator_id),
            argument_hash=bundle.approval.argument_hash,
        )
        await self._dispatch(
            bundle.request,
            definition,
            prepared,
            bundle.influences,
        )
        return ApprovalRecord(bundle.approval, bundle.request, persisted_decision)

    async def reject(
        self,
        *,
        approval_id: UUID,
        administrator: AdminPrincipal,
        reason: str | None,
    ) -> ApprovalRecord:
        """Permanently reject a pending approval without invoking OPA or an adapter."""

        _require_active_administrator(administrator)
        administrator_id = administrator.administrator.id
        deferred_error: AgentGateError | None = None
        record: ApprovalRecord | None = None
        try:
            async with self._repository.lock(approval_id) as locked:
                bundle = locked.bundle
                now = datetime.now(UTC)
                state_error = _approval_state_error(bundle, now)
                if state_error is not None:
                    if state_error.code == "APPROVAL_EXPIRED":
                        _expire(bundle, now)
                    deferred_error = state_error
                else:
                    bundle.approval.status = ApprovalStatus.REJECTED
                    bundle.approval.row_version += 1
                    bundle.request.status = ToolRequestStatus.DENIED
                    bundle.request.error_code = "APPROVAL_REJECTED"
                    bundle.request.completed_at = now
                    locked.add_action(
                        ApprovalAction(
                            id=uuid4(),
                            approval_request_id=bundle.approval.id,
                            administrator_id=administrator_id,
                            action=ApprovalActionType.REJECT,
                            reason=reason,
                            created_at=now,
                        )
                    )
                    record = ApprovalRecord(
                        bundle.approval,
                        bundle.request,
                        bundle.decision,
                    )
        except ApprovalNotFoundError as exc:
            raise _not_found() from exc

        if deferred_error is not None:
            raise deferred_error
        if record is None:
            raise _approval_error(status.HTTP_409_CONFLICT, "APPROVAL_REPLAYED")
        await logger.ainfo(
            "approval_rejected",
            approval_id=str(record.approval.id),
            tool_request_id=str(record.request.id),
            administrator_id=str(administrator_id),
        )
        return record

    def _decrypt_original_arguments(self, request: ToolRequest) -> dict[str, object]:
        if request.arguments_ciphertext is None or request.arguments_nonce is None:
            raise ValueError("stored arguments are unavailable")
        plaintext = self._cipher.decrypt(
            request.arguments_ciphertext,
            request.arguments_nonce,
            associated_data=_tool_request_aad(request.id),
        )
        decoded = json.loads(plaintext.decode("utf-8"))
        if not isinstance(decoded, dict) or any(not isinstance(key, str) for key in decoded):
            raise ValueError("stored arguments are not a JSON object")
        return cast(dict[str, object], decoded)

    async def _dispatch(
        self,
        request: ToolRequest,
        definition: ToolDefinition,
        prepared: PreparedArguments,
        influences: list[ProvenanceRecord],
    ) -> None:
        started = perf_counter()
        try:
            execution = await self._gateway.execute(definition, prepared)
        except ToolAdapterError as exc:
            await self._finish(
                request,
                status=ToolRequestStatus.FAILED,
                error_code=exc.code,
                execution=None,
                execution_latency_ms=round((perf_counter() - started) * 1000),
                produced_provenance=[],
            )
            return
        produced_provenance = create_output_records(
            request=request,
            execution=execution,
            influences=influences,
        )
        await self._finish(
            request,
            status=ToolRequestStatus.SUCCEEDED,
            error_code=None,
            execution=execution,
            execution_latency_ms=round((perf_counter() - started) * 1000),
            produced_provenance=produced_provenance,
        )

    async def _finish(
        self,
        request: ToolRequest,
        *,
        status: ToolRequestStatus,
        error_code: str | None,
        execution: ToolExecutionResult | None,
        execution_latency_ms: int,
        produced_provenance: list[ProvenanceRecord],
    ) -> None:
        await self._repository.finish_tool_request(
            request,
            status=status,
            error_code=error_code,
            response_size_bytes=execution.size_bytes if execution is not None else None,
            result_summary=execution.summary if execution is not None else None,
            execution_latency_ms=execution_latency_ms,
            completed_at=datetime.now(UTC),
            produced_provenance=produced_provenance,
        )


def _authorization_input(
    *,
    bundle: ApprovalBundle,
    definition: ToolDefinition,
    prepared: PreparedArguments,
    registry: StaticToolRegistry,
    settings: Settings,
    now: datetime,
) -> AuthorizationInput:
    request = bundle.request
    approval = bundle.approval
    return AuthorizationInput(
        agent=PolicyAgent(id=bundle.agent.id, status=bundle.agent.status),
        task=PolicyTask(id=bundle.task.id, owner_id=bundle.task.owner_admin_id),
        token=PolicyToken(
            issuer=settings.token_issuer,
            audience=settings.token_audience,
            expected_issuer=settings.token_issuer,
            expected_audience=settings.token_audience,
            expires_at=bundle.credential.expires_at,
            task_id=bundle.credential.task_id,
            capabilities=bundle.capabilities,
            revoked=bundle.revoked or bundle.credential.status is not CredentialStatus.ACTIVE,
            proof_valid=True,
        ),
        tool=PolicyTool(
            name=request.tool_name,
            known=_registry_row_matches(bundle.registry_tool, definition, registry),
            risk=definition.risk_tier,
        ),
        request=PolicyRequest(
            arguments_valid=True,
            arguments=prepared.policy_arguments,
            argument_hash=cast(str, request.argument_hash),
            body_size_bytes=request.request_size_bytes,
        ),
        provenance=summarize_influences(
            records=bundle.influences,
            requested_ids=[record.id for record in bundle.influences],
            task_id=bundle.task.id,
        ).policy,
        approval=PolicyApproval(
            status="approved",
            argument_hash=approval.argument_hash,
            expires_at=approval.expires_at,
            consumed=False,
        ),
        limits=PolicyLimits(
            rate_exceeded=False,
            request_size_exceeded=request.request_size_bytes > definition.limits.max_request_bytes,
            expected_response_size_exceeded=False,
        ),
        now=now,
    )


def _ready_to_execute(
    *,
    bundle: ApprovalBundle,
    definition: ToolDefinition | None,
    prepared: PreparedArguments | None,
    decision: AuthorizationDecision,
    now: datetime,
) -> bool:
    if definition is None or prepared is None or bundle.request.argument_hash is None:
        return False
    task_current = (
        bundle.task.status is TaskStatus.ACTIVE
        and (bundle.task.starts_at is None or bundle.task.starts_at <= now)
        and (bundle.task.expires_at is None or bundle.task.expires_at > now)
    )
    provenance = summarize_influences(
        records=bundle.influences,
        requested_ids=[record.id for record in bundle.influences],
        task_id=bundle.task.id,
    )
    return bool(
        decision.decision is PolicyOutcome.ALLOW
        and "APPROVAL_VALID" in decision.reason_codes
        and bundle.agent.status is AgentStatus.ACTIVE
        and bundle.credential.status is CredentialStatus.ACTIVE
        and bundle.credential.expires_at > now
        and not bundle.revoked
        and provenance.policy.context_valid
        and task_current
        and definition.required_capability in bundle.capabilities
        and definition.risk_tier.value == "high"
        and bundle.approval.status is ApprovalStatus.APPROVED
        and bundle.approval.expires_at > now
        and bundle.approval.consumed_at is None
        and hmac.compare_digest(
            bundle.request.argument_hash,
            canonical_sha256(prepared.normalized_arguments),
        )
    )


def _expected_hash_matches(bundle: ApprovalBundle, expected_hash: str) -> bool:
    request_hash = bundle.request.argument_hash or ""
    return hmac.compare_digest(
        bundle.approval.argument_hash, expected_hash
    ) and hmac.compare_digest(
        bundle.approval.argument_hash,
        request_hash,
    )


def _stored_binding_matches(
    bundle: ApprovalBundle,
    definition: ToolDefinition | None,
    registry: StaticToolRegistry,
    recomputed_hash: str,
) -> bool:
    request = bundle.request
    approval = bundle.approval
    registry_tool = bundle.registry_tool
    return bool(
        definition is not None
        and registry_tool is not None
        and _registry_row_matches(registry_tool, definition, registry)
        and request.tool_registry_id == registry_tool.id
        and request.risk_tier is definition.risk_tier
        and request.agent_id == approval.agent_id == bundle.agent.id == bundle.credential.agent_id
        and request.task_id == approval.task_id == bundle.task.id == bundle.credential.task_id
        and bundle.task.assigned_agent_id == bundle.agent.id
        and hmac.compare_digest(
            bundle.credential.key_thumbprint,
            bundle.agent.key_thumbprint,
        )
        and hmac.compare_digest(request.tool_name, approval.tool_name)
        and hmac.compare_digest(request.tool_name, definition.name)
        and request.argument_hash is not None
        and hmac.compare_digest(request.argument_hash, approval.argument_hash)
        and hmac.compare_digest(request.argument_hash, recomputed_hash)
    )


def _approval_state_error(bundle: ApprovalBundle, now: datetime) -> AgentGateError | None:
    approval = bundle.approval
    if approval.status is ApprovalStatus.PENDING and approval.expires_at <= now:
        return _approval_error(status.HTTP_410_GONE, "APPROVAL_EXPIRED")
    if approval.status is ApprovalStatus.EXPIRED:
        return _approval_error(status.HTTP_410_GONE, "APPROVAL_EXPIRED")
    if approval.status is ApprovalStatus.REJECTED:
        return _approval_error(status.HTTP_409_CONFLICT, "APPROVAL_REJECTED")
    if approval.status is not ApprovalStatus.PENDING:
        return _approval_error(status.HTTP_409_CONFLICT, "APPROVAL_REPLAYED")
    if bundle.request.status is not ToolRequestStatus.PENDING_APPROVAL:
        return _approval_error(status.HTTP_409_CONFLICT, "APPROVAL_REPLAYED")
    return None


def _expire(bundle: ApprovalBundle, now: datetime) -> None:
    bundle.approval.status = ApprovalStatus.EXPIRED
    bundle.approval.row_version += 1
    bundle.request.status = ToolRequestStatus.DENIED
    bundle.request.error_code = "APPROVAL_EXPIRED"
    bundle.request.completed_at = now


def _require_active_administrator(administrator: AdminPrincipal) -> None:
    if administrator.administrator.status is not AdministratorStatus.ACTIVE:
        raise AgentGateError(
            status.HTTP_403_FORBIDDEN,
            "ADMINISTRATOR_INACTIVE",
            "The request is not authorized.",
        )


def _approval_error(status_code: int, code: str) -> AgentGateError:
    return AgentGateError(
        status_code,
        code,
        "The approval is not valid for execution.",
    )


def _not_found() -> AgentGateError:
    return AgentGateError(
        status.HTTP_404_NOT_FOUND,
        "NOT_FOUND",
        "The requested resource was not found.",
    )


def _tool_request_aad(request_id: UUID) -> bytes:
    return b"agentgate:tool-request:" + request_id.bytes
