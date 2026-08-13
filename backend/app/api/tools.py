"""Authenticated REST boundary for Phase 3 tool mediation and safe request views."""

import re
from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Query, Request, Response, Security, status
from fastapi.security import HTTPAuthorizationCredentials
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.audit_dependencies import get_audit_service
from app.api.errors import AgentGateError, request_id_from
from app.api.identity import bearer_scheme, require_admin
from app.auth.crypto import canonical_json
from app.db.identity import SQLAlchemyIdentityRepository
from app.db.session import get_session
from app.db.tools import SQLAlchemyToolRequestRepository
from app.models.enums import (
    PolicyOutcome,
    ProvenanceSourceType,
    RiskTier,
    ToolRequestStatus,
    TrustLabel,
)
from app.models.provenance import ProvenanceRecord
from app.models.tool import ToolRequest
from app.services.audit import AuditService
from app.services.audit_events import tool_outcome_events
from app.services.identity import AdminPrincipal, IdentityService
from app.services.tools import ToolRequestCommand, ToolRequestOutcome, ToolRequestService

router = APIRouter(tags=["tools"])


class ToolRequestCreate(BaseModel):
    """Outer tool envelope; the selected static schema validates `arguments`."""

    model_config = ConfigDict(extra="forbid", strict=True)

    task_id: UUID
    tool_name: str = Field(
        min_length=3,
        max_length=120,
        pattern=r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$",
    )
    arguments: dict[str, object] = Field(max_length=32)
    influence_ids: list[UUID] = Field(default_factory=list, max_length=32)

    @field_validator("task_id", mode="before")
    @classmethod
    def parse_task_uuid(cls, value: object) -> object:
        """Accept only the canonical JSON string representation of a UUID."""

        if isinstance(value, str):
            try:
                parsed = UUID(value)
            except ValueError:
                return value
            if str(parsed) == value.lower():
                return parsed
        return value

    @field_validator("arguments")
    @classmethod
    def validate_argument_object(cls, value: dict[str, object]) -> dict[str, object]:
        if any(
            not isinstance(key, str) or re.fullmatch(r"^[A-Za-z][A-Za-z0-9_]{0,63}$", key) is None
            for key in value
        ):
            raise ValueError("argument property names are invalid")
        canonical_json(value)
        return value

    @field_validator("influence_ids", mode="before")
    @classmethod
    def parse_influence_ids(cls, value: object) -> object:
        if not isinstance(value, list):
            return value
        parsed: list[UUID] = []
        for item in value:
            if not isinstance(item, str):
                return value
            try:
                record_id = UUID(item)
            except ValueError:
                return value
            if str(record_id) != item.lower():
                return value
            parsed.append(record_id)
        if len(parsed) != len(set(parsed)):
            raise ValueError("influence IDs must be unique")
        return parsed


class ProvenanceReferenceResponse(BaseModel):
    """Content-free authoritative provenance metadata safe for agent reuse."""

    model_config = ConfigDict(extra="forbid")

    id: UUID
    source_type: ProvenanceSourceType
    trust_label: TrustLabel
    source_reference: str | None
    content_hash: str


class ToolRequestResponse(BaseModel):
    """Sanitized request state; full encrypted arguments are never returned."""

    model_config = ConfigDict(extra="forbid")

    id: UUID
    correlation_id: UUID
    agent_id: UUID
    task_id: UUID
    tool_name: str
    risk_tier: RiskTier | None
    status: ToolRequestStatus
    decision: PolicyOutcome | None
    policy_version: str | None
    reason_codes: list[str]
    error_code: str | None
    result: dict[str, object] | None
    result_summary: dict[str, object] | None
    request_size_bytes: int
    response_size_bytes: int | None
    execution_latency_ms: int | None
    created_at: datetime
    completed_at: datetime | None
    approval_id: UUID | None
    influences: list[ProvenanceReferenceResponse]
    produced_provenance: list[ProvenanceReferenceResponse]


async def get_tool_request_service(
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> ToolRequestService:
    return ToolRequestService(
        repository=SQLAlchemyToolRequestRepository(session),
        registry=request.app.state.tool_registry,
        gateway=request.app.state.tool_gateway,
        policy_client=request.app.state.policy_client,
        settings=request.app.state.settings,
    )


async def get_tool_identity_service(
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> IdentityService:
    return IdentityService(SQLAlchemyIdentityRepository(session), request.app.state.settings)


def _encoded_bearer(credentials: HTTPAuthorizationCredentials | None) -> str:
    if (
        credentials is None
        or credentials.scheme.lower() != "bearer"
        or not 64 <= len(credentials.credentials) <= 4_096
    ):
        raise AgentGateError(
            status.HTTP_401_UNAUTHORIZED,
            "UNAUTHENTICATED",
            "Authentication is required.",
        )
    return credentials.credentials


def _encoded_proof(proof: str | None) -> str:
    if proof is None or not 64 <= len(proof) <= 4_096:
        raise AgentGateError(
            status.HTTP_401_UNAUTHORIZED,
            "PROOF_INVALID",
            "The supplied workload credential or proof is not valid.",
        )
    return proof


@router.post(
    "/tool-requests",
    response_model=ToolRequestResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_tool_request(
    body: ToolRequestCreate,
    request: Request,
    response: Response,
    identity: Annotated[IdentityService, Depends(get_tool_identity_service)],
    service: Annotated[ToolRequestService, Depends(get_tool_request_service)],
    audit: Annotated[AuditService, Depends(get_audit_service)],
    credentials: Annotated[HTTPAuthorizationCredentials | None, Security(bearer_scheme)],
    proof: Annotated[str | None, Header(alias="X-Agent-Proof")] = None,
) -> ToolRequestResponse:
    """Authenticate, authorize, and conditionally execute one exact tool request."""

    proof_body = body.model_dump(mode="json", exclude_unset=True)
    principal = await identity.authenticate_agent_request(
        encoded_token=_encoded_bearer(credentials),
        proof=_encoded_proof(proof),
        method=request.method,
        path=request.url.path,
        body=proof_body,
        required_task_id=body.task_id,
    )
    body_size = int(
        getattr(request.state, "request_body_size_bytes", len(canonical_json(proof_body)))
    )
    outcome = await service.process(
        principal=principal,
        command=ToolRequestCommand(
            task_id=body.task_id,
            tool_name=body.tool_name,
            arguments=body.arguments,
            request_size_bytes=body_size,
            influence_ids=body.influence_ids,
        ),
        correlation_id=UUID(request_id_from(request)),
    )
    await audit.append(*tool_outcome_events(outcome))
    response.status_code = _outcome_status(outcome)
    return _tool_response(
        outcome.request,
        decision=outcome.decision.decision,
        policy_version=outcome.decision.policy_version,
        reason_codes=outcome.decision.reason_codes,
        result=outcome.result,
        approval_id=outcome.approval.id if outcome.approval is not None else None,
        influences=outcome.influences,
        produced_provenance=outcome.produced_provenance,
    )


@router.get("/tool-requests", response_model=list[ToolRequestResponse])
async def list_tool_requests(
    administrator: Annotated[AdminPrincipal, Depends(require_admin)],
    service: Annotated[ToolRequestService, Depends(get_tool_request_service)],
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
) -> list[ToolRequestResponse]:
    """Return newest-first sanitized tool activity to administrators."""

    del administrator
    return [
        _tool_response(
            bundle.request,
            decision=bundle.decision.outcome if bundle.decision is not None else None,
            policy_version=bundle.decision.policy_version if bundle.decision is not None else None,
            reason_codes=bundle.decision.reason_codes if bundle.decision is not None else [],
            result=None,
            approval_id=bundle.approval.id if bundle.approval is not None else None,
            influences=bundle.influences,
            produced_provenance=bundle.produced_provenance,
        )
        for bundle in await service.list_for_admin(limit)
    ]


@router.get("/tool-requests/{request_id}", response_model=ToolRequestResponse)
async def get_tool_request(
    request_id: UUID,
    request: Request,
    identity: Annotated[IdentityService, Depends(get_tool_identity_service)],
    service: Annotated[ToolRequestService, Depends(get_tool_request_service)],
    credentials: Annotated[HTTPAuthorizationCredentials | None, Security(bearer_scheme)],
    proof: Annotated[str | None, Header(alias="X-Agent-Proof")] = None,
) -> ToolRequestResponse:
    """Return a sanitized request view to its workload owner or an administrator."""

    bundle = await service.get(request_id)
    if bundle is None:
        raise _not_found()
    encoded = _encoded_bearer(credentials)
    if proof is None:
        await identity.authenticate_admin(encoded)
    else:
        principal = await identity.authenticate_agent_request(
            encoded_token=encoded,
            proof=_encoded_proof(proof),
            method=request.method,
            path=request.url.path,
            body={},
            required_task_id=bundle.request.task_id,
        )
        if principal.agent.id != bundle.request.agent_id:
            raise _not_found()
    return _tool_response(
        bundle.request,
        decision=bundle.decision.outcome if bundle.decision is not None else None,
        policy_version=bundle.decision.policy_version if bundle.decision is not None else None,
        reason_codes=bundle.decision.reason_codes if bundle.decision is not None else [],
        result=None,
        approval_id=bundle.approval.id if bundle.approval is not None else None,
        influences=bundle.influences,
        produced_provenance=bundle.produced_provenance,
    )


def _outcome_status(outcome: ToolRequestOutcome) -> int:
    if outcome.request.status is ToolRequestStatus.DENIED:
        return status.HTTP_403_FORBIDDEN
    if outcome.request.status is ToolRequestStatus.PENDING_APPROVAL:
        return status.HTTP_202_ACCEPTED
    if outcome.request.status is ToolRequestStatus.FAILED:
        if outcome.request.error_code == "TOOL_TIMEOUT":
            return status.HTTP_504_GATEWAY_TIMEOUT
        return status.HTTP_502_BAD_GATEWAY
    return status.HTTP_201_CREATED


def _tool_response(
    request: ToolRequest,
    *,
    decision: PolicyOutcome | None,
    policy_version: str | None,
    reason_codes: list[str],
    result: dict[str, object] | None,
    approval_id: UUID | None,
    influences: list[ProvenanceRecord],
    produced_provenance: list[ProvenanceRecord],
) -> ToolRequestResponse:
    return ToolRequestResponse(
        id=request.id,
        correlation_id=request.correlation_id,
        agent_id=request.agent_id,
        task_id=request.task_id,
        tool_name=request.tool_name,
        risk_tier=request.risk_tier,
        status=request.status,
        decision=decision,
        policy_version=policy_version,
        reason_codes=reason_codes,
        error_code=request.error_code,
        result=result,
        result_summary=request.result_summary,
        request_size_bytes=request.request_size_bytes,
        response_size_bytes=request.response_size_bytes,
        execution_latency_ms=request.execution_latency_ms,
        created_at=request.created_at,
        completed_at=request.completed_at,
        approval_id=approval_id,
        influences=[_provenance_response(record) for record in influences],
        produced_provenance=[_provenance_response(record) for record in produced_provenance],
    )


def _provenance_response(record: ProvenanceRecord) -> ProvenanceReferenceResponse:
    return ProvenanceReferenceResponse(
        id=record.id,
        source_type=record.source_type,
        trust_label=record.trust_label,
        source_reference=record.source_reference,
        content_hash=record.content_hash,
    )


def _not_found() -> AgentGateError:
    return AgentGateError(
        status.HTTP_404_NOT_FOUND,
        "NOT_FOUND",
        "The requested resource was not found.",
    )
