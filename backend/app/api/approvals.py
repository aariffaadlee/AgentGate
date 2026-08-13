"""Administrator-only Phase 4 approval endpoints."""

from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.audit_dependencies import get_audit_service
from app.api.identity import require_admin
from app.db.approvals import SQLAlchemyApprovalRepository
from app.db.session import get_session
from app.models.enums import ApprovalStatus, PolicyOutcome, ToolRequestStatus
from app.services.approvals import ApprovalRecord, ApprovalService
from app.services.audit import AuditService
from app.services.audit_events import approval_outcome_events
from app.services.identity import AdminPrincipal

router = APIRouter(tags=["approvals"])


class ApprovalDecisionRequest(BaseModel):
    """Administrator confirmation of the exact hash shown in the pending view."""

    model_config = ConfigDict(extra="forbid", strict=True)

    argument_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    reason: str | None = Field(default=None, max_length=500)


class ApprovalRejectRequest(BaseModel):
    """Optional administrative rationale for rejecting the request."""

    model_config = ConfigDict(extra="forbid", strict=True)

    reason: str | None = Field(default=None, max_length=500)


class ApprovalResponse(BaseModel):
    """Sanitized exact binding and lifecycle state; no full arguments are exposed."""

    model_config = ConfigDict(extra="forbid")

    id: UUID
    tool_request_id: UUID
    agent_id: UUID
    task_id: UUID
    tool_name: str
    argument_hash: str
    redacted_arguments: dict[str, object]
    status: ApprovalStatus
    expires_at: datetime
    consumed_at: datetime | None
    row_version: int
    tool_request_status: ToolRequestStatus
    decision: PolicyOutcome | None
    reason_codes: list[str]
    error_code: str | None
    result_summary: dict[str, object] | None
    created_at: datetime


async def get_approval_service(
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> ApprovalService:
    return ApprovalService(
        repository=SQLAlchemyApprovalRepository(session),
        registry=request.app.state.tool_registry,
        gateway=request.app.state.tool_gateway,
        policy_client=request.app.state.policy_client,
        settings=request.app.state.settings,
    )


@router.get("/approvals", response_model=list[ApprovalResponse])
async def list_approvals(
    administrator: Annotated[AdminPrincipal, Depends(require_admin)],
    service: Annotated[ApprovalService, Depends(get_approval_service)],
) -> list[ApprovalResponse]:
    """List sanitized approval records for the administrative plane only."""

    return [_approval_response(record) for record in await service.list_records(administrator)]


@router.post("/approvals/{approval_id}/approve", response_model=ApprovalResponse)
async def approve_request(
    approval_id: UUID,
    body: ApprovalDecisionRequest,
    administrator: Annotated[AdminPrincipal, Depends(require_admin)],
    service: Annotated[ApprovalService, Depends(get_approval_service)],
    audit: Annotated[AuditService, Depends(get_audit_service)],
) -> ApprovalResponse:
    """Approve the displayed hash, re-run policy, consume, then dispatch once."""

    record = await service.approve(
        approval_id=approval_id,
        expected_argument_hash=body.argument_hash,
        administrator=administrator,
        reason=body.reason,
    )
    await audit.append(
        *approval_outcome_events(
            record,
            administrator_id=administrator.administrator.id,
            action="consumed",
            reason_present=body.reason is not None,
        )
    )
    return _approval_response(record)


@router.post("/approvals/{approval_id}/reject", response_model=ApprovalResponse)
async def reject_request(
    approval_id: UUID,
    body: ApprovalRejectRequest,
    administrator: Annotated[AdminPrincipal, Depends(require_admin)],
    service: Annotated[ApprovalService, Depends(get_approval_service)],
    audit: Annotated[AuditService, Depends(get_audit_service)],
) -> ApprovalResponse:
    """Reject the exact pending request without dispatching its adapter."""

    record = await service.reject(
        approval_id=approval_id,
        administrator=administrator,
        reason=body.reason,
    )
    await audit.append(
        *approval_outcome_events(
            record,
            administrator_id=administrator.administrator.id,
            action="rejected",
            reason_present=body.reason is not None,
        )
    )
    return _approval_response(record)


def _approval_response(record: ApprovalRecord) -> ApprovalResponse:
    approval = record.approval
    request = record.request
    return ApprovalResponse(
        id=approval.id,
        tool_request_id=approval.tool_request_id,
        agent_id=approval.agent_id,
        task_id=approval.task_id,
        tool_name=approval.tool_name,
        argument_hash=approval.argument_hash,
        redacted_arguments=request.redacted_arguments,
        status=approval.status,
        expires_at=approval.expires_at,
        consumed_at=approval.consumed_at,
        row_version=approval.row_version,
        tool_request_status=request.status,
        decision=record.decision.outcome if record.decision is not None else None,
        reason_codes=record.decision.reason_codes if record.decision is not None else [],
        error_code=request.error_code,
        result_summary=request.result_summary,
        created_at=approval.created_at,
    )
