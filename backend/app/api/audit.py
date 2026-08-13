"""Administrator-only audit timeline and integrity verification API."""

from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict

from app.api.audit_dependencies import get_audit_service
from app.api.identity import require_admin
from app.models.enums import AuditActorType
from app.services.audit import AuditService
from app.services.identity import AdminPrincipal

router = APIRouter(prefix="/audit", tags=["audit"])


class AuditEventResponse(BaseModel):
    """Redacted event view retaining the fields needed to reconstruct a timeline."""

    model_config = ConfigDict(extra="forbid")

    sequence: int
    event_id: UUID
    chain_id: UUID
    event_type: str
    occurred_at: datetime
    correlation_id: UUID
    actor_type: AuditActorType
    actor_id: UUID | None
    task_id: UUID | None
    tool_request_id: UUID | None
    payload: dict[str, object]
    previous_hash: str
    event_hash: str


class AuditVerificationResponse(BaseModel):
    """Content-free result from complete chain and checkpoint verification."""

    model_config = ConfigDict(extra="forbid")

    valid: bool
    reason_code: str
    event_count: int
    verified_sequence: int
    chain_id: UUID | None
    head_hash: str
    failure_sequence: int | None


@router.get("/events", response_model=list[AuditEventResponse])
async def list_audit_events(
    administrator: Annotated[AdminPrincipal, Depends(require_admin)],
    service: Annotated[AuditService, Depends(get_audit_service)],
    after_sequence: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
    correlation_id: UUID | None = None,
    task_id: UUID | None = None,
    tool_request_id: UUID | None = None,
    event_type: Annotated[
        str | None,
        Query(min_length=3, max_length=100, pattern=r"^[a-z][a-z0-9_.]+$"),
    ] = None,
) -> list[AuditEventResponse]:
    """Return a sequence-ordered, filterable, redacted administrative timeline."""

    del administrator
    events = await service.timeline(
        after_sequence=after_sequence,
        limit=limit,
        correlation_id=correlation_id,
        task_id=task_id,
        tool_request_id=tool_request_id,
        event_type=event_type,
    )
    return [AuditEventResponse.model_validate(event, from_attributes=True) for event in events]


@router.post("/verify", response_model=AuditVerificationResponse)
async def verify_audit_integrity(
    administrator: Annotated[AdminPrincipal, Depends(require_admin)],
    service: Annotated[AuditService, Depends(get_audit_service)],
) -> AuditVerificationResponse:
    """Verify all database links and the external checkpoint without mutation."""

    del administrator
    result = await service.verify()
    return AuditVerificationResponse(
        valid=result.valid,
        reason_code=result.reason_code,
        event_count=result.event_count,
        verified_sequence=result.verified_sequence,
        chain_id=result.chain_id,
        head_hash=result.head_hash,
        failure_sequence=result.failure_sequence,
    )
