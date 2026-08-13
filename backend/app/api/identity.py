"""Strict administrative and workload identity REST endpoints."""

import re
from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Request, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    field_validator,
    model_validator,
)
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.audit_dependencies import get_audit_service
from app.api.errors import AgentGateError, request_id_from
from app.auth.crypto import Ed25519PublicJWK
from app.db.identity import SQLAlchemyIdentityRepository
from app.db.session import get_session
from app.models.enums import AgentStatus, AuditActorType, TaskStatus
from app.models.identity import Agent
from app.models.task import Task
from app.services.audit import AuditEventDraft, AuditService
from app.services.identity import (
    AdminPrincipal,
    IdentityService,
    TaskCreation,
)

router = APIRouter(tags=["identity"])
bearer_scheme = HTTPBearer(auto_error=False)


class AdminSessionRequest(BaseModel):
    """One-time bootstrap exchange; the secret is never returned."""

    model_config = ConfigDict(extra="forbid")

    bootstrap_secret: SecretStr = Field(min_length=32, max_length=512)


class AccessTokenResponse(BaseModel):
    """An encoded token is returned once and never stored by AgentGate."""

    model_config = ConfigDict(extra="forbid")

    access_token: str
    token_type: Literal["Bearer"] = "Bearer"
    expires_in: int
    expires_at: datetime


class AgentCreateRequest(BaseModel):
    """Administrator-controlled workload registration."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(
        min_length=3,
        max_length=120,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9 ._-]*$",
    )
    public_jwk: Ed25519PublicJWK


class AgentResponse(BaseModel):
    """Sanitized identity view without a complete key or credential."""

    model_config = ConfigDict(extra="forbid")

    id: UUID
    name: str
    status: AgentStatus
    key_thumbprint: str
    created_at: datetime
    revoked_at: datetime | None


class AgentTokenRequest(BaseModel):
    """A task selection only; capabilities are loaded from persisted grants."""

    model_config = ConfigDict(extra="forbid")

    task_id: UUID


class WorkloadTokenResponse(AccessTokenResponse):
    """One-time workload credential metadata."""

    agent_id: UUID
    task_id: UUID
    capabilities: list[str]


class TaskCreateRequest(BaseModel):
    """Administrator-owned task intent with exact non-wildcard capabilities."""

    model_config = ConfigDict(extra="forbid")

    assigned_agent_id: UUID
    title: str = Field(min_length=3, max_length=160)
    trusted_instruction_summary: str = Field(min_length=3, max_length=500)
    trusted_instruction: SecretStr = Field(min_length=1, max_length=10_000)
    capabilities: list[str] = Field(min_length=1, max_length=32)
    starts_at: datetime | None = None
    expires_at: datetime | None = None

    @field_validator("capabilities")
    @classmethod
    def validate_capabilities(cls, values: list[str]) -> list[str]:
        pattern = r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$"
        if len(values) != len(set(values)):
            raise ValueError("capabilities must be unique")
        if any(re.fullmatch(pattern, value) is None or len(value) > 120 for value in values):
            raise ValueError("capabilities must be exact names without wildcards")
        return values

    @model_validator(mode="after")
    def validate_schedule(self) -> "TaskCreateRequest":
        for value in (self.starts_at, self.expires_at):
            if value is not None and value.tzinfo is None:
                raise ValueError("task timestamps must include a timezone")
        if (
            self.starts_at is not None
            and self.expires_at is not None
            and self.expires_at <= self.starts_at
        ):
            raise ValueError("task expiry must be after its start")
        return self


class TaskResponse(BaseModel):
    """Task view excludes the encrypted full instruction."""

    model_config = ConfigDict(extra="forbid")

    id: UUID
    owner_admin_id: UUID
    assigned_agent_id: UUID
    title: str
    trusted_instruction_summary: str
    trusted_instruction_hash: str
    status: TaskStatus
    capabilities: list[str]
    starts_at: datetime | None
    expires_at: datetime | None
    created_at: datetime
    trusted_intent_provenance_id: UUID


class RevokeAgentRequest(BaseModel):
    """Append-only revocation metadata supplied by an administrator."""

    model_config = ConfigDict(extra="forbid")

    reason_code: str = Field(
        min_length=3,
        max_length=80,
        pattern=r"^[A-Z][A-Z0-9_]*$",
    )
    reason: str | None = Field(default=None, max_length=500)


async def get_identity_service(
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> IdentityService:
    """Construct a request-scoped identity service over one database session."""

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


async def require_admin(
    service: Annotated[IdentityService, Depends(get_identity_service)],
    credentials: Annotated[HTTPAuthorizationCredentials | None, Security(bearer_scheme)],
) -> AdminPrincipal:
    """Authenticate only the administrator audience."""

    return await service.authenticate_admin(_encoded_bearer(credentials))


@router.post("/admin/session", response_model=AccessTokenResponse)
async def create_admin_session(
    body: AdminSessionRequest,
    request: Request,
    service: Annotated[IdentityService, Depends(get_identity_service)],
    audit: Annotated[AuditService, Depends(get_audit_service)],
) -> AccessTokenResponse:
    """Create a short local admin session from the configured bootstrap secret."""

    token = await service.create_admin_session(body.bootstrap_secret.get_secret_value())
    administrator = await service.authenticate_admin(token.encoded)
    await audit.append(
        AuditEventDraft(
            event_type="identity.admin_session_issued",
            correlation_id=_correlation_id(request),
            actor_type=AuditActorType.ADMINISTRATOR,
            actor_id=administrator.administrator.id,
            payload={"expires_at": token.expires_at.isoformat()},
        )
    )
    return AccessTokenResponse(
        access_token=token.encoded,
        expires_in=int((token.expires_at - token.issued_at).total_seconds()),
        expires_at=token.expires_at,
    )


@router.post("/agents", response_model=AgentResponse, status_code=status.HTTP_201_CREATED)
async def register_agent(
    body: AgentCreateRequest,
    request: Request,
    administrator: Annotated[AdminPrincipal, Depends(require_admin)],
    service: Annotated[IdentityService, Depends(get_identity_service)],
    audit: Annotated[AuditService, Depends(get_audit_service)],
) -> AgentResponse:
    """Register a public workload key through the administrative plane."""

    agent = await service.register_agent(name=body.name, public_jwk=body.public_jwk)
    await audit.append(
        AuditEventDraft(
            event_type="identity.agent_registered",
            correlation_id=_correlation_id(request),
            actor_type=AuditActorType.ADMINISTRATOR,
            actor_id=administrator.administrator.id,
            payload={
                "agent_id": str(agent.id),
                "name": agent.name,
                "status": agent.status.value,
                "key_thumbprint": agent.key_thumbprint,
            },
        )
    )
    return _agent_response(agent)


@router.get("/agents", response_model=list[AgentResponse])
async def list_agents(
    administrator: Annotated[AdminPrincipal, Depends(require_admin)],
    service: Annotated[IdentityService, Depends(get_identity_service)],
) -> list[AgentResponse]:
    """List sanitized workload identity state for administrators."""

    del administrator
    return [_agent_response(agent) for agent in await service.list_agents()]


@router.post("/tasks", response_model=TaskResponse, status_code=status.HTTP_201_CREATED)
async def create_task(
    body: TaskCreateRequest,
    request: Request,
    administrator: Annotated[AdminPrincipal, Depends(require_admin)],
    service: Annotated[IdentityService, Depends(get_identity_service)],
    audit: Annotated[AuditService, Depends(get_audit_service)],
) -> TaskResponse:
    """Create an agent-assigned task with server-authoritative capability grants."""

    task, capabilities = await service.create_task(
        owner_admin_id=administrator.administrator.id,
        creation=TaskCreation(
            assigned_agent_id=body.assigned_agent_id,
            title=body.title,
            trusted_instruction_summary=body.trusted_instruction_summary,
            trusted_instruction=body.trusted_instruction.get_secret_value(),
            capabilities=body.capabilities,
            starts_at=body.starts_at,
            expires_at=body.expires_at,
        ),
    )
    provenance = await service.get_task_intent_provenance(task.id)
    await audit.append(
        AuditEventDraft(
            event_type="task.created",
            correlation_id=_correlation_id(request),
            actor_type=AuditActorType.ADMINISTRATOR,
            actor_id=administrator.administrator.id,
            task_id=task.id,
            payload={
                "assigned_agent_id": str(task.assigned_agent_id),
                "trusted_instruction_hash": task.trusted_instruction_hash,
                "capabilities": capabilities,
                "trusted_intent_provenance_id": str(provenance.id),
            },
        )
    )
    return _task_response(task, capabilities, provenance.id)


@router.get("/tasks", response_model=list[TaskResponse])
async def list_tasks(
    administrator: Annotated[AdminPrincipal, Depends(require_admin)],
    service: Annotated[IdentityService, Depends(get_identity_service)],
) -> list[TaskResponse]:
    """List sanitized tasks and exact capability grants for administrators."""

    del administrator
    responses: list[TaskResponse] = []
    for task, capabilities in await service.list_tasks():
        provenance = await service.get_task_intent_provenance(task.id)
        responses.append(_task_response(task, capabilities, provenance.id))
    return responses


@router.post(
    "/agents/{agent_id}/tokens",
    response_model=WorkloadTokenResponse,
    status_code=status.HTTP_201_CREATED,
)
async def issue_agent_token(
    agent_id: UUID,
    body: AgentTokenRequest,
    request: Request,
    service: Annotated[IdentityService, Depends(get_identity_service)],
    audit: Annotated[AuditService, Depends(get_audit_service)],
    proof: Annotated[str | None, Header(alias="X-Agent-Proof")] = None,
) -> WorkloadTokenResponse:
    """Issue a token only after fresh workload-key proof and task assignment checks."""

    result = await service.issue_agent_token(
        agent_id=agent_id,
        task_id=body.task_id,
        proof=_encoded_proof(proof),
        proof_body=body.model_dump(mode="json"),
        method="POST",
        path=f"/agents/{agent_id}/tokens",
    )
    token = result.token
    await audit.append(
        AuditEventDraft(
            event_type="identity.credential_issued",
            correlation_id=_correlation_id(request),
            actor_type=AuditActorType.AGENT,
            actor_id=agent_id,
            task_id=body.task_id,
            payload={
                "agent_id": str(agent_id),
                "capabilities": result.capabilities,
                "expires_at": token.expires_at.isoformat(),
            },
        )
    )
    return WorkloadTokenResponse(
        access_token=token.encoded,
        expires_in=int((token.expires_at - token.issued_at).total_seconds()),
        expires_at=token.expires_at,
        agent_id=agent_id,
        task_id=body.task_id,
        capabilities=result.capabilities,
    )


@router.get("/tasks/{task_id}", response_model=TaskResponse)
async def get_task(
    task_id: UUID,
    request: Request,
    service: Annotated[IdentityService, Depends(get_identity_service)],
    credentials: Annotated[HTTPAuthorizationCredentials | None, Security(bearer_scheme)],
    proof: Annotated[
        str | None,
        Header(alias="X-Agent-Proof"),
    ] = None,
) -> TaskResponse:
    """Allow administrators or a proof-bound token for the exact assigned task."""

    encoded = _encoded_bearer(credentials)
    if proof is None:
        await service.authenticate_admin(encoded)
    else:
        await service.authenticate_agent_request(
            encoded_token=encoded,
            proof=_encoded_proof(proof),
            method=request.method,
            path=request.url.path,
            body={},
            required_task_id=task_id,
        )
    task, capabilities = await service.get_task(task_id)
    provenance = await service.get_task_intent_provenance(task.id)
    return _task_response(task, capabilities, provenance.id)


@router.post("/agents/{agent_id}/revoke", response_model=AgentResponse)
async def revoke_agent(
    agent_id: UUID,
    body: RevokeAgentRequest,
    request: Request,
    administrator: Annotated[AdminPrincipal, Depends(require_admin)],
    service: Annotated[IdentityService, Depends(get_identity_service)],
    audit: Annotated[AuditService, Depends(get_audit_service)],
) -> AgentResponse:
    """Revoke the identity and every active token while retaining history."""

    agent = await service.revoke_agent(
        agent_id=agent_id,
        administrator_id=administrator.administrator.id,
        reason_code=body.reason_code,
        reason=body.reason,
    )
    await audit.append(
        AuditEventDraft(
            event_type="identity.agent_revoked",
            correlation_id=_correlation_id(request),
            actor_type=AuditActorType.ADMINISTRATOR,
            actor_id=administrator.administrator.id,
            payload={
                "agent_id": str(agent.id),
                "status": agent.status.value,
                "reason_code": body.reason_code,
                "reason_present": body.reason is not None,
            },
        )
    )
    return _agent_response(agent)


def _agent_response(agent: Agent) -> AgentResponse:
    return AgentResponse(
        id=agent.id,
        name=agent.name,
        status=agent.status,
        key_thumbprint=agent.key_thumbprint,
        created_at=agent.created_at,
        revoked_at=agent.revoked_at,
    )


def _correlation_id(request: Request) -> UUID:
    return UUID(request_id_from(request))


def _task_response(
    task: Task,
    capabilities: list[str],
    trusted_intent_provenance_id: UUID,
) -> TaskResponse:
    if task.assigned_agent_id is None:
        raise AgentGateError(
            status.HTTP_409_CONFLICT,
            "TASK_UNASSIGNED",
            "The task has no assigned workload identity.",
        )
    return TaskResponse(
        id=task.id,
        owner_admin_id=task.owner_admin_id,
        assigned_agent_id=task.assigned_agent_id,
        title=task.title,
        trusted_instruction_summary=task.trusted_instruction_summary,
        trusted_instruction_hash=task.trusted_instruction_hash,
        status=task.status,
        capabilities=capabilities,
        starts_at=task.starts_at,
        expires_at=task.expires_at,
        created_at=task.created_at,
        trusted_intent_provenance_id=trusted_intent_provenance_id,
    )
