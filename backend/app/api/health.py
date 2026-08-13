"""Minimal liveness and dependency-aware readiness endpoints."""

from enum import StrEnum
from typing import Annotated, cast

from fastapi import APIRouter, Depends, Request, Response, status
from pydantic import BaseModel, ConfigDict

from app.db.session import Database, get_database
from app.policies.client import PolicyClient

router = APIRouter(tags=["operations"])


class ServiceStatus(StrEnum):
    OK = "ok"
    DEGRADED = "degraded"


class DependencyStatus(StrEnum):
    UP = "up"
    DOWN = "down"


class HealthResponse(BaseModel):
    """Health data intentionally excludes versions and connection details."""

    model_config = ConfigDict(extra="forbid")

    status: ServiceStatus
    dependencies: dict[str, DependencyStatus]


async def database_is_ready(database: Annotated[Database, Depends(get_database)]) -> bool:
    """Dependency wrapper that tests can replace without patching internals."""

    return await database.ping()


async def get_policy_client(request: Request) -> PolicyClient:
    """Resolve the application-owned OPA client."""

    return cast(PolicyClient, request.app.state.policy_client)


async def policy_is_ready(
    policy_client: Annotated[PolicyClient, Depends(get_policy_client)],
) -> bool:
    """Dependency wrapper that tests can replace without network access."""

    return await policy_client.is_ready()


@router.get("/health/live", response_model=HealthResponse)
async def liveness() -> HealthResponse:
    """Report process liveness without requiring downstream dependencies."""

    return HealthResponse(status=ServiceStatus.OK, dependencies={})


async def _readiness_response(
    database_ready: bool,
    policy_ready: bool,
    response: Response,
) -> HealthResponse:
    dependencies = {
        "database": DependencyStatus.UP if database_ready else DependencyStatus.DOWN,
        "policy": DependencyStatus.UP if policy_ready else DependencyStatus.DOWN,
    }
    if not database_ready or not policy_ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return HealthResponse(
            status=ServiceStatus.DEGRADED,
            dependencies=dependencies,
        )
    return HealthResponse(status=ServiceStatus.OK, dependencies=dependencies)


@router.get("/health", response_model=HealthResponse)
async def health(
    response: Response,
    database_ready: Annotated[bool, Depends(database_is_ready)],
    policy_ready: Annotated[bool, Depends(policy_is_ready)],
) -> HealthResponse:
    """Required health endpoint with PostgreSQL and OPA readiness."""

    return await _readiness_response(database_ready, policy_ready, response)


@router.get("/health/ready", response_model=HealthResponse)
async def readiness(
    response: Response,
    database_ready: Annotated[bool, Depends(database_is_ready)],
    policy_ready: Annotated[bool, Depends(policy_is_ready)],
) -> HealthResponse:
    """Container readiness alias."""

    return await _readiness_response(database_ready, policy_ready, response)
