"""Liveness and readiness behavior tests."""

from uuid import UUID

import httpx
from fastapi import FastAPI

from app.api.health import database_is_ready, policy_is_ready
from tests.support import app_client


async def test_liveness_is_minimal_and_has_security_headers(client: httpx.AsyncClient) -> None:
    response = await client.get("/health/live")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "dependencies": {}}
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["content-security-policy"].startswith("default-src 'none'")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    UUID(response.headers["x-request-id"])
    assert "version" not in response.text.lower()


async def test_required_health_endpoint_reports_database_up(client: httpx.AsyncClient) -> None:
    response = await client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "dependencies": {"database": "up", "policy": "up"},
    }


async def test_readiness_fails_when_database_is_down(application: FastAPI) -> None:
    async def database_down() -> bool:
        return False

    async def policy_up() -> bool:
        return True

    application.dependency_overrides[database_is_ready] = database_down
    application.dependency_overrides[policy_is_ready] = policy_up
    async with app_client(application) as client:
        response = await client.get("/health/ready")

    assert response.status_code == 503
    assert response.json() == {
        "status": "degraded",
        "dependencies": {"database": "down", "policy": "up"},
    }


async def test_readiness_fails_closed_when_policy_is_down(application: FastAPI) -> None:
    async def database_up() -> bool:
        return True

    async def policy_down() -> bool:
        return False

    application.dependency_overrides[database_is_ready] = database_up
    application.dependency_overrides[policy_is_ready] = policy_down
    async with app_client(application) as client:
        response = await client.get("/health/ready")

    assert response.status_code == 503
    assert response.json() == {
        "status": "degraded",
        "dependencies": {"database": "up", "policy": "down"},
    }


async def test_valid_caller_request_id_is_preserved(client: httpx.AsyncClient) -> None:
    request_id = "7c7d8f9e-6caf-4e38-bf8e-71a43c5f36a3"
    response = await client.get("/health/live", headers={"X-Request-ID": request_id})

    assert response.headers["x-request-id"] == request_id


async def test_invalid_caller_request_id_is_replaced(client: httpx.AsyncClient) -> None:
    response = await client.get(
        "/health/live",
        headers={"X-Request-ID": "log\ninjection"},
    )

    UUID(response.headers["x-request-id"])
    assert response.headers["x-request-id"] != "log\ninjection"
