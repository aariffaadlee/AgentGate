"""Stable error-envelope and exception-leakage tests."""

import httpx
from fastapi import FastAPI

from app.api.errors import AgentGateError
from tests.support import app_client


async def test_unknown_route_uses_safe_error_envelope(client: httpx.AsyncClient) -> None:
    response = await client.get("/does-not-exist?secret=do-not-reflect")

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "NOT_FOUND"
    assert "do-not-reflect" not in response.text
    assert response.json()["error"]["request_id"] == response.headers["x-request-id"]


async def test_expected_application_error_uses_declared_safe_message(
    application: FastAPI,
) -> None:
    @application.get("/expected-error")
    async def expected_error() -> None:
        raise AgentGateError(409, "STATE_CONFLICT", "The requested state transition is invalid.")

    async with app_client(application) as client:
        response = await client.get("/expected-error")

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "STATE_CONFLICT"
    assert response.json()["error"]["message"] == "The requested state transition is invalid."


async def test_unexpected_exception_does_not_leak_message(application: FastAPI) -> None:
    @application.get("/unexpected-error")
    async def unexpected_error() -> None:
        raise RuntimeError("password=super-secret internal host=db.internal")

    async with app_client(application) as client:
        response = await client.get("/unexpected-error")

    assert response.status_code == 500
    assert response.json()["error"]["code"] == "INTERNAL_ERROR"
    assert "super-secret" not in response.text
    assert "db.internal" not in response.text


async def test_validation_error_does_not_reflect_invalid_value(application: FastAPI) -> None:
    @application.get("/integer")
    async def integer(value: int) -> dict[str, int]:
        return {"value": value}

    async with app_client(application) as client:
        response = await client.get("/integer", params={"value": "secret-invalid-input"})

    assert response.status_code == 422
    body = response.json()["error"]
    assert body["code"] == "VALIDATION_ERROR"
    assert body["fields"] == [{"path": "query.value", "error_type": "int_parsing"}]
    assert "secret-invalid-input" not in response.text
