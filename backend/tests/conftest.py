"""Shared Phase 1 test fixtures."""

from collections.abc import AsyncIterator

import httpx
import pytest
from fastapi import FastAPI

from app.api.health import database_is_ready, policy_is_ready
from app.config import Environment, Settings
from app.main import create_app
from tests.support import app_client


@pytest.fixture
def settings() -> Settings:
    """Return isolated test configuration without reading a developer's .env."""

    return Settings(
        _env_file=None,
        environment=Environment.TEST,
        database_url="postgresql+asyncpg://agentgate:test-only@127.0.0.1:5432/agentgate_test",
        cors_allowed_origins=["http://localhost:5173"],
        database_pool_timeout_seconds=0.1,
        database_health_timeout_seconds=0.1,
        max_request_body_bytes=1_024,
        docs_enabled=False,
        log_level="WARNING",
    )


@pytest.fixture
def application(settings: Settings) -> FastAPI:
    """Build a fresh application and engine for each test."""

    return create_app(settings)


@pytest.fixture
async def client(application: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    """Provide a client whose dependency readiness is deterministic."""

    async def database_up() -> bool:
        return True

    async def policy_up() -> bool:
        return True

    application.dependency_overrides[database_is_ready] = database_up
    application.dependency_overrides[policy_is_ready] = policy_up
    async with app_client(application) as test_client:
        yield test_client
