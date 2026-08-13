"""Database lifecycle tests that do not require a running PostgreSQL instance."""

from types import SimpleNamespace
from typing import Any, cast

import pytest
from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncEngine

from app.db.session import Database, get_database, get_session


class FakeConnection:
    """Record readiness statements executed through an async context manager."""

    def __init__(self) -> None:
        self.statements: list[str] = []

    async def __aenter__(self) -> "FakeConnection":
        return self

    async def __aexit__(self, *_: object) -> None:
        return None

    async def execute(self, statement: object) -> None:
        self.statements.append(str(statement))


class FakeEngine:
    """Provide the engine operations used by the database facade."""

    def __init__(self, connection: FakeConnection | None = None) -> None:
        self.connection = connection or FakeConnection()
        self.disposed = False

    def connect(self) -> FakeConnection:
        return self.connection

    async def dispose(self) -> None:
        self.disposed = True


class FailingEngine:
    """Simulate a connection failure without leaking its details."""

    def connect(self) -> None:
        raise RuntimeError("sensitive connection failure")


class FakeSessionContext:
    """Track request-scoped session entry and cleanup."""

    def __init__(self, session: object) -> None:
        self.session = session
        self.closed = False

    async def __aenter__(self) -> object:
        return self.session

    async def __aexit__(self, *_: object) -> None:
        self.closed = True


def database_with_engine(engine: object) -> Database:
    """Build the facade around a fake engine without allocating a real pool."""

    database = object.__new__(Database)
    database._health_timeout_seconds = 0.1
    database.engine = cast(AsyncEngine, engine)
    return database


@pytest.mark.asyncio
async def test_database_ping_executes_minimal_readiness_query() -> None:
    engine = FakeEngine()
    database = database_with_engine(engine)

    assert await database.ping() is True
    assert engine.connection.statements == ["SELECT 1"]


@pytest.mark.asyncio
async def test_database_ping_converts_internal_failure_to_not_ready() -> None:
    database = database_with_engine(FailingEngine())

    assert await database.ping() is False


@pytest.mark.asyncio
async def test_database_dispose_closes_engine_pool() -> None:
    engine = FakeEngine()
    database = database_with_engine(engine)

    await database.dispose()

    assert engine.disposed is True


@pytest.mark.asyncio
async def test_database_dependency_returns_application_facade() -> None:
    expected = database_with_engine(FakeEngine())
    request = cast(
        Request,
        SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(database=expected))),
    )

    assert await get_database(request) is expected


@pytest.mark.asyncio
async def test_session_dependency_closes_request_scoped_session() -> None:
    expected_session = object()
    session_context = FakeSessionContext(expected_session)
    database = SimpleNamespace(session_factory=lambda: session_context)
    request = cast(
        Request,
        SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(database=database))),
    )

    iterator = get_session(request)
    session = await anext(iterator)

    assert cast(Any, session) is expected_session
    with pytest.raises(StopAsyncIteration):
        await anext(iterator)
    assert session_context.closed is True
