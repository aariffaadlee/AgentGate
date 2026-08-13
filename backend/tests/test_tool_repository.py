"""Persistence boundary tests for manifest drift and atomic rate-window statements."""

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from app.db.tools import (
    SQLAlchemyToolRequestRepository,
    ToolManifestMismatchError,
    _registry_row,
    verify_or_install_tool_manifest,
)
from app.models.provenance import ProvenanceRecord, ToolRequestInfluence
from app.models.tool import ToolRequest
from app.tools.registry import STATIC_TOOL_REGISTRY


class _Scalars:
    def __init__(self, rows: list[object]) -> None:
        self._rows = rows

    def all(self) -> list[object]:
        return self._rows


class _Result:
    def __init__(self, *, rows: list[object] | None = None, scalar: object = None) -> None:
        self._rows = rows or []
        self._scalar = scalar

    def scalars(self) -> _Scalars:
        return _Scalars(self._rows)

    def scalar_one_or_none(self):
        return self._scalar


class _ManifestSession:
    def __init__(self, rows: list[object]) -> None:
        self.rows = rows
        self.added: list[object] = []
        self.commits = 0

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args: object) -> None:
        return None

    async def execute(self, _statement: object) -> _Result:
        return _Result(rows=self.rows)

    def add_all(self, values) -> None:
        self.added.extend(values)

    async def commit(self) -> None:
        self.commits += 1


class _ManifestFactory:
    def __init__(self, session: _ManifestSession) -> None:
        self.session = session

    def __call__(self) -> _ManifestSession:
        return self.session


async def test_empty_manifest_mirror_is_installed_once() -> None:
    session = _ManifestSession([])

    await verify_or_install_tool_manifest(_ManifestFactory(session), STATIC_TOOL_REGISTRY)  # type: ignore[arg-type]

    assert len(session.added) == 7
    assert session.commits == 1
    assert {row.name for row in session.added} == {
        definition.name for definition in STATIC_TOOL_REGISTRY
    }


async def test_exact_manifest_passes_and_any_drift_fails_startup() -> None:
    rows = [_registry_row(definition, STATIC_TOOL_REGISTRY) for definition in STATIC_TOOL_REGISTRY]
    exact = _ManifestSession(rows)
    await verify_or_install_tool_manifest(_ManifestFactory(exact), STATIC_TOOL_REGISTRY)  # type: ignore[arg-type]
    assert exact.commits == 0

    rows[0].enabled = False
    with pytest.raises(ToolManifestMismatchError, match="metadata"):
        await verify_or_install_tool_manifest(  # type: ignore[arg-type]
            _ManifestFactory(_ManifestSession(rows)),
            STATIC_TOOL_REGISTRY,
        )

    with pytest.raises(ToolManifestMismatchError, match="names"):
        await verify_or_install_tool_manifest(  # type: ignore[arg-type]
            _ManifestFactory(_ManifestSession(rows[:-1])),
            STATIC_TOOL_REGISTRY,
        )


async def test_sql_repository_returns_registry_row_and_atomic_rate_result() -> None:
    definition = next(iter(STATIC_TOOL_REGISTRY))
    row = _registry_row(definition, STATIC_TOOL_REGISTRY)
    session = MagicMock()
    session.execute = AsyncMock(side_effect=[_Result(scalar=row), _Result(scalar=3)])
    session.commit = AsyncMock()
    repository = SQLAlchemyToolRequestRepository(session)

    assert await repository.get_registry_tool(definition.name) is row
    now = datetime(2026, 8, 13, 10, 5, 37, tzinfo=UTC)
    rate = await repository.consume_rate_limit(
        agent_id=uuid4(),
        task_id=uuid4(),
        tool_name=definition.name,
        now=now,
        limit=5,
        window_seconds=60,
    )

    assert rate.allowed is True
    assert rate.request_count == 3
    assert rate.window_started_at == datetime(2026, 8, 13, 10, 5, tzinfo=UTC)
    session.commit.assert_awaited_once()


async def test_sql_repository_reports_limit_without_increment_return() -> None:
    session = MagicMock()
    session.execute = AsyncMock(return_value=_Result(scalar=None))
    session.commit = AsyncMock()
    repository = SQLAlchemyToolRequestRepository(session)

    result = await repository.consume_rate_limit(
        agent_id=uuid4(),
        task_id=uuid4(),
        tool_name="documents.search",
        now=datetime.now(UTC),
        limit=2,
        window_seconds=60,
    )

    assert result.allowed is False
    assert result.request_count == 2


async def test_tool_request_parent_is_flushed_before_influence_rows() -> None:
    session = MagicMock()
    events: list[tuple[str, object]] = []
    session.add.side_effect = lambda value: events.append(("add", value))

    async def record_flush() -> None:
        events.append(("flush", None))

    def record_add_all(values: object) -> None:
        events.append(("add_all", list(values)))  # type: ignore[arg-type]

    session.flush = AsyncMock(side_effect=record_flush)
    session.add_all.side_effect = record_add_all
    session.commit = AsyncMock()
    session.refresh = AsyncMock()
    repository = SQLAlchemyToolRequestRepository(session)
    request = ToolRequest(id=uuid4())
    influence = ProvenanceRecord(id=uuid4())

    await repository.create_tool_request(request, [influence])

    assert events[0] == ("add", request)
    assert events[1] == ("flush", None)
    assert events[2][0] == "add_all"
    children = events[2][1]
    assert isinstance(children, list)
    assert len(children) == 1
    assert isinstance(children[0], ToolRequestInfluence)
    assert children[0].tool_request_id == request.id
    assert children[0].provenance_record_id == influence.id
    session.flush.assert_awaited_once()
    session.commit.assert_awaited_once()
    session.refresh.assert_awaited_once_with(request)
