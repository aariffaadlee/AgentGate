"""Alembic revision and optional live PostgreSQL migration tests."""

import asyncio
import os
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import inspect
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import create_async_engine

BACKEND_ROOT = Path(__file__).resolve().parents[2]
EXPECTED_TABLES = {
    "administrators",
    "agent_credentials",
    "agents",
    "approval_actions",
    "approval_requests",
    "audit_events",
    "evaluation_results",
    "evaluation_runs",
    "policy_decisions",
    "provenance_records",
    "request_proofs",
    "revocations",
    "task_capabilities",
    "tasks",
    "tool_registry",
    "tool_rate_limit_windows",
    "tool_requests",
    "tool_request_influences",
}


def alembic_config(database_url: str) -> Config:
    config = Config(str(BACKEND_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_ROOT / "migrations"))
    config.attributes["database_url"] = database_url
    return config


def test_migration_history_has_one_head() -> None:
    script = ScriptDirectory.from_config(
        alembic_config("postgresql+asyncpg://agentgate:test-only@localhost/agentgate_test")
    )

    assert script.get_heads() == ["0006_evaluation_evidence"]


def test_initial_migration_renders_all_required_tables_offline(capsys: object) -> None:
    config = alembic_config(
        "postgresql+asyncpg://agentgate:test-only@localhost:5432/agentgate_test"
    )

    command.upgrade(config, "head", sql=True)

    captured = capsys.readouterr()  # type: ignore[attr-defined]
    rendered_sql = captured.out.lower()
    for table_name in EXPECTED_TABLES:
        assert f"create table {table_name}" in rendered_sql
    assert "drop table" not in rendered_sql


def test_migration_history_renders_complete_downgrade_offline(capsys: object) -> None:
    config = alembic_config(
        "postgresql+asyncpg://agentgate:test-only@localhost:5432/agentgate_test"
    )

    command.downgrade(config, "head:base", sql=True)

    captured = capsys.readouterr()  # type: ignore[attr-defined]
    rendered_sql = captured.out.lower()
    for table_name in EXPECTED_TABLES:
        assert f"drop table {table_name}" in rendered_sql
    assert "drop column assigned_agent_id" in rendered_sql
    assert rendered_sql.index("drop table evaluation_results") < rendered_sql.index(
        "drop table evaluation_runs"
    )


def test_initial_migration_upgrades_disposable_postgresql() -> None:
    database_url = os.getenv("AGENTGATE_TEST_DATABASE_URL")
    if not database_url:
        pytest.skip("AGENTGATE_TEST_DATABASE_URL is not configured")

    parsed_url = make_url(database_url)
    if parsed_url.drivername != "postgresql+asyncpg" or "test" not in (parsed_url.database or ""):
        pytest.fail("AGENTGATE_TEST_DATABASE_URL must use asyncpg and a database containing 'test'")

    command.upgrade(alembic_config(database_url), "head")

    async def read_table_names() -> set[str]:
        engine = create_async_engine(database_url)
        try:
            async with engine.connect() as connection:
                names = await connection.run_sync(lambda sync: inspect(sync).get_table_names())
            return set(names)
        finally:
            await engine.dispose()

    table_names = asyncio.run(read_table_names())
    assert EXPECTED_TABLES.issubset(table_names)
