"""Normalized schema invariants independent of a live database."""

from sqlalchemy import CheckConstraint
from sqlalchemy.dialects.postgresql import JSONB

from app import models as _models  # noqa: F401
from app.db.base import Base

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
    "tool_request_influences",
    "tool_rate_limit_windows",
    "tool_requests",
}


def test_all_required_normalized_tables_are_registered() -> None:
    assert set(Base.metadata.tables) == EXPECTED_TABLES
    assert all(table.primary_key.columns for table in Base.metadata.tables.values())


def test_encoded_bearer_tokens_have_no_persistence_column() -> None:
    credential_columns = set(Base.metadata.tables["agent_credentials"].columns.keys())

    assert "token" not in credential_columns
    assert "bearer_token" not in credential_columns
    assert "encoded_token" not in credential_columns
    assert {"jti_hash", "key_thumbprint", "expires_at"}.issubset(credential_columns)


def test_unknown_tool_requests_can_be_recorded_without_registry_foreign_key() -> None:
    tool_requests = Base.metadata.tables["tool_requests"]

    assert tool_requests.c.tool_name.nullable is False
    assert tool_requests.c.tool_registry_id.nullable is True
    assert isinstance(tool_requests.c.redacted_arguments.type, JSONB)
    assert tool_requests.c.arguments_ciphertext.nullable is True


def test_task_capability_schema_forbids_wildcards() -> None:
    constraints = Base.metadata.tables["task_capabilities"].constraints
    check_sql = " ".join(
        str(constraint.sqltext)
        for constraint in constraints
        if isinstance(constraint, CheckConstraint)
    )

    assert "position('*' in capability) = 0" in check_sql


def test_task_assignment_is_an_indexed_agent_foreign_key() -> None:
    tasks = Base.metadata.tables["tasks"]

    assert tasks.c.assigned_agent_id.nullable is True
    assert tasks.c.assigned_agent_id.index is True
    assert any(
        foreign_key.target_fullname == "agents.id"
        for foreign_key in tasks.c.assigned_agent_id.foreign_keys
    )


def test_security_timestamps_are_timezone_aware() -> None:
    for table_name, column_name in (
        ("agents", "created_at"),
        ("agent_credentials", "expires_at"),
        ("approval_requests", "expires_at"),
        ("audit_events", "occurred_at"),
    ):
        assert Base.metadata.tables[table_name].columns[column_name].type.timezone is True


def test_approval_and_proof_replay_fields_are_unique() -> None:
    proof_table = Base.metadata.tables["request_proofs"]
    approval_table = Base.metadata.tables["approval_requests"]

    assert proof_table.c.proof_jti_hash.unique is True
    assert any(
        {column.name for column in constraint.columns} == {"tool_request_id"}
        for constraint in approval_table.constraints
        if hasattr(constraint, "columns")
    )


def test_rate_limit_window_has_atomic_scope_constraint() -> None:
    table = Base.metadata.tables["tool_rate_limit_windows"]

    assert {"agent_id", "task_id", "tool_name", "window_started_at"} == {
        column.name
        for constraint in table.constraints
        if getattr(constraint, "name", None) == "uq_tool_rate_limit_scope_window"
        for column in constraint.columns
    }


def test_provenance_schema_enforces_authoritative_integrity() -> None:
    records = Base.metadata.tables["provenance_records"]
    influences = Base.metadata.tables["tool_request_influences"]
    check_sql = " ".join(
        str(constraint.sqltext)
        for constraint in records.constraints
        if isinstance(constraint, CheckConstraint)
    )

    assert "parent_id IS NULL OR parent_id <> id" in check_sql
    assert "created_by_agent_id IS NULL OR created_by_admin_id IS NULL" in check_sql
    assert "content_hash ~ '^sha256:[0-9a-f]{64}$'" in check_sql
    assert any(
        {column.name for column in constraint.columns}
        == {"tool_request_id", "provenance_record_id"}
        for constraint in influences.constraints
        if hasattr(constraint, "columns")
    )


def test_audit_schema_enforces_canonical_chain_records() -> None:
    constraints = Base.metadata.tables["audit_events"].constraints
    check_sql = " ".join(
        str(constraint.sqltext)
        for constraint in constraints
        if isinstance(constraint, CheckConstraint)
    )

    assert "sequence > 0" in check_sql
    assert "previous_hash ~ '^[0-9a-f]{64}$'" in check_sql
    assert "event_hash ~ '^[0-9a-f]{64}$'" in check_sql
    assert "jsonb_typeof(payload) = 'object'" in check_sql
    assert "actor_type = 'SYSTEM' AND actor_id IS NULL" in check_sql


def test_evaluation_schema_retains_recomputable_measurement_evidence() -> None:
    runs = Base.metadata.tables["evaluation_runs"]
    results = Base.metadata.tables["evaluation_results"]
    run_checks = " ".join(
        str(constraint.sqltext)
        for constraint in runs.constraints
        if isinstance(constraint, CheckConstraint)
    )
    result_checks = " ".join(
        str(constraint.sqltext)
        for constraint in results.constraints
        if isinstance(constraint, CheckConstraint)
    )

    assert "scenario_set_hash ~ '^sha256:[0-9a-f]{64}$'" in run_checks
    assert "configuration_hash ~ '^sha256:[0-9a-f]{64}$'" in run_checks
    assert "policy_latency_ms >= 0" in result_checks
    assert {
        "scenario_kind",
        "expected_reason_code",
        "policy_latency_ms",
        "audit_chain_valid",
    }.issubset(results.columns.keys())
