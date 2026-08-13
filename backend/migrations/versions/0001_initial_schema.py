"""Create the normalized AgentGate security schema.

Revision ID: 0001_initial_schema
Revises: None
Create Date: 2026-08-11
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001_initial_schema"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _timestamps() -> tuple[sa.Column[object], sa.Column[object]]:
    return (
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
    )


def upgrade() -> None:
    op.create_table(
        "administrators",
        sa.Column("username", sa.String(length=80), nullable=False),
        sa.Column("credential_hash", sa.String(length=255), nullable=False),
        sa.Column(
            "status",
            sa.Enum(
                "ACTIVE",
                "DISABLED",
                name="administrator_status",
                native_enum=False,
                create_constraint=True,
            ),
            nullable=False,
        ),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        *_timestamps(),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_administrators")),
        sa.UniqueConstraint("username", name=op.f("uq_administrators_username")),
    )

    op.create_table(
        "agents",
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column(
            "status",
            sa.Enum(
                "ACTIVE",
                "SUSPENDED",
                "REVOKED",
                name="agent_status",
                native_enum=False,
                create_constraint=True,
            ),
            nullable=False,
        ),
        sa.Column("public_jwk", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("key_thumbprint", sa.String(length=64), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        *_timestamps(),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_agents")),
        sa.UniqueConstraint("key_thumbprint", name=op.f("uq_agents_key_thumbprint")),
        sa.UniqueConstraint("name", name=op.f("uq_agents_name")),
    )

    op.create_table(
        "tasks",
        sa.Column("owner_admin_id", sa.Uuid(), nullable=False),
        sa.Column("title", sa.String(length=160), nullable=False),
        sa.Column("trusted_instruction_summary", sa.Text(), nullable=False),
        sa.Column("trusted_instruction_hash", sa.String(length=71), nullable=False),
        sa.Column("instruction_ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("instruction_nonce", sa.LargeBinary(), nullable=False),
        sa.Column(
            "status",
            sa.Enum(
                "ACTIVE",
                "COMPLETED",
                "CANCELLED",
                "EXPIRED",
                name="task_status",
                native_enum=False,
                create_constraint=True,
            ),
            nullable=False,
        ),
        sa.Column("starts_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        *_timestamps(),
        sa.CheckConstraint(
            "expires_at IS NULL OR starts_at IS NULL OR expires_at > starts_at",
            name=op.f("ck_tasks_task_expiry_after_start"),
        ),
        sa.ForeignKeyConstraint(
            ["owner_admin_id"],
            ["administrators.id"],
            name=op.f("fk_tasks_owner_admin_id_administrators"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_tasks")),
    )
    op.create_index(op.f("ix_tasks_expires_at"), "tasks", ["expires_at"], unique=False)
    op.create_index(op.f("ix_tasks_owner_admin_id"), "tasks", ["owner_admin_id"], unique=False)

    op.create_table(
        "task_capabilities",
        sa.Column("task_id", sa.Uuid(), nullable=False),
        sa.Column("capability", sa.String(length=120), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.CheckConstraint(
            "position('*' in capability) = 0",
            name=op.f("ck_task_capabilities_capability_has_no_wildcard"),
        ),
        sa.ForeignKeyConstraint(
            ["task_id"],
            ["tasks.id"],
            name=op.f("fk_task_capabilities_task_id_tasks"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_task_capabilities")),
        sa.UniqueConstraint(
            "task_id",
            "capability",
            name="uq_task_capabilities_task_capability",
        ),
    )
    op.create_index(
        op.f("ix_task_capabilities_task_id"),
        "task_capabilities",
        ["task_id"],
        unique=False,
    )

    op.create_table(
        "agent_credentials",
        sa.Column("agent_id", sa.Uuid(), nullable=False),
        sa.Column("task_id", sa.Uuid(), nullable=False),
        sa.Column("jti_hash", sa.String(length=64), nullable=False),
        sa.Column("key_thumbprint", sa.String(length=64), nullable=False),
        sa.Column(
            "status",
            sa.Enum(
                "ACTIVE",
                "REVOKED",
                name="credential_status",
                native_enum=False,
                create_constraint=True,
            ),
            nullable=False,
        ),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("not_before_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        *_timestamps(),
        sa.CheckConstraint(
            "expires_at > issued_at", name=op.f("ck_agent_credentials_expiry_after_issue")
        ),
        sa.CheckConstraint(
            "not_before_at <= expires_at",
            name=op.f("ck_agent_credentials_not_before_expiry"),
        ),
        sa.ForeignKeyConstraint(
            ["agent_id"],
            ["agents.id"],
            name=op.f("fk_agent_credentials_agent_id_agents"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["task_id"],
            ["tasks.id"],
            name=op.f("fk_agent_credentials_task_id_tasks"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_agent_credentials")),
        sa.UniqueConstraint("jti_hash", name=op.f("uq_agent_credentials_jti_hash")),
    )
    op.create_index(
        op.f("ix_agent_credentials_agent_id"),
        "agent_credentials",
        ["agent_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_agent_credentials_expires_at"),
        "agent_credentials",
        ["expires_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_agent_credentials_task_id"),
        "agent_credentials",
        ["task_id"],
        unique=False,
    )

    op.create_table(
        "request_proofs",
        sa.Column("agent_id", sa.Uuid(), nullable=False),
        sa.Column("credential_id", sa.Uuid(), nullable=True),
        sa.Column("proof_jti_hash", sa.String(length=64), nullable=False),
        sa.Column("proof_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(
            ["agent_id"],
            ["agents.id"],
            name=op.f("fk_request_proofs_agent_id_agents"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["credential_id"],
            ["agent_credentials.id"],
            name=op.f("fk_request_proofs_credential_id_agent_credentials"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_request_proofs")),
        sa.UniqueConstraint("proof_jti_hash", name=op.f("uq_request_proofs_proof_jti_hash")),
    )
    op.create_index(
        op.f("ix_request_proofs_agent_id"), "request_proofs", ["agent_id"], unique=False
    )
    op.create_index(
        op.f("ix_request_proofs_credential_id"),
        "request_proofs",
        ["credential_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_request_proofs_expires_at"), "request_proofs", ["expires_at"], unique=False
    )

    op.create_table(
        "revocations",
        sa.Column("agent_id", sa.Uuid(), nullable=True),
        sa.Column("credential_id", sa.Uuid(), nullable=True),
        sa.Column("revoked_by_admin_id", sa.Uuid(), nullable=False),
        sa.Column("reason_code", sa.String(length=80), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("effective_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.CheckConstraint(
            "agent_id IS NOT NULL OR credential_id IS NOT NULL",
            name=op.f("ck_revocations_revocation_has_target"),
        ),
        sa.ForeignKeyConstraint(
            ["agent_id"],
            ["agents.id"],
            name=op.f("fk_revocations_agent_id_agents"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["credential_id"],
            ["agent_credentials.id"],
            name=op.f("fk_revocations_credential_id_agent_credentials"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["revoked_by_admin_id"],
            ["administrators.id"],
            name=op.f("fk_revocations_revoked_by_admin_id_administrators"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_revocations")),
    )
    op.create_index(op.f("ix_revocations_agent_id"), "revocations", ["agent_id"], unique=False)
    op.create_index(
        op.f("ix_revocations_credential_id"),
        "revocations",
        ["credential_id"],
        unique=False,
    )

    op.create_table(
        "tool_registry",
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column(
            "risk_tier",
            sa.Enum(
                "LOW",
                "MEDIUM",
                "HIGH",
                name="risk_tier",
                native_enum=False,
                create_constraint=True,
            ),
            nullable=False,
        ),
        sa.Column("schema_version", sa.String(length=32), nullable=False),
        sa.Column("adapter_version", sa.String(length=32), nullable=False),
        sa.Column("manifest_checksum", sa.String(length=64), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column(
            "constraints",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("id", sa.Uuid(), nullable=False),
        *_timestamps(),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_tool_registry")),
        sa.UniqueConstraint("name", name=op.f("uq_tool_registry_name")),
    )

    op.create_table(
        "tool_requests",
        sa.Column("correlation_id", sa.Uuid(), nullable=False),
        sa.Column("agent_id", sa.Uuid(), nullable=False),
        sa.Column("credential_id", sa.Uuid(), nullable=False),
        sa.Column("task_id", sa.Uuid(), nullable=False),
        sa.Column("tool_registry_id", sa.Uuid(), nullable=True),
        sa.Column("tool_name", sa.String(length=120), nullable=False),
        sa.Column(
            "risk_tier",
            sa.Enum(
                "LOW",
                "MEDIUM",
                "HIGH",
                name="tool_request_risk_tier",
                native_enum=False,
                create_constraint=True,
            ),
            nullable=True,
        ),
        sa.Column("arguments_ciphertext", sa.LargeBinary(), nullable=True),
        sa.Column("arguments_nonce", sa.LargeBinary(), nullable=True),
        sa.Column(
            "redacted_arguments",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("argument_hash", sa.String(length=71), nullable=True),
        sa.Column(
            "status",
            sa.Enum(
                "RECEIVED",
                "DENIED",
                "PENDING_APPROVAL",
                "RUNNING",
                "SUCCEEDED",
                "FAILED",
                name="tool_request_status",
                native_enum=False,
                create_constraint=True,
            ),
            nullable=False,
        ),
        sa.Column("request_size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("response_size_bytes", sa.BigInteger(), nullable=True),
        sa.Column("result_summary", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("error_code", sa.String(length=80), nullable=True),
        sa.Column("execution_latency_ms", sa.Integer(), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        *_timestamps(),
        sa.CheckConstraint(
            "(arguments_ciphertext IS NULL) = (arguments_nonce IS NULL)",
            name=op.f("ck_tool_requests_arguments_encryption_pair"),
        ),
        sa.CheckConstraint(
            "execution_latency_ms IS NULL OR execution_latency_ms >= 0",
            name=op.f("ck_tool_requests_nonnegative_execution_latency"),
        ),
        sa.CheckConstraint(
            "request_size_bytes >= 0",
            name=op.f("ck_tool_requests_nonnegative_request_size"),
        ),
        sa.CheckConstraint(
            "response_size_bytes IS NULL OR response_size_bytes >= 0",
            name=op.f("ck_tool_requests_nonnegative_response_size"),
        ),
        sa.ForeignKeyConstraint(
            ["agent_id"],
            ["agents.id"],
            name=op.f("fk_tool_requests_agent_id_agents"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["credential_id"],
            ["agent_credentials.id"],
            name=op.f("fk_tool_requests_credential_id_agent_credentials"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["task_id"],
            ["tasks.id"],
            name=op.f("fk_tool_requests_task_id_tasks"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tool_registry_id"],
            ["tool_registry.id"],
            name=op.f("fk_tool_requests_tool_registry_id_tool_registry"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_tool_requests")),
    )
    for column in ("agent_id", "correlation_id", "status", "task_id", "tool_name"):
        op.create_index(op.f(f"ix_tool_requests_{column}"), "tool_requests", [column], unique=False)

    op.create_table(
        "policy_decisions",
        sa.Column("tool_request_id", sa.Uuid(), nullable=False),
        sa.Column("opa_decision_id", sa.String(length=120), nullable=True),
        sa.Column(
            "outcome",
            sa.Enum(
                "DENY",
                "REQUIRE_APPROVAL",
                "ALLOW",
                name="policy_outcome",
                native_enum=False,
                create_constraint=True,
            ),
            nullable=False,
        ),
        sa.Column("reason_codes", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("policy_version", sa.String(length=40), nullable=False),
        sa.Column("input_hash", sa.String(length=71), nullable=False),
        sa.Column("latency_ms", sa.Float(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.CheckConstraint(
            "latency_ms >= 0",
            name=op.f("ck_policy_decisions_nonnegative_policy_latency"),
        ),
        sa.ForeignKeyConstraint(
            ["tool_request_id"],
            ["tool_requests.id"],
            name=op.f("fk_policy_decisions_tool_request_id_tool_requests"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_policy_decisions")),
    )
    op.create_index(
        op.f("ix_policy_decisions_outcome"),
        "policy_decisions",
        ["outcome"],
        unique=False,
    )
    op.create_index(
        op.f("ix_policy_decisions_tool_request_id"),
        "policy_decisions",
        ["tool_request_id"],
        unique=False,
    )

    op.create_table(
        "approval_requests",
        sa.Column("tool_request_id", sa.Uuid(), nullable=False),
        sa.Column("agent_id", sa.Uuid(), nullable=False),
        sa.Column("task_id", sa.Uuid(), nullable=False),
        sa.Column("tool_name", sa.String(length=120), nullable=False),
        sa.Column("argument_hash", sa.String(length=71), nullable=False),
        sa.Column(
            "status",
            sa.Enum(
                "PENDING",
                "APPROVED",
                "REJECTED",
                "EXPIRED",
                "CONSUMED",
                name="approval_status",
                native_enum=False,
                create_constraint=True,
            ),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("row_version", sa.Integer(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.CheckConstraint(
            "expires_at > created_at",
            name=op.f("ck_approval_requests_approval_expiry_after_creation"),
        ),
        sa.CheckConstraint(
            "row_version > 0",
            name=op.f("ck_approval_requests_positive_approval_row_version"),
        ),
        sa.ForeignKeyConstraint(
            ["agent_id"],
            ["agents.id"],
            name=op.f("fk_approval_requests_agent_id_agents"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["task_id"],
            ["tasks.id"],
            name=op.f("fk_approval_requests_task_id_tasks"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tool_request_id"],
            ["tool_requests.id"],
            name=op.f("fk_approval_requests_tool_request_id_tool_requests"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_approval_requests")),
        sa.UniqueConstraint("tool_request_id", name="uq_approval_requests_tool_request"),
    )
    for column in ("agent_id", "expires_at", "status", "task_id"):
        op.create_index(
            op.f(f"ix_approval_requests_{column}"),
            "approval_requests",
            [column],
            unique=False,
        )

    op.create_table(
        "approval_actions",
        sa.Column("approval_request_id", sa.Uuid(), nullable=False),
        sa.Column("administrator_id", sa.Uuid(), nullable=False),
        sa.Column(
            "action",
            sa.Enum(
                "APPROVE",
                "REJECT",
                name="approval_action_type",
                native_enum=False,
                create_constraint=True,
            ),
            nullable=False,
        ),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(
            ["administrator_id"],
            ["administrators.id"],
            name=op.f("fk_approval_actions_administrator_id_administrators"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["approval_request_id"],
            ["approval_requests.id"],
            name=op.f("fk_approval_actions_approval_request_id_approval_requests"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_approval_actions")),
    )
    op.create_index(
        op.f("ix_approval_actions_approval_request_id"),
        "approval_actions",
        ["approval_request_id"],
        unique=False,
    )

    op.create_table(
        "provenance_records",
        sa.Column("task_id", sa.Uuid(), nullable=False),
        sa.Column("tool_request_id", sa.Uuid(), nullable=True),
        sa.Column("parent_id", sa.Uuid(), nullable=True),
        sa.Column(
            "source_type",
            sa.Enum(
                "USER_INSTRUCTION",
                "LOCAL_CONFIGURATION",
                "EXTERNAL_DOCUMENT",
                "WEBSITE",
                "EMAIL",
                "SUPPORT_TICKET",
                "TOOL_OUTPUT",
                "ANOTHER_AGENT",
                name="provenance_source_type",
                native_enum=False,
                create_constraint=True,
            ),
            nullable=False,
        ),
        sa.Column(
            "trust_label",
            sa.Enum(
                "TRUSTED",
                "UNTRUSTED",
                "UNKNOWN",
                name="trust_label",
                native_enum=False,
                create_constraint=True,
            ),
            nullable=False,
        ),
        sa.Column("source_reference", sa.String(length=255), nullable=True),
        sa.Column("content_hash", sa.String(length=71), nullable=False),
        sa.Column("created_by_agent_id", sa.Uuid(), nullable=True),
        sa.Column("created_by_admin_id", sa.Uuid(), nullable=True),
        sa.Column(
            "attributes",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(
            ["created_by_admin_id"],
            ["administrators.id"],
            name=op.f("fk_provenance_records_created_by_admin_id_administrators"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["created_by_agent_id"],
            ["agents.id"],
            name=op.f("fk_provenance_records_created_by_agent_id_agents"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["parent_id"],
            ["provenance_records.id"],
            name=op.f("fk_provenance_records_parent_id_provenance_records"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["task_id"],
            ["tasks.id"],
            name=op.f("fk_provenance_records_task_id_tasks"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tool_request_id"],
            ["tool_requests.id"],
            name=op.f("fk_provenance_records_tool_request_id_tool_requests"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_provenance_records")),
    )
    for column in ("source_type", "task_id", "tool_request_id", "trust_label"):
        op.create_index(
            op.f(f"ix_provenance_records_{column}"),
            "provenance_records",
            [column],
            unique=False,
        )

    op.create_table(
        "audit_events",
        sa.Column("sequence", sa.BigInteger(), sa.Identity(always=False), nullable=False),
        sa.Column("event_id", sa.Uuid(), nullable=False),
        sa.Column("chain_id", sa.Uuid(), nullable=False),
        sa.Column("event_type", sa.String(length=100), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("correlation_id", sa.Uuid(), nullable=False),
        sa.Column(
            "actor_type",
            sa.Enum(
                "ADMINISTRATOR",
                "AGENT",
                "SYSTEM",
                name="audit_actor_type",
                native_enum=False,
                create_constraint=True,
            ),
            nullable=False,
        ),
        sa.Column("actor_id", sa.Uuid(), nullable=True),
        sa.Column("task_id", sa.Uuid(), nullable=True),
        sa.Column("tool_request_id", sa.Uuid(), nullable=True),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("previous_hash", sa.String(length=64), nullable=False),
        sa.Column("event_hash", sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(
            ["task_id"],
            ["tasks.id"],
            name=op.f("fk_audit_events_task_id_tasks"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tool_request_id"],
            ["tool_requests.id"],
            name=op.f("fk_audit_events_tool_request_id_tool_requests"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("sequence", name=op.f("pk_audit_events")),
        sa.UniqueConstraint("event_hash", name=op.f("uq_audit_events_event_hash")),
        sa.UniqueConstraint("event_id", name=op.f("uq_audit_events_event_id")),
    )
    for column in (
        "chain_id",
        "correlation_id",
        "event_type",
        "occurred_at",
        "task_id",
        "tool_request_id",
    ):
        op.create_index(op.f(f"ix_audit_events_{column}"), "audit_events", [column], unique=False)

    op.create_table(
        "evaluation_runs",
        sa.Column("scenario_set_hash", sa.String(length=71), nullable=False),
        sa.Column("configuration_hash", sa.String(length=71), nullable=False),
        sa.Column(
            "status",
            sa.Enum(
                "RUNNING",
                "COMPLETED",
                "FAILED",
                name="evaluation_run_status",
                native_enum=False,
                create_constraint=True,
            ),
            nullable=False,
        ),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("metrics", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("json_report_path", sa.String(length=255), nullable=True),
        sa.Column("markdown_report_path", sa.String(length=255), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_evaluation_runs")),
    )
    op.create_index(
        op.f("ix_evaluation_runs_status"),
        "evaluation_runs",
        ["status"],
        unique=False,
    )

    op.create_table(
        "evaluation_results",
        sa.Column("evaluation_run_id", sa.Uuid(), nullable=False),
        sa.Column("scenario_id", sa.String(length=80), nullable=False),
        sa.Column("category", sa.String(length=80), nullable=False),
        sa.Column(
            "expected_decision",
            sa.Enum(
                "DENY",
                "REQUIRE_APPROVAL",
                "ALLOW",
                name="evaluation_expected_outcome",
                native_enum=False,
                create_constraint=True,
            ),
            nullable=False,
        ),
        sa.Column(
            "actual_decision",
            sa.Enum(
                "DENY",
                "REQUIRE_APPROVAL",
                "ALLOW",
                name="evaluation_actual_outcome",
                native_enum=False,
                create_constraint=True,
            ),
            nullable=False,
        ),
        sa.Column("reason_code", sa.String(length=80), nullable=False),
        sa.Column("passed", sa.Boolean(), nullable=False),
        sa.Column("enforcement_latency_ms", sa.Float(), nullable=False),
        sa.Column("audit_completeness", sa.Float(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.CheckConstraint(
            "audit_completeness >= 0 AND audit_completeness <= 1",
            name=op.f("ck_evaluation_results_audit_completeness_range"),
        ),
        sa.CheckConstraint(
            "enforcement_latency_ms >= 0",
            name=op.f("ck_evaluation_results_nonnegative_enforcement_latency"),
        ),
        sa.ForeignKeyConstraint(
            ["evaluation_run_id"],
            ["evaluation_runs.id"],
            name=op.f("fk_evaluation_results_evaluation_run_id_evaluation_runs"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_evaluation_results")),
        sa.UniqueConstraint(
            "evaluation_run_id",
            "scenario_id",
            name="uq_evaluation_run_scenario",
        ),
    )
    op.create_index(
        op.f("ix_evaluation_results_category"),
        "evaluation_results",
        ["category"],
        unique=False,
    )
    op.create_index(
        op.f("ix_evaluation_results_evaluation_run_id"),
        "evaluation_results",
        ["evaluation_run_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_evaluation_results_evaluation_run_id"), table_name="evaluation_results")
    op.drop_index(op.f("ix_evaluation_results_category"), table_name="evaluation_results")
    op.drop_table("evaluation_results")
    op.drop_index(op.f("ix_evaluation_runs_status"), table_name="evaluation_runs")
    op.drop_table("evaluation_runs")
    for column in (
        "tool_request_id",
        "task_id",
        "occurred_at",
        "event_type",
        "correlation_id",
        "chain_id",
    ):
        op.drop_index(op.f(f"ix_audit_events_{column}"), table_name="audit_events")
    op.drop_table("audit_events")
    for column in ("trust_label", "tool_request_id", "task_id", "source_type"):
        op.drop_index(op.f(f"ix_provenance_records_{column}"), table_name="provenance_records")
    op.drop_table("provenance_records")
    op.drop_index(
        op.f("ix_approval_actions_approval_request_id"),
        table_name="approval_actions",
    )
    op.drop_table("approval_actions")
    for column in ("task_id", "status", "expires_at", "agent_id"):
        op.drop_index(op.f(f"ix_approval_requests_{column}"), table_name="approval_requests")
    op.drop_table("approval_requests")
    op.drop_index(op.f("ix_policy_decisions_tool_request_id"), table_name="policy_decisions")
    op.drop_index(op.f("ix_policy_decisions_outcome"), table_name="policy_decisions")
    op.drop_table("policy_decisions")
    for column in ("tool_name", "task_id", "status", "correlation_id", "agent_id"):
        op.drop_index(op.f(f"ix_tool_requests_{column}"), table_name="tool_requests")
    op.drop_table("tool_requests")
    op.drop_table("tool_registry")
    op.drop_index(op.f("ix_revocations_credential_id"), table_name="revocations")
    op.drop_index(op.f("ix_revocations_agent_id"), table_name="revocations")
    op.drop_table("revocations")
    op.drop_index(op.f("ix_request_proofs_expires_at"), table_name="request_proofs")
    op.drop_index(op.f("ix_request_proofs_credential_id"), table_name="request_proofs")
    op.drop_index(op.f("ix_request_proofs_agent_id"), table_name="request_proofs")
    op.drop_table("request_proofs")
    op.drop_index(op.f("ix_agent_credentials_task_id"), table_name="agent_credentials")
    op.drop_index(op.f("ix_agent_credentials_expires_at"), table_name="agent_credentials")
    op.drop_index(op.f("ix_agent_credentials_agent_id"), table_name="agent_credentials")
    op.drop_table("agent_credentials")
    op.drop_index(op.f("ix_task_capabilities_task_id"), table_name="task_capabilities")
    op.drop_table("task_capabilities")
    op.drop_index(op.f("ix_tasks_owner_admin_id"), table_name="tasks")
    op.drop_index(op.f("ix_tasks_expires_at"), table_name="tasks")
    op.drop_table("tasks")
    op.drop_table("agents")
    op.drop_table("administrators")
