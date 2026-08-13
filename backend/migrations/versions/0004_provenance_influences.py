"""Bind authoritative provenance records to tool requests.

Revision ID: 0004_provenance_influences
Revises: 0003_tool_rate_limits
Create Date: 2026-08-13
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004_provenance_influences"
down_revision: str | None = "0003_tool_rate_limits"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_check_constraint(
        "ck_provenance_records_provenance_not_self_parent",
        "provenance_records",
        "parent_id IS NULL OR parent_id <> id",
    )
    op.create_check_constraint(
        "ck_provenance_records_provenance_single_creator",
        "provenance_records",
        "created_by_agent_id IS NULL OR created_by_admin_id IS NULL",
    )
    op.create_check_constraint(
        "ck_provenance_records_canonical_content_hash",
        "provenance_records",
        "content_hash ~ '^sha256:[0-9a-f]{64}$'",
    )
    op.create_table(
        "tool_request_influences",
        sa.Column("tool_request_id", sa.Uuid(), nullable=False),
        sa.Column("provenance_record_id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(
            ["provenance_record_id"],
            ["provenance_records.id"],
            name=op.f("fk_tool_request_influences_provenance_record_id_provenance_records"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tool_request_id"],
            ["tool_requests.id"],
            name=op.f("fk_tool_request_influences_tool_request_id_tool_requests"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_tool_request_influences")),
        sa.UniqueConstraint(
            "tool_request_id",
            "provenance_record_id",
            name="uq_tool_request_influences_request_record",
        ),
    )
    op.create_index(
        op.f("ix_tool_request_influences_provenance_record_id"),
        "tool_request_influences",
        ["provenance_record_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_tool_request_influences_tool_request_id"),
        "tool_request_influences",
        ["tool_request_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        op.f("ix_tool_request_influences_tool_request_id"),
        table_name="tool_request_influences",
    )
    op.drop_index(
        op.f("ix_tool_request_influences_provenance_record_id"),
        table_name="tool_request_influences",
    )
    op.drop_table("tool_request_influences")
    op.drop_constraint(
        "ck_provenance_records_canonical_content_hash",
        "provenance_records",
        type_="check",
    )
    op.drop_constraint(
        "ck_provenance_records_provenance_single_creator",
        "provenance_records",
        type_="check",
    )
    op.drop_constraint(
        "ck_provenance_records_provenance_not_self_parent",
        "provenance_records",
        type_="check",
    )
