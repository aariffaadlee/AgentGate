"""Add atomic fixed-window counters for Phase 3 tool governance.

Revision ID: 0003_tool_rate_limits
Revises: 0002_task_agent_assignment
Create Date: 2026-08-13
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003_tool_rate_limits"
down_revision: str | None = "0002_task_agent_assignment"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create one concurrency-safe counter row per fixed scope/window."""

    op.create_table(
        "tool_rate_limit_windows",
        sa.Column("agent_id", sa.Uuid(), nullable=False),
        sa.Column("task_id", sa.Uuid(), nullable=False),
        sa.Column("tool_name", sa.String(length=120), nullable=False),
        sa.Column("window_started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("request_count", sa.Integer(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.CheckConstraint(
            "request_count > 0",
            name=op.f("ck_tool_rate_limit_windows_positive_request_count"),
        ),
        sa.ForeignKeyConstraint(
            ["agent_id"],
            ["agents.id"],
            name=op.f("fk_tool_rate_limit_windows_agent_id_agents"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["task_id"],
            ["tasks.id"],
            name=op.f("fk_tool_rate_limit_windows_task_id_tasks"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_tool_rate_limit_windows")),
        sa.UniqueConstraint(
            "agent_id",
            "task_id",
            "tool_name",
            "window_started_at",
            name="uq_tool_rate_limit_scope_window",
        ),
    )
    op.create_index(
        op.f("ix_tool_rate_limit_windows_agent_id"),
        "tool_rate_limit_windows",
        ["agent_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_tool_rate_limit_windows_task_id"),
        "tool_rate_limit_windows",
        ["task_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_tool_rate_limit_windows_window_started_at"),
        "tool_rate_limit_windows",
        ["window_started_at"],
        unique=False,
    )


def downgrade() -> None:
    """Remove Phase 3 rate-limit counters."""

    op.drop_index(
        op.f("ix_tool_rate_limit_windows_window_started_at"),
        table_name="tool_rate_limit_windows",
    )
    op.drop_index(
        op.f("ix_tool_rate_limit_windows_task_id"),
        table_name="tool_rate_limit_windows",
    )
    op.drop_index(
        op.f("ix_tool_rate_limit_windows_agent_id"),
        table_name="tool_rate_limit_windows",
    )
    op.drop_table("tool_rate_limit_windows")
