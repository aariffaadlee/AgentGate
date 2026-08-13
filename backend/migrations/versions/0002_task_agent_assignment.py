"""Bind tasks to the agent authorized to request their credentials.

Revision ID: 0002_task_agent_assignment
Revises: 0001_initial_schema
Create Date: 2026-08-11
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002_task_agent_assignment"
down_revision: str | None = "0001_initial_schema"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add an indexed, restrictive agent assignment to tasks.

    The column is nullable only so a Phase 1 database containing pre-identity
    design records can migrate safely. Phase 2 task creation always assigns it,
    and token issuance fails closed for an unassigned task.
    """

    op.add_column("tasks", sa.Column("assigned_agent_id", sa.Uuid(), nullable=True))
    op.create_foreign_key(
        op.f("fk_tasks_assigned_agent_id_agents"),
        "tasks",
        "agents",
        ["assigned_agent_id"],
        ["id"],
        ondelete="RESTRICT",
    )
    op.create_index(
        op.f("ix_tasks_assigned_agent_id"),
        "tasks",
        ["assigned_agent_id"],
        unique=False,
    )


def downgrade() -> None:
    """Remove the task-to-agent assignment."""

    op.drop_index(op.f("ix_tasks_assigned_agent_id"), table_name="tasks")
    op.drop_constraint(
        op.f("fk_tasks_assigned_agent_id_agents"),
        "tasks",
        type_="foreignkey",
    )
    op.drop_column("tasks", "assigned_agent_id")
