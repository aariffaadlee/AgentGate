"""Persist recomputable per-scenario evaluation evidence.

Revision ID: 0006_evaluation_evidence
Revises: 0005_audit_integrity
Create Date: 2026-08-13
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006_evaluation_evidence"
down_revision: str | None = "0005_audit_integrity"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "evaluation_results",
        sa.Column(
            "scenario_kind",
            sa.Enum(
                "LEGITIMATE",
                "ADVERSARIAL",
                name="evaluation_scenario_kind",
                native_enum=False,
                create_constraint=True,
            ),
            nullable=False,
            server_default="ADVERSARIAL",
        ),
    )
    op.add_column(
        "evaluation_results",
        sa.Column(
            "expected_reason_code",
            sa.String(length=80),
            nullable=False,
            server_default="DEFAULT_DENY",
        ),
    )
    op.add_column(
        "evaluation_results",
        sa.Column("policy_latency_ms", sa.Float(), nullable=False, server_default="0"),
    )
    op.add_column(
        "evaluation_results",
        sa.Column("audit_chain_valid", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.create_check_constraint(
        "ck_evaluation_results_nonnegative_policy_latency",
        "evaluation_results",
        "policy_latency_ms >= 0",
    )
    op.create_check_constraint(
        "ck_evaluation_runs_canonical_scenario_set_hash",
        "evaluation_runs",
        "scenario_set_hash ~ '^sha256:[0-9a-f]{64}$'",
    )
    op.create_check_constraint(
        "ck_evaluation_runs_canonical_configuration_hash",
        "evaluation_runs",
        "configuration_hash ~ '^sha256:[0-9a-f]{64}$'",
    )
    op.create_index(
        op.f("ix_evaluation_results_scenario_kind"),
        "evaluation_results",
        ["scenario_kind"],
        unique=False,
    )
    for column in (
        "scenario_kind",
        "expected_reason_code",
        "policy_latency_ms",
        "audit_chain_valid",
    ):
        op.alter_column("evaluation_results", column, server_default=None)


def downgrade() -> None:
    op.drop_index(
        op.f("ix_evaluation_results_scenario_kind"),
        table_name="evaluation_results",
    )
    op.drop_constraint(
        "ck_evaluation_runs_canonical_configuration_hash",
        "evaluation_runs",
        type_="check",
    )
    op.drop_constraint(
        "ck_evaluation_runs_canonical_scenario_set_hash",
        "evaluation_runs",
        type_="check",
    )
    op.drop_constraint(
        "ck_evaluation_results_nonnegative_policy_latency",
        "evaluation_results",
        type_="check",
    )
    for column in (
        "audit_chain_valid",
        "policy_latency_ms",
        "expected_reason_code",
        "scenario_kind",
    ):
        op.drop_column("evaluation_results", column)
