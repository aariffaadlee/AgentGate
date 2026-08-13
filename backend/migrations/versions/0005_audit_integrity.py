"""Constrain canonical append-only audit-chain records.

Revision ID: 0005_audit_integrity
Revises: 0004_provenance_influences
Create Date: 2026-08-13
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0005_audit_integrity"
down_revision: str | None = "0004_provenance_influences"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_check_constraint(
        "ck_audit_events_positive_audit_sequence",
        "audit_events",
        "sequence > 0",
    )
    op.create_check_constraint(
        "ck_audit_events_canonical_audit_previous_hash",
        "audit_events",
        "previous_hash ~ '^[0-9a-f]{64}$'",
    )
    op.create_check_constraint(
        "ck_audit_events_canonical_audit_event_hash",
        "audit_events",
        "event_hash ~ '^[0-9a-f]{64}$'",
    )
    op.create_check_constraint(
        "ck_audit_events_audit_payload_object",
        "audit_events",
        "jsonb_typeof(payload) = 'object'",
    )
    op.create_check_constraint(
        "ck_audit_events_audit_actor_identity",
        "audit_events",
        "(actor_type = 'SYSTEM' AND actor_id IS NULL) OR "
        "(actor_type <> 'SYSTEM' AND actor_id IS NOT NULL)",
    )


def downgrade() -> None:
    for name in (
        "audit_actor_identity",
        "audit_payload_object",
        "canonical_audit_event_hash",
        "canonical_audit_previous_hash",
        "positive_audit_sequence",
    ):
        op.drop_constraint(
            f"ck_audit_events_{name}",
            "audit_events",
            type_="check",
        )
