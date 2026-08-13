"""Deterministic policy-decision persistence."""

from uuid import UUID

from sqlalchemy import CheckConstraint, Enum, Float, ForeignKey, String, Uuid
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, CreatedAtMixin, UUIDPrimaryKeyMixin
from app.models.enums import PolicyOutcome


class PolicyDecision(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    """One immutable authorization decision returned by OPA or fail-closed handling."""

    __tablename__ = "policy_decisions"
    __table_args__ = (CheckConstraint("latency_ms >= 0", name="nonnegative_policy_latency"),)

    tool_request_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("tool_requests.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    opa_decision_id: Mapped[str | None] = mapped_column(String(120))
    outcome: Mapped[PolicyOutcome] = mapped_column(
        Enum(
            PolicyOutcome,
            name="policy_outcome",
            native_enum=False,
            create_constraint=True,
            length=20,
        ),
        nullable=False,
        index=True,
    )
    reason_codes: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    policy_version: Mapped[str] = mapped_column(String(40), nullable=False)
    input_hash: Mapped[str] = mapped_column(String(71), nullable=False)
    latency_ms: Mapped[float] = mapped_column(Float, nullable=False)
