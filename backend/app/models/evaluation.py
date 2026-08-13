"""Measured adversarial evaluation runs and scenario results."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    String,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, CreatedAtMixin, UUIDPrimaryKeyMixin
from app.models.enums import EvaluationRunStatus, EvaluationScenarioKind, PolicyOutcome


class EvaluationRun(UUIDPrimaryKeyMixin, Base):
    """Versioned execution of one scenario set."""

    __tablename__ = "evaluation_runs"
    __table_args__ = (
        CheckConstraint(
            "scenario_set_hash ~ '^sha256:[0-9a-f]{64}$'",
            name="canonical_scenario_set_hash",
        ),
        CheckConstraint(
            "configuration_hash ~ '^sha256:[0-9a-f]{64}$'",
            name="canonical_configuration_hash",
        ),
    )

    scenario_set_hash: Mapped[str] = mapped_column(String(71), nullable=False)
    configuration_hash: Mapped[str] = mapped_column(String(71), nullable=False)
    status: Mapped[EvaluationRunStatus] = mapped_column(
        Enum(
            EvaluationRunStatus,
            name="evaluation_run_status",
            native_enum=False,
            create_constraint=True,
            length=16,
        ),
        nullable=False,
        index=True,
    )
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    metrics: Mapped[dict[str, object] | None] = mapped_column(JSONB)
    json_report_path: Mapped[str | None] = mapped_column(String(255))
    markdown_report_path: Mapped[str | None] = mapped_column(String(255))


class EvaluationResult(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    """Expected and measured outcome for one evaluation scenario."""

    __tablename__ = "evaluation_results"
    __table_args__ = (
        UniqueConstraint("evaluation_run_id", "scenario_id", name="uq_evaluation_run_scenario"),
        CheckConstraint("enforcement_latency_ms >= 0", name="nonnegative_enforcement_latency"),
        CheckConstraint("policy_latency_ms >= 0", name="nonnegative_policy_latency"),
        CheckConstraint(
            "audit_completeness >= 0 AND audit_completeness <= 1",
            name="audit_completeness_range",
        ),
    )

    evaluation_run_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("evaluation_runs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    scenario_id: Mapped[str] = mapped_column(String(80), nullable=False)
    category: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    scenario_kind: Mapped[EvaluationScenarioKind] = mapped_column(
        Enum(
            EvaluationScenarioKind,
            name="evaluation_scenario_kind",
            native_enum=False,
            create_constraint=True,
            length=16,
        ),
        nullable=False,
        index=True,
    )
    expected_decision: Mapped[PolicyOutcome] = mapped_column(
        Enum(
            PolicyOutcome,
            name="evaluation_expected_outcome",
            native_enum=False,
            create_constraint=True,
            length=20,
        ),
        nullable=False,
    )
    actual_decision: Mapped[PolicyOutcome] = mapped_column(
        Enum(
            PolicyOutcome,
            name="evaluation_actual_outcome",
            native_enum=False,
            create_constraint=True,
            length=20,
        ),
        nullable=False,
    )
    reason_code: Mapped[str] = mapped_column(String(80), nullable=False)
    expected_reason_code: Mapped[str] = mapped_column(String(80), nullable=False)
    passed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    policy_latency_ms: Mapped[float] = mapped_column(Float, nullable=False)
    enforcement_latency_ms: Mapped[float] = mapped_column(Float, nullable=False)
    audit_completeness: Mapped[float] = mapped_column(Float, nullable=False)
    audit_chain_valid: Mapped[bool] = mapped_column(Boolean, nullable=False)
