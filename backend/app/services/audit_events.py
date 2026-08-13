"""Safe audit-event batches for tool and approval state transitions."""

from uuid import UUID

from app.models.enums import AuditActorType, ToolRequestStatus
from app.models.tool import ToolRequest
from app.services.approvals import ApprovalRecord
from app.services.audit import AuditEventDraft
from app.services.tools import ToolRequestOutcome


def tool_outcome_events(outcome: ToolRequestOutcome) -> list[AuditEventDraft]:
    """Describe request, policy, and terminal/pending state without full arguments."""

    request = outcome.request
    persisted_decision = outcome.policy_decision
    events = [
        AuditEventDraft(
            event_type="tool.requested",
            correlation_id=request.correlation_id,
            actor_type=AuditActorType.AGENT,
            actor_id=request.agent_id,
            task_id=request.task_id,
            tool_request_id=request.id,
            payload={
                "tool_name": request.tool_name,
                "risk_tier": request.risk_tier.value if request.risk_tier is not None else None,
                "argument_hash": request.argument_hash,
                "arguments_summary": request.redacted_arguments,
                "request_size_bytes": request.request_size_bytes,
                "influence_ids": [str(record.id) for record in outcome.influences],
            },
            occurred_at=request.created_at,
        ),
        AuditEventDraft(
            event_type="policy.decided",
            correlation_id=request.correlation_id,
            actor_type=AuditActorType.AGENT,
            actor_id=request.agent_id,
            task_id=request.task_id,
            tool_request_id=request.id,
            payload={
                "outcome": outcome.decision.decision.value,
                "reason_codes": outcome.decision.reason_codes,
                "policy_version": outcome.decision.policy_version,
                "opa_decision_id": outcome.decision.opa_decision_id,
                "input_hash": (
                    persisted_decision.input_hash if persisted_decision is not None else None
                ),
                "latency_ms": (
                    persisted_decision.latency_ms if persisted_decision is not None else None
                ),
            },
        ),
    ]
    if outcome.approval is not None:
        events.append(
            AuditEventDraft(
                event_type="approval.pending",
                correlation_id=request.correlation_id,
                actor_type=AuditActorType.AGENT,
                actor_id=request.agent_id,
                task_id=request.task_id,
                tool_request_id=request.id,
                payload={
                    "approval_id": str(outcome.approval.id),
                    "tool_name": outcome.approval.tool_name,
                    "argument_hash": outcome.approval.argument_hash,
                    "status": outcome.approval.status.value,
                    "expires_at": outcome.approval.expires_at.isoformat(),
                },
                occurred_at=outcome.approval.created_at,
            )
        )
    else:
        events.append(_terminal_tool_event(outcome))
    return events


def approval_outcome_events(
    record: ApprovalRecord,
    *,
    administrator_id: UUID,
    action: str,
    reason_present: bool,
) -> list[AuditEventDraft]:
    """Record an admin transition and resulting policy/execution state."""

    request = record.request
    approval = record.approval
    events = [
        AuditEventDraft(
            event_type=f"approval.{action}",
            correlation_id=request.correlation_id,
            actor_type=AuditActorType.ADMINISTRATOR,
            actor_id=administrator_id,
            task_id=request.task_id,
            tool_request_id=request.id,
            payload={
                "approval_id": str(approval.id),
                "tool_name": approval.tool_name,
                "argument_hash": approval.argument_hash,
                "status": approval.status.value,
                "row_version": approval.row_version,
                "reason_present": reason_present,
            },
        )
    ]
    if record.decision is not None and action == "consumed":
        events.append(
            AuditEventDraft(
                event_type="policy.decided",
                correlation_id=request.correlation_id,
                actor_type=AuditActorType.ADMINISTRATOR,
                actor_id=administrator_id,
                task_id=request.task_id,
                tool_request_id=request.id,
                payload={
                    "outcome": record.decision.outcome.value,
                    "reason_codes": record.decision.reason_codes,
                    "policy_version": record.decision.policy_version,
                    "input_hash": record.decision.input_hash,
                    "latency_ms": record.decision.latency_ms,
                    "approval_id": str(approval.id),
                },
            )
        )
    events.append(
        AuditEventDraft(
            event_type=f"tool.{request.status.value}",
            correlation_id=request.correlation_id,
            actor_type=AuditActorType.ADMINISTRATOR,
            actor_id=administrator_id,
            task_id=request.task_id,
            tool_request_id=request.id,
            payload=_terminal_payload(request),
            occurred_at=request.completed_at,
        )
    )
    return events


def _terminal_tool_event(
    outcome: ToolRequestOutcome,
) -> AuditEventDraft:
    request = outcome.request
    return AuditEventDraft(
        event_type=f"tool.{request.status.value}",
        correlation_id=request.correlation_id,
        actor_type=AuditActorType.AGENT,
        actor_id=request.agent_id,
        task_id=request.task_id,
        tool_request_id=request.id,
        payload=_terminal_payload(request),
        occurred_at=request.completed_at,
    )


def _terminal_payload(request: ToolRequest) -> dict[str, object]:
    status: ToolRequestStatus = request.status
    return {
        "status": status.value,
        "error_code": request.error_code,
        "result_summary": request.result_summary,
        "response_size_bytes": request.response_size_bytes,
        "execution_latency_ms": request.execution_latency_ms,
    }
