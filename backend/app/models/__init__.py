"""Import every model so Alembic receives complete metadata."""

from app.models.approval import ApprovalAction, ApprovalRequest
from app.models.audit import AuditEvent
from app.models.evaluation import EvaluationResult, EvaluationRun
from app.models.identity import Administrator, Agent, AgentCredential, RequestProof, Revocation
from app.models.policy import PolicyDecision
from app.models.provenance import ProvenanceRecord, ToolRequestInfluence
from app.models.task import Task, TaskCapability
from app.models.tool import ToolRateLimitWindow, ToolRegistry, ToolRequest

__all__ = [
    "Administrator",
    "Agent",
    "AgentCredential",
    "ApprovalAction",
    "ApprovalRequest",
    "AuditEvent",
    "EvaluationResult",
    "EvaluationRun",
    "PolicyDecision",
    "ProvenanceRecord",
    "RequestProof",
    "Revocation",
    "Task",
    "TaskCapability",
    "ToolRateLimitWindow",
    "ToolRegistry",
    "ToolRequest",
    "ToolRequestInfluence",
]
