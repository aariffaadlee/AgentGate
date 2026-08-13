"""Shared persisted state enums."""

from enum import StrEnum


class AdministratorStatus(StrEnum):
    ACTIVE = "active"
    DISABLED = "disabled"


class AgentStatus(StrEnum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    REVOKED = "revoked"


class CredentialStatus(StrEnum):
    ACTIVE = "active"
    REVOKED = "revoked"


class TaskStatus(StrEnum):
    ACTIVE = "active"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    EXPIRED = "expired"


class RiskTier(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ToolRequestStatus(StrEnum):
    RECEIVED = "received"
    DENIED = "denied"
    PENDING_APPROVAL = "pending_approval"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class PolicyOutcome(StrEnum):
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"
    ALLOW = "allow"


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    CONSUMED = "consumed"


class ApprovalActionType(StrEnum):
    APPROVE = "approve"
    REJECT = "reject"


class TrustLabel(StrEnum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"
    UNKNOWN = "unknown"


class ProvenanceSourceType(StrEnum):
    USER_INSTRUCTION = "user_instruction"
    LOCAL_CONFIGURATION = "local_configuration"
    EXTERNAL_DOCUMENT = "external_document"
    WEBSITE = "website"
    EMAIL = "email"
    SUPPORT_TICKET = "support_ticket"
    TOOL_OUTPUT = "tool_output"
    ANOTHER_AGENT = "another_agent"


class AuditActorType(StrEnum):
    ADMINISTRATOR = "administrator"
    AGENT = "agent"
    SYSTEM = "system"


class EvaluationRunStatus(StrEnum):
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class EvaluationScenarioKind(StrEnum):
    LEGITIMATE = "legitimate"
    ADVERSARIAL = "adversarial"
