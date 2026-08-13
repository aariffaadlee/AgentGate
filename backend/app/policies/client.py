"""Strict OPA REST contract with deny-on-error behavior."""

import json
from datetime import datetime
from typing import Literal, Self
from uuid import UUID

import httpx
import structlog
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from app.models.enums import AgentStatus, PolicyOutcome, RiskTier, TrustLabel

logger = structlog.get_logger(__name__)

OPA_DECISION_PATH = "/v1/data/agentgate/authorization/decision"

DENY_REASON_CODES = {
    "DEFAULT_DENY",
    "AGENT_INACTIVE",
    "CREDENTIAL_EXPIRED",
    "CREDENTIAL_REVOKED",
    "TOKEN_CONTEXT_INVALID",
    "PROOF_INVALID",
    "CAPABILITY_MISSING",
    "UNKNOWN_TOOL",
    "ARGUMENTS_INVALID",
    "CROSS_TASK_CREDENTIAL",
    "UNTRUSTED_ONLY_SENSITIVE_INTENT",
    "UNKNOWN_PROVENANCE_SENSITIVE_INTENT",
    "PROVENANCE_INVALID",
    "APPROVAL_ARGUMENT_MISMATCH",
    "APPROVAL_EXPIRED",
    "APPROVAL_REPLAYED",
    "RATE_LIMIT_EXCEEDED",
    "RESOURCE_LIMIT_EXCEEDED",
    "POLICY_ENGINE_ERROR",
}
APPROVAL_REASON_CODES = {
    "HIGH_RISK_APPROVAL_REQUIRED",
    "FILE_OVERWRITE_APPROVAL_REQUIRED",
}
ALLOW_REASON_CODES = {
    "LOW_RISK_CAPABILITY_ALLOWED",
    "MEDIUM_RISK_CAPABILITY_ALLOWED",
    "APPROVAL_VALID",
}


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class PolicyAgent(StrictModel):
    id: UUID
    status: AgentStatus


class PolicyTask(StrictModel):
    id: UUID
    owner_id: UUID


class PolicyToken(StrictModel):
    issuer: str
    audience: str
    expected_issuer: str
    expected_audience: str
    expires_at: datetime
    task_id: UUID
    capabilities: list[str]
    revoked: bool
    proof_valid: bool


class PolicyTool(StrictModel):
    name: str
    known: bool
    risk: RiskTier | None


class PolicyRequest(StrictModel):
    arguments_valid: bool
    arguments: dict[str, object]
    argument_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    body_size_bytes: int = Field(ge=0)


class PolicyProvenance(StrictModel):
    labels: list[TrustLabel]
    source_types: list[str]
    untrusted_influence: bool
    trusted_intent_present: bool
    context_valid: bool


class PolicyApproval(StrictModel):
    status: Literal["none", "pending", "approved", "rejected", "expired", "consumed"]
    argument_hash: str | None
    expires_at: datetime | None
    consumed: bool


class PolicyLimits(StrictModel):
    rate_exceeded: bool
    request_size_exceeded: bool
    expected_response_size_exceeded: bool


class AuthorizationInput(StrictModel):
    """Complete server-assembled authorization document sent to OPA."""

    agent: PolicyAgent
    task: PolicyTask
    token: PolicyToken
    tool: PolicyTool
    request: PolicyRequest
    provenance: PolicyProvenance
    approval: PolicyApproval
    limits: PolicyLimits
    now: datetime


class AuthorizationDecision(StrictModel):
    """Validated deterministic outcome; reason codes must match its class."""

    decision: PolicyOutcome
    reason_codes: list[str] = Field(min_length=1, max_length=20)
    policy_version: str = Field(min_length=1, max_length=40)
    opa_decision_id: str | None = Field(default=None, max_length=120)

    @model_validator(mode="after")
    def validate_reason_codes(self) -> Self:
        if len(self.reason_codes) != len(set(self.reason_codes)):
            raise ValueError("policy reason codes must be unique")
        allowed = {
            PolicyOutcome.DENY: DENY_REASON_CODES,
            PolicyOutcome.REQUIRE_APPROVAL: APPROVAL_REASON_CODES,
            PolicyOutcome.ALLOW: ALLOW_REASON_CODES,
        }[self.decision]
        if any(reason not in allowed for reason in self.reason_codes):
            raise ValueError("policy reason code does not match the decision")
        return self


class OPAResponse(StrictModel):
    result: AuthorizationDecision | None = None
    decision_id: str | None = Field(default=None, max_length=120)


class PolicyClient:
    """Call one named OPA decision and fail closed on every transport/schema anomaly."""

    def __init__(
        self,
        *,
        base_url: str,
        timeout_seconds: float,
        max_response_bytes: int = 16_384,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(
            base_url=base_url,
            timeout=httpx.Timeout(timeout_seconds),
        )
        self._max_response_bytes = max_response_bytes

    async def evaluate(self, policy_input: AuthorizationInput) -> AuthorizationDecision:
        """Return a strict policy result or a synthetic fail-closed denial."""

        try:
            async with self._client.stream(
                "POST",
                OPA_DECISION_PATH,
                json={"input": policy_input.model_dump(mode="json")},
            ) as response:
                response.raise_for_status()
                payload = bytearray()
                async for chunk in response.aiter_bytes():
                    if len(payload) + len(chunk) > self._max_response_bytes:
                        return _policy_engine_denial()
                    payload.extend(chunk)
            envelope = OPAResponse.model_validate(json.loads(payload))
            if envelope.result is None:
                return _policy_engine_denial()
            return envelope.result.model_copy(update={"opa_decision_id": envelope.decision_id})
        except (httpx.HTTPError, ValueError, ValidationError) as exc:
            await logger.awarning(
                "policy_engine_request_failed",
                exception_type=type(exc).__name__,
            )
            return _policy_engine_denial()

    async def is_ready(self) -> bool:
        """Check OPA plugin readiness without exposing its response body."""

        try:
            response = await self._client.get("/health", params={"plugins": ""})
            return response.status_code == 200
        except httpx.HTTPError:
            return False

    async def close(self) -> None:
        """Close only the HTTP client owned by this service."""

        if self._owns_client:
            await self._client.aclose()


def _policy_engine_denial() -> AuthorizationDecision:
    return AuthorizationDecision(
        decision=PolicyOutcome.DENY,
        reason_codes=["POLICY_ENGINE_ERROR"],
        policy_version="unavailable",
    )
