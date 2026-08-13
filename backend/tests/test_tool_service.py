"""Phase 3 PEP ordering, persistence, policy, and non-dispatch security tests."""

import asyncio
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from pydantic import BaseModel

from app.api.errors import AgentGateError
from app.auth.tokens import ConfirmationClaim, WorkloadTokenClaims
from app.config import Settings
from app.db.base import utc_now
from app.models.approval import ApprovalRequest
from app.models.enums import (
    AgentStatus,
    CredentialStatus,
    PolicyOutcome,
    ProvenanceSourceType,
    RiskTier,
    TaskStatus,
    ToolRequestStatus,
    TrustLabel,
)
from app.models.identity import Agent, AgentCredential
from app.models.policy import PolicyDecision
from app.models.provenance import ProvenanceRecord
from app.models.task import Task
from app.models.tool import ToolRegistry, ToolRequest
from app.policies.client import AuthorizationDecision, AuthorizationInput
from app.services.identity import AgentPrincipal
from app.services.tools import (
    RateLimitResult,
    ToolRequestBundle,
    ToolRequestCommand,
    ToolRequestService,
)
from app.tools.adapters import MockMailbox, ToolExecutionContext
from app.tools.gateway import ToolGateway
from app.tools.registry import (
    STATIC_TOOL_REGISTRY,
    StaticToolRegistry,
    ToolDefinition,
    ToolLimits,
)
from app.tools.schemas import DocumentsSearchArguments, DocumentsSearchResult

PROJECT_ROOT = Path(__file__).resolve().parents[2]


class FakeToolRepository:
    def __init__(self, registry: StaticToolRegistry = STATIC_TOOL_REGISTRY) -> None:
        now = utc_now()
        self.registry = {
            definition.name: ToolRegistry(
                id=uuid4(),
                name=definition.name,
                risk_tier=definition.risk_tier,
                schema_version=definition.schema_version,
                adapter_version=definition.adapter_version,
                manifest_checksum=registry.manifest_checksum,
                enabled=True,
                constraints=registry.database_constraints(definition),
                created_at=now,
                updated_at=now,
            )
            for definition in registry
        }
        self.requests: dict[UUID, ToolRequest] = {}
        self.decisions: dict[UUID, PolicyDecision] = {}
        self.approvals: dict[UUID, ApprovalRequest] = {}
        self.provenance: dict[UUID, ProvenanceRecord] = {}
        self.influences: dict[UUID, list[UUID]] = {}
        self.rate_allowed = True
        self.rate_count = 1

    async def get_registry_tool(self, name: str) -> ToolRegistry | None:
        return self.registry.get(name)

    async def get_provenance_records(
        self,
        record_ids: list[UUID],
    ) -> list[ProvenanceRecord]:
        return [
            self.provenance[record_id] for record_id in record_ids if record_id in self.provenance
        ]

    async def consume_rate_limit(
        self,
        *,
        agent_id: UUID,
        task_id: UUID,
        tool_name: str,
        now: datetime,
        limit: int,
        window_seconds: int,
    ) -> RateLimitResult:
        del agent_id, task_id, tool_name, window_seconds
        return RateLimitResult(self.rate_allowed, self.rate_count, limit, now)

    async def create_tool_request(
        self,
        request: ToolRequest,
        influences: list[ProvenanceRecord],
    ) -> ToolRequest:
        request.created_at = utc_now()
        request.updated_at = request.created_at
        self.requests[request.id] = request
        self.influences[request.id] = [record.id for record in influences]
        return request

    async def store_policy_decision(self, decision: PolicyDecision) -> PolicyDecision:
        decision.created_at = utc_now()
        self.decisions[decision.tool_request_id] = decision
        return decision

    async def create_pending_approval(
        self,
        request: ToolRequest,
        approval: ApprovalRequest,
    ) -> ApprovalRequest:
        request.status = ToolRequestStatus.PENDING_APPROVAL
        request.completed_at = None
        request.updated_at = utc_now()
        self.approvals[approval.id] = approval
        return approval

    async def finish_tool_request(
        self,
        request: ToolRequest,
        *,
        status: ToolRequestStatus,
        error_code: str | None,
        response_size_bytes: int | None,
        result_summary: dict[str, object] | None,
        execution_latency_ms: int | None,
        completed_at: datetime,
        produced_provenance: list[ProvenanceRecord],
    ) -> ToolRequest:
        request.status = status
        request.error_code = error_code
        request.response_size_bytes = response_size_bytes
        request.result_summary = result_summary
        request.execution_latency_ms = execution_latency_ms
        request.completed_at = completed_at
        request.updated_at = completed_at
        for record in produced_provenance:
            record.created_at = completed_at
            self.provenance[record.id] = record
        return request

    async def get_tool_request(self, request_id: UUID) -> ToolRequestBundle | None:
        request = self.requests.get(request_id)
        if request is None:
            return None
        approval = next(
            (
                candidate
                for candidate in self.approvals.values()
                if candidate.tool_request_id == request_id
            ),
            None,
        )
        influences = [
            self.provenance[record_id] for record_id in self.influences.get(request_id, [])
        ]
        produced = [
            record for record in self.provenance.values() if record.tool_request_id == request_id
        ]
        return ToolRequestBundle(
            request,
            self.decisions.get(request_id),
            approval,
            influences,
            produced,
        )

    async def list_tool_requests(self, limit: int) -> list[ToolRequestBundle]:
        requests = sorted(
            self.requests.values(),
            key=lambda request: (request.created_at, request.id),
            reverse=True,
        )[:limit]
        bundles: list[ToolRequestBundle] = []
        for request in requests:
            bundle = await self.get_tool_request(request.id)
            if bundle is not None:
                bundles.append(bundle)
        return bundles

    def add_trusted_intent(self, principal: AgentPrincipal) -> ProvenanceRecord:
        record = ProvenanceRecord(
            id=uuid4(),
            task_id=principal.task.id,
            tool_request_id=None,
            parent_id=None,
            source_type=ProvenanceSourceType.USER_INSTRUCTION,
            trust_label=TrustLabel.TRUSTED,
            source_reference="task-owner-instruction",
            content_hash=principal.task.trusted_instruction_hash,
            created_by_agent_id=None,
            created_by_admin_id=principal.task.owner_admin_id,
            attributes={"server_classification": "task_owner_intent"},
            created_at=utc_now(),
        )
        self.provenance[record.id] = record
        return record


class DeterministicPolicy:
    def __init__(self) -> None:
        self.inputs: list[AuthorizationInput] = []

    async def evaluate(self, policy_input: AuthorizationInput) -> AuthorizationDecision:
        self.inputs.append(policy_input)
        if not policy_input.tool.known:
            return _decision(PolicyOutcome.DENY, "UNKNOWN_TOOL")
        if not policy_input.request.arguments_valid:
            return _decision(PolicyOutcome.DENY, "ARGUMENTS_INVALID")
        if not policy_input.provenance.context_valid:
            return _decision(PolicyOutcome.DENY, "PROVENANCE_INVALID")
        if policy_input.limits.rate_exceeded:
            return _decision(PolicyOutcome.DENY, "RATE_LIMIT_EXCEEDED")
        if policy_input.limits.request_size_exceeded:
            return _decision(PolicyOutcome.DENY, "RESOURCE_LIMIT_EXCEEDED")
        if policy_input.tool.name not in policy_input.token.capabilities:
            return _decision(PolicyOutcome.DENY, "CAPABILITY_MISSING")
        if policy_input.tool.risk is RiskTier.HIGH:
            if (
                policy_input.provenance.untrusted_influence
                and not policy_input.provenance.trusted_intent_present
            ):
                return _decision(
                    PolicyOutcome.DENY,
                    "UNTRUSTED_ONLY_SENSITIVE_INTENT",
                )
            if (
                TrustLabel.UNKNOWN in policy_input.provenance.labels
                and not policy_input.provenance.trusted_intent_present
            ):
                return _decision(
                    PolicyOutcome.DENY,
                    "UNKNOWN_PROVENANCE_SENSITIVE_INTENT",
                )
            if (
                policy_input.approval.status == "approved"
                and not policy_input.approval.consumed
                and policy_input.approval.argument_hash == policy_input.request.argument_hash
            ):
                return _decision(PolicyOutcome.ALLOW, "APPROVAL_VALID")
            return _decision(PolicyOutcome.REQUIRE_APPROVAL, "HIGH_RISK_APPROVAL_REQUIRED")
        reason = (
            "LOW_RISK_CAPABILITY_ALLOWED"
            if policy_input.tool.risk is RiskTier.LOW
            else "MEDIUM_RISK_CAPABILITY_ALLOWED"
        )
        return _decision(PolicyOutcome.ALLOW, reason)


class AlwaysAllowPolicy(DeterministicPolicy):
    async def evaluate(self, policy_input: AuthorizationInput) -> AuthorizationDecision:
        self.inputs.append(policy_input)
        return _decision(PolicyOutcome.ALLOW, "LOW_RISK_CAPABILITY_ALLOWED")


def _decision(outcome: PolicyOutcome, reason: str) -> AuthorizationDecision:
    return AuthorizationDecision(
        decision=outcome,
        reason_codes=[reason],
        policy_version="test-1",
    )


def _principal(*capabilities: str) -> AgentPrincipal:
    now = utc_now().replace(microsecond=0)
    agent_id = uuid4()
    task_id = uuid4()
    thumbprint = "a" * 64
    agent = Agent(
        id=agent_id,
        name="Tool Test Agent",
        status=AgentStatus.ACTIVE,
        public_jwk={"kty": "OKP", "crv": "Ed25519", "x": "A" * 43},
        key_thumbprint=thumbprint,
        created_at=now,
        updated_at=now,
    )
    task = Task(
        id=task_id,
        owner_admin_id=uuid4(),
        assigned_agent_id=agent_id,
        title="Tool service test",
        trusted_instruction_summary="Exercise one synthetic tool.",
        trusted_instruction_hash="sha256:" + ("b" * 64),
        instruction_ciphertext=b"ciphertext",
        instruction_nonce=b"0" * 12,
        status=TaskStatus.ACTIVE,
        created_at=now,
        updated_at=now,
    )
    credential = AgentCredential(
        id=uuid4(),
        agent_id=agent_id,
        task_id=task_id,
        jti_hash="c" * 64,
        key_thumbprint=thumbprint,
        status=CredentialStatus.ACTIVE,
        issued_at=now,
        not_before_at=now,
        expires_at=now + timedelta(minutes=5),
        created_at=now,
        updated_at=now,
    )
    claims = WorkloadTokenClaims(
        iss="agentgate.local",
        aud="agentgate-tools",
        sub=agent_id,
        task_id=task_id,
        capabilities=list(capabilities),
        jti=uuid4(),
        iat=int(now.timestamp()),
        nbf=int(now.timestamp()),
        exp=int((now + timedelta(minutes=5)).timestamp()),
        cnf=ConfirmationClaim(jkt=thumbprint),
    )
    return AgentPrincipal(agent, task, credential, list(capabilities), claims)


def _runtime(tmp_path: Path) -> tuple[ToolGateway, MockMailbox]:
    for name in ("documents.json", "tickets.json", "database.json"):
        shutil.copyfile(PROJECT_ROOT / "synthetic_data" / name, tmp_path / name)
    (tmp_path / "sandbox").mkdir()
    mailbox = MockMailbox()
    return ToolGateway(ToolExecutionContext(tmp_path, mailbox)), mailbox


def _service(
    tmp_path: Path,
    settings: Settings,
    repository: FakeToolRepository,
    policy,
    *,
    registry: StaticToolRegistry = STATIC_TOOL_REGISTRY,
) -> tuple[ToolRequestService, MockMailbox]:
    gateway, mailbox = _runtime(tmp_path)
    return (
        ToolRequestService(
            repository=repository,
            registry=registry,
            gateway=gateway,
            policy_client=policy,
            settings=settings,
        ),
        mailbox,
    )


async def test_allowed_low_risk_request_is_encrypted_authorized_and_executed(
    tmp_path: Path,
    settings: Settings,
) -> None:
    repository = FakeToolRepository()
    policy = DeterministicPolicy()
    service, _ = _service(tmp_path, settings, repository, policy)
    principal = _principal("documents.search")

    outcome = await service.process(
        principal=principal,
        command=ToolRequestCommand(
            task_id=principal.task.id,
            tool_name="documents.search",
            arguments={"query": "VPN", "max_results": 2},
            request_size_bytes=100,
        ),
        correlation_id=uuid4(),
    )

    assert outcome.request.status is ToolRequestStatus.SUCCEEDED
    assert outcome.decision.decision is PolicyOutcome.ALLOW
    assert outcome.result is not None
    assert outcome.result["match_count"] == 1
    assert b"VPN" not in outcome.request.arguments_ciphertext
    assert outcome.request.result_summary is not None
    assert "matches" not in outcome.request.result_summary
    assert repository.decisions[outcome.request.id].input_hash.startswith("sha256:")
    assert policy.inputs[0].agent.id == principal.agent.id
    assert policy.inputs[0].task.owner_id == principal.task.owner_admin_id
    assert policy.inputs[0].token.proof_valid is True


async def test_unknown_missing_capability_and_invalid_arguments_never_dispatch(
    tmp_path: Path,
    settings: Settings,
) -> None:
    repository = FakeToolRepository()
    policy = DeterministicPolicy()
    service, mailbox = _service(tmp_path, settings, repository, policy)
    principal = _principal("documents.search")

    cases = [
        ("shell.exec", {}, "UNKNOWN_TOOL"),
        ("email.create_draft", _email_arguments(), "CAPABILITY_MISSING"),
        ("documents.search", {"query": "vpn", "unexpected": True}, "ARGUMENTS_INVALID"),
    ]
    for tool_name, arguments, reason in cases:
        outcome = await service.process(
            principal=principal,
            command=ToolRequestCommand(principal.task.id, tool_name, arguments, 100),
            correlation_id=uuid4(),
        )
        assert outcome.request.status is ToolRequestStatus.DENIED
        assert reason in outcome.decision.reason_codes
        assert outcome.result is None
    assert mailbox.draft_count == 0
    assert mailbox.sent_count == 0


async def test_service_rejects_cross_task_command_before_persistence(
    tmp_path: Path,
    settings: Settings,
) -> None:
    repository = FakeToolRepository()
    service, _ = _service(tmp_path, settings, repository, DeterministicPolicy())
    principal = _principal("documents.search")

    with pytest.raises(AgentGateError) as denied:
        await service.process(
            principal=principal,
            command=ToolRequestCommand(
                uuid4(),
                "documents.search",
                {"query": "vpn"},
                100,
            ),
            correlation_id=uuid4(),
        )
    assert denied.value.code == "CROSS_TASK_CREDENTIAL"
    assert repository.requests == {}


async def test_high_risk_request_stops_at_require_approval(
    tmp_path: Path,
    settings: Settings,
) -> None:
    repository = FakeToolRepository()
    service, mailbox = _service(tmp_path, settings, repository, DeterministicPolicy())
    principal = _principal("email.send")
    trusted_intent = repository.add_trusted_intent(principal)

    outcome = await service.process(
        principal=principal,
        command=ToolRequestCommand(
            principal.task.id,
            "email.send",
            _email_arguments(),
            200,
            [trusted_intent.id],
        ),
        correlation_id=uuid4(),
    )

    assert outcome.request.status is ToolRequestStatus.PENDING_APPROVAL
    assert outcome.decision.decision is PolicyOutcome.REQUIRE_APPROVAL
    assert outcome.approval is not None
    assert outcome.approval.argument_hash == outcome.request.argument_hash
    assert outcome.approval.expires_at > outcome.approval.created_at
    assert mailbox.sent_count == 0


async def test_rate_and_request_resource_limits_are_policy_denials(
    tmp_path: Path,
    settings: Settings,
) -> None:
    repository = FakeToolRepository()
    repository.rate_allowed = False
    service, _ = _service(tmp_path, settings, repository, DeterministicPolicy())
    principal = _principal("documents.search")
    rate_limited = await service.process(
        principal=principal,
        command=ToolRequestCommand(
            principal.task.id,
            "documents.search",
            {"query": "vpn"},
            100,
        ),
        correlation_id=uuid4(),
    )
    assert rate_limited.decision.reason_codes == ["RATE_LIMIT_EXCEEDED"]
    assert rate_limited.request.status is ToolRequestStatus.DENIED

    repository.rate_allowed = True
    oversized = await service.process(
        principal=principal,
        command=ToolRequestCommand(
            principal.task.id,
            "documents.search",
            {"query": "vpn"},
            5_000,
        ),
        correlation_id=uuid4(),
    )
    assert oversized.decision.reason_codes == ["RESOURCE_LIMIT_EXCEEDED"]


async def test_inconsistent_allow_cannot_bypass_pep_guards(
    tmp_path: Path,
    settings: Settings,
) -> None:
    repository = FakeToolRepository()
    service, mailbox = _service(tmp_path, settings, repository, AlwaysAllowPolicy())
    principal = _principal("email.send")

    outcome = await service.process(
        principal=principal,
        command=ToolRequestCommand(
            principal.task.id,
            "email.send",
            _email_arguments(),
            100,
        ),
        correlation_id=uuid4(),
    )

    assert outcome.decision.reason_codes == ["POLICY_ENGINE_ERROR"]
    assert outcome.request.status is ToolRequestStatus.DENIED
    assert mailbox.sent_count == 0


async def test_manifest_mismatch_is_unknown_and_cannot_dispatch(
    tmp_path: Path,
    settings: Settings,
) -> None:
    repository = FakeToolRepository()
    repository.registry["documents.search"].manifest_checksum = "0" * 64
    service, _ = _service(tmp_path, settings, repository, DeterministicPolicy())
    principal = _principal("documents.search")

    outcome = await service.process(
        principal=principal,
        command=ToolRequestCommand(
            principal.task.id,
            "documents.search",
            {"query": "vpn"},
            100,
        ),
        correlation_id=uuid4(),
    )
    assert outcome.decision.reason_codes == ["UNKNOWN_TOOL"]
    assert outcome.request.tool_registry_id is None


async def test_timeout_is_a_failed_execution_not_an_authorization_bypass(
    tmp_path: Path,
    settings: Settings,
) -> None:
    async def slow(arguments: BaseModel, context: ToolExecutionContext) -> BaseModel:
        del arguments, context
        await asyncio.sleep(0.05)
        return DocumentsSearchResult(matches=[], match_count=0, truncated=False)

    definition = ToolDefinition(
        name="test.slow",
        risk_tier=RiskTier.LOW,
        argument_model=DocumentsSearchArguments,
        result_model=DocumentsSearchResult,
        adapter=slow,
        limits=ToolLimits(0.001, 1_024, 1_024, 1),
    )
    registry = StaticToolRegistry([definition])
    repository = FakeToolRepository(registry)
    service, _ = _service(
        tmp_path,
        settings,
        repository,
        DeterministicPolicy(),
        registry=registry,
    )
    principal = _principal("test.slow")

    outcome = await service.process(
        principal=principal,
        command=ToolRequestCommand(
            principal.task.id,
            "test.slow",
            {"query": "vpn"},
            100,
        ),
        correlation_id=uuid4(),
    )
    assert outcome.decision.decision is PolicyOutcome.ALLOW
    assert outcome.request.status is ToolRequestStatus.FAILED
    assert outcome.request.error_code == "TOOL_TIMEOUT"


async def test_service_get_returns_persisted_sanitized_bundle(
    tmp_path: Path,
    settings: Settings,
) -> None:
    repository = FakeToolRepository()
    service, _ = _service(tmp_path, settings, repository, DeterministicPolicy())
    principal = _principal("documents.search")
    outcome = await service.process(
        principal=principal,
        command=ToolRequestCommand(
            principal.task.id,
            "documents.search",
            {"query": "vpn"},
            100,
        ),
        correlation_id=uuid4(),
    )
    bundle = await service.get(outcome.request.id)
    assert bundle is not None
    assert bundle.request.id == outcome.request.id
    assert bundle.decision is repository.decisions[outcome.request.id]
    assert await service.get(uuid4()) is None


def _email_arguments() -> dict[str, object]:
    return {
        "recipient": "student@example.test",
        "subject": "Synthetic message",
        "body": "No real delivery.",
    }
