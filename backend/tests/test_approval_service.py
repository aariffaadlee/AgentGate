"""Phase 4 exact binding, expiry, replay, and substitution security tests."""

import asyncio
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from app.api.errors import AgentGateError
from app.auth.crypto import EnvelopeCipher, canonical_json
from app.auth.tokens import AdminTokenClaims
from app.config import Settings
from app.db.base import utc_now
from app.models.approval import ApprovalAction
from app.models.enums import (
    AdministratorStatus,
    ApprovalStatus,
    ToolRequestStatus,
)
from app.models.identity import Administrator
from app.models.policy import PolicyDecision
from app.models.tool import ToolRequest
from app.services.approvals import (
    ApprovalBundle,
    ApprovalNotFoundError,
    ApprovalRecord,
    ApprovalService,
    LockedApproval,
)
from app.services.identity import AdminPrincipal, AgentPrincipal
from app.services.tools import ToolRequestCommand, ToolRequestService
from app.tools.registry import STATIC_TOOL_REGISTRY
from tests.test_tool_service import (
    DeterministicPolicy,
    FakeToolRepository,
    _email_arguments,
    _principal,
    _runtime,
)


class FakeLockedApproval:
    def __init__(self, repository: "FakeApprovalRepository", approval_id: UUID) -> None:
        self._repository = repository
        self._approval_id = approval_id
        self._bundle: ApprovalBundle | None = None

    @property
    def bundle(self) -> ApprovalBundle:
        if self._bundle is None:
            raise RuntimeError("approval lock not entered")
        return self._bundle

    async def __aenter__(self) -> LockedApproval:
        lock = self._repository.locks.setdefault(self._approval_id, asyncio.Lock())
        await lock.acquire()
        approval = self._repository.tools.approvals.get(self._approval_id)
        if approval is None:
            lock.release()
            raise ApprovalNotFoundError
        request = self._repository.tools.requests[approval.tool_request_id]
        registry_tool = self._repository.tools.registry.get(request.tool_name)
        principal = self._repository.principal
        self._bundle = ApprovalBundle(
            approval=approval,
            request=request,
            decision=self._repository.tools.decisions.get(request.id),
            registry_tool=registry_tool,
            credential=principal.credential,
            agent=principal.agent,
            task=principal.task,
            capabilities=list(principal.capabilities),
            revoked=self._repository.revoked,
            influences=[
                self._repository.tools.provenance[record_id]
                for record_id in self._repository.tools.influences.get(request.id, [])
            ],
        )
        return self

    async def __aexit__(self, exc_type, exc_value, traceback) -> None:
        del exc_type, exc_value, traceback
        self._repository.locks[self._approval_id].release()

    def add_action(self, action: ApprovalAction) -> None:
        self._repository.actions.append(action)

    def add_policy_decision(self, decision: PolicyDecision) -> None:
        self._repository.tools.decisions[decision.tool_request_id] = decision


class FakeApprovalRepository:
    def __init__(self, tools: FakeToolRepository, principal: AgentPrincipal) -> None:
        self.tools = tools
        self.principal = principal
        self.revoked = False
        self.actions: list[ApprovalAction] = []
        self.locks: dict[UUID, asyncio.Lock] = {}

    def lock(self, approval_id: UUID) -> FakeLockedApproval:
        return FakeLockedApproval(self, approval_id)

    async def list_approvals(self, now: datetime) -> Sequence[ApprovalRecord]:
        records: list[ApprovalRecord] = []
        for approval in self.tools.approvals.values():
            request = self.tools.requests[approval.tool_request_id]
            if approval.status is ApprovalStatus.PENDING and approval.expires_at <= now:
                approval.status = ApprovalStatus.EXPIRED
                approval.row_version += 1
                request.status = ToolRequestStatus.DENIED
                request.error_code = "APPROVAL_EXPIRED"
                request.completed_at = now
            records.append(ApprovalRecord(approval, request, self.tools.decisions.get(request.id)))
        return records

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
        produced_provenance,
    ) -> ToolRequest:
        return await self.tools.finish_tool_request(
            request,
            status=status,
            error_code=error_code,
            response_size_bytes=response_size_bytes,
            result_summary=result_summary,
            execution_latency_ms=execution_latency_ms,
            completed_at=completed_at,
            produced_provenance=produced_provenance,
        )


def _administrator(*, active: bool = True) -> AdminPrincipal:
    now = utc_now().replace(microsecond=0)
    administrator = Administrator(
        id=uuid4(),
        username="approval-admin",
        credential_hash="scrypt$redacted",
        status=(AdministratorStatus.ACTIVE if active else AdministratorStatus.DISABLED),
        created_at=now,
        updated_at=now,
    )
    claims = AdminTokenClaims(
        iss="agentgate.local",
        aud="agentgate-admin",
        sub=administrator.id,
        role="administrator",
        jti=uuid4(),
        iat=int(now.timestamp()),
        nbf=int(now.timestamp()),
        exp=int((now + timedelta(minutes=15)).timestamp()),
    )
    return AdminPrincipal(administrator, claims)


async def _approval_runtime(
    tmp_path: Path,
    settings: Settings,
) -> tuple[
    ApprovalService,
    FakeApprovalRepository,
    DeterministicPolicy,
    object,
    ApprovalRecord,
]:
    gateway, mailbox = _runtime(tmp_path)
    tools = FakeToolRepository()
    policy = DeterministicPolicy()
    principal = _principal("email.send")
    trusted_intent = tools.add_trusted_intent(principal)
    request_service = ToolRequestService(
        repository=tools,
        registry=STATIC_TOOL_REGISTRY,
        gateway=gateway,
        policy_client=policy,
        settings=settings,
    )
    pending = await request_service.process(
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
    assert pending.approval is not None
    repository = FakeApprovalRepository(tools, principal)
    service = ApprovalService(
        repository=repository,
        registry=STATIC_TOOL_REGISTRY,
        gateway=gateway,
        policy_client=policy,
        settings=settings,
    )
    return (
        service,
        repository,
        policy,
        mailbox,
        ApprovalRecord(
            pending.approval,
            pending.request,
            tools.decisions[pending.request.id],
        ),
    )


async def test_exact_approval_re_evaluates_policy_consumes_and_executes_original(
    tmp_path: Path,
    settings: Settings,
) -> None:
    service, repository, policy, mailbox, pending = await _approval_runtime(tmp_path, settings)

    completed = await service.approve(
        approval_id=pending.approval.id,
        expected_argument_hash=pending.approval.argument_hash,
        administrator=_administrator(),
        reason="Exact synthetic action confirmed.",
    )

    assert completed.approval.status is ApprovalStatus.CONSUMED
    assert completed.approval.consumed_at is not None
    assert completed.request.status is ToolRequestStatus.SUCCEEDED
    assert completed.request.result_summary is not None
    assert completed.request.result_summary["status"] == "sent"
    assert mailbox.sent_count == 1
    assert len(policy.inputs) == 2
    assert policy.inputs[-1].approval.status == "approved"
    assert policy.inputs[-1].approval.argument_hash == pending.approval.argument_hash
    assert len(repository.actions) == 1


async def test_one_character_hash_change_never_authorizes_or_dispatches(
    tmp_path: Path,
    settings: Settings,
) -> None:
    service, _repository, policy, mailbox, pending = await _approval_runtime(tmp_path, settings)
    original = pending.approval.argument_hash
    changed = original[:-1] + ("0" if original[-1] != "0" else "1")

    with pytest.raises(AgentGateError) as denied:
        await service.approve(
            approval_id=pending.approval.id,
            expected_argument_hash=changed,
            administrator=_administrator(),
            reason=None,
        )

    assert denied.value.code == "APPROVAL_ARGUMENT_MISMATCH"
    assert pending.approval.status is ApprovalStatus.PENDING
    assert mailbox.sent_count == 0
    assert len(policy.inputs) == 1


async def test_one_character_argument_substitution_after_pending_is_detected(
    tmp_path: Path,
    settings: Settings,
) -> None:
    service, _repository, policy, mailbox, pending = await _approval_runtime(tmp_path, settings)
    changed_arguments = _email_arguments()
    changed_arguments["body"] = "No real delivery!"  # one-character substitution
    cipher = EnvelopeCipher(settings.data_encryption_key_bytes)
    ciphertext, nonce = cipher.encrypt(
        canonical_json(changed_arguments),
        associated_data=b"agentgate:tool-request:" + pending.request.id.bytes,
    )
    pending.request.arguments_ciphertext = ciphertext
    pending.request.arguments_nonce = nonce

    with pytest.raises(AgentGateError) as denied:
        await service.approve(
            approval_id=pending.approval.id,
            expected_argument_hash=pending.approval.argument_hash,
            administrator=_administrator(),
            reason=None,
        )

    assert denied.value.code == "APPROVAL_ARGUMENT_MISMATCH"
    assert pending.approval.status is ApprovalStatus.PENDING
    assert mailbox.sent_count == 0
    assert len(policy.inputs) == 1


async def test_expired_and_rejected_approvals_never_execute(
    tmp_path: Path,
    settings: Settings,
) -> None:
    service, _repository, _policy, mailbox, pending = await _approval_runtime(tmp_path, settings)
    pending.approval.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    with pytest.raises(AgentGateError) as expired:
        await service.approve(
            approval_id=pending.approval.id,
            expected_argument_hash=pending.approval.argument_hash,
            administrator=_administrator(),
            reason=None,
        )
    assert expired.value.code == "APPROVAL_EXPIRED"
    assert pending.approval.status is ApprovalStatus.EXPIRED
    assert mailbox.sent_count == 0

    other_path = tmp_path / "rejected"
    other_path.mkdir()
    service, repository, _policy, mailbox, pending = await _approval_runtime(other_path, settings)
    rejected = await service.reject(
        approval_id=pending.approval.id,
        administrator=_administrator(),
        reason="Not intended.",
    )
    assert rejected.approval.status is ApprovalStatus.REJECTED
    assert rejected.request.status is ToolRequestStatus.DENIED
    assert len(repository.actions) == 1
    assert mailbox.sent_count == 0


async def test_concurrent_approval_has_one_winner_and_replay_is_rejected(
    tmp_path: Path,
    settings: Settings,
) -> None:
    service, _repository, _policy, mailbox, pending = await _approval_runtime(tmp_path, settings)

    async def approve_once() -> ApprovalRecord:
        return await service.approve(
            approval_id=pending.approval.id,
            expected_argument_hash=pending.approval.argument_hash,
            administrator=_administrator(),
            reason=None,
        )

    results = await asyncio.gather(approve_once(), approve_once(), return_exceptions=True)
    successes = [result for result in results if isinstance(result, ApprovalRecord)]
    failures = [result for result in results if isinstance(result, AgentGateError)]
    assert len(successes) == 1
    assert len(failures) == 1
    assert failures[0].code == "APPROVAL_REPLAYED"
    assert mailbox.sent_count == 1


async def test_only_active_administrator_can_list_or_decide(
    tmp_path: Path,
    settings: Settings,
) -> None:
    service, _repository, _policy, mailbox, pending = await _approval_runtime(tmp_path, settings)
    with pytest.raises(AgentGateError) as denied:
        await service.approve(
            approval_id=pending.approval.id,
            expected_argument_hash=pending.approval.argument_hash,
            administrator=_administrator(active=False),
            reason=None,
        )
    assert denied.value.code == "ADMINISTRATOR_INACTIVE"
    assert mailbox.sent_count == 0

    records = await service.list_records(_administrator())
    assert len(records) == 1
    assert records[0].approval.id == pending.approval.id
