"""Administrator-only HTTP contract tests for Phase 4 approvals."""

from pathlib import Path
from uuid import UUID, uuid4

from app.api.approvals import get_approval_service
from app.api.identity import get_identity_service
from app.auth.tokens import TokenService
from app.config import Settings
from app.main import create_app
from app.services.approvals import ApprovalService
from app.services.identity import IdentityService
from app.services.tools import ToolRequestCommand, ToolRequestService
from tests.support import app_client, install_recording_audit
from tests.test_approval_service import FakeApprovalRepository
from tests.test_identity_service import FakeIdentityRepository
from tests.test_tool_service import (
    DeterministicPolicy,
    FakeToolRepository,
    _email_arguments,
    _principal,
    _runtime,
)


async def _pending_application(tmp_path: Path, settings: Settings):
    active_settings = settings.model_copy(update={"synthetic_data_root": tmp_path})
    application = create_app(active_settings)
    install_recording_audit(application)
    gateway, mailbox = _runtime(tmp_path)
    policy = DeterministicPolicy()
    tools = FakeToolRepository()
    principal = _principal("email.send")
    trusted_intent = tools.add_trusted_intent(principal)
    tool_service = ToolRequestService(
        repository=tools,
        registry=application.state.tool_registry,
        gateway=gateway,
        policy_client=policy,
        settings=active_settings,
    )
    pending = await tool_service.process(
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

    approval_service = ApprovalService(
        repository=FakeApprovalRepository(tools, principal),
        registry=application.state.tool_registry,
        gateway=gateway,
        policy_client=policy,
        settings=active_settings,
    )
    identity = IdentityService(FakeIdentityRepository(), active_settings)
    admin = await identity.create_admin_session(
        active_settings.admin_bootstrap_secret.get_secret_value()
    )
    workload = TokenService(active_settings).issue_workload_token(
        agent_id=principal.agent.id,
        task_id=principal.task.id,
        capabilities=principal.capabilities,
        key_thumbprint=principal.agent.key_thumbprint,
    )
    application.dependency_overrides[get_identity_service] = lambda: identity
    application.dependency_overrides[get_approval_service] = lambda: approval_service
    return application, pending, admin.encoded, workload.encoded, mailbox


async def test_admin_lists_confirms_exact_hash_and_replay_is_rejected(
    tmp_path: Path,
    settings: Settings,
) -> None:
    application, pending, admin_token, workload_token, mailbox = await _pending_application(
        tmp_path, settings
    )
    approval = pending.approval
    assert approval is not None
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    async with app_client(application) as client:
        unauthenticated = await client.get("/approvals")
        wrong_audience = await client.get(
            "/approvals",
            headers={"Authorization": f"Bearer {workload_token}"},
        )
        listed = await client.get("/approvals", headers=admin_headers)
        payload = listed.json()[0]
        assert "No real delivery" not in str(payload)
        changed_hash = approval.argument_hash[:-1] + (
            "0" if approval.argument_hash[-1] != "0" else "1"
        )
        mismatch = await client.post(
            f"/approvals/{approval.id}/approve",
            json={"argument_hash": changed_hash},
            headers=admin_headers,
        )
        approved = await client.post(
            f"/approvals/{approval.id}/approve",
            json={"argument_hash": approval.argument_hash},
            headers=admin_headers,
        )
        replay = await client.post(
            f"/approvals/{approval.id}/approve",
            json={"argument_hash": approval.argument_hash},
            headers=admin_headers,
        )

    assert unauthenticated.status_code == 401
    assert wrong_audience.status_code == 401
    assert listed.status_code == 200
    assert UUID(payload["id"]) == approval.id
    assert payload["argument_hash"] == approval.argument_hash
    assert payload["redacted_arguments"]["fields"] == ["body", "recipient", "subject"]
    assert mismatch.status_code == 409
    assert mismatch.json()["error"]["code"] == "APPROVAL_ARGUMENT_MISMATCH"
    assert approved.status_code == 200
    assert approved.json()["status"] == "consumed"
    assert approved.json()["tool_request_status"] == "succeeded"
    assert approved.json()["decision"] == "allow"
    assert replay.status_code == 409
    assert replay.json()["error"]["code"] == "APPROVAL_REPLAYED"
    assert mailbox.sent_count == 1
    assert [event.event_type for event in application.state.recording_audit.events] == [
        "approval.consumed",
        "policy.decided",
        "tool.succeeded",
    ]


async def test_admin_rejection_is_terminal_and_never_dispatches(
    tmp_path: Path,
    settings: Settings,
) -> None:
    application, pending, admin_token, _workload_token, mailbox = await _pending_application(
        tmp_path, settings
    )
    approval = pending.approval
    assert approval is not None
    headers = {"Authorization": f"Bearer {admin_token}"}

    async with app_client(application) as client:
        rejected = await client.post(
            f"/approvals/{approval.id}/reject",
            json={"reason": "The message was not intended."},
            headers=headers,
        )
        later_approval = await client.post(
            f"/approvals/{approval.id}/approve",
            json={"argument_hash": approval.argument_hash},
            headers=headers,
        )

    assert rejected.status_code == 200
    assert rejected.json()["status"] == "rejected"
    assert rejected.json()["tool_request_status"] == "denied"
    assert later_approval.status_code == 409
    assert later_approval.json()["error"]["code"] == "APPROVAL_REJECTED"
    assert mailbox.sent_count == 0
    assert [event.event_type for event in application.state.recording_audit.events] == [
        "approval.rejected",
        "tool.denied",
    ]
