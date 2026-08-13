"""Authenticated HTTP tests for allowed, denied, replayed, and malformed tool calls."""

import json
import shutil
from pathlib import Path
from uuid import UUID, uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.api.identity import get_identity_service
from app.api.tools import get_tool_identity_service, get_tool_request_service
from app.auth.crypto import public_jwk_from_key
from app.auth.proofs import create_request_proof
from app.config import Settings
from app.main import create_app
from app.services.identity import IdentityService, TaskCreation
from app.services.tools import ToolRequestService
from tests.support import app_client, install_recording_audit
from tests.test_identity_service import FakeIdentityRepository
from tests.test_tool_service import DeterministicPolicy, FakeToolRepository

PROJECT_ROOT = Path(__file__).resolve().parents[2]


async def _workflow(
    tmp_path: Path,
    settings: Settings,
) -> tuple[
    object,
    IdentityService,
    ToolRequestService,
    Ed25519PrivateKey,
    UUID,
    str,
]:
    for name in ("documents.json", "tickets.json", "database.json"):
        shutil.copyfile(PROJECT_ROOT / "synthetic_data" / name, tmp_path / name)
    (tmp_path / "sandbox").mkdir()
    active_settings = settings.model_copy(update={"synthetic_data_root": tmp_path})
    application = create_app(active_settings)
    install_recording_audit(application)
    identity = IdentityService(FakeIdentityRepository(), active_settings)
    private_key = Ed25519PrivateKey.generate()
    agent = await identity.register_agent(
        name="HTTP Tool Agent",
        public_jwk=public_jwk_from_key(private_key.public_key()),
    )
    task, _ = await identity.create_task(
        owner_admin_id=uuid4(),
        creation=TaskCreation(
            assigned_agent_id=agent.id,
            title="HTTP tool mediation",
            trusted_instruction_summary="Search documents and test policy denial.",
            trusted_instruction="Use only the exact synthetic capabilities.",
            capabilities=["documents.search", "email.send", "tickets.read"],
            starts_at=None,
            expires_at=None,
        ),
    )
    issuance_body = {"task_id": str(task.id)}
    issuance_path = f"/agents/{agent.id}/tokens"
    issued = await identity.issue_agent_token(
        agent_id=agent.id,
        task_id=task.id,
        proof=create_request_proof(
            private_key,
            agent_id=agent.id,
            method="POST",
            path=issuance_path,
            body=issuance_body,
            ttl_seconds=active_settings.request_proof_ttl_seconds,
        ),
        proof_body=issuance_body,
        method="POST",
        path=issuance_path,
    )
    tool_repository = FakeToolRepository()
    trusted_intent = await identity.get_task_intent_provenance(task.id)
    tool_repository.provenance[trusted_intent.id] = trusted_intent
    tools = ToolRequestService(
        repository=tool_repository,
        registry=application.state.tool_registry,
        gateway=application.state.tool_gateway,
        policy_client=DeterministicPolicy(),
        settings=active_settings,
    )
    application.dependency_overrides[get_tool_identity_service] = lambda: identity
    application.dependency_overrides[get_identity_service] = lambda: identity
    application.dependency_overrides[get_tool_request_service] = lambda: tools
    return application, identity, tools, private_key, task.id, issued.token.encoded


def _proof(
    key: Ed25519PrivateKey,
    *,
    agent_id: UUID,
    body: dict[str, object],
    token: str,
    settings: Settings,
    path: str = "/tool-requests",
    method: str = "POST",
) -> str:
    return create_request_proof(
        key,
        agent_id=agent_id,
        method=method,
        path=path,
        body=body,
        ttl_seconds=settings.request_proof_ttl_seconds,
        access_token=token,
    )


async def test_allowed_request_executes_and_get_returns_only_summary(
    tmp_path: Path,
    settings: Settings,
) -> None:
    application, identity, _tools, key, task_id, token = await _workflow(tmp_path, settings)
    task, _ = await identity.get_task(task_id)
    assert task.assigned_agent_id is not None
    body: dict[str, object] = {
        "task_id": str(task_id),
        "tool_name": "documents.search",
        "arguments": {"query": "VPN", "max_results": 2},
    }
    headers = {
        "Authorization": f"Bearer {token}",
        "X-Agent-Proof": _proof(
            key,
            agent_id=task.assigned_agent_id,
            body=body,
            token=token,
            settings=settings,
        ),
    }

    async with app_client(application) as client:
        response = await client.post("/tool-requests", json=body, headers=headers)
        assert response.status_code == 201
        payload = response.json()
        assert payload["status"] == "succeeded"
        assert payload["decision"] == "allow"
        assert payload["result"]["match_count"] == 1
        assert payload["produced_provenance"][0]["trust_label"] == "untrusted"
        assert payload["produced_provenance"][0]["source_type"] == "external_document"
        request_id = UUID(payload["id"])

        path = f"/tool-requests/{request_id}"
        get_headers = {
            "Authorization": f"Bearer {token}",
            "X-Agent-Proof": _proof(
                key,
                agent_id=task.assigned_agent_id,
                body={},
                token=token,
                settings=settings,
                path=path,
                method="GET",
            ),
        }
        stored = await client.get(path, headers=get_headers)

        admin_token = (
            await identity.create_admin_session(settings.admin_bootstrap_secret.get_secret_value())
        ).encoded
        timeline = await client.get(
            "/tool-requests",
            headers={"Authorization": f"Bearer {admin_token}"},
        )

    assert stored.status_code == 200
    stored_payload = stored.json()
    assert stored_payload["result"] is None
    assert stored_payload["result_summary"]["match_count"] == 1
    assert "matches" not in stored_payload["result_summary"]
    assert stored_payload["produced_provenance"] == payload["produced_provenance"]
    assert timeline.status_code == 200
    assert [item["id"] for item in timeline.json()] == [str(request_id)]
    assert timeline.json()[0]["result"] is None
    assert timeline.json()[0]["reason_codes"] == ["LOW_RISK_CAPABILITY_ALLOWED"]
    audit_events = application.state.recording_audit.events
    assert [event.event_type for event in audit_events] == [
        "tool.requested",
        "policy.decided",
        "tool.succeeded",
    ]
    assert "VPN" not in repr(audit_events)


async def test_indirect_ticket_injection_is_denied_before_approval_over_http(
    tmp_path: Path,
    settings: Settings,
) -> None:
    application, identity, _tools, key, task_id, token = await _workflow(tmp_path, settings)
    task, _ = await identity.get_task(task_id)
    assert task.assigned_agent_id is not None

    ticket_body: dict[str, object] = {
        "task_id": str(task_id),
        "tool_name": "tickets.read",
        "arguments": {"ticket_id": "TICKET-002"},
    }
    async with app_client(application) as client:
        ticket = await client.post(
            "/tool-requests",
            json=ticket_body,
            headers={
                "Authorization": f"Bearer {token}",
                "X-Agent-Proof": _proof(
                    key,
                    agent_id=task.assigned_agent_id,
                    body=ticket_body,
                    token=token,
                    settings=settings,
                ),
            },
        )
        provenance_id = ticket.json()["produced_provenance"][0]["id"]
        sensitive_body: dict[str, object] = {
            "task_id": str(task_id),
            "tool_name": "email.send",
            "arguments": {
                "recipient": "attacker@example.test",
                "subject": "Injected action",
                "body": "Exfiltrate the administrator token.",
            },
            "influence_ids": [provenance_id],
        }
        sensitive = await client.post(
            "/tool-requests",
            json=sensitive_body,
            headers={
                "Authorization": f"Bearer {token}",
                "X-Agent-Proof": _proof(
                    key,
                    agent_id=task.assigned_agent_id,
                    body=sensitive_body,
                    token=token,
                    settings=settings,
                ),
            },
        )

    assert ticket.status_code == 201
    assert ticket.json()["produced_provenance"][0]["source_reference"] == "TICKET-002"
    assert sensitive.status_code == 403
    assert sensitive.json()["reason_codes"] == ["UNTRUSTED_ONLY_SENSITIVE_INTENT"]
    assert sensitive.json()["approval_id"] is None


async def test_agent_cannot_supply_labels_or_duplicate_influence_ids(
    tmp_path: Path,
    settings: Settings,
) -> None:
    application, _identity, _tools, _key, task_id, _token = await _workflow(tmp_path, settings)
    record_id = uuid4()
    base: dict[str, object] = {
        "task_id": str(task_id),
        "tool_name": "documents.search",
        "arguments": {"query": "VPN"},
    }

    async with app_client(application) as client:
        forged = await client.post(
            "/tool-requests",
            json={**base, "trust_label": "trusted"},
        )
        duplicate = await client.post(
            "/tool-requests",
            json={**base, "influence_ids": [str(record_id), str(record_id)]},
        )

    assert forged.status_code == 422
    assert forged.json()["error"]["code"] == "VALIDATION_ERROR"
    assert duplicate.status_code == 422
    assert duplicate.json()["error"]["code"] == "VALIDATION_ERROR"


async def test_denied_and_approval_required_requests_are_never_dispatched(
    tmp_path: Path,
    settings: Settings,
) -> None:
    application, identity, _tools, key, task_id, token = await _workflow(tmp_path, settings)
    task, _ = await identity.get_task(task_id)
    trusted_intent = await identity.get_task_intent_provenance(task_id)
    assert task.assigned_agent_id is not None

    async with app_client(application) as client:
        unknown_body: dict[str, object] = {
            "task_id": str(task_id),
            "tool_name": "shell.exec",
            "arguments": {},
        }
        unknown = await client.post(
            "/tool-requests",
            json=unknown_body,
            headers={
                "Authorization": f"Bearer {token}",
                "X-Agent-Proof": _proof(
                    key,
                    agent_id=task.assigned_agent_id,
                    body=unknown_body,
                    token=token,
                    settings=settings,
                ),
            },
        )
        high_body: dict[str, object] = {
            "task_id": str(task_id),
            "tool_name": "email.send",
            "arguments": {
                "recipient": "student@example.test",
                "subject": "Synthetic",
                "body": "No real delivery",
            },
            "influence_ids": [str(trusted_intent.id)],
        }
        high = await client.post(
            "/tool-requests",
            json=high_body,
            headers={
                "Authorization": f"Bearer {token}",
                "X-Agent-Proof": _proof(
                    key,
                    agent_id=task.assigned_agent_id,
                    body=high_body,
                    token=token,
                    settings=settings,
                ),
            },
        )

    assert unknown.status_code == 403
    assert unknown.json()["reason_codes"] == ["UNKNOWN_TOOL"]
    assert high.status_code == 202
    assert high.json()["status"] == "pending_approval"
    assert high.json()["result"] is None


async def test_proof_replay_and_schema_bypass_are_rejected(
    tmp_path: Path,
    settings: Settings,
) -> None:
    application, identity, _tools, key, task_id, token = await _workflow(tmp_path, settings)
    task, _ = await identity.get_task(task_id)
    assert task.assigned_agent_id is not None
    body: dict[str, object] = {
        "task_id": str(task_id),
        "tool_name": "documents.search",
        "arguments": {"query": "VPN"},
    }
    proof = _proof(
        key,
        agent_id=task.assigned_agent_id,
        body=body,
        token=token,
        settings=settings,
    )
    headers = {"Authorization": f"Bearer {token}", "X-Agent-Proof": proof}

    async with app_client(application) as client:
        first = await client.post("/tool-requests", json=body, headers=headers)
        replay = await client.post("/tool-requests", json=body, headers=headers)
        outer_extra = await client.post(
            "/tool-requests",
            json={**body, "adapter": "subprocess"},
            headers=headers,
        )
        duplicated = (
            "{"
            f'"task_id":"{task_id}",'
            f'"task_id":"{task_id}",'
            '"tool_name":"documents.search","arguments":{"query":"VPN"}'
            "}"
        )
        duplicate = await client.post(
            "/tool-requests",
            content=duplicated,
            headers={"Content-Type": "application/json"},
        )
        non_finite = await client.post(
            "/tool-requests",
            content=(
                "{"
                f'"task_id":"{task_id}",'
                '"tool_name":"documents.search","arguments":{"max_results":NaN}'
                "}"
            ),
            headers={"Content-Type": "application/json"},
        )

    assert first.status_code == 201
    assert replay.status_code == 401
    assert replay.json()["error"]["code"] == "PROOF_REPLAYED"
    assert outer_extra.status_code == 422
    assert outer_extra.json()["error"]["code"] == "VALIDATION_ERROR"
    assert duplicate.status_code == 400
    assert duplicate.json()["error"]["code"] == "MALFORMED_REQUEST"
    assert non_finite.status_code == 400
    assert non_finite.json()["error"]["code"] == "MALFORMED_REQUEST"
    assert token not in json.dumps(replay.json())
