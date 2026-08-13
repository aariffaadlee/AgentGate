"""Phase 2 REST workflow and strict-schema tests without a live database."""

from uuid import UUID, uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.api.identity import get_identity_service
from app.auth.crypto import public_jwk_from_key
from app.auth.proofs import create_request_proof
from app.config import Settings
from app.main import create_app
from app.services.identity import IdentityService
from tests.support import app_client, install_recording_audit
from tests.test_identity_service import FakeIdentityRepository


async def test_administrator_registration_task_and_agent_token_workflow(
    settings: Settings,
) -> None:
    repository = FakeIdentityRepository()
    service = IdentityService(repository, settings)
    application = create_app(settings)
    install_recording_audit(application)
    application.dependency_overrides[get_identity_service] = lambda: service
    private_key = Ed25519PrivateKey.generate()

    async with app_client(application) as client:
        admin_session = await client.post(
            "/admin/session",
            json={
                "bootstrap_secret": settings.admin_bootstrap_secret.get_secret_value(),
            },
        )
        assert admin_session.status_code == 200
        admin_token = admin_session.json()["access_token"]
        admin_headers = {"Authorization": f"Bearer {admin_token}"}

        registration = await client.post(
            "/agents",
            headers=admin_headers,
            json={
                "name": "Portfolio Demo Agent",
                "public_jwk": public_jwk_from_key(private_key.public_key()).model_dump(),
            },
        )
        assert registration.status_code == 201
        agent = registration.json()
        assert "public_jwk" not in agent
        assert "credential" not in registration.text.lower()
        agent_id = UUID(agent["id"])

        task_response = await client.post(
            "/tasks",
            headers=admin_headers,
            json={
                "assigned_agent_id": str(agent_id),
                "title": "Read one synthetic ticket",
                "trusted_instruction_summary": "Read and summarize ticket TICKET-001.",
                "trusted_instruction": "Read only TICKET-001 and return a short summary.",
                "capabilities": ["tickets.read"],
            },
        )
        assert task_response.status_code == 201
        task = task_response.json()
        assert "trusted_instruction" not in task
        assert task["capabilities"] == ["tickets.read"]
        task_id = UUID(task["id"])

        issuance_body = {"task_id": str(task_id)}
        issuance_path = f"/agents/{agent_id}/tokens"
        issuance_proof = create_request_proof(
            private_key,
            agent_id=agent_id,
            method="POST",
            path=issuance_path,
            body=issuance_body,
            ttl_seconds=settings.request_proof_ttl_seconds,
        )
        token_response = await client.post(
            issuance_path,
            headers={"X-Agent-Proof": issuance_proof},
            json=issuance_body,
        )
        assert token_response.status_code == 201
        token_payload = token_response.json()
        assert token_payload["expires_in"] == settings.access_token_ttl_seconds
        assert token_payload["capabilities"] == ["tickets.read"]
        workload_token = token_payload["access_token"]

        task_path = f"/tasks/{task_id}"
        task_proof = create_request_proof(
            private_key,
            agent_id=agent_id,
            method="GET",
            path=task_path,
            body={},
            ttl_seconds=settings.request_proof_ttl_seconds,
            access_token=workload_token,
        )
        workload_view = await client.get(
            task_path,
            headers={
                "Authorization": f"Bearer {workload_token}",
                "X-Agent-Proof": task_proof,
            },
        )
        assert workload_view.status_code == 200
        assert workload_view.json()["id"] == str(task_id)

        agents = await client.get("/agents", headers=admin_headers)
        assert agents.status_code == 200
        assert [item["id"] for item in agents.json()] == [str(agent_id)]

        tasks = await client.get("/tasks", headers=admin_headers)
        assert tasks.status_code == 200
        assert [item["id"] for item in tasks.json()] == [str(task_id)]
        assert tasks.json()[0]["capabilities"] == ["tickets.read"]
        assert "Read only TICKET-001 and return a short summary." not in tasks.text

    audit_events = application.state.recording_audit.events
    assert [event.event_type for event in audit_events] == [
        "identity.admin_session_issued",
        "identity.agent_registered",
        "task.created",
        "identity.credential_issued",
    ]
    audit_text = repr(audit_events)
    assert settings.admin_bootstrap_secret.get_secret_value() not in audit_text
    assert workload_token not in audit_text
    assert "Read only TICKET-001" not in audit_text


async def test_identity_endpoints_enforce_admin_separation_and_extra_field_rejection(
    settings: Settings,
) -> None:
    repository = FakeIdentityRepository()
    service = IdentityService(repository, settings)
    application = create_app(settings)
    install_recording_audit(application)
    application.dependency_overrides[get_identity_service] = lambda: service
    private_key = Ed25519PrivateKey.generate()

    async with app_client(application) as client:
        unauthenticated = await client.post(
            "/agents",
            json={
                "name": "Unauthorized Agent",
                "public_jwk": public_jwk_from_key(private_key.public_key()).model_dump(),
            },
        )
        assert unauthenticated.status_code == 401
        assert unauthenticated.json()["error"]["code"] == "UNAUTHENTICATED"

        secret = "do-not-reflect-this-bootstrap-secret-value"
        extra_field = await client.post(
            "/admin/session",
            json={"bootstrap_secret": secret, "role": "administrator"},
        )
        assert extra_field.status_code == 422
        assert extra_field.json()["error"]["code"] == "VALIDATION_ERROR"
        assert secret not in extra_field.text


async def test_revocation_invalidates_workload_token_through_api(settings: Settings) -> None:
    repository = FakeIdentityRepository()
    service = IdentityService(repository, settings)
    application = create_app(settings)
    install_recording_audit(application)
    application.dependency_overrides[get_identity_service] = lambda: service
    private_key = Ed25519PrivateKey.generate()

    async with app_client(application) as client:
        session = await client.post(
            "/admin/session",
            json={"bootstrap_secret": settings.admin_bootstrap_secret.get_secret_value()},
        )
        admin_token = session.json()["access_token"]
        admin_headers = {"Authorization": f"Bearer {admin_token}"}
        registration = await client.post(
            "/agents",
            headers=admin_headers,
            json={
                "name": "Revocable Agent",
                "public_jwk": public_jwk_from_key(private_key.public_key()).model_dump(),
            },
        )
        agent_id = UUID(registration.json()["id"])
        task = await client.post(
            "/tasks",
            headers=admin_headers,
            json={
                "assigned_agent_id": str(agent_id),
                "title": "Revocation test task",
                "trusted_instruction_summary": "Read a ticket before revocation.",
                "trusted_instruction": "Read TICKET-001.",
                "capabilities": ["tickets.read"],
            },
        )
        task_id = UUID(task.json()["id"])
        body = {"task_id": str(task_id)}
        issuance_path = f"/agents/{agent_id}/tokens"
        token = await client.post(
            issuance_path,
            json=body,
            headers={
                "X-Agent-Proof": create_request_proof(
                    private_key,
                    agent_id=agent_id,
                    method="POST",
                    path=issuance_path,
                    body=body,
                    ttl_seconds=settings.request_proof_ttl_seconds,
                )
            },
        )
        encoded_token = token.json()["access_token"]

        revoked = await client.post(
            f"/agents/{agent_id}/revoke",
            headers=admin_headers,
            json={"reason_code": "KEY_COMPROMISE", "reason": "Synthetic exercise"},
        )
        assert revoked.status_code == 200
        assert revoked.json()["status"] == "revoked"

        task_path = f"/tasks/{task_id}"
        denied = await client.get(
            task_path,
            headers={
                "Authorization": f"Bearer {encoded_token}",
                "X-Agent-Proof": create_request_proof(
                    private_key,
                    agent_id=agent_id,
                    method="GET",
                    path=task_path,
                    body={},
                    ttl_seconds=settings.request_proof_ttl_seconds,
                    access_token=encoded_token,
                ),
            },
        )
        assert denied.status_code == 401
        assert denied.json()["error"]["code"] == "CREDENTIAL_REVOKED"
        assert encoded_token not in denied.text


async def test_token_issuance_rejects_missing_or_malformed_proof(settings: Settings) -> None:
    application = create_app(settings)
    install_recording_audit(application)
    application.dependency_overrides[get_identity_service] = lambda: IdentityService(
        FakeIdentityRepository(), settings
    )

    async with app_client(application) as client:
        missing = await client.post(
            f"/agents/{uuid4()}/tokens",
            json={"task_id": str(uuid4())},
        )
        malformed = await client.post(
            f"/agents/{uuid4()}/tokens",
            headers={"X-Agent-Proof": "not-a-proof"},
            json={"task_id": str(uuid4())},
        )

    assert missing.status_code == 401
    assert malformed.status_code == 401
    assert missing.json()["error"]["code"] == "PROOF_INVALID"
    assert malformed.json()["error"]["code"] == "PROOF_INVALID"
    assert "not-a-proof" not in malformed.text
