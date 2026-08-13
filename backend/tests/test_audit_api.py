"""Administrator-only Phase 6 timeline and verification HTTP contract."""

from uuid import uuid4

from app.api.audit_dependencies import get_audit_service
from app.api.identity import get_identity_service
from app.auth.tokens import TokenService
from app.config import Settings
from app.main import create_app
from app.models.enums import AuditActorType
from app.services.audit import AuditEventDraft, AuditService
from app.services.identity import IdentityService
from tests.support import app_client
from tests.test_audit_service import FakeAuditRepository
from tests.test_identity_service import FakeIdentityRepository


async def test_admin_timeline_and_verification_detect_tampering(
    tmp_path,
    settings: Settings,
) -> None:
    active_settings = settings.model_copy(
        update={"audit_checkpoint_path": tmp_path / "external" / "head.json"}
    )
    application = create_app(active_settings)
    identity = IdentityService(FakeIdentityRepository(), active_settings)
    admin_token = await identity.create_admin_session(
        active_settings.admin_bootstrap_secret.get_secret_value()
    )
    repository = FakeAuditRepository()
    audit = AuditService(
        repository,
        key=active_settings.audit_hmac_key_bytes,
        checkpoint_path=active_settings.audit_checkpoint_path,
    )
    correlation_id = uuid4()
    task_id = uuid4()
    await audit.append(
        AuditEventDraft(
            event_type="tool.requested",
            correlation_id=correlation_id,
            actor_type=AuditActorType.AGENT,
            actor_id=uuid4(),
            task_id=task_id,
            payload={"argument_hash": "sha256:" + ("a" * 64)},
        ),
        AuditEventDraft(
            event_type="policy.decided",
            correlation_id=correlation_id,
            actor_type=AuditActorType.SYSTEM,
            actor_id=None,
            task_id=task_id,
            payload={"outcome": "deny", "reason_codes": ["CAPABILITY_MISSING"]},
        ),
    )
    application.dependency_overrides[get_identity_service] = lambda: identity
    application.dependency_overrides[get_audit_service] = lambda: audit
    headers = {"Authorization": f"Bearer {admin_token.encoded}"}
    wrong_audience = TokenService(active_settings).issue_workload_token(
        agent_id=uuid4(),
        task_id=task_id,
        capabilities=["documents.search"],
        key_thumbprint="b" * 64,
    )

    async with app_client(application) as client:
        unauthenticated = await client.get("/audit/events")
        workload = await client.get(
            "/audit/events",
            headers={"Authorization": f"Bearer {wrong_audience.encoded}"},
        )
        timeline = await client.get(
            "/audit/events",
            params={"correlation_id": str(correlation_id), "after_sequence": 1},
            headers=headers,
        )
        valid = await client.post("/audit/verify", headers=headers)
        invalid_limit = await client.get("/audit/events?limit=0", headers=headers)
        repository.events[0].payload = {"argument_hash": "modified"}
        tampered = await client.post("/audit/verify", headers=headers)

    assert unauthenticated.status_code == 401
    assert workload.status_code == 401
    assert [event["sequence"] for event in timeline.json()] == [2]
    assert timeline.json()[0]["event_type"] == "policy.decided"
    assert valid.status_code == 200
    assert valid.json()["valid"] is True
    assert valid.json()["reason_code"] == "CHAIN_VALID"
    assert invalid_limit.status_code == 422
    assert tampered.status_code == 200
    assert tampered.json()["valid"] is False
    assert tampered.json()["reason_code"] == "EVENT_HASH_MISMATCH"
