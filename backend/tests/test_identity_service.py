"""Identity-service security invariants using an isolated persistence double."""

from collections.abc import Sequence
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.api.errors import AgentGateError
from app.auth.crypto import public_jwk_from_key
from app.auth.proofs import create_request_proof
from app.config import Settings
from app.db.base import utc_now
from app.models.enums import (
    AdministratorStatus,
    AgentStatus,
    CredentialStatus,
)
from app.models.identity import Administrator, Agent, AgentCredential, RequestProof
from app.models.provenance import ProvenanceRecord
from app.models.task import Task
from app.services.identity import (
    CredentialBundle,
    IdentityConflictError,
    IdentityService,
    ProofReplayError,
    TaskCreation,
)


class FakeIdentityRepository:
    """In-memory state with the same replay and history invariants as PostgreSQL."""

    def __init__(self) -> None:
        self.administrators: dict[UUID, Administrator] = {}
        self.agents: dict[UUID, Agent] = {}
        self.tasks: dict[UUID, tuple[Task, list[str]]] = {}
        self.credentials: dict[str, AgentCredential] = {}
        self.proofs: dict[str, RequestProof] = {}
        self.revoked_agents: set[UUID] = set()
        self.provenance: dict[UUID, ProvenanceRecord] = {}

    async def ensure_bootstrap_admin(
        self,
        *,
        username: str,
        credential_hash: str,
    ) -> Administrator:
        for administrator in self.administrators.values():
            if administrator.username == username:
                return administrator
        now = utc_now()
        administrator = Administrator(
            id=uuid4(),
            username=username,
            credential_hash=credential_hash,
            status=AdministratorStatus.ACTIVE,
            created_at=now,
            updated_at=now,
        )
        self.administrators[administrator.id] = administrator
        return administrator

    async def get_administrator(self, administrator_id: UUID) -> Administrator | None:
        return self.administrators.get(administrator_id)

    async def create_agent(self, agent: Agent) -> Agent:
        if any(
            current.name == agent.name or current.key_thumbprint == agent.key_thumbprint
            for current in self.agents.values()
        ):
            raise IdentityConflictError
        now = utc_now()
        agent.created_at = now
        agent.updated_at = now
        self.agents[agent.id] = agent
        return agent

    async def get_agent(self, agent_id: UUID) -> Agent | None:
        return self.agents.get(agent_id)

    async def list_agents(self) -> Sequence[Agent]:
        return list(self.agents.values())

    async def create_task(
        self,
        task: Task,
        capabilities: list[str],
        trusted_intent: ProvenanceRecord,
    ) -> tuple[Task, list[str]]:
        now = utc_now()
        task.created_at = now
        task.updated_at = now
        self.tasks[task.id] = (task, capabilities)
        trusted_intent.created_at = now
        self.provenance[trusted_intent.id] = trusted_intent
        return task, capabilities

    async def get_task(self, task_id: UUID) -> tuple[Task, list[str]] | None:
        return self.tasks.get(task_id)

    async def list_tasks(self) -> Sequence[tuple[Task, list[str]]]:
        return sorted(
            self.tasks.values(),
            key=lambda item: (item[0].created_at, item[0].id),
            reverse=True,
        )

    async def get_task_intent_provenance(self, task_id: UUID) -> ProvenanceRecord | None:
        return next(
            (record for record in self.provenance.values() if record.task_id == task_id),
            None,
        )

    async def store_credential_and_proof(
        self,
        credential: AgentCredential,
        proof: RequestProof,
    ) -> None:
        if proof.proof_jti_hash in self.proofs:
            raise ProofReplayError
        self.credentials[credential.jti_hash] = credential
        self.proofs[proof.proof_jti_hash] = proof

    async def get_credential_bundle(self, jti_hash: str) -> CredentialBundle | None:
        credential = self.credentials.get(jti_hash)
        if credential is None:
            return None
        agent = self.agents[credential.agent_id]
        task, capabilities = self.tasks[credential.task_id]
        return CredentialBundle(
            credential=credential,
            agent=agent,
            task=task,
            capabilities=capabilities,
            revoked=agent.id in self.revoked_agents,
        )

    async def store_request_proof(self, proof: RequestProof) -> None:
        if proof.proof_jti_hash in self.proofs:
            raise ProofReplayError
        self.proofs[proof.proof_jti_hash] = proof

    async def revoke_agent(
        self,
        *,
        agent: Agent,
        administrator_id: UUID,
        reason_code: str,
        reason: str | None,
        now: datetime,
    ) -> None:
        del administrator_id, reason_code, reason
        agent.status = AgentStatus.REVOKED
        agent.revoked_at = now
        self.revoked_agents.add(agent.id)
        for credential in self.credentials.values():
            if credential.agent_id == agent.id:
                credential.status = CredentialStatus.REVOKED
                credential.revoked_at = now


async def _registered_agent(
    service: IdentityService,
    *,
    name: str = "Demo Agent",
) -> tuple[Agent, Ed25519PrivateKey]:
    private_key = Ed25519PrivateKey.generate()
    agent = await service.register_agent(
        name=name,
        public_jwk=public_jwk_from_key(private_key.public_key()),
    )
    return agent, private_key


async def _task_for(
    service: IdentityService,
    agent: Agent,
    *,
    capabilities: list[str] | None = None,
) -> tuple[Task, list[str]]:
    return await service.create_task(
        owner_admin_id=uuid4(),
        creation=TaskCreation(
            assigned_agent_id=agent.id,
            title="Read synthetic tickets",
            trusted_instruction_summary="Read the assigned support ticket.",
            trusted_instruction="Read ticket TICKET-001 and summarize it.",
            capabilities=capabilities or ["tickets.read"],
            starts_at=None,
            expires_at=None,
        ),
    )


async def _issue(
    service: IdentityService,
    settings: Settings,
    agent: Agent,
    private_key: Ed25519PrivateKey,
    task: Task,
    *,
    proof_jti: UUID | None = None,
):
    body = {"task_id": str(task.id)}
    path = f"/agents/{agent.id}/tokens"
    proof = create_request_proof(
        private_key,
        agent_id=agent.id,
        method="POST",
        path=path,
        body=body,
        ttl_seconds=settings.request_proof_ttl_seconds,
        jti=proof_jti,
    )
    return await service.issue_agent_token(
        agent_id=agent.id,
        task_id=task.id,
        proof=proof,
        proof_body=body,
        method="POST",
        path=path,
    )


async def test_full_proof_bound_token_flow_and_proof_replay_denial(settings: Settings) -> None:
    repository = FakeIdentityRepository()
    service = IdentityService(repository, settings)
    agent, private_key = await _registered_agent(service)
    task, capabilities = await _task_for(service, agent)

    result = await _issue(service, settings, agent, private_key, task)

    assert result.capabilities == capabilities
    assert all(
        result.token.encoded != credential.jti_hash
        for credential in repository.credentials.values()
    )
    path = f"/tasks/{task.id}"
    proof = create_request_proof(
        private_key,
        agent_id=agent.id,
        method="GET",
        path=path,
        body={},
        ttl_seconds=settings.request_proof_ttl_seconds,
        access_token=result.token.encoded,
    )
    principal = await service.authenticate_agent_request(
        encoded_token=result.token.encoded,
        proof=proof,
        method="GET",
        path=path,
        body={},
        required_task_id=task.id,
    )

    assert principal.agent.id == agent.id
    assert principal.task.id == task.id
    with pytest.raises(AgentGateError) as replay:
        await service.authenticate_agent_request(
            encoded_token=result.token.encoded,
            proof=proof,
            method="GET",
            path=path,
            body={},
            required_task_id=task.id,
        )
    assert replay.value.code == "PROOF_REPLAYED"


async def test_cross_task_and_cross_agent_credential_requests_are_denied(
    settings: Settings,
) -> None:
    repository = FakeIdentityRepository()
    service = IdentityService(repository, settings)
    first, first_key = await _registered_agent(service, name="First Agent")
    second, second_key = await _registered_agent(service, name="Second Agent")
    first_task, _ = await _task_for(service, first)
    second_task, _ = await _task_for(service, second)
    result = await _issue(service, settings, first, first_key, first_task)

    path = f"/tasks/{second_task.id}"
    cross_task_proof = create_request_proof(
        first_key,
        agent_id=first.id,
        method="GET",
        path=path,
        body={},
        ttl_seconds=settings.request_proof_ttl_seconds,
        access_token=result.token.encoded,
    )
    with pytest.raises(AgentGateError) as cross_task:
        await service.authenticate_agent_request(
            encoded_token=result.token.encoded,
            proof=cross_task_proof,
            method="GET",
            path=path,
            body={},
            required_task_id=second_task.id,
        )
    assert cross_task.value.code == "CROSS_TASK_CREDENTIAL"

    issuance_body = {"task_id": str(first_task.id)}
    issuance_path = f"/agents/{second.id}/tokens"
    second_proof = create_request_proof(
        second_key,
        agent_id=second.id,
        method="POST",
        path=issuance_path,
        body=issuance_body,
        ttl_seconds=settings.request_proof_ttl_seconds,
    )
    with pytest.raises(AgentGateError) as cross_agent:
        await service.issue_agent_token(
            agent_id=second.id,
            task_id=first_task.id,
            proof=second_proof,
            proof_body=issuance_body,
            method="POST",
            path=issuance_path,
        )
    assert cross_agent.value.code == "CROSS_TASK_CREDENTIAL"


async def test_revocation_invalidates_already_issued_token(settings: Settings) -> None:
    repository = FakeIdentityRepository()
    service = IdentityService(repository, settings)
    agent, private_key = await _registered_agent(service)
    task, _ = await _task_for(service, agent)
    result = await _issue(service, settings, agent, private_key, task)

    await service.revoke_agent(
        agent_id=agent.id,
        administrator_id=uuid4(),
        reason_code="KEY_COMPROMISE",
        reason="Synthetic test revocation",
    )
    path = f"/tasks/{task.id}"
    proof = create_request_proof(
        private_key,
        agent_id=agent.id,
        method="GET",
        path=path,
        body={},
        ttl_seconds=settings.request_proof_ttl_seconds,
        access_token=result.token.encoded,
    )

    with pytest.raises(AgentGateError) as revoked:
        await service.authenticate_agent_request(
            encoded_token=result.token.encoded,
            proof=proof,
            method="GET",
            path=path,
            body={},
            required_task_id=task.id,
        )
    assert revoked.value.code == "CREDENTIAL_REVOKED"


async def test_admin_session_is_a_separate_audience_and_checks_live_status(
    settings: Settings,
) -> None:
    repository = FakeIdentityRepository()
    service = IdentityService(repository, settings)

    with pytest.raises(AgentGateError) as invalid:
        await service.create_admin_session("x" * 40)
    assert invalid.value.code == "UNAUTHENTICATED"

    issued = await service.create_admin_session(settings.admin_bootstrap_secret.get_secret_value())
    principal = await service.authenticate_admin(issued.encoded)
    assert principal.administrator.username == settings.admin_bootstrap_username

    principal.administrator.status = AdministratorStatus.DISABLED
    with pytest.raises(AgentGateError) as disabled:
        await service.authenticate_admin(issued.encoded)
    assert disabled.value.code == "ADMINISTRATOR_INACTIVE"


async def test_task_capabilities_are_exact_unique_and_instruction_is_encrypted(
    settings: Settings,
) -> None:
    repository = FakeIdentityRepository()
    service = IdentityService(repository, settings)
    agent, _ = await _registered_agent(service)

    with pytest.raises(AgentGateError) as duplicate:
        await _task_for(service, agent, capabilities=["tickets.read", "tickets.read"])
    assert duplicate.value.code == "VALIDATION_ERROR"
    with pytest.raises(AgentGateError) as wildcard:
        await _task_for(service, agent, capabilities=["tickets.*"])
    assert wildcard.value.code == "VALIDATION_ERROR"

    task, capabilities = await _task_for(
        service,
        agent,
        capabilities=["tickets.read", "documents.search"],
    )
    assert capabilities == ["documents.search", "tickets.read"]
    assert b"Read ticket" not in task.instruction_ciphertext
    assert task.assigned_agent_id == agent.id
    assert task.trusted_instruction_hash.startswith("sha256:")


def test_fake_repository_uses_utc_aware_timestamps() -> None:
    assert datetime.now(UTC).tzinfo is UTC
