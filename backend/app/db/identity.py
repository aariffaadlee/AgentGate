"""SQLAlchemy persistence for Phase 2 identity and task authorization state."""

from collections.abc import Sequence
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.enums import AgentStatus, CredentialStatus, ProvenanceSourceType, TrustLabel
from app.models.identity import Administrator, Agent, AgentCredential, RequestProof, Revocation
from app.models.provenance import ProvenanceRecord
from app.models.task import Task, TaskCapability
from app.services.identity import CredentialBundle, IdentityConflictError, ProofReplayError


class SQLAlchemyIdentityRepository:
    """Persist identity transitions transactionally in PostgreSQL."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def ensure_bootstrap_admin(
        self,
        *,
        username: str,
        credential_hash: str,
    ) -> Administrator:
        result = await self._session.execute(
            select(Administrator).where(Administrator.username == username)
        )
        administrator = result.scalar_one_or_none()
        if administrator is not None:
            return administrator
        administrator = Administrator(username=username, credential_hash=credential_hash)
        self._session.add(administrator)
        try:
            await self._session.commit()
            await self._session.refresh(administrator)
        except IntegrityError:
            await self._session.rollback()
            result = await self._session.execute(
                select(Administrator).where(Administrator.username == username)
            )
            administrator = result.scalar_one()
        return administrator

    async def get_administrator(self, administrator_id: UUID) -> Administrator | None:
        return await self._session.get(Administrator, administrator_id)

    async def create_agent(self, agent: Agent) -> Agent:
        self._session.add(agent)
        try:
            await self._session.commit()
            await self._session.refresh(agent)
        except IntegrityError as exc:
            await self._session.rollback()
            raise IdentityConflictError from exc
        return agent

    async def get_agent(self, agent_id: UUID) -> Agent | None:
        return await self._session.get(Agent, agent_id)

    async def list_agents(self) -> Sequence[Agent]:
        result = await self._session.execute(select(Agent).order_by(Agent.created_at, Agent.id))
        return result.scalars().all()

    async def create_task(
        self,
        task: Task,
        capabilities: list[str],
        trusted_intent: ProvenanceRecord,
    ) -> tuple[Task, list[str]]:
        self._session.add_all([task, trusted_intent])
        self._session.add_all(
            TaskCapability(task_id=task.id, capability=capability) for capability in capabilities
        )
        try:
            await self._session.commit()
            await self._session.refresh(task)
        except IntegrityError as exc:
            await self._session.rollback()
            raise IdentityConflictError from exc
        return task, capabilities

    async def get_task(self, task_id: UUID) -> tuple[Task, list[str]] | None:
        task = await self._session.get(Task, task_id)
        if task is None:
            return None
        result = await self._session.execute(
            select(TaskCapability.capability)
            .where(TaskCapability.task_id == task_id)
            .order_by(TaskCapability.capability)
        )
        return task, list(result.scalars().all())

    async def list_tasks(self) -> Sequence[tuple[Task, list[str]]]:
        result = await self._session.execute(select(Task).order_by(Task.created_at.desc(), Task.id))
        tasks = list(result.scalars().all())
        task_views: list[tuple[Task, list[str]]] = []
        for task in tasks:
            task_result = await self.get_task(task.id)
            if task_result is not None:
                task_views.append(task_result)
        return task_views

    async def get_task_intent_provenance(self, task_id: UUID) -> ProvenanceRecord | None:
        result = await self._session.execute(
            select(ProvenanceRecord).where(
                ProvenanceRecord.task_id == task_id,
                ProvenanceRecord.source_type == ProvenanceSourceType.USER_INSTRUCTION,
                ProvenanceRecord.trust_label == TrustLabel.TRUSTED,
                ProvenanceRecord.tool_request_id.is_(None),
            )
        )
        return result.scalar_one_or_none()

    async def store_credential_and_proof(
        self,
        credential: AgentCredential,
        proof: RequestProof,
    ) -> None:
        self._session.add_all([credential, proof])
        await self._commit_proof_sensitive()

    async def get_credential_bundle(self, jti_hash: str) -> CredentialBundle | None:
        result = await self._session.execute(
            select(AgentCredential).where(AgentCredential.jti_hash == jti_hash)
        )
        credential = result.scalar_one_or_none()
        if credential is None:
            return None
        agent = await self._session.get(Agent, credential.agent_id)
        task_result = await self.get_task(credential.task_id)
        if agent is None or task_result is None:
            return None
        task, capabilities = task_result
        now = datetime.now(UTC)
        revocation = await self._session.execute(
            select(Revocation.id).where(
                Revocation.effective_at <= now,
                or_(
                    Revocation.agent_id == agent.id,
                    Revocation.credential_id == credential.id,
                ),
            )
        )
        return CredentialBundle(
            credential=credential,
            agent=agent,
            task=task,
            capabilities=capabilities,
            revoked=revocation.scalar_one_or_none() is not None,
        )

    async def store_request_proof(self, proof: RequestProof) -> None:
        self._session.add(proof)
        await self._commit_proof_sensitive()

    async def revoke_agent(
        self,
        *,
        agent: Agent,
        administrator_id: UUID,
        reason_code: str,
        reason: str | None,
        now: datetime,
    ) -> None:
        agent.status = AgentStatus.REVOKED
        agent.revoked_at = now
        await self._session.execute(
            update(AgentCredential)
            .where(
                AgentCredential.agent_id == agent.id,
                AgentCredential.status == CredentialStatus.ACTIVE,
            )
            .values(status=CredentialStatus.REVOKED, revoked_at=now)
        )
        self._session.add(
            Revocation(
                agent_id=agent.id,
                credential_id=None,
                revoked_by_admin_id=administrator_id,
                reason_code=reason_code,
                reason=reason,
                effective_at=now,
            )
        )
        await self._session.commit()

    async def _commit_proof_sensitive(self) -> None:
        try:
            await self._session.commit()
        except IntegrityError as exc:
            await self._session.rollback()
            raise ProofReplayError from exc
