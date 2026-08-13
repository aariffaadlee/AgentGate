"""Identity orchestration independent of HTTP and SQL query details."""

import hmac
import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol
from uuid import UUID, uuid4

from fastapi import status

from app.api.errors import AgentGateError
from app.auth.crypto import (
    Ed25519PublicJWK,
    EnvelopeCipher,
    canonical_sha256,
    hash_secret_for_storage,
    jwk_thumbprint,
    secret_matches,
)
from app.auth.proofs import ProofValidationError, RequestProofVerifier, proof_jti_hash
from app.auth.tokens import (
    AdminTokenClaims,
    IssuedToken,
    TokenService,
    TokenValidationError,
    WorkloadTokenClaims,
    token_jti_hash,
)
from app.config import Settings
from app.db.base import utc_now
from app.models.enums import (
    AdministratorStatus,
    AgentStatus,
    CredentialStatus,
    ProvenanceSourceType,
    TaskStatus,
    TrustLabel,
)
from app.models.identity import Administrator, Agent, AgentCredential, RequestProof
from app.models.provenance import ProvenanceRecord
from app.models.task import Task


class IdentityConflictError(Exception):
    """A uniqueness invariant rejected a registration or task change."""


class ProofReplayError(Exception):
    """A proof identifier already exists in the replay ledger."""


@dataclass(frozen=True)
class CredentialBundle:
    """Authoritative records needed to validate one presented credential."""

    credential: AgentCredential
    agent: Agent
    task: Task
    capabilities: list[str]
    revoked: bool


class IdentityRepository(Protocol):
    """Persistence contract consumed by the security service."""

    async def ensure_bootstrap_admin(
        self,
        *,
        username: str,
        credential_hash: str,
    ) -> Administrator: ...

    async def get_administrator(self, administrator_id: UUID) -> Administrator | None: ...

    async def create_agent(self, agent: Agent) -> Agent: ...

    async def get_agent(self, agent_id: UUID) -> Agent | None: ...

    async def list_agents(self) -> Sequence[Agent]: ...

    async def create_task(
        self,
        task: Task,
        capabilities: list[str],
        trusted_intent: ProvenanceRecord,
    ) -> tuple[Task, list[str]]: ...

    async def get_task(self, task_id: UUID) -> tuple[Task, list[str]] | None: ...

    async def list_tasks(self) -> Sequence[tuple[Task, list[str]]]: ...

    async def get_task_intent_provenance(self, task_id: UUID) -> ProvenanceRecord | None: ...

    async def store_credential_and_proof(
        self,
        credential: AgentCredential,
        proof: RequestProof,
    ) -> None: ...

    async def get_credential_bundle(self, jti_hash: str) -> CredentialBundle | None: ...

    async def store_request_proof(self, proof: RequestProof) -> None: ...

    async def revoke_agent(
        self,
        *,
        agent: Agent,
        administrator_id: UUID,
        reason_code: str,
        reason: str | None,
        now: datetime,
    ) -> None: ...


@dataclass(frozen=True)
class AdminPrincipal:
    administrator: Administrator
    claims: AdminTokenClaims


@dataclass(frozen=True)
class AgentPrincipal:
    agent: Agent
    task: Task
    credential: AgentCredential
    capabilities: list[str]
    claims: WorkloadTokenClaims


@dataclass(frozen=True)
class TaskCreation:
    assigned_agent_id: UUID
    title: str
    trusted_instruction_summary: str
    trusted_instruction: str
    capabilities: list[str]
    starts_at: datetime | None
    expires_at: datetime | None


@dataclass(frozen=True)
class TokenIssueResult:
    token: IssuedToken
    capabilities: list[str]


class IdentityService:
    """Enforce workload identity, task scope, proof freshness, and revocation."""

    def __init__(self, repository: IdentityRepository, settings: Settings) -> None:
        self._repository = repository
        self._settings = settings
        self._tokens = TokenService(settings)
        self._proofs = RequestProofVerifier(settings)
        self._cipher = EnvelopeCipher(settings.data_encryption_key_bytes)

    async def create_admin_session(self, candidate_secret: str) -> IssuedToken:
        """Exchange the configured local bootstrap secret for an admin-only token."""

        expected = self._settings.admin_bootstrap_secret.get_secret_value()
        if not secret_matches(candidate_secret, expected):
            raise _authentication_error("UNAUTHENTICATED")
        administrator = await self._repository.ensure_bootstrap_admin(
            username=self._settings.admin_bootstrap_username,
            credential_hash=hash_secret_for_storage(expected),
        )
        if administrator.status is not AdministratorStatus.ACTIVE:
            raise _authorization_error("ADMINISTRATOR_INACTIVE")
        return self._tokens.issue_admin_token(administrator_id=administrator.id)

    async def authenticate_admin(self, encoded_token: str) -> AdminPrincipal:
        """Validate admin audience and current persisted administrator status."""

        try:
            claims = self._tokens.decode_admin_token(encoded_token)
        except TokenValidationError as exc:
            raise _authentication_error(exc.reason_code) from exc
        administrator = await self._repository.get_administrator(claims.sub)
        if administrator is None:
            raise _authentication_error("TOKEN_CONTEXT_INVALID")
        if administrator.status is not AdministratorStatus.ACTIVE:
            raise _authorization_error("ADMINISTRATOR_INACTIVE")
        return AdminPrincipal(administrator=administrator, claims=claims)

    async def register_agent(self, *, name: str, public_jwk: Ed25519PublicJWK) -> Agent:
        """Register a unique public workload key; private keys never cross this boundary."""

        agent = Agent(
            id=uuid4(),
            name=name,
            public_jwk=public_jwk.model_dump(mode="json"),
            key_thumbprint=jwk_thumbprint(public_jwk),
            status=AgentStatus.ACTIVE,
        )
        try:
            return await self._repository.create_agent(agent)
        except IdentityConflictError as exc:
            raise AgentGateError(
                status.HTTP_409_CONFLICT,
                "AGENT_ALREADY_EXISTS",
                "An agent with that name or workload key already exists.",
            ) from exc

    async def list_agents(self) -> Sequence[Agent]:
        """Return sanitized identity records for an authenticated administrator."""

        return await self._repository.list_agents()

    async def create_task(
        self,
        *,
        owner_admin_id: UUID,
        creation: TaskCreation,
    ) -> tuple[Task, list[str]]:
        """Create a trusted task whose exact grants are assigned by an administrator."""

        agent = await self._repository.get_agent(creation.assigned_agent_id)
        if agent is None:
            raise _not_found_error()
        if agent.status is not AgentStatus.ACTIVE:
            raise _authorization_error("AGENT_INACTIVE")
        capabilities = sorted(set(creation.capabilities))
        if (
            not 1 <= len(capabilities) <= 32
            or len(capabilities) != len(creation.capabilities)
            or any(
                len(capability) > 120
                or re.fullmatch(
                    r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$",
                    capability,
                )
                is None
                for capability in capabilities
            )
        ):
            raise _validation_error("Capabilities must be unique exact names.")

        task_id = uuid4()
        instruction_bytes = creation.trusted_instruction.encode("utf-8")
        ciphertext, nonce = self._cipher.encrypt(
            instruction_bytes,
            associated_data=_task_instruction_aad(task_id),
        )
        task = Task(
            id=task_id,
            owner_admin_id=owner_admin_id,
            assigned_agent_id=agent.id,
            title=creation.title,
            trusted_instruction_summary=creation.trusted_instruction_summary,
            trusted_instruction_hash=canonical_sha256(creation.trusted_instruction),
            instruction_ciphertext=ciphertext,
            instruction_nonce=nonce,
            status=TaskStatus.ACTIVE,
            starts_at=creation.starts_at,
            expires_at=creation.expires_at,
        )
        trusted_intent = ProvenanceRecord(
            id=uuid4(),
            task_id=task_id,
            tool_request_id=None,
            parent_id=None,
            source_type=ProvenanceSourceType.USER_INSTRUCTION,
            trust_label=TrustLabel.TRUSTED,
            source_reference="task-owner-instruction",
            content_hash=task.trusted_instruction_hash,
            created_by_agent_id=None,
            created_by_admin_id=owner_admin_id,
            attributes={"server_classification": "task_owner_intent"},
        )
        try:
            return await self._repository.create_task(task, capabilities, trusted_intent)
        except IdentityConflictError as exc:
            raise AgentGateError(
                status.HTTP_409_CONFLICT,
                "TASK_CONFLICT",
                "The task could not be created because its identity conflicts.",
            ) from exc

    async def get_task(self, task_id: UUID) -> tuple[Task, list[str]]:
        """Load one task and its authoritative exact grants."""

        result = await self._repository.get_task(task_id)
        if result is None:
            raise _not_found_error()
        return result

    async def list_tasks(self) -> Sequence[tuple[Task, list[str]]]:
        """Return task records and exact grants for the administrative dashboard."""

        return await self._repository.list_tasks()

    async def get_task_intent_provenance(self, task_id: UUID) -> ProvenanceRecord:
        """Return the server-created trusted intent record for a task."""

        record = await self._repository.get_task_intent_provenance(task_id)
        if record is None:
            raise _not_found_error()
        return record

    async def issue_agent_token(
        self,
        *,
        agent_id: UUID,
        task_id: UUID,
        proof: str,
        proof_body: object,
        method: str,
        path: str,
    ) -> TokenIssueResult:
        """Verify the issuance proof and persist only token/proof identifiers as hashes."""

        agent = await self._repository.get_agent(agent_id)
        task_result = await self._repository.get_task(task_id)
        if agent is None or task_result is None:
            raise _not_found_error()
        task, capabilities = task_result
        now = utc_now()
        self._validate_active_context(agent, task, now)
        if task.assigned_agent_id != agent.id:
            raise _authorization_error("CROSS_TASK_CREDENTIAL")
        if not capabilities:
            raise _authorization_error("CAPABILITY_MISSING")

        public_jwk = Ed25519PublicJWK.model_validate(agent.public_jwk)
        try:
            proof_claims = self._proofs.verify(
                proof,
                public_jwk=public_jwk,
                agent_id=agent.id,
                method=method,
                path=path,
                body=proof_body,
                access_token=None,
            )
        except ProofValidationError as exc:
            raise _authentication_error("PROOF_INVALID") from exc

        issued = self._tokens.issue_workload_token(
            agent_id=agent.id,
            task_id=task.id,
            capabilities=capabilities,
            key_thumbprint=agent.key_thumbprint,
            now=now,
        )
        credential_id = uuid4()
        credential = AgentCredential(
            id=credential_id,
            agent_id=agent.id,
            task_id=task.id,
            jti_hash=token_jti_hash(issued.jti),
            key_thumbprint=agent.key_thumbprint,
            status=CredentialStatus.ACTIVE,
            issued_at=issued.issued_at,
            not_before_at=issued.not_before_at,
            expires_at=issued.expires_at,
        )
        proof_record = RequestProof(
            id=uuid4(),
            agent_id=agent.id,
            credential_id=credential_id,
            proof_jti_hash=proof_jti_hash(proof_claims.jti),
            proof_at=datetime.fromtimestamp(proof_claims.iat, tz=UTC),
            expires_at=datetime.fromtimestamp(proof_claims.exp, tz=UTC),
        )
        try:
            await self._repository.store_credential_and_proof(credential, proof_record)
        except ProofReplayError as exc:
            raise _authentication_error("PROOF_REPLAYED") from exc
        return TokenIssueResult(token=issued, capabilities=capabilities)

    async def authenticate_agent_request(
        self,
        *,
        encoded_token: str,
        proof: str,
        method: str,
        path: str,
        body: object,
        required_task_id: UUID | None = None,
    ) -> AgentPrincipal:
        """Validate token, live database context, proof binding, and one-time use."""

        try:
            claims = self._tokens.decode_workload_token(encoded_token)
        except TokenValidationError as exc:
            raise _authentication_error(exc.reason_code) from exc
        bundle = await self._repository.get_credential_bundle(token_jti_hash(claims.jti))
        if bundle is None:
            raise _authentication_error("TOKEN_CONTEXT_INVALID")
        now = utc_now()
        self._validate_credential_context(bundle, claims, now)
        if required_task_id is not None and claims.task_id != required_task_id:
            raise _authorization_error("CROSS_TASK_CREDENTIAL")

        try:
            proof_claims = self._proofs.verify(
                proof,
                public_jwk=Ed25519PublicJWK.model_validate(bundle.agent.public_jwk),
                agent_id=bundle.agent.id,
                method=method,
                path=path,
                body=body,
                access_token=encoded_token,
            )
        except ProofValidationError as exc:
            raise _authentication_error("PROOF_INVALID") from exc
        proof_record = RequestProof(
            id=uuid4(),
            agent_id=bundle.agent.id,
            credential_id=bundle.credential.id,
            proof_jti_hash=proof_jti_hash(proof_claims.jti),
            proof_at=datetime.fromtimestamp(proof_claims.iat, tz=UTC),
            expires_at=datetime.fromtimestamp(proof_claims.exp, tz=UTC),
        )
        try:
            await self._repository.store_request_proof(proof_record)
        except ProofReplayError as exc:
            raise _authentication_error("PROOF_REPLAYED") from exc
        return AgentPrincipal(
            agent=bundle.agent,
            task=bundle.task,
            credential=bundle.credential,
            capabilities=bundle.capabilities,
            claims=claims,
        )

    async def revoke_agent(
        self,
        *,
        agent_id: UUID,
        administrator_id: UUID,
        reason_code: str,
        reason: str | None,
    ) -> Agent:
        """Revoke an agent and all active credentials without deleting history."""

        agent = await self._repository.get_agent(agent_id)
        if agent is None:
            raise _not_found_error()
        if agent.status is AgentStatus.REVOKED:
            return agent
        await self._repository.revoke_agent(
            agent=agent,
            administrator_id=administrator_id,
            reason_code=reason_code,
            reason=reason,
            now=utc_now(),
        )
        return agent

    @staticmethod
    def _validate_active_context(agent: Agent, task: Task, now: datetime) -> None:
        if agent.status is not AgentStatus.ACTIVE:
            raise _authorization_error("AGENT_INACTIVE")
        if task.status is not TaskStatus.ACTIVE:
            raise _authorization_error("TASK_INACTIVE")
        if task.starts_at is not None and task.starts_at > now:
            raise _authorization_error("TASK_INACTIVE")
        if task.expires_at is not None and task.expires_at <= now:
            raise _authorization_error("TASK_INACTIVE")

    def _validate_credential_context(
        self,
        bundle: CredentialBundle,
        claims: WorkloadTokenClaims,
        now: datetime,
    ) -> None:
        credential = bundle.credential
        if bundle.revoked or credential.status is CredentialStatus.REVOKED:
            raise _authentication_error("CREDENTIAL_REVOKED")
        if credential.expires_at <= now:
            raise _authentication_error("CREDENTIAL_EXPIRED")
        self._validate_active_context(bundle.agent, bundle.task, now)
        authoritative_match = (
            credential.agent_id == claims.sub
            and credential.task_id == claims.task_id
            and bundle.agent.id == claims.sub
            and bundle.task.id == claims.task_id
            and bundle.task.assigned_agent_id == claims.sub
            and credential.issued_at.timestamp() == claims.iat
            and credential.not_before_at.timestamp() == claims.nbf
            and credential.expires_at.timestamp() == claims.exp
            and sorted(bundle.capabilities) == sorted(claims.capabilities)
            and hmac.compare_digest(credential.key_thumbprint, claims.cnf.jkt)
            and hmac.compare_digest(bundle.agent.key_thumbprint, claims.cnf.jkt)
        )
        if not authoritative_match:
            raise _authentication_error("TOKEN_CONTEXT_INVALID")


def _task_instruction_aad(task_id: UUID) -> bytes:
    return b"agentgate:task-instruction:" + task_id.bytes


def _authentication_error(code: str) -> AgentGateError:
    return AgentGateError(
        status.HTTP_401_UNAUTHORIZED,
        code,
        "The supplied workload credential or proof is not valid.",
    )


def _authorization_error(code: str) -> AgentGateError:
    return AgentGateError(
        status.HTTP_403_FORBIDDEN,
        code,
        "The request is not authorized.",
    )


def _not_found_error() -> AgentGateError:
    return AgentGateError(
        status.HTTP_404_NOT_FOUND,
        "NOT_FOUND",
        "The requested resource was not found.",
    )


def _validation_error(message: str) -> AgentGateError:
    return AgentGateError(status.HTTP_422_UNPROCESSABLE_CONTENT, "VALIDATION_ERROR", message)
