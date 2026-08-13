"""Transaction and replay behavior at the SQLAlchemy identity boundary."""

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.identity import SQLAlchemyIdentityRepository
from app.models.enums import AgentStatus, CredentialStatus
from app.models.identity import Agent, AgentCredential, RequestProof
from app.services.identity import IdentityConflictError, ProofReplayError


def fake_session() -> MagicMock:
    session = MagicMock(spec=AsyncSession)
    session.commit = AsyncMock()
    session.rollback = AsyncMock()
    session.refresh = AsyncMock()
    session.execute = AsyncMock()
    session.get = AsyncMock()
    return session


def proof_record() -> RequestProof:
    now = datetime.now(UTC)
    return RequestProof(
        id=uuid4(),
        agent_id=uuid4(),
        credential_id=uuid4(),
        proof_jti_hash="a" * 64,
        proof_at=now,
        expires_at=now,
    )


async def test_proof_commit_succeeds_and_uniqueness_failure_maps_to_replay() -> None:
    session = fake_session()
    repository = SQLAlchemyIdentityRepository(session)
    proof = proof_record()

    await repository.store_request_proof(proof)

    session.add.assert_called_once_with(proof)
    session.commit.assert_awaited_once()

    conflict_session = fake_session()
    conflict_session.commit.side_effect = IntegrityError(
        "insert request proof",
        {},
        Exception("unique proof_jti_hash"),
    )
    conflict_repository = SQLAlchemyIdentityRepository(conflict_session)

    with pytest.raises(ProofReplayError):
        await conflict_repository.store_request_proof(proof_record())
    conflict_session.rollback.assert_awaited_once()


async def test_agent_registration_rolls_back_and_returns_stable_conflict() -> None:
    session = fake_session()
    session.commit.side_effect = IntegrityError(
        "insert agent",
        {},
        Exception("unique key_thumbprint"),
    )
    repository = SQLAlchemyIdentityRepository(session)
    agent = Agent(
        id=uuid4(),
        name="Duplicate Agent",
        public_jwk={"kty": "OKP", "crv": "Ed25519", "x": "A" * 43},
        key_thumbprint="b" * 64,
        status=AgentStatus.ACTIVE,
    )

    with pytest.raises(IdentityConflictError):
        await repository.create_agent(agent)

    session.rollback.assert_awaited_once()


async def test_revocation_updates_agent_credentials_and_commits_once() -> None:
    session = fake_session()
    repository = SQLAlchemyIdentityRepository(session)
    agent = Agent(
        id=uuid4(),
        name="Revoked Agent",
        public_jwk={"kty": "OKP", "crv": "Ed25519", "x": "A" * 43},
        key_thumbprint="c" * 64,
        status=AgentStatus.ACTIVE,
    )
    now = datetime.now(UTC)

    await repository.revoke_agent(
        agent=agent,
        administrator_id=uuid4(),
        reason_code="KEY_COMPROMISE",
        reason="Synthetic test",
        now=now,
    )

    assert agent.status is AgentStatus.REVOKED
    assert agent.revoked_at == now
    session.execute.assert_awaited_once()
    session.add.assert_called_once()
    revocation = session.add.call_args.args[0]
    assert revocation.agent_id == agent.id
    assert revocation.credential_id is None
    assert revocation.reason_code == "KEY_COMPROMISE"
    session.commit.assert_awaited_once()


async def test_store_credential_and_proof_is_one_commit() -> None:
    session = fake_session()
    repository = SQLAlchemyIdentityRepository(session)
    now = datetime.now(UTC)
    credential = AgentCredential(
        id=uuid4(),
        agent_id=uuid4(),
        task_id=uuid4(),
        jti_hash="d" * 64,
        key_thumbprint="e" * 64,
        status=CredentialStatus.ACTIVE,
        issued_at=now,
        not_before_at=now,
        expires_at=now,
    )
    proof = proof_record()

    await repository.store_credential_and_proof(credential, proof)

    session.add_all.assert_called_once_with([credential, proof])
    session.commit.assert_awaited_once()
