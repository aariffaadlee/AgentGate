"""Phase 6 keyed audit chain, redaction, checkpoint, and tampering tests."""

import asyncio
import copy
import json
from collections.abc import Sequence
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from app.models.audit import AuditEvent
from app.models.enums import AuditActorType
from app.services.audit import (
    GENESIS_HASH,
    AuditEventDraft,
    AuditIntegrityError,
    AuditService,
    CheckpointStore,
    build_audit_event,
    create_checkpoint,
    verify_audit_chain,
)


class FakeAuditRepository:
    """Lock-faithful in-memory append repository for chain behavior tests."""

    def __init__(self) -> None:
        self.events: list[AuditEvent] = []
        self.lock = asyncio.Lock()

    async def append_batch(
        self,
        drafts: Sequence[AuditEventDraft],
        *,
        key: bytes,
        checkpoint_store: CheckpointStore,
    ) -> list[AuditEvent]:
        async with self.lock:
            checkpoint = checkpoint_store.read()
            current = verify_audit_chain(self.events, checkpoint, key)
            if not current.valid:
                raise AuditIntegrityError(current.reason_code)
            chain_id = self.events[0].chain_id if self.events else uuid4()
            sequence = self.events[-1].sequence if self.events else 0
            previous_hash = self.events[-1].event_hash if self.events else GENESIS_HASH
            appended: list[AuditEvent] = []
            for draft in drafts:
                sequence += 1
                event = build_audit_event(
                    draft,
                    sequence=sequence,
                    chain_id=chain_id,
                    previous_hash=previous_hash,
                    key=key,
                )
                appended.append(event)
                previous_hash = event.event_hash
            self.events.extend(appended)
            checkpoint_store.write(create_checkpoint(appended[-1], key))
            return appended

    async def list_events(
        self,
        *,
        after_sequence: int,
        limit: int,
        correlation_id: UUID | None,
        task_id: UUID | None,
        tool_request_id: UUID | None,
        event_type: str | None,
    ) -> Sequence[AuditEvent]:
        selected = [event for event in self.events if event.sequence > after_sequence]
        if correlation_id is not None:
            selected = [event for event in selected if event.correlation_id == correlation_id]
        if task_id is not None:
            selected = [event for event in selected if event.task_id == task_id]
        if tool_request_id is not None:
            selected = [event for event in selected if event.tool_request_id == tool_request_id]
        if event_type is not None:
            selected = [event for event in selected if event.event_type == event_type]
        return selected[:limit]

    async def list_all_events(self) -> Sequence[AuditEvent]:
        return self.events


def _draft(index: int, *, correlation_id: UUID | None = None) -> AuditEventDraft:
    return AuditEventDraft(
        event_type=f"tool.test_{index}",
        correlation_id=correlation_id or uuid4(),
        actor_type=AuditActorType.AGENT,
        actor_id=uuid4(),
        task_id=uuid4(),
        tool_request_id=uuid4(),
        payload={"index": index, "status": "synthetic"},
    )


async def _populated(tmp_path: Path) -> tuple[AuditService, FakeAuditRepository, bytes, Path]:
    repository = FakeAuditRepository()
    key = b"A" * 32
    checkpoint_path = tmp_path / "external" / "audit-head.json"
    service = AuditService(repository, key=key, checkpoint_path=checkpoint_path)
    await service.append(_draft(1), _draft(2), _draft(3))
    return service, repository, key, checkpoint_path


async def test_chain_checkpoint_and_recursive_secret_redaction(tmp_path: Path) -> None:
    repository = FakeAuditRepository()
    checkpoint_path = tmp_path / "checkpoint" / "head.json"
    service = AuditService(repository, key=b"A" * 32, checkpoint_path=checkpoint_path)
    secret = "do-not-persist-this-secret-value"

    events = await service.append(
        AuditEventDraft(
            event_type="identity.credential_issued",
            correlation_id=uuid4(),
            actor_type=AuditActorType.ADMINISTRATOR,
            actor_id=uuid4(),
            payload={
                "password": secret,
                "nested": {"access_token": secret},
                "authorization": f"Bearer {secret}",
                "safe": "kept",
            },
        ),
        _draft(2),
    )

    assert [event.sequence for event in events] == [1, 2]
    assert events[0].previous_hash == GENESIS_HASH
    assert events[1].previous_hash == events[0].event_hash
    assert events[0].payload["password"] == "[REDACTED]"
    assert events[0].payload["nested"] == {"access_token": "[REDACTED]"}
    assert events[0].payload["authorization"] == "[REDACTED]"
    assert secret not in checkpoint_path.read_text(encoding="utf-8")
    assert (await service.verify()).valid is True


@pytest.mark.parametrize(
    ("tamper", "expected_reason"),
    [
        ("modify", "EVENT_HASH_MISMATCH"),
        ("delete", "SEQUENCE_GAP"),
        ("insert", "EVENT_HASH_MISMATCH"),
        ("reorder", "SEQUENCE_GAP"),
        ("truncate", "CHECKPOINT_HEAD_MISMATCH"),
    ],
)
async def test_audit_mutation_matrix_fails_verification(
    tmp_path: Path,
    tamper: str,
    expected_reason: str,
) -> None:
    service, repository, _key, _checkpoint = await _populated(tmp_path)
    if tamper == "modify":
        repository.events[1].payload = {"index": 999}
    elif tamper == "delete":
        del repository.events[1]
    elif tamper == "insert":
        forged = copy.deepcopy(repository.events[1])
        forged.event_id = uuid4()
        forged.event_hash = "f" * 64
        repository.events.insert(1, forged)
    elif tamper == "reorder":
        repository.events[0], repository.events[1] = (
            repository.events[1],
            repository.events[0],
        )
    else:
        repository.events.pop()

    result = await service.verify()

    assert result.valid is False
    assert result.reason_code == expected_reason


async def test_checkpoint_modification_and_corruption_are_detected(tmp_path: Path) -> None:
    service, _repository, _key, checkpoint = await _populated(tmp_path)
    document = json.loads(checkpoint.read_text(encoding="utf-8"))
    document["mac"] = "f" * 64
    checkpoint.write_text(json.dumps(document), encoding="utf-8")
    modified = await service.verify()
    assert modified.valid is False
    assert modified.reason_code == "CHECKPOINT_MAC_INVALID"

    checkpoint.write_text("{not-json", encoding="utf-8")
    corrupt = await service.verify()
    assert corrupt.valid is False
    assert corrupt.reason_code == "CHECKPOINT_INVALID"


async def test_append_refuses_to_extend_a_tampered_chain(tmp_path: Path) -> None:
    service, repository, _key, _checkpoint = await _populated(tmp_path)
    repository.events[0].event_type = "tool.modified"

    with pytest.raises(AuditIntegrityError, match="EVENT_HASH_MISMATCH"):
        await service.append(_draft(4))

    assert len(repository.events) == 3


async def test_concurrent_appends_form_one_contiguous_chain(tmp_path: Path) -> None:
    repository = FakeAuditRepository()
    service = AuditService(
        repository,
        key=b"A" * 32,
        checkpoint_path=tmp_path / "head.json",
    )

    await asyncio.gather(*(service.append(_draft(index)) for index in range(1, 21)))

    assert [event.sequence for event in repository.events] == list(range(1, 21))
    assert (await service.verify()).valid is True


async def test_timeline_filters_by_correlation_and_sequence(tmp_path: Path) -> None:
    repository = FakeAuditRepository()
    service = AuditService(
        repository,
        key=b"A" * 32,
        checkpoint_path=tmp_path / "head.json",
    )
    correlation_id = uuid4()
    await service.append(
        _draft(1, correlation_id=correlation_id),
        _draft(2),
        _draft(3, correlation_id=correlation_id),
    )

    events = await service.timeline(
        after_sequence=1,
        limit=1,
        correlation_id=correlation_id,
    )

    assert [event.sequence for event in events] == [3]
