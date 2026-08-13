"""Keyed audit-chain construction, redaction, checkpointing, and verification."""

import asyncio
import hashlib
import hmac
import json
import os
import re
import tempfile
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol, cast
from uuid import UUID, uuid4

from app.auth.crypto import canonical_json
from app.logging import redact_value
from app.models.audit import AuditEvent
from app.models.enums import AuditActorType

AUDIT_FORMAT_VERSION = 1
GENESIS_HASH = "0" * 64
MAX_AUDIT_PAYLOAD_BYTES = 65_536
_HASH_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class AuditIntegrityError(RuntimeError):
    """The audit chain cannot be safely read or extended."""


class CheckpointFormatError(AuditIntegrityError):
    """The external checkpoint is malformed or unreadable."""


@dataclass(frozen=True)
class AuditEventDraft:
    """Server-owned, content-limited facts to append to the audit chain."""

    event_type: str
    correlation_id: UUID
    actor_type: AuditActorType
    actor_id: UUID | None
    payload: dict[str, object]
    task_id: UUID | None = None
    tool_request_id: UUID | None = None
    occurred_at: datetime | None = None


@dataclass(frozen=True)
class AuditCheckpoint:
    """MACed external commitment to the latest committed database event."""

    version: int
    chain_id: UUID
    sequence: int
    head_hash: str
    updated_at: datetime
    mac: str


@dataclass(frozen=True)
class AuditVerificationResult:
    """Safe integrity status shared by the API and command-line verifier."""

    valid: bool
    reason_code: str
    event_count: int
    verified_sequence: int
    chain_id: UUID | None
    head_hash: str
    failure_sequence: int | None = None


class AuditRepository(Protocol):
    """Persistence contract with one serialized append boundary."""

    async def append_batch(
        self,
        drafts: Sequence[AuditEventDraft],
        *,
        key: bytes,
        checkpoint_store: "CheckpointStore",
    ) -> list[AuditEvent]: ...

    async def list_events(
        self,
        *,
        after_sequence: int,
        limit: int,
        correlation_id: UUID | None,
        task_id: UUID | None,
        tool_request_id: UUID | None,
        event_type: str | None,
    ) -> Sequence[AuditEvent]: ...

    async def list_all_events(self) -> Sequence[AuditEvent]: ...


class CheckpointStore:
    """Read and atomically replace one external audit-head checkpoint file."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def read(self) -> AuditCheckpoint | None:
        if not self.path.exists():
            return None
        try:
            raw = self.path.read_text(encoding="utf-8")
            decoded = json.loads(raw, object_pairs_hook=_unique_object)
            return _parse_checkpoint(decoded)
        except (OSError, UnicodeError, ValueError, TypeError, KeyError) as exc:
            raise CheckpointFormatError("the audit checkpoint is invalid") from exc

    def write(self, checkpoint: AuditCheckpoint) -> None:
        """Commit a complete file with replace semantics; partial files are never visible."""

        self.path.parent.mkdir(parents=True, exist_ok=True)
        document = _checkpoint_document(checkpoint)
        encoded = canonical_json(document)
        temporary_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb",
                prefix=f".{self.path.name}.",
                suffix=".tmp",
                dir=self.path.parent,
                delete=False,
            ) as temporary:
                temporary_path = Path(temporary.name)
                temporary.write(encoded)
                temporary.flush()
                os.fsync(temporary.fileno())
            with suppress(OSError):
                temporary_path.chmod(0o600)
            os.replace(temporary_path, self.path)
        except OSError as exc:
            raise AuditIntegrityError("the audit checkpoint could not be committed") from exc
        finally:
            if temporary_path is not None and temporary_path.exists():
                temporary_path.unlink(missing_ok=True)


class AuditService:
    """Append redacted events and expose read-only timeline/integrity operations."""

    def __init__(
        self,
        repository: AuditRepository,
        *,
        key: bytes,
        checkpoint_path: Path,
    ) -> None:
        if len(key) != 32:
            raise ValueError("audit HMAC key must be exactly 32 bytes")
        self._repository = repository
        self._key = key
        self._checkpoint_store = CheckpointStore(checkpoint_path)

    async def append(self, *drafts: AuditEventDraft) -> list[AuditEvent]:
        """Redact and append one ordered batch, or fail without a partial batch."""

        prepared = [_prepare_draft(draft) for draft in drafts]
        if not prepared:
            return []
        return await self._repository.append_batch(
            prepared,
            key=self._key,
            checkpoint_store=self._checkpoint_store,
        )

    async def timeline(
        self,
        *,
        after_sequence: int = 0,
        limit: int = 100,
        correlation_id: UUID | None = None,
        task_id: UUID | None = None,
        tool_request_id: UUID | None = None,
        event_type: str | None = None,
    ) -> Sequence[AuditEvent]:
        return await self._repository.list_events(
            after_sequence=after_sequence,
            limit=limit,
            correlation_id=correlation_id,
            task_id=task_id,
            tool_request_id=tool_request_id,
            event_type=event_type,
        )

    async def verify(self) -> AuditVerificationResult:
        events = await self._repository.list_all_events()
        try:
            checkpoint = await asyncio.to_thread(self._checkpoint_store.read)
        except CheckpointFormatError:
            return _failure(
                "CHECKPOINT_INVALID",
                events,
                verified_sequence=0,
            )
        return verify_audit_chain(events, checkpoint, self._key)


def build_audit_event(
    draft: AuditEventDraft,
    *,
    sequence: int,
    chain_id: UUID,
    previous_hash: str,
    key: bytes,
) -> AuditEvent:
    """Construct one deterministic chain link from already-redacted server facts."""

    occurred_at = _utc(draft.occurred_at or datetime.now(UTC))
    event = AuditEvent(
        sequence=sequence,
        event_id=uuid4(),
        chain_id=chain_id,
        event_type=draft.event_type,
        occurred_at=occurred_at,
        correlation_id=draft.correlation_id,
        actor_type=draft.actor_type,
        actor_id=draft.actor_id,
        task_id=draft.task_id,
        tool_request_id=draft.tool_request_id,
        payload=draft.payload,
        previous_hash=previous_hash,
        event_hash="",
    )
    event.event_hash = _event_hash(event, key)
    return event


def create_checkpoint(event: AuditEvent, key: bytes) -> AuditCheckpoint:
    unsigned = AuditCheckpoint(
        version=AUDIT_FORMAT_VERSION,
        chain_id=event.chain_id,
        sequence=event.sequence,
        head_hash=event.event_hash,
        updated_at=datetime.now(UTC),
        mac="",
    )
    return AuditCheckpoint(
        version=unsigned.version,
        chain_id=unsigned.chain_id,
        sequence=unsigned.sequence,
        head_hash=unsigned.head_hash,
        updated_at=unsigned.updated_at,
        mac=_checkpoint_mac(unsigned, key),
    )


def verify_audit_chain(
    events: Sequence[AuditEvent],
    checkpoint: AuditCheckpoint | None,
    key: bytes,
) -> AuditVerificationResult:
    """Verify sequence, canonical event MACs, links, chain identity, and checkpoint."""

    if not events:
        if checkpoint is None:
            return AuditVerificationResult(True, "CHAIN_VALID", 0, 0, None, GENESIS_HASH)
        return AuditVerificationResult(
            False,
            "CHECKPOINT_HEAD_MISMATCH",
            0,
            0,
            checkpoint.chain_id,
            GENESIS_HASH,
        )

    chain_id = events[0].chain_id
    previous_hash = GENESIS_HASH
    verified_sequence = 0
    for expected_sequence, event in enumerate(events, start=1):
        if event.sequence != expected_sequence:
            return _failure(
                "SEQUENCE_GAP",
                events,
                verified_sequence=verified_sequence,
                failure_sequence=event.sequence,
                chain_id=chain_id,
                head_hash=previous_hash,
            )
        if event.chain_id != chain_id:
            return _failure(
                "CHAIN_ID_MISMATCH",
                events,
                verified_sequence=verified_sequence,
                failure_sequence=event.sequence,
                chain_id=chain_id,
                head_hash=previous_hash,
            )
        if not hmac.compare_digest(event.previous_hash, previous_hash):
            return _failure(
                "PREVIOUS_HASH_MISMATCH",
                events,
                verified_sequence=verified_sequence,
                failure_sequence=event.sequence,
                chain_id=chain_id,
                head_hash=previous_hash,
            )
        expected_hash = _event_hash(event, key)
        if not hmac.compare_digest(event.event_hash, expected_hash):
            return _failure(
                "EVENT_HASH_MISMATCH",
                events,
                verified_sequence=verified_sequence,
                failure_sequence=event.sequence,
                chain_id=chain_id,
                head_hash=previous_hash,
            )
        previous_hash = event.event_hash
        verified_sequence = event.sequence

    if checkpoint is None:
        return _failure(
            "CHECKPOINT_MISSING",
            events,
            verified_sequence=verified_sequence,
            chain_id=chain_id,
            head_hash=previous_hash,
        )
    if checkpoint.version != AUDIT_FORMAT_VERSION or not hmac.compare_digest(
        checkpoint.mac,
        _checkpoint_mac(checkpoint, key),
    ):
        return _failure(
            "CHECKPOINT_MAC_INVALID",
            events,
            verified_sequence=verified_sequence,
            chain_id=chain_id,
            head_hash=previous_hash,
        )
    if (
        checkpoint.chain_id != chain_id
        or checkpoint.sequence != verified_sequence
        or not hmac.compare_digest(checkpoint.head_hash, previous_hash)
    ):
        return _failure(
            "CHECKPOINT_HEAD_MISMATCH",
            events,
            verified_sequence=verified_sequence,
            chain_id=chain_id,
            head_hash=previous_hash,
        )
    return AuditVerificationResult(
        True,
        "CHAIN_VALID",
        len(events),
        verified_sequence,
        chain_id,
        previous_hash,
    )


def _prepare_draft(draft: AuditEventDraft) -> AuditEventDraft:
    if re.fullmatch(r"^[a-z][a-z0-9_.]{2,99}$", draft.event_type) is None:
        raise ValueError("audit event type is invalid")
    if draft.actor_type is AuditActorType.SYSTEM and draft.actor_id is not None:
        raise ValueError("system audit events cannot claim an actor identity")
    if draft.actor_type is not AuditActorType.SYSTEM and draft.actor_id is None:
        raise ValueError("principal audit events require an actor identity")
    redacted = redact_value(draft.payload)
    if not isinstance(redacted, Mapping):
        raise ValueError("audit payload must be an object")
    payload = cast(dict[str, object], dict(redacted))
    if len(canonical_json(payload)) > MAX_AUDIT_PAYLOAD_BYTES:
        raise ValueError("audit payload exceeds the maximum size")
    return AuditEventDraft(
        event_type=draft.event_type,
        correlation_id=draft.correlation_id,
        actor_type=draft.actor_type,
        actor_id=draft.actor_id,
        payload=payload,
        task_id=draft.task_id,
        tool_request_id=draft.tool_request_id,
        occurred_at=_utc(draft.occurred_at) if draft.occurred_at is not None else None,
    )


def _event_hash(event: AuditEvent, key: bytes) -> str:
    return hmac.new(key, canonical_json(_event_material(event)), hashlib.sha256).hexdigest()


def _event_material(event: AuditEvent) -> dict[str, object]:
    return {
        "sequence": event.sequence,
        "event_id": str(event.event_id),
        "chain_id": str(event.chain_id),
        "event_type": event.event_type,
        "occurred_at": _timestamp(event.occurred_at),
        "correlation_id": str(event.correlation_id),
        "actor_type": event.actor_type.value,
        "actor_id": str(event.actor_id) if event.actor_id is not None else None,
        "task_id": str(event.task_id) if event.task_id is not None else None,
        "tool_request_id": (
            str(event.tool_request_id) if event.tool_request_id is not None else None
        ),
        "payload": event.payload,
        "previous_hash": event.previous_hash,
    }


def _checkpoint_material(checkpoint: AuditCheckpoint) -> dict[str, object]:
    return {
        "version": checkpoint.version,
        "chain_id": str(checkpoint.chain_id),
        "sequence": checkpoint.sequence,
        "head_hash": checkpoint.head_hash,
        "updated_at": _timestamp(checkpoint.updated_at),
    }


def _checkpoint_mac(checkpoint: AuditCheckpoint, key: bytes) -> str:
    return hmac.new(
        key,
        canonical_json(_checkpoint_material(checkpoint)),
        hashlib.sha256,
    ).hexdigest()


def _checkpoint_document(checkpoint: AuditCheckpoint) -> dict[str, object]:
    return {**_checkpoint_material(checkpoint), "mac": checkpoint.mac}


def _parse_checkpoint(value: object) -> AuditCheckpoint:
    if not isinstance(value, dict) or set(value) != {
        "version",
        "chain_id",
        "sequence",
        "head_hash",
        "updated_at",
        "mac",
    }:
        raise ValueError("checkpoint properties are invalid")
    if type(value["version"]) is not int or value["version"] != AUDIT_FORMAT_VERSION:
        raise ValueError("checkpoint version is invalid")
    if type(value["sequence"]) is not int or value["sequence"] < 1:
        raise ValueError("checkpoint sequence is invalid")
    head_hash = value["head_hash"]
    mac = value["mac"]
    if not isinstance(head_hash, str) or _HASH_PATTERN.fullmatch(head_hash) is None:
        raise ValueError("checkpoint head is invalid")
    if not isinstance(mac, str) or _HASH_PATTERN.fullmatch(mac) is None:
        raise ValueError("checkpoint MAC is invalid")
    return AuditCheckpoint(
        version=value["version"],
        chain_id=UUID(cast(str, value["chain_id"])),
        sequence=value["sequence"],
        head_hash=head_hash,
        updated_at=_utc(
            datetime.fromisoformat(cast(str, value["updated_at"]).replace("Z", "+00:00"))
        ),
        mac=mac,
    )


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate checkpoint property")
        result[key] = value
    return result


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("audit timestamps must include a timezone")
    return value.astimezone(UTC)


def _timestamp(value: datetime) -> str:
    return _utc(value).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _failure(
    reason_code: str,
    events: Sequence[AuditEvent],
    *,
    verified_sequence: int,
    failure_sequence: int | None = None,
    chain_id: UUID | None = None,
    head_hash: str = GENESIS_HASH,
) -> AuditVerificationResult:
    return AuditVerificationResult(
        False,
        reason_code,
        len(events),
        verified_sequence,
        chain_id,
        head_hash,
        failure_sequence,
    )
