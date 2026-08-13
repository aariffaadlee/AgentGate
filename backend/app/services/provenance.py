"""Authoritative provenance classification, propagation, and safe views."""

from dataclasses import dataclass
from uuid import UUID, uuid4

from app.auth.crypto import canonical_sha256
from app.models.enums import ProvenanceSourceType, TrustLabel
from app.models.provenance import ProvenanceRecord
from app.models.tool import ToolRequest
from app.policies.client import PolicyProvenance
from app.tools.gateway import ToolExecutionResult


@dataclass(frozen=True)
class ProvenanceContext:
    """Validated influences and their policy-ready conservative summary."""

    records: list[ProvenanceRecord]
    policy: PolicyProvenance


def summarize_influences(
    *,
    records: list[ProvenanceRecord],
    requested_ids: list[UUID],
    task_id: UUID,
) -> ProvenanceContext:
    """Reject missing/cross-task records and never accept caller-supplied labels."""

    record_ids = {record.id for record in records}
    expected_ids = set(requested_ids)
    context_valid = (
        len(requested_ids) == len(expected_ids)
        and record_ids == expected_ids
        and all(record.task_id == task_id for record in records)
    )
    if not context_valid:
        return ProvenanceContext(
            records=[],
            policy=PolicyProvenance(
                labels=[TrustLabel.UNKNOWN],
                source_types=[],
                untrusted_influence=False,
                trusted_intent_present=False,
                context_valid=False,
            ),
        )

    labels = sorted({record.trust_label for record in records}, key=lambda item: item.value)
    source_types = sorted({record.source_type.value for record in records})
    return ProvenanceContext(
        records=records,
        policy=PolicyProvenance(
            labels=labels or [TrustLabel.UNKNOWN],
            source_types=source_types,
            untrusted_influence=any(
                record.trust_label is TrustLabel.UNTRUSTED for record in records
            ),
            trusted_intent_present=any(
                record.trust_label is TrustLabel.TRUSTED
                and record.source_type
                in {
                    ProvenanceSourceType.USER_INSTRUCTION,
                    ProvenanceSourceType.LOCAL_CONFIGURATION,
                }
                for record in records
            ),
            context_valid=True,
        ),
    )


def create_output_records(
    *,
    request: ToolRequest,
    execution: ToolExecutionResult,
    influences: list[ProvenanceRecord],
) -> list[ProvenanceRecord]:
    """Create content hashes and labels from trusted tool identity, never result claims."""

    if request.tool_name == "documents.search":
        matches = execution.result.get("matches")
        if not isinstance(matches, list):
            return []
        return [
            _record(
                request=request,
                source_type=ProvenanceSourceType.EXTERNAL_DOCUMENT,
                trust_label=TrustLabel.UNTRUSTED,
                source_reference=_safe_reference(item, "document_id", "external-document"),
                content=_without_provenance(item),
                attributes={"server_classification": "synthetic_external_document"},
            )
            for item in matches
            if isinstance(item, dict)
        ]
    if request.tool_name == "tickets.read":
        return [
            _record(
                request=request,
                source_type=ProvenanceSourceType.SUPPORT_TICKET,
                trust_label=TrustLabel.UNTRUSTED,
                source_reference=_safe_reference(
                    execution.result,
                    "ticket_id",
                    "support-ticket",
                ),
                content=_without_provenance(execution.result),
                attributes={"server_classification": "synthetic_support_ticket"},
            )
        ]

    return [
        _record(
            request=request,
            source_type=ProvenanceSourceType.TOOL_OUTPUT,
            trust_label=_derived_label(influences),
            source_reference=f"tool-request:{request.id}",
            content=execution.result,
            attributes={"tool_name": request.tool_name, "derived": True},
        )
    ]


def _record(
    *,
    request: ToolRequest,
    source_type: ProvenanceSourceType,
    trust_label: TrustLabel,
    source_reference: str,
    content: object,
    attributes: dict[str, object],
) -> ProvenanceRecord:
    return ProvenanceRecord(
        id=uuid4(),
        task_id=request.task_id,
        tool_request_id=request.id,
        parent_id=None,
        source_type=source_type,
        trust_label=trust_label,
        source_reference=source_reference,
        content_hash=canonical_sha256(content),
        created_by_agent_id=request.agent_id,
        created_by_admin_id=None,
        attributes=attributes,
    )


def _derived_label(influences: list[ProvenanceRecord]) -> TrustLabel:
    """A derived value can never become more trusted than any material input."""

    if any(record.trust_label is TrustLabel.UNTRUSTED for record in influences):
        return TrustLabel.UNTRUSTED
    # Tool output is conservatively unknown even when every declared input was trusted.
    return TrustLabel.UNKNOWN


def _safe_reference(value: dict[str, object], field: str, fallback: str) -> str:
    candidate = value.get(field)
    if isinstance(candidate, str) and 1 <= len(candidate) <= 120:
        return candidate
    return fallback


def _without_provenance(value: dict[str, object]) -> dict[str, object]:
    return {key: item for key, item in value.items() if key != "provenance"}
