"""Read-only AgentGate audit-chain and external-checkpoint verifier."""

import asyncio
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = PROJECT_ROOT / "backend"
sys.path.insert(0, str(BACKEND_ROOT))

from app.config import get_settings  # noqa: E402
from app.db.audit import SQLAlchemyAuditRepository  # noqa: E402
from app.db.session import Database  # noqa: E402
from app.services.audit import AuditService  # noqa: E402


async def _verify() -> int:
    settings = get_settings()
    database = Database(settings)
    try:
        service = AuditService(
            SQLAlchemyAuditRepository(database.engine),
            key=settings.audit_hmac_key_bytes,
            checkpoint_path=settings.audit_checkpoint_path,
        )
        result = await service.verify()
    finally:
        await database.dispose()

    print(
        json.dumps(
            {
                "valid": result.valid,
                "reason_code": result.reason_code,
                "event_count": result.event_count,
                "verified_sequence": result.verified_sequence,
                "chain_id": str(result.chain_id) if result.chain_id is not None else None,
                "head_hash": result.head_hash,
                "failure_sequence": result.failure_sequence,
            },
            sort_keys=True,
        )
    )
    return 0 if result.valid else 1


def main() -> int:
    try:
        return asyncio.run(_verify())
    except Exception:
        print(
            json.dumps(
                {
                    "valid": False,
                    "reason_code": "VERIFICATION_UNAVAILABLE",
                },
                sort_keys=True,
            )
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
