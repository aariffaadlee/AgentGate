"""Wait for the configured PostgreSQL service without printing its credentials."""

import asyncio
import os
import sys
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[1] / "backend"
sys.path.insert(0, str(BACKEND_ROOT))

from app.config import get_settings  # noqa: E402
from app.db.session import Database  # noqa: E402


async def wait_for_database() -> int:
    """Poll readiness for a bounded period and return a process exit code."""

    try:
        timeout_seconds = float(os.getenv("AGENTGATE_DATABASE_WAIT_SECONDS", "30"))
    except ValueError:
        print("AGENTGATE_DATABASE_WAIT_SECONDS must be numeric.")
        return 2
    if not 1 <= timeout_seconds <= 300:
        print("AGENTGATE_DATABASE_WAIT_SECONDS must be between 1 and 300.")
        return 2

    database = Database(get_settings())
    deadline = asyncio.get_running_loop().time() + timeout_seconds
    try:
        while asyncio.get_running_loop().time() < deadline:
            if await database.ping():
                print("PostgreSQL is ready.")
                return 0
            await asyncio.sleep(0.5)
    finally:
        await database.dispose()
    print("PostgreSQL did not become ready before the timeout.")
    return 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(wait_for_database()))
