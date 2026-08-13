"""Run the proof-bound AgentGate portfolio demonstration against a local stack."""

import asyncio
import json
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = PROJECT_ROOT / "backend"
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(BACKEND_ROOT))

from demo_agent import DemoClientError, run_demo  # noqa: E402


def main() -> int:
    """Read secrets only from the environment and print a sanitized result."""

    bootstrap_secret = os.environ.get("AGENTGATE_ADMIN_BOOTSTRAP_SECRET")
    if bootstrap_secret is None:
        print(json.dumps({"status": "failed", "reason_code": "DEMO_SECRET_MISSING"}))
        return 2
    api_base = os.environ.get("AGENTGATE_API_URL", "http://127.0.0.1:8000")
    try:
        summary = asyncio.run(run_demo(api_base=api_base, bootstrap_secret=bootstrap_secret))
    except DemoClientError as exc:
        print(json.dumps({"status": "failed", "reason_code": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps({"status": "passed", **summary.as_dict()}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
