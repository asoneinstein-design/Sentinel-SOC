from typing import Any

from app.environment.simulator import SOCEnvironment


def quarantine_host(
    environment: SOCEnvironment,
    host_id: str,
    reason: str,
) -> dict[str, Any]:
    success = environment.quarantine_host(host_id)

    return {
        "tool": "quarantine_host",
        "success": success,
        "host_id": host_id,
        "isolated": environment.is_host_isolated(host_id),
        "reason": reason,
    }
