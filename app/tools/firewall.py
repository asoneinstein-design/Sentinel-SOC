from typing import Any

from app.environment.simulator import SOCEnvironment


def firewall_block(
    environment: SOCEnvironment,
    ip: str,
    reason: str,
) -> dict[str, Any]:
    rule = environment.block_ip(ip, reason)

    return {
        "tool": "firewall_block",
        "success": True,
        "ip": ip,
        "rule_id": rule.rule_id,
        "blocked": rule.blocked,
        "reason": rule.reason,
        "created_at": rule.created_at,
    }
